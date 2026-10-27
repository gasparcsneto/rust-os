//! A âncora contra um TPM de verdade: o `swtpm`, a implementação de
//! referência da IBM sobre a `libtpms`.
//!
//! O TPM simulado dos casos de unidade foi escrito junto com este pacote, e
//! uma implementação concorda consigo mesma mesmo errada. Este arquivo é o
//! que diz se os dois entenderam a especificação do mesmo jeito que quem a
//! implementou para valer — os códigos de erro com o número do handle, o
//! valor com que um contador nasce, o formato exato de cada resposta.
//!
//! Precisa do `swtpm` no `PATH`. Sem ele o teste **falha**, e não pula: um
//! teste que passa quando o que ele testa não existe é um teste que mente.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use ancora::cofre::{self, Cofre, Geracao, Selado, SeladoDaIdentidade};
use ancora::identidade;
use ancora::{Ancora, Erro, MAIOR_QUADRO, Sorteio, Tpm, atributo, codigo};

const INDICE: u32 = 0x0180_D0E0;
const SENHA: [u8; 32] = [0x3C; 32];

/// Um `swtpm` num diretório próprio, falando o protocolo cru do TPM num
/// socket: cada comando vai inteiro, cada resposta volta inteira.
struct Swtpm {
    processo: Child,
    fluxo: UnixStream,
    _dir: Dir,
}

/// Um diretório temporário apagado no fim.
struct Dir(PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Swtpm {
    fn novo(nome: &str) -> Swtpm {
        // Um diretório curto: socket Unix tem teto de 108 bytes de caminho.
        let dir = std::env::temp_dir().join(format!("ancora-{nome}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (processo, fluxo) = Swtpm::ligar(&dir);
        Swtpm {
            processo,
            fluxo,
            _dir: Dir(dir),
        }
    }

    /// Desliga o TPM e liga de novo, sobre o mesmo estado: o que um boot
    /// faz. O NV e as sementes ficam; os objetos carregados e as sessões
    /// somem.
    fn reiniciar(&mut self) {
        let _ = self.processo.kill();
        let _ = self.processo.wait();
        let (processo, fluxo) = Swtpm::ligar(&self._dir.0);
        self.processo = processo;
        self.fluxo = fluxo;
    }

    fn ligar(dir: &std::path::Path) -> (Child, UnixStream) {
        let socket = dir.join("s");
        let _ = std::fs::remove_file(&socket);
        let processo = Command::new("swtpm")
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", dir.display()),
                "--server",
                &format!("type=unixio,path={}", socket.display()),
                // Sem o protocolo de controle: o TPM aceita comandos sem o
                // `CMD_INIT` que o QEMU mandaria. O `TPM2_Startup` continua
                // por nossa conta, que é o que este pacote faz.
                "--flags",
                "not-need-init",
            ])
            .spawn()
            .expect("o swtpm precisa estar no PATH (pacote swtpm)");
        let limite = Instant::now() + Duration::from_secs(10);
        let fluxo = loop {
            if let Ok(f) = UnixStream::connect(&socket) {
                break f;
            }
            assert!(Instant::now() < limite, "o swtpm nao abriu o socket");
            std::thread::sleep(Duration::from_millis(20));
        };
        fluxo
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        (processo, fluxo)
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.processo.kill();
        let _ = self.processo.wait();
    }
}

impl Tpm for Swtpm {
    fn trocar(&mut self, comando: &[u8], resposta: &mut [u8; MAIOR_QUADRO]) -> Result<usize, Erro> {
        self.fluxo
            .write_all(comando)
            .map_err(|_| Erro::Transporte("escrita no socket do swtpm"))?;
        self.fluxo
            .read_exact(&mut resposta[..10])
            .map_err(|_| Erro::Transporte("leitura do cabecalho"))?;
        let n = u32::from_be_bytes(resposta[2..6].try_into().unwrap()) as usize;
        assert!((10..=MAIOR_QUADRO).contains(&n), "resposta de {n} bytes");
        self.fluxo
            .read_exact(&mut resposta[10..n])
            .map_err(|_| Erro::Transporte("leitura do corpo"))?;
        Ok(n)
    }
}

/// Bytes sorteados pelo sistema, para os nonces e o par efêmero.
struct DoSistema;
impl Sorteio for DoSistema {
    fn sortear(&mut self, destino: &mut [u8]) -> Result<(), Erro> {
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(destino))
            .map_err(|_| Erro::SemEntropia)
    }
}

/// O que o interposto faz com uma resposta: vê o comando, a resposta e as
/// respostas de antes, e mexe na de agora.
type Mexer<'a> = Box<dyn FnMut(&[u8], &mut Vec<u8>, &[Vec<u8>]) + 'a>;

/// O que o interposto faz com um comando antes de ele chegar ao TPM.
type MexerNoComando<'a> = Box<dyn FnMut(&mut Vec<u8>) + 'a>;

/// Um interposto no barramento: guarda todo comando que passa, e pode
/// mexer em cada comando antes de ele chegar ao TPM e em cada resposta
/// antes de ela voltar.
struct Interposto<'a> {
    tpm: &'a mut Swtpm,
    comandos: Vec<Vec<u8>>,
    respostas: Vec<Vec<u8>>,
    mexer: Option<Mexer<'a>>,
    mexer_no_comando: Option<MexerNoComando<'a>>,
}

impl<'a> Interposto<'a> {
    fn novo(tpm: &'a mut Swtpm) -> Interposto<'a> {
        Interposto {
            tpm,
            comandos: Vec::new(),
            respostas: Vec::new(),
            mexer: None,
            mexer_no_comando: None,
        }
    }
}

impl Tpm for Interposto<'_> {
    fn trocar(&mut self, comando: &[u8], resposta: &mut [u8; MAIOR_QUADRO]) -> Result<usize, Erro> {
        let mut comando = comando.to_vec();
        if let Some(m) = self.mexer_no_comando.as_mut() {
            m(&mut comando);
        }
        self.comandos.push(comando.clone());
        let n = self.tpm.trocar(&comando, resposta)?;
        let mut r = resposta[..n].to_vec();
        if let Some(m) = self.mexer.as_mut() {
            m(&comando, &mut r, &self.respostas);
        }
        self.respostas.push(resposta[..n].to_vec());
        resposta[..r.len()].copy_from_slice(&r);
        Ok(r.len())
    }
}

fn codigo_do_comando(c: &[u8]) -> u32 {
    u32::from_be_bytes(c[6..10].try_into().unwrap())
}

const NV_READ: u32 = 0x14E;

/// Uma âncora nova, definida e avançada uma vez, num TPM novo.
fn criada<T: Tpm>(tpm: &mut T) -> (Ancora, u64) {
    let mut a = Ancora::conectar(tpm, INDICE, SENHA, None).unwrap();
    assert!(!a.existe(tpm).unwrap());
    a.definir(tpm, &[], &mut DoSistema).unwrap();
    let v = a.valor(tpm, &mut DoSistema).unwrap();
    (a, v)
}

#[test]
fn a_ancora_num_tpm_de_verdade() {
    let mut tpm = Swtpm::novo("vida");
    let (mut a, primeiro) = criada(&mut tpm);
    let ponto = a.ponto_do_tpm();

    // Só cresce, de um em um.
    let mut anterior = primeiro;
    for _ in 0..5 {
        let novo = a.avancar(&mut tpm, &mut DoSistema).unwrap();
        assert_eq!(novo, anterior + 1);
        anterior = novo;
    }
    a.encerrar(&mut tpm);

    // Conectada de novo, com a EK fixada: a mesma EK, o mesmo valor.
    let mut b = Ancora::conectar(&mut tpm, INDICE, SENHA, Some(&ponto)).unwrap();
    assert_eq!(b.ponto_do_tpm(), ponto, "a EK mudou de um boot para outro");
    assert!(b.existe(&mut tpm).unwrap());
    assert_eq!(b.valor(&mut tpm, &mut DoSistema).unwrap(), anterior);
    b.encerrar(&mut tpm);

    // Outra EK fixada: recusada antes de qualquer comando ao contador.
    let mut outra = ponto;
    outra[5] ^= 1;
    assert_eq!(
        Ancora::conectar(&mut tpm, INDICE, SENHA, Some(&outra)).err(),
        Some(Erro::ChaveDoTpmTrocada)
    );

    // Definir de novo no mesmo número é recusado.
    let mut c = Ancora::conectar(&mut tpm, INDICE, SENHA, Some(&ponto)).unwrap();
    assert_eq!(
        c.definir(&mut tpm, &[], &mut DoSistema),
        Err(Erro::Codigo(codigo::NV_JA_DEFINIDO))
    );

    // Apagar e recriar não faz voltar: o contador novo nasce no maior valor
    // que o TPM já viu.
    ancora::apagar(&mut tpm, INDICE, &[]).unwrap();
    let mut d = Ancora::conectar(&mut tpm, INDICE, SENHA, Some(&ponto)).unwrap();
    assert!(!d.existe(&mut tpm).unwrap());
    d.definir(&mut tpm, &[], &mut DoSistema).unwrap();
    let renascido = d.valor(&mut tpm, &mut DoSistema).unwrap();
    assert!(
        renascido >= anterior,
        "o contador recriado nasceu em {renascido}, abaixo de {anterior}"
    );
}

/// A senha do contador não passa pelo barramento: nem na definição, nem
/// num avanço, nem numa leitura, nem no nascimento.
#[test]
fn a_senha_nao_passa_pelo_barramento() {
    const NASCIMENTO: u32 = 0x0180_D0E1;
    let mut tpm = Swtpm::novo("escuta");
    let mut escuta = Interposto::novo(&mut tpm);
    let (mut a, _) = criada(&mut escuta);
    a.registrar_nascimento(&mut escuta, NASCIMENTO, &[], &mut DoSistema)
        .unwrap();
    a.avancar(&mut escuta, &mut DoSistema).unwrap();
    a.nascimento(&mut escuta, NASCIMENTO, &mut DoSistema)
        .unwrap();
    assert!(escuta.comandos.len() > 8);
    for c in escuta.comandos.iter().chain(&escuta.respostas) {
        assert!(
            !c.windows(8).any(|w| w == &SENHA[..8]),
            "a senha passou pelo barramento"
        );
    }
}

/// Uma resposta adulterada no barramento não vira valor: a leitura falha,
/// e a seguinte, por uma sessão nova, lê o valor verdadeiro.
#[test]
fn a_resposta_adulterada_e_recusada() {
    let mut tpm = Swtpm::novo("adulterada");
    let mut i = Interposto::novo(&mut tpm);
    let (mut a, v) = criada(&mut i);
    i.mexer = Some(Box::new(|c, r, _| {
        if codigo_do_comando(c) == NV_READ {
            // O último byte do valor: um contador uma unidade maior.
            r[23] ^= 1;
        }
    }));
    assert_eq!(
        a.ler(&mut i, &mut DoSistema),
        Err(Erro::RespostaNaoAutenticada)
    );
    i.mexer = None;
    assert_eq!(a.ler(&mut i, &mut DoSistema).unwrap(), v);
}

/// Uma resposta de antes, repetida no barramento depois de o contador
/// andar, não passa: ela foi feita para outro nonce.
#[test]
fn a_resposta_repetida_e_recusada() {
    let mut tpm = Swtpm::novo("repetida");
    let mut i = Interposto::novo(&mut tpm);
    let (mut a, v) = criada(&mut i);
    let antiga = i
        .respostas
        .iter()
        .zip(&i.comandos)
        .rev()
        .find(|(_, c)| codigo_do_comando(c) == NV_READ)
        .map(|(r, _)| r.clone())
        .unwrap();
    assert_eq!(a.avancar(&mut i, &mut DoSistema).unwrap(), v + 1);
    i.mexer = Some(Box::new(move |c, r, _| {
        if codigo_do_comando(c) == NV_READ {
            *r = antiga.clone();
        }
    }));
    assert_eq!(
        a.ler(&mut i, &mut DoSistema),
        Err(Erro::RespostaNaoAutenticada)
    );
    i.mexer = None;
    assert_eq!(a.ler(&mut i, &mut DoSistema).unwrap(), v + 1);
}

/// Uma resposta forjada — bem formada, com o valor que o falsário quer e
/// um HMAC qualquer — não passa.
#[test]
fn a_resposta_forjada_e_recusada() {
    let mut tpm = Swtpm::novo("forjada");
    let mut i = Interposto::novo(&mut tpm);
    let (mut a, _) = criada(&mut i);
    i.mexer = Some(Box::new(|c, r, _| {
        if codigo_do_comando(c) == NV_READ {
            // O valor zero, e o HMAC zerado: o formato certo, nada mais.
            for b in &mut r[16..24] {
                *b = 0;
            }
            let n = r.len();
            for b in &mut r[n - 32..] {
                *b = 0;
            }
        }
    }));
    assert_eq!(
        a.ler(&mut i, &mut DoSistema),
        Err(Erro::RespostaNaoAutenticada)
    );
}

/// Com a senha errada, o TPM não lê nem avança — e o contador não anda.
#[test]
fn a_senha_errada_nao_le_nem_avanca() {
    let mut tpm = Swtpm::novo("errada");
    let (a, v) = criada(&mut tpm);
    let ponto = a.ponto_do_tpm();
    a.encerrar(&mut tpm);
    let mut errada = Ancora::conectar(&mut tpm, INDICE, [0xC3; 32], Some(&ponto)).unwrap();
    assert!(errada.existe(&mut tpm).unwrap());
    assert_eq!(
        errada.ler(&mut tpm, &mut DoSistema),
        Err(Erro::Codigo(codigo::SENHA_ERRADA))
    );
    assert_eq!(
        errada.incrementar(&mut tpm, &mut DoSistema),
        Err(Erro::Codigo(codigo::SENHA_ERRADA))
    );
    errada.encerrar(&mut tpm);
    let mut certa = Ancora::conectar(&mut tpm, INDICE, SENHA, Some(&ponto)).unwrap();
    assert_eq!(certa.valor(&mut tpm, &mut DoSistema).unwrap(), v);
}

/// Define à mão, pela hierarquia do dono e com uma sessão de senha, um
/// índice de oito bytes com a senha da âncora e estes `atributos`.
fn definir_a_mao(tpm: &mut Swtpm, indice: u32, atributos: u32) {
    let mut c = Vec::new();
    c.extend_from_slice(&0x8002u16.to_be_bytes());
    c.extend_from_slice(&0u32.to_be_bytes());
    c.extend_from_slice(&0x0000_012Au32.to_be_bytes());
    c.extend_from_slice(&0x4000_0001u32.to_be_bytes());
    c.extend_from_slice(&9u32.to_be_bytes());
    c.extend_from_slice(&0x4000_0009u32.to_be_bytes());
    c.extend_from_slice(&[0, 0, 1, 0, 0]);
    c.extend_from_slice(&(SENHA.len() as u16).to_be_bytes());
    c.extend_from_slice(&SENHA);
    c.extend_from_slice(&14u16.to_be_bytes());
    c.extend_from_slice(&indice.to_be_bytes());
    c.extend_from_slice(&0x000Bu16.to_be_bytes());
    c.extend_from_slice(&atributos.to_be_bytes());
    c.extend_from_slice(&[0, 0]);
    c.extend_from_slice(&8u16.to_be_bytes());
    let n = (c.len() as u32).to_be_bytes();
    c[2..6].copy_from_slice(&n);
    let mut r = [0; MAIOR_QUADRO];
    let tam = tpm.trocar(&c, &mut r).unwrap();
    assert_eq!(&r[6..10], &[0, 0, 0, 0], "o swtpm recusou o indice");
    assert!(tam >= 10);
}

#[test]
fn um_indice_de_outro_tipo_no_lugar_e_recusado() {
    let mut tpm = Swtpm::novo("estranho");
    ancora::iniciar(&mut tpm).unwrap();
    // Um índice comum de oito bytes, e não um contador, no número da
    // âncora. Montado à mão: este pacote só sabe criar o contador.
    definir_a_mao(&mut tpm, INDICE, atributo::DO_NASCIMENTO);
    let mut a = Ancora::conectar(&mut tpm, INDICE, SENHA, None).unwrap();
    assert_eq!(a.existe(&mut tpm).err(), Some(Erro::IndiceEstranho));
}

/// O nascimento definido e nunca escrito — a criação parou entre definir
/// o índice e escrever nele — é `None`, e não erro: o boot seguinte o
/// escreve e segue. Um erro aqui recusaria o journal para sempre.
#[test]
fn o_nascimento_definido_e_nunca_escrito_se_completa() {
    const NASCIMENTO: u32 = 0x0180_D0E1;
    let mut tpm = Swtpm::novo("nascimento-pela-metade");
    let (mut a, primeiro) = criada(&mut tpm);
    definir_a_mao(&mut tpm, NASCIMENTO, atributo::DO_NASCIMENTO);
    assert_eq!(
        a.nascimento(&mut tpm, NASCIMENTO, &mut DoSistema).unwrap(),
        None
    );
    assert_eq!(
        a.registrar_nascimento(&mut tpm, NASCIMENTO, &[], &mut DoSistema)
            .unwrap(),
        primeiro
    );
    assert_eq!(
        a.nascimento(&mut tpm, NASCIMENTO, &mut DoSistema).unwrap(),
        Some(primeiro)
    );
}

/// O nascimento num TPM de verdade: o índice comum se define, se escreve e
/// se lê pela sessão, e guarda o primeiro valor enquanto o contador anda.
#[test]
fn o_nascimento_num_tpm_de_verdade() {
    const NASCIMENTO: u32 = 0x0180_D0E1;
    let mut tpm = Swtpm::novo("nascimento");
    let (mut a, primeiro) = criada(&mut tpm);
    assert_eq!(
        a.nascimento(&mut tpm, NASCIMENTO, &mut DoSistema).unwrap(),
        None
    );
    assert_eq!(
        a.registrar_nascimento(&mut tpm, NASCIMENTO, &[], &mut DoSistema)
            .unwrap(),
        primeiro
    );
    for _ in 0..3 {
        a.avancar(&mut tpm, &mut DoSistema).unwrap();
    }
    assert_eq!(
        a.nascimento(&mut tpm, NASCIMENTO, &mut DoSistema).unwrap(),
        Some(primeiro)
    );
    assert_eq!(a.ler(&mut tpm, &mut DoSistema).unwrap(), primeiro + 3);
}

/// Dois TPMs têm duas EKs: a fixação distingue um do outro.
#[test]
fn cada_tpm_tem_a_sua_ek() {
    let mut um = Swtpm::novo("ek-um");
    let mut outro = Swtpm::novo("ek-outro");
    let a = Ancora::conectar(&mut um, INDICE, SENHA, None).unwrap();
    let b = Ancora::conectar(&mut outro, INDICE, SENHA, None).unwrap();
    assert_ne!(a.ponto_do_tpm(), b.ponto_do_tpm());
    assert_eq!(
        Ancora::conectar(&mut outro, INDICE, SENHA, Some(&a.ponto_do_tpm())).err(),
        Some(Erro::ChaveDoTpmTrocada)
    );
}

/// Respostas quebradas no barramento viram erro, e não valor: o cabeçalho
/// com outro tamanho, a resposta cortada, um byte a mais, a etiqueta
/// trocada, o contador com sete bytes.
#[test]
fn respostas_quebradas_viram_erro_e_nao_valor() {
    type Estrago = fn(&mut Vec<u8>);
    let acertar = |r: &mut Vec<u8>| {
        let n = (r.len() as u32).to_be_bytes();
        r[2..6].copy_from_slice(&n);
    };
    let estragos: [Estrago; 5] = [
        |r| r[5] = r[5].wrapping_add(1),
        |r| {
            r.truncate(r.len() - 1);
        },
        |r| r.push(0),
        |r| r[1] ^= 0x03,
        |r| {
            r[15] = 7;
            r.remove(16);
        },
    ];
    for (i, estrago) in estragos.iter().enumerate() {
        let mut tpm = Swtpm::novo(&format!("quebrada-{i}"));
        let mut p = Interposto::novo(&mut tpm);
        let (mut a, _) = criada(&mut p);
        let e = *estrago;
        p.mexer = Some(Box::new(move |c, r, _| {
            if codigo_do_comando(c) == NV_READ {
                e(r);
                if i > 0 && i != 3 {
                    acertar(r);
                }
            }
        }));
        assert!(
            a.ler(&mut p, &mut DoSistema).is_err(),
            "o estrago {i} foi lido como valor"
        );
    }
}

/// O nome que este pacote calcula para o índice — e põe no HMAC — é o
/// que o TPM calcula: antes e depois da primeira escrita.
#[test]
fn o_nome_calculado_e_o_do_tpm() {
    let mut tpm = Swtpm::novo("nome");
    let mut a = Ancora::conectar(&mut tpm, INDICE, SENHA, None).unwrap();
    a.definir(&mut tpm, &[], &mut DoSistema).unwrap();
    let nome_do_tpm = |tpm: &mut Swtpm| {
        let mut c = Vec::new();
        c.extend_from_slice(&0x8001u16.to_be_bytes());
        c.extend_from_slice(&14u32.to_be_bytes());
        c.extend_from_slice(&0x169u32.to_be_bytes());
        c.extend_from_slice(&INDICE.to_be_bytes());
        let mut r = [0; MAIOR_QUADRO];
        let n = tpm.trocar(&c, &mut r).unwrap();
        let publico = u16::from_be_bytes([r[10], r[11]]) as usize;
        let inicio = 12 + publico + 2;
        r[inicio..n].to_vec()
    };
    assert_eq!(
        nome_do_tpm(&mut tpm),
        ancora::nome_do_indice(INDICE, ancora::atributo::DA_ANCORA)
    );
    a.valor(&mut tpm, &mut DoSistema).unwrap();
    assert_eq!(
        nome_do_tpm(&mut tpm),
        ancora::nome_do_indice(
            INDICE,
            ancora::atributo::DA_ANCORA | ancora::atributo::ESCRITO
        )
    );
}

/// Uma senha que termina em zeros autoriza do mesmo jeito: o TPM tira os
/// zeros do fim antes de pô-la na chave do HMAC, e quem não tirar erra o
/// HMAC. A senha do kernel é sorteada — uma vez em 256 ela termina em zero.
#[test]
fn a_senha_com_zeros_no_fim_autoriza() {
    let mut senha = [0x5A; 32];
    senha[29..].fill(0);
    let mut tpm = Swtpm::novo("zeros");
    let mut a = Ancora::conectar(&mut tpm, INDICE, senha, None).unwrap();
    a.definir(&mut tpm, &[], &mut DoSistema).unwrap();
    let v = a.valor(&mut tpm, &mut DoSistema).unwrap();
    assert_eq!(a.avancar(&mut tpm, &mut DoSistema).unwrap(), v + 1);
    assert_eq!(a.ler(&mut tpm, &mut DoSistema).unwrap(), v + 1);
}

/// Uma chave de outro modelo no lugar da EK — outros atributos, como a de
/// quem responde no lugar do TPM com uma chave que ele escolheu — é
/// recusada antes de qualquer sessão: o sal iria para a chave errada.
#[test]
fn a_chave_de_outro_modelo_e_recusada() {
    const CREATE_PRIMARY: u32 = 0x131;
    let mut tpm = Swtpm::novo("outro-modelo");
    let mut i = Interposto::novo(&mut tpm);
    i.mexer = Some(Box::new(|c, r, _| {
        if codigo_do_comando(c) == CREATE_PRIMARY {
            // Cabeçalho (10), handle (4), tamanho dos parâmetros (4),
            // tamanho da parte pública (2), tipo (2), algoritmo do nome
            // (2): o último byte dos atributos.
            r[27] ^= 0x10;
        }
    }));
    assert!(matches!(
        Ancora::conectar(&mut i, INDICE, SENHA, None).err(),
        Some(Erro::RespostaMalformada(_))
    ));
}

/// O primeiro avanço de um contador recém-definido, com a resposta
/// adulterada: não se sabe se andou — e andou, e o nome do índice mudou
/// com a primeira escrita. A leitura seguinte, por uma sessão nova, usa o
/// nome que o TPM tem agora, e lê o valor.
#[test]
fn o_primeiro_avanco_sem_resposta_nao_deixa_o_nome_velho() {
    const NV_INCREMENT: u32 = 0x134;
    let mut tpm = Swtpm::novo("primeiro-avanco");
    let mut i = Interposto::novo(&mut tpm);
    let mut a = Ancora::conectar(&mut i, INDICE, SENHA, None).unwrap();
    a.definir(&mut i, &[], &mut DoSistema).unwrap();
    i.mexer = Some(Box::new(|c, r, _| {
        if codigo_do_comando(c) == NV_INCREMENT {
            let n = r.len();
            r[n - 1] ^= 1;
        }
    }));
    assert_eq!(
        a.valor(&mut i, &mut DoSistema),
        Err(Erro::RespostaNaoAutenticada)
    );
    i.mexer = None;
    let v = a.ler(&mut i, &mut DoSistema).unwrap();
    assert_eq!(a.avancar(&mut i, &mut DoSistema).unwrap(), v + 1);
}

/// Uma EK fora da curva — um ponto que não é de P-256 — é recusada ao
/// conectar, antes de fixada: um journal nunca guarda um ponto que não é
/// uma chave.
#[test]
fn a_ek_fora_da_curva_e_recusada() {
    const CREATE_PRIMARY: u32 = 0x131;
    let mut tpm = Swtpm::novo("fora-da-curva");
    let mut i = Interposto::novo(&mut tpm);
    i.mexer = Some(Box::new(|c, r, _| {
        if codigo_do_comando(c) == CREATE_PRIMARY {
            // Um byte do x da EK: depois do cabeçalho, do handle, dos
            // tamanhos, dos atributos, da política, da cifra, do esquema,
            // da curva, do kdf e do tamanho do x.
            r[80] ^= 1;
        }
    }));
    assert_eq!(
        Ancora::conectar(&mut i, INDICE, SENHA, None).err(),
        Some(Erro::RespostaMalformada(
            "a chave do TPM nao e um ponto de P-256"
        ))
    );
}

/// A senha nova do contador vai cifrada em AES-128-CFB — que, sozinho, não
/// tem integridade: um bit trocado no texto cifrado trocaria o mesmo bit
/// da senha que o TPM guardaria. O texto cifrado inteiro está dentro do
/// `cpHash`, e o HMAC da sessão o cobre. Mexido no caminho — um byte do
/// texto cifrado, o atributo que diz que ele vai cifrado, um byte do resto
/// dos parâmetros —, o TPM recusa o comando antes de decifrar, e nada é
/// definido. Intacto, o mesmo TPM define e o contador funciona.
#[test]
fn a_senha_cifrada_mexida_no_caminho_e_recusada() {
    const NV_DEFINE_SPACE: u32 = 0x12A;
    // O começo dos parâmetros: o cabeçalho (10), o handle do dono (4), o
    // tamanho da área de autorização (4) e a área.
    fn parametros(c: &[u8]) -> usize {
        18 + u32::from_be_bytes(c[14..18].try_into().unwrap()) as usize
    }
    type Mexida = fn(&mut Vec<u8>);
    let mexidas: [(&str, Mexida); 4] = [
        ("o primeiro byte do texto cifrado", |c| {
            let p = parametros(c);
            c[p + 2] ^= 0x01;
        }),
        ("o ultimo byte do texto cifrado", |c| {
            let p = parametros(c);
            let n = u16::from_be_bytes([c[p], c[p + 1]]) as usize;
            c[p + 1 + n] ^= 0x80;
        }),
        // A área de autorização: handle (4), nonce (2 + 32), atributos.
        ("o atributo que diz que vai cifrado", |c| {
            c[18 + 4 + 2 + 32] &= !0x20
        }),
        ("os atributos do indice, depois do texto cifrado", |c| {
            let p = parametros(c);
            let n = u16::from_be_bytes([c[p], c[p + 1]]) as usize;
            // TPM2B_NV_PUBLIC: tamanho (2), índice (4), algoritmo (2), e os
            // atributos.
            c[p + 2 + n + 2 + 4 + 2 + 3] ^= 0x01;
        }),
    ];
    for (i, (qual, mexida)) in mexidas.into_iter().enumerate() {
        let mut tpm = Swtpm::novo(&format!("cifra-mexida-{i}"));
        {
            let mut p = Interposto::novo(&mut tpm);
            p.mexer_no_comando = Some(Box::new(move |c| {
                if codigo_do_comando(c) == NV_DEFINE_SPACE {
                    mexida(c);
                }
            }));
            let mut a = Ancora::conectar(&mut p, INDICE, SENHA, None).unwrap();
            assert!(
                // `BAD_AUTH` na sessão 1: o HMAC não confere — recusado
                // pela autenticação, antes de decifrar, e não por outro motivo.
                a.definir(&mut p, &[], &mut DoSistema) == Err(Erro::Codigo(codigo::SENHA_ERRADA)),
                "{qual}: o TPM nao recusou o comando mexido pelo HMAC"
            );
            a.encerrar(&mut p);
        }
        let mut b = Ancora::conectar(&mut tpm, INDICE, SENHA, None).unwrap();
        assert!(
            !b.existe(&mut tpm).unwrap(),
            "{qual}: o indice foi definido pelo comando mexido"
        );
        b.definir(&mut tpm, &[], &mut DoSistema).unwrap();
        let v = b.valor(&mut tpm, &mut DoSistema).unwrap();
        assert_eq!(b.avancar(&mut tpm, &mut DoSistema).unwrap(), v + 1);
    }
}

// ---------------------------------------------------------------------------
// O cofre: as sementes seladas, e o índice de geração
// ---------------------------------------------------------------------------

const GERACAO: u32 = 0x0180_D0E2;
const SENHA_DA_GERACAO: [u8; 32] = [0x5D; 32];

/// `TPM_RC_POLICY`: o `TPM2_PolicyNV` com o valor que o contador não tem.
const POLITICA_RECUSADA: u32 = 0x126;
/// `TPM_RC_INTEGRITY` no primeiro parâmetro do `TPM2_Load`: o bloco privado
/// não confere com o pai e com o nome do objeto. É o que todo selado de
/// outro primário, ou mexido, recebe — conferido contra o `swtpm`, e
/// escrito aqui à parte das constantes do pacote, que os nomeiam igual.
const INTEGRIDADE: u32 = 0x1DF;
/// `TPM_RC_LOCKOUT`: o TPM bloqueado contra força bruta.
const BLOQUEADO: u32 = 0x921;
/// `TPM_PT_LOCKOUT_COUNTER`: quantas autorizações erradas contaram.
const CONTADOR_DO_BLOQUEIO: u32 = 0x20E;
const CREATE: u32 = 0x153;
const LOAD: u32 = 0x157;
const UNSEAL: u32 = 0x15E;
const POLICY_NV: u32 = 0x149;

/// Um TPM novo com a âncora conectada, o índice de geração definido e o
/// primário criado: o que o kernel tem no fim do boot.
fn cofre_novo<T: Tpm>(tpm: &mut T) -> (Ancora, Cofre, Geracao, u64) {
    let mut a = Ancora::conectar(tpm, INDICE, SENHA, None).unwrap();
    let mut g = Geracao::nova(GERACAO, SENHA_DA_GERACAO);
    assert!(!a.geracao_existe(tpm, &mut g).unwrap());
    a.definir_geracao(tpm, &mut g, &[], &mut DoSistema).unwrap();
    let valor = a.valor_da_geracao(tpm, &mut g, &mut DoSistema).unwrap();
    let c = a.abrir_cofre(tpm, &[], &mut DoSistema).unwrap();
    (a, c, g, valor)
}

/// Uma semente com bytes diferentes uns dos outros, para nenhum padrão
/// repetido se confundir com outra coisa.
fn semente(semeadura: u8) -> [u8; 32] {
    core::array::from_fn(|i| semeadura.wrapping_mul(31).wrapping_add(i as u8 * 7 + 1))
}

fn sorteada() -> [u8; 32] {
    let mut s = [0; 32];
    DoSistema.sortear(&mut s).unwrap();
    s
}

/// Um comando montado à mão: a etiqueta, o código e o corpo.
fn a_mao(etiqueta: u16, codigo: u32, corpo: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&etiqueta.to_be_bytes());
    c.extend_from_slice(&((10 + corpo.len()) as u32).to_be_bytes());
    c.extend_from_slice(&codigo.to_be_bytes());
    c.extend_from_slice(corpo);
    c
}

fn tpm2b(v: &mut Vec<u8>, b: &[u8]) {
    v.extend_from_slice(&(b.len() as u16).to_be_bytes());
    v.extend_from_slice(b);
}

/// A área de autorização com uma sessão de senha — em claro: é um teste.
fn sessao_de_senha(senha: &[u8]) -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(&0x4000_0009u32.to_be_bytes());
    a.extend_from_slice(&[0, 0, 1]);
    tpm2b(&mut a, senha);
    let mut v = (a.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(&a);
    v
}

/// Manda um comando e devolve o código e o corpo da resposta.
fn mandar(tpm: &mut Swtpm, c: &[u8]) -> (u32, Vec<u8>) {
    let mut r = [0; MAIOR_QUADRO];
    let n = tpm.trocar(c, &mut r).unwrap();
    (
        u32::from_be_bytes(r[6..10].try_into().unwrap()),
        r[10..n].to_vec(),
    )
}

/// Uma propriedade do TPM, por `TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)`.
fn propriedade(tpm: &mut Swtpm, prop: u32) -> u32 {
    let mut corpo = Vec::new();
    corpo.extend_from_slice(&6u32.to_be_bytes());
    corpo.extend_from_slice(&prop.to_be_bytes());
    corpo.extend_from_slice(&1u32.to_be_bytes());
    let (rc, r) = mandar(tpm, &a_mao(0x8001, 0x17A, &corpo));
    assert_eq!(rc, 0);
    // Mais dados (1), a capacidade (4), quantos (4), e o par.
    assert_eq!(u32::from_be_bytes(r[9..13].try_into().unwrap()), prop);
    u32::from_be_bytes(r[13..17].try_into().unwrap())
}

/// Bloqueia o TPM do jeito de quem tenta adivinhar uma senha: um índice
/// comum com senha e **sem** `NO_DA`, lido com a senha errada até o TPM
/// parar de aceitar senha em tudo o que conta para o bloqueio.
fn bloquear(tpm: &mut Swtpm) {
    const ISCA: u32 = 0x0180_D0F0;
    let mut corpo = Vec::new();
    corpo.extend_from_slice(&0x4000_0001u32.to_be_bytes());
    corpo.extend_from_slice(&sessao_de_senha(&[]));
    tpm2b(&mut corpo, b"certa");
    let mut publico = Vec::new();
    publico.extend_from_slice(&ISCA.to_be_bytes());
    publico.extend_from_slice(&0x000Bu16.to_be_bytes());
    publico.extend_from_slice(
        &(atributo::ESCRITA_COM_SENHA | atributo::LEITURA_COM_SENHA).to_be_bytes(),
    );
    tpm2b(&mut publico, &[]);
    publico.extend_from_slice(&8u16.to_be_bytes());
    tpm2b(&mut corpo, &publico);
    let (rc, _) = mandar(tpm, &a_mao(0x8002, 0x12A, &corpo));
    assert_eq!(rc, 0, "o indice isca nao foi definido");
    for _ in 0..64 {
        let mut corpo = Vec::new();
        corpo.extend_from_slice(&ISCA.to_be_bytes());
        corpo.extend_from_slice(&ISCA.to_be_bytes());
        corpo.extend_from_slice(&sessao_de_senha(b"errada"));
        corpo.extend_from_slice(&8u16.to_be_bytes());
        corpo.extend_from_slice(&0u16.to_be_bytes());
        if mandar(tpm, &a_mao(0x8002, NV_READ, &corpo)).0 == BLOQUEADO {
            return;
        }
    }
    panic!("o TPM nao bloqueou");
}

/// O controle do bloqueio: um primário igual ao do cofre, só que **sem**
/// `noDA`, criado à mão, e um `TPM2_Create` sob ele com a senha (vazia) do
/// pai. Devolve o código do `TPM2_Create`.
fn criar_sob_um_primario_sem_no_da(tpm: &mut Swtpm) -> u32 {
    let mut publico = Vec::new();
    publico.extend_from_slice(&0x0023u16.to_be_bytes());
    publico.extend_from_slice(&0x000Bu16.to_be_bytes());
    publico.extend_from_slice(&(cofre::objeto::DO_PRIMARIO & !(1 << 10)).to_be_bytes());
    tpm2b(&mut publico, &[]);
    for v in [0x0006u16, 128, 0x0043, 0x0010, 0x0003, 0x0010] {
        publico.extend_from_slice(&v.to_be_bytes());
    }
    tpm2b(&mut publico, &[0; 32]);
    tpm2b(&mut publico, &[0; 32]);
    let mut corpo = Vec::new();
    corpo.extend_from_slice(&0x4000_0001u32.to_be_bytes());
    corpo.extend_from_slice(&sessao_de_senha(&[]));
    corpo.extend_from_slice(&[0, 4, 0, 0, 0, 0]);
    tpm2b(&mut corpo, &publico);
    tpm2b(&mut corpo, &[]);
    corpo.extend_from_slice(&0u32.to_be_bytes());
    let (rc, r) = mandar(tpm, &a_mao(0x8002, 0x131, &corpo));
    assert_eq!(rc, 0, "o primario sem noDA nao foi criado");
    let pai = u32::from_be_bytes(r[0..4].try_into().unwrap());
    let mut selado = Vec::new();
    selado.extend_from_slice(&0x0008u16.to_be_bytes());
    selado.extend_from_slice(&0x000Bu16.to_be_bytes());
    // fixedTPM, fixedParent, userWithAuth e noDA: um selado de senha.
    selado.extend_from_slice(&0x0000_0452u32.to_be_bytes());
    tpm2b(&mut selado, &[]);
    selado.extend_from_slice(&0x0010u16.to_be_bytes());
    tpm2b(&mut selado, &[]);
    let mut sensivel = Vec::new();
    tpm2b(&mut sensivel, &[]);
    tpm2b(&mut sensivel, &[0x11; 32]);
    let mut corpo = Vec::new();
    corpo.extend_from_slice(&pai.to_be_bytes());
    corpo.extend_from_slice(&sessao_de_senha(&[]));
    tpm2b(&mut corpo, &sensivel);
    tpm2b(&mut corpo, &selado);
    tpm2b(&mut corpo, &[]);
    corpo.extend_from_slice(&0u32.to_be_bytes());
    let (rc, _) = mandar(tpm, &a_mao(0x8002, CREATE, &corpo));
    ancora::esquecer(tpm, pai).unwrap();
    rc
}

/// `TPM2_Clear` pela hierarquia do bloqueio, com a senha dela, vazia: a
/// semente do dono muda e os índices do dono somem. A EK fica.
fn limpar(tpm: &mut Swtpm) {
    let mut corpo = Vec::new();
    corpo.extend_from_slice(&0x4000_000Au32.to_be_bytes());
    corpo.extend_from_slice(&sessao_de_senha(&[]));
    let (rc, _) = mandar(tpm, &a_mao(0x8002, 0x126, &corpo));
    assert_eq!(rc, 0, "o TPM nao foi limpo");
}

/// A política da geração `valor` como o próprio TPM a calcula: uma sessão
/// de ensaio (`TPM_SE_TRIAL`), o `TPM2_PolicyNV` nela e o
/// `TPM2_PolicyGetDigest`.
fn politica_pelo_tpm(tpm: &mut Swtpm, valor: u64) -> Vec<u8> {
    let mut corpo = Vec::new();
    corpo.extend_from_slice(&0x4000_0007u32.to_be_bytes());
    corpo.extend_from_slice(&0x4000_0007u32.to_be_bytes());
    tpm2b(&mut corpo, &[0x77; 32]);
    tpm2b(&mut corpo, &[]);
    corpo.push(0x03);
    corpo.extend_from_slice(&0x0010u16.to_be_bytes());
    corpo.extend_from_slice(&0x000Bu16.to_be_bytes());
    let (rc, r) = mandar(tpm, &a_mao(0x8001, 0x176, &corpo));
    assert_eq!(rc, 0, "a sessao de ensaio nao abriu");
    let sessao = u32::from_be_bytes(r[0..4].try_into().unwrap());
    let mut corpo = Vec::new();
    corpo.extend_from_slice(&GERACAO.to_be_bytes());
    corpo.extend_from_slice(&GERACAO.to_be_bytes());
    corpo.extend_from_slice(&sessao.to_be_bytes());
    corpo.extend_from_slice(&sessao_de_senha(&SENHA_DA_GERACAO));
    tpm2b(&mut corpo, &valor.to_be_bytes());
    corpo.extend_from_slice(&0u16.to_be_bytes());
    corpo.extend_from_slice(&0u16.to_be_bytes());
    let (rc, _) = mandar(tpm, &a_mao(0x8002, POLICY_NV, &corpo));
    assert_eq!(rc, 0, "o PolicyNV de ensaio falhou");
    let (rc, r) = mandar(tpm, &a_mao(0x8001, 0x189, &sessao.to_be_bytes()));
    assert_eq!(rc, 0);
    ancora::esquecer(tpm, sessao).unwrap();
    let n = u16::from_be_bytes([r[0], r[1]]) as usize;
    r[2..2 + n].to_vec()
}

/// A resposta ao primeiro comando de código `codigo` que passou pelo
/// interposto e satisfaz `filtro`.
fn resposta_a(i: &Interposto, codigo: u32, filtro: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    i.comandos
        .iter()
        .zip(&i.respostas)
        .find(|(c, _)| codigo_do_comando(c) == codigo && filtro(c))
        .map(|(_, r)| r.clone())
        .expect("o comando nao passou pelo interposto")
}

#[test]
fn selar_e_abrir() {
    let mut tpm = Swtpm::novo("selar");
    let (mut a, mut c, mut g, valor) = cofre_novo(&mut tpm);
    let sementes: Vec<[u8; 32]> = (0..5).map(semente).collect();
    let selados: Vec<Selado> = sementes
        .iter()
        .map(|s| a.selar(&mut tpm, &c, &g, valor, s, &mut DoSistema).unwrap())
        .collect();
    assert!(selados.iter().all(|s| s.geracao() == valor));
    // A mesma semente selada duas vezes não dá o mesmo objeto: o TPM
    // sorteia o sal do `unique`, e o bloco privado é outro.
    let de_novo = a
        .selar(&mut tpm, &c, &g, valor, &sementes[0], &mut DoSistema)
        .unwrap();
    assert_ne!(de_novo, selados[0]);
    // Abertas em fila, pela mesma sessão de política, recomeçada a cada uma.
    for (s, selado) in sementes.iter().zip(&selados) {
        let aberta = a
            .abrir(&mut tpm, &mut c, &mut g, selado, &mut DoSistema)
            .unwrap();
        assert_eq!(aberta.como_bytes(), s);
    }
    // Fechada a sessão de política, a próxima abertura abre outra.
    c.fechar_a_politica(&mut tpm);
    let aberta = a
        .abrir(&mut tpm, &mut c, &mut g, &de_novo, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &sementes[0]);
}

/// O primário é recriado a cada boot, e é o mesmo: o que foi selado num
/// boot abre no seguinte.
#[test]
fn o_primario_e_o_mesmo_em_dois_boots() {
    let mut tpm = Swtpm::novo("primario");
    let (mut a, c, g, valor) = cofre_novo(&mut tpm);
    let ponto = a.ponto_do_tpm();
    let nome = *c.nome();
    let s = semente(9);
    let selado = a
        .selar(&mut tpm, &c, &g, valor, &s, &mut DoSistema)
        .unwrap();
    // Duas vezes no mesmo boot: o mesmo.
    let outro = a.abrir_cofre(&mut tpm, &[], &mut DoSistema).unwrap();
    assert_eq!(outro.nome(), &nome);
    outro.fechar(&mut tpm);

    tpm.reiniciar();
    let mut a = Ancora::conectar(&mut tpm, INDICE, SENHA, Some(&ponto)).unwrap();
    let mut g = Geracao::nova(GERACAO, SENHA_DA_GERACAO);
    assert!(a.geracao_existe(&mut tpm, &mut g).unwrap());
    assert_eq!(
        a.ler_geracao(&mut tpm, &mut g, &mut DoSistema).unwrap(),
        valor
    );
    let mut c = a.abrir_cofre(&mut tpm, &[], &mut DoSistema).unwrap();
    assert_eq!(c.nome(), &nome, "o primario mudou de um boot para outro");
    let aberta = a
        .abrir(&mut tpm, &mut c, &mut g, &selado, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &s);
}

/// Outro TPM, com o mesmo índice, a mesma senha e a mesma geração: o
/// primário é outro, e o selado não carrega.
#[test]
fn o_selado_nao_abre_em_outro_tpm() {
    let mut um = Swtpm::novo("cofre-um");
    let mut outro = Swtpm::novo("cofre-outro");
    let (mut a, c, g, valor) = cofre_novo(&mut um);
    let selado = a
        .selar(&mut um, &c, &g, valor, &semente(3), &mut DoSistema)
        .unwrap();
    let (mut b, mut d, mut h, valor_b) = cofre_novo(&mut outro);
    assert_eq!(valor_b, valor, "as duas geracoes deviam ser iguais");
    assert_ne!(d.nome(), c.nome());
    let e = b
        .abrir(&mut outro, &mut d, &mut h, &selado, &mut DoSistema)
        .err();
    assert_eq!(e, Some(Erro::Codigo(INTEGRIDADE)));
}

/// O TPM limpo: a mesma EK, outro dono, outro primário — e nenhum selado
/// de antes abre.
#[test]
fn o_tpm_limpo_nao_abre_os_selados_de_antes() {
    let mut tpm = Swtpm::novo("limpo");
    let (mut a, c, g, valor) = cofre_novo(&mut tpm);
    let ponto = a.ponto_do_tpm();
    let nome = *c.nome();
    let selado = a
        .selar(&mut tpm, &c, &g, valor, &semente(4), &mut DoSistema)
        .unwrap();
    c.fechar(&mut tpm);
    a.encerrar(&mut tpm);
    limpar(&mut tpm);
    let (mut a, mut c, mut g, _) = cofre_novo(&mut tpm);
    assert_eq!(a.ponto_do_tpm(), ponto);
    assert_ne!(c.nome(), &nome);
    let e = a
        .abrir(&mut tpm, &mut c, &mut g, &selado, &mut DoSistema)
        .err();
    assert_eq!(e, Some(Erro::Codigo(INTEGRIDADE)));
}

/// Um selado mexido não carrega: um byte do bloco privado, do `unique`,
/// o bloco cortado — e a geração escrita ao lado trocada pela atual, que
/// muda a política, o nome, e a integridade do bloco privado.
#[test]
fn o_selado_mexido_e_recusado() {
    let mut tpm = Swtpm::novo("mexido");
    let (mut a, mut c, mut g, valor) = cofre_novo(&mut tpm);
    let s = semente(5);
    let selado = a
        .selar(&mut tpm, &c, &g, valor, &s, &mut DoSistema)
        .unwrap();
    let privado = selado.privado().to_vec();
    let com_byte = |i: usize| {
        let mut p = privado.clone();
        p[i] ^= 0x01;
        Selado::de_partes(valor, selado.unico(), &p).unwrap()
    };
    let mut unico = *selado.unico();
    unico[0] ^= 0x80;
    let mexidos = [
        ("um byte da integridade", com_byte(2)),
        (
            "um byte do meio do bloco privado",
            com_byte(privado.len() / 2),
        ),
        (
            "o ultimo byte do bloco privado",
            com_byte(privado.len() - 1),
        ),
        (
            "o bloco privado cortado",
            Selado::de_partes(valor, selado.unico(), &privado[..privado.len() - 1]).unwrap(),
        ),
        (
            "um byte do unique",
            Selado::de_partes(valor, &unico, &privado).unwrap(),
        ),
    ];
    for (qual, m) in &mexidos {
        let e = a.abrir(&mut tpm, &mut c, &mut g, m, &mut DoSistema).err();
        assert_eq!(e, Some(Erro::Codigo(INTEGRIDADE)), "{qual}");
    }
    // O pacote dá nome ao código, e o motivo diz o que ele quer dizer.
    assert_eq!(codigo::INTEGRIDADE, INTEGRIDADE);
    assert_eq!(
        Erro::Codigo(INTEGRIDADE).motivo(),
        "o objeto selado nao e deste TPM, ou foi mexido"
    );
    assert_eq!(
        a.avancar_geracao(&mut tpm, &mut g, &mut DoSistema).unwrap(),
        valor + 1
    );
    let trocado = Selado::de_partes(valor + 1, selado.unico(), &privado).unwrap();
    let e = a
        .abrir(&mut tpm, &mut c, &mut g, &trocado, &mut DoSistema)
        .err();
    assert_eq!(e, Some(Erro::Codigo(INTEGRIDADE)), "a geracao trocada");
}

/// A semente não passa em claro pelo barramento: nem na selagem, nem na
/// abertura. A senha do índice de geração também não.
#[test]
fn a_semente_nao_passa_pelo_barramento() {
    let mut tpm = Swtpm::novo("cofre-escuta");
    let mut i = Interposto::novo(&mut tpm);
    let (mut a, mut c, mut g, valor) = cofre_novo(&mut i);
    let s = sorteada();
    let selado = a.selar(&mut i, &c, &g, valor, &s, &mut DoSistema).unwrap();
    let aberta = a
        .abrir(&mut i, &mut c, &mut g, &selado, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &s);
    let codigos: Vec<u32> = i.comandos.iter().map(|c| codigo_do_comando(c)).collect();
    for esperado in [CREATE, LOAD, POLICY_NV, UNSEAL] {
        assert!(
            codigos.contains(&esperado),
            "o comando {esperado:#x} nao passou"
        );
    }
    for b in i.comandos.iter().chain(&i.respostas) {
        assert!(
            !b.windows(8).any(|w| s.windows(8).any(|p| p == w)),
            "a semente passou pelo barramento"
        );
        assert!(
            !b.windows(8).any(|w| w == &SENHA_DA_GERACAO[..8]),
            "a senha do indice de geracao passou pelo barramento"
        );
    }
}

/// A resposta do `TPM2_Unseal` vem cifrada **e** autenticada: um byte do
/// texto cifrado mexido, ou uma resposta de antes repetida, não viram
/// semente. E a recusa não deixa nada ocupado no TPM.
#[test]
fn a_resposta_do_unseal_mexida_ou_repetida_e_recusada() {
    let mut tpm = Swtpm::novo("unseal-mexido");
    let mut i = Interposto::novo(&mut tpm);
    let (mut a, mut c, mut g, valor) = cofre_novo(&mut i);
    let s = semente(6);
    let selado = a.selar(&mut i, &c, &g, valor, &s, &mut DoSistema).unwrap();
    // Cabeçalho (10), tamanho dos parâmetros (4), tamanho da semente (2):
    // o primeiro byte dela, cifrado.
    i.mexer = Some(Box::new(|c, r, _| {
        if codigo_do_comando(c) == UNSEAL {
            r[16] ^= 0x01;
        }
    }));
    assert_eq!(
        a.abrir(&mut i, &mut c, &mut g, &selado, &mut DoSistema)
            .err(),
        Some(Erro::RespostaNaoAutenticada)
    );
    i.mexer = None;
    let aberta = a
        .abrir(&mut i, &mut c, &mut g, &selado, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &s);
    let antiga = i
        .respostas
        .iter()
        .zip(&i.comandos)
        .rev()
        .find(|(_, c)| codigo_do_comando(c) == UNSEAL)
        .map(|(r, _)| r.clone())
        .unwrap();
    i.mexer = Some(Box::new(move |c, r, _| {
        if codigo_do_comando(c) == UNSEAL {
            *r = antiga.clone();
        }
    }));
    assert_eq!(
        a.abrir(&mut i, &mut c, &mut g, &selado, &mut DoSistema)
            .err(),
        Some(Erro::RespostaNaoAutenticada)
    );
    i.mexer = None;
    let aberta = a
        .abrir(&mut i, &mut c, &mut g, &selado, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &s);
}

/// A destruição: as vivas seladas de novo para a geração seguinte, e só
/// então o contador anda. Depois, nenhum selado da geração velha abre — o
/// da chave morta e o antigo da viva, como uma cópia antiga do disco os
/// teria —, nem depois de um boot. E antes do avanço, os novos também não
/// abriam: é por isso que o boot completa um avanço interrompido.
#[test]
fn a_geracao_que_anda_mata_os_selados_velhos() {
    let mut tpm = Swtpm::novo("geracao");
    let (mut a, mut c, mut g, valor) = cofre_novo(&mut tpm);
    let ponto = a.ponto_do_tpm();
    let (viva, morta) = (semente(7), semente(8));
    let viva_velha = a
        .selar(&mut tpm, &c, &g, valor, &viva, &mut DoSistema)
        .unwrap();
    let morta_velha = a
        .selar(&mut tpm, &c, &g, valor, &morta, &mut DoSistema)
        .unwrap();
    let viva_nova = a
        .selar(&mut tpm, &c, &g, valor + 1, &viva, &mut DoSistema)
        .unwrap();
    assert_eq!(viva_nova.geracao(), valor + 1);
    assert_eq!(
        a.abrir(&mut tpm, &mut c, &mut g, &viva_nova, &mut DoSistema)
            .err(),
        Some(Erro::Codigo(POLITICA_RECUSADA)),
        "o selado novo abriu antes de a geracao andar"
    );
    assert_eq!(
        a.avancar_geracao(&mut tpm, &mut g, &mut DoSistema).unwrap(),
        valor + 1
    );
    assert_eq!(codigo::POLITICA_RECUSADA, POLITICA_RECUSADA);
    assert_eq!(
        Erro::Codigo(POLITICA_RECUSADA).motivo(),
        "o objeto selado e de outra geracao que a do indice do TPM"
    );
    for _ in 0..2 {
        for velho in [&viva_velha, &morta_velha] {
            assert_eq!(
                a.abrir(&mut tpm, &mut c, &mut g, velho, &mut DoSistema)
                    .err(),
                Some(Erro::Codigo(POLITICA_RECUSADA))
            );
        }
        let aberta = a
            .abrir(&mut tpm, &mut c, &mut g, &viva_nova, &mut DoSistema)
            .unwrap();
        assert_eq!(aberta.como_bytes(), &viva);
        // Um boot no meio não muda nada.
        tpm.reiniciar();
        a = Ancora::conectar(&mut tpm, INDICE, SENHA, Some(&ponto)).unwrap();
        g = Geracao::nova(GERACAO, SENHA_DA_GERACAO);
        c = a.abrir_cofre(&mut tpm, &[], &mut DoSistema).unwrap();
    }
}

/// O índice apagado e definido de novo nasce acima de onde estava — um
/// contador recriado nasce no maior valor que o TPM já viu —, e o selado
/// de antes continua sem abrir. Sem índice, nada abre.
#[test]
fn o_indice_recriado_nao_ressuscita_selados() {
    let mut tpm = Swtpm::novo("recriado");
    let (mut a, mut c, _, valor) = cofre_novo(&mut tpm);
    let g = Geracao::nova(GERACAO, SENHA_DA_GERACAO);
    let selado = a
        .selar(&mut tpm, &c, &g, valor, &semente(10), &mut DoSistema)
        .unwrap();
    ancora::apagar(&mut tpm, GERACAO, &[]).unwrap();
    let mut g = Geracao::nova(GERACAO, SENHA_DA_GERACAO);
    assert!(!a.geracao_existe(&mut tpm, &mut g).unwrap());
    assert_eq!(
        a.abrir(&mut tpm, &mut c, &mut g, &selado, &mut DoSistema)
            .err(),
        Some(Erro::Codigo(codigo::INDICE_INEXISTENTE))
    );
    a.definir_geracao(&mut tpm, &mut g, &[], &mut DoSistema)
        .unwrap();
    let renascido = a
        .valor_da_geracao(&mut tpm, &mut g, &mut DoSistema)
        .unwrap();
    assert!(
        renascido > valor,
        "recriado em {renascido}, nao acima de {valor}"
    );
    assert_eq!(
        a.abrir(&mut tpm, &mut c, &mut g, &selado, &mut DoSistema)
            .err(),
        Some(Erro::Codigo(POLITICA_RECUSADA))
    );
}

/// O índice definido e nunca avançado — a definição parou entre os dois —
/// se completa no boot seguinte, como a âncora.
#[test]
fn a_geracao_definida_e_nunca_avancada_se_completa() {
    let mut tpm = Swtpm::novo("geracao-pela-metade");
    let mut a = Ancora::conectar(&mut tpm, INDICE, SENHA, None).unwrap();
    let mut g = Geracao::nova(GERACAO, SENHA_DA_GERACAO);
    a.definir_geracao(&mut tpm, &mut g, &[], &mut DoSistema)
        .unwrap();
    let mut g = Geracao::nova(GERACAO, SENHA_DA_GERACAO);
    assert!(a.geracao_existe(&mut tpm, &mut g).unwrap());
    assert_eq!(
        a.ler_geracao(&mut tpm, &mut g, &mut DoSistema).err(),
        Some(Erro::Codigo(codigo::NV_NAO_INICIALIZADO))
    );
    let v = a
        .valor_da_geracao(&mut tpm, &mut g, &mut DoSistema)
        .unwrap();
    assert_eq!(a.ler_geracao(&mut tpm, &mut g, &mut DoSistema).unwrap(), v);
    assert_eq!(
        a.avancar_geracao(&mut tpm, &mut g, &mut DoSistema).unwrap(),
        v + 1
    );
}

/// Sem a senha do índice de geração, a geração não se prova e nada abre —
/// e as tentativas não contam para o bloqueio do TPM.
#[test]
fn a_senha_errada_da_geracao_nao_abre_nem_bloqueia() {
    let mut tpm = Swtpm::novo("geracao-errada");
    let (mut a, mut c, mut g, valor) = cofre_novo(&mut tpm);
    let s = semente(11);
    let selado = a
        .selar(&mut tpm, &c, &g, valor, &s, &mut DoSistema)
        .unwrap();
    let antes = propriedade(&mut tpm, CONTADOR_DO_BLOQUEIO);
    let mut errada = Geracao::nova(GERACAO, [0xD5; 32]);
    for _ in 0..5 {
        assert_eq!(
            a.abrir(&mut tpm, &mut c, &mut errada, &selado, &mut DoSistema)
                .err(),
            Some(Erro::Codigo(codigo::SENHA_ERRADA))
        );
    }
    assert_eq!(propriedade(&mut tpm, CONTADOR_DO_BLOQUEIO), antes);
    let aberta = a
        .abrir(&mut tpm, &mut c, &mut g, &selado, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &s);
}

/// O bloqueio do TPM contra força bruta não trava o cofre. As falhas do
/// próprio cofre não contam para ele; e com o TPM bloqueado por outra
/// entidade, o cofre abre, sela, avança a geração e recria o primário. O
/// controle: um primário igual, sem `noDA`, não serve de pai bloqueado.
#[test]
fn o_bloqueio_do_tpm_nao_trava_o_cofre() {
    let mut tpm = Swtpm::novo("bloqueio");
    let (mut a, mut c, mut g, valor) = cofre_novo(&mut tpm);
    let (s, t) = (semente(12), semente(13));
    let selado = a
        .selar(&mut tpm, &c, &g, valor, &s, &mut DoSistema)
        .unwrap();
    let adiantado = a
        .selar(&mut tpm, &c, &g, valor + 1, &s, &mut DoSistema)
        .unwrap();
    let mut privado = selado.privado().to_vec();
    privado[3] ^= 0x01;
    let mexido = Selado::de_partes(valor, selado.unico(), &privado).unwrap();
    let antes = propriedade(&mut tpm, CONTADOR_DO_BLOQUEIO);
    for _ in 0..4 {
        assert_eq!(
            a.abrir(&mut tpm, &mut c, &mut g, &adiantado, &mut DoSistema)
                .err(),
            Some(Erro::Codigo(POLITICA_RECUSADA))
        );
        assert_eq!(
            a.abrir(&mut tpm, &mut c, &mut g, &mexido, &mut DoSistema)
                .err(),
            Some(Erro::Codigo(INTEGRIDADE))
        );
    }
    assert_eq!(propriedade(&mut tpm, CONTADOR_DO_BLOQUEIO), antes);

    bloquear(&mut tpm);
    assert_eq!(criar_sob_um_primario_sem_no_da(&mut tpm), BLOQUEADO);
    let aberta = a
        .abrir(&mut tpm, &mut c, &mut g, &selado, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &s);
    let outro = a
        .selar(&mut tpm, &c, &g, valor + 1, &t, &mut DoSistema)
        .unwrap();
    assert_eq!(
        a.avancar_geracao(&mut tpm, &mut g, &mut DoSistema).unwrap(),
        valor + 1
    );
    let aberta = a
        .abrir(&mut tpm, &mut c, &mut g, &outro, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &t);
    let de_novo = a.abrir_cofre(&mut tpm, &[], &mut DoSistema).unwrap();
    assert_eq!(de_novo.nome(), c.nome());
    de_novo.fechar(&mut tpm);
}

/// A política que o pacote calcula para cada geração é a que o próprio TPM
/// calcula, numa sessão de ensaio.
#[test]
fn a_politica_e_a_que_o_tpm_calcula() {
    let mut tpm = Swtpm::novo("politica");
    let (_a, _c, _g, valor) = cofre_novo(&mut tpm);
    for v in [valor, valor + 1, 0, 1 << 40, u64::MAX] {
        assert_eq!(
            politica_pelo_tpm(&mut tpm, v),
            cofre::politica_da_geracao(GERACAO, v),
            "a politica da geracao {v}"
        );
    }
}

/// O primário e o selado, como o TPM os criou, têm os atributos pedidos —
/// lidos da resposta e conferidos bit a bit, com os bits escritos aqui pela
/// especificação (parte 2, 8.3), e não pelas constantes do pacote. E a
/// política do selado é a que o TPM calcula para a geração.
#[test]
fn o_primario_e_o_selado_tem_os_atributos_pedidos() {
    const FIXED_TPM: u32 = 1 << 1;
    const FIXED_PARENT: u32 = 1 << 4;
    const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
    const USER_WITH_AUTH: u32 = 1 << 6;
    const ADMIN_WITH_POLICY: u32 = 1 << 7;
    const NO_DA: u32 = 1 << 10;
    const RESTRICTED: u32 = 1 << 16;
    const DECRYPT: u32 = 1 << 17;
    let mut tpm = Swtpm::novo("atributos");
    let (primario, criado, valor) = {
        let mut i = Interposto::novo(&mut tpm);
        let (mut a, c, g, valor) = cofre_novo(&mut i);
        a.selar(&mut i, &c, &g, valor, &semente(14), &mut DoSistema)
            .unwrap();
        let do_dono = |c: &[u8]| c[10..14] == 0x4000_0001u32.to_be_bytes();
        (
            resposta_a(&i, 0x131, do_dono),
            resposta_a(&i, CREATE, |_| true),
            valor,
        )
    };
    // Cabeçalho (10), handle (4), tamanho dos parâmetros (4), tamanho da
    // parte pública (2), tipo (2) e algoritmo do nome (2): os atributos.
    let atributos = u32::from_be_bytes(primario[24..28].try_into().unwrap());
    assert_eq!(
        atributos,
        FIXED_TPM
            | FIXED_PARENT
            | SENSITIVE_DATA_ORIGIN
            | USER_WITH_AUTH
            | NO_DA
            | RESTRICTED
            | DECRYPT
    );
    // Cabeçalho (10), tamanho dos parâmetros (4), o bloco privado, e o
    // tamanho da parte pública (2).
    let n = u16::from_be_bytes([criado[14], criado[15]]) as usize;
    let p = 16 + n + 2;
    assert_eq!(&criado[p..p + 2], &[0x00, 0x08], "o selado nao e keyedhash");
    assert_eq!(&criado[p + 2..p + 4], &[0x00, 0x0B]);
    let atributos = u32::from_be_bytes(criado[p + 4..p + 8].try_into().unwrap());
    assert_eq!(
        atributos,
        FIXED_TPM | FIXED_PARENT | ADMIN_WITH_POLICY | NO_DA
    );
    assert_eq!(
        atributos & USER_WITH_AUTH,
        0,
        "a senha do selado autorizaria"
    );
    assert_eq!(atributos & SENSITIVE_DATA_ORIGIN, 0);
    assert_eq!(&criado[p + 8..p + 10], &[0x00, 0x20]);
    assert_eq!(
        criado[p + 10..p + 42],
        politica_pelo_tpm(&mut tpm, valor)[..]
    );
}

/// Aberturas que falham depois do `TPM2_Load` — a política recusada —
/// tiram do TPM o objeto e a sessão de política: dez seguidas, num TPM de
/// três vagas de cada, e a seguinte abre.
#[test]
fn as_aberturas_que_falham_nao_ocupam_o_tpm() {
    let mut tpm = Swtpm::novo("vagas");
    let (mut a, mut c, mut g, valor) = cofre_novo(&mut tpm);
    let s = semente(15);
    let selado = a
        .selar(&mut tpm, &c, &g, valor, &s, &mut DoSistema)
        .unwrap();
    let adiantado = a
        .selar(&mut tpm, &c, &g, valor + 1, &s, &mut DoSistema)
        .unwrap();
    for _ in 0..10 {
        assert_eq!(
            a.abrir(&mut tpm, &mut c, &mut g, &adiantado, &mut DoSistema)
                .err(),
            Some(Erro::Codigo(POLITICA_RECUSADA))
        );
    }
    let aberta = a
        .abrir(&mut tpm, &mut c, &mut g, &selado, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &s);
}

// ---------------------------------------------------------------------------
// A identidade
// ---------------------------------------------------------------------------

/// `TPM2_ObjectChangeAuth`.
const OBJECT_CHANGE_AUTH: u32 = 0x150;
/// `TPM_RC_AUTH_TYPE`: o papel de administração de um objeto com
/// `adminWithPolicy` pede uma sessão de política, e veio outra —
/// conferido contra o `swtpm`.
const TIPO_DE_AUTORIZACAO: u32 = 0x124;

/// A conexão da identidade num TPM: a EK — sem índice nenhum, que a senha
/// zerada da âncora nunca chega a ser usada — e o primário. É o que o boot
/// tem antes da persistência.
fn identidade_nova<T: Tpm>(tpm: &mut T, esperada: Option<&[u8; 64]>) -> (Ancora, Cofre) {
    let mut a = Ancora::conectar(tpm, INDICE, [0; 32], esperada).unwrap();
    let c = a.abrir_cofre(tpm, &[], &mut DoSistema).unwrap();
    (a, c)
}

/// O primário de armazenamento feito à mão, com o modelo do cofre: a mesma
/// chave que o cofre recria, num handle à parte.
fn primario_a_mao(tpm: &mut Swtpm) -> u32 {
    let mut publico = Vec::new();
    publico.extend_from_slice(&0x0023u16.to_be_bytes());
    publico.extend_from_slice(&0x000Bu16.to_be_bytes());
    publico.extend_from_slice(&cofre::objeto::DO_PRIMARIO.to_be_bytes());
    tpm2b(&mut publico, &[]);
    for v in [0x0006u16, 128, 0x0043, 0x0010, 0x0003, 0x0010] {
        publico.extend_from_slice(&v.to_be_bytes());
    }
    tpm2b(&mut publico, &[0; 32]);
    tpm2b(&mut publico, &[0; 32]);
    let mut corpo = Vec::new();
    corpo.extend_from_slice(&0x4000_0001u32.to_be_bytes());
    corpo.extend_from_slice(&sessao_de_senha(&[]));
    corpo.extend_from_slice(&[0, 4, 0, 0, 0, 0]);
    tpm2b(&mut corpo, &publico);
    tpm2b(&mut corpo, &[]);
    corpo.extend_from_slice(&0u32.to_be_bytes());
    let (rc, r) = mandar(tpm, &a_mao(0x8002, 0x131, &corpo));
    assert_eq!(rc, 0, "o primario a mao nao foi criado");
    u32::from_be_bytes(r[0..4].try_into().unwrap())
}

/// A parte pública de um *keyedhash* selado, com estes atributos, sem
/// política, e o `unique`.
fn publico_selado(atributos: u32, unico: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0x0008u16.to_be_bytes());
    p.extend_from_slice(&0x000Bu16.to_be_bytes());
    p.extend_from_slice(&atributos.to_be_bytes());
    tpm2b(&mut p, &[]);
    p.extend_from_slice(&0x0010u16.to_be_bytes());
    tpm2b(&mut p, unico);
    p
}

/// `TPM2_Create` à mão, pela senha vazia do pai: um selado com estes
/// atributos e estes dados. Devolve o bloco privado e o `unique`.
fn selar_a_mao(tpm: &mut Swtpm, pai: u32, atributos: u32, dados: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut sensivel = Vec::new();
    tpm2b(&mut sensivel, &[]);
    tpm2b(&mut sensivel, dados);
    let mut corpo = Vec::new();
    corpo.extend_from_slice(&pai.to_be_bytes());
    corpo.extend_from_slice(&sessao_de_senha(&[]));
    tpm2b(&mut corpo, &sensivel);
    tpm2b(&mut corpo, &publico_selado(atributos, &[]));
    tpm2b(&mut corpo, &[]);
    corpo.extend_from_slice(&0u32.to_be_bytes());
    let (rc, r) = mandar(tpm, &a_mao(0x8002, CREATE, &corpo));
    assert_eq!(rc, 0, "o selado a mao nao foi criado");
    // O tamanho dos parâmetros (4), o bloco privado e a parte pública.
    let n = u16::from_be_bytes([r[4], r[5]]) as usize;
    let privado = r[6..6 + n].to_vec();
    let p = 6 + n + 2;
    let m = u16::from_be_bytes([r[p - 2], r[p - 1]]) as usize;
    let publico = &r[p..p + m];
    let u = u16::from_be_bytes([publico[m - 34], publico[m - 33]]) as usize;
    assert_eq!(u, 32);
    (privado, publico[m - 32..].to_vec())
}

/// `TPM2_Load` à mão, pela senha vazia do pai. Devolve o código e o handle.
fn carregar_a_mao(
    tpm: &mut Swtpm,
    pai: u32,
    atributos: u32,
    unico: &[u8],
    privado: &[u8],
) -> (u32, u32) {
    let mut corpo = Vec::new();
    corpo.extend_from_slice(&pai.to_be_bytes());
    corpo.extend_from_slice(&sessao_de_senha(&[]));
    tpm2b(&mut corpo, privado);
    tpm2b(&mut corpo, &publico_selado(atributos, unico));
    let (rc, r) = mandar(tpm, &a_mao(0x8002, LOAD, &corpo));
    let alca = if rc == 0 {
        u32::from_be_bytes(r[0..4].try_into().unwrap())
    } else {
        0
    };
    (rc, alca)
}

/// `TPM2_ObjectChangeAuth` à mão, pela senha vazia do objeto. Devolve o
/// código.
fn trocar_a_senha_a_mao(tpm: &mut Swtpm, objeto: u32, pai: u32) -> u32 {
    let mut corpo = Vec::new();
    corpo.extend_from_slice(&objeto.to_be_bytes());
    corpo.extend_from_slice(&pai.to_be_bytes());
    corpo.extend_from_slice(&sessao_de_senha(&[]));
    tpm2b(&mut corpo, b"outra senha");
    mandar(tpm, &a_mao(0x8002, OBJECT_CHANGE_AUTH, &corpo)).0
}

/// `TPM2_Unseal` à mão, pela senha vazia, numa sessão de senha: a resposta
/// em claro.
fn abrir_a_mao(tpm: &mut Swtpm, objeto: u32) -> Vec<u8> {
    let mut corpo = Vec::new();
    corpo.extend_from_slice(&objeto.to_be_bytes());
    corpo.extend_from_slice(&sessao_de_senha(&[]));
    let (rc, r) = mandar(tpm, &a_mao(0x8002, UNSEAL, &corpo));
    assert_eq!(rc, 0, "o unseal a mao falhou");
    let n = u16::from_be_bytes([r[4], r[5]]) as usize;
    r[6..6 + n].to_vec()
}

/// Selar e abrir; a mesma chave selada duas vezes dá dois selados que
/// abrem igual; e, depois de um boot, a área lida do disco — a EK fixada
/// dela, o primário recriado — abre a mesma chave.
#[test]
fn a_identidade_sela_e_abre() {
    let mut tpm = Swtpm::novo("identidade");
    let (mut a, c) = identidade_nova(&mut tpm, None);
    let chave = sorteada();
    let selado = a
        .selar_identidade(&mut tpm, &c, &chave, &mut DoSistema)
        .unwrap();
    let outro = a
        .selar_identidade(&mut tpm, &c, &chave, &mut DoSistema)
        .unwrap();
    assert_ne!(outro, selado, "o TPM sorteia o sal do unique");
    for s in [&selado, &outro, &selado] {
        let aberta = a.abrir_identidade(&mut tpm, &c, s, &mut DoSistema).unwrap();
        assert_eq!(aberta.como_bytes(), &chave);
    }
    let area = identidade::Area {
        ek: a.ponto_do_tpm(),
        publica: [0x77; 32],
        selado,
    };
    let no_disco = area.em_bytes();
    c.fechar(&mut tpm);
    a.encerrar(&mut tpm);

    tpm.reiniciar();
    let identidade::Leitura::Valida(lida) = identidade::ler(&no_disco) else {
        panic!("a area nao voltou do disco");
    };
    assert_eq!(lida, area);
    let (mut a, c) = identidade_nova(&mut tpm, Some(&lida.ek));
    let aberta = a
        .abrir_identidade(&mut tpm, &c, &lida.selado, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &chave);
}

/// A chave não passa em claro pelo barramento — nem na selagem, nem na
/// abertura —, e a identidade não usa índice nem política: nenhum comando
/// de NV, nenhum `TPM2_PolicyNV`.
#[test]
fn a_identidade_nao_passa_pelo_barramento() {
    let mut tpm = Swtpm::novo("identidade-escuta");
    let mut i = Interposto::novo(&mut tpm);
    let (mut a, c) = identidade_nova(&mut i, None);
    let chave = sorteada();
    let selado = a
        .selar_identidade(&mut i, &c, &chave, &mut DoSistema)
        .unwrap();
    let aberta = a
        .abrir_identidade(&mut i, &c, &selado, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &chave);
    let codigos: Vec<u32> = i.comandos.iter().map(|c| codigo_do_comando(c)).collect();
    for esperado in [CREATE, LOAD, UNSEAL] {
        assert!(
            codigos.contains(&esperado),
            "o comando {esperado:#x} nao passou"
        );
    }
    for proibido in [POLICY_NV, NV_READ, 0x12A, 0x134, 0x137, 0x169] {
        assert!(
            !codigos.contains(&proibido),
            "o comando {proibido:#x} passou"
        );
    }
    for b in i.comandos.iter().chain(&i.respostas) {
        assert!(
            !b.windows(8).any(|w| chave.windows(8).any(|p| p == w)),
            "a chave da identidade passou pelo barramento"
        );
    }
}

/// Outro TPM: a EK da área não é a dele, e a conexão recusa antes de
/// qualquer sessão; sem a fixação, o primário dele é outro, e o selado não
/// carrega.
#[test]
fn a_identidade_nao_abre_em_outro_tpm() {
    let mut um = Swtpm::novo("identidade-um");
    let mut outro = Swtpm::novo("identidade-outro");
    let (mut a, c) = identidade_nova(&mut um, None);
    let ek = a.ponto_do_tpm();
    let selado = a
        .selar_identidade(&mut um, &c, &sorteada(), &mut DoSistema)
        .unwrap();
    assert_eq!(
        Ancora::conectar(&mut outro, INDICE, [0; 32], Some(&ek)).err(),
        Some(Erro::ChaveDoTpmTrocada)
    );
    let (mut b, d) = identidade_nova(&mut outro, None);
    assert_ne!(b.ponto_do_tpm(), ek);
    assert_eq!(
        b.abrir_identidade(&mut outro, &d, &selado, &mut DoSistema)
            .err(),
        Some(Erro::Codigo(INTEGRIDADE))
    );
}

/// O TPM limpo depois do nascimento: a mesma EK — a conexão passa —, outro
/// primário, e o selado não carrega. A identidade de antes está perdida.
#[test]
fn a_identidade_nao_abre_no_tpm_limpo() {
    let mut tpm = Swtpm::novo("identidade-limpo");
    let (mut a, c) = identidade_nova(&mut tpm, None);
    let ek = a.ponto_do_tpm();
    let selado = a
        .selar_identidade(&mut tpm, &c, &sorteada(), &mut DoSistema)
        .unwrap();
    c.fechar(&mut tpm);
    a.encerrar(&mut tpm);
    limpar(&mut tpm);
    let (mut a, c) = identidade_nova(&mut tpm, Some(&ek));
    assert_eq!(
        a.abrir_identidade(&mut tpm, &c, &selado, &mut DoSistema)
            .err(),
        Some(Erro::Codigo(INTEGRIDADE))
    );
}

/// O selado mexido não carrega: a integridade, o meio, o fim, o bloco
/// cortado, o `unique`. E um selado não passa pelo outro: o de uma chave
/// do cofre não abre como identidade, nem o da identidade como chave — a
/// parte pública de um não é a do outro, e o nome entra na integridade.
#[test]
fn o_selo_da_identidade_mexido_e_recusado() {
    let mut tpm = Swtpm::novo("identidade-mexida");
    let (mut a, mut c, mut g, valor) = cofre_novo(&mut tpm);
    let chave = semente(21);
    let selado = a
        .selar_identidade(&mut tpm, &c, &chave, &mut DoSistema)
        .unwrap();
    let privado = selado.privado().to_vec();
    let com_byte = |i: usize| {
        let mut p = privado.clone();
        p[i] ^= 0x01;
        SeladoDaIdentidade::de_partes(selado.unico(), &p).unwrap()
    };
    let mut unico = *selado.unico();
    unico[31] ^= 0x40;
    let mexidos = [
        ("um byte da integridade", com_byte(2)),
        ("um byte do meio", com_byte(privado.len() / 2)),
        ("o ultimo byte", com_byte(privado.len() - 1)),
        (
            "o bloco cortado",
            SeladoDaIdentidade::de_partes(selado.unico(), &privado[..privado.len() - 1]).unwrap(),
        ),
        (
            "um byte do unique",
            SeladoDaIdentidade::de_partes(&unico, &privado).unwrap(),
        ),
    ];
    for (qual, m) in &mexidos {
        assert_eq!(
            a.abrir_identidade(&mut tpm, &c, m, &mut DoSistema).err(),
            Some(Erro::Codigo(INTEGRIDADE)),
            "{qual}"
        );
    }
    let da_chave = a
        .selar(&mut tpm, &c, &g, valor, &semente(22), &mut DoSistema)
        .unwrap();
    let como_identidade =
        SeladoDaIdentidade::de_partes(da_chave.unico(), da_chave.privado()).unwrap();
    assert_eq!(
        a.abrir_identidade(&mut tpm, &c, &como_identidade, &mut DoSistema)
            .err(),
        Some(Erro::Codigo(INTEGRIDADE))
    );
    let como_chave = Selado::de_partes(valor, selado.unico(), selado.privado()).unwrap();
    assert_eq!(
        a.abrir(&mut tpm, &mut c, &mut g, &como_chave, &mut DoSistema)
            .err(),
        Some(Erro::Codigo(INTEGRIDADE))
    );
    let aberta = a
        .abrir_identidade(&mut tpm, &c, &selado, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &chave);
}

/// A resposta do `TPM2_Unseal` da identidade vem cifrada e autenticada: um
/// byte do texto cifrado mexido, ou uma resposta de antes repetida, não
/// viram chave — e nenhuma recusa deixa o objeto no TPM.
#[test]
fn a_resposta_do_unseal_da_identidade_mexida_ou_repetida_e_recusada() {
    let mut tpm = Swtpm::novo("identidade-unseal");
    let mut i = Interposto::novo(&mut tpm);
    let (mut a, c) = identidade_nova(&mut i, None);
    let chave = semente(23);
    let selado = a
        .selar_identidade(&mut i, &c, &chave, &mut DoSistema)
        .unwrap();
    i.mexer = Some(Box::new(|c, r, _| {
        if codigo_do_comando(c) == UNSEAL {
            r[16] ^= 0x01;
        }
    }));
    for _ in 0..5 {
        assert_eq!(
            a.abrir_identidade(&mut i, &c, &selado, &mut DoSistema)
                .err(),
            Some(Erro::RespostaNaoAutenticada)
        );
    }
    i.mexer = None;
    let aberta = a
        .abrir_identidade(&mut i, &c, &selado, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &chave);
    let antiga = i
        .respostas
        .iter()
        .zip(&i.comandos)
        .rev()
        .find(|(_, c)| codigo_do_comando(c) == UNSEAL)
        .map(|(r, _)| r.clone())
        .unwrap();
    i.mexer = Some(Box::new(move |c, r, _| {
        if codigo_do_comando(c) == UNSEAL {
            *r = antiga.clone();
        }
    }));
    for _ in 0..5 {
        assert_eq!(
            a.abrir_identidade(&mut i, &c, &selado, &mut DoSistema)
                .err(),
            Some(Erro::RespostaNaoAutenticada)
        );
    }
    i.mexer = None;
    let aberta = a
        .abrir_identidade(&mut i, &c, &selado, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &chave);
}

/// O selado da identidade, como o TPM o criou, tem os atributos pedidos —
/// conferidos bit a bit, com os bits escritos aqui pela especificação — e
/// nenhuma política.
#[test]
fn o_selado_da_identidade_tem_os_atributos_pedidos() {
    const FIXED_TPM: u32 = 1 << 1;
    const FIXED_PARENT: u32 = 1 << 4;
    const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
    const USER_WITH_AUTH: u32 = 1 << 6;
    const ADMIN_WITH_POLICY: u32 = 1 << 7;
    const NO_DA: u32 = 1 << 10;
    let mut tpm = Swtpm::novo("identidade-atributos");
    let mut i = Interposto::novo(&mut tpm);
    let (mut a, c) = identidade_nova(&mut i, None);
    a.selar_identidade(&mut i, &c, &semente(24), &mut DoSistema)
        .unwrap();
    let criado = resposta_a(&i, CREATE, |_| true);
    let n = u16::from_be_bytes([criado[14], criado[15]]) as usize;
    let p = 16 + n + 2;
    assert_eq!(&criado[p..p + 2], &[0x00, 0x08], "o selado nao e keyedhash");
    assert_eq!(&criado[p + 2..p + 4], &[0x00, 0x0B]);
    let atributos = u32::from_be_bytes(criado[p + 4..p + 8].try_into().unwrap());
    assert_eq!(
        atributos,
        FIXED_TPM | FIXED_PARENT | USER_WITH_AUTH | ADMIN_WITH_POLICY | NO_DA
    );
    assert_eq!(atributos & SENSITIVE_DATA_ORIGIN, 0);
    assert_eq!(&criado[p + 8..p + 10], &[0, 0], "o selado tem politica");
    assert_eq!(
        &criado[p + 10..p + 12],
        &[0x00, 0x10],
        "o selado tem esquema"
    );
    assert_eq!(&criado[p + 12..p + 14], &[0x00, 0x20]);
}

/// Ninguém troca a senha do selado da identidade: `adminWithPolicy` com a
/// política vazia fecha o `TPM2_ObjectChangeAuth` — que um selado igual,
/// sem o bit, aceita.
#[test]
fn ninguem_troca_a_senha_da_identidade() {
    let mut tpm = Swtpm::novo("identidade-senha");
    let (mut a, c) = identidade_nova(&mut tpm, None);
    let selado = a
        .selar_identidade(&mut tpm, &c, &semente(25), &mut DoSistema)
        .unwrap();
    c.fechar(&mut tpm);
    a.encerrar(&mut tpm);
    let pai = primario_a_mao(&mut tpm);
    let (rc, objeto) = carregar_a_mao(
        &mut tpm,
        pai,
        cofre::objeto::DA_IDENTIDADE,
        selado.unico(),
        selado.privado(),
    );
    assert_eq!(
        rc, 0,
        "o selado da identidade nao carregou sob o primario a mao"
    );
    assert_eq!(
        trocar_a_senha_a_mao(&mut tpm, objeto, pai),
        TIPO_DE_AUTORIZACAO,
        "a senha da identidade foi trocada"
    );
    ancora::esquecer(&mut tpm, objeto).unwrap();
    // O controle: o mesmo selado sem `adminWithPolicy`.
    let sem_o_bit = cofre::objeto::DA_IDENTIDADE & !cofre::objeto::ADMINISTRACAO_PELA_POLITICA;
    let (privado, unico) = selar_a_mao(&mut tpm, pai, sem_o_bit, &semente(26));
    let (rc, objeto) = carregar_a_mao(&mut tpm, pai, sem_o_bit, &unico, &privado);
    assert_eq!(rc, 0);
    assert_eq!(trocar_a_senha_a_mao(&mut tpm, objeto, pai), 0);
    ancora::esquecer(&mut tpm, objeto).unwrap();
    ancora::esquecer(&mut tpm, pai).unwrap();
}

/// O preço da senha vazia, dito num teste: quem tem o bloco do disco **e**
/// fala com o TPM da máquina abre o selado, por uma sessão de senha, sem
/// sal e sem cifra. É o limite que o cabeçalho do cofre descreve — o que o
/// selo protege é o disco sozinho, num outro TPM ou num TPM limpo.
#[test]
fn quem_tem_o_disco_e_a_maquina_abre_a_identidade() {
    let mut tpm = Swtpm::novo("identidade-limite");
    let (mut a, c) = identidade_nova(&mut tpm, None);
    let chave = semente(27);
    let selado = a
        .selar_identidade(&mut tpm, &c, &chave, &mut DoSistema)
        .unwrap();
    c.fechar(&mut tpm);
    a.encerrar(&mut tpm);
    let pai = primario_a_mao(&mut tpm);
    let (rc, objeto) = carregar_a_mao(
        &mut tpm,
        pai,
        cofre::objeto::DA_IDENTIDADE,
        selado.unico(),
        selado.privado(),
    );
    assert_eq!(rc, 0);
    assert_eq!(abrir_a_mao(&mut tpm, objeto), chave);
    ancora::esquecer(&mut tpm, objeto).unwrap();
    ancora::esquecer(&mut tpm, pai).unwrap();
}

/// O bloqueio do TPM contra força bruta não trava a identidade: com o TPM
/// bloqueado por outra entidade, ela sela e abre.
#[test]
fn o_bloqueio_do_tpm_nao_trava_a_identidade() {
    let mut tpm = Swtpm::novo("identidade-bloqueio");
    let (mut a, c) = identidade_nova(&mut tpm, None);
    let chave = semente(28);
    let selado = a
        .selar_identidade(&mut tpm, &c, &chave, &mut DoSistema)
        .unwrap();
    bloquear(&mut tpm);
    assert_eq!(criar_sob_um_primario_sem_no_da(&mut tpm), BLOQUEADO);
    let aberta = a
        .abrir_identidade(&mut tpm, &c, &selado, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &chave);
    let outro = a
        .selar_identidade(&mut tpm, &c, &semente(29), &mut DoSistema)
        .unwrap();
    let aberta = a
        .abrir_identidade(&mut tpm, &c, &outro, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &semente(29));
}

/// A identidade e o cofre sob o mesmo primário: a geração que anda mata a
/// semente velha e não toca na identidade, que não tem geração.
#[test]
fn a_geracao_nao_toca_na_identidade() {
    let mut tpm = Swtpm::novo("identidade-geracao");
    let (mut a, mut c, mut g, valor) = cofre_novo(&mut tpm);
    let chave = semente(30);
    let identidade = a
        .selar_identidade(&mut tpm, &c, &chave, &mut DoSistema)
        .unwrap();
    let velha = a
        .selar(&mut tpm, &c, &g, valor, &semente(31), &mut DoSistema)
        .unwrap();
    for _ in 0..2 {
        a.avancar_geracao(&mut tpm, &mut g, &mut DoSistema).unwrap();
        assert_eq!(
            a.abrir(&mut tpm, &mut c, &mut g, &velha, &mut DoSistema)
                .err(),
            Some(Erro::Codigo(POLITICA_RECUSADA))
        );
        let aberta = a
            .abrir_identidade(&mut tpm, &c, &identidade, &mut DoSistema)
            .unwrap();
        assert_eq!(aberta.como_bytes(), &chave);
    }
}

/// Aberturas que falham — o selado mexido, no `TPM2_Load`; a resposta
/// mexida, depois dele — não deixam nada no TPM: dez de cada, num TPM de
/// três vagas de objeto, e a seguinte abre.
#[test]
fn as_aberturas_da_identidade_que_falham_nao_ocupam_o_tpm() {
    let mut tpm = Swtpm::novo("identidade-vagas");
    let mut i = Interposto::novo(&mut tpm);
    let (mut a, c) = identidade_nova(&mut i, None);
    let chave = semente(32);
    let selado = a
        .selar_identidade(&mut i, &c, &chave, &mut DoSistema)
        .unwrap();
    let mut privado = selado.privado().to_vec();
    privado[5] ^= 0x02;
    let mexido = SeladoDaIdentidade::de_partes(selado.unico(), &privado).unwrap();
    for _ in 0..10 {
        assert_eq!(
            a.abrir_identidade(&mut i, &c, &mexido, &mut DoSistema)
                .err(),
            Some(Erro::Codigo(INTEGRIDADE))
        );
    }
    i.mexer = Some(Box::new(|c, r, _| {
        if codigo_do_comando(c) == UNSEAL {
            r[20] ^= 0x10;
        }
    }));
    for _ in 0..10 {
        assert!(
            a.abrir_identidade(&mut i, &c, &selado, &mut DoSistema)
                .is_err()
        );
    }
    i.mexer = None;
    let aberta = a
        .abrir_identidade(&mut i, &c, &selado, &mut DoSistema)
        .unwrap();
    assert_eq!(aberta.como_bytes(), &chave);
}
