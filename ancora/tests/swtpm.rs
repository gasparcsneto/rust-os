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
        let socket = dir.join("s");
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
        Swtpm {
            processo,
            fluxo,
            _dir: Dir(dir),
        }
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
