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

use ancora::{Aberta, Ancora, Erro, MAIOR_QUADRO, Tpm, codigo};

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

#[test]
fn a_ancora_num_tpm_de_verdade() {
    let mut tpm = Swtpm::novo("vida");

    // Um TPM novo não tem âncora.
    assert!(matches!(
        Ancora::abrir(&mut tpm, INDICE, SENHA).unwrap(),
        Aberta::Ausente
    ));

    // Criada, ela tem um valor, e só cresce, de um em um.
    let (a, primeiro) = Ancora::criar(&mut tpm, INDICE, &[], SENHA).unwrap();
    let mut anterior = primeiro;
    for _ in 0..5 {
        let novo = a.avancar(&mut tpm).unwrap();
        assert_eq!(novo, anterior + 1);
        anterior = novo;
    }

    // Aberta de novo, é a mesma, com o mesmo valor.
    match Ancora::abrir(&mut tpm, INDICE, SENHA).unwrap() {
        Aberta::Presente(_, v) => assert_eq!(v, anterior),
        Aberta::Ausente => panic!("a ancora sumiu"),
    }

    // A senha errada é recusada com o código que o pacote distingue — e o
    // contador não anda.
    let errada = [0xC3; 32];
    assert_eq!(
        ancora::ler_contador(&mut tpm, INDICE, &errada),
        Err(Erro::Codigo(codigo::SENHA_ERRADA))
    );
    assert_eq!(
        ancora::incrementar(&mut tpm, INDICE, &errada),
        Err(Erro::Codigo(codigo::SENHA_ERRADA))
    );
    assert_eq!(a.ler(&mut tpm).unwrap(), anterior);

    // Definir de novo no mesmo número é recusado.
    assert_eq!(
        ancora::definir_contador(&mut tpm, INDICE, &[], &SENHA),
        Err(Erro::Codigo(codigo::NV_JA_DEFINIDO))
    );

    // Apagar e recriar não faz voltar: o contador novo nasce no maior valor
    // que o TPM já viu. É a propriedade que impede zerar a âncora com a
    // senha do dono.
    ancora::apagar(&mut tpm, INDICE, &[]).unwrap();
    assert!(matches!(
        Ancora::abrir(&mut tpm, INDICE, SENHA).unwrap(),
        Aberta::Ausente
    ));
    let (_, renascido) = Ancora::criar(&mut tpm, INDICE, &[], SENHA).unwrap();
    assert!(
        renascido >= anterior,
        "o contador recriado nasceu em {renascido}, abaixo de {anterior}"
    );
}

#[test]
fn um_indice_de_outro_tipo_no_lugar_e_recusado() {
    let mut tpm = Swtpm::novo("estranho");
    ancora::iniciar(&mut tpm).unwrap();
    // Um índice comum de oito bytes, e não um contador, no número da
    // âncora. Montado à mão: este pacote só sabe criar o contador.
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
    c.extend_from_slice(&INDICE.to_be_bytes());
    c.extend_from_slice(&0x000Bu16.to_be_bytes());
    // Escrita e leitura com senha, sem bloqueio, tipo comum (0).
    c.extend_from_slice(&((1u32 << 2) | (1 << 18) | (1 << 25)).to_be_bytes());
    c.extend_from_slice(&[0, 0]);
    c.extend_from_slice(&8u16.to_be_bytes());
    let n = (c.len() as u32).to_be_bytes();
    c[2..6].copy_from_slice(&n);
    let mut r = [0; MAIOR_QUADRO];
    let tam = tpm.trocar(&c, &mut r).unwrap();
    assert_eq!(&r[6..10], &[0, 0, 0, 0], "o swtpm recusou o indice comum");
    assert!(tam >= 10);

    assert_eq!(
        Ancora::abrir(&mut tpm, INDICE, SENHA).err(),
        Some(Erro::IndiceEstranho)
    );
}
