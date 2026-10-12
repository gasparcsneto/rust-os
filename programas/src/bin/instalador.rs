//! Instala código que chega pela rede, e o executa: o caminho inteiro do
//! código de fora da imagem, de dentro de um processo.
//!
//! - **baixa**: o nome `bancada.duke` pelo DNS da bancada da suíte — a
//!   associação com `udp:10.0.2.53:53`, que o gate decide —, a conexão com
//!   `tcp:10.0.2.100:8443`, que o gate decide como se o número tivesse sido
//!   digitado, o TLS com a âncora da imagem, e um
//!   `GET /codigo/<arquitetura>/<arquivo>`. O servidor serve o programa
//!   publicado, selado ou não — ver `xtask/src/codigo.rs`;
//! - **grava**: o corpo vai para o armazém pelo `fs.write`, no anexo do
//!   pedido — é binário —, contra a versão de agora. O gate decide o
//!   caminho; o que está sendo gravado é só bytes para ele;
//! - **roda**: o processo se bifurca, e o filho executa o arquivo gravado
//!   pela chamada `executar` — a mesma conferência do `user.run`: o código
//!   de fora da imagem só roda com o selo de um editor em que o papel de
//!   quem lançou o instalador confia. O pai espera o filho e diz como ele
//!   saiu: o código dele, ou o erro do `executar` que o recusou.
//!
//! Nada aqui decide nada: o selo é conferido pelo kernel, na hora de
//! executar, e o instalador só fica sabendo pelo erro.
//!
//! Espera as ordens no canal [`CANAL`]. A cada evento ACAO, o `a` diz o
//! passo — [`BAIXAR`] ou [`RODAR`] — e o `b` o arquivo, pela posição em
//! [`ARQUIVOS`]. Depois de cada passo, diz `instalador: <passo> <arquivo>:
//! <desfecho>`; sai com [`CODIGO`] quando a suíte pede o fim.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "instalador",
    "net.connect",
    "random.read",
    "system.read",
    "fs.read",
    "fs.write",
    "process.run"
);

use alloc::format;
use alloc::string::String;
use programas::conexao::Prazo;
use programas::escreverln;
use programas::http::{self, Falha, Limites, Opcoes, Resolucao};
use programas::nativo::{self, Recusa};
use programas::sistema;
use programas::tls;
use protocolo::usuario::evento::{Evento, tipo};

/// O código de saída no fim pedido. A suíte do kernel o procura.
const CODIGO: i64 = 94;

/// O canal por onde a suíte dita o passo.
const CANAL: &str = "teste-instalador";

/// Os passos — a suíte tem as mesmas constantes.
const BAIXAR: i64 = 1;
const RODAR: i64 = 2;

/// Os arquivos que a bancada publica, pela posição — ver
/// `xtask/src/codigo.rs`.
const ARQUIVOS: [&str; 5] = [
    "vindo",
    "vindo-sem-selo",
    "vindo-adulterado",
    "vindo-estranho",
    "vindo-outro",
];

/// Onde o código instalado mora: o diretório que a política deixa o
/// operador executar, e o de cima dele.
const DIRETORIO: &str = "/armazem/compartilhado/codigo";
const COMPARTILHADO: &str = "/armazem/compartilhado";

/// O DNS da bancada da suíte.
const DNS: &str = "udp:10.0.2.53:53";

/// A raiz da bancada, na imagem.
const ANCORAS: &str = "/dados/tls/bancada.pem";

/// O servidor da bancada, atrás do TLS.
const SERVIDOR: &str = "https://bancada.duke:8443";

/// A arquitetura, como a bancada a escreve no caminho.
#[cfg(target_arch = "x86_64")]
const ARQUITETURA: &str = "x86_64";
#[cfg(target_arch = "aarch64")]
const ARQUITETURA: &str = "aarch64";

/// O código de quem respondeu um pedido ao registro: o de uma recusa do
/// gate, ou o `code` de um resultado.
fn codigo_de(r: &nativo::Resposta) -> Option<String> {
    match r.resultado() {
        Err(Recusa { motivo, .. }) => motivo.map(String::from),
        Ok(v) => v.member("code").and_then(|c| c.as_str()).map(String::from),
    }
}

/// A versão de agora do arquivo — zero se ele não existe.
fn versao(caminho: &str) -> Result<u64, String> {
    let r = nativo::pedir("fs.stat", |w| w.field_str("path", caminho))
        .map_err(|e| format!("fs.stat {e}"))?;
    match r.resultado() {
        Ok(v) => Ok(v.member("version").and_then(|v| v.as_u64()).unwrap_or(0)),
        Err(_) => Err(format!("fs.stat {:?}", codigo_de(&r))),
    }
}

/// Cria o diretório `caminho`, se ele ainda não existe.
fn criar_diretorio(caminho: &str) -> Result<(), String> {
    let feito = nativo::pedir("fs.mkdir", |w| w.field_str("path", caminho))
        .map_err(|e| format!("fs.mkdir {e}"))?;
    let campo = |nome: &str| feito.resultado().ok().and_then(|v| v.member(nome));
    let ok = campo("ok").and_then(|v| v.as_bool()) == Some(true);
    let ja_havia = campo("error").and_then(|v| v.as_str()) == Some("ja ha algo nesse caminho");
    if !ok && !ja_havia {
        return Err(format!("fs.mkdir {caminho} {:?}", codigo_de(&feito)));
    }
    Ok(())
}

/// Baixa `arquivo` da bancada e o grava no armazém. Os bytes, ou o que
/// falhou — com o código de quem falhou.
fn baixar(arquivo: &str, opcoes: &Opcoes<'_>) -> Result<usize, String> {
    let url = format!("{SERVIDOR}/codigo/{ARQUITETURA}/{arquivo}");
    // O corpo inteiro vai num anexo: o teto é o dele.
    let limites = Limites {
        corpo: protocolo::usuario::nativo::MAIOR_ANEXO,
        ..Limites::default()
    };
    let r = http::obter(&url, opcoes, &limites)
        .map_err(|f: Falha| format!("{} {}", f.categoria().nome(), f.codigo()))?;
    if r.status != 200 {
        return Err(format!("status {}", r.status));
    }

    // O diretório e o de cima dele, explícitos — o `fs.mkdir` cria um
    // nível —: já existir não é erro.
    for diretorio in [COMPARTILHADO, DIRETORIO] {
        criar_diretorio(diretorio)?;
    }

    let caminho = format!("{DIRETORIO}/{arquivo}");
    let atual = versao(&caminho)?;
    let gravado = nativo::pedir_com_anexo(
        "fs.write",
        |w| {
            w.field_str("path", &caminho)?;
            w.field_u64("expect_version", atual)
        },
        &r.corpo,
    )
    .map_err(|e| format!("fs.write {e}"))?;
    let ok = gravado
        .resultado()
        .ok()
        .and_then(|v| v.member("ok"))
        .and_then(|v| v.as_bool())
        == Some(true);
    if !ok {
        return Err(format!("fs.write {:?}", codigo_de(&gravado)));
    }
    Ok(r.corpo.len())
}

/// Executa `arquivo` num filho, e espera: o código com que ele saiu — o do
/// programa, ou o erro do `executar` que o recusou.
fn rodar(arquivo: &str) -> Result<i64, String> {
    let caminho = format!("{DIRETORIO}/{arquivo}");
    match sistema::bifurcar() {
        0 => {
            // O filho: troca de imagem, ou sai com o erro da troca.
            let erro = sistema::executar(&caminho);
            sistema::sair(erro)
        }
        filho if filho > 0 => match sistema::esperar(filho as u64) {
            Ok((_, Some(codigo))) => Ok(codigo),
            Ok((_, None)) => Err(String::from("o filho morreu")),
            Err(e) => Err(format!("esperar {e}")),
        },
        erro => Err(format!("bifurcar {erro}")),
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let canal = sistema::escutar(CANAL);
    if canal < 0 {
        escreverln!("instalador: escutar devolveu {}", canal);
        return 1;
    }
    let ancoras = match tls::ancoras(ANCORAS) {
        Ok(a) => a,
        Err(f) => {
            escreverln!("instalador: as ancoras nao se leram: {}", f.codigo());
            return 2;
        }
    };
    let opcoes = Opcoes {
        resolucao: Resolucao::Dns(DNS),
        ancoras: Some(&ancoras),
        prazo: Prazo {
            espera_ms: 2_000,
            esperas: 3,
        },
    };
    escreverln!("instalador: pronto");

    let mut eventos = [Evento::default(); 8];
    loop {
        let n = match sistema::ler_eventos(canal as u64, &mut eventos) {
            Ok(n) => n,
            Err(e) => {
                escreverln!("instalador: a leitura do canal falhou: {}", e);
                return 3;
            }
        };
        for e in &eventos[..n] {
            if e.tipo == tipo::ENCERRAR {
                escreverln!("instalador: encerrado");
                return CODIGO;
            }
            if e.tipo != tipo::ACAO {
                continue;
            }
            let Some(arquivo) = usize::try_from(e.b).ok().and_then(|i| ARQUIVOS.get(i)) else {
                escreverln!("instalador: arquivo desconhecido {}", e.b);
                continue;
            };
            match e.a {
                BAIXAR => match baixar(arquivo, &opcoes) {
                    Ok(bytes) => {
                        escreverln!("instalador: baixou {}: {} bytes", arquivo, bytes);
                    }
                    Err(f) => {
                        escreverln!("instalador: baixou {}: falhou {}", arquivo, f);
                    }
                },
                RODAR => match rodar(arquivo) {
                    Ok(codigo) => {
                        escreverln!("instalador: rodou {}: saiu {}", arquivo, codigo);
                    }
                    Err(f) => {
                        escreverln!("instalador: rodou {}: falhou {}", arquivo, f);
                    }
                },
                outro => {
                    escreverln!("instalador: passo desconhecido {}", outro);
                }
            }
        }
    }
}
