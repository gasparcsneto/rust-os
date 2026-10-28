//! A bancada da atualização A/B — ver `docs/ATUALIZACAO.md`.
//!
//! # A máquina
//!
//! A de produção da bancada de persistência — o mesmo disco de testes, o
//! mesmo TPM entre os boots, o corte de energia com `SIGKILL` —, mas
//! sempre pelo firmware, nas duas arquiteturas: o OVMF no x86, o AAVMF no
//! ARM, o iniciador da ESP, o controle de boot, o slot. É o caminho que a
//! atualização muda, e um kernel posto pelo `-kernel` não passa por ele.
//!
//! # As imagens
//!
//! O kernel é o do slot A — o que `cargo xtask build` pôs lá —, em
//! manifestos diferentes:
//!
//! - a versão nova, `bancada-2`, de geração 2, com um pacote de um arquivo
//!   só, `/versao/marca`: a máquina que bootou a nova o lê, a que bootou a
//!   velha não;
//! - a mesma assinada por uma chave que o registro da máquina não tem;
//! - uma de geração 1, que não sobe acima do piso;
//! - uma cujo kernel não é ELF, publicada e assinada assim — a instalação
//!   a aceita, e é o iniciador que a recusa no boot.
//!
//! # As quedas
//!
//! Os cenários de queda rodam sobre o kernel com a feature `quedas` — ver
//! `kernel/src/quedas.rs` —, no slot A e nas imagens: o plano no fim da
//! partição de estado diz onde a energia cai, e a bancada corta.

use std::path::PathBuf;
use std::time::Instant;

use atualizacao::Slot;
use atualizacao::cabecalho::{self, KERNEL_EM};
use atualizacao::controle::{Controle, Falha, TENTATIVAS};
use protocolo::json::Json;

use super::disco_hostil::{Corte, DiscoHostil, Faixa, Sentido};
use super::persistencia::{self as p, Ligada};
use super::{
    AgenteNaPorta, Ambiente, Arquitetura, Artefato, Duration, ExitCode, Path, build_com, chaves,
    disco, disco_de_testes, producao, slots, zerar_o_estado,
};

/// A versão nova da bancada, e a geração dela.
const VERSAO_NOVA: &str = "bancada-2";
const GERACAO_NOVA: u64 = 2;

/// O arquivo do pacote da versão nova — montado em `/versao`, por cima de
/// uma raiz que não tem nada ali.
const MARCA: &str = "versao/marca";

/// A porta do agente `sistema` da bancada: o que escreve no slot inativo.
const PORTA_DO_SISTEMA: u8 = 4;

/// A porta de um agente `operador`: sem `system.update`.
const PORTA_DO_OPERADOR: u8 = 1;

/// Os pontos de queda da atualização, com os números de
/// `kernel/src/quedas.rs`; os do journal são os da bancada de
/// persistência.
mod ponto {
    pub use super::p::ponto::{
        ANTES_DA_ESCRITA, DEPOIS_DA_DESCARGA, DEPOIS_DA_ESCRITA, DEPOIS_DO_CONTADOR,
    };
    pub const CONTROLE_GRAVADO: u8 = 24;
    pub const ANTES_DA_CONFIRMACAO: u8 = 25;
    pub const NO_MEIO_DA_ENCENACAO: u8 = 26;
}

/// A bandeira 5 do plano: no ponto da confirmação, o pânico em vez de
/// congelar.
const PANICO_NA_CONFIRMACAO: u8 = 32;

/// Os tipos de registro do journal que as quedas contam.
const OPERACAO: u16 = diario::estado::tipo::OPERACAO;
const ATUALIZACAO: u16 = diario::estado::tipo::ATUALIZACAO;

/// Quanto esperar um boot que atende: a atualização atravessa vários —
/// três tentativas que entram em pânico, e a volta — antes de um atender,
/// e o ARM, emulado, demora mais em cada um.
fn espera(arch: Arquitetura) -> Duration {
    match arch {
        Arquitetura::X86_64 => Duration::from_secs(300),
        Arquitetura::Aarch64 => Duration::from_secs(900),
    }
}

/// As imagens dos slots que a bancada escreve.
struct Imagens {
    nova: slots::Imagem,
    estranha: slots::Imagem,
    velha: slots::Imagem,
    quebrada: slots::Imagem,
    /// A nova, num manifesto que lê só um formato de estado que a máquina
    /// não grava.
    outro_formato: slots::Imagem,
    /// A nova, num manifesto da outra arquitetura.
    outra_arquitetura: slots::Imagem,
}

fn imagem(
    arch: Arquitetura,
    kernel: &[u8],
    pacote: &[u8],
    versao: &str,
    geracao: u64,
    privada: &[u8; 32],
) -> Result<slots::Imagem, String> {
    imagem_de_formato(
        arch,
        kernel,
        pacote,
        versao,
        geracao,
        privada,
        slots::FORMATO_DO_ESTADO,
    )
}

fn imagem_de_formato(
    arch: Arquitetura,
    kernel: &[u8],
    pacote: &[u8],
    versao: &str,
    geracao: u64,
    privada: &[u8; 32],
    formato: u32,
) -> Result<slots::Imagem, String> {
    slots::imagem(
        &slots::Pedido {
            arch,
            kernel,
            pacote,
            versao,
            geracao,
            estado: (formato, formato),
        },
        privada,
    )
}

/// As imagens, do kernel que está no slot A do disco de testes.
fn imagens(arch: Arquitetura) -> Result<Imagens, String> {
    let disco = disco_de_testes()?;
    let kernel = slots::kernel_da_imagem(&slots::imagem_do_slot(&disco, Slot::A)?)?;
    let c = chaves::Chaves::garantir()?;
    let pacote = atualizacao::pacote::montar(&[(MARCA, VERSAO_NOVA.as_bytes())])
        .map_err(|m| format!("o pacote da versao nova: {m}"))?;
    let vazio = slots::pacote_vazio();
    let quebrado = b"um kernel que nao e ELF, publicado e assinado assim por engano\n".repeat(1024);
    Ok(Imagens {
        nova: imagem(
            arch,
            &kernel,
            &pacote,
            VERSAO_NOVA,
            GERACAO_NOVA,
            &c.atualizacao,
        )?,
        estranha: imagem(
            arch,
            &kernel,
            &pacote,
            "bancada-de-fora",
            GERACAO_NOVA,
            &c.atualizacao_estranha,
        )?,
        velha: imagem(arch, &kernel, &vazio, "bancada-velha", 1, &c.atualizacao)?,
        quebrada: imagem(
            arch,
            &quebrado,
            &vazio,
            "bancada-quebrada",
            3,
            &c.atualizacao,
        )?,
        outro_formato: imagem_de_formato(
            arch,
            &kernel,
            &pacote,
            "bancada-outro-formato",
            GERACAO_NOVA,
            &c.atualizacao,
            slots::FORMATO_DO_ESTADO + 1,
        )?,
        outra_arquitetura: imagem(
            match arch {
                Arquitetura::X86_64 => Arquitetura::Aarch64,
                Arquitetura::Aarch64 => Arquitetura::X86_64,
            },
            &kernel,
            &pacote,
            "bancada-outra-arquitetura",
            GERACAO_NOVA,
            &c.atualizacao,
        )?,
    })
}

/// O que cada cenário recebe.
struct Bancada {
    arch: Arquitetura,
    /// O disco de testes, pelo firmware.
    firmware: Artefato,
    /// O kernel do ARM pelo `-kernel`, fora de um slot; `None` no x86.
    sem_slot: Option<Artefato>,
    imagens: Imagens,
}

impl Bancada {
    fn disco(&self) -> Result<PathBuf, String> {
        disco_de_testes()
    }

    /// Liga a máquina pelo firmware, com o TPM.
    fn subir(&self) -> Result<Ligada, String> {
        self.subir_com(Ambiente::ligar(self.arch, None)?)
    }

    fn subir_com(&self, ambiente: Ambiente) -> Result<Ligada, String> {
        Ligada::subir_esperando(self.arch, &self.firmware, ambiente, espera(self.arch))
    }
}

/// Um cenário: um nome que se lê como afirmação, e a função que a confere.
struct Cenario {
    nome: &'static str,
    rodar: fn(&Bancada) -> Result<String, String>,
}

/// Os cenários sobre o kernel de produção, na ordem em que rodam. Cada um
/// começa com o estado zerado: o journal, o TPM, o armazém, o slot A como
/// o build o deixou, o B vazio e o controle apontando para o A.
const CENARIOS: &[Cenario] = &[
    Cenario {
        nome: "o primeiro boot pelo firmware: o slot A conferido, a linha de base no journal, e o controle igual a ela",
        rodar: o_primeiro_boot,
    },
    Cenario {
        nome: "a versao nova escrita, instalada por quorum, tentada e confirmada; a identidade, as credenciais, a senha trocada, o armazem e a auditoria continuam",
        rodar: a_atualizacao_inteira,
    },
    Cenario {
        nome: "a versao velha nao volta: o controle forjado para ela e a velha reescrita e armada sao recusados, e a maquina volta para a nova",
        rodar: a_versao_velha_nao_volta,
    },
    Cenario {
        nome: "a versao nova que o iniciador nao carrega - o kernel estragado depois da instalacao, ou que nao e ELF - volta para a velha no mesmo boot",
        rodar: a_versao_nova_que_nao_carrega,
    },
    Cenario {
        nome: "a instalacao recusa a chave de fora, a geracao que nao sobe, o formato de estado e a arquitetura incompativeis, o manifesto trocado, a assinatura adulterada, o slot estragado, o quorum incompleto e quem nao tem a permissao; nada muda",
        rodar: as_recusas_da_instalacao,
    },
    Cenario {
        nome: "a versao cancelada nao boota, nem com o controle armado de novo a mao",
        rodar: a_versao_cancelada_nao_boota,
    },
    Cenario {
        nome: "as duas copias do controle estragadas: o iniciador sintetiza pelos slots, e o kernel regrava o controle pelo journal",
        rodar: as_duas_copias_estragadas,
    },
    Cenario {
        nome: "sem o TPM, ou com outro, a tentativa nao se confirma e volta; com o TPM de volta, a velha desfaz pelo journal",
        rodar: sem_o_tpm_na_tentativa,
    },
    Cenario {
        nome: "o disco que falha no slot inativo: a escrita e a instalacao sem o disco nao armam nada, a carga sem ele volta para a velha, e com o disco de volta a versao nova se instala",
        rodar: o_disco_que_falha,
    },
    Cenario {
        nome: "duas instalacoes ao mesmo tempo armam uma so, e a escrita que disputa o slot com a instalacao nao o troca depois de armado",
        rodar: a_concorrencia,
    },
    Cenario {
        nome: "a imagem de producao se atualiza pelo operador: publicada, escrita pelo agente dele, instalada pelo quorum dele, com a identidade nascida no primeiro boot",
        rodar: a_producao_se_atualiza,
    },
    Cenario {
        nome: "o kernel fora de um slot nao tem autoridade quando o journal ja tem a atualizacao",
        rodar: o_kernel_fora_de_um_slot,
    },
];

/// Os cenários que precisam do kernel com os pontos de queda.
const CENARIOS_DE_QUEDA: &[Cenario] = &[
    Cenario {
        nome: "a queda em cada fronteira da instalacao: armada exatamente quando o registro esta no disco, e o controle segue o journal",
        rodar: as_quedas_na_instalacao,
    },
    Cenario {
        nome: "a queda em cada fronteira da confirmacao: a maquina termina na versao nova, confirmada uma vez",
        rodar: as_quedas_na_confirmacao,
    },
    Cenario {
        nome: "a queda no meio da escrita da versao nova: o slot pela metade nao se instala, e a escrita de novo instala",
        rodar: a_queda_no_meio_da_escrita,
    },
    Cenario {
        nome: "a queda em cada fronteira do desfazimento: a velha termina ativa, sem a candidata",
        rodar: as_quedas_no_desfazimento,
    },
    Cenario {
        nome: "a versao nova que entra em panico na tentativa: o iniciador conta tres, e a velha volta e desfaz",
        rodar: o_panico_na_tentativa,
    },
    Cenario {
        nome: "a imagem de producao cuja versao nova entra em panico na tentativa volta para a velha com a identidade nascida no primeiro boot",
        rodar: a_producao_desfeita_com_a_identidade,
    },
];

/// `cargo xtask atualizacao`: roda os cenários e diz quais passaram.
///
/// Os de queda vêm por último, sobre outra compilação do kernel — a de
/// produção mais os pontos de queda —, que substitui a primeira no slot A.
/// `DUKE_CENARIOS` filtra pelo nome, como na bancada de persistência.
pub(crate) fn atualizacao(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    let _ = p::SERIAL_DA_BANCADA
        .set(super::raiz_do_estado().join(format!("atualizacao-{}.serial", arch.nome())));
    let filtro = std::env::var("DUKE_CENARIOS").ok();
    let escolhido = |c: &Cenario| {
        filtro
            .as_deref()
            .is_none_or(|f| f.split('|').any(|p| c.nome.contains(p)))
    };
    let total = CENARIOS
        .iter()
        .chain(CENARIOS_DE_QUEDA)
        .filter(|c| escolhido(c))
        .count();
    println!(
        "[xtask] atualizacao: {total} cenarios, cada um sobre um estado zerado, pelo firmware ({})",
        arch.nome()
    );
    let mut falhas = 0;
    let mut rodar = |cenarios: &[Cenario], b: &Bancada| -> Result<(), String> {
        for cenario in cenarios.iter().filter(|c| escolhido(c)) {
            zerar_o_estado(arch)?;
            if let (None, Some(serial)) =
                (std::env::var_os("DUKE_BANCADA_LOG"), p::serial_do_cenario())
            {
                let _ = std::fs::write(serial, b"");
            }
            let inicio = Instant::now();
            match (cenario.rodar)(b) {
                Ok(detalhe) => println!(
                    "  [atualizacao] ok  {} ({} s): {detalhe}",
                    cenario.nome,
                    inicio.elapsed().as_secs()
                ),
                Err(motivo) => {
                    falhas += 1;
                    println!("  [atualizacao] FALHOU  {}: {motivo}", cenario.nome);
                    p::mostrar_o_fim_da_serial();
                }
            }
        }
        Ok(())
    };
    if CENARIOS.iter().any(escolhido) {
        rodar(CENARIOS, &bancada(arch, release, &[])?)?;
    }
    if CENARIOS_DE_QUEDA.iter().any(escolhido) {
        rodar(
            CENARIOS_DE_QUEDA,
            &bancada(arch, release, &[p::FEATURE_DE_QUEDAS])?,
        )?;
    }
    // O disco fica zerado para quem vier depois, como todo comando o deixa.
    zerar_o_estado(arch)?;
    if falhas > 0 {
        println!("\n[xtask] atualizacao: {falhas} cenario(s) falharam");
        return Ok(ExitCode::FAILURE);
    }
    println!("\n[xtask] atualizacao: todos os cenarios passaram");
    Ok(ExitCode::SUCCESS)
}

/// Compila o kernel com `features`, que vai para o slot A do disco de
/// testes, e monta as imagens a partir dele.
fn bancada(arch: Arquitetura, release: bool, features: &[&str]) -> Result<Bancada, String> {
    let sem_slot = match build_com(arch, release, features)? {
        Artefato::Binario(img) => Some(Artefato::Binario(img)),
        Artefato::Disco(_) => None,
    };
    Ok(Bancada {
        arch,
        firmware: Artefato::Disco(disco_de_testes()?),
        sem_slot,
        imagens: imagens(arch)?,
    })
}

// ---------------------------------------------------------------------------
// O que a máquina diz
// ---------------------------------------------------------------------------

/// O valor de `result.<caminho>` de uma resposta, em texto: a string, o
/// número, o booleano; `None` para um objeto, um `null` ou a falta.
fn valor(r: &str, caminho: &[&str]) -> Option<String> {
    let mut j = Json(r.as_bytes()).member("result")?;
    for c in caminho {
        j = j.member(c)?;
    }
    j.as_str()
        .map(str::to_string)
        .or_else(|| j.as_u64().map(|n| n.to_string()))
        .or_else(|| j.as_bool().map(|b| b.to_string()))
}

/// Se `result.<caminho>` existe e não é `null`.
fn presente(r: &str, caminho: &[&str]) -> bool {
    let mut j = match Json(r.as_bytes()).member("result") {
        Some(j) => j,
        None => return false,
    };
    for c in caminho {
        match j.member(c) {
            Some(v) => j = v,
            None => return false,
        }
    }
    !j.is_null()
}

/// O `update.status`, lido: o boot, o journal e o controle.
struct Situacao {
    bruto: String,
    reconciliacao: String,
    autoridade: String,
    /// O boot: o slot, o modo, a geração e a versão da imagem conferida.
    slot: String,
    modo: String,
    conferida: bool,
    geracao: u64,
    versao: String,
    /// O journal: o piso, a ativa e a candidata, se há.
    piso: u64,
    ativo: String,
    geracao_ativa: u64,
    candidato: Option<(String, u64)>,
    /// O controle que vale: o bom, a tentativa, as restantes, a falha.
    bom: String,
    tentativa: Option<String>,
    restantes: u64,
    falha: Option<String>,
    sintetizado: bool,
    sequencia: u64,
    gravavel: bool,
}

impl Situacao {
    fn de(r: String) -> Situacao {
        let texto = |c: &[&str]| valor(&r, c).unwrap_or_default();
        let numero = |c: &[&str]| valor(&r, c).and_then(|v| v.parse().ok()).unwrap_or(0);
        Situacao {
            reconciliacao: texto(&["reconciliation"]),
            autoridade: texto(&["authority"]),
            slot: texto(&["booted", "slot"]),
            modo: texto(&["booted", "mode"]),
            conferida: texto(&["booted", "verified"]) == "true",
            geracao: numero(&["booted", "generation"]),
            versao: texto(&["booted", "version"]),
            piso: numero(&["journal", "floor"]),
            ativo: texto(&["journal", "active", "slot"]),
            geracao_ativa: numero(&["journal", "active", "generation"]),
            candidato: presente(&r, &["journal", "candidate"]).then(|| {
                (
                    texto(&["journal", "candidate", "slot"]),
                    numero(&["journal", "candidate", "generation"]),
                )
            }),
            bom: texto(&["control", "good"]),
            tentativa: valor(&r, &["control", "trial"]),
            restantes: numero(&["control", "remaining"]),
            falha: valor(&r, &["control", "failure"]),
            sintetizado: texto(&["control", "synthesized"]) == "true",
            sequencia: numero(&["control", "sequence"]),
            gravavel: texto(&["inactive_writable"]) == "true",
            bruto: r,
        }
    }

    /// Uma linha, para os detalhes e as falhas.
    fn resumo(&self) -> String {
        format!(
            "boot {}/{} g{} ({}); journal piso {} ativa {} g{} candidata {:?}; controle bom {} tentativa {:?} restam {} falha {:?}; {} / {}",
            self.slot,
            self.modo,
            self.geracao,
            self.versao,
            self.piso,
            self.ativo,
            self.geracao_ativa,
            self.candidato,
            self.bom,
            self.tentativa,
            self.restantes,
            self.falha,
            self.reconciliacao,
            self.autoridade
        )
    }

    /// `Ok` se `condicao` vale; senão, o que se esperava e o que veio.
    fn exigir(&self, o_que: &str, condicao: bool) -> Result<(), String> {
        if condicao {
            Ok(())
        } else {
            Err(format!("{o_que}: {}\n  {}", self.resumo(), self.bruto))
        }
    }

    /// A máquina na versão `geracao`, ativa e confirmada no slot `slot`,
    /// sem candidata, e o controle dizendo só ela.
    fn na_versao(&self, o_que: &str, slot: &str, geracao: u64) -> Result<(), String> {
        self.exigir(
            o_que,
            self.slot == slot
                && self.conferida
                && self.geracao == geracao
                && self.autoridade == "granted"
                && self.piso == geracao
                && self.ativo == slot
                && self.geracao_ativa == geracao
                && self.candidato.is_none()
                && self.bom == slot
                && self.tentativa.is_none()
                && !self.sintetizado,
        )
    }
}

fn situacao(m: &mut Ligada) -> Result<Situacao, String> {
    let r = m.pedir("update.status", "{}")?;
    if valor(&r, &["slots"]).as_deref() != Some("true") {
        return Err(format!("o update.status nao diz os slots\n  {r}"));
    }
    Ok(Situacao::de(r))
}

/// Um registro da auditoria: o código, o recurso e o detalhe.
struct Registro {
    codigo: String,
    recurso: String,
    detalhe: String,
}

/// Os registros de `metodo` em toda a auditoria que a máquina guarda: as
/// páginas do `audit.tail` desde o começo. Só a cauda não basta — o boot
/// seguinte a uma recusa registra o bastante, das leituras do tecido de
/// segurança às tentativas de conexão do canal, para empurrar o registro
/// dela para fora dos últimos 128.
fn na_auditoria(m: &mut Ligada, metodo: &str) -> Result<Vec<Registro>, String> {
    let mut v = Vec::new();
    let mut depois = 0u64;
    loop {
        let r = m.pedir(
            "audit.tail",
            &format!(r#"{{"count":128,"after":{depois}}}"#),
        )?;
        let registros = Json(r.as_bytes())
            .member("result")
            .and_then(|j| j.member("records"))
            .ok_or_else(|| format!("o audit.tail nao trouxe registros\n  {r}"))?;
        let mut i = 0;
        while let Some(e) = registros.item(i) {
            i += 1;
            let campo = |n: &str| {
                e.member(n)
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string()
            };
            if let Some(seq) = e.member("seq").and_then(|x| x.as_u64()) {
                depois = depois.max(seq);
            }
            if campo("method") == metodo {
                v.push(Registro {
                    codigo: campo("code"),
                    recurso: campo("resource"),
                    detalhe: campo("detail"),
                });
            }
        }
        if i < 128 {
            return Ok(v);
        }
    }
}

/// Um registro de `metodo` com o código `codigo` e `trecho` no detalhe.
fn auditado(m: &mut Ligada, metodo: &str, codigo: &str, trecho: &str) -> Result<(), String> {
    let registros = na_auditoria(m, metodo)?;
    if registros
        .iter()
        .any(|r| r.codigo == codigo && r.detalhe.contains(trecho))
    {
        return Ok(());
    }
    Err(format!(
        "a auditoria nao tem {metodo} {codigo} com `{trecho}`: {:?}",
        registros
            .iter()
            .map(|r| format!("{} {}: {}", r.codigo, r.recurso, r.detalhe))
            .collect::<Vec<_>>()
    ))
}

/// Pede o reinício pelo comando, e espera o boot seguinte atender.
fn reiniciar(m: &mut Ligada, arch: Arquitetura) -> Result<(), String> {
    let antes = p::persistencia_de(m)?.boots;
    let r = m.pedir("system.reboot", "{}")?;
    if !r.contains(r#""state":"rebooting""#) {
        return Err(format!("o reinicio nao foi aceito\n  {r}"));
    }
    m.esperar_o_boot_ate(antes, espera(arch)).map(|_| ())
}

// ---------------------------------------------------------------------------
// O que a bancada pede
// ---------------------------------------------------------------------------

/// Escreve a imagem inteira no slot inativo pelo agente `sistema`, como o
/// operador faria — ver `producao::encenar`.
fn encenar(arch: Arquitetura, bytes: &[u8]) -> Result<(), String> {
    let mut agente = AgenteNaPorta::conectar(arch, PORTA_DO_SISTEMA)?;
    producao::encenar(&mut agente, bytes).map(|_| ())
}

/// Escreve `depois` no slot inativo sabendo que ele já tem `antes`: só os
/// pedaços que diferem — as imagens da bancada têm o mesmo kernel, e
/// mudam no cabeçalho e no pacote. Pelo canal do agente, uma imagem
/// inteira leva perto de um minuto. Um `antes` errado não faz nada passar:
/// a instalação confere o slot inteiro, e o que não bate é recusado.
fn encenar_sobre(arch: Arquitetura, antes: &[u8], depois: &[u8]) -> Result<(), String> {
    let mut agente = AgenteNaPorta::conectar(arch, PORTA_DO_SISTEMA)?;
    encenar_sobre_por(&mut agente, antes, depois)
}

/// [`encenar_sobre`] por uma conexão que já está aberta.
fn encenar_sobre_por(
    agente: &mut AgenteNaPorta,
    antes: &[u8],
    depois: &[u8],
) -> Result<(), String> {
    let pedaco = producao::PEDACO_DA_ENCENACAO;
    for (i, novo) in depois.chunks(pedaco).enumerate() {
        let de = i * pedaco;
        if antes.get(de..de + novo.len()) == Some(novo) {
            continue;
        }
        let r = agente.pedir_com_anexo("update.stage", &format!(r#"{{"offset":{de}}}"#), novo)?;
        if !r.contains(r#""written":"#) {
            return Err(format!("o update.stage parou no byte {de}\n  {r}"));
        }
    }
    Ok(())
}

/// O que o slot B tem depois de [`zerar_o_estado`], se antes tinha
/// `imagem`: ela, com o cabeçalho apagado.
fn sem_cabecalho(imagem: &[u8]) -> Vec<u8> {
    let mut v = imagem.to_vec();
    v[..cabecalho::TAM_CABECALHO].fill(0);
    v
}

/// Escreve `imagem` no slot inativo no caso `i` de um laço que zera o
/// estado entre os casos: inteira no primeiro; nos outros, o slot B ainda
/// tem a do caso anterior sem o cabeçalho — ver [`sem_cabecalho`].
fn encenar_no_caso(arch: Arquitetura, i: usize, imagem: &[u8]) -> Result<(), String> {
    if i == 0 {
        encenar(arch, imagem)
    } else {
        encenar_sobre(arch, &sem_cabecalho(imagem), imagem)
    }
}

/// Um `update.stage` cru, de `bytes` a partir de `de`: a resposta.
fn encenar_em(arch: Arquitetura, porta: u8, de: u64, bytes: &[u8]) -> Result<String, String> {
    let mut agente = AgenteNaPorta::conectar(arch, porta)?;
    encenar_em_por(&mut agente, de, bytes)
}

/// [`encenar_em`] por uma conexão que já está aberta.
fn encenar_em_por(agente: &mut AgenteNaPorta, de: u64, bytes: &[u8]) -> Result<String, String> {
    agente.pedir_com_anexo("update.stage", &format!(r#"{{"offset":{de}}}"#), bytes)
}

fn parametros(acao: &str, resumo: &[u8; 32]) -> String {
    format!(
        r#"{{"action":"{acao}","manifest":"{}"}}"#,
        sigilo::hex(resumo)
    )
}

/// O `system.update` pela serial, assinado pelas credenciais `quem`.
fn quorum(
    m: &mut Ligada,
    arch: Arquitetura,
    acao: &str,
    resumo: &[u8; 32],
    quem: &[usize],
) -> Result<String, String> {
    let c = chaves::Chaves::garantir()?;
    m.quorum(arch, &c, "system.update", &parametros(acao, resumo), quem)
}

/// A instalação de `resumo` por duas credenciais, que tem de valer.
fn instalar(m: &mut Ligada, arch: Arquitetura, resumo: &[u8; 32]) -> Result<(), String> {
    let r = quorum(m, arch, "install", resumo, &[0, 1])?;
    if !p::executou(&r) || !r.contains(r#""control_written":true"#) {
        return Err(format!("a instalacao nao valeu\n  {r}"));
    }
    Ok(())
}

/// A desistência de `resumo` por duas credenciais, que tem de valer.
fn cancelar(m: &mut Ligada, arch: Arquitetura, resumo: &[u8; 32]) -> Result<(), String> {
    let r = quorum(m, arch, "cancel", resumo, &[1, 2])?;
    if !p::executou(&r) {
        return Err(format!("a desistencia nao valeu\n  {r}"));
    }
    Ok(())
}

/// `r` é uma recusa, com `trecho` no motivo.
fn recusado(o_que: &str, r: &str, trecho: &str) -> Result<(), String> {
    if p::executou(r) || r.contains(r#""written":"#) || !r.contains(trecho) {
        return Err(format!("{o_que}: nao foi recusado com `{trecho}`\n  {r}"));
    }
    Ok(())
}

/// A atualização inteira para `nova`: escrita, instalada, o reinício, a
/// tentativa e a confirmação — e a máquina nela.
fn atualizar(
    m: &mut Ligada,
    b: &Bancada,
    nova: &slots::Imagem,
    geracao: u64,
) -> Result<(), String> {
    encenar(b.arch, &nova.bytes)?;
    instalar(m, b.arch, &nova.resumo)?;
    reiniciar(m, b.arch)?;
    let s = situacao(m)?;
    let slot = s.ativo.clone();
    s.na_versao("depois da atualizacao", &slot, geracao)?;
    s.exigir(
        "a versao nova confirmada na tentativa",
        s.modo == "tentativa" && s.reconciliacao == "confirmar no fim do boot",
    )
}

// ---------------------------------------------------------------------------
// O disco, com a máquina desligada
// ---------------------------------------------------------------------------

/// Reescreve o controle que vale, mudado por `mudar`, com a sequência
/// adiante: o que alguém com o disco na mão pode fazer — o controle não
/// tem segredo, e quem decide é o kernel.
fn forjar(disco: &Path, mudar: impl FnOnce(&mut Controle)) -> Result<(), String> {
    let (i, mut c) =
        slots::controle_valido(disco)?.ok_or("o disco nao tem controle valido para forjar")?;
    mudar(&mut c);
    c.sequencia += 10;
    slots::escrever_copia(disco, 1 - i, &c)
}

/// O resumo do manifesto que está no slot `s` do disco.
fn manifesto_no_slot(disco: &Path, s: Slot) -> Result<[u8; 32], String> {
    let cab = slots::ler_em(disco, disco::slot_em(s) * 512, cabecalho::TAM_CABECALHO)?;
    let c = cabecalho::ler(&cab).map_err(|m| format!("o slot {}: {m}", s.nome()))?;
    Ok(atualizacao::manifesto::resumo_do_manifesto(c.manifesto))
}

/// Troca um byte no meio do kernel do slot `s`: o resumo não confere mais.
fn estragar_o_kernel(disco: &Path, s: Slot) -> Result<(), String> {
    let em = disco::slot_em(s) * 512 + KERNEL_EM + 1_000_000;
    let mut b = slots::ler_em(disco, em, 1)?;
    b[0] ^= 0x5A;
    slots::escrever_em(disco, em, &b)
}

/// O slot `s` inteiro em zeros.
fn zerar_o_slot(disco: &Path, s: Slot) -> Result<(), String> {
    let zeros = vec![0u8; 1 << 20];
    let inicio = disco::slot_em(s) * 512;
    let fim = inicio + disco::SLOT_SETORES * 512;
    let mut em = inicio;
    while em < fim {
        let n = ((fim - em) as usize).min(zeros.len());
        slots::escrever_em(disco, em, &zeros[..n])?;
        em += n as u64;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Os cenários
// ---------------------------------------------------------------------------

/// O primeiro boot sobre o estado zerado: o slot A, conferido; a linha de
/// base no journal — o piso é a geração dele —; o controle, que o `xtask`
/// gravou igual, não muda. O segundo boot só segue.
fn o_primeiro_boot(b: &Bancada) -> Result<String, String> {
    let mut m = b.subir()?;
    let r = (|| {
        let s = situacao(&mut m)?;
        s.na_versao("o primeiro boot", "a", 1)?;
        s.exigir(
            "a linha de base no primeiro boot, com o B gravavel",
            s.modo == "normal" && s.reconciliacao == "linha de base" && s.gravavel,
        )?;
        auditado(&mut m, "system.update.baseline", "ALLOW", "linha de base")?;
        Ok::<_, String>(s.sequencia)
    })();
    m.cortar_a_energia()?;
    let sequencia = r?;
    let mut m = b.subir()?;
    let s = situacao(&mut m);
    m.cortar_a_energia()?;
    let s = s?;
    s.na_versao("o segundo boot", "a", 1)?;
    s.exigir(
        "o segundo boot segue, sem gravar o controle",
        s.reconciliacao == "seguir" && s.sequencia == sequencia,
    )?;
    Ok(format!(
        "slot a, geracao 1, piso 1, controle na sequencia {sequencia}; o segundo boot segue"
    ))
}

/// A atualização de ponta a ponta, e o estado da máquina de antes dela,
/// inteiro depois: um agente registrado, um arquivo no armazém, a cadeia
/// da auditoria, a geração administrativa.
fn a_atualizacao_inteira(b: &Bancada) -> Result<String, String> {
    let c = chaves::Chaves::garantir()?;
    let mut m = b.subir()?;
    let r = (|| -> Result<String, String> {
        let r = p::administrar(
            &mut m,
            &c.administrador,
            "agent.register",
            &p::registro_de_agente(&[0xB1; 32], "antes-da-versao", "observador"),
        )?;
        if !p::executou(&r) {
            return Err(format!("o registro de antes nao valeu\n  {r}"));
        }
        for (metodo, params) in [
            ("fs.mkdir", r#"{"path":"/armazem/sistema"}"#),
            (
                "fs.write",
                r#"{"path":"/armazem/sistema/atualizacao.txt","content":"de antes da versao nova","expect_version":0}"#,
            ),
        ] {
            let r = m.pedir(metodo, params)?;
            if !r.contains(r#""ok":true"#) {
                return Err(format!("{metodo} no armazem\n  {r}"));
            }
        }
        // A pessoa troca a própria senha antes da versão nova: a troca vai
        // ao journal, que fica fora dos slots.
        let (_, _, senha) = c.pessoa_dev();
        let mut t = super::senha::teclado(b.arch)?;
        super::senha::terminal_atendendo(&mut m, &mut t)?;
        let login = super::senha::entrar(&mut m, &mut t, chaves::NOME_DA_PESSOA_DEV, &senha)?;
        if login != "ALLOW" {
            return Err(format!("a pessoa de desenvolvimento nao entrou: {login}"));
        }
        let troca = super::senha::trocar(&mut m, &mut t, &senha, super::senha::SENHA_NOVA)?;
        if troca.codigo != "ALLOW" || !troca.duravel {
            return Err(format!("a troca da senha antes da versao nova: {troca:?}"));
        }
        let antes = p::persistencia_de(&mut m)?;

        encenar(b.arch, &b.imagens.nova.bytes)?;
        let s = situacao(&mut m)?;
        s.exigir(
            "escrita, ainda nao armada",
            s.candidato.is_none() && s.tentativa.is_none() && s.gravavel,
        )?;
        instalar(&mut m, b.arch, &b.imagens.nova.resumo)?;
        let s = situacao(&mut m)?;
        s.exigir(
            "instalada: a candidata no journal e a tentativa no controle",
            s.candidato == Some(("b".into(), GERACAO_NOVA))
                && s.bom == "a"
                && s.tentativa.as_deref() == Some("b")
                && s.restantes == u64::from(TENTATIVAS)
                && s.slot == "a",
        )?;
        auditado(&mut m, "system.update", "ALLOW", "instalar")?;

        reiniciar(&mut m, b.arch)?;
        let s = situacao(&mut m)?;
        s.na_versao("a versao nova", "b", GERACAO_NOVA)?;
        s.exigir(
            "a versao nova bootou numa tentativa e se confirmou",
            s.modo == "tentativa"
                && s.reconciliacao == "confirmar no fim do boot"
                && s.versao == VERSAO_NOVA
                && s.gravavel,
        )?;
        auditado(&mut m, "system.update.attempt", "ALLOW", "tentativa")?;
        auditado(&mut m, "system.update.confirm", "ALLOW", "confirmada")?;
        let marca = m.pedir("fs.read", r#"{"path":"/versao/marca"}"#)?;
        if !marca.contains(VERSAO_NOVA) {
            return Err(format!("o pacote da versao nova nao montou\n  {marca}"));
        }

        // O estado de antes, inteiro.
        let registro = m.pedir("agent.registry", "{}")?;
        if !registro.contains("antes-da-versao") {
            return Err(format!(
                "o agente registrado antes sumiu na atualizacao\n  {registro}"
            ));
        }
        let arquivo = m.pedir("fs.read", r#"{"path":"/armazem/sistema/atualizacao.txt"}"#)?;
        if !arquivo.contains("de antes da versao nova") {
            return Err(format!("o armazem perdeu o arquivo de antes\n  {arquivo}"));
        }
        // A senha trocada antes: a versão nova a repôs do journal — a
        // antiga não entra, a nova entra.
        let mut t = super::senha::teclado(b.arch)?;
        super::senha::terminal_atendendo(&mut m, &mut t)?;
        if super::senha::entra_com(
            &mut m,
            &mut t,
            chaves::NOME_DA_PESSOA_DEV,
            &senha,
            super::senha::SENHA_NOVA,
        )? {
            return Err("na versao nova, a senha de antes da troca entra".into());
        }
        p::auditoria_verifica(&mut m)?;
        let depois = p::persistencia_de(&mut m)?;
        if depois.estado != "available"
            || depois.ek != antes.ek
            || depois.geracao <= antes.geracao
            || depois.boots <= antes.boots
        {
            return Err(format!(
                "a persistencia depois da atualizacao: {} ({}), EK {} e nao {}, geracao {} depois de {}",
                depois.estado, depois.motivo, depois.ek, antes.ek, depois.geracao, antes.geracao
            ));
        }

        // E o boot seguinte, normal.
        reiniciar(&mut m, b.arch)?;
        let s = situacao(&mut m)?;
        s.na_versao("o boot depois da confirmacao", "b", GERACAO_NOVA)?;
        s.exigir(
            "o boot seguinte segue na nova",
            s.modo == "normal" && s.reconciliacao == "seguir",
        )?;
        Ok(format!(
            "slot a g1 -> slot b g{GERACAO_NOVA} ({VERSAO_NOVA}), piso {}; o agente, o armazem, a senha trocada e a cadeia continuam; geracao administrativa {} -> {}",
            s.piso, antes.geracao, depois.geracao
        ))
    })();
    m.cortar_a_energia()?;
    r
}

/// Depois da atualização, a velha — o slot A — não boota com autoridade:
/// nem com o controle forjado dizendo que ela é a boa, nem reescrita no
/// slot e armada como tentativa. Nos dois, o kernel dela se recusa, regrava
/// o controle pelo journal, e a máquina volta sozinha para a nova.
fn a_versao_velha_nao_volta(b: &Bancada) -> Result<String, String> {
    let disco = b.disco()?;
    let mut m = b.subir()?;
    let r = atualizar(&mut m, b, &b.imagens.nova, GERACAO_NOVA);
    m.cortar_a_energia()?;
    r?;

    let velha_no_a = manifesto_no_slot(&disco, Slot::A)?;
    forjar(&disco, |c| {
        c.bom = Slot::A;
        c.tentativa = None;
        c.restantes = 0;
        c.manifestos[0] = velha_no_a;
    })?;
    let mut m = b.subir()?;
    let r = (|| {
        let s = situacao(&mut m)?;
        s.na_versao("depois do controle forjado para a velha", "b", GERACAO_NOVA)?;
        auditado(
            &mut m,
            "system.update.refuse",
            "DENY_POLICY",
            "a imagem e anterior ao piso",
        )
    })();
    m.cortar_a_energia()?;
    r?;

    slots::escrever_no_slot(&disco, Slot::A, &b.imagens.velha.bytes)?;
    let velha = b.imagens.velha.resumo;
    forjar(&disco, |c| {
        c.tentativa = Some(Slot::A);
        c.restantes = TENTATIVAS;
        c.falha = Falha::Nenhuma;
        c.manifestos[0] = velha;
    })?;
    let mut m = b.subir()?;
    let r = (|| {
        let s = situacao(&mut m)?;
        s.na_versao("depois da velha armada a mao", "b", GERACAO_NOVA)?;
        let recusas = na_auditoria(&mut m, "system.update.refuse")?
            .into_iter()
            .filter(|r| r.detalhe.contains("anterior ao piso"))
            .count();
        if recusas < 2 {
            return Err(format!(
                "as duas voltas da velha nao estao na auditoria: {recusas}"
            ));
        }
        Ok(())
    })();
    m.cortar_a_energia()?;
    r?;
    Ok("o controle forjado e a velha armada a mao: recusadas abaixo do piso, e a maquina de volta na nova".into())
}

/// A versão nova que não carrega volta no mesmo boot: o iniciador marca a
/// recusa no controle e boota a velha, desfeita, que tira a candidata do
/// journal. O kernel estragado no disco depois da instalação, e um que não
/// é ELF — assinado, de resumos certos, e aceito pela instalação.
fn a_versao_nova_que_nao_carrega(b: &Bancada) -> Result<String, String> {
    let disco = b.disco()?;
    let mut m = b.subir()?;
    let r = (|| {
        encenar(b.arch, &b.imagens.nova.bytes)?;
        instalar(&mut m, b.arch, &b.imagens.nova.resumo)
    })();
    m.cortar_a_energia()?;
    r?;
    estragar_o_kernel(&disco, Slot::B)?;
    let mut m = b.subir()?;
    let r = (|| {
        let s = situacao(&mut m)?;
        s.na_versao("depois do kernel estragado", "a", 1)?;
        s.exigir(
            "a velha, desfeita",
            s.modo == "desfeita" && s.reconciliacao == "desfazer",
        )?;
        auditado(
            &mut m,
            "system.update.rollback",
            "ALLOW",
            Falha::CargaRecusada.motivo(),
        )?;

        encenar(b.arch, &b.imagens.quebrada.bytes)?;
        instalar(&mut m, b.arch, &b.imagens.quebrada.resumo)?;
        reiniciar(&mut m, b.arch)?;
        let s = situacao(&mut m)?;
        s.na_versao("depois do kernel que nao e ELF", "a", 1)?;
        s.exigir(
            "a velha, desfeita de novo",
            s.modo == "desfeita" && s.reconciliacao == "desfazer",
        )?;
        let desfeitas = na_auditoria(&mut m, "system.update.rollback")?
            .into_iter()
            .filter(|r| r.detalhe.contains(Falha::CargaRecusada.motivo()))
            .count();
        if desfeitas < 2 {
            return Err(format!(
                "os dois desfazimentos nao estao na auditoria: {desfeitas}"
            ));
        }
        Ok(())
    })();
    m.cortar_a_energia()?;
    r?;
    Ok("o kernel estragado e o que nao e ELF: o iniciador recusou a carga, e a velha desfez as duas no mesmo boot".into())
}

/// Cada recusa da instalação, numa máquina só, e nenhuma muda o journal ou
/// o controle. Depois, a instalação certa vale, a escrita com ela armada é
/// recusada, a desistência com o manifesto errado também, e a certa vale.
fn as_recusas_da_instalacao(b: &Bancada) -> Result<String, String> {
    let c = chaves::Chaves::garantir()?;
    let mut m = b.subir()?;
    let r = (|| -> Result<String, String> {
        let antes = situacao(&mut m)?;
        let arch = b.arch;
        let im = &b.imagens;
        let mut recusas = Vec::new();
        // Uma conexão só pela porta do sistema, para todas as escritas: a
        // política limita os apertos de mão a dez por porta a cada dez
        // segundos (`apertos 10 10000`), e o cenário escreve no slot uma
        // dúzia de vezes no mesmo boot. Com uma conexão por escrita, um
        // emulador mais rápido punha onze apertos na mesma janela, e o
        // décimo primeiro era recusado — como deve.
        let mut sistema = AgenteNaPorta::conectar(arch, PORTA_DO_SISTEMA)?;

        producao::encenar(&mut sistema, &im.estranha.bytes)?;
        let r = quorum(&mut m, arch, "install", &im.estranha.resumo, &[0, 1])?;
        recusado("a chave de fora", &r, "nao esta no registro de atualizacao")?;
        recusas.push("chave de fora");

        encenar_sobre_por(&mut sistema, &im.estranha.bytes, &im.velha.bytes)?;
        let r = quorum(&mut m, arch, "install", &im.velha.resumo, &[0, 1])?;
        recusado("a geracao que nao sobe", &r, "nao e maior que a da ativa")?;
        recusas.push("geracao");

        encenar_sobre_por(&mut sistema, &im.velha.bytes, &im.outro_formato.bytes)?;
        let r = quorum(&mut m, arch, "install", &im.outro_formato.resumo, &[0, 1])?;
        recusado(
            "o formato de estado incompativel",
            &r,
            "nao le o formato de estado",
        )?;
        recusas.push("formato de estado");

        encenar_sobre_por(
            &mut sistema,
            &im.outro_formato.bytes,
            &im.outra_arquitetura.bytes,
        )?;
        let r = quorum(
            &mut m,
            arch,
            "install",
            &im.outra_arquitetura.resumo,
            &[0, 1],
        )?;
        recusado("a outra arquitetura", &r, "a imagem e de outra arquitetura")?;
        recusas.push("outra arquitetura");

        encenar_sobre_por(&mut sistema, &im.outra_arquitetura.bytes, &im.nova.bytes)?;
        let r = quorum(&mut m, arch, "install", &im.estranha.resumo, &[0, 1])?;
        recusado("o manifesto trocado", &r, "nao e o que se esperava")?;
        recusas.push("manifesto trocado");

        // A assinatura adulterada, com a chave do registro e o manifesto
        // certo: um byte dela trocado no cabeçalho.
        let mut adulterada = im.nova.bytes[..512].to_vec();
        adulterada[16] ^= 0x01;
        let r = encenar_em_por(&mut sistema, 0, &adulterada)?;
        if !r.contains(r#""written":"#) {
            return Err(format!("a assinatura adulterada nao foi escrita\n  {r}"));
        }
        let r = quorum(&mut m, arch, "install", &im.nova.resumo, &[0, 1])?;
        recusado(
            "a assinatura adulterada",
            &r,
            "a assinatura do manifesto nao confere",
        )?;
        recusas.push("assinatura adulterada");
        encenar_em_por(&mut sistema, 0, &im.nova.bytes[..512])?;

        // O kernel estragado no slot: um pedaço de zeros no meio dele.
        let zeros = vec![0u8; producao::PEDACO_DA_ENCENACAO];
        let r = encenar_em_por(&mut sistema, KERNEL_EM + (1 << 20), &zeros)?;
        if !r.contains(r#""written":"#) {
            return Err(format!(
                "os zeros no meio do kernel nao foram escritos\n  {r}"
            ));
        }
        let r = quorum(&mut m, arch, "install", &im.nova.resumo, &[0, 1])?;
        recusado(
            "o kernel estragado",
            &r,
            "o kernel do slot nao bate com o manifesto",
        )?;
        recusas.push("kernel estragado");
        let mut estragado = im.nova.bytes.clone();
        let k = (KERNEL_EM + (1 << 20)) as usize;
        let fim = (k + zeros.len()).min(estragado.len());
        estragado[k..fim].copy_from_slice(&zeros[..fim - k]);

        // O pacote estragado.
        encenar_sobre_por(&mut sistema, &estragado, &im.nova.bytes)?;
        let kernel = slots::kernel_da_imagem(&im.nova.bytes)?;
        let pacote_em = cabecalho::pacote_em(kernel.len() as u64);
        let r = encenar_em_por(&mut sistema, pacote_em, &zeros[..512])?;
        if !r.contains(r#""written":"#) {
            return Err(format!("os zeros no pacote nao foram escritos\n  {r}"));
        }
        let r = quorum(&mut m, arch, "install", &im.nova.resumo, &[0, 1])?;
        recusado("o pacote estragado", &r, "o pacote")?;
        recusas.push("pacote estragado");

        let r = encenar_em_por(
            &mut sistema,
            pacote_em,
            &im.nova.bytes[pacote_em as usize..pacote_em as usize + 512],
        )?;
        if !r.contains(r#""written":"#) {
            return Err(format!("o pacote de volta nao foi escrito\n  {r}"));
        }
        let r = quorum(&mut m, arch, "install", &im.nova.resumo, &[0])?;
        recusado("o quorum incompleto", &r, "quorum incompleto")?;
        recusas.push("quorum incompleto");

        let r = p::administrar(
            &mut m,
            &c.administrador,
            "system.update",
            &parametros("install", &im.nova.resumo),
        )?;
        recusado(
            "a credencial sozinha",
            &r,
            "operacao administrativa desconhecida",
        )?;
        recusas.push("credencial sozinha");

        let r = encenar_em(arch, PORTA_DO_OPERADOR, 0, &zeros[..512])?;
        recusado("a escrita do operador", &r, "DENY")?;
        recusas.push("operador escrevendo");

        let depois = situacao(&mut m)?;
        depois.exigir(
            "nada mudou com as recusas",
            depois.candidato.is_none()
                && depois.tentativa.is_none()
                && depois.sequencia == antes.sequencia
                && depois.piso == antes.piso,
        )?;
        for metodo in ["system.update", "update.stage"] {
            let negadas = na_auditoria(&mut m, metodo)?
                .into_iter()
                .filter(|r| r.codigo != "ALLOW")
                .count();
            if negadas == 0 {
                return Err(format!("nenhuma recusa de {metodo} na auditoria"));
            }
        }

        // A certa vale; com ela armada, a escrita e a desistência errada são
        // recusadas; a desistência certa vale.
        instalar(&mut m, arch, &im.nova.resumo)?;
        let r = encenar_em_por(&mut sistema, 0, &zeros[..512])?;
        recusado(
            "a escrita com a versao armada",
            &r,
            "ha uma versao nova armada",
        )?;
        let r = quorum(&mut m, arch, "cancel", &im.estranha.resumo, &[1, 2])?;
        recusado("a desistencia de outra", &r, "o manifest nao confere")?;
        cancelar(&mut m, arch, &im.nova.resumo)?;
        let s = situacao(&mut m)?;
        s.exigir(
            "a desistencia tirou a candidata e a tentativa",
            s.candidato.is_none() && s.tentativa.is_none() && s.bom == "a",
        )?;
        auditado(&mut m, "system.update", "ALLOW", "cancelar")?;
        Ok(format!(
            "{} recusas sem mudar nada ({}); a instalacao e a desistencia certas valem",
            recusas.len(),
            recusas.join(", ")
        ))
    })();
    m.cortar_a_energia()?;
    r
}

/// A versão cancelada, com o controle armado de novo à mão — como se a
/// gravação do controle da desistência tivesse se perdido —, boota na
/// tentativa e se recusa: o journal não a tem. A máquina volta para a
/// velha sozinha.
fn a_versao_cancelada_nao_boota(b: &Bancada) -> Result<String, String> {
    let disco = b.disco()?;
    let mut m = b.subir()?;
    let r = (|| {
        encenar(b.arch, &b.imagens.nova.bytes)?;
        instalar(&mut m, b.arch, &b.imagens.nova.resumo)?;
        cancelar(&mut m, b.arch, &b.imagens.nova.resumo)
    })();
    m.cortar_a_energia()?;
    r?;
    let nova = b.imagens.nova.resumo;
    forjar(&disco, |c| {
        c.tentativa = Some(Slot::B);
        c.restantes = TENTATIVAS;
        c.falha = Falha::Nenhuma;
        c.manifestos[1] = nova;
    })?;
    let mut m = b.subir()?;
    let r = (|| {
        let s = situacao(&mut m)?;
        s.na_versao("depois da cancelada armada a mao", "a", 1)?;
        auditado(
            &mut m,
            "system.update.refuse",
            "DENY_POLICY",
            "nem a versao nova armada",
        )
    })();
    m.cortar_a_energia()?;
    r?;
    Ok("a cancelada bootou na tentativa, recusou a si mesma, e a velha seguiu".into())
}

/// As duas cópias do controle estragadas — com um slot só, e com os dois
/// depois de uma atualização —: o iniciador sintetiza um controle pelos
/// cabeçalhos dos slots, e o kernel o regrava pelo journal. A máquina
/// termina na ativa do journal, com o controle íntegro.
fn as_duas_copias_estragadas(b: &Bancada) -> Result<String, String> {
    let disco = b.disco()?;
    let m = b.subir()?;
    m.cortar_a_energia()?;
    slots::estragar_copia(&disco, 0)?;
    slots::estragar_copia(&disco, 1)?;
    let mut m = b.subir()?;
    let r = (|| {
        let s = situacao(&mut m)?;
        s.na_versao("com um slot so", "a", 1)?;
        atualizar(&mut m, b, &b.imagens.nova, GERACAO_NOVA)
    })();
    m.cortar_a_energia()?;
    r?;
    slots::estragar_copia(&disco, 0)?;
    slots::estragar_copia(&disco, 1)?;
    let mut m = b.subir()?;
    let r = situacao(&mut m);
    m.cortar_a_energia()?;
    let s = r?;
    s.na_versao("com os dois slots", "b", GERACAO_NOVA)?;
    Ok(format!(
        "com um slot, o A; com os dois, o B, a ativa do journal ({})",
        s.reconciliacao
    ))
}

/// A tentativa sem o TPM — ou diante de outro —: a versão nova não abre a
/// persistência, recusa a si mesma, e o iniciador volta para a velha, que
/// também não tem o journal. Com o TPM de volta, a velha desfaz a
/// candidata pelo journal.
fn sem_o_tpm_na_tentativa(b: &Bancada) -> Result<String, String> {
    let arch = b.arch;
    let mut feitos = Vec::new();
    for (i, (caso, trocar)) in [("sem TPM", false), ("com outro TPM", true)]
        .into_iter()
        .enumerate()
    {
        if trocar {
            zerar_o_estado(arch)?;
        }
        let mut m = b.subir()?;
        let r = (|| {
            encenar_no_caso(arch, i, &b.imagens.nova.bytes)?;
            instalar(&mut m, arch, &b.imagens.nova.resumo)
        })();
        m.cortar_a_energia()?;
        r?;
        let estado = super::diretorio_do_tpm(arch).join("estado");
        let guardado = super::diretorio_do_tpm(arch).join("guardado");
        let ambiente = if trocar {
            p::copiar_diretorio(&estado, &guardado)?;
            let _ = std::fs::remove_dir_all(&estado);
            std::fs::create_dir_all(&estado).map_err(|e| e.to_string())?;
            Ambiente::ligar(arch, None)?
        } else {
            Ambiente::sem_tpm(None)
        };
        let mut m = b.subir_com(ambiente)?;
        let r = situacao(&mut m);
        m.cortar_a_energia()?;
        let s = r?;
        s.exigir(
            &format!("{caso}: a velha, desfeita, sem persistencia"),
            s.slot == "a"
                && s.modo == "desfeita"
                && s.reconciliacao == "sem persistencia"
                && s.tentativa.as_deref() == Some("b")
                && s.restantes == 0
                && s.falha.as_deref() == Some(Falha::ValidacaoRecusada.motivo()),
        )?;
        if trocar {
            p::copiar_diretorio(&guardado, &estado)?;
            let _ = std::fs::remove_dir_all(&guardado);
        }
        let mut m = b.subir()?;
        let r = (|| {
            let s = situacao(&mut m)?;
            s.na_versao(&format!("{caso}: com o TPM de volta"), "a", 1)?;
            s.exigir("desfeita pelo journal", s.reconciliacao == "desfazer")?;
            auditado(
                &mut m,
                "system.update.rollback",
                "ALLOW",
                Falha::ValidacaoRecusada.motivo(),
            )
        })();
        m.cortar_a_energia()?;
        r?;
        feitos.push(caso);
    }
    Ok(format!(
        "{}: a tentativa acabou sem confirmar, e a velha desfez com o TPM de volta",
        feitos.join(" e ")
    ))
}

/// O disco que falha no slot inativo — o erro de mídia do disco hostil,
/// ver [`super::disco_hostil`] —, em cada passo da atualização: a escrita
/// que o disco recusa não arma nada; a instalação que não consegue ler o
/// slot é recusada; e a versão nova instalada que o iniciador não consegue
/// ler volta para a velha no mesmo boot, que a desfaz. Em todo passo, a
/// ativa segue com a autoridade. Com o disco de volta, a mesma versão se
/// instala, boota e se confirma.
fn o_disco_que_falha(b: &Bancada) -> Result<String, String> {
    let arch = b.arch;
    let hostil = DiscoHostil::servir(
        &b.disco()?,
        &p::socket_do_disco_hostil(arch),
        Corte::PerdeTudo,
    )?;
    let slot_b = Faixa {
        primeiro: disco::SLOT_B_EM,
        quantos: disco::SLOT_SETORES,
    };
    let nova = &b.imagens.nova;
    let ambiente = || Ambiente::ligar(arch, None).map(|a| a.com_disco_hostil(hostil.socket()));
    let mut m = b.subir_com(ambiente()?)?;
    let r = (|| -> Result<(), String> {
        hostil.erro_em(Some((slot_b, Sentido::Escrita)));
        let r = encenar_em(
            arch,
            PORTA_DO_SISTEMA,
            0,
            &nova.bytes[..producao::PEDACO_DA_ENCENACAO],
        );
        hostil.erro_em(None);
        recusado(
            "a escrita que o disco recusa",
            &r?,
            "o dispositivo recusou a escrita",
        )?;
        situacao(&mut m)?.na_versao("depois da escrita recusada", "a", 1)?;

        encenar(arch, &nova.bytes)?;
        hostil.erro_em(Some((slot_b, Sentido::Leitura)));
        let r = quorum(&mut m, arch, "install", &nova.resumo, &[0, 1]);
        hostil.erro_em(None);
        recusado(
            "a instalacao que nao le o slot",
            &r?,
            "o dispositivo recusou a leitura",
        )?;
        situacao(&mut m)?.na_versao("depois da instalacao sem o disco", "a", 1)?;

        instalar(&mut m, arch, &nova.resumo)?;
        hostil.erro_em(Some((slot_b, Sentido::Leitura)));
        let r = reiniciar(&mut m, arch);
        hostil.erro_em(None);
        r?;
        let s = situacao(&mut m)?;
        s.na_versao("depois da carga sem o disco", "a", 1)?;
        s.exigir(
            "a velha, desfeita",
            s.modo == "desfeita" && s.reconciliacao == "desfazer",
        )?;
        auditado(
            &mut m,
            "system.update.rollback",
            "ALLOW",
            Falha::CargaRecusada.motivo(),
        )?;

        instalar(&mut m, arch, &nova.resumo)?;
        reiniciar(&mut m, arch)?;
        situacao(&mut m)?.na_versao("com o disco de volta", "b", GERACAO_NOVA)
    })();
    m.cortar_a_energia()?;
    r?;
    let contas = hostil.contas();
    Ok(format!(
        "a escrita e a instalacao recusadas pelo disco, a carga sem ele desfeita, e a versao nova confirmada com ele de volta ({contas:?})"
    ))
}

/// Duas instalações ao mesmo tempo — pela serial e pela porta do agente
/// `sistema`, cada uma com o seu desafio e o seu quórum —: uma vale, a
/// outra é recusada. Depois, uma escrita da imagem de fora disputa o slot
/// com uma instalação da nova: o que vale é coerente — ou a escrita veio
/// antes e a instalação é recusada, ou a instalação armou e a escrita não
/// passou por cima. A máquina termina na nova, que boota e se confirma: um
/// slot trocado depois de armado seria recusado pelo iniciador.
fn a_concorrencia(b: &Bancada) -> Result<String, String> {
    let arch = b.arch;
    let c = chaves::Chaves::garantir()?;
    let mut m = b.subir()?;
    let r = (|| -> Result<String, String> {
        encenar(arch, &b.imagens.nova.bytes)?;
        let params = parametros("install", &b.imagens.nova.resumo);
        let desafio = m.pedir("admin.challenge", r#"{"for":"system.update"}"#)?;
        let pela_serial = super::assinar_quorum_da_bancada(
            arch,
            &c,
            &desafio,
            0,
            "system.update",
            &params,
            &[0, 1],
        )?;
        let mut porta = AgenteNaPorta::conectar(arch, PORTA_DO_SISTEMA)?;
        let sessao = porta.pedir("agent.session", "{}")?;
        let sessao: u8 = super::campo_simples(&sessao, "session")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("a sessao da porta nao diz o numero\n  {sessao}"))?;
        let desafio = porta.pedir("admin.challenge", r#"{"for":"system.update"}"#)?;
        let pela_porta = super::assinar_quorum_da_bancada(
            arch,
            &c,
            &desafio,
            sessao,
            "system.update",
            &params,
            &[1, 2],
        )?;
        let id = m.mandar("admin.execute", &pela_serial)?;
        let fio = std::thread::spawn(move || porta.pedir("admin.execute", &pela_porta));
        let r_serial = loop {
            let (i, r) = m.proxima_resposta()?;
            if i == id {
                break r;
            }
        };
        let r_porta = fio
            .join()
            .map_err(|_| "o fio da porta caiu".to_string())??;
        let valeram = [&r_serial, &r_porta]
            .iter()
            .filter(|r| p::executou(r))
            .count();
        if valeram != 1 {
            return Err(format!(
                "{valeram} das duas instalacoes valeram\n  serial: {r_serial}\n  porta: {r_porta}"
            ));
        }
        let s = situacao(&mut m)?;
        s.exigir(
            "uma candidata so",
            s.candidato == Some(("b".into(), GERACAO_NOVA)) && s.tentativa.as_deref() == Some("b"),
        )?;
        cancelar(&mut m, arch, &b.imagens.nova.resumo)?;

        // A escrita da de fora disputa o slot com a instalação da nova.
        let estranha = b.imagens.estranha.bytes.clone();
        let fio = std::thread::spawn(move || encenar(arch, &estranha));
        std::thread::sleep(Duration::from_millis(300));
        let r = quorum(&mut m, arch, "install", &b.imagens.nova.resumo, &[0, 2])?;
        let escrita = fio
            .join()
            .map_err(|_| "o fio da escrita caiu".to_string())?;
        let armou = p::executou(&r);
        if !armou {
            // A escrita veio antes, ou no meio: o slot não é mais a nova.
            encenar(arch, &b.imagens.nova.bytes)?;
            instalar(&mut m, arch, &b.imagens.nova.resumo)?;
        }
        reiniciar(&mut m, arch)?;
        let s = situacao(&mut m)?;
        s.na_versao("depois da disputa", "b", GERACAO_NOVA)?;
        Ok(format!(
            "uma de duas instalacoes valeu; na disputa com a escrita, a instalacao {} e a escrita {}; a nova bootou e se confirmou",
            if armou { "armou" } else { "foi recusada" },
            match escrita {
                Ok(()) => "terminou".to_string(),
                Err(e) => format!("parou ({})", e.lines().next().unwrap_or("")),
            }
        ))
    })();
    m.cortar_a_energia()?;
    r
}

/// Uma máquina de produção desta bancada: o material de um operador — a
/// política de exemplo, o agente `sistema` dele, três administradores e a
/// chave de atualização —, a imagem dele no slot A com o kernel desta
/// compilação — a versão 1 —, e a versão 2 assinada pela mesma chave.
/// Nenhuma chave do Duke: a identidade nasce no primeiro boot.
struct Producao {
    dir: PathBuf,
    disco: PathBuf,
    sistema: [u8; 32],
    administradores: Vec<PathBuf>,
    v2: slots::Imagem,
}

impl Producao {
    fn montar(b: &Bancada, nome: &str) -> Result<Producao, String> {
        let arch = b.arch;
        let dir = super::raiz_do_estado().join(format!("operador-{nome}-{}", arch.nome()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let escrever = |nome: &str, conteudo: &str| {
            std::fs::write(dir.join(nome), conteudo).map_err(|e| format!("{nome}: {e}"))
        };
        let exemplo = super::raiz_do_projeto().join("docs/exemplos/producao/politica");
        escrever(
            "politica",
            &std::fs::read_to_string(&exemplo)
                .map_err(|e| format!("{}: {e}", exemplo.display()))?,
        )?;
        escrever("nome", &format!("bancada-{nome}\n"))?;
        let (sistema, linha_do_sistema, _) =
            producao::chave_nova("agente", "sistema-1", Some("sistema"))?;
        escrever("agentes", &linha_do_sistema)?;
        let mut administradores = String::new();
        let mut arquivos_dos_administradores = Vec::new();
        for nome in ["adm-a", "adm-b", "adm-c"] {
            let (privada, linha, _) =
                producao::chave_nova("administrador", nome, Some("administrador"))?;
            administradores.push_str(&linha);
            let arquivo = dir.join(format!("{nome}.chave"));
            std::fs::write(&arquivo, privada).map_err(|e| format!("{nome}: {e}"))?;
            arquivos_dos_administradores.push(arquivo);
        }
        escrever("administradores", &administradores)?;
        let (publicador, linha_do_publicador, _) =
            producao::chave_nova("atualizacao", "publicador-1", None)?;
        escrever("atualizacao", &linha_do_publicador)?;
        let op = producao::ler_o_operador(&dir)?;
        let politica = producao::conferir(&op)?;
        let mut id = [0u8; 16];
        id.copy_from_slice(&super::aleatorios()?[..16]);
        let arquivos = producao::arquivos_da_raiz(&op, &politica, id)?;
        let privada = producao::chave_de_atualizacao_de_texto(&publicador)?;
        let kernel = slots::kernel_da_imagem(&slots::imagem_do_slot(&b.disco()?, Slot::A)?)?;
        let pacote = producao::pacote_do_produto(arch)?;
        let v1 = imagem(arch, &kernel, &pacote, "producao-1", 1, &privada)?;
        let v2 = imagem(arch, &kernel, &pacote, "producao-2", 2, &privada)?;
        slots::conferir_imagem(&v2.bytes, &op.atualizacao, arch)?;
        let disco = super::raiz_do_estado().join(format!("producao-{nome}-{}.img", arch.nome()));
        producao::montar_o_disco(arch, false, &disco, &arquivos, &v1.bytes)?;
        Ok(Producao {
            dir,
            disco,
            sistema: producao::chave_de_agente_de_texto(&sistema)?,
            administradores: arquivos_dos_administradores,
            v2,
        })
    }

    fn subir(&self, arch: Arquitetura) -> Result<Ligada, String> {
        Ligada::subir_esperando(
            arch,
            &Artefato::Disco(self.disco.clone()),
            Ambiente::ligar(arch, None)?.com_disco(self.disco.clone()),
            espera(arch),
        )
    }

    /// O caminho do operador até a versão 2: o primeiro boot, com a
    /// identidade nascida e mostrada; a versão 2 escrita pelo agente dele,
    /// que fixa a pública mostrada, com o `encenar` do `operar`; instalada
    /// pelo quórum dos administradores dele; e o reinício pelo agente.
    /// Devolve a pública e os boots de antes do reinício.
    fn instalar_a_versao_2(
        &self,
        arch: Arquitetura,
        m: &mut Ligada,
    ) -> Result<([u8; 32], u64), String> {
        let s = situacao(m)?;
        s.na_versao("a imagem de producao", "a", 1)?;
        s.exigir("a versao publicada", s.versao == "producao-1")?;
        let publica = p::identidade_com_origem(m, "born")?;
        let mut agente = AgenteNaPorta::conectar_com_publica(arch, 1, &self.sistema, &publica)?;
        producao::encenar(&mut agente, &self.v2.bytes)?;
        let r = super::quorum_pelo_operador(
            &mut agente,
            "system.update",
            &parametros("install", &self.v2.resumo),
            &self.administradores[..2],
        )?;
        if !p::executou(&r) {
            return Err(format!("o quorum do operador nao instalou\n  {r}"));
        }
        let antes = p::persistencia_de(m)?.boots;
        let r = agente.pedir("system.reboot", "{}")?;
        if !r.contains(r#""state":"rebooting""#) {
            return Err(format!("o agente do operador nao reiniciou\n  {r}"));
        }
        Ok((publica, antes))
    }

    fn apagar(&self) {
        let _ = std::fs::remove_dir_all(&self.dir);
        let _ = std::fs::remove_file(&self.disco);
    }
}

/// O caminho do operador numa imagem de produção: a chave de atualização
/// dele, a imagem publicada no slot A pelo `provisionar`, a identidade do
/// Duke nascida no primeiro boot e fixada pelo agente, a versão 2 escrita
/// pelo agente `sistema` dele com o `encenar` do `operar`, instalada pelo
/// quórum dos administradores dele, e o reinício pelo agente. A versão 2
/// boota, se confirma com a mesma identidade — aberta do selo —, e traz os
/// programas do produto no pacote.
fn a_producao_se_atualiza(b: &Bancada) -> Result<String, String> {
    let arch = b.arch;
    let pr = Producao::montar(b, "atualizacao")?;
    let mut m = pr.subir(arch)?;
    let r = (|| -> Result<String, String> {
        let (publica, antes) = pr.instalar_a_versao_2(arch, &mut m)?;
        m.esperar_o_boot_ate(antes, espera(arch))?;
        let s = situacao(&mut m)?;
        s.na_versao("a imagem de producao, atualizada", "b", 2)?;
        s.exigir("a versao 2 confirmada", s.versao == "producao-2")?;
        if p::identidade_com_origem(&mut m, "sealed")? != publica {
            return Err("a versao 2 abriu outra identidade que a nascida na 1".into());
        }
        let mut agente = AgenteNaPorta::conectar_com_publica(arch, 1, &pr.sistema, &publica)?;
        let programas = agente.pedir(
            "fs.list",
            &format!(r#"{{"path":"/programas/{}"}}"#, arch.nome()),
        )?;
        for programa in producao::PROGRAMAS_DO_PRODUTO {
            if !programas.contains(&format!(r#""{programa}""#)) {
                return Err(format!(
                    "o programa `{programa}` nao veio no pacote da versao 2\n  {programas}"
                ));
            }
        }
        Ok(format!(
            "producao-1 -> producao-2 pelo agente e pelo quorum do operador, com a identidade nascida na 1 aberta do selo na 2; {} programas do produto no pacote",
            producao::PROGRAMAS_DO_PRODUTO.len()
        ))
    })();
    m.cortar_a_energia()?;
    pr.apagar();
    r
}

/// A imagem de produção cuja versão 2 entra em pânico antes de se
/// confirmar, em toda tentativa: o iniciador conta três, a versão 1 volta e
/// desfaz — e a identidade nascida no primeiro boot é a mesma nas
/// tentativas e na volta. O agente que a fixou entra de novo.
fn a_producao_desfeita_com_a_identidade(b: &Bancada) -> Result<String, String> {
    let arch = b.arch;
    let pr = Producao::montar(b, "desfeita")?;
    let mut m = pr.subir(arch)?;
    let r = pr.instalar_a_versao_2(arch, &mut m);
    m.cortar_a_energia()?;
    let (publica, boots) = r?;
    p::plano(
        &pr.disco,
        p::Plano {
            ponto: ponto::ANTES_DA_CONFIRMACAO,
            bandeiras: PANICO_NA_CONFIRMACAO,
            ..p::Plano::default()
        },
    )?;
    let mut m = pr.subir(arch)?;
    let r = (|| -> Result<u64, String> {
        let s = situacao(&mut m)?;
        s.na_versao("depois dos panicos", "a", 1)?;
        s.exigir(
            "a velha, desfeita",
            s.modo == "desfeita" && s.reconciliacao == "desfazer",
        )?;
        if p::identidade_com_origem(&mut m, "sealed")? != publica {
            return Err("a versao 1 de volta abriu outra identidade".into());
        }
        let depois = p::persistencia_de(&mut m)?.boots;
        if depois < boots + u64::from(TENTATIVAS) + 1 {
            return Err(format!(
                "de {boots} a {depois} boots: as {TENTATIVAS} tentativas nao foram todas"
            ));
        }
        let mut agente = AgenteNaPorta::conectar_com_publica(arch, 1, &pr.sistema, &publica)?;
        let sessao = agente.pedir("agent.session", "{}")?;
        if !sessao.contains(r#""agent":"sistema-1""#) {
            return Err(format!(
                "o agente do operador nao entrou de volta\n  {sessao}"
            ));
        }
        Ok(depois - boots)
    })();
    m.cortar_a_energia()?;
    pr.apagar();
    let boots = r?;
    Ok(format!(
        "{boots} boots: {TENTATIVAS} tentativas da versao 2 em panico e a volta da 1, desfeita, com a identidade {} nascida no primeiro boot",
        &sigilo::hex(&publica)[..8]
    ))
}

/// No ARM, o kernel posto pelo `-kernel` não vem de um slot: com o journal
/// já com o estado da atualização, ele não tem autoridade — um kernel que
/// contornasse o iniciador contornaria o piso.
fn o_kernel_fora_de_um_slot(b: &Bancada) -> Result<String, String> {
    let Some(sem_slot) = &b.sem_slot else {
        return Ok("o x86 so boota pelo firmware: nada a conferir".into());
    };
    let c = chaves::Chaves::garantir()?;
    let m = b.subir()?;
    m.cortar_a_energia()?;
    let mut m = Ligada::subir_esperando(
        b.arch,
        sem_slot,
        Ambiente::ligar(b.arch, None)?,
        espera(b.arch),
    )?;
    let r = (|| {
        let s = situacao(&mut m)?;
        s.exigir(
            "fora de um slot",
            s.reconciliacao == "recusar" && s.autoridade == "refused" && s.slot.is_empty(),
        )?;
        let r = p::administrar(
            &mut m,
            &c.administrador,
            "agent.register",
            &p::registro_de_agente(&[0xB2; 32], "fora-do-slot", "observador"),
        )?;
        recusado("o registro fora de um slot", &r, "nao veio de um slot")
    })();
    m.cortar_a_energia()?;
    r?;
    Ok("recusado: o kernel nao veio de um slot".into())
}

// ---------------------------------------------------------------------------
// As quedas
// ---------------------------------------------------------------------------

/// Uma queda: o ponto, o tipo de registro e a gravação dele que o plano
/// conta, se a escrita sem descarga se perde, se o registro vale depois, e
/// o nome.
type Queda = (u8, u16, u32, bool, bool, &'static str);

/// Liga com o plano, escreve e instala até cair; corta, apaga o plano e
/// sobe de novo.
fn as_quedas_na_instalacao(b: &Bancada) -> Result<String, String> {
    const CASOS: [Queda; 6] = [
        (
            ponto::ANTES_DA_ESCRITA,
            OPERACAO,
            1,
            false,
            false,
            "antes da escrita do registro",
        ),
        (
            ponto::DEPOIS_DA_ESCRITA,
            OPERACAO,
            1,
            false,
            true,
            "depois da escrita, que chegou ao disco",
        ),
        (
            ponto::DEPOIS_DA_ESCRITA,
            OPERACAO,
            1,
            true,
            false,
            "depois da escrita, que se perdeu",
        ),
        (
            ponto::DEPOIS_DA_DESCARGA,
            OPERACAO,
            1,
            false,
            true,
            "depois da descarga, antes do contador",
        ),
        (
            ponto::DEPOIS_DO_CONTADOR,
            OPERACAO,
            1,
            false,
            true,
            "depois do contador, antes do controle",
        ),
        (
            ponto::CONTROLE_GRAVADO,
            0,
            1,
            false,
            true,
            "depois do controle, antes da resposta",
        ),
    ];
    let arch = b.arch;
    let disco = b.disco()?;
    let c = chaves::Chaves::garantir()?;
    let mut feitos = Vec::new();
    for (i, (ponto, tipo, gravacao, perder, vale, nome)) in CASOS.into_iter().enumerate() {
        if i > 0 {
            zerar_o_estado(arch)?;
        }
        p::plano(
            &disco,
            p::Plano {
                ponto,
                tipo,
                gravacao,
                ..p::Plano::default()
            },
        )?;
        let mut m = b.subir()?;
        let preparo = (|| {
            encenar_no_caso(arch, i, &b.imagens.nova.bytes)?;
            let desafio = m.pedir("admin.challenge", r#"{"for":"system.update"}"#)?;
            super::assinar_quorum_da_bancada(
                arch,
                &c,
                &desafio,
                0,
                "system.update",
                &parametros("install", &b.imagens.nova.resumo),
                &[0, 1],
            )
        })();
        let pedido = match preparo {
            Ok(p) => p,
            Err(e) => {
                m.cortar_a_energia()?;
                return Err(format!("{nome}: {e}"));
            }
        };
        let caiu = m.pedir_ate_cair("admin.execute", &pedido)?;
        if caiu != ponto {
            return Err(format!("{nome}: caiu no ponto {caiu}, e nao no {ponto}"));
        }
        if perder {
            p::perder_o_ultimo_registro(&disco, None)?;
        }
        p::sem_plano(&disco)?;
        let mut m = b.subir()?;
        let r = (|| {
            let s = situacao(&mut m)?;
            if ponto == ponto::CONTROLE_GRAVADO {
                // O controle já dizia a tentativa quando a energia caiu: o
                // boot seguinte é ela, e ela se confirma.
                s.exigir(&format!("{nome}: a tentativa"), s.modo == "tentativa")?;
                s.na_versao(
                    &format!("{nome}: a tentativa, confirmada"),
                    "b",
                    GERACAO_NOVA,
                )
            } else if vale {
                s.exigir(
                    &format!("{nome}: armada, e o controle armado pelo journal"),
                    s.slot == "a"
                        && s.candidato == Some(("b".into(), GERACAO_NOVA))
                        && s.tentativa.as_deref() == Some("b")
                        && s.restantes == u64::from(TENTATIVAS)
                        && s.autoridade == "granted",
                )?;
                reiniciar(&mut m, arch)?;
                situacao(&mut m)?.na_versao(&format!("{nome}: depois"), "b", GERACAO_NOVA)
            } else {
                s.na_versao(&format!("{nome}: nada armado"), "a", 1)?;
                instalar(&mut m, arch, &b.imagens.nova.resumo)
            }
        })();
        m.cortar_a_energia()?;
        r?;
        feitos.push(format!("{nome}: {}", if vale { "armada" } else { "nada" }));
    }
    Ok(feitos.join("; "))
}

/// Instala, corta; liga com o plano na tentativa até cair; apaga o plano e
/// sobe: a máquina termina na nova, ativa e confirmada.
fn as_quedas_na_confirmacao(b: &Bancada) -> Result<String, String> {
    const CASOS: [Queda; 6] = [
        (
            ponto::ANTES_DA_CONFIRMACAO,
            0,
            0,
            false,
            false,
            "conferida, antes da confirmacao",
        ),
        (
            ponto::ANTES_DA_ESCRITA,
            ATUALIZACAO,
            1,
            false,
            false,
            "antes da escrita da confirmacao",
        ),
        (
            ponto::DEPOIS_DA_ESCRITA,
            ATUALIZACAO,
            1,
            true,
            false,
            "a escrita da confirmacao perdida",
        ),
        (
            ponto::DEPOIS_DA_DESCARGA,
            ATUALIZACAO,
            1,
            false,
            true,
            "depois da descarga da confirmacao",
        ),
        (
            ponto::DEPOIS_DO_CONTADOR,
            ATUALIZACAO,
            1,
            false,
            true,
            "depois do contador, antes do controle",
        ),
        (
            ponto::CONTROLE_GRAVADO,
            0,
            1,
            false,
            true,
            "depois do controle, antes dos canais",
        ),
    ];
    let arch = b.arch;
    let disco = b.disco()?;
    let mut feitos = Vec::new();
    for (i, (ponto, tipo, gravacao, perder, vale, nome)) in CASOS.into_iter().enumerate() {
        if i > 0 {
            zerar_o_estado(arch)?;
        }
        let mut m = b.subir()?;
        let r = (|| {
            encenar_no_caso(arch, i, &b.imagens.nova.bytes)?;
            instalar(&mut m, arch, &b.imagens.nova.resumo)
        })();
        m.cortar_a_energia()?;
        r.map_err(|e| format!("{nome}: {e}"))?;
        p::plano(
            &disco,
            p::Plano {
                ponto,
                tipo,
                gravacao,
                ..p::Plano::default()
            },
        )?;
        let caiu = p::subir_ate_cair_em(arch, &b.firmware, espera(arch))?;
        if caiu != ponto {
            return Err(format!("{nome}: caiu no ponto {caiu}, e nao no {ponto}"));
        }
        if perder {
            p::perder_o_ultimo_registro(&disco, None)?;
        }
        p::sem_plano(&disco)?;
        let mut m = b.subir()?;
        let r = (|| {
            let s = situacao(&mut m)?;
            s.na_versao(&format!("{nome}: depois"), "b", GERACAO_NOVA)?;
            let esperada = if vale {
                "seguir"
            } else {
                "confirmar no fim do boot"
            };
            s.exigir(
                &format!(
                    "{nome}: a confirmacao {}",
                    if vale { "ja valia" } else { "de novo" }
                ),
                s.reconciliacao == esperada,
            )?;
            let confirmacoes = na_auditoria(&mut m, "system.update.confirm")?.len();
            if confirmacoes != 1 {
                return Err(format!("{nome}: {confirmacoes} confirmacoes na auditoria"));
            }
            Ok(())
        })();
        m.cortar_a_energia()?;
        r?;
        feitos.push(format!(
            "{nome}: {}",
            if vale {
                "ja confirmada"
            } else {
                "confirmada de novo"
            }
        ));
    }
    Ok(feitos.join("; "))
}

/// A energia cai no terceiro pedaço da escrita da versão nova, num slot que
/// começou em zeros: a instalação da metade é recusada, e a escrita
/// inteira, de novo, instala e boota.
fn a_queda_no_meio_da_escrita(b: &Bancada) -> Result<String, String> {
    let arch = b.arch;
    let disco = b.disco()?;
    zerar_o_slot(&disco, Slot::B)?;
    p::plano(
        &disco,
        p::Plano {
            ponto: ponto::NO_MEIO_DA_ENCENACAO,
            gravacao: 3,
            ..p::Plano::default()
        },
    )?;
    let m = b.subir()?;
    let bytes = b.imagens.nova.bytes.clone();
    let fio = std::thread::spawn(move || encenar(arch, &bytes));
    let caiu = m.esperar_a_queda()?;
    let escrita = fio
        .join()
        .map_err(|_| "o fio da escrita caiu".to_string())?;
    if caiu != ponto::NO_MEIO_DA_ENCENACAO || escrita.is_ok() {
        return Err(format!(
            "caiu no ponto {caiu}, e a escrita {}",
            if escrita.is_ok() { "terminou" } else { "parou" }
        ));
    }
    p::sem_plano(&disco)?;
    let mut m = b.subir()?;
    let r = (|| {
        let s = situacao(&mut m)?;
        s.na_versao("depois da queda", "a", 1)?;
        let r = quorum(&mut m, arch, "install", &b.imagens.nova.resumo, &[0, 1])?;
        recusado("a metade da versao nova", &r, "nao bate com o manifesto")?;
        atualizar(&mut m, b, &b.imagens.nova, GERACAO_NOVA)
    })();
    m.cortar_a_energia()?;
    r?;
    Ok("tres pedacos escritos: a metade recusada, e a escrita inteira instalou e bootou".into())
}

/// A versão que o iniciador recusa — o kernel que não é ELF —, com o plano
/// no boot da velha, desfeita: a queda no registro do desfazimento ou no
/// controle depois dele. A máquina termina na velha, sem a candidata.
fn as_quedas_no_desfazimento(b: &Bancada) -> Result<String, String> {
    const CASOS: [Queda; 3] = [
        (
            ponto::ANTES_DA_ESCRITA,
            ATUALIZACAO,
            1,
            false,
            false,
            "antes da escrita do desfazimento",
        ),
        (
            ponto::DEPOIS_DO_CONTADOR,
            ATUALIZACAO,
            1,
            false,
            true,
            "depois do contador do desfazimento",
        ),
        (
            ponto::CONTROLE_GRAVADO,
            0,
            1,
            false,
            true,
            "depois do controle do desfazimento",
        ),
    ];
    let arch = b.arch;
    let disco = b.disco()?;
    let mut feitos = Vec::new();
    for (i, (ponto, tipo, gravacao, _, vale, nome)) in CASOS.into_iter().enumerate() {
        if i > 0 {
            zerar_o_estado(arch)?;
        }
        let mut m = b.subir()?;
        let r = (|| {
            encenar_no_caso(arch, i, &b.imagens.quebrada.bytes)?;
            instalar(&mut m, arch, &b.imagens.quebrada.resumo)
        })();
        m.cortar_a_energia()?;
        r.map_err(|e| format!("{nome}: {e}"))?;
        p::plano(
            &disco,
            p::Plano {
                ponto,
                tipo,
                gravacao,
                ..p::Plano::default()
            },
        )?;
        let caiu = p::subir_ate_cair_em(arch, &b.firmware, espera(arch))?;
        if caiu != ponto {
            return Err(format!("{nome}: caiu no ponto {caiu}, e nao no {ponto}"));
        }
        p::sem_plano(&disco)?;
        let mut m = b.subir()?;
        let r = (|| {
            let s = situacao(&mut m)?;
            s.na_versao(&format!("{nome}: depois"), "a", 1)?;
            let esperada = if vale { "seguir" } else { "desfazer" };
            s.exigir(
                &format!(
                    "{nome}: o desfazimento {}",
                    if vale { "ja valia" } else { "de novo" }
                ),
                s.reconciliacao == esperada,
            )
        })();
        m.cortar_a_energia()?;
        r?;
        feitos.push(format!(
            "{nome}: {}",
            if vale {
                "ja desfeita"
            } else {
                "desfeita de novo"
            }
        ));
    }
    Ok(feitos.join("; "))
}

/// A versão nova entra em pânico antes de se confirmar, em toda tentativa:
/// o pânico numa tentativa reinicia a máquina, o iniciador conta, e depois
/// da terceira boota a velha, desfeita, que tira a candidata do journal.
fn o_panico_na_tentativa(b: &Bancada) -> Result<String, String> {
    let arch = b.arch;
    let disco = b.disco()?;
    let mut m = b.subir()?;
    let r = (|| {
        encenar(arch, &b.imagens.nova.bytes)?;
        instalar(&mut m, arch, &b.imagens.nova.resumo)?;
        p::persistencia_de(&mut m).map(|p| p.boots)
    })();
    m.cortar_a_energia()?;
    let boots = r?;
    p::plano(
        &disco,
        p::Plano {
            ponto: ponto::ANTES_DA_CONFIRMACAO,
            bandeiras: PANICO_NA_CONFIRMACAO,
            ..p::Plano::default()
        },
    )?;
    let mut m = b.subir()?;
    let r = (|| {
        let s = situacao(&mut m)?;
        s.na_versao("depois dos panicos", "a", 1)?;
        s.exigir(
            "a velha, desfeita",
            s.modo == "desfeita" && s.reconciliacao == "desfazer",
        )?;
        auditado(
            &mut m,
            "system.update.rollback",
            "ALLOW",
            Falha::Nenhuma.motivo(),
        )?;
        let depois = p::persistencia_de(&mut m)?.boots;
        // As três tentativas abriram o journal antes de cair: cada uma é um
        // boot, e a volta, outro.
        if depois < boots + u64::from(TENTATIVAS) + 1 {
            return Err(format!(
                "de {boots} a {depois} boots: as {TENTATIVAS} tentativas nao foram todas"
            ));
        }
        Ok(depois - boots)
    })();
    m.cortar_a_energia()?;
    p::sem_plano(&disco)?;
    let boots = r?;
    Ok(format!(
        "{boots} boots depois da instalacao: {TENTATIVAS} tentativas em panico e a volta, desfeita"
    ))
}
