//! A bancada da troca da própria senha: `cargo xtask senha`.
//!
//! A pessoa troca a senha pelo teclado da máquina — o `sendkey` do monitor
//! do emulador, no Terminal que tem o foco desde o boot —, como faria na
//! frente dela: `login`, e então `senha`, a atual, a nova e a nova de novo.
//! Nada se simula dentro do kernel; o que se confere é o que a pessoa
//! confere depois: com qual senha ela entra. E a auditoria, pela serial.
//!
//! - a troca sobrevive ao corte de energia: no boot seguinte, a antiga não
//!   entra, a nova entra, e a decisão voltou do journal;
//! - a queda em cada fronteira da troca — as senhas digitadas e nada
//!   conferido; a atual conferida e a nova calculada; a decisão feita; cada
//!   passo da gravação; tudo gravado e a resposta não dada; a resposta
//!   dada —: no boot seguinte, exatamente uma senha entra, e é a nova
//!   exatamente quando o registro está no disco;
//! - a troca com o botão de energia apertado logo depois do Enter: a
//!   máquina desliga, e no boot seguinte exatamente uma senha entra — a
//!   nova exatamente quando a troca está no journal;
//! - na imagem de produção — a do `provisionar`, com a identidade nascida
//!   no primeiro boot —, a pessoa do operador troca a senha pelo mesmo
//!   caminho, e a nova sobrevive ao corte.
//!
//! A troca correndo com a atualização A/B é da bancada da atualização: a
//! versão nova, instalada depois da troca, repõe a senha nova.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use super::persistencia::{self as p, Ligada, Rastro};
use super::{Ambiente, Arquitetura, Artefato, chaves};

/// A senha nova que a bancada digita: do tamanho de uma senha, e só com o
/// que o monitor do emulador digita.
pub(crate) const SENHA_NOVA: &str = "a senha nova da bancada";

/// A pessoa da imagem de desenvolvimento, e a do operador na de produção.
const DEV: &str = chaves::NOME_DA_PESSOA_DEV;
const ANA: &str = "ana";
const SENHA_DA_ANA: &str = "uma senha comprida de teste";

/// Quanto esperar o desfecho gravado de um login ou de uma troca: o
/// Argon2id no emulador, duas vezes na troca, e o journal.
const ESPERA_PELO_DESFECHO: Duration = Duration::from_secs(120);

/// Quanto esperar a máquina sair sozinha depois do aperto do botão.
const ESPERA_PELO_DESLIGAMENTO: Duration = Duration::from_secs(120);

/// A bancada: as duas compilações do kernel de produção — sem e com os
/// pontos de queda: a segunda só depois dos cenários da primeira, porque
/// substitui a primeira no disco de testes —, o disco do cenário de
/// produção, e o molde dele.
struct Bancada {
    arch: Arquitetura,
    dev: Artefato,
    quedas: Option<Artefato>,
    disco: PathBuf,
    producao: Option<PathBuf>,
}

/// Um cenário: um nome que se lê como afirmação, e a função que a confere.
struct Cenario {
    nome: &'static str,
    /// O que ele pede da bancada: a compilação com os pontos de queda, ou
    /// o molde de produção.
    quedas: bool,
    producao: bool,
    rodar: fn(&Bancada) -> Result<String, String>,
}

const CENARIOS: &[Cenario] = &[
    Cenario {
        nome: "a pessoa troca a propria senha pelo teclado, e a nova sobrevive ao corte",
        quedas: false,
        producao: false,
        rodar: a_troca_sobrevive_ao_corte,
    },
    Cenario {
        nome: "a troca e o botao de energia ao mesmo tempo: exatamente uma senha entra depois",
        quedas: false,
        producao: false,
        rodar: a_troca_e_o_botao,
    },
    Cenario {
        nome: "a imagem de producao: a pessoa do operador troca a senha, e a nova sobrevive ao corte",
        quedas: false,
        producao: true,
        rodar: a_producao_troca_a_senha,
    },
    // Por último: a compilação com os pontos de queda substitui a outra no
    // disco de testes.
    Cenario {
        nome: "a queda em cada fronteira da troca: no boot seguinte, exatamente uma senha entra",
        quedas: true,
        producao: false,
        rodar: as_quedas_na_troca,
    },
];

// ---------------------------------------------------------------------------
// A pessoa no teclado da máquina
// ---------------------------------------------------------------------------

/// O teclado da máquina: o monitor do emulador.
pub(crate) fn teclado(arch: Arquitetura) -> Result<UnixStream, String> {
    UnixStream::connect(super::caminho_monitor(arch))
        .map_err(|e| format!("o monitor nao aceitou conexao: {e}"))
}

/// O número do registro mais recente da auditoria, pela serial.
fn ultima_seq(m: &mut Ligada) -> Result<u64, String> {
    Ok(p::cauda_da_auditoria(m)?
        .iter()
        .map(|r| r.seq)
        .max()
        .unwrap_or(0))
}

/// O primeiro registro de `metodo` gravado depois de `seq` que `f` aceita,
/// esperado até `espera`.
fn esperar_registro(
    m: &mut Ligada,
    metodo: &str,
    seq: u64,
    espera: Duration,
    f: impl Fn(&Rastro) -> bool,
) -> Result<Rastro, String> {
    let limite = Instant::now() + espera;
    loop {
        let cauda = p::cauda_da_auditoria(m)?;
        if let Some(r) = cauda
            .into_iter()
            .find(|r| r.seq > seq && r.metodo == metodo && f(r))
        {
            return Ok(r);
        }
        if Instant::now() >= limite {
            return Err(format!(
                "nenhum registro de `{metodo}` depois de {seq} em {}s",
                espera.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// O Terminal atende o teclado: um comando digitado antes do login é
/// recusado e gravado com o console dele.
pub(crate) fn terminal_atendendo(m: &mut Ligada, t: &mut UnixStream) -> Result<(), String> {
    let seq = ultima_seq(m)?;
    super::digitar_pelo_monitor(t, "\nagent.ping\n", "senha")?;
    esperar_registro(m, "agent.ping", seq, Duration::from_secs(60), |r| {
        r.codigo == "DENY_NOT_AUTHENTICATED" && r.recurso.starts_with("terminal:")
    })
    .map(|_| ())
    .map_err(|e| format!("o Terminal nao atendeu o teclado: {e}"))
}

/// `login` pelo teclado, no Terminal: o código do desfecho gravado —
/// `ALLOW`, a sessão aberta; uma recusa, não.
pub(crate) fn entrar(
    m: &mut Ligada,
    t: &mut UnixStream,
    nome: &str,
    senha: &str,
) -> Result<String, String> {
    let seq = ultima_seq(m)?;
    super::digitar_pelo_monitor(t, &format!("login\n{nome}\n{senha}\n"), "senha")?;
    esperar_registro(m, "person.login", seq, ESPERA_PELO_DESFECHO, |_| true).map(|r| r.codigo)
}

/// Só digita a troca: `senha`, a atual, a nova e a nova de novo.
fn digitar_a_troca(t: &mut UnixStream, atual: &str, nova: &str) -> Result<(), String> {
    super::digitar_pelo_monitor(t, &format!("senha\n{atual}\n{nova}\n{nova}\n"), "senha")
}

/// `senha` pelo teclado, no Terminal: o registro do desfecho gravado.
pub(crate) fn trocar(
    m: &mut Ligada,
    t: &mut UnixStream,
    atual: &str,
    nova: &str,
) -> Result<Rastro, String> {
    let seq = ultima_seq(m)?;
    digitar_a_troca(t, atual, nova)?;
    esperar_registro(
        m,
        "credential.change_self",
        seq,
        ESPERA_PELO_DESFECHO,
        |_| true,
    )
}

/// Com qual das duas senhas `nome` entra agora: a primeira, a segunda,
/// ou — o que nunca pode ser — as duas, ou nenhuma. `Err` com o par de
/// códigos se não for exatamente uma.
pub(crate) fn entra_com(
    m: &mut Ligada,
    t: &mut UnixStream,
    nome: &str,
    primeira: &str,
    segunda: &str,
) -> Result<bool, String> {
    let a = entrar(m, t, nome, primeira)?;
    let b = entrar(m, t, nome, segunda)?;
    match (a.as_str(), b.as_str()) {
        ("ALLOW", "DENY_NOT_AUTHENTICATED") => Ok(true),
        ("DENY_NOT_AUTHENTICATED", "ALLOW") => Ok(false),
        _ => Err(format!(
            "`{nome}` nao entra com exatamente uma das duas senhas: {a} e {b}"
        )),
    }
}

/// A persistência disponível — nada recusado.
fn de_pe(m: &mut Ligada) -> Result<p::Persistencia, String> {
    let estado = p::persistencia_de(m)?;
    if estado.estado != "available" {
        return Err(format!(
            "a persistencia nao esta disponivel: {} ({})",
            estado.estado, estado.motivo
        ));
    }
    Ok(estado)
}

/// A decisão da troca na auditoria, gravada no journal: a que voltou com
/// ele, depois de um boot.
fn troca_no_journal(m: &mut Ligada) -> Result<bool, String> {
    Ok(p::cauda_da_auditoria(m)?
        .iter()
        .any(|r| r.metodo == "credential.change_self" && r.codigo == "ALLOW" && r.duravel))
}

// ---------------------------------------------------------------------------
// Os cenários
// ---------------------------------------------------------------------------

/// A troca de verdade: a pessoa de desenvolvimento entra, troca a senha, e
/// na mesma máquina a antiga já não entra e a nova entra; a decisão está
/// no journal antes da resposta. Depois do corte de energia, a decisão
/// voltou do journal, a cadeia da auditoria se verifica, a antiga não
/// entra, e a nova entra.
fn a_troca_sobrevive_ao_corte(b: &Bancada) -> Result<String, String> {
    let (_, _, atual) = chaves::Chaves::garantir()?.pessoa_dev();
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let antes = (|| -> Result<(u64, u64), String> {
        let estado = de_pe(&mut m)?;
        let mut t = teclado(b.arch)?;
        terminal_atendendo(&mut m, &mut t)?;
        let login = entrar(&mut m, &mut t, DEV, &atual)?;
        if login != "ALLOW" {
            return Err(format!("a pessoa de desenvolvimento nao entrou: {login}"));
        }
        let troca = trocar(&mut m, &mut t, &atual, SENHA_NOVA)?;
        if troca.codigo != "ALLOW" || !troca.duravel || troca.titular != "person" {
            return Err(format!(
                "a troca nao foi gravada como da pessoa, no journal: {troca:?}"
            ));
        }
        if entra_com(&mut m, &mut t, DEV, &atual, SENHA_NOVA)? {
            return Err("na mesma maquina, a senha antiga ainda entra".into());
        }
        Ok((troca.seq, estado.boots))
    })();
    m.cortar_a_energia()?;
    let (seq, boots) = antes?;

    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let depois = (|| -> Result<String, String> {
        let estado = de_pe(&mut m)?;
        if estado.boots <= boots {
            return Err(format!(
                "o boot seguinte nao contou: {} depois de {boots}",
                estado.boots
            ));
        }
        if !troca_no_journal(&mut m)? {
            return Err("a decisao da troca nao voltou do journal".into());
        }
        p::auditoria_verifica(&mut m)?;
        let mut t = teclado(b.arch)?;
        terminal_atendendo(&mut m, &mut t)?;
        if entra_com(&mut m, &mut t, DEV, &atual, SENHA_NOVA)? {
            return Err("depois do corte, a senha antiga entra".into());
        }
        Ok(format!(
            "a troca {seq} no journal; depois do corte, boot {}: a antiga recusada, a nova entra, a cadeia se verifica",
            estado.boots
        ))
    })();
    m.cortar_a_energia()?;
    depois
}

/// Uma queda dentro da troca: o ponto, se a escrita sem descarga se perde,
/// se a troca vale depois, e como se lê. O ponto zero é o corte depois da
/// resposta.
type Queda = (u8, bool, bool, &'static str);

const QUEDAS_NA_TROCA: [Queda; 11] = [
    (
        p::ponto::TROCA_DIGITADA,
        false,
        false,
        "antes da validacao: as senhas digitadas, nada conferido",
    ),
    (
        p::ponto::SENHA_CONFERIDA,
        false,
        false,
        "depois da validacao: a atual conferida, a nova calculada",
    ),
    (
        p::ponto::TROCA_AUTORIZADA,
        false,
        false,
        "depois da autorizacao: a decisao feita, nada no journal",
    ),
    (
        p::ponto::ANTES_DA_ESCRITA,
        false,
        false,
        "na gravacao: o registro montado, nada escrito",
    ),
    (
        p::ponto::DEPOIS_DA_ESCRITA,
        false,
        true,
        "na gravacao: o registro escrito, e no disco",
    ),
    (
        p::ponto::DEPOIS_DA_ESCRITA,
        true,
        false,
        "na gravacao: o registro escrito, e perdido sem a descarga",
    ),
    (
        p::ponto::DEPOIS_DA_DESCARGA,
        false,
        true,
        "depois do journal: descarregado, o contador ainda nao",
    ),
    (
        p::ponto::DEPOIS_DO_INCREMENTO,
        false,
        true,
        "depois da persistencia: o contador avancado, sem a leitura de volta",
    ),
    (
        p::ponto::DEPOIS_DO_CONTADOR,
        false,
        true,
        "depois da persistencia: o contador conferido, a troca nao terminada",
    ),
    (
        p::ponto::TROCA_GRAVADA,
        false,
        true,
        "antes da confirmacao: tudo gravado, a resposta nao dada",
    ),
    (0, false, true, "depois da confirmacao: a resposta dada"),
];

/// A queda em cada fronteira da troca, sobre a compilação com os pontos de
/// queda: o plano faz a energia cair no ponto, o disco fica como estava ali
/// — e, num dos casos, o registro não descarregado se perde. No boot
/// seguinte a persistência está de pé, nada recusado, e exatamente uma
/// senha entra: a nova exatamente quando o caso diz que a troca vale, e
/// então com a decisão dela de volta do journal.
fn as_quedas_na_troca(b: &Bancada) -> Result<String, String> {
    let quedas = b
        .quedas
        .as_ref()
        .ok_or("sem a compilacao com os pontos de queda")?;
    let (_, _, atual) = chaves::Chaves::garantir()?.pessoa_dev();
    let disco = super::disco_de_testes()?;
    let mut feitos = Vec::new();
    for (ponto, perder, vale, caso) in QUEDAS_NA_TROCA {
        super::zerar_o_estado(b.arch)?;
        if ponto != 0 {
            // A primeira operação do boot: a troca. O login não grava
            // operação.
            p::plano(
                &disco,
                p::Plano {
                    ponto,
                    tipo: p::tipo::OPERACAO,
                    gravacao: 1,
                    ..p::Plano::default()
                },
            )?;
        }
        let mut m = Ligada::subir(b.arch, quedas, None)?;
        let preparada = (|| -> Result<(), String> {
            de_pe(&mut m)?;
            let mut t = teclado(b.arch)?;
            terminal_atendendo(&mut m, &mut t)?;
            let login = entrar(&mut m, &mut t, DEV, &atual)?;
            if login != "ALLOW" {
                return Err(format!("{caso}: a pessoa nao entrou ({login})"));
            }
            if ponto == 0 {
                let troca = trocar(&mut m, &mut t, &atual, SENHA_NOVA)?;
                if troca.codigo != "ALLOW" || !troca.duravel {
                    return Err(format!("{caso}: a troca nao valeu: {troca:?}"));
                }
            } else {
                digitar_a_troca(&mut t, &atual, SENHA_NOVA)?;
            }
            Ok(())
        })();
        if let Err(e) = preparada {
            m.cortar_a_energia()?;
            return Err(e);
        }
        if ponto == 0 {
            m.cortar_a_energia()?;
        } else {
            let caiu = m.esperar_a_queda()?;
            if caiu != ponto {
                return Err(format!("{caso}: caiu no ponto {caiu}, e nao no {ponto}"));
            }
        }
        p::sem_plano(&disco)?;
        if perder {
            p::perder_o_ultimo_registro(&disco, None)?;
        }

        let mut m = Ligada::subir(b.arch, quedas, None)?;
        let depois = (|| -> Result<(), String> {
            de_pe(&mut m)?;
            let no_journal = troca_no_journal(&mut m)?;
            if no_journal != vale {
                return Err(format!(
                    "{caso}: a decisao da troca {} no journal, e a troca {}",
                    if no_journal { "esta" } else { "nao esta" },
                    if vale { "vale" } else { "nao vale" }
                ));
            }
            let mut t = teclado(b.arch)?;
            terminal_atendendo(&mut m, &mut t)?;
            let antiga = entra_com(&mut m, &mut t, DEV, &atual, SENHA_NOVA)
                .map_err(|e| format!("{caso}: {e}"))?;
            if antiga == vale {
                return Err(format!(
                    "{caso}: depois do boot entra a senha {}",
                    if antiga { "antiga" } else { "nova" }
                ));
            }
            Ok(())
        })();
        m.cortar_a_energia()?;
        depois?;
        feitos.push(if vale { "nova" } else { "antiga" });
    }
    Ok(format!(
        "{} quedas, em cada uma exatamente uma senha entra depois: {}",
        QUEDAS_NA_TROCA.len(),
        feitos.join(", ")
    ))
}

/// O botão do emulador, apertado: o `system_powerdown` do QMP.
fn apertar(arch: Arquitetura) -> Result<(), String> {
    let (mut escrita, mut leitor) = super::qmp_abrir(&super::caminho_qmp(arch))?;
    let r = super::qmp_pedir(
        &mut escrita,
        &mut leitor,
        r#"{"execute":"system_powerdown"}"#,
    )?;
    if r.contains("\"error\"") {
        return Err(format!("o QMP recusou o aperto\n  {r}"));
    }
    Ok(())
}

/// A troca e o botão de energia: a pessoa digita a troca, e o botão é
/// apertado logo depois do último Enter. A máquina desliga — sozinha, com
/// sucesso —, e no boot seguinte a persistência está de pé e exatamente
/// uma senha entra: a nova exatamente quando a decisão da troca voltou do
/// journal. Nunca as duas, nunca nenhuma.
fn a_troca_e_o_botao(b: &Bancada) -> Result<String, String> {
    let (_, _, atual) = chaves::Chaves::garantir()?.pessoa_dev();
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let preparada = (|| -> Result<(), String> {
        de_pe(&mut m)?;
        let mut t = teclado(b.arch)?;
        terminal_atendendo(&mut m, &mut t)?;
        let login = entrar(&mut m, &mut t, DEV, &atual)?;
        if login != "ALLOW" {
            return Err(format!("a pessoa nao entrou ({login})"));
        }
        digitar_a_troca(&mut t, &atual, SENHA_NOVA)?;
        apertar(b.arch)
    })();
    if let Err(e) = preparada {
        m.cortar_a_energia()?;
        return Err(e);
    }
    let status = m.esperar_sair(ESPERA_PELO_DESLIGAMENTO)?;
    if !status.success() {
        return Err(format!("o QEMU saiu com {status}, e nao pelo desligamento"));
    }
    drop(m);
    let mut m = Ligada::subir(b.arch, &b.dev, None)?;
    let depois = (|| -> Result<String, String> {
        de_pe(&mut m)?;
        let no_journal = troca_no_journal(&mut m)?;
        let mut t = teclado(b.arch)?;
        terminal_atendendo(&mut m, &mut t)?;
        let antiga = entra_com(&mut m, &mut t, DEV, &atual, SENHA_NOVA)?;
        if antiga == no_journal {
            return Err(format!(
                "a troca {} no journal, e entra a senha {}",
                if no_journal { "esta" } else { "nao esta" },
                if antiga { "antiga" } else { "nova" }
            ));
        }
        Ok(format!(
            "a maquina desligou ({status}); a troca {} antes do desligamento, e entra so a senha {}",
            if no_journal {
                "foi gravada"
            } else {
                "nao chegou ao journal"
            },
            if antiga { "antiga" } else { "nova" }
        ))
    })();
    m.cortar_a_energia()?;
    depois
}

impl Bancada {
    /// A máquina de produção, pelo firmware, com o TPM dela, no disco do
    /// cenário — copiado do molde só na primeira vez.
    fn ligar_producao(&self, do_molde: bool) -> Result<Ligada, String> {
        if do_molde {
            let molde = self.producao.as_ref().ok_or("sem o molde de producao")?;
            std::fs::copy(molde, &self.disco)
                .map_err(|e| format!("não foi possível copiar o molde: {e}"))?;
        }
        Ligada::subir_com(
            self.arch,
            &Artefato::Disco(self.disco.clone()),
            Ambiente::ligar(self.arch, None)?.com_disco(self.disco.clone()),
        )
    }
}

/// Na imagem de produção — a do `provisionar`, com a política do exemplo,
/// a identidade nascida no primeiro boot e a pessoa do operador —, a troca
/// é o mesmo caminho: a pessoa entra pelo Terminal, troca a senha pelo
/// teclado, e depois do corte de energia a antiga não entra e a nova
/// entra.
fn a_producao_troca_a_senha(b: &Bancada) -> Result<String, String> {
    let mut m = b.ligar_producao(true)?;
    let antes = (|| -> Result<(), String> {
        de_pe(&mut m)?;
        let mut t = teclado(b.arch)?;
        terminal_atendendo(&mut m, &mut t)?;
        let login = entrar(&mut m, &mut t, ANA, SENHA_DA_ANA)?;
        if login != "ALLOW" {
            return Err(format!("a pessoa do operador nao entrou ({login})"));
        }
        let troca = trocar(&mut m, &mut t, SENHA_DA_ANA, SENHA_NOVA)?;
        if troca.codigo != "ALLOW" || !troca.duravel {
            return Err(format!(
                "a troca na imagem de producao nao valeu: {troca:?}"
            ));
        }
        Ok(())
    })();
    m.cortar_a_energia()?;
    antes?;
    let mut m = b.ligar_producao(false)?;
    let depois = (|| -> Result<String, String> {
        de_pe(&mut m)?;
        if !troca_no_journal(&mut m)? {
            return Err("a decisao da troca nao voltou do journal".into());
        }
        let mut t = teclado(b.arch)?;
        terminal_atendendo(&mut m, &mut t)?;
        if entra_com(&mut m, &mut t, ANA, SENHA_DA_ANA, SENHA_NOVA)? {
            return Err("na imagem de producao, depois do corte, a senha antiga entra".into());
        }
        Ok("a pessoa do operador trocou a senha; depois do corte, so a nova entra".into())
    })();
    m.cortar_a_energia()?;
    depois
}

/// `cargo xtask senha`: roda os cenários e diz quais passaram.
pub(crate) fn senha(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    // Um filtro opcional pelo nome, como o da persistência: pedaços do nome
    // separados por `|`.
    let filtro = std::env::var("DUKE_CENARIOS").ok();
    let escolhido = |c: &Cenario| {
        filtro
            .as_deref()
            .is_none_or(|f| f.split('|').any(|p| c.nome.contains(p)))
    };
    let escolhidos: Vec<&Cenario> = CENARIOS.iter().filter(|c| escolhido(c)).collect();
    // A compilação sem os pontos de queda primeiro: é a que o molde de
    // produção copia do disco de testes.
    let dev = super::build(arch, release, false)?;
    let _ = p::SERIAL_DA_BANCADA
        .set(super::raiz_do_estado().join(format!("senha-{}.serial", arch.nome())));
    let mut bancada = Bancada {
        arch,
        dev,
        quedas: None,
        disco: super::raiz_do_estado().join(format!("senha-{}.img", arch.nome())),
        producao: if escolhidos.iter().any(|c| c.producao) {
            Some(super::botao::molde_de_producao(arch, "senha", |t| {
                Ok(t.to_string())
            })?)
        } else {
            None
        },
    };
    println!(
        "[xtask] senha: {} cenarios, cada um numa maquina nova ({})",
        escolhidos.len(),
        arch.nome()
    );
    let mut falhas = 0;
    for cenario in escolhidos {
        if cenario.quedas && bancada.quedas.is_none() {
            bancada.quedas = Some(super::build_com(arch, release, &[p::FEATURE_DE_QUEDAS])?);
        }
        super::zerar_o_estado(arch)?;
        if let (None, Some(serial)) = (std::env::var_os("DUKE_BANCADA_LOG"), p::serial_do_cenario())
        {
            let _ = std::fs::write(serial, b"");
        }
        match (cenario.rodar)(&bancada) {
            Ok(detalhe) => println!("  [senha] ok  {}: {detalhe}", cenario.nome),
            Err(motivo) => {
                falhas += 1;
                println!("  [senha] FALHOU  {}: {motivo}", cenario.nome);
                p::mostrar_o_fim_da_serial();
            }
        }
    }
    super::zerar_o_estado(arch)?;
    if let Some(molde) = &bancada.producao {
        let _ = std::fs::remove_file(molde);
    }
    let _ = std::fs::remove_file(&bancada.disco);
    if falhas > 0 {
        println!("\n[xtask] senha: {falhas} cenario(s) falharam");
        return Ok(ExitCode::FAILURE);
    }
    println!("\n[xtask] senha: todos os cenarios passaram");
    Ok(ExitCode::SUCCESS)
}
