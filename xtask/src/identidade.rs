//! A bancada da identidade do Duke: `cargo xtask identidade`.
//!
//! A identidade de uma máquina de produção nasce no primeiro boot, selada
//! no TPM dela — ver `kernel/src/selo.rs` e `ancora::identidade`. Esta
//! bancada é uma máquina de produção de verdade — a imagem do
//! `provisionar`, sem chave do Duke nenhuma, pelo firmware, nas duas
//! arquiteturas —, num disco novo e num TPM novo a cada cenário, e confere
//! o que acontece com a identidade em cada coisa que pode acontecer a uma
//! máquina: o primeiro boot, os seguintes, a energia caindo em cada passo
//! do nascimento, uma cópia do selo estragada e as duas, a máquina sem
//! TPM, o disco clonado noutra máquina, e a reinstalação — com o TPM limpo
//! e sem ele.
//!
//! O que a máquina mostra é lido como o operador o lê: o `system.info`,
//! campo `identity`, pela serial — o console. O agente `sistema` do
//! operador entra fixando a pública que ela mostrou, e lê a auditoria. Numa
//! máquina sem identidade nenhum agente entra, e a recusa na auditoria é
//! lida pela serial: a política desta bancada é a do exemplo de produção
//! com a serial `sistema`, e não `observador`. A área do selo é lida e
//! estragada no arquivo do disco, entre um boot e outro; a energia que cai
//! com o cache do disco por descarregar é a do disco hostil — ver
//! `xtask/src/disco_hostil.rs`.
//!
//! A atualização A/B com a identidade nascida — a versão nova que se
//! confirma, e a que cai na tentativa e volta — é da bancada da
//! atualização: `cargo xtask atualizacao`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

use ancora::identidade::{Area, Leitura, Recusa, TAM_AREA};

use super::disco_hostil::{Corte, DiscoHostil, Gatilho};
use super::persistencia::{self as p, Ligada, ponto};
use super::{AgenteNaPorta, Ambiente, Arquitetura, Artefato, disco, producao};

/// Quanto esperar o aviso de uma queda no primeiro boot.
const ESPERA_PELA_QUEDA: Duration = Duration::from_secs(120);

/// A bancada: o disco de produção recém-provisionado, que cada cenário
/// copia, e a chave do agente do operador.
struct Bancada {
    arch: Arquitetura,
    /// O disco como o `provisionar` o deixa: cada cenário começa de uma
    /// cópia dele — a imagem gravada numa máquina nova.
    molde: PathBuf,
    /// O disco da máquina do cenário.
    disco: PathBuf,
    /// A chave do agente `sistema` do operador.
    sistema: [u8; 32],
    /// Onde o TPM da máquina fica guardado quando outro chip entra no
    /// lugar dele.
    tpm_guardado: PathBuf,
}

impl Bancada {
    /// A imagem de produção de molde: o material de um operador — a
    /// política de `docs/exemplos/producao`, um agente `sistema`, três
    /// administradores, uma pessoa e a chave de atualização —, o kernel
    /// desta bancada no slot A, assinado por ela, e nenhuma chave do Duke.
    fn preparar(arch: Arquitetura) -> Result<Bancada, String> {
        let raiz = super::raiz_do_estado();
        let dir = raiz.join(format!("operador-identidade-{}", arch.nome()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let escrever = |nome: &str, conteudo: &str| {
            std::fs::write(dir.join(nome), conteudo).map_err(|e| format!("{nome}: {e}"))
        };
        let exemplo = super::raiz_do_projeto().join("docs/exemplos/producao/politica");
        let do_exemplo =
            std::fs::read_to_string(&exemplo).map_err(|e| format!("{}: {e}", exemplo.display()))?;
        // A serial `sistema`, e não `observador`: numa máquina sem
        // identidade nenhum agente entra, e é pela serial que a bancada lê a
        // recusa na auditoria.
        let politica = do_exemplo.replace("\nserial observador\n", "\nserial sistema\n");
        if politica == do_exemplo {
            return Err(format!(
                "{}: o exemplo nao tem a linha `serial observador`",
                exemplo.display()
            ));
        }
        escrever("politica", &politica)?;
        escrever("nome", "bancada-identidade\n")?;
        let (sistema, linha, _) = producao::chave_nova("agente", "sistema-1", Some("sistema"))?;
        escrever("agentes", &linha)?;
        let mut administradores = String::new();
        for nome in ["adm-a", "adm-b", "adm-c"] {
            administradores
                .push_str(&producao::chave_nova("administrador", nome, Some("administrador"))?.1);
        }
        escrever("administradores", &administradores)?;
        escrever("senha-ana", "uma senha comprida de teste\n")?;
        escrever("pessoas", "ana operador senha-ana\n")?;
        let (publicador, linha, _) = producao::chave_nova("atualizacao", "publicador-1", None)?;
        escrever("atualizacao", &linha)?;
        let op = producao::ler_o_operador(&dir)?;
        let politica = producao::conferir(&op)?;
        let mut id = [0u8; 16];
        id.copy_from_slice(&super::aleatorios()?[..16]);
        let arquivos = producao::arquivos_da_raiz(&op, &politica, id)?;
        if arquivos
            .iter()
            .any(|(nome, _)| nome.starts_with("etc/duke/privado/chave"))
        {
            return Err("a raiz de producao leva uma chave do Duke".into());
        }
        let kernel = super::slots::kernel_da_imagem(&super::slots::imagem_do_slot(
            &super::disco_de_testes()?,
            atualizacao::Slot::A,
        )?)?;
        let slot = super::slots::imagem(
            &super::slots::Pedido {
                arch,
                kernel: &kernel,
                pacote: &producao::pacote_do_produto(arch)?,
                versao: "bancada-identidade",
                geracao: 1,
                estado: (
                    super::slots::FORMATO_DO_ESTADO,
                    super::slots::FORMATO_DO_ESTADO,
                ),
            },
            &producao::chave_de_atualizacao_de_texto(&publicador)?,
        )?;
        super::slots::conferir_imagem(&slot.bytes, &op.atualizacao, arch)?;
        let molde = raiz.join(format!("identidade-molde-{}.img", arch.nome()));
        let _ = std::fs::remove_file(&molde);
        producao::montar_o_disco(arch, false, &molde, &arquivos, &slot.bytes)?;
        let _ = std::fs::remove_dir_all(&dir);
        Ok(Bancada {
            arch,
            molde,
            disco: raiz.join(format!("identidade-{}.img", arch.nome())),
            sistema: producao::chave_de_agente_de_texto(&sistema)?,
            tpm_guardado: raiz.join(format!("identidade-tpm-guardado-{}", arch.nome())),
        })
    }

    /// Um disco novo: a imagem de molde gravada de novo.
    fn disco_novo(&self) -> Result<(), String> {
        std::fs::copy(&self.molde, &self.disco)
            .map(|_| ())
            .map_err(|e| format!("não foi possível copiar o molde: {e}"))
    }

    fn artefato(&self) -> Artefato {
        Artefato::Disco(self.disco.clone())
    }

    /// Liga a máquina pelo firmware, com o TPM dela.
    fn ligar(&self) -> Result<Ligada, String> {
        Ligada::subir_com(
            self.arch,
            &self.artefato(),
            Ambiente::ligar(self.arch, None)?.com_disco(self.disco.clone()),
        )
    }

    /// Liga a máquina sem TPM nenhum.
    fn ligar_sem_tpm(&self) -> Result<Ligada, String> {
        Ligada::subir_com(
            self.arch,
            &self.artefato(),
            Ambiente::sem_tpm(None).com_disco(self.disco.clone()),
        )
    }

    /// Liga a máquina com o plano de queda no `ponto` e espera ela cair.
    fn ate_cair_em(&self, ponto: u8) -> Result<(), String> {
        p::plano(
            &self.disco,
            p::Plano {
                ponto,
                ..p::Plano::default()
            },
        )?;
        let caiu = p::subir_ate_cair_com(
            self.arch,
            &self.artefato(),
            Ambiente::ligar(self.arch, None)?.com_disco(self.disco.clone()),
            ESPERA_PELA_QUEDA,
        );
        p::sem_plano(&self.disco)?;
        match caiu? {
            c if c == ponto => Ok(()),
            outro => Err(format!("a maquina caiu no ponto {outro}, e nao no {ponto}")),
        }
    }

    /// O agente `sistema` do operador na porta `porta`, fixando `publica`.
    fn agente(&self, publica: &[u8; 32], porta: u8) -> Result<AgenteNaPorta, String> {
        AgenteNaPorta::conectar_com_publica(self.arch, porta, &self.sistema, publica)
    }

    /// As duas cópias da área do selo, como estão no disco.
    fn area(&self) -> Result<[[u8; TAM_AREA]; 2], String> {
        let estado = super::ler_o_estado(&self.disco)?;
        let base = (disco::ESTADO_SETORES - diario::RESERVA_NO_FIM) as usize * TAM_AREA;
        let mut copias = [[0u8; TAM_AREA]; 2];
        for (i, c) in copias.iter_mut().enumerate() {
            c.copy_from_slice(&estado[base + i * TAM_AREA..base + (i + 1) * TAM_AREA]);
        }
        Ok(copias)
    }

    /// A área inteira — as duas cópias iguais e válidas —, ou o que ela é.
    fn area_inteira(&self) -> Result<Area, String> {
        let [a, b] = self.area()?;
        match (ancora::identidade::ler(&a), a == b) {
            (Leitura::Valida(area), true) => Ok(area),
            (l, iguais) => Err(format!(
                "a area do selo nao esta inteira: a primeira copia {}, as duas {}",
                descrever(&l),
                if iguais { "iguais" } else { "diferentes" }
            )),
        }
    }

    /// Grava a cópia `copia` da área do selo no disco.
    fn gravar_copia(&self, copia: usize, bytes: &[u8; TAM_AREA]) -> Result<(), String> {
        let mut estado = super::ler_o_estado(&self.disco)?;
        let base = (disco::ESTADO_SETORES - diario::RESERVA_NO_FIM) as usize * TAM_AREA;
        estado[base + copia * TAM_AREA..base + (copia + 1) * TAM_AREA].copy_from_slice(bytes);
        super::escrever_no_estado(&self.disco, &estado)
    }
}

/// O que uma leitura de uma cópia é, para uma mensagem.
fn descrever(l: &Leitura) -> &'static str {
    match l {
        Leitura::Valida(_) => "inteira",
        Leitura::Vazia => "vazia",
        Leitura::Estragada => "estragada",
        Leitura::Ilegivel => "ilegivel",
    }
}

/// Os registros `system.identity` da auditoria, lidos pelo agente.
fn da_identidade_na_auditoria(agente: &mut AgenteNaPorta) -> Result<Vec<p::Rastro>, String> {
    let r = agente.pedir("audit.tail", r#"{"count":128}"#)?;
    Ok(p::rastros(&r)?
        .into_iter()
        .filter(|r| r.metodo == "system.identity")
        .collect())
}

/// A recusa da identidade na auditoria — pelo kernel, sem recurso, com
/// `motivo` —, e nenhum outro registro dela, lidos pela serial: numa
/// máquina sem identidade nenhum agente entra.
fn recusa_na_auditoria(m: &mut Ligada, motivo: &str) -> Result<(), String> {
    let r = m.pedir("audit.tail", r#"{"count":128}"#)?;
    let da_identidade: Vec<_> = p::rastros(&r)?
        .into_iter()
        .filter(|r| r.metodo == "system.identity")
        .collect();
    match da_identidade.as_slice() {
        [r] if r.titular == "kernel" && r.codigo == "ERROR" && r.recurso.is_empty() => {}
        outro => {
            return Err(format!(
                "a recusa da identidade nao foi para a auditoria, e so ela: {outro:?}"
            ));
        }
    }
    if !r.contains(&format!(r#""detail":"{motivo}""#)) {
        return Err(format!(
            "a auditoria nao diz por que a identidade foi recusada (`{motivo}`)\n  {r}"
        ));
    }
    Ok(())
}

/// A máquina sem identidade: o `system.info` diz `none` com `motivo`, a
/// recusa na auditoria, a persistência — com journal no disco — recusada,
/// e o agente que fixa `publica` não entra.
fn sem_identidade(
    b: &Bancada,
    m: &mut Ligada,
    motivo: &str,
    publica: &[u8; 32],
) -> Result<(), String> {
    let vista = p::identidade_vista(m)?;
    if vista.origem != "none" || vista.erro.as_deref() != Some(motivo) {
        return Err(format!(
            "a identidade nao foi recusada por `{motivo}`: {} ({:?})",
            vista.origem, vista.erro
        ));
    }
    recusa_na_auditoria(m, motivo)?;
    let estado = p::persistencia_de(m)?;
    if estado.estado != "refused" {
        return Err(format!(
            "sem identidade e com journal, a persistencia nao foi recusada: {} ({})",
            estado.estado, estado.motivo
        ));
    }
    if b.agente(publica, 2).is_ok() {
        return Err("o agente entrou numa maquina sem identidade".into());
    }
    Ok(())
}

/// O primeiro boot de uma máquina nova, e o que ele deixa: a pública que
/// ela mostra, e a área do selo no disco.
fn nascer(b: &Bancada) -> Result<([u8; 32], Area), String> {
    let mut m = b.ligar()?;
    let r = (|| {
        let publica = p::identidade_com_origem(&mut m, "born")?;
        let estado = p::persistencia_de(&mut m)?;
        if estado.estado != "available" {
            return Err(format!(
                "a persistencia nao abriu no boot do nascimento: {} ({})",
                estado.estado, estado.motivo
            ));
        }
        Ok((publica, estado.ek))
    })();
    m.cortar_a_energia()?;
    let (publica, ek) = r?;
    let area = b.area_inteira()?;
    if area.publica != publica {
        return Err("a area do selo guarda outra publica que a que a maquina mostrou".into());
    }
    // O `system.info` diz a impressão da EK do journal: os oito primeiros
    // bytes do ponto.
    if sigilo::hex_de(&area.ek[..8]) != ek {
        return Err(format!(
            "a area do selo fixou outra EK que a do TPM da maquina ({ek})"
        ));
    }
    Ok((publica, area))
}

/// Um cenário: um nome que se lê como afirmação, e a função que a confere.
struct Cenario {
    nome: &'static str,
    rodar: fn(&Bancada) -> Result<String, String>,
}

const CENARIOS: &[Cenario] = &[
    Cenario {
        nome: "o primeiro boot: a identidade nasce, selada no TPM, a maquina mostra a publica, a auditoria registra, e o agente que a fixa entra",
        rodar: o_primeiro_boot,
    },
    Cenario {
        nome: "os boots seguintes: a mesma identidade, aberta do selo, sem nascer de novo",
        rodar: os_boots_seguintes,
    },
    Cenario {
        nome: "a energia caindo em cada passo do nascimento: antes das copias nasce de novo, com uma abre e repara, e a criacao da ancora interrompida retoma com a mesma",
        rodar: as_quedas_no_nascimento,
    },
    Cenario {
        nome: "a energia caindo com o cache do disco por descarregar, na descarga de cada copia e na primeira do journal: o boot seguinte nasce de novo ou abre a copia descarregada, e nunca recusa",
        rodar: o_cache_do_disco_no_nascimento,
    },
    Cenario {
        nome: "uma copia do selo estragada: a outra abre e a repara; as duas estragadas recusam, e com elas de volta a identidade volta",
        rodar: as_copias_estragadas,
    },
    Cenario {
        nome: "sem o TPM: a identidade nao abre nem nasce, a persistencia recusa, e com o TPM de volta a identidade volta",
        rodar: sem_o_tpm,
    },
    Cenario {
        nome: "o disco clonado noutra maquina: a EK nao confere, nada nasce por cima, e a maquina de verdade continua",
        rodar: o_disco_clonado,
    },
    Cenario {
        nome: "reinstalar: o disco novo com o TPM de antes recusa; com o TPM limpo nasce outra; o disco velho no TPM limpo nao abre",
        rodar: reinstalar,
    },
    Cenario {
        nome: "concorrencia: quatro agentes entram ao mesmo tempo, fixando a identidade nascida, e ela nao muda",
        rodar: os_agentes_ao_mesmo_tempo,
    },
];

fn o_primeiro_boot(b: &Bancada) -> Result<String, String> {
    let mut m = b.ligar()?;
    let r = (|| {
        let publica = p::identidade_com_origem(&mut m, "born")?;
        let mut agente = b.agente(&publica, 1)?;
        let s = agente.pedir("agent.session", "{}")?;
        if !s.contains(r#""agent":"sistema-1""#) {
            return Err(format!("o agente do operador entrou com outro nome\n  {s}"));
        }
        let registro = agente.pedir("agent.registry", "{}")?;
        if !registro.contains(&format!(r#""duke_key":"{}""#, sigilo::hex(&publica))) {
            return Err(format!(
                "o agent.registry diz outra chave do Duke\n  {registro}"
            ));
        }
        // O nascimento na auditoria: pelo kernel, com a pública como
        // recurso, permitido — e um só.
        let nascimentos = da_identidade_na_auditoria(&mut agente)?;
        match nascimentos.as_slice() {
            [n] if n.titular == "kernel"
                && n.codigo == "ALLOW"
                && n.recurso == sigilo::hex(&publica) => {}
            outro => {
                return Err(format!(
                    "a auditoria nao tem o nascimento, e so ele: {outro:?}"
                ));
            }
        }
        Ok(publica)
    })();
    m.cortar_a_energia()?;
    let publica = r?;
    let area = b.area_inteira()?;
    if area.publica != publica {
        return Err("a area do selo guarda outra publica que a que a maquina mostrou".into());
    }
    Ok(format!(
        "{} nascida e selada; as duas copias da area iguais, com a EK do TPM",
        &sigilo::hex(&publica)[..8]
    ))
}

fn os_boots_seguintes(b: &Bancada) -> Result<String, String> {
    let (publica, area) = nascer(b)?;
    for volta in 1..=2 {
        let mut m = b.ligar()?;
        let r = (|| {
            if p::identidade_com_origem(&mut m, "sealed")? != publica {
                return Err(format!("o boot {volta} depois abriu outra identidade"));
            }
            let mut agente = b.agente(&publica, 1)?;
            let nascimentos = da_identidade_na_auditoria(&mut agente)?;
            if nascimentos.len() != 1 {
                return Err(format!(
                    "o boot {volta} depois registrou outra coisa da identidade: {nascimentos:?}"
                ));
            }
            Ok(())
        })();
        m.cortar_a_energia()?;
        r?;
    }
    if b.area_inteira()? != area {
        return Err("os boots seguintes mexeram na area do selo".into());
    }
    Ok(format!(
        "{} aberta do selo em dois boots, com o nascimento registrado uma vez",
        &sigilo::hex(&publica)[..8]
    ))
}

fn as_quedas_no_nascimento(b: &Bancada) -> Result<String, String> {
    let mut feitos = Vec::new();
    // O ponto, o que a área tem de ter depois da queda, e se o boot
    // seguinte abre a mesma chave — com uma cópia a reparar — ou nasce de
    // novo.
    let pontos: [(u8, [bool; 2], &str); 4] = [
        (
            ponto::IDENTIDADE_SELADA,
            [false, false],
            "selada, sem copia",
        ),
        (
            ponto::PRIMEIRA_COPIA,
            [true, false],
            "a primeira copia gravada",
        ),
        (
            ponto::IDENTIDADE_GRAVADA,
            [true, true],
            "as duas copias gravadas",
        ),
        (
            ponto::ANCORA_DEFINIDA,
            [true, true],
            "a ancora definida no TPM",
        ),
    ];
    for (i, (onde, inteiras, nome)) in pontos.into_iter().enumerate() {
        if i > 0 {
            super::zerar_o_tpm(b.arch)?;
            b.disco_novo()?;
        }
        b.ate_cair_em(onde)?;
        let [a, c] = b.area()?;
        let lidas = [ancora::identidade::ler(&a), ancora::identidade::ler(&c)];
        for (copia, (lida, inteira)) in lidas.iter().zip(inteiras).enumerate() {
            let esperada = if inteira { "inteira" } else { "vazia" };
            if descrever(lida) != esperada {
                return Err(format!(
                    "{nome}: a copia {copia} esta {}, e nao {esperada}",
                    descrever(lida)
                ));
            }
        }
        let antes = match &lidas[0] {
            Leitura::Valida(area) => Some(area.publica),
            _ => None,
        };
        let mut m = b.ligar()?;
        let r = (|| {
            let vista = p::identidade_vista(&mut m)?;
            let publica = vista.publica.ok_or_else(|| {
                format!("{nome}: sem identidade depois da queda: {:?}", vista.erro)
            })?;
            match antes {
                // Nada dependia da chave sorteada: nasce outra.
                None if vista.origem == "born" => {}
                // A cópia inteira abre a mesma — e a outra, se faltava,
                // é reparada.
                Some(p) if vista.origem == "sealed" && p == publica => {}
                _ => {
                    return Err(format!(
                        "{nome}: depois da queda, a identidade e {} ({}), e a area tinha {:?}",
                        vista.origem,
                        sigilo::hex(&publica),
                        antes.map(|p| sigilo::hex(&p))
                    ));
                }
            }
            let estado = p::persistencia_de(&mut m)?;
            if estado.estado != "available" {
                return Err(format!(
                    "{nome}: a persistencia nao abriu depois da queda: {} ({})",
                    estado.estado, estado.motivo
                ));
            }
            let mut agente = b.agente(&publica, 1)?;
            let registros = da_identidade_na_auditoria(&mut agente)?;
            let reparos = registros
                .iter()
                .filter(|r| r.codigo == "ALLOW" && r.recurso == sigilo::hex(&publica))
                .count();
            let esperados = match onde {
                // O nascimento do boot seguinte — o da queda não gravou
                // nada no journal.
                ponto::IDENTIDADE_SELADA => 1,
                // O reparo da segunda cópia. O nascimento foi do boot que
                // caiu, e não chegou a nenhum journal.
                ponto::PRIMEIRA_COPIA => 1,
                _ => 0,
            };
            if reparos != esperados {
                return Err(format!(
                    "{nome}: a auditoria tem {reparos} registros da identidade, e nao {esperados}: {registros:?}"
                ));
            }
            Ok(publica)
        })();
        m.cortar_a_energia()?;
        let publica = r?;
        let area = b.area_inteira()?;
        if area.publica != publica {
            return Err(format!("{nome}: a area nao ficou com a identidade aberta"));
        }
        feitos.push(nome);
    }
    Ok(feitos.join("; "))
}

/// A energia caindo com o cache do disco por descarregar, pelo disco
/// hostil — ver `xtask/src/disco_hostil.rs`: cada escrita fica num cache
/// volátil até a descarga, e o corte o perde todo. O corte vem na descarga
/// de cada cópia, antes de ela gravar, e na primeira descarga depois das
/// duas, que é a do journal.
///
/// O que o nascimento promete é a ordem: a chave só entra em uso — a
/// âncora e o nascimento definidos no TPM, o journal — depois de uma cópia
/// descarregada. O arquivo do disco sozinho não pega uma descarga que
/// falta: o que o emulador escreveu está no cache do hospedeiro e
/// sobrevive à morte dele. Aqui, sem ela, o corte levaria as duas cópias
/// com os índices do Duke já no TPM, e a máquina ficaria recusada como a
/// de outra instalação, para sempre.
fn o_cache_do_disco_no_nascimento(b: &Bancada) -> Result<String, String> {
    let mut feitos = Vec::new();
    // A descarga em que a energia acaba, as cópias que o arquivo guarda
    // depois do corte, e o nome.
    let cortes: [(u64, [bool; 2], &str); 3] = [
        (1, [false, false], "na descarga da primeira copia"),
        (2, [true, false], "na descarga da segunda copia"),
        (3, [true, true], "na primeira descarga do journal"),
    ];
    for (i, (n, inteiras, nome)) in cortes.into_iter().enumerate() {
        if i > 0 {
            super::zerar_o_tpm(b.arch)?;
            b.disco_novo()?;
        }
        let disco = DiscoHostil::servir(
            &b.disco,
            &p::socket_do_disco_hostil(b.arch),
            Corte::PerdeTudo,
        )?;
        disco.cortar_em(Gatilho::Descarga(n));
        // O boot segue depois do corte, sem disco: a máquina sobe, ou não,
        // e a bancada a desliga quando o servidor diz que cortou.
        let ligada = Ligada::subir_com(
            b.arch,
            &b.artefato(),
            Ambiente::ligar(b.arch, None)?.com_disco_hostil(disco.socket()),
        );
        let limite = Instant::now() + ESPERA_PELA_QUEDA;
        while disco.contas().cortes == 0 && Instant::now() < limite {
            std::thread::sleep(Duration::from_millis(50));
        }
        if let Ok(m) = ligada {
            m.cortar_a_energia()?;
        }
        let contas = disco.esperar_o_fim_da_conexao(1)?;
        drop(disco);
        if contas.cortes != 1 || contas.no_corte == 0 {
            return Err(format!(
                "{nome}: o corte nao pegou nada no cache: {contas:?}"
            ));
        }
        let [a, c] = b.area()?;
        let lidas = [ancora::identidade::ler(&a), ancora::identidade::ler(&c)];
        for (copia, (lida, inteira)) in lidas.iter().zip(inteiras).enumerate() {
            let esperada = if inteira { "inteira" } else { "vazia" };
            if descrever(lida) != esperada {
                return Err(format!(
                    "{nome}: a copia {copia} esta {}, e nao {esperada}",
                    descrever(lida)
                ));
            }
        }
        let antes = match &lidas[0] {
            Leitura::Valida(area) => Some(area.publica),
            _ => None,
        };
        let mut m = b.ligar()?;
        let r = (|| {
            let vista = p::identidade_vista(&mut m)?;
            let publica = vista.publica.ok_or_else(|| {
                format!("{nome}: sem identidade depois do corte: {:?}", vista.erro)
            })?;
            match antes {
                None if vista.origem == "born" => {}
                Some(p) if vista.origem == "sealed" && p == publica => {}
                _ => {
                    return Err(format!(
                        "{nome}: depois do corte, a identidade e {} ({}), e a area tinha {:?}",
                        vista.origem,
                        sigilo::hex(&publica),
                        antes.map(|p| sigilo::hex(&p))
                    ));
                }
            }
            let estado = p::persistencia_de(&mut m)?;
            if estado.estado != "available" {
                return Err(format!(
                    "{nome}: a persistencia nao abriu depois do corte: {} ({})",
                    estado.estado, estado.motivo
                ));
            }
            Ok(publica)
        })();
        m.cortar_a_energia()?;
        let publica = r?;
        if b.area_inteira()?.publica != publica {
            return Err(format!("{nome}: a area nao ficou com a identidade aberta"));
        }
        feitos.push(format!(
            "{nome}: {} setores no cache no corte",
            contas.no_corte
        ));
    }
    Ok(feitos.join("; "))
}

fn as_copias_estragadas(b: &Bancada) -> Result<String, String> {
    let (publica, area) = nascer(b)?;
    let inteira = area.em_bytes();
    for copia in 0..2 {
        let mut estragada = inteira;
        estragada[200] ^= 0x04;
        b.gravar_copia(copia, &estragada)?;
        let mut m = b.ligar()?;
        let r = (|| {
            if p::identidade_com_origem(&mut m, "sealed")? != publica {
                return Err(format!("com a copia {copia} estragada, outra identidade"));
            }
            let mut agente = b.agente(&publica, 1)?;
            let reparo = da_identidade_na_auditoria(&mut agente)?
                .into_iter()
                .filter(|r| r.codigo == "ALLOW")
                .count();
            if reparo != copia + 2 {
                return Err(format!(
                    "o reparo da copia {copia} nao foi para a auditoria ({reparo} registros)"
                ));
            }
            Ok(())
        })();
        m.cortar_a_energia()?;
        r?;
        if b.area()?[copia] != inteira {
            return Err(format!("a copia {copia} nao foi reparada"));
        }
    }
    let mut estragada = inteira;
    estragada[300] ^= 0x01;
    b.gravar_copia(0, &estragada)?;
    b.gravar_copia(1, &[0x5A; TAM_AREA])?;
    let mut m = b.ligar()?;
    let r = sem_identidade(b, &mut m, Recusa::SemSelo.motivo(), &publica);
    m.cortar_a_energia()?;
    r?;
    // Nada nasceu por cima: as cópias estão como ficaram.
    if b.area()? != [estragada, [0x5A; TAM_AREA]] {
        return Err("a recusa mexeu na area do selo".into());
    }
    b.gravar_copia(0, &inteira)?;
    b.gravar_copia(1, &inteira)?;
    let mut m = b.ligar()?;
    let r = p::identidade_com_origem(&mut m, "sealed").and_then(|aberta| {
        let estado = p::persistencia_de(&mut m)?;
        if aberta != publica || estado.estado != "available" {
            return Err(format!(
                "com a area de volta, a identidade ou a persistencia nao voltaram: {} ({})",
                estado.estado, estado.motivo
            ));
        }
        Ok(())
    });
    m.cortar_a_energia()?;
    r?;
    Ok(format!(
        "{}: cada copia reparada pela outra; as duas estragadas recusam sem nascer; de volta, abre",
        &sigilo::hex(&publica)[..8]
    ))
}

fn sem_o_tpm(b: &Bancada) -> Result<String, String> {
    let (publica, area) = nascer(b)?;
    let mut m = b.ligar_sem_tpm()?;
    let r = sem_identidade(b, &mut m, Recusa::SemTpm.motivo(), &publica);
    m.cortar_a_energia()?;
    r?;
    if b.area_inteira()? != area {
        return Err("o boot sem TPM mexeu na area do selo".into());
    }
    let mut m = b.ligar()?;
    let r = p::identidade_com_origem(&mut m, "sealed");
    m.cortar_a_energia()?;
    if r? != publica {
        return Err("com o TPM de volta, outra identidade".into());
    }
    Ok(format!(
        "{}: sem TPM recusada, a persistencia recusada; com ele de volta, aberta",
        &sigilo::hex(&publica)[..8]
    ))
}

fn o_disco_clonado(b: &Bancada) -> Result<String, String> {
    let (publica, area) = nascer(b)?;
    // O clone: o disco inteiro copiado para outra máquina — outro TPM.
    let original =
        super::raiz_do_estado().join(format!("identidade-original-{}.img", b.arch.nome()));
    std::fs::copy(&b.disco, &original).map_err(|e| format!("o clone: {e}"))?;
    super::guardar_o_tpm(b.arch, &b.tpm_guardado)?;
    let r = (|| -> Result<(), String> {
        let mut m = b.ligar()?;
        let r = sem_identidade(
            b,
            &mut m,
            "o TPM nao e o do nascimento da identidade: outra chave de endosso",
            &publica,
        );
        m.cortar_a_energia()?;
        r?;
        // Nada nasceu por cima no clone.
        if b.area_inteira()? != area {
            return Err("o boot do clone mexeu na area do selo".into());
        }
        Ok(())
    })();
    super::repor_o_tpm(b.arch, &b.tpm_guardado)?;
    std::fs::rename(&original, &b.disco).map_err(|e| format!("o original: {e}"))?;
    r?;
    let mut m = b.ligar()?;
    let r = p::identidade_com_origem(&mut m, "sealed").and_then(|aberta| {
        let estado = p::persistencia_de(&mut m)?;
        if aberta != publica || estado.estado != "available" {
            return Err(format!(
                "a maquina de verdade nao continuou: {} ({})",
                estado.estado, estado.motivo
            ));
        }
        Ok(())
    });
    m.cortar_a_energia()?;
    r?;
    Ok(format!(
        "o clone de {} recusado noutro TPM, sem nascer; o original continua",
        &sigilo::hex(&publica)[..8]
    ))
}

fn reinstalar(b: &Bancada) -> Result<String, String> {
    let (publica, area) = nascer(b)?;
    let velho = super::raiz_do_estado().join(format!("identidade-velho-{}.img", b.arch.nome()));
    std::fs::copy(&b.disco, &velho).map_err(|e| format!("o disco velho: {e}"))?;
    let r = (|| {
        // O disco novo com o TPM de antes: os índices da instalação velha
        // estão lá, e nada nasce por cima deles.
        b.disco_novo()?;
        let mut m = b.ligar()?;
        let motivo = Recusa::TpmDeOutraInstalacao.motivo();
        let vista = p::identidade_vista(&mut m)
            .and_then(|v| recusa_na_auditoria(&mut m, motivo).map(|()| v));
        m.cortar_a_energia()?;
        let vista = vista?;
        if vista.origem != "none" || vista.erro.as_deref() != Some(motivo) {
            return Err(format!(
                "o disco novo no TPM de antes nao recusou: {} ({:?})",
                vista.origem, vista.erro
            ));
        }
        if b.area()? != [[0; TAM_AREA]; 2] {
            return Err("a recusa gravou alguma coisa na area do disco novo".into());
        }
        // O TPM limpo, como no firmware: nasce outra identidade.
        limpar_o_tpm(b.arch)?;
        let (nova, _) = nascer(b)?;
        if nova == publica {
            return Err("a reinstalacao nasceu com a identidade de antes".into());
        }
        // O disco velho no TPM limpo: a mesma EK, outro primário, e o selo
        // de antes não abre.
        std::fs::copy(&velho, &b.disco).map_err(|e| format!("o disco velho: {e}"))?;
        let mut m = b.ligar()?;
        let r = sem_identidade(
            b,
            &mut m,
            "o selo da identidade nao abre neste TPM: limpo depois do nascimento, ou o selo foi mexido",
            &publica,
        );
        m.cortar_a_energia()?;
        r?;
        if b.area_inteira()? != area {
            return Err("o boot do disco velho mexeu na area do selo".into());
        }
        Ok(nova)
    })();
    let _ = std::fs::remove_file(&velho);
    let nova = r?;
    Ok(format!(
        "{} recusada no disco novo sem limpar; {} nascida com o TPM limpo; o disco velho nao abre nele",
        &sigilo::hex(&publica)[..8],
        &sigilo::hex(&nova)[..8]
    ))
}

fn os_agentes_ao_mesmo_tempo(b: &Bancada) -> Result<String, String> {
    let mut m = b.ligar()?;
    let r = (|| -> Result<[u8; 32], String> {
        let publica = p::identidade_com_origem(&mut m, "born")?;
        let fios: Vec<_> = (1..=4u8)
            .map(|porta| {
                let chave = b.sistema;
                let arch = b.arch;
                std::thread::spawn(move || -> Result<(), String> {
                    let mut agente =
                        AgenteNaPorta::conectar_com_publica(arch, porta, &chave, &publica)?;
                    for _ in 0..5 {
                        let r = agente.pedir("agent.registry", "{}")?;
                        if !r.contains(&format!(r#""duke_key":"{}""#, sigilo::hex(&publica))) {
                            return Err(format!("porta {porta}: outra chave do Duke\n  {r}"));
                        }
                    }
                    Ok(())
                })
            })
            .collect();
        for fio in fios {
            fio.join()
                .map_err(|_| "um agente entrou em panico".to_string())??;
        }
        if p::identidade_com_origem(&mut m, "born")? != publica {
            return Err("a identidade mudou com os agentes".into());
        }
        Ok(publica)
    })();
    m.cortar_a_energia()?;
    let publica = r?;
    Ok(format!(
        "quatro agentes, vinte pedidos, todos com {}",
        &sigilo::hex(&publica)[..8]
    ))
}

/// O TPM da máquina limpo, como o operador o limpa no firmware antes de
/// reinstalar: o `TPM2_Clear` pela hierarquia do bloqueio, com a senha
/// dela, vazia. A semente do dono muda — o primário do cofre também, e
/// nada selado antes abre —, os índices do dono somem, e a EK fica.
fn limpar_o_tpm(arch: Arquitetura) -> Result<(), String> {
    let dir = super::diretorio_do_tpm(arch);
    let socket = dir.join("limpar.sock");
    let _ = std::fs::remove_file(&socket);
    let mut swtpm = Command::new("swtpm")
        .args([
            "socket",
            "--tpm2",
            "--tpmstate",
            &format!("dir={}", dir.join("estado").display()),
            "--server",
            &format!("type=unixio,path={}", socket.display()),
            "--flags",
            "not-need-init",
        ])
        .spawn()
        .map_err(|e| format!("não foi possível iniciar o swtpm para limpar: {e}"))?;
    let r = (|| -> Result<(), String> {
        let limite = Instant::now() + Duration::from_secs(10);
        let mut fluxo = loop {
            if let Ok(f) = UnixStream::connect(&socket) {
                break f;
            }
            if Instant::now() >= limite {
                return Err("o swtpm de limpar nao abriu o socket".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        fluxo
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|e| e.to_string())?;
        let mut trocar = |comando: &[u8]| -> Result<u32, String> {
            fluxo.write_all(comando).map_err(|e| e.to_string())?;
            let mut cabecalho = [0u8; 10];
            fluxo
                .read_exact(&mut cabecalho)
                .map_err(|e| e.to_string())?;
            let n = u32::from_be_bytes(cabecalho[2..6].try_into().expect("4 bytes")) as usize;
            let mut resto = vec![0u8; n.saturating_sub(10)];
            fluxo.read_exact(&mut resto).map_err(|e| e.to_string())?;
            Ok(u32::from_be_bytes(
                cabecalho[6..10].try_into().expect("4 bytes"),
            ))
        };
        // TPM2_Startup(CLEAR) — já iniciado também serve.
        match trocar(&[0x80, 0x01, 0, 0, 0, 0x0C, 0, 0, 0x01, 0x44, 0, 0])? {
            0 | 0x100 => {}
            rc => return Err(format!("o TPM2_Startup de limpar devolveu {rc:#x}")),
        }
        // TPM2_Clear(TPM_RH_LOCKOUT), pela sessão de senha vazia.
        let limpar = [
            0x80, 0x02, 0, 0, 0, 0x1B, 0, 0, 0x01, 0x26, 0x40, 0, 0, 0x0A, 0, 0, 0, 0x09, 0x40, 0,
            0, 0x09, 0, 0, 0x01, 0, 0,
        ];
        match trocar(&limpar)? {
            0 => {}
            rc => return Err(format!("o TPM2_Clear devolveu {rc:#x}")),
        }
        // TPM2_Shutdown(CLEAR): o estado vai para o disco do swtpm.
        trocar(&[0x80, 0x01, 0, 0, 0, 0x0C, 0, 0, 0x01, 0x45, 0, 0])?;
        Ok(())
    })();
    let _ = swtpm.kill();
    let _ = swtpm.wait();
    let _ = std::fs::remove_file(&socket);
    r
}

/// `cargo xtask identidade`: roda os cenários e diz quais passaram. O
/// kernel é o de produção com os pontos de queda — os de todos os
/// cenários, para a imagem ser uma só. `DUKE_CENARIOS` filtra pelo nome,
/// como nas outras bancadas.
pub(crate) fn identidade(arch: Arquitetura, release: bool) -> Result<ExitCode, String> {
    let _ = p::SERIAL_DA_BANCADA
        .set(super::raiz_do_estado().join(format!("identidade-{}.serial", arch.nome())));
    let filtro = std::env::var("DUKE_CENARIOS").ok();
    let escolhido = |c: &&Cenario| {
        filtro
            .as_deref()
            .is_none_or(|f| f.split('|').any(|p| c.nome.contains(p)))
    };
    let escolhidos: Vec<&Cenario> = CENARIOS.iter().filter(escolhido).collect();
    super::build_com(arch, release, &[p::FEATURE_DE_QUEDAS])?;
    let b = Bancada::preparar(arch)?;
    println!(
        "[xtask] identidade: {} cenarios, cada um numa maquina de producao nova - o disco do provisionar e um TPM novo - pelo firmware ({})",
        escolhidos.len(),
        arch.nome()
    );
    let mut falhas = 0;
    for cenario in escolhidos {
        super::zerar_o_tpm(arch)?;
        b.disco_novo()?;
        if let (None, Some(serial)) = (std::env::var_os("DUKE_BANCADA_LOG"), p::serial_do_cenario())
        {
            let _ = std::fs::write(serial, b"");
        }
        let inicio = Instant::now();
        match (cenario.rodar)(&b) {
            Ok(detalhe) => println!(
                "  [identidade] ok  {} ({}s): {detalhe}",
                cenario.nome,
                inicio.elapsed().as_secs()
            ),
            Err(motivo) => {
                falhas += 1;
                println!("  [identidade] FALHOU  {}: {motivo}", cenario.nome);
                p::mostrar_o_fim_da_serial();
            }
        }
    }
    let _ = std::fs::remove_file(&b.disco);
    let _ = std::fs::remove_file(&b.molde);
    let _ = std::fs::remove_dir_all(&b.tpm_guardado);
    super::zerar_o_tpm(arch)?;
    if falhas > 0 {
        println!("\n[xtask] identidade: {falhas} cenario(s) falharam");
        return Ok(ExitCode::FAILURE);
    }
    println!("\n[xtask] identidade: todos os cenarios passaram");
    Ok(ExitCode::SUCCESS)
}
