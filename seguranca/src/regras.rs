//! As regras de detecção.
//!
//! Cada regra tem nome, severidade e explicação, e aponta os registros que
//! a dispararam. As janelas são medidas pelo tempo dos registros. Uma regra
//! dispara uma vez por nível para a mesma identidade — a sondagem que
//! continua não vira cem detecções iguais —, sobe de nível quando a conta
//! passa do degrau seguinte, e pode disparar de novo depois de
//! [`RECARGA_MS`].
//!
//! Detectar não é autorizar: uma detecção abre ou alimenta um incidente e
//! pode levar o NSF a **pedir** uma ação. O que ela não faz é decidir nada:
//! o gate não lê o que está aqui.
//!
//! # Categoria e confiança
//!
//! Cada detecção diz **o que** é — [`Categoria`]: o incomum, o arriscado, a
//! violação, o contorno, que não são a mesma coisa — e **quanto** ela diz
//! de uma ameaça real — [`Confianca`]. A severidade é o tamanho do estrago
//! se for verdade; a confiança, o quanto é verdade. O que o NSF faz com a
//! detecção depende das duas: ver [`crate::resposta`].
//!
//! # Volume não é ameaça
//!
//! As contas são do que distingue um ataque de uma repetição: a sondagem
//! conta métodos **distintos**; "fora do alcance", pedidos distintos —
//! método e recurso —; o firewall, destinos distintos. O mesmo pedido
//! recusado cem vezes é um agente repetindo, e não um reconhecimento: o
//! gate já o recusa, e a taxa do papel já o limita.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use politica::Codigo;

use crate::dns::{Dns, Resolucao};
use crate::evento::{Evento, Severidade, Tipo, Titular};
use crate::grafo::Grafo;
use crate::ueba::Anomalia;

/// A janela das contagens.
pub const JANELA_MS: u64 = 30_000;
/// Depois disto, a mesma regra pode disparar de novo para a mesma
/// identidade, no mesmo nível.
pub const RECARGA_MS: u64 = 600_000;
/// Métodos distintos recusados por permissão que fazem sondagem.
pub const SONDAGEM: usize = 3;
/// Pedidos distintos — método e recurso — recusados por alcance que fazem
/// o primeiro e o segundo degrau.
pub const FORA_DO_ALCANCE: [usize; 2] = [3, 6];
/// Recusas de autenticação que fazem o primeiro e o segundo degrau.
pub const AUTENTICACAO: [usize; 2] = [3, 10];
/// Destinos distintos barrados pelo firewall que fazem o primeiro e o
/// segundo degrau.
pub const FIREWALL: [usize; 2] = [2, 4];
/// A profundidade de uma cadeia de processos que chama atenção.
pub const PROFUNDIDADE: usize = 4;
/// Nascimentos da mesma raiz, na janela, que chamam atenção.
pub const RAJADA_DE_PROCESSOS: usize = 6;
/// Quantos eventos a janela de cada identidade guarda.
const MAIS_NA_JANELA: usize = 64;
/// Quantas identidades o detector acompanha.
const MAIS_IDENTIDADES: usize = 64;

/// As mudanças de política.
const METODOS_DE_POLITICA: &[&str] = &["policy.write", "policy.assign"];

/// Uma regra.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Regra {
    SondagemDePrivilegio,
    ForaDoManifesto,
    AbusoDeCredencial,
    ForaDoAlcance,
    MudancaDePolitica,
    ComportamentoAnomalo,
    ContornoDoFirewall,
    DnsContraAPolitica,
    CadeiaDeProcessos,
    TetoExercido,
    SaidaDepoisDeSondagem,
    // O monitor de invariantes — ver [`crate::invariantes`].
    AuditoriaAdulterada,
    LacunaNaLeitura,
    TempoQueVolta,
    AcaoSemPlano,
}

impl Regra {
    /// O nome, como as consultas o escrevem.
    pub const fn nome(self) -> &'static str {
        match self {
            Regra::SondagemDePrivilegio => "privilege-probing",
            Regra::ForaDoManifesto => "outside-manifest",
            Regra::AbusoDeCredencial => "credential-abuse",
            Regra::ForaDoAlcance => "out-of-scope",
            Regra::MudancaDePolitica => "policy-change",
            Regra::ComportamentoAnomalo => "anomalous-behavior",
            Regra::ContornoDoFirewall => "firewall-evasion",
            Regra::DnsContraAPolitica => "dns-against-policy",
            Regra::CadeiaDeProcessos => "process-chain",
            Regra::TetoExercido => "ceiling-exercised",
            Regra::SaidaDepoisDeSondagem => "egress-after-probing",
            Regra::AuditoriaAdulterada => "audit-tampered",
            Regra::LacunaNaLeitura => "audit-gap",
            Regra::TempoQueVolta => "time-goes-back",
            Regra::AcaoSemPlano => "unplanned-nsf-action",
        }
    }

    /// O que a regra vê — ver [`Categoria`].
    pub const fn categoria(self) -> Categoria {
        match self {
            Regra::ComportamentoAnomalo | Regra::CadeiaDeProcessos => Categoria::Incomum,
            Regra::AbusoDeCredencial
            | Regra::MudancaDePolitica
            | Regra::DnsContraAPolitica
            | Regra::LacunaNaLeitura
            | Regra::TempoQueVolta => Categoria::Risco,
            Regra::SondagemDePrivilegio
            | Regra::ForaDoManifesto
            | Regra::ForaDoAlcance
            | Regra::ContornoDoFirewall
            | Regra::SaidaDepoisDeSondagem => Categoria::Violacao,
            Regra::TetoExercido | Regra::AuditoriaAdulterada | Regra::AcaoSemPlano => {
                Categoria::Contorno
            }
        }
    }

    /// Todas, para quem lista.
    pub const TODAS: [Regra; 15] = [
        Regra::SondagemDePrivilegio,
        Regra::ForaDoManifesto,
        Regra::AbusoDeCredencial,
        Regra::ForaDoAlcance,
        Regra::MudancaDePolitica,
        Regra::ComportamentoAnomalo,
        Regra::ContornoDoFirewall,
        Regra::DnsContraAPolitica,
        Regra::CadeiaDeProcessos,
        Regra::TetoExercido,
        Regra::SaidaDepoisDeSondagem,
        Regra::AuditoriaAdulterada,
        Regra::LacunaNaLeitura,
        Regra::TempoQueVolta,
        Regra::AcaoSemPlano,
    ];
}

/// O que uma detecção é — a seção 3 do incremento de usabilidade: estas
/// quatro coisas não se tratam como equivalentes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Categoria {
    /// Fora do perfil, sem ser recusado: o volume, um método novo, uma
    /// cadeia de processos. Um agente de compilação é incomum o dia todo.
    Incomum,
    /// Pode ser o começo de algo: falhas de autenticação, DNS que leva a um
    /// destino recusado, mudança de política recusada, a leitura que perdeu
    /// registros.
    Risco,
    /// O gate recusou por política de um jeito que diz intenção — métodos
    /// que o papel não dá, recursos fora do alcance, o manifesto —, ou a
    /// rede usada depois disso.
    Violacao,
    /// Alguém tentou passar por cima da autoridade: o teto do administrador
    /// exercido, uma ação do NSF sem plano, a auditoria adulterada.
    Contorno,
}

impl Categoria {
    /// O nome, como as consultas o escrevem.
    pub const fn nome(self) -> &'static str {
        match self {
            Categoria::Incomum => "unusual",
            Categoria::Risco => "risky",
            Categoria::Violacao => "violation",
            Categoria::Contorno => "bypass",
        }
    }
}

/// Quanto uma detecção diz de uma ameaça real.
///
/// O que é só estatística — o perfil, o volume — é baixa; uma recusa da
/// política que diz intenção é média; alta pede corroboração — duas coisas
/// independentes apontando para o mesmo lado — ou um contorno, que não tem
/// leitura inocente.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confianca {
    Baixa,
    Media,
    Alta,
}

impl Confianca {
    /// O nome, como as consultas o escrevem.
    pub const fn nome(self) -> &'static str {
        match self {
            Confianca::Baixa => "low",
            Confianca::Media => "medium",
            Confianca::Alta => "high",
        }
    }

    /// Um degrau acima, até alta.
    pub const fn acima(self) -> Confianca {
        match self {
            Confianca::Baixa => Confianca::Media,
            _ => Confianca::Alta,
        }
    }
}

/// O que uma contenção alcançaria: o destino, o dono do fluxo, e o papel
/// com que o gate decidiu o pedido — o alcance de uma contenção do dono é
/// `papel:<papel>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alvo {
    pub destino: String,
    pub dono: String,
    pub papel: String,
}

/// Uma detecção.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deteccao {
    pub regra: Regra,
    pub severidade: Severidade,
    pub confianca: Confianca,
    pub principal: String,
    pub titular: Titular,
    /// Os registros da auditoria que a dispararam.
    pub registros: Vec<u64>,
    pub explicacao: String,
    pub alvo: Option<Alvo>,
    pub ts_ms: u64,
    pub epoca: u32,
}

/// O que o detector guarda de cada evento da janela.
#[derive(Clone, Debug)]
struct Visto {
    seq: u64,
    ts: u64,
    metodo: String,
    recurso: String,
    codigo: Codigo,
    tipo: Tipo,
    /// Uma recusa do manifesto do programa — ver
    /// [`Evento::fora_do_manifesto`].
    manifesto: bool,
}

/// Uma conexão que o gate recusou por estar fora do alcance: o dono do
/// fluxo e o endereço — o que uma resolução de DNS pode ter dado.
pub fn conexao_recusada(e: &Evento) -> Option<(String, [u8; 4])> {
    if e.metodo != "net.connect" || e.tipo != Tipo::Decisao || e.codigo != Codigo::DenyResource {
        return None;
    }
    let destino = politica::endereco::ler(&e.recurso)?;
    Some((e.dono()?, destino.ip))
}

/// O que mais as regras olham, além do evento.
pub struct Contexto<'a> {
    pub dns: &'a Dns,
    pub grafo: &'a Grafo,
    pub anomalia: Option<&'a Anomalia>,
}

/// O detector.
#[derive(Clone, Debug, Default)]
pub struct Detector {
    janelas: BTreeMap<String, VecDeque<Visto>>,
    ordem: VecDeque<String>,
    /// O nível e o tempo do último disparo de cada (regra, identidade).
    disparos: BTreeMap<(Regra, String), (u8, u64)>,
    /// Os nascimentos de cada raiz, na janela.
    nascimentos: BTreeMap<String, VecDeque<(u64, u64)>>,
    /// Os nomes que levaram cada identidade a um destino recusado.
    nomes_recusados: BTreeMap<String, BTreeSet<String>>,
}

impl Detector {
    pub fn novo() -> Detector {
        Detector::default()
    }

    /// Se a regra pode disparar no nível `nivel` para `principal` agora; e,
    /// se pode, marca.
    fn pode(&mut self, regra: Regra, principal: &str, nivel: u8, ts: u64) -> bool {
        let chave = (regra, principal.to_string());
        match self.disparos.get(&chave) {
            Some(&(n, t)) if n >= nivel && ts < t + RECARGA_MS => false,
            _ => {
                self.disparos.insert(chave, (nivel, ts));
                true
            }
        }
    }

    /// Esquece os disparos de uma identidade — o incidente dela acabou.
    pub fn esquecer(&mut self, principal: &str) {
        // As chaves da saída depois da sondagem são `identidade>destino`.
        let por_destino = alloc::format!("{principal}>");
        self.disparos
            .retain(|(_, p), _| p != principal && !p.starts_with(&por_destino));
        self.nomes_recusados.remove(principal);
    }

    fn janela(&mut self, e: &Evento) -> &VecDeque<Visto> {
        if !self.janelas.contains_key(&e.principal) {
            if self.ordem.len() == MAIS_IDENTIDADES
                && let Some(velha) = self.ordem.pop_front()
            {
                self.janelas.remove(&velha);
            }
            self.ordem.push_back(e.principal.clone());
        }
        let j = self.janelas.entry(e.principal.clone()).or_default();
        j.push_back(Visto {
            seq: e.seq,
            ts: e.ts_ms,
            metodo: e.metodo.clone(),
            recurso: e.recurso.clone(),
            codigo: e.codigo,
            tipo: e.tipo,
            manifesto: e.fora_do_manifesto(),
        });
        while j.len() > MAIS_NA_JANELA || j.front().is_some_and(|v| v.ts + JANELA_MS < e.ts_ms) {
            j.pop_front();
        }
        j
    }

    /// Passa um evento pelas regras. As detecções novas, em ordem.
    pub fn observar(&mut self, e: &Evento, ctx: &Contexto) -> Vec<Deteccao> {
        let mut saida = Vec::new();
        // As leituras do próprio NSF e os registros do kernel não fazem
        // janela de ninguém.
        if e.tipo == Tipo::Leitura || e.titular == Titular::Kernel && e.tipo == Tipo::Decisao {
            return saida;
        }
        let j: Vec<Visto> = self.janela(e).iter().cloned().collect();
        let det =
            |regra, severidade, confianca, registros: Vec<u64>, explicacao: String| Deteccao {
                regra,
                severidade,
                confianca,
                principal: e.principal.clone(),
                titular: e.titular,
                registros,
                explicacao,
                alvo: None,
                ts_ms: e.ts_ms,
                epoca: e.epoca,
            };
        let decisoes = |c: Codigo| -> Vec<&Visto> {
            j.iter()
                .filter(|v| v.tipo == Tipo::Decisao && v.codigo == c)
                .collect()
        };

        // A sondagem é de quem pede o que o papel dele não dá; a recusa do
        // manifesto de um programa é outra coisa — o papel tem, o programa
        // não declarou —, e tem a regra dela. Três métodos distintos dizem
        // intenção, mas um agente que explora a própria API também os
        // tenta: confiança média. Alta é com a rede usada depois.
        if e.tipo == Tipo::Decisao && e.codigo == Codigo::DenyPermission && !e.fora_do_manifesto() {
            let vs: Vec<&Visto> = decisoes(Codigo::DenyPermission)
                .into_iter()
                .filter(|v| !v.manifesto)
                .collect();
            let metodos: BTreeSet<&str> = vs.iter().map(|v| v.metodo.as_str()).collect();
            if metodos.len() >= SONDAGEM
                && self.pode(Regra::SondagemDePrivilegio, &e.principal, 1, e.ts_ms)
            {
                let lista: Vec<&str> = metodos.into_iter().collect();
                saida.push(det(
                    Regra::SondagemDePrivilegio,
                    Severidade::Alta,
                    Confianca::Media,
                    vs.iter().map(|v| v.seq).collect(),
                    alloc::format!(
                        "{} metodos tentados sem a permissao em {} s: {}",
                        lista.len(),
                        JANELA_MS / 1000,
                        lista.join(", ")
                    ),
                ));
            }
        }

        if e.tipo == Tipo::Decisao
            && e.fora_do_manifesto()
            && self.pode(Regra::ForaDoManifesto, &e.principal, 1, e.ts_ms)
        {
            let programa = e.processo.as_ref().map_or_else(String::new, |(fio, p)| {
                alloc::format!(" {p} (processo {fio})")
            });
            saida.push(det(
                Regra::ForaDoManifesto,
                Severidade::Media,
                Confianca::Media,
                alloc::vec![e.seq],
                alloc::format!(
                    "o programa{programa} pediu {}, que o manifesto dele nao declara — a atenuacao recusou",
                    e.metodo
                ),
            ));
        }

        // Fora do alcance: pedidos distintos. Um alcance estreito demais
        // faz um agente legítimo bater em três recursos — é de olhar, não
        // de alertar; seis distintos em meio minuto é reconhecimento.
        if e.tipo == Tipo::Decisao && e.codigo == Codigo::DenyResource {
            let vs = decisoes(Codigo::DenyResource);
            let (distintos, registros) = primeiros(&vs, |v| (v.metodo.clone(), v.recurso.clone()));
            for (nivel, (&limite, (severidade, confianca))) in FORA_DO_ALCANCE
                .iter()
                .zip([
                    (Severidade::Media, Confianca::Baixa),
                    (Severidade::Alta, Confianca::Media),
                ])
                .enumerate()
                .rev()
            {
                if distintos >= limite {
                    if self.pode(Regra::ForaDoAlcance, &e.principal, nivel as u8 + 1, e.ts_ms) {
                        saida.push(det(
                            Regra::ForaDoAlcance,
                            severidade,
                            confianca,
                            registros,
                            alloc::format!(
                                "{} pedidos distintos fora do alcance do papel em {} s ({} recusas)",
                                distintos,
                                JANELA_MS / 1000,
                                vs.len()
                            ),
                        ));
                    }
                    break;
                }
            }
        }

        // A credencial: uma chave revogada que continua pedindo é de
        // alertar — alguém revogou por um motivo —; falhas de
        // autenticação, de olhar, até serem muitas: quem erra a senha três
        // vezes não é um ataque.
        if e.codigo == Codigo::DenyNotAuthenticated {
            let vs = decisoes(Codigo::DenyNotAuthenticated);
            if vs.len() >= AUTENTICACAO[1]
                && self.pode(Regra::AbusoDeCredencial, &e.principal, 2, e.ts_ms)
            {
                saida.push(det(
                    Regra::AbusoDeCredencial,
                    Severidade::Alta,
                    Confianca::Media,
                    vs.iter().map(|v| v.seq).collect(),
                    alloc::format!(
                        "{} pedidos sem autenticacao valida em {} s ({})",
                        vs.len(),
                        JANELA_MS / 1000,
                        e.detalhe
                    ),
                ));
            } else if e.detalhe.contains("revogad")
                && self.pode(Regra::AbusoDeCredencial, &e.principal, 1, e.ts_ms)
            {
                saida.push(det(
                    Regra::AbusoDeCredencial,
                    Severidade::Media,
                    Confianca::Media,
                    alloc::vec![e.seq],
                    alloc::format!("uso de credencial revogada: {}", e.metodo),
                ));
            } else if vs.len() >= AUTENTICACAO[0]
                && self.pode(Regra::AbusoDeCredencial, &e.principal, 1, e.ts_ms)
            {
                saida.push(det(
                    Regra::AbusoDeCredencial,
                    Severidade::Media,
                    Confianca::Baixa,
                    vs.iter().map(|v| v.seq).collect(),
                    alloc::format!(
                        "{} falhas de autenticacao em {} s ({})",
                        vs.len(),
                        JANELA_MS / 1000,
                        e.detalhe
                    ),
                ));
            }
        }

        if e.codigo == Codigo::DenyRole
            && e.detalhe.contains("teto")
            && self.pode(Regra::TetoExercido, &e.principal, 1, e.ts_ms)
        {
            saida.push(det(
                Regra::TetoExercido,
                Severidade::Alta,
                Confianca::Alta,
                alloc::vec![e.seq],
                alloc::format!("tentou exercer o teto de um administrador: {}", e.metodo),
            ));
        }

        if METODOS_DE_POLITICA.contains(&e.metodo.as_str()) && e.tipo == Tipo::Decisao {
            if e.codigo.permite() {
                // Uma mudança executada é um fato a registrar, não um
                // ataque: severidade baixa, sem incidente.
                saida.push(det(
                    Regra::MudancaDePolitica,
                    Severidade::Baixa,
                    Confianca::Baixa,
                    alloc::vec![e.seq],
                    alloc::format!("{} executada sobre `{}`", e.metodo, e.recurso),
                ));
            } else {
                let vs: Vec<&Visto> = j
                    .iter()
                    .filter(|v| {
                        METODOS_DE_POLITICA.contains(&v.metodo.as_str()) && !v.codigo.permite()
                    })
                    .collect();
                if vs.len() >= 2 && self.pode(Regra::MudancaDePolitica, &e.principal, 1, e.ts_ms) {
                    saida.push(det(
                        Regra::MudancaDePolitica,
                        Severidade::Media,
                        Confianca::Media,
                        vs.iter().map(|v| v.seq).collect(),
                        alloc::format!("{} mudancas de politica recusadas", vs.len()),
                    ));
                }
            }
        }

        // O perfil: o que é só estatística é de olhar. Anomalia não é
        // autorização, e nem alerta sozinha.
        if let Some(a) = ctx.anomalia
            && self.pode(Regra::ComportamentoAnomalo, &e.principal, 1, e.ts_ms)
        {
            let quem = match e.titular {
                Titular::Agente => "agente de IA",
                Titular::Pessoa => "pessoa",
                _ => "identidade",
            };
            saida.push(det(
                Regra::ComportamentoAnomalo,
                Severidade::Media,
                Confianca::Baixa,
                alloc::vec![e.seq],
                alloc::format!("{quem} fora da linha de base: {}", a.motivos.join("; ")),
            ));
        }

        // O firewall: destinos distintos. Quem bate de novo no destino
        // barrado está repetindo — a regra já o segura —; quem procura
        // outro destino depois de barrado é que tenta contornar.
        if matches!(e.tipo, Tipo::Firewall { .. }) {
            let vs: Vec<&Visto> = j
                .iter()
                .filter(|v| matches!(v.tipo, Tipo::Firewall { .. }))
                .collect();
            let (distintos, registros) = primeiros(&vs, |v| v.recurso.clone());
            for (nivel, (&limite, (severidade, confianca))) in FIREWALL
                .iter()
                .zip([
                    (Severidade::Media, Confianca::Baixa),
                    (Severidade::Alta, Confianca::Media),
                ])
                .enumerate()
                .rev()
            {
                if distintos >= limite {
                    if self.pode(
                        Regra::ContornoDoFirewall,
                        &e.principal,
                        nivel as u8 + 1,
                        e.ts_ms,
                    ) {
                        saida.push(det(
                            Regra::ContornoDoFirewall,
                            severidade,
                            confianca,
                            registros,
                            alloc::format!(
                                "{} destinos distintos barrados pelo firewall em {} s, o ultimo {}",
                                distintos,
                                JANELA_MS / 1000,
                                e.recurso
                            ),
                        ));
                    }
                    break;
                }
            }
        }

        if let Some((dono, ip)) = conexao_recusada(e)
            && let Some(r) = ctx.dns.antes_de(&dono, ip, e.seq)
            && let Some(d) = self.dns_contra_a_politica(e, r)
        {
            saida.push(d);
        }

        // Muitos processos é o trabalho de muito agente legítimo: de
        // olhar, nunca de alertar sozinho.
        if let Tipo::Nascimento { filho } = e.tipo {
            let prov = ctx.grafo.proveniencia(e.epoca, filho);
            let raiz = ctx
                .grafo
                .raiz(e.epoca, filho)
                .unwrap_or_else(|| e.principal.clone());
            let lista = self.nascimentos.entry(raiz.clone()).or_default();
            lista.push_back((e.ts_ms, e.seq));
            while lista.front().is_some_and(|(t, _)| t + JANELA_MS < e.ts_ms) {
                lista.pop_front();
            }
            let rajada: Vec<u64> = lista.iter().map(|(_, s)| *s).collect();
            if (prov.cadeia.len() >= PROFUNDIDADE || rajada.len() >= RAJADA_DE_PROCESSOS)
                && self.pode(Regra::CadeiaDeProcessos, &e.principal, 1, e.ts_ms)
            {
                let explicacao = alloc::format!(
                    "processo {filho} numa cadeia de {} a partir de {raiz}; {} nascimentos em {} s",
                    prov.cadeia.len(),
                    rajada.len(),
                    JANELA_MS / 1000
                );
                saida.push(det(
                    Regra::CadeiaDeProcessos,
                    Severidade::Media,
                    Confianca::Baixa,
                    rajada,
                    explicacao,
                ));
            }
        }
        saida
    }

    /// O DNS contra a política: a resolução `r` deu o endereço que o gate
    /// recusou na conexão `e`. Chamada dos dois lados — pela conexão, que
    /// encontra a resolução já lida, e pela resolução, lida da captura
    /// depois da conexão: a ordem das leituras não decide se a regra vê.
    ///
    /// Um nome que mudou de endereço para fora do alcance é o caso de todo
    /// dia de um alcance estreito: de olhar. Dois nomes, de alertar.
    pub fn dns_contra_a_politica(&mut self, e: &Evento, r: &Resolucao) -> Option<Deteccao> {
        let nomes = self.nomes_recusados.entry(e.principal.clone()).or_default();
        nomes.insert(r.nome.clone());
        let n = nomes.len();
        let (nivel, severidade, confianca) = if n >= 2 {
            (2, Severidade::Alta, Confianca::Media)
        } else {
            (1, Severidade::Media, Confianca::Baixa)
        };
        if !self.pode(Regra::DnsContraAPolitica, &e.principal, nivel, e.ts_ms) {
            return None;
        }
        Some(Deteccao {
            regra: Regra::DnsContraAPolitica,
            severidade,
            confianca,
            principal: e.principal.clone(),
            titular: e.titular,
            registros: alloc::vec![e.seq],
            explicacao: alloc::format!(
                "`{}` resolveu para {}, e o gate recusou a conexao ({} nome(s) assim)",
                r.nome,
                e.recurso,
                n
            ),
            alvo: None,
            ts_ms: e.ts_ms,
            epoca: e.epoca,
        })
    }

    /// A saída depois da sondagem: quem tem um incidente alto aberto usa a
    /// rede, e o gate deixou. O alvo é o destino, para o dono do fluxo —
    /// o que uma contenção alcançaria. A confiança é a que o incidente
    /// corrobora — ver [`crate::incidente::Incidente::corroboracao`].
    pub fn saida_depois_de_sondagem(
        &mut self,
        e: &Evento,
        confianca: Confianca,
    ) -> Option<Deteccao> {
        if !(e.tipo == Tipo::Decisao
            && e.codigo.permite()
            && matches!(e.metodo.as_str(), "net.connect" | "net.send"))
        {
            return None;
        }
        let destino = politica::endereco::ler(&e.recurso)?;
        let dono = e.dono()?;
        let chave = alloc::format!("{}>{}", e.principal, destino.texto());
        if !self.pode(Regra::SaidaDepoisDeSondagem, &chave, 1, e.ts_ms) {
            return None;
        }
        Some(Deteccao {
            regra: Regra::SaidaDepoisDeSondagem,
            severidade: Severidade::Alta,
            confianca,
            principal: e.principal.clone(),
            titular: e.titular,
            registros: alloc::vec![e.seq],
            explicacao: alloc::format!(
                "com um incidente alto aberto, usou a rede: {} para {}",
                e.metodo,
                destino.texto()
            ),
            alvo: Some(Alvo {
                destino: destino.texto(),
                dono,
                papel: e.papel.clone(),
            }),
            ts_ms: e.ts_ms,
            epoca: e.epoca,
        })
    }
}

/// Quantos distintos há em `vs` pela chave, e o primeiro registro de cada
/// um — o que mostra cada coisa distinta, sem as repetições.
fn primeiros<K: Ord>(vs: &[&Visto], chave: impl Fn(&Visto) -> K) -> (usize, Vec<u64>) {
    let mut vistos = BTreeSet::new();
    let mut registros = Vec::new();
    for v in vs {
        if vistos.insert(chave(v)) {
            registros.push(v.seq);
        }
    }
    (vistos.len(), registros)
}
#[cfg(test)]
pub(crate) mod testes {
    use super::*;
    use crate::evento::Severidade;

    pub(crate) fn ev(
        seq: u64,
        principal: &str,
        titular: Titular,
        metodo: &str,
        codigo: Codigo,
    ) -> Evento {
        Evento {
            seq,
            elo: [0; 32],
            epoca: 0,
            ts_ms: 1_000 + seq * 100,
            titular,
            principal: principal.to_string(),
            identificador: String::new(),
            chave: Some([0xAA; 32]),
            sessao: 1,
            sessao_de_pessoa: Some([1; 8]),
            papel: "operador".to_string(),
            metodo: metodo.to_string(),
            recurso: String::new(),
            codigo,
            detalhe: String::new(),
            processo: None,
            decisao: None,
            tipo: Tipo::Decisao,
            correlacao: 0,
            severidade: Severidade::Info,
        }
    }

    fn rodar(evs: &[Evento]) -> Vec<Deteccao> {
        let mut d = Detector::novo();
        let (dns, grafo) = (Dns::novo(), Grafo::novo());
        let ctx = Contexto {
            dns: &dns,
            grafo: &grafo,
            anomalia: None,
        };
        evs.iter().flat_map(|e| d.observar(e, &ctx)).collect()
    }

    #[test]
    fn a_sondagem() {
        let evs: Vec<Evento> = [
            "fs.read",
            "policy.show",
            "fs.read",
            "disk.read",
            "audit.tail",
        ]
        .iter()
        .enumerate()
        .map(|(i, m)| {
            ev(
                i as u64 + 1,
                "agent:aa",
                Titular::Agente,
                m,
                Codigo::DenyPermission,
            )
        })
        .collect();
        let ds = rodar(&evs);
        assert_eq!(ds.len(), 1, "{ds:?}");
        assert_eq!(ds[0].regra, Regra::SondagemDePrivilegio);
        assert_eq!(ds[0].severidade, Severidade::Alta);
        // Disparou no quarto: o terceiro método distinto.
        assert_eq!(ds[0].registros, [1, 2, 3, 4]);
        assert!(ds[0].explicacao.contains("disk.read"));
    }

    /// As recusas do manifesto de um programa não são a sondagem de quem o
    /// lançou: o papel tem as permissões, o programa não as declarou. Elas
    /// fazem a regra delas, média, uma vez.
    #[test]
    fn a_recusa_do_manifesto_nao_e_sondagem() {
        let evs: Vec<Evento> = ["fs.open", "message.send", "process.exec", "net.connect"]
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let mut e = ev(
                    i as u64 + 1,
                    "serial",
                    Titular::Serial,
                    m,
                    Codigo::DenyPermission,
                );
                e.processo = Some((9, "contido 0a1b2c3d".to_string()));
                e.detalhe = alloc::format!("o manifesto nao declara {m}");
                e
            })
            .collect();
        let ds = rodar(&evs);
        assert_eq!(ds.len(), 1, "{ds:?}");
        assert_eq!(ds[0].regra, Regra::ForaDoManifesto);
        assert_eq!(ds[0].severidade, Severidade::Media);
        assert!(ds[0].explicacao.contains("contido"), "{}", ds[0].explicacao);
        // Misturadas: só as do papel contam para a sondagem.
        let mut mistas = evs.clone();
        for (i, m) in ["policy.show", "audit.tail"].iter().enumerate() {
            mistas.push(ev(
                10 + i as u64,
                "serial",
                Titular::Serial,
                m,
                Codigo::DenyPermission,
            ));
        }
        assert!(
            rodar(&mistas)
                .iter()
                .all(|d| d.regra != Regra::SondagemDePrivilegio)
        );
    }

    /// Pessoa e agente: a mesma sequência dispara a mesma regra.
    #[test]
    fn pessoa_e_agente_pela_mesma_regra() {
        let seq = |p: &str, t: Titular| -> Vec<(Regra, Severidade, Confianca)> {
            let evs: Vec<Evento> = (1..=7)
                .map(|i| {
                    let mut e = ev(i, p, t, "net.connect", Codigo::DenyResource);
                    e.recurso = alloc::format!("tcp:10.0.2.{i}:80");
                    e
                })
                .collect();
            rodar(&evs)
                .iter()
                .map(|d| (d.regra, d.severidade, d.confianca))
                .collect()
        };
        let agente = seq("agent:aa", Titular::Agente);
        assert_eq!(
            agente,
            [
                (Regra::ForaDoAlcance, Severidade::Media, Confianca::Baixa),
                (Regra::ForaDoAlcance, Severidade::Alta, Confianca::Media)
            ]
        );
        assert_eq!(agente, seq("person:01", Titular::Pessoa));
    }

    /// O mesmo pedido recusado cem vezes é um agente repetindo, não um
    /// reconhecimento: nenhuma regra conta a repetição — nem a do alcance,
    /// nem a do firewall. A sondagem também não: um método só.
    #[test]
    fn a_repeticao_nao_e_reconhecimento() {
        let mut evs = Vec::new();
        for i in 1..=100 {
            let mut e = ev(
                i,
                "agent:aa",
                Titular::Agente,
                "fs.read",
                Codigo::DenyResource,
            );
            e.recurso = "/dados/fora".to_string();
            evs.push(e);
            let mut f = ev(
                1000 + i,
                "agent:aa",
                Titular::Agente,
                "policy.show",
                Codigo::DenyPermission,
            );
            f.recurso = String::new();
            evs.push(f);
            let mut g = ev(
                2000 + i,
                "agent:aa",
                Titular::Agente,
                "net.connect",
                Codigo::DenyPolicy,
            );
            g.tipo = Tipo::Firewall { regra: 1 };
            g.recurso = "tcp:10.0.2.100:7".to_string();
            evs.push(g);
        }
        for e in &mut evs {
            e.ts_ms = 1_000 + e.seq % 1000 * 10;
        }
        evs.sort_by_key(|e| e.ts_ms);
        let ds = rodar(&evs);
        assert!(ds.is_empty(), "{ds:?}");
    }

    /// Cada regra tem a categoria dela, e as quatro existem: o incomum não
    /// é o arriscado, nem a violação, nem o contorno.
    #[test]
    fn as_categorias() {
        let mut vistas = BTreeSet::new();
        for r in Regra::TODAS {
            vistas.insert(r.categoria());
        }
        assert_eq!(
            vistas.into_iter().collect::<Vec<_>>(),
            [
                Categoria::Incomum,
                Categoria::Risco,
                Categoria::Violacao,
                Categoria::Contorno
            ]
        );
        assert_eq!(Regra::ComportamentoAnomalo.categoria(), Categoria::Incomum);
        assert_eq!(Regra::CadeiaDeProcessos.categoria(), Categoria::Incomum);
        assert_eq!(Regra::SondagemDePrivilegio.categoria(), Categoria::Violacao);
        assert_eq!(Regra::TetoExercido.categoria(), Categoria::Contorno);
        assert_eq!(Confianca::Baixa.acima(), Confianca::Media);
        assert_eq!(Confianca::Media.acima(), Confianca::Alta);
        assert_eq!(Confianca::Alta.acima(), Confianca::Alta);
    }

    /// Três falhas de autenticação são de olhar — quem erra a senha não é um
    /// ataque —; dez, de alertar.
    #[test]
    fn as_falhas_de_autenticacao() {
        let falhas = |n: u64| -> Vec<(Severidade, Confianca)> {
            let evs: Vec<Evento> = (1..=n)
                .map(|i| {
                    let mut e = ev(
                        i,
                        "anonymous:person:01",
                        Titular::Anonimo,
                        "login",
                        Codigo::DenyNotAuthenticated,
                    );
                    e.detalhe = "a senha nao confere".to_string();
                    e
                })
                .collect();
            rodar(&evs)
                .iter()
                .map(|d| (d.severidade, d.confianca))
                .collect()
        };
        assert!(falhas(2).is_empty());
        assert_eq!(falhas(3), [(Severidade::Media, Confianca::Baixa)]);
        assert_eq!(
            falhas(10),
            [
                (Severidade::Media, Confianca::Baixa),
                (Severidade::Alta, Confianca::Media)
            ]
        );
    }

    #[test]
    fn a_credencial_revogada() {
        let mut evs: Vec<Evento> = (1..=3)
            .map(|i| {
                ev(
                    i,
                    "agent:aa",
                    Titular::Agente,
                    "agent.ping",
                    Codigo::DenyNotAuthenticated,
                )
            })
            .collect();
        for e in &mut evs {
            e.detalhe = "chave revogada".to_string();
        }
        let ds = rodar(&evs);
        let r: Vec<_> = ds
            .iter()
            .map(|d| (d.regra, d.severidade, d.confianca))
            .collect();
        // Uma vez: a chave revogada que insiste é a mesma coisa.
        assert_eq!(
            r,
            [(
                Regra::AbusoDeCredencial,
                Severidade::Media,
                Confianca::Media
            )]
        );
    }

    #[test]
    fn o_teto_e_a_politica() {
        let mut teto = ev(
            1,
            "agent:aa",
            Titular::Agente,
            "agent.ping",
            Codigo::DenyRole,
        );
        teto.detalhe = "o papel e o teto de um administrador: delega, nao se exerce".to_string();
        let mut feita = ev(
            2,
            "admin:adm",
            Titular::Administrador,
            "policy.write",
            Codigo::Allow,
        );
        feita.recurso = "papel operador ui.read".to_string();
        let r1 = ev(
            3,
            "admin:adm",
            Titular::Administrador,
            "policy.write",
            Codigo::DenyPolicy,
        );
        let r2 = ev(
            4,
            "admin:adm",
            Titular::Administrador,
            "policy.assign",
            Codigo::DenyPolicy,
        );
        let ds = rodar(&[teto, feita, r1, r2]);
        let r: Vec<_> = ds.iter().map(|d| (d.regra, d.severidade)).collect();
        assert_eq!(
            r,
            [
                (Regra::TetoExercido, Severidade::Alta),
                (Regra::MudancaDePolitica, Severidade::Baixa),
                (Regra::MudancaDePolitica, Severidade::Media)
            ]
        );
    }

    /// O firewall: destinos distintos. Bater de novo no mesmo destino
    /// barrado não conta; procurar outros, sim.
    #[test]
    fn o_firewall() {
        let barrado = |i: u64, destino: &str| {
            let mut e = ev(
                i,
                "agent:aa",
                Titular::Agente,
                "net.connect",
                Codigo::DenyPolicy,
            );
            e.tipo = Tipo::Firewall { regra: 1 };
            e.recurso = destino.to_string();
            e
        };
        let mesmo: Vec<Evento> = (1..=5).map(|i| barrado(i, "tcp:10.0.2.100:7")).collect();
        assert!(rodar(&mesmo).is_empty());
        // Dois destinos, cada um duas vezes, e depois mais dois.
        let outros: Vec<Evento> = [100, 100, 101, 101, 102, 103]
            .iter()
            .zip(1..)
            .map(|(d, i)| barrado(i, &alloc::format!("tcp:10.0.2.{d}:7")))
            .collect();
        let ds = rodar(&outros);
        let r: Vec<_> = ds
            .iter()
            .map(|d| (d.regra, d.severidade, d.confianca, d.registros.clone()))
            .collect();
        assert_eq!(
            r,
            [
                (
                    Regra::ContornoDoFirewall,
                    Severidade::Media,
                    Confianca::Baixa,
                    alloc::vec![1, 3]
                ),
                (
                    Regra::ContornoDoFirewall,
                    Severidade::Alta,
                    Confianca::Media,
                    alloc::vec![1, 3, 5, 6]
                ),
            ],
            "cada degrau com o primeiro registro de cada destino"
        );
    }

    /// O que sai da janela não conta, e a recarga deixa disparar de novo.
    #[test]
    fn janela_e_recarga() {
        let mut d = Detector::novo();
        let (dns, grafo) = (Dns::novo(), Grafo::novo());
        let ctx = Contexto {
            dns: &dns,
            grafo: &grafo,
            anomalia: None,
        };
        let mut n = 0;
        for (i, ts) in [(1, 0), (2, JANELA_MS + 1), (3, 2 * JANELA_MS + 2)] {
            let mut e = ev(
                i,
                "agent:aa",
                Titular::Agente,
                &alloc::format!("m{i}"),
                Codigo::DenyPermission,
            );
            e.ts_ms = ts;
            n += d.observar(&e, &ctx).len();
        }
        assert_eq!(n, 0);
        let mut total = 0;
        for base in [
            10 * JANELA_MS,
            10 * JANELA_MS + 1000,
            10 * JANELA_MS + RECARGA_MS + 1000,
        ] {
            for k in 0..3 {
                let mut e = ev(
                    base + k,
                    "agent:aa",
                    Titular::Agente,
                    &alloc::format!("x{k}"),
                    Codigo::DenyPermission,
                );
                e.ts_ms = base + k;
                total += d.observar(&e, &ctx).len();
            }
        }
        // Uma no primeiro grupo; nada no segundo (dentro da recarga); uma
        // no terceiro.
        assert_eq!(total, 2);
    }

    #[test]
    fn a_saida_depois_da_sondagem() {
        let mut d = Detector::novo();
        let mut e = ev(9, "agent:aa", Titular::Agente, "net.connect", Codigo::Allow);
        e.recurso = "tcp:10.0.2.100:7".to_string();
        let det = d.saida_depois_de_sondagem(&e, Confianca::Alta).unwrap();
        assert_eq!(
            det.alvo,
            Some(Alvo {
                destino: "tcp:10.0.2.100:7".to_string(),
                dono: alloc::format!("agent:{}", crate::util::hex(&[0xAA; 32])),
                papel: "operador".to_string(),
            })
        );
        assert_eq!(det.confianca, Confianca::Alta);
        // Uma vez por destino.
        assert!(d.saida_depois_de_sondagem(&e, Confianca::Alta).is_none());
        // Recusada, ou sem destino, não.
        e.codigo = Codigo::DenyResource;
        e.recurso = "tcp:10.0.2.101:7".to_string();
        assert!(d.saida_depois_de_sondagem(&e, Confianca::Alta).is_none());
    }
}
