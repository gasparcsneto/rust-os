//! A explicação de uma recusa — para um agente, estruturada; para uma
//! pessoa, uma frase.
//!
//! **Não é uma segunda decisão.** O gate decidiu; aqui só se lê o que ele
//! decidiu — o código, a permissão, o recurso, o papel e o motivo que a
//! auditoria gravou — e se diz o que aquilo quer dizer para quem pediu: por
//! que, se adianta repetir, e o que fazer. Ver `docs/USABILIDADE.md`.
//!
//! # A razão não é o código
//!
//! O código é o que a auditoria grava, e não muda. A razão é a taxonomia
//! de quem precisa se recuperar: dois códigos podem ter a mesma razão, e o
//! mesmo código, razões diferentes — uma chave revogada e uma porta sem
//! aperto são ambas `DENY_NOT_AUTHENTICATED`, mas uma pede um
//! administrador, e a outra, só o aperto.
//!
//! # O que a frase não diz
//!
//! A frase diz o que quem pediu já sabe — o que ele pediu, sobre o quê, e o
//! papel dele — e o que fazer. Não diz a regra de ninguém, o alcance de
//! outro papel, nem o que há do outro lado do recurso.
//!
//! # O que a explicação lê do motivo
//!
//! O motivo é da auditoria, e pode dizer o que a resposta esconde de
//! propósito. A explicação o lê só para distinguir o que é de quem pediu:
//! a identidade dele (revogada, ou sem aperto), o manifesto do programa
//! dele, o arrendamento que a resposta já mostra, e o pedido mal formado
//! que ele mesmo escreveu. **Nunca** num `DENY_RESOURCE`: o kernel responde
//! o mesmo ao recurso que não existe, ao que é de outro e ao que está fora
//! do alcance — um destinatário revogado e um que nunca existiu, a
//! mensagem de outro e um número que ninguém tem —, e a explicação
//! também. Uma explicação que os distinguisse diria o que o código calou.

use alloc::format;
use alloc::string::String;

use crate::Codigo;

/// Por que o pedido não passou — a taxonomia da recuperação.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Razao {
    /// Ninguém provado: sem login, sem aperto, uma prova que não confere.
    NaoAutenticado,
    /// A identidade não vale mais: revogada, ou o journal recusado não
    /// sabe quais revogações perdeu.
    Revogacao,
    /// A credencial está suspensa.
    Credencial,
    /// Sem papel, o papel não tem a permissão, o manifesto do programa não
    /// a declara, ou uma regra da política além do papel recusou.
    Politica,
    /// O papel tem a permissão, mas não sobre este recurso.
    Alcance,
    /// Quem pediu está contido: o processo isolado, o agente suspenso.
    Contido,
    /// A versão mudou desde a leitura.
    Conflito,
    /// Outro titular tem o arrendamento.
    ArrendamentoOcupado,
    /// A ação pede o arrendamento, e quem pediu não o tem.
    ArrendamentoExigido,
    /// Passou da taxa do papel.
    Taxa,
    /// Passaria de uma cota.
    Limite,
    /// O pedido não se entende.
    PedidoInvalido,
    /// O pedido repete um que já passou.
    Repeticao,
    /// Permitido, e falhou ao executar: não é uma recusa.
    ErroTecnico,
}

impl Razao {
    /// O nome, como a explicação estruturada o escreve.
    pub const fn nome(self) -> &'static str {
        match self {
            Razao::NaoAutenticado => "DENY_NOT_AUTHENTICATED",
            Razao::Revogacao => "DENY_REVOCATION",
            Razao::Credencial => "DENY_CREDENTIAL",
            Razao::Politica => "DENY_POLICY",
            Razao::Alcance => "DENY_SCOPE",
            Razao::Contido => "DENY_CONTAINED",
            Razao::Conflito => "CONFLICT",
            Razao::ArrendamentoOcupado => "LEASE_BUSY",
            Razao::ArrendamentoExigido => "LEASE_REQUIRED",
            Razao::Taxa => "RATE_LIMIT",
            Razao::Limite => "RESOURCE_LIMIT",
            Razao::PedidoInvalido => "INVALID_REQUEST",
            Razao::Repeticao => "REPLAY",
            Razao::ErroTecnico => "TECHNICAL_ERROR",
        }
    }
}

/// Se adianta repetir — e o que precisa mudar antes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Repetir {
    /// O mesmo pedido pode passar depois: esperar, ler de novo, tomar o
    /// arrendamento.
    Sim,
    /// O mesmo pedido nunca passa: é preciso mudar o pedido.
    Nao,
    /// Só passa depois que alguém com autoridade mudar alguma coisa — o
    /// papel, a contenção, a credencial.
    PedeAutorizacao,
    /// Só passa depois que o alcance incluir o recurso.
    PedeAlcance,
    /// Só passa depois que quem pede fizer algo — entrar.
    PedeAcaoDoUsuario,
}

impl Repetir {
    /// O nome, como a explicação estruturada o escreve.
    pub const fn nome(self) -> &'static str {
        match self {
            Repetir::Sim => "retryable",
            Repetir::Nao => "non_retryable",
            Repetir::PedeAutorizacao => "requires_authorization",
            Repetir::PedeAlcance => "requires_scope",
            Repetir::PedeAcaoDoUsuario => "requires_user_action",
        }
    }
}

/// O que fazer em seguida.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProximaAcao {
    Entrar,
    PedirAutorizacao,
    PedirAlcance,
    LerDeNovoERepetir,
    EsperarERepetir,
    TomarERepetir,
    LiberarRecursos,
    CorrigirOPedido,
    FalarComUmAdministrador,
    Repetir,
}

impl ProximaAcao {
    /// O nome, como a explicação estruturada o escreve.
    pub const fn nome(self) -> &'static str {
        match self {
            ProximaAcao::Entrar => "LOGIN",
            ProximaAcao::PedirAutorizacao => "REQUEST_AUTHORIZATION",
            ProximaAcao::PedirAlcance => "REQUEST_SCOPE",
            ProximaAcao::LerDeNovoERepetir => "REFRESH_AND_RETRY",
            ProximaAcao::EsperarERepetir => "WAIT_AND_RETRY",
            ProximaAcao::TomarERepetir => "CLAIM_AND_RETRY",
            ProximaAcao::LiberarRecursos => "FREE_RESOURCES",
            ProximaAcao::CorrigirOPedido => "FIX_REQUEST",
            ProximaAcao::FalarComUmAdministrador => "CONTACT_ADMIN",
            ProximaAcao::Repetir => "RETRY",
        }
    }
}

/// O que o gate decidiu, como quem explica o recebe.
#[derive(Clone, Copy, Debug)]
pub struct Decidido<'a> {
    pub codigo: Codigo,
    /// O nome da permissão que o método exige, se exige uma.
    pub permissao: Option<&'a str>,
    /// O método pedido.
    pub metodo: &'a str,
    /// O recurso que o gate decidiu.
    pub recurso: &'a str,
    /// O papel com que o gate decidiu, se havia um.
    pub papel: Option<&'a str>,
    /// O motivo que a auditoria gravou.
    pub motivo: &'a str,
}

/// A explicação de uma recusa.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Explicacao {
    pub razao: Razao,
    pub repetir: Repetir,
    pub proxima: ProximaAcao,
}

impl Explicacao {
    /// O resultado em uma palavra: `DENY`, `CONFLICT` ou `ERROR`. Um
    /// conflito e um erro técnico não são recusas da política.
    pub const fn resultado(&self) -> &'static str {
        match self.razao {
            Razao::Conflito | Razao::ArrendamentoOcupado => "CONFLICT",
            Razao::ErroTecnico => "ERROR",
            _ => "DENY",
        }
    }

    /// Quem pediu consegue sair disto — esperando, corrigindo, ou pedindo a
    /// quem pode. Só o que nunca passa não é recuperável.
    pub const fn recuperavel(&self) -> bool {
        !matches!(self.repetir, Repetir::Nao)
    }
}

/// A explicação do que o gate decidiu. `None` para o que passou.
pub fn explicar(d: &Decidido) -> Option<Explicacao> {
    let (razao, repetir, proxima) = match d.codigo {
        Codigo::Allow => return None,
        Codigo::DenyNotAuthenticated => {
            if d.motivo.contains("revogad") || d.motivo.contains("journal") {
                (
                    Razao::Revogacao,
                    Repetir::Nao,
                    ProximaAcao::FalarComUmAdministrador,
                )
            } else {
                (
                    Razao::NaoAutenticado,
                    Repetir::PedeAcaoDoUsuario,
                    ProximaAcao::Entrar,
                )
            }
        }
        Codigo::DenyRole | Codigo::DenyPolicy => (
            Razao::Politica,
            Repetir::PedeAutorizacao,
            ProximaAcao::PedirAutorizacao,
        ),
        Codigo::DenyPermission if d.motivo.contains("manifesto") => {
            // O papel tem; o programa não declarou. Quem corrige é o
            // programa — nenhum papel novo resolve.
            (Razao::Politica, Repetir::Nao, ProximaAcao::CorrigirOPedido)
        }
        Codigo::DenyPermission => (
            Razao::Politica,
            Repetir::PedeAutorizacao,
            ProximaAcao::PedirAutorizacao,
        ),
        // O recurso que não existe, o de outro e o fora do alcance: uma
        // explicação só, como uma resposta só (ver o começo do módulo).
        Codigo::DenyResource => (
            Razao::Alcance,
            Repetir::PedeAlcance,
            ProximaAcao::PedirAlcance,
        ),
        Codigo::DenyContained => (
            Razao::Contido,
            Repetir::PedeAutorizacao,
            ProximaAcao::FalarComUmAdministrador,
        ),
        Codigo::DenyCredential => (
            Razao::Credencial,
            Repetir::PedeAutorizacao,
            ProximaAcao::FalarComUmAdministrador,
        ),
        Codigo::Conflict if d.motivo.contains("arrendamento") => (
            Razao::ArrendamentoOcupado,
            Repetir::Sim,
            ProximaAcao::EsperarERepetir,
        ),
        Codigo::Conflict => (
            Razao::Conflito,
            Repetir::Sim,
            ProximaAcao::LerDeNovoERepetir,
        ),
        Codigo::DenyLease => (
            Razao::ArrendamentoExigido,
            Repetir::Sim,
            ProximaAcao::TomarERepetir,
        ),
        Codigo::RateLimit => (Razao::Taxa, Repetir::Sim, ProximaAcao::EsperarERepetir),
        Codigo::DenyQuota => (Razao::Limite, Repetir::Nao, ProximaAcao::LiberarRecursos),
        Codigo::InvalidArgument => (
            Razao::PedidoInvalido,
            Repetir::Nao,
            ProximaAcao::CorrigirOPedido,
        ),
        Codigo::DenyReplay => (Razao::Repeticao, Repetir::Nao, ProximaAcao::CorrigirOPedido),
        Codigo::Error => (Razao::ErroTecnico, Repetir::Sim, ProximaAcao::Repetir),
    };
    Some(Explicacao {
        razao,
        repetir,
        proxima,
    })
}

/// A frase para uma pessoa: o que aconteceu, e o que fazer. Sem acento,
/// como as mensagens do kernel.
pub fn frase(d: &Decidido, e: &Explicacao) -> String {
    // O que a pessoa pediu é o método que ela digitou; o que o papel não
    // tem é a permissão que ele exige — `fs.list` pede `fs.read`.
    let metodo = d.metodo;
    let pedido = d.permissao.unwrap_or(d.metodo);
    let papel = d.papel.unwrap_or("nenhum");
    match e.razao {
        Razao::NaoAutenticado => format!(
            "Ninguem identificado pediu {metodo}: entre com o login (ou, num agente, complete o aperto) e repita."
        ),
        Razao::Revogacao => {
            "Esta identidade nao vale agora: foi revogada, ou nao se sabe se foi. Fale com um administrador.".into()
        }
        Razao::Credencial => {
            "Sua credencial esta suspensa. Um administrador pode retoma-la.".into()
        }
        Razao::Politica if e.proxima == ProximaAcao::CorrigirOPedido => format!(
            "O programa nao declara {pedido} no manifesto dele: ele nao pode pedir isso, qualquer que seja o seu papel."
        ),
        Razao::Politica if d.papel.is_none() => {
            "Esta identidade nao tem papel na politica. Um administrador pode atribuir um.".into()
        }
        Razao::Politica => format!(
            "Seu papel ({papel}) nao permite {pedido}. Voce pode executar esta operacao solicitando autorizacao administrativa."
        ),
        Razao::Alcance => format!(
            "{metodo} sobre {} nao passou: o recurso nao existe para voce, ou esta fora do alcance do seu papel ({papel}). Confira o pedido; se ele estiver certo, um administrador pode incluir esse recurso no seu papel.",
            alvo(d.recurso)
        ),
        Razao::Contido => {
            "Esta atividade esta contida pela seguranca: o processo isolado, ou o agente suspenso. Um administrador pode libera-la.".into()
        }
        Razao::Conflito => {
            "O recurso foi alterado desde a ultima leitura. Atualize o estado e tente novamente.".into()
        }
        Razao::ArrendamentoOcupado => {
            "O recurso esta ocupado: outro titular o tem. Tente de novo quando ele soltar.".into()
        }
        Razao::ArrendamentoExigido => {
            "Esta acao pede o arrendamento do recurso: tome-o e repita.".into()
        }
        Razao::Taxa => "Pedidos demais em pouco tempo. Espere um pouco e repita.".into(),
        Razao::Limite => {
            "A cota de armazenamento se esgotaria. Libere espaco e repita.".into()
        }
        Razao::PedidoInvalido => format!("O pedido nao se entende: {}.", d.motivo),
        Razao::Repeticao => "Este pedido repete um que ja foi usado.".into(),
        Razao::ErroTecnico => {
            "Nao conseguimos fazer isso agora: a operacao falhou ao executar. Tente de novo.".into()
        }
    }
}

/// O recurso, como a frase o diz: `este recurso` quando não há um.
fn alvo(recurso: &str) -> &str {
    if recurso.is_empty() {
        "este recurso"
    } else {
        recurso
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    /// Os motivos de um `DENY_RESOURCE`, como o kernel os grava: o que não
    /// existe, o que é de outro e o que está fora do alcance.
    const MOTIVOS_DE_RECURSO: [&str; 8] = [
        "",
        "fora do alcance de net.connect",
        "conexao inexistente, ou de outro titular",
        "destinatario inexistente",
        "destinatario revogado",
        "processo inexistente",
        "nao ha mensagem com este id para quem pede",
        "o papel do alvo esta fora do alcance do papel",
    ];

    fn d(codigo: Codigo, motivo: &'static str) -> Decidido<'static> {
        Decidido {
            codigo,
            permissao: Some("net.connect"),
            metodo: "net.connect",
            recurso: "tcp:10.0.2.99:7",
            papel: Some("operador"),
            motivo,
        }
    }

    /// Todo código que não é `ALLOW` tem uma explicação; o `ALLOW`, não.
    #[test]
    fn toda_recusa_se_explica() {
        for c in Codigo::TODOS {
            let e = explicar(&d(c, ""));
            assert_eq!(e.is_none(), c == Codigo::Allow, "{}", c.nome());
            if let Some(e) = e {
                assert!(!frase(&d(c, ""), &e).is_empty(), "{}", c.nome());
            }
        }
    }

    /// A tabela de `docs/USABILIDADE.md`.
    #[test]
    fn a_taxonomia() {
        let caso = |c, motivo| {
            let e = explicar(&d(c, motivo)).unwrap();
            (e.razao.nome(), e.repetir.nome(), e.proxima.nome())
        };
        assert_eq!(
            caso(Codigo::DenyResource, ""),
            ("DENY_SCOPE", "requires_scope", "REQUEST_SCOPE")
        );
        // O alvo que não existe, o de outro e o fora do alcance — como o
        // kernel escreve cada um na auditoria — explicam-se igual.
        for motivo in MOTIVOS_DE_RECURSO {
            assert_eq!(
                caso(Codigo::DenyResource, motivo),
                ("DENY_SCOPE", "requires_scope", "REQUEST_SCOPE"),
                "{motivo}"
            );
        }
        assert_eq!(
            caso(Codigo::DenyPermission, ""),
            (
                "DENY_POLICY",
                "requires_authorization",
                "REQUEST_AUTHORIZATION"
            )
        );
        assert_eq!(
            caso(Codigo::DenyPermission, "o manifesto nao declara fs.read"),
            ("DENY_POLICY", "non_retryable", "FIX_REQUEST")
        );
        assert_eq!(
            caso(Codigo::DenyNotAuthenticated, "sessao sem aperto"),
            ("DENY_NOT_AUTHENTICATED", "requires_user_action", "LOGIN")
        );
        assert_eq!(
            caso(Codigo::DenyNotAuthenticated, "chave revogada"),
            ("DENY_REVOCATION", "non_retryable", "CONTACT_ADMIN")
        );
        assert_eq!(
            caso(Codigo::Conflict, "versao 10, e o recurso esta na 11"),
            ("CONFLICT", "retryable", "REFRESH_AND_RETRY")
        );
        assert_eq!(
            caso(Codigo::Conflict, "outro titular tem o arrendamento"),
            ("LEASE_BUSY", "retryable", "WAIT_AND_RETRY")
        );
        assert_eq!(
            caso(Codigo::DenyContained, ""),
            ("DENY_CONTAINED", "requires_authorization", "CONTACT_ADMIN")
        );
        assert_eq!(
            caso(Codigo::DenyCredential, ""),
            ("DENY_CREDENTIAL", "requires_authorization", "CONTACT_ADMIN")
        );
        assert_eq!(
            caso(Codigo::RateLimit, ""),
            ("RATE_LIMIT", "retryable", "WAIT_AND_RETRY")
        );
        assert_eq!(
            caso(Codigo::Error, ""),
            ("TECHNICAL_ERROR", "retryable", "RETRY")
        );
    }

    /// Recusa não é erro técnico, e conflito não é recusa (seções 14 e 33).
    #[test]
    fn recusa_conflito_e_erro_sao_coisas_diferentes() {
        let r = |c| explicar(&d(c, "")).unwrap().resultado();
        assert_eq!(r(Codigo::DenyResource), "DENY");
        assert_eq!(r(Codigo::Conflict), "CONFLICT");
        assert_eq!(r(Codigo::Error), "ERROR");
        let conflito = explicar(&d(Codigo::Conflict, "")).unwrap();
        assert!(
            frase(&d(Codigo::Conflict, ""), &conflito).contains("alterado desde a ultima leitura")
        );
        let erro = explicar(&d(Codigo::Error, "")).unwrap();
        let f = frase(&d(Codigo::Error, ""), &erro);
        assert!(f.contains("Nao conseguimos") && !f.contains("nao permite"));
    }

    /// A frase diz o pedido, o recurso e o papel de quem pediu — e o que
    /// fazer —, e nada além.
    #[test]
    fn a_frase_para_pessoas() {
        let alcance = d(Codigo::DenyResource, "fora do alcance de net.connect");
        let f = frase(&alcance, &explicar(&alcance).unwrap());
        assert!(
            f.contains("operador") && f.contains("net.connect") && f.contains("tcp:10.0.2.99:7")
        );
        assert!(f.contains("administrador pode incluir"));
        assert!(
            !f.contains("alcance de net.connect"),
            "o motivo interno nao vaza: {f}"
        );
        let politica = d(Codigo::DenyPermission, "");
        let f = frase(&politica, &explicar(&politica).unwrap());
        assert!(f.contains("solicitando autorizacao administrativa"), "{f}");
        // Quem não se identificou ouve o que digitou — o método —, e quem
        // não tem a permissão ouve a permissão que falta.
        let digitado = Decidido {
            metodo: "fs.list",
            permissao: Some("fs.read"),
            ..d(Codigo::DenyNotAuthenticated, "sessao sem aperto")
        };
        let f = frase(&digitado, &explicar(&digitado).unwrap());
        assert!(f.contains("pediu fs.list") && !f.contains("fs.read"), "{f}");
        let sem_permissao = Decidido {
            codigo: Codigo::DenyPermission,
            ..digitado
        };
        let f = frase(&sem_permissao, &explicar(&sem_permissao).unwrap());
        assert!(f.contains("nao permite fs.read"), "{f}");
    }

    /// O que a resposta esconde, a explicação não diz: um `DENY_RESOURCE`
    /// se explica igual, palavra por palavra, qualquer que seja o motivo
    /// gravado — o destinatário revogado e o que nunca existiu, a mensagem
    /// de outro e a que não há.
    #[test]
    fn o_recurso_que_nao_ha_e_o_fora_do_alcance_se_explicam_igual() {
        let um = |motivo| {
            let d = d(Codigo::DenyResource, motivo);
            let e = explicar(&d).unwrap();
            (e, frase(&d, &e))
        };
        let primeiro = um(MOTIVOS_DE_RECURSO[0]);
        for motivo in MOTIVOS_DE_RECURSO {
            assert_eq!(um(motivo), primeiro, "{motivo}");
        }
    }

    /// A frase não carrega o motivo da auditoria — salvo a do pedido mal
    /// formado, que diz o que quem pediu escreveu errado.
    #[test]
    fn a_frase_nao_carrega_o_motivo() {
        for c in Codigo::TODOS {
            let d = d(c, "segredo da auditoria");
            let Some(e) = explicar(&d) else { continue };
            let f = frase(&d, &e);
            assert_eq!(
                f.contains("segredo da auditoria"),
                c == Codigo::InvalidArgument,
                "{}: {f}",
                c.nome()
            );
        }
        let revogada = d(Codigo::DenyNotAuthenticated, "chave revogada");
        let f = frase(&revogada, &explicar(&revogada).unwrap());
        assert!(
            f.contains("revogada") && !f.contains("chave revogada"),
            "{f}"
        );
    }

    /// Só o que nunca passa não é recuperável: um agente sabe quando parar.
    #[test]
    fn recuperavel_ou_nao() {
        let r = |c, m| explicar(&d(c, m)).unwrap().recuperavel();
        assert!(r(Codigo::RateLimit, "") && r(Codigo::DenyResource, ""));
        assert!(r(Codigo::DenyContained, "") && r(Codigo::Conflict, ""));
        assert!(!r(Codigo::InvalidArgument, "") && !r(Codigo::DenyReplay, ""));
        assert!(!r(Codigo::DenyNotAuthenticated, "chave revogada"));
    }
}
