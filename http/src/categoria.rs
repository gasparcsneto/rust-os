//! De que família é o código de uma falha que chegou a quem fez o pedido.
//!
//! Uma troca HTTP de um programa do Duke passa por várias camadas — o DNS,
//! o gate, o firewall, o TCP, o TLS, o HTTP —, e cada uma falha com o seu
//! código, que sobe como veio. Quem se recupera precisa saber **de onde**
//! ele veio antes de saber o que fazer: a recusa do gate não se resolve
//! tentando de novo, o prazo talvez; o firewall não é a política; uma
//! resposta torta não é a rede. [`categoria`] diz a família de um código,
//! sem misturar nenhuma com outra.
//!
//! Isto não decide nada. O HTTP não autoriza, não recusa e não interpreta a
//! recusa de ninguém: o código é de quem o deu — o gate, o firewall, a
//! pilha, o TLS, o servidor —, e a família só o nomeia.

/// A família de uma falha.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Categoria {
    /// O gate recusou: a autoridade de quem pediu não alcança o pedido —
    /// `DENY_*`, ou a taxa do papel (`RATE_LIMIT`).
    Negado,
    /// O gate recusou porque quem pediu está contido (`DENY_CONTAINED`): o
    /// processo isolado, o agente ou a credencial suspensos.
    Contido,
    /// O gate deixou, e o firewall barrou o fluxo (`FIREWALL_BLOCKED`).
    Firewall,
    /// O nome não virou endereço: o DNS não respondeu, ou o nome não
    /// existe.
    Dns,
    /// A rede não levou: sem rede, sem vaga, a conexão recusada ou
    /// derrubada pelo outro lado.
    Transporte,
    /// O outro lado não respondeu no prazo.
    Prazo,
    /// O TLS não fechou, ou não conferiu: o certificado, o aperto, um
    /// registro adulterado.
    Tls,
    /// A conversa acabou antes da hora: o servidor fechou no meio da
    /// resposta, ou a conexão não leva mais pedidos.
    Fechada,
    /// O que chegou não é HTTP/1.1.
    Protocolo,
    /// A resposta passou de um limite de quem pediu.
    Limite,
    /// O pedido não se escreve: a URL, um cabeçalho, um parâmetro.
    Pedido,
    /// Uma falha daqui: sem aleatório, sem relógio, uma falha técnica.
    Local,
}

impl Categoria {
    pub const fn nome(self) -> &'static str {
        match self {
            Categoria::Negado => "denied",
            Categoria::Contido => "contained",
            Categoria::Firewall => "firewall",
            Categoria::Dns => "dns",
            Categoria::Transporte => "transport",
            Categoria::Prazo => "timeout",
            Categoria::Tls => "tls",
            Categoria::Fechada => "closed",
            Categoria::Protocolo => "protocol",
            Categoria::Limite => "limit",
            Categoria::Pedido => "request",
            Categoria::Local => "local",
        }
    }
}

/// A família do código `codigo`. Um código que nenhuma camada dá é
/// [`Categoria::Local`]: uma falha técnica, e não uma recusa — nada que
/// não se reconhece vira autorização, nem negação de alguém.
pub fn categoria(codigo: &str) -> Categoria {
    match codigo {
        "DENY_CONTAINED" => Categoria::Contido,
        "RATE_LIMIT" => Categoria::Negado,
        c if c.starts_with("DENY_") => Categoria::Negado,
        "FIREWALL_BLOCKED" => Categoria::Firewall,
        "DNS_UNAVAILABLE" | "DNS_NAME_NOT_FOUND" => Categoria::Dns,
        "NETWORK_UNAVAILABLE" | "RESOURCE_LIMIT" | "CONNECTION_REFUSED" | "CONNECTION_RESET" => {
            Categoria::Transporte
        }
        "NETWORK_TIMEOUT" => Categoria::Prazo,
        // O TLS fechado sem `close_notify` é a conversa que acabou antes da
        // hora — o que chegou pode estar cortado —, como o HTTP que fecha
        // no meio da resposta.
        "TLS_INTERRUPTED" | "HTTP_CLOSED" | "HTTP_CONNECTION_SPENT" => Categoria::Fechada,
        c if c.starts_with("TLS_") => Categoria::Tls,
        "HTTP_MALFORMED" => Categoria::Protocolo,
        "HTTP_TOO_LARGE" => Categoria::Limite,
        "INVALID_REQUEST" | "INVALID_ARGUMENT" => Categoria::Pedido,
        _ => Categoria::Local,
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn cada_codigo_na_sua_familia() {
        for (codigo, esperada) in [
            ("DENY_RESOURCE", Categoria::Negado),
            ("DENY_ROLE", Categoria::Negado),
            ("DENY_PERMISSION", Categoria::Negado),
            ("DENY_NOT_AUTHENTICATED", Categoria::Negado),
            ("DENY_POLICY", Categoria::Negado),
            ("DENY_CREDENTIAL", Categoria::Negado),
            ("RATE_LIMIT", Categoria::Negado),
            ("DENY_CONTAINED", Categoria::Contido),
            ("FIREWALL_BLOCKED", Categoria::Firewall),
            ("DNS_UNAVAILABLE", Categoria::Dns),
            ("DNS_NAME_NOT_FOUND", Categoria::Dns),
            ("NETWORK_UNAVAILABLE", Categoria::Transporte),
            ("RESOURCE_LIMIT", Categoria::Transporte),
            ("CONNECTION_REFUSED", Categoria::Transporte),
            ("CONNECTION_RESET", Categoria::Transporte),
            ("NETWORK_TIMEOUT", Categoria::Prazo),
            ("TLS_UNTRUSTED", Categoria::Tls),
            ("TLS_NAME_MISMATCH", Categoria::Tls),
            ("TLS_EXPIRED", Categoria::Tls),
            ("TLS_HANDSHAKE_FAILED", Categoria::Tls),
            ("TLS_TAMPERED", Categoria::Tls),
            ("TLS_ANCHORS_INVALID", Categoria::Tls),
            ("TLS_INTERRUPTED", Categoria::Fechada),
            ("HTTP_CLOSED", Categoria::Fechada),
            ("HTTP_CONNECTION_SPENT", Categoria::Fechada),
            ("HTTP_MALFORMED", Categoria::Protocolo),
            ("HTTP_TOO_LARGE", Categoria::Limite),
            ("INVALID_REQUEST", Categoria::Pedido),
            ("INVALID_ARGUMENT", Categoria::Pedido),
            ("ENTROPY_UNAVAILABLE", Categoria::Local),
            ("CLOCK_UNAVAILABLE", Categoria::Local),
            ("TECHNICAL_ERROR", Categoria::Local),
        ] {
            assert_eq!(categoria(codigo), esperada, "{codigo}");
        }
    }

    #[test]
    fn o_desconhecido_nao_e_recusa_nem_permissao() {
        // Nem `ALLOW` — que não é falha de ninguém —, nem um texto
        // qualquer, nem um prefixo pela metade vira recusa do gate.
        for codigo in [
            "ALLOW",
            "",
            "DENY",
            "deny_resource",
            "XDENY_ROLE",
            "FIREWALL",
        ] {
            assert_eq!(categoria(codigo), Categoria::Local, "{codigo:?}");
        }
    }

    #[test]
    fn as_familias_nao_se_confundem() {
        let todas = [
            Categoria::Negado,
            Categoria::Contido,
            Categoria::Firewall,
            Categoria::Dns,
            Categoria::Transporte,
            Categoria::Prazo,
            Categoria::Tls,
            Categoria::Fechada,
            Categoria::Protocolo,
            Categoria::Limite,
            Categoria::Pedido,
            Categoria::Local,
        ];
        for (i, a) in todas.iter().enumerate() {
            for b in &todas[i + 1..] {
                assert_ne!(a.nome(), b.nome());
            }
        }
    }
}
