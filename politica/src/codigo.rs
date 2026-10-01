//! O desfecho de uma decisão, como a auditoria o grava.

/// Por que uma operação foi permitida ou não.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Codigo {
    /// Permitida.
    Allow = 0,
    /// Quem pediu não está autenticado: porta sem aperto, chave fora do
    /// registro, prova administrativa que não confere.
    DenyNotAuthenticated = 1,
    /// Autenticado, mas sem papel — ou com um papel que a política não tem.
    DenyRole = 2,
    /// O papel não tem a permissão.
    DenyPermission = 3,
    /// O papel tem a permissão, mas não sobre este recurso.
    DenyResource = 4,
    /// A política recusou: sem política carregada, uma operação sem
    /// permissão declarada, ou uma mudança que daria a alguém o que ele não
    /// tinha.
    DenyPolicy = 5,
    /// Mais pedidos do que o papel permite por segundo.
    RateLimit = 6,
    /// O pedido não se entende: método desconhecido, parâmetros inválidos.
    InvalidArgument = 7,
    /// Permitida, e falhou ao executar.
    Error = 8,
}

impl Codigo {
    /// O código, como a auditoria e o relatório o escrevem.
    pub const fn nome(self) -> &'static str {
        match self {
            Codigo::Allow => "ALLOW",
            Codigo::DenyNotAuthenticated => "DENY_NOT_AUTHENTICATED",
            Codigo::DenyRole => "DENY_ROLE",
            Codigo::DenyPermission => "DENY_PERMISSION",
            Codigo::DenyResource => "DENY_RESOURCE",
            Codigo::DenyPolicy => "DENY_POLICY",
            Codigo::RateLimit => "RATE_LIMIT",
            Codigo::InvalidArgument => "INVALID_ARGUMENT",
            Codigo::Error => "ERROR",
        }
    }

    /// Todos, na ordem do número.
    pub const TODOS: [Codigo; 9] = [
        Codigo::Allow,
        Codigo::DenyNotAuthenticated,
        Codigo::DenyRole,
        Codigo::DenyPermission,
        Codigo::DenyResource,
        Codigo::DenyPolicy,
        Codigo::RateLimit,
        Codigo::InvalidArgument,
        Codigo::Error,
    ];

    /// O código de um nome, como [`Codigo::nome`] o escreve: o caminho de
    /// volta de quem lê a auditoria de fora e refaz os elos.
    pub fn de_nome(nome: &str) -> Option<Codigo> {
        Codigo::TODOS.into_iter().find(|c| c.nome() == nome)
    }

    /// O resultado em uma palavra: `allow`, `deny` ou `error`.
    pub const fn resultado(self) -> &'static str {
        match self {
            Codigo::Allow => "allow",
            Codigo::Error => "error",
            _ => "deny",
        }
    }

    /// Se a operação pode seguir.
    pub const fn permite(self) -> bool {
        matches!(self, Codigo::Allow)
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    /// O nome vai e volta, e o número de cada um é a posição dele: é o
    /// número que entra no elo.
    #[test]
    fn o_nome_vai_e_volta() {
        for (i, c) in Codigo::TODOS.into_iter().enumerate() {
            assert_eq!(c as usize, i);
            assert_eq!(Codigo::de_nome(c.nome()), Some(c));
        }
        assert_eq!(Codigo::de_nome("allow"), None);
    }
}
