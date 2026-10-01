//! A política de autorização do Duke.
//!
//! # A cadeia de decisão
//!
//! ```text
//! identidade → sessão → papel → permissão → operação
//! ```
//!
//! A identidade é a do canal seguro (a chave que provou o aperto), ou a da
//! serial, que é aberta. A sessão diz qual identidade está pedindo. O papel
//! vem do registro, e a política diz o que cada papel pode. Cada operação
//! declara a permissão que exige, e a decisão é uma conta só, em
//! [`Politica::decidir`] — que o kernel chama num ponto só, e que a
//! auditoria grava, permitida ou não.
//!
//! # O que há aqui
//!
//! - [`permissao`]: o vocabulário fechado, e quais permissões são sensíveis;
//! - [`arquivo`]: o formato da política, a validação, a decisão e as regras
//!   de mudança — ninguém muda o próprio papel, ninguém concede o que não
//!   tem;
//! - [`taxa`]: o balde de pedidos e a janela de apertos de mão;
//! - [`auditoria`]: os registros e a cadeia de elos;
//! - [`caminho`]: a forma normal dos caminhos, a mesma do VFS do kernel.

#![no_std]

extern crate alloc;

pub mod arquivo;
pub mod auditoria;
pub mod caminho;
pub mod codigo;
pub mod permissao;
pub mod taxa;

pub use arquivo::{Apertos, Papel, Politica, Recusa, Taxa};
pub use codigo::Codigo;
pub use permissao::Permissao;

/// Os papéis que as duas políticas embutidas têm iguais — a padrão e a de
/// emergência —, escritos uma vez só.
///
/// - `sistema` é a autoridade máxima do sistema: a serial, a pessoa no
///   console e os processos do sistema. Máxima e **enumerada**: cada
///   permissão escrita pelo nome, e o alcance de cada uma de caminho também
///   — `/` é a árvore inteira, menos o diretório reservado do kernel, que não
///   é recurso de papel nenhum. Não inclui outro papel: o que ele pode está
///   todo nesta linha. As administrativas não estão nela: são do
///   `administrador`, com a prova.
/// - `administrador` é o **teto** do que um administrador delega: as
///   permissões comuns dele não se exercem — uma chave de administrador não
///   abre sessão de agente —, e dizem só o que ele pode conceder. Escritas
///   uma a uma, sem incluir o operador: um papel incluído que muda muda o
///   do administrador, e o do administrador não muda em tempo de execução.
macro_rules! papeis_de_sistema {
    () => {
        "\
papel sistema agent.read system.read log.read ui.read ui.act process.run net.send fs.read fs.raw_read keyboard.read debug.trigger terminal.attach audit.read policy.read
recurso sistema fs.read /
recurso sistema process.run /
taxa sistema 400 800

papel administrador agent.read system.read log.read ui.read ui.act process.run net.send fs.read audit.read policy.read agent.register agent.revoke policy.assign policy.write
recurso administrador fs.read /dados /bin /programas
recurso administrador process.run /bin /programas
taxa administrador 10 20
"
    };
}

/// A política padrão da imagem de desenvolvimento.
///
/// Mora aqui, e não no `xtask`, para que o texto que vai para o disco seja
/// o mesmo que os testes deste pacote leem e conferem.
///
/// - `observador` observa o estado do sistema e a tela; não lê arquivos;
/// - `operador` observa e age: a tela, programas de `/bin` e
///   `/programas`, arquivos de `/dados`, `/bin` e `/programas`;
/// - `sistema` e `administrador`: ver `papeis_de_sistema`.
pub const PADRAO: &str = concat!(
    "\
# A politica do Duke: papeis, permissoes, recursos e taxas.
#
# Uma permissao sensivel (fs.*, keyboard.read, debug.trigger, terminal.attach,
# policy.*, agent.register, agent.revoke) nao atravessa a inclusao de outro
# papel: cada papel que a tem a escreve. Toda permissao de caminho tem o
# alcance escrito numa linha `recurso`. Nao ha curinga.

papel observador agent.read system.read log.read ui.read
taxa observador 20 40

papel operador @observador ui.act process.run net.send fs.read
recurso operador fs.read /dados /bin /programas
recurso operador process.run /bin /programas
taxa operador 50 100

",
    papeis_de_sistema!(),
    "
apertos 10 10000
serial sistema
local sistema
"
);

/// A política de emergência, embutida no kernel: a que vale quando
/// `/etc/duke/politica` falta ou não se lê.
///
/// O `sistema` é o mesmo da padrão — o mesmo texto —, e continua sendo o da
/// serial e o da autoridade local: sem política no disco, a autoridade
/// máxima não encolhe, e não vira curinga. O `administrador` também é o
/// mesmo, para quem tem a prova recuperar a política em memória com
/// `policy.write`. Os outros papéis não estão aqui: um agente de papel
/// `operador` ou `observador` é recusado; um de papel `sistema` continua o
/// que era — ninguém ganha nem perde papel na emergência.
pub const EMERGENCIA: &str = concat!(
    "\
# A politica de emergencia, embutida no kernel.

",
    papeis_de_sistema!(),
    "
apertos 10 10000
serial sistema
local sistema
"
);

#[cfg(test)]
mod testes {
    use super::*;
    use alloc::string::ToString;

    fn padrao() -> Politica {
        Politica::ler(PADRAO).expect("a politica padrao precisa valer")
    }

    /// Uma política mínima de teste: `corpo` mais as linhas obrigatórias.
    fn com(corpo: &str) -> Result<Politica, arquivo::Erro> {
        Politica::ler(&alloc::format!("{corpo}\nserial a\nlocal a\n"))
    }

    /// A matriz aprovada, linha a linha.
    #[test]
    fn a_matriz_aprovada() {
        let p = padrao();
        let d = |papel, perm, rec| p.decidir(Some(papel), perm, rec);
        use Permissao::*;
        // fs.read: o observador não; o operador nos prefixos dele.
        assert_eq!(
            d("observador", FsRead, Some("/dados/x")),
            Codigo::DenyPermission
        );
        assert_eq!(d("operador", FsRead, Some("/dados/x")), Codigo::Allow);
        assert_eq!(
            d("operador", FsRead, Some("/grande.txt")),
            Codigo::DenyResource
        );
        assert_eq!(d("operador", FsRead, Some("/dadosx")), Codigo::DenyResource);
        assert_eq!(d("operador", FsRead, None), Codigo::DenyResource);
        // O sistema alcança a árvore porque a linha `recurso` diz `/`.
        assert_eq!(d("sistema", FsRead, Some("/grande.txt")), Codigo::Allow);
        assert_eq!(d("sistema", ProcessRun, Some("/x/y")), Codigo::Allow);
        // As de sistema, só o sistema.
        for perm in [FsRawRead, DebugTrigger, KeyboardRead, TerminalAttach] {
            assert_eq!(d("sistema", perm, None), Codigo::Allow);
            for papel in ["observador", "operador", "administrador"] {
                assert_eq!(d(papel, perm, None), Codigo::DenyPermission, "{papel}");
            }
        }
        // As administrativas, só o administrador; o sistema não.
        for perm in [AgentRegister, AgentRevoke, PolicyAssign, PolicyWrite] {
            assert_eq!(d("administrador", perm, None), Codigo::Allow);
            assert_eq!(d("sistema", perm, None), Codigo::DenyPermission);
        }
        // Ninguém tem as de escrita: não há operação para elas.
        for perm in [FsWrite, FsRawWrite] {
            for papel in ["observador", "operador", "administrador", "sistema"] {
                assert_eq!(d(papel, perm, Some("/dados")), Codigo::DenyPermission);
            }
        }
        assert_eq!(p.decidir(None, AgentRead, None), Codigo::DenyRole);
        assert_eq!(
            p.decidir(Some("fantasma"), AgentRead, None),
            Codigo::DenyRole
        );
        assert_eq!(p.serial(), "sistema");
        assert_eq!(p.local(), "sistema");
    }

    /// O sistema é a autoridade máxima, e enumerada: tem cada permissão que
    /// não é administrativa nem de escrita — sem incluir papel nenhum, sem
    /// curinga —, e cada uma de caminho com o alcance escrito.
    #[test]
    fn o_sistema_e_maximo_e_enumerado() {
        let p = padrao();
        let sistema = p.papel("sistema").unwrap();
        assert!(sistema.inclui.is_empty(), "o sistema inclui outro papel");
        for perm in permissao::TODAS {
            let esperado = !perm.administrativa()
                && !matches!(perm, Permissao::FsWrite | Permissao::FsRawWrite);
            assert_eq!(sistema.tem(perm), esperado, "{}", perm.nome());
            assert_eq!(
                sistema.diretas.contains(&perm),
                esperado,
                "{} nao esta escrita",
                perm.nome()
            );
            if esperado && perm.recurso_e_caminho() {
                assert_eq!(sistema.recursos.get(&perm).unwrap(), &["/".to_string()]);
            }
        }
        // Nenhum outro papel da padrão alcança mais que ele.
        for papel in ["observador", "operador"] {
            assert!(p.cabe_em(papel, "sistema").is_ok(), "{papel}");
        }
    }

    /// Uma permissão de caminho sem o alcance escrito não é "tudo": a
    /// política é recusada — também quando a permissão veio por inclusão.
    #[test]
    fn caminho_sem_alcance_e_erro() {
        assert!(matches!(
            com("papel a fs.read").unwrap_err().tipo,
            arquivo::ErroTipo::RecursoFaltando(_, _)
        ));
        assert!(matches!(
            com("papel b process.run\nrecurso b process.run /bin\npapel a @b").unwrap_err().tipo,
            arquivo::ErroTipo::RecursoFaltando(papel, _) if papel == "a"
        ));
        assert!(com("papel a fs.read\nrecurso a fs.read /").is_ok());
    }

    /// A inclusão não carrega as sensíveis: sem escrever, não tem.
    #[test]
    fn sensivel_nao_atravessa_a_inclusao() {
        let p = com("papel a fs.read ui.read\nrecurso a fs.read /\npapel b @a\nserial b").unwrap();
        assert!(p.papel("b").unwrap().tem(Permissao::UiRead));
        assert!(!p.papel("b").unwrap().tem(Permissao::FsRead));
    }

    #[test]
    fn erros_com_a_linha() {
        let erro = |t: &str| com(t).unwrap_err();
        assert_eq!(erro("papel a *").tipo, arquivo::ErroTipo::Curinga);
        assert_eq!(erro("papel a *").linha, 1);
        assert!(matches!(
            erro("papel a fs.raed").tipo,
            arquivo::ErroTipo::PermissaoDesconhecida(_)
        ));
        assert!(matches!(
            erro("papel a @b\npapel b @a").tipo,
            arquivo::ErroTipo::Ciclo(_)
        ));
        assert!(matches!(
            Politica::ler("papel a ui.read\nlocal a\n")
                .unwrap_err()
                .tipo,
            arquivo::ErroTipo::SemSerial
        ));
        assert!(matches!(
            Politica::ler("papel a ui.read\nserial a\n")
                .unwrap_err()
                .tipo,
            arquivo::ErroTipo::SemLocal
        ));
        assert!(matches!(
            Politica::ler("papel a ui.read\nserial a\nlocal b\n")
                .unwrap_err()
                .tipo,
            arquivo::ErroTipo::PapelDesconhecido(_)
        ));
        assert!(matches!(
            erro("papel a ui.read\nrecurso a ui.read /x").tipo,
            arquivo::ErroTipo::RecursoNaoECaminho(_)
        ));
        assert!(matches!(
            erro("papel a ui.read\nrecurso a fs.read /x").tipo,
            arquivo::ErroTipo::RecursoSemPermissao(_)
        ));
        assert!(matches!(
            erro("papel a ui.read\npapel a ui.read").tipo,
            arquivo::ErroTipo::PapelRepetido(_)
        ));
        assert!(matches!(
            erro("papel a fs.read\nrecurso a fs.read ../x").tipo,
            arquivo::ErroTipo::CaminhoInvalido(_)
        ));
    }

    /// O administrador concede o que cabe nele: operador e observador sim,
    /// sistema não.
    #[test]
    fn concede_o_que_cabe() {
        let p = padrao();
        assert!(p.cabe_em("observador", "administrador").is_ok());
        assert!(p.cabe_em("operador", "administrador").is_ok());
        assert!(p.cabe_em("sistema", "administrador").is_err());
    }

    /// `policy.write`: as regras de não-autoprivilegiamento.
    #[test]
    fn policy_write_nao_autoprivilegia() {
        let p = padrao();
        let teto = "administrador";
        // O kernel protege os papéis dos administradores e os da serial e
        // da autoridade local.
        let protegidos = ["administrador", "sistema"];
        let mudar = |linha: &str| p.com_linha(linha, teto, &protegidos);

        // Tirar uma permissão do observador: vale.
        let nova = mudar("papel observador agent.read system.read").unwrap();
        assert!(!nova.papel("observador").unwrap().tem(Permissao::UiRead));
        // E o operador, que o inclui, também perdeu.
        assert!(!nova.papel("operador").unwrap().tem(Permissao::UiRead));

        // O próprio papel: não.
        assert!(matches!(
            mudar("papel administrador agent.read"),
            Err(Recusa::Proibida(_))
        ));
        assert!(matches!(
            mudar("taxa administrador 1000 1000"),
            Err(Recusa::Proibida(_))
        ));
        // O do sistema — a autoridade máxima — não encolhe por aqui.
        assert!(matches!(
            mudar("papel sistema agent.read"),
            Err(Recusa::Proibida(_))
        ));
        assert!(matches!(
            mudar("recurso sistema fs.read /dados"),
            Err(Recusa::Proibida(_))
        ));
        // Dar ao observador o que o administrador não tem: não.
        assert!(matches!(
            mudar("papel observador agent.read debug.trigger"),
            Err(Recusa::Proibida(_))
        ));
        // Dar ao operador o que o administrador tem: vale.
        let nova =
            mudar("papel operador @observador ui.act process.run net.send fs.read audit.read")
                .unwrap();
        assert!(nova.papel("operador").unwrap().tem(Permissao::AuditRead));
        // O que ele não tem: não.
        assert!(matches!(
            mudar("papel operador @observador ui.act process.run net.send fs.read keyboard.read"),
            Err(Recusa::Proibida(_))
        ));
        // Alargar o recurso do operador além do alcance do administrador:
        // não.
        assert!(matches!(
            mudar("recurso operador fs.read /"),
            Err(Recusa::Proibida(_))
        ));
        // Estreitar: vale.
        assert!(mudar("recurso operador fs.read /dados").is_ok());
        // Um papel novo com uma permissão de caminho sem alcance: inválido —
        // não há "sem limite".
        assert!(matches!(
            mudar("papel leitor fs.read"),
            Err(Recusa::Invalida(_))
        ));
        // Um papel incluído por um protegido também é protegido: um
        // administrador que inclua outro papel não deixa editá-lo.
        let acoplada = Politica::ler(
            "papel base ui.read\npapel adm @base policy.write\nserial base\nlocal base\n",
        )
        .unwrap();
        assert!(matches!(
            acoplada.com_linha("papel base agent.read", "adm", &["adm"]),
            Err(Recusa::Proibida(_))
        ));
        // Um papel novo que cabe: vale.
        let nova = mudar("papel leitor ui.read").unwrap();
        assert!(nova.papel("leitor").is_some());
        // A serial, o papel local e os apertos não mudam por policy.write.
        for linha in ["serial observador", "local observador", "apertos 1 1"] {
            assert!(matches!(mudar(linha), Err(Recusa::Proibida(_))), "{linha}");
        }
        // Uma linha inválida: inválida, e a política velha fica.
        assert!(matches!(
            mudar("papel observador *"),
            Err(Recusa::Invalida(_))
        ));
        assert_eq!(p, padrao());
    }

    /// Sem política no disco, o sistema não encolhe: o mesmo papel, com as
    /// mesmas permissões enumeradas, para a serial e a autoridade local. Os
    /// papéis dos agentes não existem.
    #[test]
    fn emergencia_mantem_o_sistema() {
        let e = Politica::emergencia();
        let p = padrao();
        assert_eq!(e.serial(), "sistema");
        assert_eq!(e.local(), "sistema");
        assert_eq!(e.papel("sistema"), p.papel("sistema"));
        assert_eq!(e.papel("administrador"), p.papel("administrador"));
        for papel in ["observador", "operador"] {
            assert!(e.papel(papel).is_none(), "{papel}");
            assert_eq!(
                e.decidir(Some(papel), Permissao::AgentRead, None),
                Codigo::DenyRole
            );
        }
        assert_eq!(
            e.decidir(Some("sistema"), Permissao::TerminalAttach, None),
            Codigo::Allow
        );
        let _ = "x".to_string();
    }
}
