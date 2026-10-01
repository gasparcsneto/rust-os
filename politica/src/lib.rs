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

/// A política padrão da imagem de desenvolvimento.
///
/// Mora aqui, e não no `xtask`, para que o texto que vai para o disco seja
/// o mesmo que os testes deste pacote leem e conferem.
///
/// - `observador` observa o estado do sistema e a tela; não lê arquivos;
/// - `operador` observa e age: a tela, programas de `/bin` e
///   `/programas`, arquivos de `/dados`, `/bin` e `/programas`;
/// - `administrador` é o **teto** do que um administrador delega: as
///   permissões comuns dele não se exercem — uma chave de administrador não
///   abre sessão de agente —, e dizem só o que ele pode conceder. Escritas
///   uma a uma, sem incluir o operador: um papel incluído que muda muda o
///   do administrador, e o do administrador não muda em tempo de execução —
///   com a inclusão, nenhum papel incluído poderia ser editado;
/// - `sistema` lista o que pode, uma a uma: as sensíveis de sistema
///   (`fs.raw_read`, `keyboard.read`, `debug.trigger`) só ele tem, e as
///   administrativas não tem.
pub const PADRAO: &str = "\
# A politica do Duke: papeis, permissoes, recursos e taxas.
#
# Uma permissao sensivel (fs.*, keyboard.read, debug.trigger, policy.*,
# agent.register, agent.revoke) nao atravessa a inclusao de outro papel:
# cada papel que a tem a escreve. Nao ha curinga.

papel observador agent.read system.read log.read ui.read
papel operador @observador ui.act process.run net.send fs.read
papel administrador agent.read system.read log.read ui.read ui.act process.run net.send fs.read audit.read policy.read agent.register agent.revoke policy.assign policy.write
papel sistema @operador fs.read fs.raw_read keyboard.read debug.trigger audit.read policy.read

recurso operador fs.read /dados /bin /programas
recurso operador process.run /bin /programas
recurso administrador fs.read /dados /bin /programas
recurso administrador process.run /bin /programas

taxa observador 20 40
taxa operador 50 100
taxa administrador 10 20
taxa sistema 400 800

apertos 10 10000
serial sistema
";

#[cfg(test)]
mod testes {
    use super::*;
    use alloc::string::ToString;

    fn padrao() -> Politica {
        Politica::ler(PADRAO).expect("a politica padrao precisa valer")
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
        assert_eq!(d("sistema", FsRead, Some("/grande.txt")), Codigo::Allow);
        // As de sistema, só o sistema.
        for perm in [FsRawRead, DebugTrigger, KeyboardRead] {
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
    }

    /// A inclusão não carrega as sensíveis: o sistema inclui o operador e
    /// escreve `fs.read` de novo; sem escrever, não teria.
    #[test]
    fn sensivel_nao_atravessa_a_inclusao() {
        let p = Politica::ler("papel a fs.read ui.read\npapel b @a\nserial b\n").unwrap();
        assert!(p.papel("b").unwrap().tem(Permissao::UiRead));
        assert!(!p.papel("b").unwrap().tem(Permissao::FsRead));
    }

    #[test]
    fn erros_com_a_linha() {
        let erro = |t: &str| Politica::ler(t).unwrap_err();
        assert_eq!(
            erro("papel a *\nserial a\n").tipo,
            arquivo::ErroTipo::Curinga
        );
        assert_eq!(erro("papel a *\nserial a\n").linha, 1);
        assert!(matches!(
            erro("papel a fs.raed\nserial a\n").tipo,
            arquivo::ErroTipo::PermissaoDesconhecida(_)
        ));
        assert!(matches!(
            erro("papel a @b\npapel b @a\nserial a\n").tipo,
            arquivo::ErroTipo::Ciclo(_)
        ));
        assert!(matches!(
            erro("papel a ui.read\n").tipo,
            arquivo::ErroTipo::SemSerial
        ));
        assert!(matches!(
            erro("papel a ui.read\nrecurso a ui.read /x\nserial a\n").tipo,
            arquivo::ErroTipo::RecursoNaoECaminho(_)
        ));
        assert!(matches!(
            erro("papel a ui.read\nrecurso a fs.read /x\nserial a\n").tipo,
            arquivo::ErroTipo::RecursoSemPermissao(_)
        ));
        assert!(matches!(
            erro("papel a ui.read\npapel a ui.read\nserial a\n").tipo,
            arquivo::ErroTipo::PapelRepetido(_)
        ));
        assert!(matches!(
            erro("papel a fs.read\nrecurso a fs.read ../x\nserial a\n").tipo,
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
        let protegidos = ["administrador"];
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
        // Um papel novo com fs.read sem limite: alcança mais do que o
        // administrador alcança.
        assert!(matches!(
            mudar("papel leitor fs.read"),
            Err(Recusa::Proibida(_))
        ));
        // Um papel incluído por um protegido também é protegido: um
        // administrador que inclua outro papel não deixa editá-lo.
        let acoplada =
            Politica::ler("papel base ui.read\npapel adm @base policy.write\nserial base\n")
                .unwrap();
        assert!(matches!(
            acoplada.com_linha("papel base agent.read", "adm", &["adm"]),
            Err(Recusa::Proibida(_))
        ));
        // Um papel novo que cabe: vale, depois de limitado.
        let nova = mudar("papel leitor ui.read").unwrap();
        assert!(nova.papel("leitor").is_some());
        // A serial e os apertos não mudam por policy.write.
        assert!(matches!(
            mudar("serial observador"),
            Err(Recusa::Proibida(_))
        ));
        assert!(matches!(mudar("apertos 1 1"), Err(Recusa::Proibida(_))));
        // Uma linha inválida: inválida, e a política velha fica.
        assert!(matches!(
            mudar("papel observador *"),
            Err(Recusa::Invalida(_))
        ));
        assert_eq!(p, padrao());
    }

    #[test]
    fn emergencia_so_le() {
        let p = Politica::emergencia();
        assert_eq!(p.serial(), "emergencia");
        assert_eq!(
            p.decidir(Some("emergencia"), Permissao::DebugTrigger, None),
            Codigo::DenyPermission
        );
        assert_eq!(
            p.decidir(Some("emergencia"), Permissao::AuditRead, None),
            Codigo::Allow
        );
        assert_eq!(
            p.decidir(Some("operador"), Permissao::AgentRead, None),
            Codigo::DenyRole
        );
        let _ = "x".to_string();
    }
}
