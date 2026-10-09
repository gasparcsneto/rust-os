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
//! - [`arrendamento`]: a versão e o arrendamento de cada recurso
//!   compartilhado — quem está mexendo nele agora;
//! - [`caminho`]: a forma normal dos caminhos, a mesma do VFS do kernel.
//! - [`endereco`]: a forma normal dos destinos de rede, a mesma que o
//!   kernel disca.

#![no_std]

extern crate alloc;

pub mod arquivo;
pub mod arrendamento;
pub mod auditoria;
pub mod caminho;
pub mod codigo;
pub mod endereco;
pub mod manifesto;
pub mod mensagens;
pub mod permissao;
pub mod sigiloso;
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
///   `administrador`, com a prova. A escrita (`fs.write`) alcança só o
///   armazém, `/armazem` — ver `docs/ARMAZENAMENTO.md` —: é a única árvore
///   gravável, e a linha a concede por escrito, como qualquer outra.
/// - `administrador` é o **teto** do que um administrador delega: as
///   permissões comuns dele não se exercem — uma chave de administrador não
///   abre sessão de agente —, e dizem só o que ele pode conceder. Escritas
///   uma a uma, sem incluir o operador: um papel incluído que muda muda o
///   do administrador, e o do administrador não muda em tempo de execução.
///   O `fs.write` dele é o do operador, `/armazem/compartilhado`: o teto
///   tem de conter o que o operador recebe, para o operador ser delegável.
/// - `net.connect`, nos dois, alcança os três destinos da bancada, os três
///   servidos pelo próprio emulador, sem servidor no hospedeiro: o eco TCP,
///   em `10.0.2.100:7` (um `guestfwd`), o TFTP do emulador, em
///   `10.0.2.2:69` (UDP), e o DNS do emulador, em `10.0.2.3:53` (UDP).
///   Enumerados, como todo destino: a imagem de desenvolvimento não disca
///   nada que não esteja escrito, nem o sistema.
/// - `quorum admin.revoke 2 3`: revogar a credencial de um administrador
///   exige a prova de duas outras, de um grupo de três — o da imagem.
/// - `seguranca` é o papel do tecido de segurança — o serviço `nsf`, pela
///   linha `servico` (ver `docs/SEGURANCA.md`): lê a auditoria, observa o
///   DNS da bancada e barra os destinos da bancada. Nada além: não conecta,
///   não lança, não lê arquivo, não muda a política, e não é o `sistema`.
///   Está nas duas políticas: sem política no disco, o tecido continua
///   vendo — e continua só com isto. O `sistema` e o `administrador` têm
///   `security.read`, `net.observe` e `net.block` escritas nas linhas
///   deles, com o alcance enumerado: o `sistema` porque é o máximo
///   enumerado, e o `administrador` para que as três do papel `seguranca`
///   caibam no teto de quem as delega.
macro_rules! papeis_de_sistema {
    () => {
        "\
papel sistema agent.read system.read log.read ui.read ui.act process.run net.send net.connect fs.read fs.write fs.raw_read keyboard.read debug.trigger terminal.attach audit.read policy.read message.send message.read security.read net.observe net.block
recurso sistema fs.read /
recurso sistema fs.write /armazem
recurso sistema net.connect tcp:10.0.2.100:7 udp:10.0.2.2:69 udp:10.0.2.3:53
recurso sistema net.observe udp:10.0.2.3:53
recurso sistema net.block tcp:10.0.2.100:7 udp:10.0.2.2:69 udp:10.0.2.3:53
armazem sistema 268435456 65536
recurso sistema process.run /
recurso sistema message.send papel:observador papel:operador papel:sistema papel:administrador
taxa sistema 400 800
processos sistema 32

papel administrador agent.read system.read log.read ui.read ui.act process.run net.send net.connect fs.read fs.write audit.read policy.read agent.register agent.revoke policy.assign policy.write person.register person.revoke credential.rotate session.revoke lease.revoke message.send message.read message.purge message.purge_mailbox admin.revoke security.read net.observe net.block
recurso administrador fs.read /dados /bin /programas /armazem/compartilhado
recurso administrador fs.write /armazem/compartilhado
recurso administrador net.connect tcp:10.0.2.100:7 udp:10.0.2.2:69 udp:10.0.2.3:53
recurso administrador net.observe udp:10.0.2.3:53
recurso administrador net.block tcp:10.0.2.100:7 udp:10.0.2.2:69 udp:10.0.2.3:53
armazem administrador 67108864 16384
recurso administrador process.run /bin /programas
recurso administrador message.send papel:operador papel:sistema papel:administrador
taxa administrador 10 20
processos administrador 8

quorum admin.revoke 2 3

papel seguranca audit.read net.observe net.block
recurso seguranca net.observe udp:10.0.2.3:53
recurso seguranca net.block tcp:10.0.2.100:7 udp:10.0.2.2:69 udp:10.0.2.3:53
taxa seguranca 10 20
servico nsf seguranca
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
///   `/programas`, arquivos de `/dados`, `/bin` e `/programas`; lê e
///   escreve no armazém compartilhado, `/armazem/compartilhado`;
/// - `sistema` e `administrador`: ver `papeis_de_sistema`.
pub const PADRAO: &str = concat!(
    "\
# A politica do Duke: papeis, permissoes, recursos e taxas.
#
# Uma permissao sensivel (fs.*, net.connect, keyboard.read, debug.trigger,
# terminal.attach, policy.*, agent.register, agent.revoke, person.*,
# credential.rotate, session.revoke, lease.revoke, message.*) nao atravessa
# a inclusao de outro papel: cada papel que a tem a escreve. Toda permissao
# de caminho, o message.send e o net.connect tem o alcance escrito numa
# linha `recurso` — o de message.send e o papel do destinatario,
# `papel:<nome>`, e o de net.connect cada destino inteiro,
# `tcp:<ipv4>:<porta>` ou `udp:<ipv4>:<porta>`, os dois enumerados. Nao ha
# curinga. Os unicos destinos desta imagem sao os da bancada: o eco TCP em
# 10.0.2.100:7, o TFTP do emulador, UDP, em 10.0.2.2:69, e o DNS do
# emulador, UDP, em 10.0.2.3:53. So o sistema e o proprio administrador
# alcancam o administrador: nenhum policy.write da esse alcance a outro
# papel. O tecido de seguranca (servico nsf) decide pelo papel seguranca, e
# so pelo que ele enumera.

papel observador agent.read system.read log.read ui.read message.read
taxa observador 20 40
processos observador 2

papel operador @observador ui.act process.run net.send net.connect fs.read fs.write message.send message.read
recurso operador fs.read /dados /bin /programas /armazem/compartilhado
recurso operador fs.write /armazem/compartilhado
recurso operador net.connect tcp:10.0.2.100:7 udp:10.0.2.2:69 udp:10.0.2.3:53
armazem operador 16777216 4096
recurso operador process.run /bin /programas
recurso operador message.send papel:operador papel:sistema
taxa operador 50 100
processos operador 8

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
        // A escrita bruta, ninguém: não há operação para ela.
        for papel in ["observador", "operador", "administrador", "sistema"] {
            assert_eq!(d(papel, FsRawWrite, Some("/dados")), Codigo::DenyPermission);
        }
        // fs.write: só no armazém, e cada papel no alcance que a linha dele
        // escreve. O observador, nada.
        assert_eq!(
            d("observador", FsWrite, Some("/armazem/compartilhado/x")),
            Codigo::DenyPermission
        );
        for papel in ["operador", "administrador"] {
            assert_eq!(
                d(papel, FsWrite, Some("/armazem/compartilhado/x")),
                Codigo::Allow
            );
            for fora in [
                "/armazem/x",
                "/armazem",
                "/armazem/compartilhadox",
                "/dados/x",
            ] {
                assert_eq!(
                    d(papel, FsWrite, Some(fora)),
                    Codigo::DenyResource,
                    "{papel} {fora}"
                );
            }
            assert_eq!(
                d(papel, FsRead, Some("/armazem/compartilhado/x")),
                Codigo::Allow
            );
            assert_eq!(d(papel, FsRead, Some("/armazem/x")), Codigo::DenyResource);
        }
        assert_eq!(d("sistema", FsWrite, Some("/armazem/x/y")), Codigo::Allow);
        assert_eq!(d("sistema", FsWrite, Some("/armazem")), Codigo::Allow);
        for fora in ["/dados/x", "/", "/armazemx", "/etc/duke/politica"] {
            assert_eq!(
                d("sistema", FsWrite, Some(fora)),
                Codigo::DenyResource,
                "{fora}"
            );
        }
        assert_eq!(d("sistema", FsWrite, None), Codigo::DenyResource);
        // net.connect: o observador não; os outros, só o destino escrito —
        // inteiro, na forma normal. Nem outra porta, nem outro endereço,
        // nem a mesma coisa escrita de outro jeito.
        assert_eq!(
            d("observador", NetConnect, Some("tcp:10.0.2.100:7")),
            Codigo::DenyPermission
        );
        for papel in ["operador", "administrador", "sistema"] {
            for dentro in ["tcp:10.0.2.100:7", "udp:10.0.2.2:69", "udp:10.0.2.3:53"] {
                assert_eq!(
                    d(papel, NetConnect, Some(dentro)),
                    Codigo::Allow,
                    "{papel} {dentro}"
                );
            }
            // O protocolo é parte do destino: o TFTP, que é UDP, não é
            // alcançado como TCP, nem o eco TCP como UDP.
            for fora in [
                "tcp:10.0.2.100:8",
                "tcp:10.0.2.101:7",
                "tcp:10.0.2.2:7",
                "tcp:010.0.2.100:7",
                "tcp:10.0.2.100:07",
                "udp:10.0.2.100:7",
                "tcp:10.0.2.2:69",
                "udp:10.0.2.2:70",
                "tcp:10.0.2.3:53",
                "udp:10.0.2.3:5353",
                "udp:10.0.2.2:069",
                "UDP:10.0.2.2:69",
                "tcp:10.0.2.100",
                "",
            ] {
                assert_eq!(
                    d(papel, NetConnect, Some(fora)),
                    Codigo::DenyResource,
                    "{papel} {fora}"
                );
            }
            assert_eq!(d(papel, NetConnect, None), Codigo::DenyResource);
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
    /// não é administrativa nem a escrita bruta — sem incluir papel nenhum,
    /// sem curinga —, e cada uma de caminho com o alcance escrito: `/` para
    /// ler e executar, e só o armazém para escrever.
    #[test]
    fn o_sistema_e_maximo_e_enumerado() {
        let p = padrao();
        let sistema = p.papel("sistema").unwrap();
        assert!(sistema.inclui.is_empty(), "o sistema inclui outro papel");
        for perm in permissao::TODAS {
            let esperado = !perm.administrativa() && perm != Permissao::FsRawWrite;
            assert_eq!(sistema.tem(perm), esperado, "{}", perm.nome());
            assert_eq!(
                sistema.diretas.contains(&perm),
                esperado,
                "{} nao esta escrita",
                perm.nome()
            );
            if esperado && perm.recurso_e_endereco() {
                // Os destinos da bancada, cada um escrito; observar, só o
                // DNS — o único que alguém observa.
                let alcance: &[&str] = if perm == Permissao::NetObserve {
                    &["udp:10.0.2.3:53"]
                } else {
                    &["tcp:10.0.2.100:7", "udp:10.0.2.2:69", "udp:10.0.2.3:53"]
                };
                assert_eq!(
                    sistema.recursos.get(&perm).unwrap(),
                    alcance,
                    "{}",
                    perm.nome()
                );
            }
            if esperado && perm.recurso_e_caminho() {
                let alcance = if perm == Permissao::FsWrite {
                    "/armazem"
                } else {
                    "/"
                };
                assert_eq!(sistema.recursos.get(&perm).unwrap(), &[alcance.to_string()]);
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
            mudar("papel operador @observador ui.act process.run net.send net.connect fs.read fs.write message.send message.read audit.read")
                .unwrap();
        assert!(nova.papel("operador").unwrap().tem(Permissao::AuditRead));
        // O que ele não tem: não.
        assert!(matches!(
            mudar(
                "papel operador @observador ui.act process.run net.send net.connect fs.read fs.write message.send message.read keyboard.read"
            ),
            Err(Recusa::Proibida(_))
        ));
        // Tirar net.connect e deixar a linha do alcance dela: a política
        // que resultaria não vale — um alcance para o que o papel não tem.
        assert!(matches!(
            mudar(
                "papel operador @observador ui.act process.run net.send fs.read fs.write message.send message.read"
            ),
            Err(Recusa::Invalida(_))
        ));
        // Um destino que o administrador não alcança: não. Nem outra porta.
        for fora in [
            "recurso operador net.connect tcp:10.0.2.100:7 tcp:10.0.2.2:80",
            "recurso operador net.connect tcp:10.0.2.100:8",
        ] {
            assert!(matches!(mudar(fora), Err(Recusa::Proibida(_))), "{fora}");
        }
        // Um destino fora da forma normal: a linha não se lê.
        assert!(matches!(
            mudar("recurso operador net.connect tcp:10.0.2.100:07"),
            Err(Recusa::Invalida(_))
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

    /// O `fs.write` do sistema é a linha da política, e só ela: na padrão e
    /// na de emergência as decisões são as mesmas, caminho a caminho; sem a
    /// linha, o sistema não escreve — nada no código a supre.
    #[test]
    fn o_fs_write_do_sistema_e_so_a_linha() {
        let p = padrao();
        let e = Politica::emergencia();
        for caminho in [
            "/armazem",
            "/armazem/x",
            "/armazem/compartilhado/y",
            "/armazemx",
            "/dados/x",
            "/",
            "/etc/duke/privado/x",
        ] {
            assert_eq!(
                e.decidir(Some("sistema"), Permissao::FsWrite, Some(caminho)),
                p.decidir(Some("sistema"), Permissao::FsWrite, Some(caminho)),
                "{caminho}"
            );
        }
        assert_eq!(
            p.decidir(Some("sistema"), Permissao::FsWrite, Some("/armazem/x")),
            Codigo::Allow
        );
        assert_eq!(
            p.decidir(Some("sistema"), Permissao::FsWrite, Some("/dados/x")),
            Codigo::DenyResource
        );
        // A mesma política sem a permissão e sem a linha de alcance dela.
        let sem: alloc::string::String = PADRAO
            .lines()
            .filter(|l| !l.starts_with("recurso sistema fs.write"))
            .map(|l| {
                if l.starts_with("papel sistema ") {
                    l.replace(" fs.write ", " ")
                } else {
                    l.to_string()
                }
            })
            .collect::<alloc::vec::Vec<_>>()
            .join("\n");
        let sem = Politica::ler(&sem).expect("a politica sem fs.write vale");
        assert_eq!(
            sem.decidir(Some("sistema"), Permissao::FsWrite, Some("/armazem/x")),
            Codigo::DenyPermission
        );
        // E o teto não muda por isso: o administrador continua o mesmo.
        assert_eq!(sem.papel("administrador"), p.papel("administrador"));
    }

    /// O teto não é posse: a padrão e a de emergência não dão o papel de
    /// administrador à serial nem à autoridade local, e uma que desse não
    /// passa pela conferência.
    #[test]
    fn nenhum_teto_e_exercido() {
        for p in [padrao(), Politica::emergencia()] {
            assert_eq!(p.conferir_tetos(&["administrador"]), Ok(()));
        }
        let serial = PADRAO.replace("serial sistema", "serial administrador");
        let serial = Politica::ler(&serial).expect("le");
        assert!(serial.conferir_tetos(&["administrador"]).is_err());
        let local = PADRAO.replace("local sistema", "local administrador");
        let local = Politica::ler(&local).expect("le");
        assert!(local.conferir_tetos(&["administrador"]).is_err());
        // Outro papel de administrador, do registro, é teto também.
        assert!(padrao().conferir_tetos(&["sistema"]).is_err());
    }

    /// O tecido de segurança é um principal como os outros: o serviço `nsf`
    /// decide pelo papel `seguranca`, que enumera três permissões e o
    /// alcance de cada uma — nas duas políticas embutidas. Nada além: nem
    /// conectar, nem ler arquivo, nem lançar, nem ler o que ele mesmo viu.
    #[test]
    fn o_servico_decide_pelo_papel_dele() {
        use Permissao::*;
        for p in [padrao(), Politica::emergencia()] {
            assert_eq!(p.servico("nsf"), Some("seguranca"));
            assert_eq!(p.servico("outro"), None);
            let papel = p.papel("seguranca").unwrap();
            let todas: alloc::vec::Vec<_> = papel.permissoes().map(|x| x.nome()).collect();
            assert_eq!(todas, ["audit.read", "net.observe", "net.block"]);
            let d = |perm, rec| p.decidir(Some("seguranca"), perm, rec);
            assert_eq!(d(AuditRead, None), Codigo::Allow);
            assert_eq!(d(NetObserve, Some("udp:10.0.2.3:53")), Codigo::Allow);
            assert_eq!(d(NetObserve, Some("udp:10.0.2.2:69")), Codigo::DenyResource);
            for dentro in ["tcp:10.0.2.100:7", "udp:10.0.2.2:69", "udp:10.0.2.3:53"] {
                assert_eq!(d(NetBlock, Some(dentro)), Codigo::Allow, "{dentro}");
            }
            for fora in ["tcp:10.0.2.100:8", "udp:10.0.2.99:53", ""] {
                assert_eq!(d(NetBlock, Some(fora)), Codigo::DenyResource, "{fora}");
            }
            for perm in [
                NetConnect,
                FsRead,
                FsWrite,
                ProcessRun,
                SecurityRead,
                PolicyRead,
                MessageSend,
                AgentRevoke,
                TerminalAttach,
            ] {
                assert_eq!(
                    d(perm, Some("tcp:10.0.2.100:7")),
                    Codigo::DenyPermission,
                    "{}",
                    perm.nome()
                );
            }
            // E o papel dele cabe no teto: um administrador pode mudá-lo
            // por policy.write, dentro do que ele mesmo tem.
            assert_eq!(p.cabe_em("seguranca", "administrador"), Ok(()));
            // O serviço não exerce teto.
            assert_eq!(p.conferir_tetos(&["administrador"]), Ok(()));
        }
    }

    /// O serviço não herda o sistema: uma política que lhe dê o papel da
    /// serial ou o da autoridade local não vigora, e uma troca da serial
    /// para o papel dele é recusada. Nem o teto de um administrador.
    #[test]
    fn o_servico_nao_herda_o_sistema() {
        let erro = |t: &str| Politica::ler(t).unwrap_err().tipo;
        assert!(matches!(
            erro("papel a ui.read\nserial a\nlocal a\nservico nsf a\n"),
            arquivo::ErroTipo::ServicoComPapelDoSistema(s, p) if s == "nsf" && p == "a"
        ));
        assert!(matches!(
            erro("papel a ui.read\npapel b ui.read\nserial a\nlocal b\nservico nsf b\n"),
            arquivo::ErroTipo::ServicoComPapelDoSistema(_, _)
        ));
        let p = padrao();
        assert!(matches!(
            p.com_serial("seguranca"),
            Err(Recusa::Invalida(arquivo::Erro {
                tipo: arquivo::ErroTipo::ServicoComPapelDoSistema(_, _),
                ..
            }))
        ));
        assert!(p.com_serial("operador").is_ok());
        let teto = PADRAO.replace("servico nsf seguranca", "servico nsf administrador");
        let teto = Politica::ler(&teto).expect("le");
        assert!(teto.conferir_tetos(&["administrador"]).is_err());
    }

    /// Só o DNS da bancada é observável — o único destino que um papel tem
    /// em `net.observe` —, e só enquanto um papel o tiver.
    #[test]
    fn o_que_se_observa() {
        let p = padrao();
        assert!(p.observavel("udp:10.0.2.3:53"));
        for d in [
            "udp:10.0.2.2:69",
            "tcp:10.0.2.100:7",
            "udp:10.0.2.3:5353",
            "",
        ] {
            assert!(!p.observavel(d), "{d}");
        }
        // Sem a permissão em papel nenhum — a linha do alcance e o nome.
        let sem: alloc::string::String = PADRAO
            .lines()
            .filter(|l| !(l.starts_with("recurso") && l.contains("net.observe")))
            .map(|l| alloc::format!("{}\n", l.replace(" net.observe", "")))
            .collect();
        let sem = Politica::ler(&sem).expect("le sem net.observe");
        assert!(!sem.observavel("udp:10.0.2.3:53"));
    }

    /// A linha `servico`: um nome do vocabulário fechado, uma vez, com um
    /// papel que existe — e só pela imagem: `policy.write` a recusa.
    #[test]
    fn a_linha_servico() {
        let erro = |corpo: &str| com(corpo).unwrap_err().tipo;
        assert!(matches!(
            erro("papel a ui.read\npapel b ui.read\nservico outro b"),
            arquivo::ErroTipo::ServicoDesconhecido(n) if n == "outro"
        ));
        assert!(matches!(
            erro("papel a ui.read\npapel b ui.read\nservico nsf b\nservico nsf b"),
            arquivo::ErroTipo::ServicoRepetido(_)
        ));
        assert!(matches!(
            erro("papel a ui.read\npapel b ui.read\nservico nsf fantasma"),
            arquivo::ErroTipo::PapelDesconhecido(n) if n == "fantasma"
        ));
        assert_eq!(
            erro("papel a ui.read\npapel b ui.read\nservico nsf"),
            arquivo::ErroTipo::Sintaxe
        );
        assert_eq!(
            erro("papel a ui.read\npapel b ui.read\nservico nsf b c"),
            arquivo::ErroTipo::Sintaxe
        );
        assert!(matches!(
            erro("papel a ui.read\npapel b ui.read\nservico nsf B"),
            arquivo::ErroTipo::NomeInvalido(_)
        ));
        let p = com("papel a ui.read\npapel b ui.read\nservico nsf b").unwrap();
        assert_eq!(p.servico("nsf"), Some("b"));
        // Sem a linha, o serviço não tem papel — e a decisão sem papel é
        // DENY_ROLE.
        let sem = com("papel a ui.read\npapel b ui.read").unwrap();
        assert_eq!(sem.servico("nsf"), None);
        assert_eq!(
            sem.decidir(sem.servico("nsf"), Permissao::AuditRead, None),
            Codigo::DenyRole
        );
        // O texto a leva, e a leitura a devolve.
        let padrao = padrao();
        assert_eq!(Politica::ler(&padrao.texto()).unwrap(), padrao);
        assert!(padrao.texto().contains("servico nsf seguranca\n"));
        // policy.write não a escreve, nem para tirar o papel do sistema.
        for linha in ["servico nsf operador", "servico nsf seguranca"] {
            assert!(matches!(
                padrao.com_linha(linha, "administrador", &[]),
                Err(Recusa::Proibida(_))
            ));
        }
    }
}
