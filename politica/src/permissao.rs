//! O vocabulário fechado das permissões.
//!
//! Uma permissão é um nome desta lista, e só. Um nome fora dela num arquivo
//! de política é um erro, e não uma permissão que ninguém confere: o dia em
//! que alguém escrever `fs.raed` num papel, a política inteira é recusada
//! dizendo a linha, em vez de o papel ficar sem a permissão que parecia ter.
//!
//! # Sensíveis e administrativas
//!
//! As **sensíveis** são as que o papel precisa listar com o próprio nome: a
//! inclusão de outro papel (`@observador`) não as traz. É o que impede um
//! papel amplo de conceder, por herança, acesso que ninguém escreveu.
//!
//! As **administrativas** só se exercem por `admin.execute`, com a prova de
//! um administrador: nenhum comando comum as usa. Estão no vocabulário para
//! que o papel do administrador as declare — e o papel diga o que ele pode.

/// Uma permissão.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permissao {
    /// O próprio canal: sessão, registro, a lista de comandos.
    AgentRead,
    /// O estado do sistema: memória, tarefas, dispositivos, contadores.
    SystemRead,
    /// O log do kernel.
    LogRead,
    /// O que está na tela: a árvore e a amostra do vídeo.
    UiRead,
    /// Agir num elemento da tela.
    UiAct,
    /// Ler arquivos.
    FsRead,
    /// Escrever arquivos. Nenhuma operação a usa ainda: o disco é só leitura.
    FsWrite,
    /// Ler setores crus do disco, por baixo do sistema de arquivos.
    FsRawRead,
    /// Escrever setores crus. Nenhuma operação a usa ainda.
    FsRawWrite,
    /// Lançar um programa.
    ProcessRun,
    /// Mandar um pacote pela rede.
    NetSend,
    /// Ler o que a pessoa digitou.
    KeyboardRead,
    /// Provocar uma falha fatal de propósito.
    DebugTrigger,
    /// Prender-se ao pseudo-terminal: o que se escreve nele o interpretador
    /// executa como a pessoa na frente da máquina.
    TerminalAttach,
    /// Ler a auditoria.
    AuditRead,
    /// Ler a política.
    PolicyRead,
    /// Registrar um agente.
    AgentRegister,
    /// Revogar um agente.
    AgentRevoke,
    /// Mudar o papel de um agente, ou o da serial.
    PolicyAssign,
    /// Mudar a definição de um papel.
    PolicyWrite,
    /// Registrar uma pessoa.
    PersonRegister,
    /// Revogar uma pessoa: ela não entra mais, e as sessões dela acabam. O
    /// registro dela fica, para a auditoria.
    PersonRevoke,
    /// Trocar a credencial de uma pessoa, sem criar outra pessoa.
    CredentialRotate,
    /// Encerrar uma sessão de pessoa, sem tocar na pessoa.
    SessionRevoke,
    /// Revogar o arrendamento de um recurso, de quem for. A única forma de
    /// quebrar o arrendamento de outro — ninguém o toma por ter um papel
    /// maior.
    LeaseRevoke,
    /// Mandar uma mensagem a outro titular. O recurso é o papel do
    /// destinatário, e o alcance de cada papel é enumerado: `papel:<nome>`.
    MessageSend,
    /// Ler e confirmar a **própria** caixa, consultar as próprias
    /// mensagens, e cancelar as que mandou enquanto ninguém as leu. Nunca a
    /// caixa de outro: a caixa vem da sessão, e não de um parâmetro.
    MessageRead,
    /// Tirar mensagens de outro titular, ou uma caixa inteira — só pela
    /// operação administrativa, com prova.
    MessagePurge,
}

/// Todas, na ordem do relatório.
pub const TODAS: [Permissao; 28] = [
    Permissao::AgentRead,
    Permissao::SystemRead,
    Permissao::LogRead,
    Permissao::UiRead,
    Permissao::UiAct,
    Permissao::FsRead,
    Permissao::FsWrite,
    Permissao::FsRawRead,
    Permissao::FsRawWrite,
    Permissao::ProcessRun,
    Permissao::NetSend,
    Permissao::KeyboardRead,
    Permissao::DebugTrigger,
    Permissao::TerminalAttach,
    Permissao::AuditRead,
    Permissao::PolicyRead,
    Permissao::AgentRegister,
    Permissao::AgentRevoke,
    Permissao::PolicyAssign,
    Permissao::PolicyWrite,
    Permissao::PersonRegister,
    Permissao::PersonRevoke,
    Permissao::CredentialRotate,
    Permissao::SessionRevoke,
    Permissao::LeaseRevoke,
    Permissao::MessageSend,
    Permissao::MessageRead,
    Permissao::MessagePurge,
];

impl Permissao {
    /// O nome, como aparece na política, na auditoria e no relatório.
    pub const fn nome(self) -> &'static str {
        match self {
            Permissao::AgentRead => "agent.read",
            Permissao::SystemRead => "system.read",
            Permissao::LogRead => "log.read",
            Permissao::UiRead => "ui.read",
            Permissao::UiAct => "ui.act",
            Permissao::FsRead => "fs.read",
            Permissao::FsWrite => "fs.write",
            Permissao::FsRawRead => "fs.raw_read",
            Permissao::FsRawWrite => "fs.raw_write",
            Permissao::ProcessRun => "process.run",
            Permissao::NetSend => "net.send",
            Permissao::KeyboardRead => "keyboard.read",
            Permissao::DebugTrigger => "debug.trigger",
            Permissao::TerminalAttach => "terminal.attach",
            Permissao::AuditRead => "audit.read",
            Permissao::PolicyRead => "policy.read",
            Permissao::AgentRegister => "agent.register",
            Permissao::AgentRevoke => "agent.revoke",
            Permissao::PolicyAssign => "policy.assign",
            Permissao::PolicyWrite => "policy.write",
            Permissao::PersonRegister => "person.register",
            Permissao::PersonRevoke => "person.revoke",
            Permissao::CredentialRotate => "credential.rotate",
            Permissao::SessionRevoke => "session.revoke",
            Permissao::LeaseRevoke => "lease.revoke",
            Permissao::MessageSend => "message.send",
            Permissao::MessageRead => "message.read",
            Permissao::MessagePurge => "message.purge",
        }
    }

    /// A permissão com este nome.
    pub fn de_nome(nome: &str) -> Option<Permissao> {
        TODAS.iter().copied().find(|p| p.nome() == nome)
    }

    /// Precisa ser listada pelo nome: a inclusão de outro papel não a traz.
    pub const fn sensivel(self) -> bool {
        matches!(
            self,
            Permissao::FsRead
                | Permissao::FsWrite
                | Permissao::FsRawRead
                | Permissao::FsRawWrite
                | Permissao::KeyboardRead
                | Permissao::DebugTrigger
                | Permissao::TerminalAttach
                | Permissao::PolicyRead
                | Permissao::AgentRegister
                | Permissao::AgentRevoke
                | Permissao::PolicyAssign
                | Permissao::PolicyWrite
                | Permissao::PersonRegister
                | Permissao::PersonRevoke
                | Permissao::CredentialRotate
                | Permissao::SessionRevoke
                | Permissao::LeaseRevoke
                | Permissao::MessageSend
                | Permissao::MessageRead
                | Permissao::MessagePurge
        )
    }

    /// Só se exerce por `admin.execute`, com prova.
    pub const fn administrativa(self) -> bool {
        matches!(
            self,
            Permissao::AgentRegister
                | Permissao::AgentRevoke
                | Permissao::PolicyAssign
                | Permissao::PolicyWrite
                | Permissao::PersonRegister
                | Permissao::PersonRevoke
                | Permissao::CredentialRotate
                | Permissao::SessionRevoke
                | Permissao::LeaseRevoke
                | Permissao::MessagePurge
        )
    }

    /// O recurso desta permissão é um caminho, e um papel pode limitá-lo a
    /// alguns prefixos.
    pub const fn recurso_e_caminho(self) -> bool {
        matches!(
            self,
            Permissao::FsRead | Permissao::FsWrite | Permissao::ProcessRun
        )
    }

    /// O recurso desta permissão é o papel de um destinatário — `papel:<nome>`
    /// —, e um papel o limita a uma lista enumerada de papéis. Sem curinga:
    /// um papel que não está na lista não é alcançado.
    pub const fn recurso_e_destino(self) -> bool {
        matches!(self, Permissao::MessageSend)
    }

    /// Exercê-la muda alguma coisa na máquina — o que a pessoa vê, um
    /// arquivo, um processo, o registro, a caixa de outro —, em vez de só
    /// ler. É o que a barra conta como **agir**: quem a exerceu por último é
    /// o "último" do indicador, e o momento é o "há quanto tempo" do
    /// `agent.list`.
    ///
    /// # Por que pela permissão, e não pelo comando
    ///
    /// Porque a permissão é o que a decisão vê, e a conta é feita no ponto
    /// de decisão: não há comando que mude algo sem passar por uma destas.
    /// E porque o `match` é exaustivo — uma permissão nova não compila sem
    /// alguém dizer de que lado ela fica.
    ///
    /// `message.read` é leitura, e leva junto `message.ack` e
    /// `message.cancel`: confirmar e cancelar mexem só nas mensagens do
    /// próprio titular — a caixa dele, as que ele mandou —, e não no que
    /// outro vê da máquina.
    pub const fn muda_estado(self) -> bool {
        match self {
            Permissao::AgentRead
            | Permissao::SystemRead
            | Permissao::LogRead
            | Permissao::UiRead
            | Permissao::FsRead
            | Permissao::FsRawRead
            | Permissao::KeyboardRead
            | Permissao::AuditRead
            | Permissao::PolicyRead
            | Permissao::MessageRead => false,
            Permissao::UiAct
            | Permissao::FsWrite
            | Permissao::FsRawWrite
            | Permissao::ProcessRun
            | Permissao::NetSend
            | Permissao::DebugTrigger
            | Permissao::TerminalAttach
            | Permissao::AgentRegister
            | Permissao::AgentRevoke
            | Permissao::PolicyAssign
            | Permissao::PolicyWrite
            | Permissao::PersonRegister
            | Permissao::PersonRevoke
            | Permissao::CredentialRotate
            | Permissao::SessionRevoke
            | Permissao::LeaseRevoke
            | Permissao::MessageSend
            | Permissao::MessagePurge => true,
        }
    }

    /// O papel limita o recurso desta permissão por uma linha `recurso`: de
    /// caminho ou de destino. A linha é obrigatória para quem a tem.
    pub const fn tem_alcance(self) -> bool {
        self.recurso_e_caminho() || self.recurso_e_destino()
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn as_que_mudam_o_estado() {
        // As de leitura, pelo nome: tudo o mais muda alguma coisa.
        let leituras = [
            "agent.read",
            "system.read",
            "log.read",
            "ui.read",
            "fs.read",
            "fs.raw_read",
            "keyboard.read",
            "audit.read",
            "policy.read",
            "message.read",
        ];
        for p in TODAS {
            assert_eq!(
                p.muda_estado(),
                !leituras.contains(&p.nome()),
                "{} do lado errado",
                p.nome()
            );
        }
        // Toda administrativa muda: a prova não é pedida para ler.
        for p in TODAS.into_iter().filter(|p| p.administrativa()) {
            assert!(p.muda_estado(), "{}", p.nome());
        }
    }

    #[test]
    fn nomes_vao_e_voltam() {
        for p in TODAS {
            assert_eq!(Permissao::de_nome(p.nome()), Some(p));
        }
        assert_eq!(Permissao::de_nome("fs.raed"), None);
        assert_eq!(Permissao::de_nome("*"), None);
    }

    /// As que o pedido nomeou como sensíveis são sensíveis.
    #[test]
    fn as_sensiveis_do_pedido() {
        for nome in [
            "fs.read",
            "fs.write",
            "fs.raw_read",
            "fs.raw_write",
            "debug.trigger",
            "terminal.attach",
            "agent.register",
            "agent.revoke",
            "policy.read",
            "policy.write",
        ] {
            assert!(Permissao::de_nome(nome).unwrap().sensivel(), "{nome}");
        }
    }

    /// As operações sobre pessoas só se exercem com prova, e o papel que as
    /// tem as escreve pelo nome.
    #[test]
    fn as_de_pessoa_sao_administrativas() {
        for nome in [
            "person.register",
            "person.revoke",
            "credential.rotate",
            "session.revoke",
            "lease.revoke",
        ] {
            let p = Permissao::de_nome(nome).unwrap();
            assert!(p.administrativa() && p.sensivel(), "{nome}");
        }
    }

    /// As de mensagem não atravessam a inclusão: cada papel que manda ou lê
    /// as escreve pelo nome. Tirar mensagem de outro é administrativo; mandar
    /// e ler, não. E só mandar tem o papel do destinatário como recurso.
    #[test]
    fn as_de_mensagem() {
        let (manda, le, purga) = (
            Permissao::MessageSend,
            Permissao::MessageRead,
            Permissao::MessagePurge,
        );
        assert!(manda.sensivel() && le.sensivel() && purga.sensivel());
        assert!(!manda.administrativa() && !le.administrativa() && purga.administrativa());
        assert!(manda.recurso_e_destino() && !manda.recurso_e_caminho());
        assert!(!le.recurso_e_destino() && !purga.recurso_e_destino());
        assert!(TODAS.iter().filter(|p| p.recurso_e_destino()).count() == 1);
    }
}
