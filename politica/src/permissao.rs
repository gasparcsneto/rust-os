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
//!
//! # As do tempo
//!
//! `time.sync` autoriza **apresentar evidência**, e não escolher a hora:
//! pedir ao kernel um pedido do Roughtime para uma fonte do registro de
//! fontes, e entregar a resposta que chegou — o kernel a confere contra o
//! que ele mesmo emitiu, e só o acordo de pelo menos duas chaves move o
//! relógio civil (ver o pacote `hora`). `time.confirm` aplica um salto que
//! o quórum já indicou e que ficou pendente; é administrativa, e não aceita
//! uma hora digitada. As duas são sensíveis — nenhuma vem pela inclusão de
//! outro papel —, e nenhuma tem alcance próprio: as fontes são destinos de
//! `net.connect`, e o alcance delas é o dessa permissão.
//!
//! # A declaração
//!
//! `audit.declare` autoriza um programa a **declarar** um fato dele para a
//! auditoria — um evento, o assunto e o desfecho, ancorados, se ele quiser,
//! numa conexão dele —, e nada mais. A declaração é uma alegação: o kernel
//! a grava na mesma cadeia com o que só ele sabe — quem, o papel, a sessão,
//! o processo, a proveniência e o destino real da conexão —, e nenhuma
//! decisão a lê: nem o gate, nem o firewall, nem as cotas, nem a contenção.
//! Não autoriza, não nega e não muda nada além do registro. Sem alcance: o
//! que se declara não é recurso de política. Sensível — o papel que a tem a
//! escreve —, e não administrativa: um programa a exerce pelo gate, com o
//! manifesto dele.
//!
//! # As chaves
//!
//! Uma chave de assinatura é da **identidade durável** de quem a cria — a
//! pessoa, o agente, o serviço, o sistema —, e não da sessão, do processo
//! ou da credencial; a chave privada nunca sai do kernel. `key.create`,
//! `key.read`, `key.sign` e `key.destroy` têm alcance: o recurso é
//! `chave:<nome>`, e cada papel enumera os nomes — sem curinga. O nome se
//! resolve no espaço de quem pede: `chave:x` de uma identidade não é
//! `chave:x` de outra, e saber o nome da chave de outro não dá nada. Assinar
//! é sempre num **domínio** registrado na imagem, que a linha `dominios` do
//! papel enumera (ver [`crate::arquivo`]); o kernel assina o prefixo do
//! domínio seguido de um resumo de 32 bytes, e nada mais. `key.revoke` é
//! administrativa: anula a chave de outra identidade, por `admin.execute`,
//! com prova — e não dá a ninguém o uso dela. Todas sensíveis: nenhuma vem
//! pela inclusão de outro papel.
//!
//! # A própria credencial
//!
//! `credential.change_self` autoriza uma pessoa a trocar a **própria**
//! senha, e nada mais: o alvo é sempre a credencial da dona da sessão que
//! pede — nunca um parâmetro, nunca a de outra pessoa. Autoriza; não
//! autentica: a troca exige, além dela, a prova da senha atual, conferida
//! pelo kernel contra o verificador. Sem alcance — não há recurso a
//! enumerar —, sensível — cada papel que a tem a escreve —, e não
//! administrativa: a pessoa a exerce pelo gate, sem prova de
//! administrador. Trocar a credencial **de outro** continua sendo
//! `credential.rotate`, administrativa.

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
    /// Abrir uma conexão de saída e usá-la — mandar, receber, fechar. O
    /// recurso é o destino, `tcp:<ipv4>:<porta>` ou `udp:<ipv4>:<porta>`, e
    /// o alcance de cada papel é enumerado: cada destino escrito por
    /// inteiro, com o protocolo.
    NetConnect,
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
    /// Tirar uma mensagem viva de outro titular, pelo id — só pela
    /// operação administrativa, com prova.
    MessagePurge,
    /// Esvaziar a caixa inteira de um titular — só pela operação
    /// administrativa, com prova.
    ///
    /// Uma permissão própria, e não a de tirar uma mensagem: esvaziar uma
    /// caixa é destrutivo de outro tamanho — tudo o que alguém ia ler, de
    /// uma vez, sem olhar uma por uma —, e quem pode o menor não ganha o
    /// maior por tabela. Um papel que tem uma não tem a outra sem escrevê-la.
    MessagePurgeMailbox,
    /// Revogar a credencial de um administrador — só pela operação de
    /// quórum: M credenciais distintas provam o mesmo pedido, e o papel de
    /// cada uma precisa ter esta permissão. Uma credencial só não revoga
    /// outra.
    AdminRevoke,
    /// Ler o que o tecido de segurança observou: os eventos, os
    /// incidentes, a proveniência, o risco, a evidência e as regras do
    /// firewall. Sensível: diz o que os outros fizeram. Ver
    /// `docs/SEGURANCA.md`.
    SecurityRead,
    /// Ler o conteúdo dos datagramas trocados com um destino observado —
    /// de associações de qualquer titular. O recurso é o destino, como o
    /// de `net.connect`, e o alcance de cada papel é enumerado: só o que
    /// está escrito se observa, e só destinos que algum papel observa são
    /// guardados para isso.
    NetObserve,
    /// Barrar o tráfego para um destino, e tirar a barreira. Só restringe:
    /// nenhuma regra do firewall deixa passar o que o gate não decidiu. O
    /// recurso é o destino, e o alcance de cada papel é enumerado.
    NetBlock,
    /// Isolar um processo — todo pedido dele ao gate passa a ser
    /// `DENY_CONTAINED`, e as conexões dele caem —, e soltá-lo. Uma
    /// contenção reversível, que só restringe. O recurso é o papel de quem
    /// responde pelo processo, `papel:<nome>`, enumerado como o do
    /// `message.send`. Ver `docs/USABILIDADE.md`.
    ProcessIsolate,
    /// Suspender um agente — os pedidos dele e dos processos dele passam a
    /// ser `DENY_CONTAINED`, as conexões caem e os arrendamentos são
    /// soltos —, e retomá-lo. Reversível; não é revogação. O recurso é o
    /// papel do agente.
    AgentSuspend,
    /// Suspender uma credencial — de pessoa ou de agente: ela não
    /// autentica, e as sessões abertas com ela não agem —, e retomá-la.
    /// Reversível; não é revogação. O recurso é o papel do titular.
    CredentialSuspend,
    /// Bytes aleatórios do gerador do kernel — `random.read` —, para quem
    /// precisa de uma chave efêmera, um `random` de aperto, um nonce: o TLS
    /// de um programa (`docs/SEGURANCA.md`). Sem recurso, e não sensível: o
    /// que sai não diz nada de ninguém, e a taxa do papel limita quanto. Os
    /// bytes nunca vão para a auditoria — só a decisão.
    RandomRead,
    /// Apresentar evidência de hora: pedir ao kernel o pedido do Roughtime
    /// para uma fonte do registro de fontes (`time.request`), e entregar a
    /// resposta que chegou (`time.sync`). Não escolhe a hora — o kernel
    /// confere a resposta contra o pedido que ele emitiu, e só um acordo de
    /// pelo menos duas chaves move o relógio civil. Sensível: o papel que a
    /// tem a escreve. Sem alcance próprio: o transporte até a fonte é um
    /// `net.connect`, decidido à parte, com os destinos enumerados.
    TimeSync,
    /// Aplicar o salto pendente — o que o quórum indicou e que, acima do
    /// teto ou fora do envelope, espera uma pessoa. Administrativa: só por
    /// `admin.execute`, com prova. Não aceita uma hora digitada; sem salto
    /// pendente, não há o que confirmar.
    TimeConfirm,
    /// Declarar um fato do programa para a auditoria — `audit.declare`: uma
    /// alegação, gravada com os fatos do kernel, que nenhuma decisão lê. Ver
    /// o cabeçalho do módulo.
    AuditDeclare,
    /// Criar uma chave de assinatura da própria identidade, para um domínio
    /// que o papel enumera. O recurso é `chave:<nome>`, no espaço de quem
    /// pede; um nome que já foi usado — por uma chave viva ou destruída —
    /// não se cria de novo.
    KeyCreate,
    /// Ler o que é público de uma chave da própria identidade: a chave
    /// pública, o algoritmo, o domínio e o estado. Nunca a privada.
    KeyRead,
    /// Assinar, com uma chave da própria identidade, um resumo de 32 bytes
    /// no domínio da chave. Uma decisão por assinatura, reconfirmada no
    /// ponto de commit, e gravada na auditoria antes de a assinatura sair.
    KeySign,
    /// Destruir uma chave da própria identidade: a privada é apagada, e o
    /// nome fica marcado para sempre — não se cria outra com ele.
    KeyDestroy,
    /// Anular a chave de outra identidade — só pela operação
    /// administrativa, com prova. Não dá o uso da chave a quem anula: ela
    /// deixa de assinar para todos.
    KeyRevoke,
    /// Encerrar um processo: ele é isolado na hora — os pedidos dele
    /// passam a ser `DENY_CONTAINED`, as conexões caem — e morre no próximo
    /// ponto seguro, sem sair por `sair`. Não tem inverso: não é uma
    /// contenção, e quem a tem não ganha `process.isolate` por isso. O
    /// recurso é o papel de quem responde pelo processo, `papel:<nome>`,
    /// enumerado como o do `process.isolate`. Sensível, e não
    /// administrativa: quem a tem a exerce pelo gate; o administrador, pela
    /// prova.
    ProcessTerminate,
    /// Reiniciar ou desligar a máquina — `system.reboot` e
    /// `system.poweroff`. O registro do pedido vai ao journal antes, e sem
    /// ele a máquina não para; as gravações param com a ordem da
    /// persistência e a tranca do disco na mão. Sem recurso: a máquina é
    /// uma só. Sensível — o papel que a tem a escreve —, e não
    /// administrativa: o `sistema` a exerce pelo gate, como o
    /// `debug.trigger`, que derruba a máquina de outro jeito; o
    /// administrador, pela prova.
    SystemPower,
    /// A atualização A/B: escrever a versão nova no slot inativo —
    /// `update.stage`, pelo gate — e, no papel de **cada** credencial que
    /// assina, instalá-la ou desistir dela — a operação de quórum
    /// `system.update`, com a linha `quorum` da política. Escrever não
    /// instala nada: só o quórum arma uma versão, e só a versão que bootou
    /// e se conferiu vira a ativa. Sem recurso: o slot que se escreve é o
    /// inativo, que o journal diz qual é. Sensível, e não administrativa,
    /// como o `system.power`: o `sistema` a exerce pelo gate; a instalação
    /// é do quórum.
    SystemUpdate,
    /// Trocar a **própria** senha — a credencial da dona da sessão que
    /// pede, provando a atual. Ver o cabeçalho do módulo. Sem recurso,
    /// sensível, e não administrativa.
    CredentialChangeSelf,
}

/// Todas, na ordem do relatório. As novas entram no fim: a posição é o bit
/// do manifesto — ver [`crate::manifesto::Permissoes`].
pub const TODAS: [Permissao; 50] = [
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
    Permissao::NetConnect,
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
    Permissao::MessagePurgeMailbox,
    Permissao::AdminRevoke,
    Permissao::SecurityRead,
    Permissao::NetObserve,
    Permissao::NetBlock,
    Permissao::ProcessIsolate,
    Permissao::AgentSuspend,
    Permissao::CredentialSuspend,
    Permissao::RandomRead,
    Permissao::TimeSync,
    Permissao::TimeConfirm,
    Permissao::AuditDeclare,
    Permissao::KeyCreate,
    Permissao::KeyRead,
    Permissao::KeySign,
    Permissao::KeyDestroy,
    Permissao::KeyRevoke,
    Permissao::ProcessTerminate,
    Permissao::SystemPower,
    Permissao::SystemUpdate,
    Permissao::CredentialChangeSelf,
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
            Permissao::NetConnect => "net.connect",
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
            Permissao::MessagePurgeMailbox => "message.purge_mailbox",
            Permissao::AdminRevoke => "admin.revoke",
            Permissao::SecurityRead => "security.read",
            Permissao::NetObserve => "net.observe",
            Permissao::NetBlock => "net.block",
            Permissao::ProcessIsolate => "process.isolate",
            Permissao::AgentSuspend => "agent.suspend",
            Permissao::CredentialSuspend => "credential.suspend",
            Permissao::RandomRead => "random.read",
            Permissao::TimeSync => "time.sync",
            Permissao::TimeConfirm => "time.confirm",
            Permissao::AuditDeclare => "audit.declare",
            Permissao::KeyCreate => "key.create",
            Permissao::KeyRead => "key.read",
            Permissao::KeySign => "key.sign",
            Permissao::KeyDestroy => "key.destroy",
            Permissao::KeyRevoke => "key.revoke",
            Permissao::ProcessTerminate => "process.terminate",
            Permissao::SystemPower => "system.power",
            Permissao::SystemUpdate => "system.update",
            Permissao::CredentialChangeSelf => "credential.change_self",
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
                | Permissao::NetConnect
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
                | Permissao::MessagePurgeMailbox
                | Permissao::AdminRevoke
                | Permissao::SecurityRead
                | Permissao::NetObserve
                | Permissao::NetBlock
                | Permissao::ProcessIsolate
                | Permissao::AgentSuspend
                | Permissao::CredentialSuspend
                | Permissao::TimeSync
                | Permissao::TimeConfirm
                | Permissao::AuditDeclare
                | Permissao::KeyCreate
                | Permissao::KeyRead
                | Permissao::KeySign
                | Permissao::KeyDestroy
                | Permissao::KeyRevoke
                | Permissao::ProcessTerminate
                | Permissao::SystemPower
                | Permissao::SystemUpdate
                | Permissao::CredentialChangeSelf
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
                | Permissao::MessagePurgeMailbox
                | Permissao::AdminRevoke
                | Permissao::TimeConfirm
                | Permissao::KeyRevoke
        )
    }

    /// O recurso desta permissão é uma chave da identidade de quem pede —
    /// `chave:<nome>` —, e um papel o limita a uma lista enumerada de
    /// nomes. Sem curinga: um nome que não está na lista não é alcançado. O
    /// nome se resolve no espaço da identidade de quem pede, e não diz nada
    /// das chaves de outra.
    pub const fn recurso_e_chave(self) -> bool {
        matches!(
            self,
            Permissao::KeyCreate | Permissao::KeyRead | Permissao::KeySign | Permissao::KeyDestroy
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
    /// —, resolvido do endereço de uma mensagem. Ver [`Self::recurso_e_papel`].
    pub const fn recurso_e_destino(self) -> bool {
        matches!(self, Permissao::MessageSend)
    }

    /// O recurso desta permissão é um papel — `papel:<nome>` —, e um papel o
    /// limita a uma lista enumerada de papéis. Sem curinga: um papel que não
    /// está na lista não é alcançado. O do destinatário de uma mensagem, e o
    /// de quem uma contenção alcança — o dono do processo, o agente, o
    /// titular da credencial.
    pub const fn recurso_e_papel(self) -> bool {
        matches!(
            self,
            Permissao::MessageSend
                | Permissao::ProcessIsolate
                | Permissao::AgentSuspend
                | Permissao::CredentialSuspend
                | Permissao::ProcessTerminate
        )
    }

    /// O recurso desta permissão é o papel de quem um **alvo** do pedido
    /// alcança — o processo, o agente, a credencial, nomeados pelos
    /// parâmetros —, e não o de um destinatário de mensagem. O gate lê o
    /// alvo do pedido, decide `papel:<papel do alvo>`, e o handler só age
    /// sobre o alvo decidido. As três contenções e o término de um
    /// processo.
    pub const fn alvo_e_papel(self) -> bool {
        self.recurso_e_papel() && !self.recurso_e_destino()
    }

    /// Uma contenção reversível: só restringe, e tem o seu inverso na mesma
    /// permissão.
    pub const fn contencao(self) -> bool {
        matches!(
            self,
            Permissao::ProcessIsolate | Permissao::AgentSuspend | Permissao::CredentialSuspend
        )
    }

    /// O recurso desta permissão é um destino de rede —
    /// `tcp:<ipv4>:<porta>` ou `udp:<ipv4>:<porta>` —, e um papel o limita a
    /// uma lista enumerada de destinos, cada um escrito por inteiro, com o
    /// protocolo. Sem curinga, sem faixa: ver [`crate::endereco`]. Conectar,
    /// observar e barrar: as três falam do mesmo destino, e cada papel
    /// enumera o seu alcance de cada uma.
    pub const fn recurso_e_endereco(self) -> bool {
        matches!(
            self,
            Permissao::NetConnect | Permissao::NetObserve | Permissao::NetBlock
        )
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
    ///
    /// `time.sync` muda: a evidência entregue pode mover o relógio civil, e
    /// o pedido emitido ocupa a tabela do kernel. `time.confirm` aplica um
    /// salto.
    ///
    /// `audit.declare` não muda: a declaração só acrescenta à auditoria o
    /// registro dela — como toda decisão acrescenta o seu —, e nada que
    /// alguém veja na máquina muda por ela.
    ///
    /// `key.read` é leitura — o que é público da chave. As outras de chave
    /// mudam: criar e destruir mexem na tabela de chaves, anular também, e
    /// assinar é um ato da identidade que sai da máquina com efeito — quem
    /// assinou por último é quem agiu.
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
            | Permissao::MessageRead
            | Permissao::SecurityRead
            | Permissao::NetObserve
            | Permissao::RandomRead
            | Permissao::AuditDeclare
            | Permissao::KeyRead => false,
            Permissao::UiAct
            | Permissao::FsWrite
            | Permissao::FsRawWrite
            | Permissao::ProcessRun
            | Permissao::NetSend
            | Permissao::NetConnect
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
            | Permissao::MessagePurge
            | Permissao::MessagePurgeMailbox
            | Permissao::AdminRevoke
            | Permissao::NetBlock
            | Permissao::ProcessIsolate
            | Permissao::AgentSuspend
            | Permissao::CredentialSuspend
            | Permissao::TimeSync
            | Permissao::TimeConfirm
            | Permissao::KeyCreate
            | Permissao::KeySign
            | Permissao::KeyDestroy
            | Permissao::KeyRevoke
            | Permissao::ProcessTerminate
            | Permissao::SystemPower
            | Permissao::SystemUpdate
            | Permissao::CredentialChangeSelf => true,
        }
    }

    /// O papel limita o recurso desta permissão por uma linha `recurso`: de
    /// caminho, de destinatário, de destino de rede ou de chave. A linha é
    /// obrigatória para quem a tem.
    pub const fn tem_alcance(self) -> bool {
        self.recurso_e_caminho()
            || self.recurso_e_papel()
            || self.recurso_e_endereco()
            || self.recurso_e_chave()
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
            "security.read",
            "net.observe",
            // O gerador anda, mas nada que alguém veja muda.
            "random.read",
            // Só o registro da declaração, como o de toda decisão.
            "audit.declare",
            // O que é público da chave.
            "key.read",
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

    /// As três contenções reversíveis: sensíveis, nenhuma administrativa — o
    /// tecido as exerce pelo gate, sem prova, quando o papel dele as tem —,
    /// todas mudam o estado, e o recurso de cada uma é o papel do alvo.
    #[test]
    fn as_contencoes() {
        let nomes: alloc::vec::Vec<_> = TODAS
            .iter()
            .filter(|p| p.contencao())
            .map(|p| p.nome())
            .collect();
        assert_eq!(
            nomes,
            ["process.isolate", "agent.suspend", "credential.suspend"]
        );
        for p in TODAS.into_iter().filter(|p| p.contencao()) {
            assert!(
                p.sensivel() && !p.administrativa() && p.muda_estado(),
                "{}",
                p.nome()
            );
            assert!(p.recurso_e_papel() && p.tem_alcance() && !p.recurso_e_destino());
            assert!(!p.recurso_e_caminho() && !p.recurso_e_endereco());
        }
        // O papel como recurso: o destinatário de uma mensagem, as três e
        // o término de um processo.
        assert_eq!(TODAS.iter().filter(|p| p.recurso_e_papel()).count(), 5);
    }

    /// Encerrar um processo: sensível, não administrativa — quem a tem a
    /// exerce pelo gate —, muda o estado, e o recurso é o papel de quem
    /// responde pelo processo, como o do isolamento. Mas não é uma
    /// contenção: não tem inverso, e ter uma não dá a outra.
    #[test]
    fn encerrar_um_processo() {
        let t = Permissao::de_nome("process.terminate").unwrap();
        assert_eq!(t, Permissao::ProcessTerminate);
        assert!(t.sensivel() && !t.administrativa() && t.muda_estado());
        assert!(t.recurso_e_papel() && t.alvo_e_papel() && t.tem_alcance());
        assert!(!t.contencao() && !t.recurso_e_destino());
        assert!(!t.recurso_e_caminho() && !t.recurso_e_endereco() && !t.recurso_e_chave());
        // No fim da lista: a posição é o bit do manifesto, e as de antes
        // não mudam de lugar.
        assert_eq!(TODAS[46], t);
        // O alvo do pedido como recurso: as três contenções e esta — o
        // destinatário de uma mensagem é outra coisa.
        let alvos: alloc::vec::Vec<_> = TODAS
            .iter()
            .filter(|p| p.alvo_e_papel())
            .map(|p| p.nome())
            .collect();
        assert_eq!(
            alvos,
            [
                "process.isolate",
                "agent.suspend",
                "credential.suspend",
                "process.terminate"
            ]
        );
    }

    /// Reiniciar e desligar: sensível, não administrativa — o sistema a
    /// exerce pelo gate —, muda o estado, e sem recurso nenhum. Depois do
    /// término de um processo.
    #[test]
    fn reiniciar_e_desligar() {
        let e = Permissao::de_nome("system.power").unwrap();
        assert_eq!(e, Permissao::SystemPower);
        assert!(e.sensivel() && !e.administrativa() && e.muda_estado());
        assert!(!e.tem_alcance() && !e.alvo_e_papel() && !e.contencao());
        assert_eq!(TODAS[47], e);
    }

    /// A atualização: como o `system.power` — sensível, não
    /// administrativa, muda o estado, sem recurso —, depois dele: a
    /// posição é o bit do manifesto, e as que já existiam não se movem.
    #[test]
    fn atualizar() {
        let e = Permissao::de_nome("system.update").unwrap();
        assert_eq!(e, Permissao::SystemUpdate);
        assert!(e.sensivel() && !e.administrativa() && e.muda_estado());
        assert!(!e.tem_alcance() && !e.alvo_e_papel() && !e.contencao());
        assert_eq!(TODAS[48], e);
    }

    /// Trocar a própria senha: sensível — cada papel que a tem a escreve —,
    /// **não** administrativa — a pessoa a exerce pelo gate, sem prova de
    /// administrador —, muda o estado, e sem recurso nenhum: o alvo é a
    /// credencial da dona da sessão, e não algo que o papel enumere. Não é
    /// a de trocar a de outro, que continua administrativa. E no fim da
    /// lista: as de antes não mudam de bit.
    #[test]
    fn trocar_a_propria_senha() {
        let p = Permissao::de_nome("credential.change_self").unwrap();
        assert_eq!(p, Permissao::CredentialChangeSelf);
        assert!(p.sensivel() && !p.administrativa() && p.muda_estado());
        assert!(!p.tem_alcance() && !p.alvo_e_papel() && !p.contencao());
        assert!(!p.recurso_e_caminho() && !p.recurso_e_endereco() && !p.recurso_e_chave());
        assert!(!p.recurso_e_destino() && !p.recurso_e_papel());
        let de_outro = Permissao::CredentialRotate;
        assert_ne!(p, de_outro);
        assert!(de_outro.administrativa());
        assert_eq!(TODAS.last(), Some(&p));
        assert_eq!(Permissao::CredentialChangeSelf as usize, 49);
        for (i, p) in TODAS.into_iter().enumerate() {
            assert_eq!(p as usize, i, "{}", p.nome());
        }
        assert_eq!(Permissao::de_nome("credential.*"), None);
        assert_eq!(Permissao::de_nome("credential.change"), None);
        assert_eq!(Permissao::de_nome("credential.change_other"), None);
    }

    /// Conectar é sensível — não vem por inclusão: cada papel que disca
    /// escreve a permissão e os destinos —, não é administrativa, muda o
    /// estado, e é a única com o destino de rede como recurso.
    #[test]
    fn conectar() {
        let c = Permissao::de_nome("net.connect").unwrap();
        assert_eq!(c, Permissao::NetConnect);
        assert!(c.sensivel() && !c.administrativa() && c.muda_estado());
        assert!(c.recurso_e_endereco() && c.tem_alcance());
        assert!(!c.recurso_e_caminho() && !c.recurso_e_destino());
        // O `net.send` de antes continua o que era: sem alcance.
        assert!(!Permissao::NetSend.tem_alcance());
    }

    /// As três do destino de rede: conectar, observar e barrar. Todas
    /// sensíveis — cada papel as escreve, com os destinos —, nenhuma
    /// administrativa: o tecido de segurança as exerce pelo gate, sem
    /// prova. Só barrar muda o estado; observar é leitura, e ler o que o
    /// tecido viu também.
    #[test]
    fn as_do_destino_de_rede() {
        let destino: alloc::vec::Vec<_> = TODAS
            .iter()
            .filter(|p| p.recurso_e_endereco())
            .map(|p| p.nome())
            .collect();
        assert_eq!(destino, ["net.connect", "net.observe", "net.block"]);
        for nome in ["net.observe", "net.block", "security.read"] {
            let p = Permissao::de_nome(nome).unwrap();
            assert!(p.sensivel() && !p.administrativa(), "{nome}");
        }
        assert!(Permissao::NetBlock.muda_estado());
        assert!(!Permissao::NetObserve.muda_estado());
        assert!(!Permissao::SecurityRead.muda_estado() && !Permissao::SecurityRead.tem_alcance());
    }

    /// Esvaziar uma caixa é uma permissão própria, com nome próprio:
    /// administrativa, sensível — não vem por inclusão —, e muda o estado.
    #[test]
    fn esvaziar_a_caixa_e_outra_permissao() {
        let caixa = Permissao::de_nome("message.purge_mailbox").unwrap();
        assert_eq!(caixa, Permissao::MessagePurgeMailbox);
        assert_ne!(caixa, Permissao::MessagePurge);
        assert!(caixa.administrativa() && caixa.sensivel() && caixa.muda_estado());
        assert!(!caixa.tem_alcance());
    }

    /// Revogar um administrador é administrativo e sensível: só com quórum,
    /// e o papel que a tem a escreve.
    #[test]
    fn revogar_administrador() {
        let p = Permissao::de_nome("admin.revoke").unwrap();
        assert_eq!(p, Permissao::AdminRevoke);
        assert!(p.administrativa() && p.sensivel() && p.muda_estado() && !p.tem_alcance());
    }

    /// As do tempo. `time.sync` é sensível — não vem pela inclusão de outro
    /// papel: quem apresenta evidência de hora o escreve — e não é
    /// administrativa: o serviço de hora a exerce pelo gate, sem prova.
    /// `time.confirm` é administrativa e sensível: só com prova. As duas
    /// mudam o estado e nenhuma tem alcance próprio — as fontes são
    /// destinos de `net.connect`. E entram no fim: a posição é o bit do
    /// manifesto, e as de antes não mudam de bit.
    #[test]
    fn as_do_tempo() {
        let (sync, confirm) = (
            Permissao::de_nome("time.sync").unwrap(),
            Permissao::de_nome("time.confirm").unwrap(),
        );
        assert_eq!(
            (sync, confirm),
            (Permissao::TimeSync, Permissao::TimeConfirm)
        );
        assert!(sync.sensivel() && !sync.administrativa() && sync.muda_estado());
        assert!(confirm.sensivel() && confirm.administrativa() && confirm.muda_estado());
        for p in [sync, confirm] {
            assert!(!p.tem_alcance(), "{}", p.nome());
            assert!(!p.recurso_e_caminho() && !p.recurso_e_endereco() && !p.recurso_e_papel());
            assert!(!p.recurso_e_destino() && !p.contencao());
        }
        assert_eq!(TODAS[38], Permissao::TimeSync);
        assert_eq!(TODAS[39], Permissao::TimeConfirm);
        assert_eq!(TODAS[37], Permissao::RandomRead);
        assert_eq!(Permissao::de_nome("time.*"), None);
        assert_eq!(Permissao::de_nome("time"), None);
    }

    /// Declarar é sensível — o papel que declara a escreve —, não é
    /// administrativa — um programa a exerce pelo gate, com o manifesto —,
    /// não muda o estado e não tem alcance: o que se declara não é recurso
    /// de política. E entra no fim: as de antes não mudam de bit.
    #[test]
    fn declarar() {
        let p = Permissao::de_nome("audit.declare").unwrap();
        assert_eq!(p, Permissao::AuditDeclare);
        assert!(p.sensivel() && !p.administrativa() && !p.muda_estado());
        assert!(!p.tem_alcance() && !p.contencao());
        assert!(!p.recurso_e_caminho() && !p.recurso_e_endereco() && !p.recurso_e_papel());
        assert!(!p.recurso_e_destino());
        assert_eq!(TODAS[40], Permissao::AuditDeclare);
        assert_eq!(TODAS[39], Permissao::TimeConfirm);
        assert_eq!(Permissao::AuditDeclare as usize, 40);
        // A posição na lista é o número da variante: o bit do manifesto.
        for (i, p) in TODAS.into_iter().enumerate() {
            assert_eq!(p as usize, i, "{}", p.nome());
        }
        assert_eq!(Permissao::de_nome("audit.*"), None);
        assert_eq!(Permissao::de_nome("audit"), None);
    }

    /// As de chave: todas sensíveis — nenhuma vem pela inclusão de outro
    /// papel —; só anular é administrativa; criar, ler, assinar e destruir
    /// têm a chave como recurso, com alcance obrigatório; só ler não muda
    /// o estado. E entram no fim, nas posições 41 a 45: as de antes não
    /// mudam de bit.
    #[test]
    fn as_de_chave() {
        let nomes: alloc::vec::Vec<_> = TODAS
            .iter()
            .filter(|p| p.nome().starts_with("key."))
            .map(|p| p.nome())
            .collect();
        assert_eq!(
            nomes,
            [
                "key.create",
                "key.read",
                "key.sign",
                "key.destroy",
                "key.revoke"
            ]
        );
        for p in TODAS.into_iter().filter(|p| p.nome().starts_with("key.")) {
            assert!(p.sensivel(), "{}", p.nome());
            assert_eq!(
                p.administrativa(),
                p == Permissao::KeyRevoke,
                "{}",
                p.nome()
            );
            assert_eq!(
                p.recurso_e_chave(),
                p != Permissao::KeyRevoke,
                "{}",
                p.nome()
            );
            assert_eq!(p.tem_alcance(), p.recurso_e_chave(), "{}", p.nome());
            assert_eq!(p.muda_estado(), p != Permissao::KeyRead, "{}", p.nome());
            assert!(!p.recurso_e_caminho() && !p.recurso_e_endereco() && !p.recurso_e_papel());
            assert!(!p.recurso_e_destino() && !p.contencao());
        }
        // Só as quatro têm a chave como recurso.
        assert_eq!(TODAS.iter().filter(|p| p.recurso_e_chave()).count(), 4);
        assert_eq!(TODAS[40], Permissao::AuditDeclare);
        assert_eq!(TODAS[41], Permissao::KeyCreate);
        assert_eq!(TODAS[45], Permissao::KeyRevoke);
        assert_eq!(Permissao::KeyRevoke as usize, 45);
        for (i, p) in TODAS.into_iter().enumerate() {
            assert_eq!(p as usize, i, "{}", p.nome());
        }
        assert_eq!(Permissao::de_nome("key.*"), None);
        assert_eq!(Permissao::de_nome("key"), None);
        assert_eq!(Permissao::de_nome("key.export"), None);
        assert_eq!(Permissao::de_nome("key.import"), None);
    }
}
