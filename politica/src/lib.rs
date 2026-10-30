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
//! - [`explicacao`]: o que uma recusa quer dizer para quem pediu — a razão,
//!   se adianta repetir, o que fazer, e a frase para uma pessoa. Lê a
//!   decisão; não decide.
//! - [`procedencia`]: por que um código de fora da imagem não roda — sem
//!   selo, o selo que não confere, o editor desconhecido ou em que o papel
//!   não confia —, com o motivo da auditoria e o código da resposta.

#![no_std]

extern crate alloc;

pub mod arquivo;
pub mod arrendamento;
pub mod auditoria;
pub mod caminho;
pub mod codigo;
pub mod endereco;
pub mod explicacao;
pub mod malha;
pub mod manifesto;
pub mod mensagens;
pub mod permissao;
pub mod procedencia;
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
///   gravável, e a linha a concede por escrito, como qualquer outra. A
///   restauração (`fs.restore`) também: o armazém inteiro.
/// - `administrador` é o **teto** do que um administrador delega: as
///   permissões comuns dele não se exercem — uma chave de administrador não
///   abre sessão de agente —, e dizem só o que ele pode conceder. Escritas
///   uma a uma, sem incluir o operador: um papel incluído que muda muda o
///   do administrador, e o do administrador não muda em tempo de execução.
///   O `fs.write` dele é o do operador, `/armazem/compartilhado`: o teto
///   tem de conter o que o operador recebe, para o operador ser delegável.
///   O `fs.restore`, pelo mesmo motivo, também.
/// - `net.connect`, nos dois, alcança os sete destinos da bancada, sem
///   porta aberta no hospedeiro: o eco TCP, em `10.0.2.100:7` (um
///   `guestfwd` que roda um `cat` a cada conexão), o eco TLS, em
///   `10.0.2.100:443` (um `guestfwd` que roda, a cada conexão, o servidor
///   TLS da bancada — o OpenSSL, pelo Python), o TFTP do emulador, em
///   `10.0.2.2:69` (UDP), o DNS do emulador, em `10.0.2.3:53` (UDP), o
///   servidor HTTP da bancada, claro em `10.0.2.100:80` e atrás do TLS em
///   `10.0.2.100:8443`, e o gateway HTTPS da bancada, em `10.0.2.100:4943`.
///   Enumerados, como todo destino: a imagem de desenvolvimento não disca
///   nada que não esteja escrito, nem o sistema. O nome que o servidor TLS
///   apresenta não é recurso: o eco TLS serve vários nomes no mesmo
///   destino, e o gate decide o destino. Do HTTP, também não: o método, o
///   caminho, o `Host` e o status são do protocolo, e o gate decide o
///   destino. Nem do que se fala atrás do gateway: o protocolo é do
///   programa, e o gate decide o destino.
/// - `audit.declare` — declarar um fato do programa para a auditoria: uma
///   alegação, gravada com os fatos do kernel, que nenhuma decisão lê —
///   no `sistema`, no `administrador` e no `operador`, que conecta; não no
///   `observador`, nem no tecido de segurança, que só observam.
/// - `credential.change_self` — a pessoa troca a própria senha, provando a
///   atual — no `administrador`, o teto, para que o `observador` e o
///   `operador`, que a têm na padrão, sejam delegáveis; o teto não se
///   exerce, e nenhuma pessoa tem o papel dele. Não no `sistema`: ele não
///   é uma pessoa, não tem senha, e a autoridade máxima não ganha por isso
///   um curinga sobre a credencial de ninguém.
/// - `random.read` — os bytes do gerador do kernel — no `sistema`, no
///   `administrador` e no `operador`, que conecta; não no `observador`, que
///   não conecta a nada.
/// - As fontes de hora da bancada — `udp:10.0.2.2:5319`, `udp:10.0.2.2:5320`
///   e `udp:10.0.2.2:5321`, as do registro de fontes, `/etc/duke/tempo` —
///   estão no `net.connect` e no `net.block` dos dois, além dos sete
///   destinos acima: o `sistema` porque é o máximo enumerado, e o
///   `administrador` para que o papel `tempo` caiba no teto de quem o
///   delega, e para que ele possa cortar uma fonte. O `seguranca` não as
///   barra: o tecido não corta fonte de hora — quem forja respostas ruins
///   não faz o tecido cortar a fonte legítima.
/// - `time.sync` — apresentar evidência de hora — no `sistema`, que é o
///   máximo enumerado, e no `administrador`; `time.confirm` — aplicar o
///   salto pendente —, administrativa, só no `administrador`. Nenhum dos
///   dois é curinga: o `tempo` não inclui o `sistema`, e a linha `servico`
///   não pode dar ao serviço o papel da serial nem o da autoridade local.
/// - `process.isolate`, `agent.suspend` e `credential.suspend`, no `sistema` e
///   no `administrador`, alcançam `observador`, `operador` e `sistema` —
///   nunca `administrador`: suspender um administrador seria tirar dele,
///   sem quórum, o que a revogação só tira com quórum.
/// - `process.terminate` — encerrar um processo, sem volta —, no `sistema`
///   e no `administrador`, com o mesmo alcance do isolamento: `observador`,
///   `operador` e `sistema`, nunca `administrador`. O `seguranca` não a tem:
///   o tecido só contém, de forma reversível, e não mata nada.
/// - `system.power` — reiniciar e desligar a máquina —, no `sistema`, que a
///   exerce pelo gate como o `debug.trigger`, e no `administrador`, pela
///   prova. Ninguém mais: nem o `operador`, nem o tecido de segurança.
/// - `quorum admin.revoke 2 3`: revogar a credencial de um administrador
///   exige a prova de duas outras, de um grupo de três — o da imagem.
/// - `system.update` — escrever a versão nova no slot inativo da
///   atualização A/B —, no `sistema`, pelo gate, e no `administrador`, para
///   o papel de cada credencial que assina a instalação; e `quorum
///   system.update 2 3`: instalar uma versão nova, ou desistir dela, exige
///   duas credenciais do grupo de três. Escrever não instala: só o quórum
///   arma — ver `docs/ATUALIZACAO.md`.
/// - `editores`: o `sistema` e o `administrador` confiam no editor
///   `bancada`, o da imagem de desenvolvimento — ver `sigilo::codigo` e o
///   registro de editores, `/etc/duke/editores`. O código de fora da
///   imagem roda só com o selo dele; o `administrador` precisa confiar para
///   poder delegar a confiança, e alcança com `process.run` o diretório do
///   código instalado, `/armazem/compartilhado/codigo`, para que o
///   operador seja delegável.
/// - `seguranca` é o papel do tecido de segurança — o serviço `nsf`, pela
///   linha `servico` (ver `docs/SEGURANCA.md`): lê a auditoria, observa o
///   DNS da bancada, barra os destinos da bancada e isola processos de
///   `observador` e de `operador` — a contenção reversível mais estreita;
///   suspender um agente ou uma credencial ele só recomenda (ver
///   `docs/USABILIDADE.md`). Nada além: não conecta,
///   não lança, não lê arquivo, não muda a política, e não é o `sistema`.
///   Está nas duas políticas: sem política no disco, o tecido continua
///   vendo — e continua só com isto. O `sistema` e o `administrador` têm
///   `security.read`, `net.observe` e `net.block` escritas nas linhas
///   deles, com o alcance enumerado: o `sistema` porque é o máximo
///   enumerado, e o `administrador` para que as três do papel `seguranca`
///   caibam no teto de quem as delega.
/// - As de chave (`key.*`) **não** estão no `sistema`, em nenhuma das duas:
///   uma chave de assinatura é da identidade durável de quem a cria — a
///   pessoa, o agente —, e o sistema é o máximo sobre a máquina, não o
///   dono das chaves de alguém; nem há chave global do sistema. O teto do
///   `administrador` as tem só na padrão — os dois parâmetros da macro:
///   as permissões e o alcance —, para que o operador seja delegável, e
///   `key.revoke`, para anular com prova a chave de outra identidade; o
///   teto não se exerce, e anular não dá o uso de nada. Na de emergência,
///   nenhuma: sem política no disco, ninguém cria, usa nem delega chave —
///   a revogação de uma pessoa ou de um agente ainda anula as dele.
macro_rules! papeis_de_sistema {
    ($chaves_do_administrador:literal, $alcance_das_chaves_do_administrador:literal) => {
        concat!(
            "\
papel sistema agent.read system.read log.read ui.read ui.act process.run net.send net.connect fs.read fs.write fs.restore fs.raw_read keyboard.read debug.trigger terminal.attach audit.read policy.read message.send message.read security.read net.observe net.block process.isolate agent.suspend credential.suspend random.read time.sync audit.declare process.terminate system.power system.update fabric.offer fabric.send
recurso sistema fs.read /
recurso sistema fs.write /armazem
recurso sistema fs.restore /armazem
recurso sistema net.connect tcp:10.0.2.100:7 tcp:10.0.2.100:443 udp:10.0.2.2:69 udp:10.0.2.3:53 tcp:10.0.2.100:80 tcp:10.0.2.100:8443 tcp:10.0.2.100:4943 udp:10.0.2.2:5319 udp:10.0.2.2:5320 udp:10.0.2.2:5321
recurso sistema net.observe udp:10.0.2.3:53
recurso sistema net.block tcp:10.0.2.100:7 tcp:10.0.2.100:443 udp:10.0.2.2:69 udp:10.0.2.3:53 tcp:10.0.2.100:80 tcp:10.0.2.100:8443 tcp:10.0.2.100:4943 udp:10.0.2.2:5319 udp:10.0.2.2:5320 udp:10.0.2.2:5321
armazem sistema 268435456 65536
recurso sistema process.run /
editores sistema bancada
recurso sistema message.send papel:observador papel:operador papel:sistema papel:administrador
recurso sistema process.isolate papel:observador papel:operador papel:sistema
recurso sistema agent.suspend papel:observador papel:operador papel:sistema
recurso sistema credential.suspend papel:observador papel:operador papel:sistema
recurso sistema process.terminate papel:observador papel:operador papel:sistema
recurso sistema fabric.offer intencao:imagem.compartilhar intencao:pdf.anotar
recurso sistema fabric.send intencao:imagem.compartilhar intencao:pdf.anotar
taxa sistema 400 800
processos sistema 32

papel administrador agent.read system.read log.read ui.read ui.act process.run net.send net.connect fs.read fs.write fs.restore audit.read policy.read agent.register agent.revoke policy.assign policy.write person.register person.revoke credential.rotate session.revoke lease.revoke message.send message.read message.purge message.purge_mailbox admin.revoke security.read net.observe net.block process.isolate agent.suspend credential.suspend random.read time.sync time.confirm audit.declare process.terminate system.power system.update credential.change_self fabric.offer fabric.send",
            $chaves_do_administrador,
            "
recurso administrador fs.read /dados /bin /programas /armazem/compartilhado
recurso administrador fs.write /armazem/compartilhado
recurso administrador fs.restore /armazem/compartilhado
recurso administrador net.connect tcp:10.0.2.100:7 tcp:10.0.2.100:443 udp:10.0.2.2:69 udp:10.0.2.3:53 tcp:10.0.2.100:80 tcp:10.0.2.100:8443 tcp:10.0.2.100:4943 udp:10.0.2.2:5319 udp:10.0.2.2:5320 udp:10.0.2.2:5321
recurso administrador net.observe udp:10.0.2.3:53
recurso administrador net.block tcp:10.0.2.100:7 tcp:10.0.2.100:443 udp:10.0.2.2:69 udp:10.0.2.3:53 tcp:10.0.2.100:80 tcp:10.0.2.100:8443 tcp:10.0.2.100:4943 udp:10.0.2.2:5319 udp:10.0.2.2:5320 udp:10.0.2.2:5321
armazem administrador 67108864 16384
recurso administrador process.run /bin /programas /armazem/compartilhado/codigo
editores administrador bancada
recurso administrador message.send papel:operador papel:sistema papel:administrador
recurso administrador process.isolate papel:observador papel:operador papel:sistema
recurso administrador agent.suspend papel:observador papel:operador papel:sistema
recurso administrador credential.suspend papel:observador papel:operador papel:sistema
recurso administrador process.terminate papel:observador papel:operador papel:sistema
recurso administrador fabric.offer intencao:imagem.compartilhar intencao:pdf.anotar
recurso administrador fabric.send intencao:imagem.compartilhar intencao:pdf.anotar
taxa administrador 10 20
processos administrador 8
",
            $alcance_das_chaves_do_administrador,
            "
quorum admin.revoke 2 3
quorum system.update 2 3

papel seguranca audit.read net.observe net.block process.isolate
recurso seguranca net.observe udp:10.0.2.3:53
recurso seguranca net.block tcp:10.0.2.100:7 tcp:10.0.2.100:443 udp:10.0.2.2:69 udp:10.0.2.3:53 tcp:10.0.2.100:80 tcp:10.0.2.100:8443 tcp:10.0.2.100:4943
recurso seguranca process.isolate papel:observador papel:operador
taxa seguranca 10 20
servico nsf seguranca
"
        )
    };
}

/// A política padrão da imagem de desenvolvimento.
///
/// Mora aqui, e não no `xtask`, para que o texto que vai para o disco seja
/// o mesmo que os testes deste pacote leem e conferem.
///
/// - `observador` observa o estado do sistema e a tela; não lê arquivos;
///   troca a própria senha (`credential.change_self`), como o `operador`
///   — cada um a escreve: ela é sensível, e não vem pela inclusão;
/// - `operador` observa e age: a tela, programas de `/bin` e
///   `/programas`, arquivos de `/dados`, `/bin` e `/programas`; lê e
///   escreve no armazém compartilhado, `/armazem/compartilhado`, e o
///   restaura de uma cópia desta máquina (`fs.restore`); roda o
///   código instalado em `/armazem/compartilhado/codigo` — só o selado
///   pelo editor `bancada`, em que ele confia —; e cria, lê, assina e
///   destrói as chaves `chave:bancada` e `chave:bancada-2` da própria
///   identidade, só no domínio `ic-request` do registro de domínios; e,
///   na malha, oferece e procura as intenções `imagem.compartilhar` e
///   `pdf.anotar` (`fabric.offer`, `fabric.send`), entre os programas dele;
/// - `tempo` é o papel do serviço de hora — a linha `servico hora tempo`:
///   apresenta evidência de hora (`time.sync`) e conecta às três fontes do
///   registro de fontes, `/etc/duke/tempo`, cada uma escrita por inteiro,
///   UDP. Nada mais: não lê nem escreve arquivo, não lança, não manda
///   mensagem, não confirma salto, e não é o `sistema`. Só nesta política:
///   a de emergência não tem a linha `servico hora`, e sem política no
///   disco o serviço de hora não tem papel — o relógio civil fica no RTC,
///   como era antes dele;
/// - `sistema` e `administrador`: ver `papeis_de_sistema`.
pub const PADRAO: &str = concat!(
    "\
# A politica do Duke: papeis, permissoes, recursos e taxas.
#
# Uma permissao sensivel (fs.*, net.connect, keyboard.read, debug.trigger,
# terminal.attach, policy.*, agent.register, agent.revoke, person.*,
# credential.rotate, session.revoke, lease.revoke, message.*, as contencoes
# process.isolate, agent.suspend e credential.suspend, process.terminate,
# system.power, system.update, time.*, audit.declare, key.* e
# credential.change_self) nao atravessa a inclusao de
# outro papel: cada
# papel que a tem a escreve. Toda permissao
# de caminho, o message.send, o net.connect e as de chave tem o alcance
# escrito numa linha `recurso` — o de message.send e o papel do
# destinatario, `papel:<nome>`, o de net.connect cada destino inteiro,
# `tcp:<ipv4>:<porta>` ou `udp:<ipv4>:<porta>`, e o de key.* cada nome de
# chave, `chave:<nome>`, todos enumerados. Nao ha curinga. Os unicos destinos desta imagem sao os da bancada: o eco TCP em
# 10.0.2.100:7, o eco TLS em 10.0.2.100:443, o TFTP do emulador, UDP, em
# 10.0.2.2:69, o DNS do emulador, UDP, em 10.0.2.3:53, o HTTP da bancada
# em 10.0.2.100:80 e, atras do TLS, em 10.0.2.100:8443, e o gateway HTTPS da
# bancada em 10.0.2.100:4943. O nome de um servidor TLS nao e recurso, nem
# o caminho, o metodo ou o Host de um pedido HTTP, nem o protocolo que se
# fala atras do gateway: o que se enumera e o destino. O random.read
# (bytes do gerador do kernel, para a chave efemera do TLS) e de quem
# conecta, e o audit.declare tambem: declarar um fato do programa para a
# auditoria, uma alegacao que o kernel grava com os fatos dele e que
# nenhuma decisao le. So o sistema e o proprio administrador
# alcancam o administrador: nenhum policy.write da esse alcance a outro
# papel. O tecido de seguranca (servico nsf) decide pelo papel seguranca, e
# so pelo que ele enumera. O codigo de fora da imagem (o instalado no
# armazem, o que chegou pela rede) so roda com o selo de um editor em que
# o papel de quem o lanca confia: a linha `editores`. Nesta imagem, o
# editor `bancada`, do registro de editores (/etc/duke/editores). O servico
# de hora (servico hora) decide pelo papel tempo: so apresenta evidencia de
# hora (time.sync) e so fala com as fontes do registro de fontes
# (/etc/duke/tempo), UDP em 10.0.2.2:5319, 10.0.2.2:5320 e 10.0.2.2:5321 —
# cada fonte do registro tem o destino dela aqui, e o xtask confere. A hora
# nao se escolhe: so o acordo de pelo menos duas chaves a move, e o salto
# que fica pendente so o administrador confirma, com prova (time.confirm).
# As chaves de assinatura (key.*) sao da identidade duravel de quem as cria
# — a pessoa, o agente —, nunca do sistema, e a privada nunca sai do
# kernel: o operador cria, le, assina e destroi as chaves chave:bancada e
# chave:bancada-2 da propria identidade — o nome se resolve no espaco de
# quem pede —, e assina so no dominio ic-request do registro de dominios
# (/etc/duke/dominios), a linha `dominios`. O sistema nao tem nenhuma de
# chave. O administrador anula a chave de outra identidade com prova
# (key.revoke), sem poder usa-la. A pessoa troca a propria senha
# (credential.change_self), provando a atual: o observador e o operador, e
# so a da propria sessao. O sistema nao tem: nao e pessoa. Trocar a senha
# de outra pessoa continua sendo credential.rotate, com prova. Restaurar
# uma subarvore do armazem de uma copia desta maquina (fs.restore) e uma
# permissao propria, de caminho: o sistema no armazem inteiro, o operador no
# compartilhado. A copia e uma leitura (fs.read), e sai cifrada para esta
# maquina. Na malha, um programa oferece uma intencao (fabric.offer) e outro
# do mesmo titular a procura e entrega a ele (fabric.send): as intencoes
# enumeradas, inteiras, imagem.compartilhar e pdf.anotar, para o operador,
# o sistema e o teto do administrador. Nenhuma das duas da acesso a nada do
# outro lado.

papel observador agent.read system.read log.read ui.read message.read credential.change_self
taxa observador 20 40
processos observador 2

papel operador @observador ui.act process.run net.send net.connect fs.read fs.write fs.restore message.send message.read random.read audit.declare key.create key.read key.sign key.destroy credential.change_self fabric.offer fabric.send
recurso operador fs.read /dados /bin /programas /armazem/compartilhado
recurso operador fs.write /armazem/compartilhado
recurso operador fs.restore /armazem/compartilhado
recurso operador net.connect tcp:10.0.2.100:7 tcp:10.0.2.100:443 udp:10.0.2.2:69 udp:10.0.2.3:53 tcp:10.0.2.100:80 tcp:10.0.2.100:8443 tcp:10.0.2.100:4943
armazem operador 16777216 4096
recurso operador process.run /bin /programas /armazem/compartilhado/codigo
editores operador bancada
recurso operador message.send papel:operador papel:sistema
recurso operador key.create chave:bancada chave:bancada-2
recurso operador key.read chave:bancada chave:bancada-2
recurso operador key.sign chave:bancada chave:bancada-2
recurso operador key.destroy chave:bancada chave:bancada-2
dominios operador ic-request
recurso operador fabric.offer intencao:imagem.compartilhar intencao:pdf.anotar
recurso operador fabric.send intencao:imagem.compartilhar intencao:pdf.anotar
taxa operador 50 100
processos operador 8

papel tempo net.connect time.sync
recurso tempo net.connect udp:10.0.2.2:5319 udp:10.0.2.2:5320 udp:10.0.2.2:5321
taxa tempo 10 20
servico hora tempo

",
    papeis_de_sistema!(
        " key.create key.read key.sign key.destroy key.revoke",
        "recurso administrador key.create chave:bancada chave:bancada-2
recurso administrador key.read chave:bancada chave:bancada-2
recurso administrador key.sign chave:bancada chave:bancada-2
recurso administrador key.destroy chave:bancada chave:bancada-2
dominios administrador ic-request
"
    ),
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
/// mesmo, menos as de chave, para quem tem a prova recuperar a política em
/// memória com `policy.write`. Os outros papéis não estão aqui: um agente
/// de papel `operador` ou `observador` é recusado; um de papel `sistema`
/// continua o que era — ninguém ganha nem perde papel na emergência. E
/// nenhum papel tem permissão de chave: sem política no disco, nenhuma
/// chave se cria nem assina.
pub const EMERGENCIA: &str = concat!(
    "\
# A politica de emergencia, embutida no kernel.

",
    papeis_de_sistema!("", ""),
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
        // O código instalado: o operador e o administrador rodam o que está
        // no diretório dele — e só lá, no armazém —; o observador nada. Quem
        // selou é outra pergunta, a dos editores.
        for papel in ["operador", "administrador"] {
            assert_eq!(
                d(papel, ProcessRun, Some("/armazem/compartilhado/codigo/x")),
                Codigo::Allow
            );
            for fora in [
                "/armazem/compartilhado/x",
                "/armazem/compartilhado/codigox",
                "/armazem/x",
            ] {
                assert_eq!(
                    d(papel, ProcessRun, Some(fora)),
                    Codigo::DenyResource,
                    "{papel} {fora}"
                );
            }
        }
        assert_eq!(
            d(
                "observador",
                ProcessRun,
                Some("/armazem/compartilhado/codigo/x")
            ),
            Codigo::DenyPermission
        );
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
            for dentro in [
                "tcp:10.0.2.100:7",
                "tcp:10.0.2.100:443",
                "udp:10.0.2.2:69",
                "udp:10.0.2.3:53",
                "tcp:10.0.2.100:80",
                "tcp:10.0.2.100:8443",
                "tcp:10.0.2.100:4943",
            ] {
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
                "tcp:10.0.2.100:81",
                "tcp:10.0.2.100:8444",
                "tcp:10.0.2.100:4944",
                "udp:10.0.2.100:4943",
                "udp:10.0.2.100:80",
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
        // O tempo: apresentar evidência de hora, o papel do serviço de hora,
        // o sistema e o teto do administrador; confirmar o salto pendente,
        // só o administrador. O observador, o operador e o tecido de
        // segurança, nenhuma das duas.
        for (papel, sync, confirm) in [
            ("observador", Codigo::DenyPermission, Codigo::DenyPermission),
            ("operador", Codigo::DenyPermission, Codigo::DenyPermission),
            ("seguranca", Codigo::DenyPermission, Codigo::DenyPermission),
            ("tempo", Codigo::Allow, Codigo::DenyPermission),
            ("sistema", Codigo::Allow, Codigo::DenyPermission),
            ("administrador", Codigo::Allow, Codigo::Allow),
        ] {
            assert_eq!(d(papel, TimeSync, None), sync, "{papel}");
            assert_eq!(d(papel, TimeConfirm, None), confirm, "{papel}");
            // O recurso não muda nada: as duas não têm alcance.
            assert_eq!(d(papel, TimeSync, Some("udp:10.0.2.2:5319")), sync);
        }
        // As fontes de hora: o tempo, o sistema e o administrador conectam;
        // o operador e o observador não — elas não estão no alcance deles.
        for fonte in FONTES {
            for papel in ["tempo", "sistema", "administrador"] {
                assert_eq!(d(papel, NetConnect, Some(fonte)), Codigo::Allow, "{papel}");
            }
            assert_eq!(d("operador", NetConnect, Some(fonte)), Codigo::DenyResource);
            assert_eq!(
                d("observador", NetConnect, Some(fonte)),
                Codigo::DenyPermission
            );
        }
        // As chaves: o operador cria, lê, assina e destrói as dele, pelo
        // nome enumerado; o observador, o tecido de segurança, o serviço de
        // hora e o sistema, nenhuma — não há chave do sistema. O teto do
        // administrador as tem para delegar (o gate não deixa o teto se
        // exercer); anular é administrativa, só dele.
        for perm in [KeyCreate, KeyRead, KeySign, KeyDestroy] {
            for (papel, esperado) in [
                ("operador", Codigo::Allow),
                ("administrador", Codigo::Allow),
                ("observador", Codigo::DenyPermission),
                ("seguranca", Codigo::DenyPermission),
                ("tempo", Codigo::DenyPermission),
                ("sistema", Codigo::DenyPermission),
            ] {
                assert_eq!(
                    d(papel, perm, Some("chave:bancada")),
                    esperado,
                    "{papel} {}",
                    perm.nome()
                );
            }
            assert_eq!(
                d("operador", perm, Some("chave:outra")),
                Codigo::DenyResource
            );
        }
        for (papel, esperado) in [
            ("administrador", Codigo::Allow),
            ("operador", Codigo::DenyPermission),
            ("sistema", Codigo::DenyPermission),
        ] {
            assert_eq!(d(papel, KeyRevoke, None), esperado, "{papel}");
        }
        assert_eq!(p.decidir(None, AgentRead, None), Codigo::DenyRole);
        assert_eq!(
            p.decidir(Some("fantasma"), AgentRead, None),
            Codigo::DenyRole
        );
        assert_eq!(p.serial(), "sistema");
        assert_eq!(p.local(), "sistema");
    }

    /// A emergência não tem chave nenhuma: nenhum papel cria, lê, assina,
    /// destrói nem anula — nem o teto do administrador —, e nenhum usa
    /// domínio.
    #[test]
    fn a_emergencia_nao_tem_chave() {
        let e = Politica::emergencia();
        for papel in e.papeis() {
            for perm in permissao::TODAS
                .into_iter()
                .filter(|q| q.nome().starts_with("key."))
            {
                assert!(!papel.tem(perm), "{} {}", papel.nome, perm.nome());
                assert_eq!(
                    e.decidir(Some(&papel.nome), perm, Some("chave:bancada")),
                    Codigo::DenyPermission
                );
            }
            assert!(papel.dominios.is_empty(), "{}", papel.nome);
        }
        assert!(!EMERGENCIA.contains("key."));
        assert!(!EMERGENCIA.contains("dominios"));
        // E fora as de chave, o administrador da emergência é o da padrão.
        let p = padrao();
        let (a, b) = (
            p.papel("administrador").unwrap(),
            e.papel("administrador").unwrap(),
        );
        let fora_as_de_chave = |x: &Papel| {
            x.permissoes()
                .filter(|q| !q.nome().starts_with("key."))
                .collect::<alloc::vec::Vec<_>>()
        };
        assert_eq!(fora_as_de_chave(a), fora_as_de_chave(b));
        assert_eq!(p.papel("sistema"), e.papel("sistema"));
    }

    /// O sistema é a autoridade máxima, e enumerada: tem cada permissão que
    /// não é administrativa, nem a escrita bruta, nem da identidade de
    /// alguém — sem incluir papel nenhum, sem curinga —, e cada uma de
    /// caminho com o alcance escrito: `/` para ler e executar, e só o
    /// armazém para escrever. As de chave não: a chave é da identidade de
    /// quem a cria, e não há chave do sistema. A da própria senha também
    /// não: o sistema não é pessoa, e a autoridade máxima não vira um
    /// curinga sobre a credencial de ninguém.
    #[test]
    fn o_sistema_e_maximo_e_enumerado() {
        let p = padrao();
        let sistema = p.papel("sistema").unwrap();
        assert!(sistema.inclui.is_empty(), "o sistema inclui outro papel");
        for perm in permissao::TODAS {
            let de_identidade = perm.recurso_e_chave()
                || perm == Permissao::KeyRevoke
                || perm == Permissao::CredentialChangeSelf;
            let esperado =
                !perm.administrativa() && perm != Permissao::FsRawWrite && !de_identidade;
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
                    &[
                        "tcp:10.0.2.100:7",
                        "tcp:10.0.2.100:443",
                        "udp:10.0.2.2:69",
                        "udp:10.0.2.3:53",
                        "tcp:10.0.2.100:80",
                        "tcp:10.0.2.100:8443",
                        "tcp:10.0.2.100:4943",
                        FONTES[0],
                        FONTES[1],
                        FONTES[2],
                    ]
                };
                assert_eq!(
                    sistema.recursos.get(&perm).unwrap(),
                    alcance,
                    "{}",
                    perm.nome()
                );
            }
            if esperado && perm.recurso_e_caminho() {
                let alcance = if matches!(perm, Permissao::FsWrite | Permissao::FsRestore) {
                    "/armazem"
                } else {
                    "/"
                };
                assert_eq!(sistema.recursos.get(&perm).unwrap(), &[alcance.to_string()]);
            }
        }
        // Nenhum outro papel da padrão alcança mais que ele — fora o que é
        // da identidade de cada um: as chaves do operador e a própria senha
        // do observador e do operador, que o sistema não tem de propósito.
        assert!(p.cabe_em("tempo", "sistema").is_ok());
        let r = p.cabe_em("observador", "sistema");
        assert!(
            matches!(&r, Err(Recusa::Proibida(m)) if m.contains("credential.change_self")),
            "{r:?}"
        );
        let r = p.cabe_em("operador", "sistema");
        assert!(
            matches!(&r, Err(Recusa::Proibida(m)) if m.contains("key.") || m.contains("dominio") || m.contains("credential.change_self")),
            "{r:?}"
        );
        // Sem as de chave e sem a da própria senha, os dois cabem no
        // sistema.
        let sem_identidade: alloc::string::String = PADRAO
            .lines()
            .filter(|l| {
                !l.starts_with("recurso operador key.") && !l.starts_with("dominios operador")
            })
            .map(|l| {
                if l.starts_with("papel operador ") || l.starts_with("papel observador ") {
                    let l = l
                        .replace(" key.create key.read key.sign key.destroy", "")
                        .replace(" credential.change_self", "");
                    alloc::format!("{l}\n")
                } else {
                    alloc::format!("{l}\n")
                }
            })
            .collect();
        let q = Politica::ler(&sem_identidade).unwrap();
        assert!(!q.papel("operador").unwrap().tem(Permissao::KeySign));
        assert!(
            !q.papel("observador")
                .unwrap()
                .tem(Permissao::CredentialChangeSelf)
        );
        assert!(q.cabe_em("observador", "sistema").is_ok());
        assert!(q.cabe_em("operador", "sistema").is_ok());
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
            mudar("papel operador @observador ui.act process.run net.send net.connect fs.read fs.write fs.restore message.send message.read key.create key.read key.sign key.destroy fabric.offer fabric.send audit.read")
                .unwrap();
        assert!(nova.papel("operador").unwrap().tem(Permissao::AuditRead));
        // O que ele não tem: não.
        assert!(matches!(
            mudar(
                "papel operador @observador ui.act process.run net.send net.connect fs.read fs.write fs.restore message.send message.read key.create key.read key.sign key.destroy fabric.offer fabric.send keyboard.read"
            ),
            Err(Recusa::Proibida(_))
        ));
        // Tirar net.connect e deixar a linha do alcance dela: a política
        // que resultaria não vale — um alcance para o que o papel não tem.
        assert!(matches!(
            mudar(
                "papel operador @observador ui.act process.run net.send fs.read fs.write fs.restore message.send message.read key.create key.read key.sign key.destroy"
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
        // O administrador é o mesmo, menos as de chave — ver
        // `a_emergencia_nao_tem_chave`.
        let mut sem_chaves = p.papel("administrador").unwrap().clone();
        sem_chaves.diretas.retain(|q| !q.nome().starts_with("key."));
        sem_chaves
            .recursos
            .retain(|q, _| !q.nome().starts_with("key."));
        sem_chaves.dominios.clear();
        let adm = e.papel("administrador").unwrap();
        assert_eq!(adm.diretas, sem_chaves.diretas);
        assert_eq!(adm.recursos, sem_chaves.recursos);
        assert_eq!(adm.dominios, sem_chaves.dominios);
        assert_eq!(
            (adm.taxa, adm.processos, adm.armazem, &adm.editores),
            (
                sem_chaves.taxa,
                sem_chaves.processos,
                sem_chaves.armazem,
                &sem_chaves.editores
            )
        );
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
    /// decide pelo papel `seguranca`, que enumera quatro permissões e o
    /// alcance de cada uma — nas duas políticas embutidas. Nada além: nem
    /// conectar, nem ler arquivo, nem lançar, nem ler o que ele mesmo viu;
    /// e das contenções, só a mais estreita — isolar o processo de quem é
    /// `observador` ou `operador` —, nunca a de um agente ou de uma
    /// credencial.
    #[test]
    fn o_servico_decide_pelo_papel_dele() {
        use Permissao::*;
        for p in [padrao(), Politica::emergencia()] {
            assert_eq!(p.servico("nsf"), Some("seguranca"));
            assert_eq!(p.servico("outro"), None);
            let papel = p.papel("seguranca").unwrap();
            let todas: alloc::vec::Vec<_> = papel.permissoes().map(|x| x.nome()).collect();
            assert_eq!(
                todas,
                ["audit.read", "net.observe", "net.block", "process.isolate"]
            );
            let d = |perm, rec| p.decidir(Some("seguranca"), perm, rec);
            assert_eq!(d(AuditRead, None), Codigo::Allow);
            assert_eq!(d(NetObserve, Some("udp:10.0.2.3:53")), Codigo::Allow);
            assert_eq!(d(NetObserve, Some("udp:10.0.2.2:69")), Codigo::DenyResource);
            for dentro in [
                "tcp:10.0.2.100:7",
                "tcp:10.0.2.100:443",
                "udp:10.0.2.2:69",
                "udp:10.0.2.3:53",
                "tcp:10.0.2.100:80",
                "tcp:10.0.2.100:8443",
                "tcp:10.0.2.100:4943",
            ] {
                assert_eq!(d(NetBlock, Some(dentro)), Codigo::Allow, "{dentro}");
            }
            for fora in ["tcp:10.0.2.100:8", "udp:10.0.2.99:53", ""] {
                assert_eq!(d(NetBlock, Some(fora)), Codigo::DenyResource, "{fora}");
            }
            // As fontes de hora não: o tecido não corta fonte de hora — quem
            // forja respostas ruins não o faz cortar a legítima.
            for fonte in FONTES {
                assert_eq!(d(NetBlock, Some(fonte)), Codigo::DenyResource, "{fonte}");
            }
            // Na de emergência não há observador nem operador: o tecido não
            // alcança ninguém — o papel do alvo precisa existir.
            let esperado = if p.papel("operador").is_some() {
                Codigo::Allow
            } else {
                Codigo::DenyResource
            };
            for dentro in ["papel:observador", "papel:operador"] {
                assert_eq!(d(ProcessIsolate, Some(dentro)), esperado, "{dentro}");
            }
            for fora in [
                "papel:sistema",
                "papel:administrador",
                "papel:seguranca",
                "",
            ] {
                assert_eq!(
                    d(ProcessIsolate, Some(fora)),
                    Codigo::DenyResource,
                    "{fora}"
                );
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
                AgentSuspend,
                CredentialSuspend,
                RandomRead,
                TimeSync,
                TimeConfirm,
                AuditDeclare,
                ProcessTerminate,
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

    /// Encerrar um processo: o `sistema` e o `administrador`, com o alcance
    /// do isolamento — `observador`, `operador` e `sistema`, nunca o
    /// `administrador` —, nas duas políticas embutidas; ninguém mais.
    /// Nenhum papel a ganha pela inclusão de outro.
    #[test]
    fn quem_encerra_um_processo() {
        use Permissao::ProcessTerminate;
        for p in [padrao(), Politica::emergencia()] {
            for papel in ["sistema", "administrador"] {
                let d = |rec| p.decidir(Some(papel), ProcessTerminate, rec);
                // Na de emergência não há observador nem operador: o papel do
                // alvo precisa existir para ser alcançado.
                for dentro in ["papel:observador", "papel:operador", "papel:sistema"] {
                    let esperado = if p.papel(&dentro["papel:".len()..]).is_some() {
                        Codigo::Allow
                    } else {
                        Codigo::DenyResource
                    };
                    assert_eq!(d(Some(dentro)), esperado, "{papel} {dentro}");
                }
                for fora in ["papel:administrador", "papel:seguranca", "papel:x", ""] {
                    assert_eq!(d(Some(fora)), Codigo::DenyResource, "{papel} {fora}");
                }
                assert_eq!(d(None), Codigo::DenyResource, "{papel}");
                assert!(
                    p.papel(papel).unwrap().diretas.contains(&ProcessTerminate),
                    "{papel}: escrita pelo nome"
                );
            }
            for papel in ["observador", "operador", "tempo", "seguranca"] {
                if p.papel(papel).is_some() {
                    assert_eq!(
                        p.decidir(Some(papel), ProcessTerminate, Some("papel:operador")),
                        Codigo::DenyPermission,
                        "{papel}"
                    );
                }
            }
        }
        // Sensível: um papel que inclui quem a tem não a herda.
        let p = com(
            "papel a ui.read process.terminate\nrecurso a process.terminate papel:a\n\
             papel b @a\nserial a",
        )
        .unwrap();
        assert!(p.papel("a").unwrap().tem(ProcessTerminate));
        assert!(p.papel("b").unwrap().tem(Permissao::UiRead));
        assert!(!p.papel("b").unwrap().tem(ProcessTerminate));
        assert_eq!(
            p.decidir(Some("b"), ProcessTerminate, Some("papel:a")),
            Codigo::DenyPermission
        );
        // E o alcance é obrigatório: sem a linha `recurso`, a política
        // inteira é recusada.
        assert!(com("papel a process.terminate\nserial a").is_err());
    }

    /// Reiniciar e desligar: o `sistema` e o `administrador`, nas duas
    /// políticas embutidas, escrita pelo nome; nenhum outro papel.
    #[test]
    fn quem_reinicia_e_desliga() {
        use Permissao::SystemPower;
        for p in [padrao(), Politica::emergencia()] {
            for papel in ["sistema", "administrador"] {
                assert_eq!(
                    p.decidir(Some(papel), SystemPower, None),
                    Codigo::Allow,
                    "{papel}"
                );
                assert!(p.papel(papel).unwrap().diretas.contains(&SystemPower));
            }
            for papel in ["observador", "operador", "tempo", "seguranca"] {
                if p.papel(papel).is_some() {
                    assert_eq!(
                        p.decidir(Some(papel), SystemPower, None),
                        Codigo::DenyPermission,
                        "{papel}"
                    );
                }
            }
        }
        // Sensível: incluir quem a tem não a traz.
        let p = com("papel a ui.read system.power\npapel b @a\nserial a").unwrap();
        assert!(p.papel("a").unwrap().tem(SystemPower));
        assert!(!p.papel("b").unwrap().tem(SystemPower));
    }

    /// Trocar a própria senha: na padrão, o `observador` e o `operador` —
    /// os papéis de pessoa —, cada um escrevendo a permissão; o teto do
    /// administrador a contém, para delegá-los, nas duas políticas; o
    /// `sistema` não, nas duas: não é pessoa, e a autoridade máxima não é
    /// curinga. Nem os serviços. Sem recurso: decidida com nenhum, e um
    /// papel que a escreve não precisa de linha `recurso`.
    #[test]
    fn quem_troca_a_propria_senha() {
        use Permissao::CredentialChangeSelf;
        let p = padrao();
        for papel in ["observador", "operador", "administrador"] {
            assert_eq!(
                p.decidir(Some(papel), CredentialChangeSelf, None),
                Codigo::Allow,
                "{papel}"
            );
            assert_eq!(
                p.decidir(Some(papel), CredentialChangeSelf, Some("")),
                Codigo::Allow,
                "{papel}"
            );
            assert!(
                p.papel(papel)
                    .unwrap()
                    .diretas
                    .contains(&CredentialChangeSelf),
                "{papel}"
            );
        }
        for papel in ["sistema", "tempo", "seguranca"] {
            assert_eq!(
                p.decidir(Some(papel), CredentialChangeSelf, None),
                Codigo::DenyPermission,
                "{papel}"
            );
        }
        assert_eq!(
            p.decidir(None, CredentialChangeSelf, None),
            Codigo::DenyRole
        );
        // A de emergência: o teto a contém, o sistema não; os papéis de
        // pessoa não existem nela.
        let e = Politica::emergencia();
        assert_eq!(
            e.decidir(Some("administrador"), CredentialChangeSelf, None),
            Codigo::Allow
        );
        assert_eq!(
            e.decidir(Some("sistema"), CredentialChangeSelf, None),
            Codigo::DenyPermission
        );
        assert_eq!(
            e.decidir(Some("operador"), CredentialChangeSelf, None),
            Codigo::DenyRole
        );
        // Os papéis de pessoa cabem no teto: o administrador os delega.
        for papel in ["observador", "operador"] {
            assert!(p.cabe_em(papel, "administrador").is_ok(), "{papel}");
        }
        // Sensível: incluir quem a tem não a traz, e sem alcance a
        // escrever.
        let q = com("papel a ui.read credential.change_self\npapel b @a\nserial a").unwrap();
        assert!(q.papel("a").unwrap().tem(CredentialChangeSelf));
        assert!(!q.papel("b").unwrap().tem(CredentialChangeSelf));
        assert!(
            com("papel a credential.change_self\nrecurso a credential.change_self x\nserial a")
                .is_err()
        );
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

    /// `random.read`: quem conecta tem — o operador, o administrador e o
    /// sistema —; quem não conecta a nada não — o observador, o tecido de
    /// segurança. Sem recurso, e não sensível: não é caminho, nem destino,
    /// nem papel, e o que sai não diz nada de ninguém.
    #[test]
    fn quem_le_o_aleatorio() {
        use Permissao::RandomRead;
        let p = padrao();
        for papel in ["operador", "administrador", "sistema"] {
            assert_eq!(
                p.decidir(Some(papel), RandomRead, None),
                Codigo::Allow,
                "{papel}"
            );
        }
        for papel in ["observador", "seguranca"] {
            assert_eq!(
                p.decidir(Some(papel), RandomRead, None),
                Codigo::DenyPermission,
                "{papel}"
            );
        }
        assert!(!RandomRead.sensivel());
        assert!(!RandomRead.administrativa());
        assert!(
            !RandomRead.recurso_e_caminho()
                && !RandomRead.recurso_e_endereco()
                && !RandomRead.recurso_e_papel()
        );
        assert_eq!(Permissao::de_nome("random.read"), Some(RandomRead));
        // O teto do administrador contém o que o operador recebe: o
        // operador continua delegável.
        assert_eq!(p.cabe_em("operador", "administrador"), Ok(()));
        // Na emergência, o sistema continua com ela.
        let e = Politica::emergencia();
        assert_eq!(e.decidir(Some("sistema"), RandomRead, None), Codigo::Allow);
    }

    /// `audit.declare`: quem conecta declara — o operador, o administrador
    /// e o sistema —; quem só observa não — o observador, o tecido de
    /// segurança, o serviço de hora. O recurso não muda nada: não há
    /// alcance, e o que se declara não é recurso de política. Sensível: não
    /// vem pela inclusão de outro papel — só quem a escreve a tem.
    #[test]
    fn quem_declara() {
        use Permissao::AuditDeclare;
        let p = padrao();
        for papel in ["operador", "administrador", "sistema"] {
            for recurso in [None, Some(""), Some("x.y"), Some("tcp:10.0.2.100:4943")] {
                assert_eq!(
                    p.decidir(Some(papel), AuditDeclare, recurso),
                    Codigo::Allow,
                    "{papel} {recurso:?}"
                );
            }
        }
        for papel in ["observador", "seguranca", "tempo"] {
            assert_eq!(
                p.decidir(Some(papel), AuditDeclare, None),
                Codigo::DenyPermission,
                "{papel}"
            );
        }
        assert_eq!(p.decidir(None, AuditDeclare, None), Codigo::DenyRole);
        // A inclusão não a traz.
        let p = com("papel a audit.declare ui.read\npapel b @a\nserial b").unwrap();
        assert!(p.papel("b").unwrap().tem(Permissao::UiRead));
        assert!(!p.papel("b").unwrap().tem(AuditDeclare));
        assert_eq!(
            p.decidir(Some("b"), AuditDeclare, None),
            Codigo::DenyPermission
        );
        // Um programa a declara no manifesto: não é administrativa.
        assert!(manifesto::declaravel(AuditDeclare));
        // O teto do administrador contém o que o operador recebe.
        assert_eq!(padrao().cabe_em("operador", "administrador"), Ok(()));
        // Na emergência, o sistema continua com ela.
        let e = Politica::emergencia();
        assert_eq!(
            e.decidir(Some("sistema"), AuditDeclare, None),
            Codigo::Allow
        );
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

    /// As três fontes de hora da bancada, como o registro de fontes as
    /// escreve.
    const FONTES: [&str; 3] = [
        "udp:10.0.2.2:5319",
        "udp:10.0.2.2:5320",
        "udp:10.0.2.2:5321",
    ];

    /// O serviço de hora decide pelo papel `tempo`, que enumera duas
    /// permissões — conectar às fontes e apresentar evidência de hora — e
    /// nada mais. Só na padrão: na de emergência o serviço não tem papel, e
    /// a decisão sem papel é `DENY_ROLE`.
    #[test]
    fn o_servico_de_hora_decide_pelo_papel_tempo() {
        use Permissao::*;
        let p = padrao();
        assert_eq!(p.servico("hora"), Some("tempo"));
        let tempo = p.papel("tempo").unwrap();
        assert!(tempo.inclui.is_empty(), "o tempo inclui outro papel");
        let todas: alloc::vec::Vec<_> = tempo.permissoes().map(|x| x.nome()).collect();
        assert_eq!(todas, ["net.connect", "time.sync"]);
        assert_eq!(tempo.recursos.get(&NetConnect).unwrap(), &FONTES);
        assert!(tempo.editores.is_empty());
        let d = |perm, rec| p.decidir(p.servico("hora"), perm, rec);
        assert_eq!(d(TimeSync, None), Codigo::Allow);
        for fonte in FONTES {
            assert_eq!(d(NetConnect, Some(fonte)), Codigo::Allow, "{fonte}");
        }
        // Nenhum outro destino: nem os da bancada, nem outra porta da fonte,
        // nem a fonte por TCP.
        for fora in [
            "udp:10.0.2.2:69",
            "udp:10.0.2.3:53",
            "tcp:10.0.2.100:7",
            "udp:10.0.2.2:5318",
            "udp:10.0.2.2:5322",
            "tcp:10.0.2.2:5319",
            "udp:10.0.2.3:5319",
            "",
        ] {
            assert_eq!(d(NetConnect, Some(fora)), Codigo::DenyResource, "{fora}");
        }
        assert_eq!(d(NetConnect, None), Codigo::DenyResource);
        // Cada outra permissão do vocabulário, recusada.
        for perm in permissao::TODAS {
            if perm == NetConnect || perm == TimeSync {
                continue;
            }
            assert_eq!(
                d(perm, Some("/")),
                Codigo::DenyPermission,
                "{}",
                perm.nome()
            );
        }
        // Cabe no teto do administrador — que pode mudá-lo por policy.write,
        // dentro do que ele mesmo tem — e não é teto de ninguém.
        assert_eq!(p.cabe_em("tempo", "administrador"), Ok(()));
        assert_eq!(p.conferir_tetos(&["administrador"]), Ok(()));
        // Na de emergência: sem a linha, sem papel.
        let e = Politica::emergencia();
        assert_eq!(e.servico("hora"), None);
        assert!(e.papel("tempo").is_none());
        assert_eq!(
            e.decidir(e.servico("hora"), TimeSync, None),
            Codigo::DenyRole
        );
        // O texto leva a linha, e a leitura a devolve.
        assert!(p.texto().contains("servico hora tempo\n"));
        assert_eq!(Politica::ler(&p.texto()).unwrap(), p);
    }

    /// O `tempo` não é o `sistema`, nem o recebe por nenhum caminho: não o
    /// inclui; uma inclusão do `sistema` não traria `time.sync` nem
    /// `net.connect`, que são sensíveis; e a linha `servico` não pode dar
    /// ao serviço de hora o papel da serial, o da autoridade local, nem o
    /// teto de um administrador.
    #[test]
    fn o_tempo_nao_herda_o_sistema() {
        use Permissao::*;
        let p = padrao();
        let sistema = p.papel("sistema").unwrap();
        let tempo = p.papel("tempo").unwrap();
        // Das que o sistema tem, o tempo tem só as duas que escreve.
        let comuns: alloc::vec::Vec<_> = sistema
            .permissoes()
            .filter(|x| tempo.tem(*x))
            .map(|x| x.nome())
            .collect();
        assert_eq!(comuns, ["net.connect", "time.sync"]);
        // Uma política em que o tempo incluísse o sistema: só as não
        // sensíveis atravessariam — nem `time.sync`, nem `net.connect`. E
        // nem se lê sem escrever o alcance do `process.run` que viria junto:
        // o alcance é de cada papel, e não se herda.
        let tempo_do_padrao = "papel tempo net.connect time.sync\nrecurso tempo net.connect udp:10.0.2.2:5319 udp:10.0.2.2:5320 udp:10.0.2.2:5321\n";
        assert!(PADRAO.contains(tempo_do_padrao));
        let so_incluindo = PADRAO.replace(tempo_do_padrao, "papel tempo @sistema\n");
        assert!(matches!(
            Politica::ler(&so_incluindo).unwrap_err().tipo,
            arquivo::ErroTipo::RecursoFaltando(papel, perm) if papel == "tempo" && perm == "process.run"
        ));
        let incluindo = PADRAO.replace(
            tempo_do_padrao,
            "papel tempo @sistema\nrecurso tempo process.run /bin\n",
        );
        let incluindo = Politica::ler(&incluindo).expect("le");
        let herdado = incluindo.papel("tempo").unwrap();
        assert!(!herdado.tem(TimeSync) && !herdado.tem(NetConnect));
        assert!(!herdado.tem(TimeConfirm));
        assert_eq!(
            incluindo.decidir(incluindo.servico("hora"), TimeSync, None),
            Codigo::DenyPermission
        );
        // O papel da serial, o da autoridade local: a política não vigora.
        let como_o_sistema = PADRAO.replace("servico hora tempo", "servico hora sistema");
        assert!(matches!(
            Politica::ler(&como_o_sistema).unwrap_err().tipo,
            arquivo::ErroTipo::ServicoComPapelDoSistema(s, q) if s == "hora" && q == "sistema"
        ));
        let como_o_local = PADRAO
            .replace("servico hora tempo", "servico hora operador")
            .replace("local sistema", "local operador");
        assert!(matches!(
            Politica::ler(&como_o_local).unwrap_err().tipo,
            arquivo::ErroTipo::ServicoComPapelDoSistema(s, q) if s == "hora" && q == "operador"
        ));
        // E a troca da serial para o papel do serviço é recusada.
        assert!(matches!(
            p.com_serial("tempo"),
            Err(Recusa::Invalida(arquivo::Erro {
                tipo: arquivo::ErroTipo::ServicoComPapelDoSistema(_, _),
                ..
            }))
        ));
        // O teto de um administrador: a política se lê, e a conferência dos
        // tetos — a do kernel e a do `xtask` — a recusa.
        let teto = PADRAO.replace("servico hora tempo", "servico hora administrador");
        let teto = Politica::ler(&teto).expect("le");
        assert!(teto.conferir_tetos(&["administrador"]).is_err());
    }

    /// `time.sync` não é implícita: um papel que inclui outro que a tem não
    /// a tem; só quem a escreve. E `time.confirm`, além disso, só se exerce
    /// com prova — ver `Permissao::administrativa`.
    #[test]
    fn as_do_tempo_nao_atravessam_a_inclusao() {
        use Permissao::*;
        let p = com("papel a time.sync net.connect\nrecurso a net.connect udp:10.0.2.2:5319\npapel b @a ui.read")
            .unwrap();
        let b = p.papel("b").unwrap();
        assert!(b.tem(UiRead) && !b.tem(TimeSync) && !b.tem(NetConnect));
        assert_eq!(p.decidir(Some("b"), TimeSync, None), Codigo::DenyPermission);
        let p = com("papel a time.confirm\npapel b @a ui.read").unwrap();
        assert!(!p.papel("b").unwrap().tem(TimeConfirm));
        // Na padrão, quem tem cada uma: as listas inteiras.
        let p = padrao();
        let quem = |perm| {
            [
                "observador",
                "operador",
                "tempo",
                "sistema",
                "administrador",
                "seguranca",
            ]
            .into_iter()
            .filter(|papel| p.papel(papel).unwrap().tem(perm))
            .collect::<alloc::vec::Vec<_>>()
        };
        assert_eq!(quem(TimeSync), ["tempo", "sistema", "administrador"]);
        assert_eq!(quem(TimeConfirm), ["administrador"]);
    }

    /// `policy.write` e o tempo: o administrador revoga `time.sync` do
    /// papel `tempo` — e a decisão seguinte do serviço é recusada —,
    /// estreita os destinos dele, e o delega a quem cabe no teto; não dá ao
    /// `tempo` um destino que o teto não alcança, nem o que o teto não tem.
    /// A linha `servico hora` não muda por aqui.
    #[test]
    fn policy_write_e_o_tempo() {
        use Permissao::*;
        let p = padrao();
        let mudar =
            |linha: &str| p.com_linha(linha, "administrador", &["administrador", "sistema"]);
        // Revogar: o papel continua, sem a permissão; o serviço é recusado.
        let sem = mudar("papel tempo net.connect").unwrap();
        assert_eq!(
            sem.decidir(sem.servico("hora"), TimeSync, None),
            Codigo::DenyPermission
        );
        assert_eq!(
            sem.decidir(sem.servico("hora"), NetConnect, Some(FONTES[0])),
            Codigo::Allow
        );
        // Tirar uma fonte do alcance: o serviço não conecta mais a ela.
        let estreito =
            mudar("recurso tempo net.connect udp:10.0.2.2:5319 udp:10.0.2.2:5320").unwrap();
        assert_eq!(
            estreito.decidir(estreito.servico("hora"), NetConnect, Some(FONTES[2])),
            Codigo::DenyResource
        );
        // Um destino que o administrador não alcança: não.
        assert!(matches!(
            mudar("recurso tempo net.connect udp:10.0.2.2:5319 udp:10.0.2.2:5399"),
            Err(Recusa::Proibida(_))
        ));
        // O que o administrador não tem: não.
        assert!(matches!(
            mudar("papel tempo net.connect time.sync debug.trigger"),
            Err(Recusa::Proibida(_))
        ));
        // Delegar `time.sync` ao operador cabe no teto: é decisão de quem
        // tem a prova, e a auditoria a grava.
        let delegado = mudar(
            "papel operador @observador ui.act process.run net.send net.connect fs.read fs.write fs.restore message.send message.read random.read key.create key.read key.sign key.destroy fabric.offer fabric.send time.sync",
        )
        .unwrap();
        assert_eq!(
            delegado.decidir(Some("operador"), TimeSync, None),
            Codigo::Allow
        );
        // A linha do serviço é só da imagem.
        for linha in ["servico hora operador", "servico hora tempo"] {
            assert!(matches!(mudar(linha), Err(Recusa::Proibida(_))), "{linha}");
        }
        // Nada disso mudou a política de onde partiu.
        assert_eq!(p, padrao());
    }
}
