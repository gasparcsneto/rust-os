//! A sessão cifrada de um canal do agente: uma porta do `virtio-console`,
//! ou uma vaga do canal por TCP.
//!
//! # Onde fica
//!
//! Entre os bytes crus do transporte e o [`super::Montador`]. Para baixo, quadros
//! do [`sigilo::quadro`] com mensagens do Noise; para cima, o mesmo JSON por
//! linha de sempre. O enquadramento por linha, o JSON-RPC e os comandos não
//! mudaram: só passaram a receber o que sobrevive à decifração.
//!
//! ```text
//! transporte ── bytes ──> quadros ──> aperto / decifrar ──> texto ──> Montador
//! transporte <── bytes ── quadros <── cifrar <──────────── resposta ─┘
//! ```
//!
//! O estado que precisa sobreviver entre uma chamada e outra — quem está em
//! cada sessão, e as chaves — mora em [`crate::sessoes`]: lá pode haver
//! travas estáticas, e aqui não há `unsafe`.
//!
//! # Um código para os dois transportes
//!
//! A porta e a vaga do TCP passam pelo mesmo aperto, pela mesma conferência
//! do registro, pela mesma suspensão de credencial, pela mesma taxa de
//! apertos e pela mesma auditoria — este arquivo não tem um caminho do TCP.
//! O que muda é só onde os bytes entram e saem, e duas coisas que só uma
//! conexão de rede tem: o fim da sessão **fecha** a conexão — a recusa em
//! claro sai antes do FIN, ver [`crate::rede::canal::encerrar`] —, e a
//! auditoria de um aperto diz o par de quem o fez. Quem conecta pelo TCP e
//! não faz o aperto — manda outra coisa, ou nada — também vai à auditoria:
//! a porta é do hospedeiro, a rede é de qualquer um.
//!
//! # A vida de uma sessão
//!
//! 1. **Aguardando**: o primeiro quadro tem de ser o início do aperto.
//! 2. O Duke lê a primeira mensagem do IK e aprende a chave do agente. Se ela
//!    não está no registro, ou falta entropia para a resposta, o Duke manda
//!    uma **recusa** em claro e a porta fica **encerrada**.
//! 3. Senão responde, e a sessão fica **estabelecida**: cada quadro de dados
//!    é decifrado, e o texto vai ao montador. No TCP, o aperto só termina
//!    com o primeiro quadro que abre — a chave **confirmada**, ver
//!    [`Cifrada::confirmar`]: é só então que o aperto vai à auditoria e a
//!    sessão é mostrada como do agente. A que acaba antes disso vai à
//!    auditoria como um aperto recusado.
//! 4. Um quadro que não abre — adulterado, repetido, fora de ordem, ou com
//!    bytes perdidos no caminho — **encerra** a sessão. Não há segunda
//!    tentativa: depois de um erro o contador não sabe mais onde o outro lado
//!    está, e tentar adivinhar é abrir a porta para quem está no meio.
//! 5. Encerrada, a sessão ignora tudo até o outro lado reconectar — a
//!    geração do canal muda —, e aí volta ao começo. No TCP a conexão
//!    encerrada fecha, e quem quiser voltar conecta de novo.
//!
//! # A serial não passa por aqui
//!
//! A sessão 0 é o canal de emergência: aberto, independente do Noise, e o
//! único que responde no modo post-mortem — quando o heap e o escalonador
//! podem ser o que quebrou, e fazer criptografia seria pedir a eles. As
//! operações administrativas têm prova própria, que vale nela também — ver
//! [`super::administracao`].

use alloc::string::String;
use alloc::vec;

use sigilo::quadro::{self, Leitor, Tipo};
use sigilo::{Respondedor, Transporte};

use politica::Codigo;

use super::sessao::Canal;
use crate::autorizacao;
use crate::sessoes;
use crate::virtio::console;

/// Bytes crus pelo transporte do canal. Falso se ele não os aceitou.
fn mandar_bytes(canal: Canal, geracao: Option<u64>, q: &[u8]) -> bool {
    match (canal, geracao) {
        (Canal::Porta(p), None) => console::enviar(p, q),
        (Canal::Porta(p), Some(g)) => console::enviar_na_conexao(p, g, q),
        (Canal::Tcp(v), None) => crate::rede::canal::enviar(v, q),
        (Canal::Tcp(v), Some(g)) => crate::rede::canal::enviar_na_conexao(v, g, q),
        // A serial não tem sessão cifrada.
        (Canal::Serial, _) => false,
    }
}

/// Manda um quadro cru pelo canal. Falso se o transporte não o aceitou.
fn mandar_quadro(canal: Canal, tipo: Tipo, corpo: &[u8]) -> bool {
    match quadro::montar(tipo, corpo) {
        Ok(q) => mandar_bytes(canal, None, &q),
        Err(_) => false,
    }
}

/// Manda um quadro cru pelo canal só se ele ainda está na conexão
/// `geracao`. O aperto e a recusa são de uma conexão: calculados enquanto
/// o cliente desistia e outro chegava, iam para o novo — que ouvia a
/// resposta de um aperto que não mandou, ou a recusa dele.
///
/// A geração separa o que o kernel já viu trocar. Numa porta, a troca e os
/// bytes dos dois clientes num mesmo tique chegam juntos, e nada no fluxo
/// os separa: é um limite do transporte — ver "Vários agentes", no README.
/// No TCP, cada byte vem com a conexão dele.
fn mandar_quadro_na_conexao(canal: Canal, geracao: u64, tipo: Tipo, corpo: &[u8]) -> bool {
    match quadro::montar(tipo, corpo) {
        Ok(q) => mandar_bytes(canal, Some(geracao), &q),
        Err(_) => false,
    }
}

/// O fim da sessão da conexão `geracao`, no transporte: no TCP, a conexão
/// fecha depois do que já está na saída — a recusa em claro sai antes do
/// FIN. Uma porta não fecha por dentro: o agente fica do outro lado, e a
/// sessão espera que ele reconecte.
fn fechar_transporte(canal: Canal, geracao: u64) {
    if let Canal::Tcp(v) = canal {
        crate::rede::canal::encerrar(v, geracao);
    }
}

/// Grava o fim de uma sessão do TCP cuja chave não foi confirmada: um
/// aperto que não terminou — ver [`Cifrada::confirmar`] —, recusado como
/// os outros, com a chave alegada e o par. A sessão confirmada, e a de uma
/// porta, não gravam nada aqui: o aperto delas já foi gravado.
pub fn gravar_sem_confirmacao(p: u8, id: &sessoes::Identificada, motivo: &str) {
    if id.confirmada {
        return;
    }
    let par = id
        .par
        .map_or_else(|| String::from("tcp"), crate::rede::canal::texto_do_par);
    let detalhe = alloc::format!(
        "a chave do aperto nao foi confirmada: {motivo} ({par}, conexao {})",
        id.geracao
    );
    crate::log_warn!("agent", "sessao {}: {}", p, detalhe);
    sessoes::contar_recusa();
    autorizacao::auditar_aperto(
        p,
        Some(id.chave),
        "",
        Codigo::DenyNotAuthenticated,
        &detalhe,
    );
}

/// Como o log chama o canal: `porta 2`, `sessao 6 (tcp)`.
fn rotulo(canal: Canal) -> alloc::string::String {
    match canal {
        Canal::Porta(p) => alloc::format!("porta {p}"),
        outro => alloc::format!("sessao {} ({})", outro.sessao(), outro.transporte()),
    }
}

/// Cifra e manda uma resposta pelo canal. Falso se não havia sessão, ou se
/// algum quadro não saiu — e nesse caso a sessão acabou: o contador do
/// lado de cá andou e o de lá não, e as próximas mensagens não abririam.
pub fn enviar(canal: Canal, texto: &[u8]) -> bool {
    let p = canal.sessao();
    let Some(mut transporte) = sessoes::tirar(p) else {
        return false;
    };

    let mut cifrado = vec![0u8; sigilo::MAIOR_MENSAGEM];
    let mut inteiro = true;
    for pedaco in texto.chunks(Transporte::MAIOR_CLARO) {
        let saiu = match transporte.cifrar(pedaco, &mut cifrado) {
            Ok(n) => mandar_quadro(canal, Tipo::Dados, &cifrado[..n]),
            Err(_) => false,
        };
        if !saiu {
            inteiro = false;
            break;
        }
    }

    if inteiro {
        sessoes::devolver(p, transporte);
    } else {
        crate::log_warn!(
            "agent",
            "{}: uma resposta nao saiu inteira; sessao encerrada",
            rotulo(canal)
        );
        sessoes::contar_encerrada();
        drop(transporte);
        if let Some(id) = sessoes::esquecer(p) {
            fechar_transporte(canal, id.geracao);
        }
    }
    inteiro
}

/// Encerra toda sessão aberta com `chave`, em qualquer transporte: a chave
/// foi revogada. Devolve as sessões encerradas.
///
/// Quem revoga é outra sessão — a de um administrador —, e a da chave
/// revogada pode estar no meio de qualquer coisa. Esquecer a sessão basta
/// para o resto: sem identidade, o ponto de decisão recusa o próximo pedido
/// dela, e o canal, no próximo quadro, se dá por encerrado. A recusa em
/// claro sai daqui, agora, para o agente saber já, e por quê — pela conexão
/// em que ele fez o aperto, e só por ela —; no TCP, a conexão fecha depois
/// dela.
pub fn revogar(chave: &[u8; 32]) -> alloc::vec::Vec<u8> {
    let mut encerradas = alloc::vec::Vec::new();
    for p in 1..=sessoes::CIFRADAS as u8 {
        let Some(canal) = Canal::da_sessao(p) else {
            continue;
        };
        if !sessoes::identidade(p).is_some_and(|id| id.chave == *chave) {
            continue;
        }
        let Some(id) = sessoes::esquecer(p) else {
            continue;
        };
        if id.confirmada {
            sessoes::contar_encerrada();
        } else {
            gravar_sem_confirmacao(p, &id, "chave revogada");
        }
        crate::log_warn!(
            "agent",
            "{}: chave revogada; sessao encerrada",
            rotulo(canal)
        );
        mandar_quadro_na_conexao(canal, id.geracao, Tipo::Recusa, b"chave revogada");
        sessoes::marcar_avisada(p);
        fechar_transporte(canal, id.geracao);
        encerradas.push(p);
    }
    encerradas
}

/// Em que ponto a sessão de uma porta está.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Estado {
    /// Esperando o início do aperto.
    Aguardando,
    /// Aperto feito; os quadros são de dados.
    Estabelecida,
    /// Recusada ou encerrada: nada até o outro lado reconectar.
    Encerrada,
}

/// O lado de dentro de um canal cifrado: remonta os quadros, faz o aperto
/// e decifra. Um por canal, da tarefa que o atende.
pub struct Cifrada {
    canal: Canal,
    /// A sessão do canal.
    p: u8,
    geracao: u64,
    perdas: u64,
    leitor: Leitor,
    estado: Estado,
    /// No TCP, o aperto respondido cuja chave o agente ainda não
    /// confirmou — ver [`Cifrada::confirmar`].
    a_confirmar: bool,
}

impl Cifrada {
    /// O canal cifrado `canal` — uma porta, ou uma vaga do TCP —, no começo.
    pub fn nova(canal: Canal) -> Self {
        Self {
            canal,
            p: canal.sessao(),
            geracao: canal.geracao(),
            perdas: canal.perdidos(),
            leitor: Leitor::novo(),
            estado: Estado::Aguardando,
            a_confirmar: false,
        }
    }

    /// Recebe um byte cru do canal, que chegou pela conexão `geracao`, e
    /// entrega a `texto` cada byte decifrado.
    pub fn receber(&mut self, geracao: u64, byte: u8, mut texto: impl FnMut(u8)) {
        // Uma conexão nova: o que havia era de quem saiu.
        if geracao != self.geracao {
            self.geracao = geracao;
            self.leitor.recomecar();
            self.estado = Estado::Aguardando;
            self.a_confirmar = false;
            // A sessão da conexão que acabou, se ninguém a esqueceu antes —
            // o fecho da porta, ou o coletor no TCP, que dizem a saída eles
            // mesmos: uma linha por saída, de quem esqueceu.
            match sessoes::esquecer(self.p) {
                Some(id) if id.confirmada => {
                    crate::log_info!("agent", "{}: {} saiu", rotulo(self.canal), id.nome);
                }
                Some(id) => gravar_sem_confirmacao(self.p, &id, "a conexao acabou"),
                None => {}
            }
            let _ = sessoes::tirar_aviso(self.p);
        }

        // Um byte perdido na entrada desalinha os quadros, ou corrompe um.
        // Depois do aperto a sessão acabou de qualquer forma — o próximo
        // quadro não abriria —, e dizer agora é melhor do que deixar o agente
        // esperando a resposta de um pedido que nunca chegou inteiro.
        let perdas = self.canal.perdidos();
        if perdas != self.perdas {
            self.perdas = perdas;
            self.encerrar("bytes perdidos na entrada");
        }

        if self.estado == Estado::Encerrada {
            return;
        }

        let (tipo, corpo) = match self.leitor.empurrar(byte) {
            Ok(Some((tipo, corpo))) => (tipo, corpo.to_vec()),
            Ok(None) => return,
            Err(e) => return self.encerrar(e.motivo()),
        };

        // Uma sessão que a revogação encerrou por fora: a recusa já foi —
        // ver [`revogar`]. Daqui até o outro lado reconectar, nada.
        if sessoes::tirar_aviso(self.p) && self.estado == Estado::Estabelecida {
            self.estado = Estado::Encerrada;
            return;
        }

        match (self.estado, tipo) {
            (Estado::Aguardando, Tipo::Inicio) => self.apertar(&corpo),
            (Estado::Estabelecida, Tipo::Dados) => self.decifrar(&corpo, &mut texto),
            _ => self.encerrar("quadro fora de ordem"),
        }
    }

    /// Encerra a sessão, avisando o outro lado em claro. Uma conexão do
    /// TCP que acaba antes do aperto — mandou outra coisa — vai à
    /// auditoria como recusa, com o par: ver o cabeçalho.
    fn encerrar(&mut self, motivo: &str) {
        if self.estado == Estado::Aguardando && matches!(self.canal, Canal::Tcp(_)) {
            crate::rede::canal::recusar_conexao(self.p, &self.com_o_par(motivo));
        }
        self.terminar(motivo);
    }

    /// O fim, sem auditoria: avisa o outro lado em claro, esquece a sessão e
    /// fecha o transporte.
    fn terminar(&mut self, motivo: &str) {
        if self.estado == Estado::Encerrada {
            return;
        }
        crate::log_warn!(
            "agent",
            "{}: {}; sessao encerrada",
            rotulo(self.canal),
            motivo
        );
        match sessoes::esquecer(self.p) {
            // O aperto do TCP que não terminou: uma recusa, gravada.
            Some(id) if !id.confirmada => gravar_sem_confirmacao(self.p, &id, motivo),
            _ if self.estado == Estado::Estabelecida => sessoes::contar_encerrada(),
            _ => sessoes::contar_recusa(),
        }
        self.estado = Estado::Encerrada;
        mandar_quadro_na_conexao(self.canal, self.geracao, Tipo::Recusa, motivo.as_bytes());
        fechar_transporte(self.canal, self.geracao);
    }

    /// O motivo como a auditoria o grava: no TCP, com o par de quem fez o
    /// aperto — a conexão desta sessão, e não a de agora na vaga.
    fn com_o_par(&self, motivo: &str) -> alloc::string::String {
        match self.canal {
            Canal::Tcp(v) => match crate::rede::canal::remoto_da_conexao(v, self.geracao) {
                Some(par) => alloc::format!(
                    "{motivo} ({}, conexao {})",
                    crate::rede::canal::texto_do_par(par),
                    self.geracao
                ),
                None => alloc::format!("{motivo} (tcp, conexao {})", self.geracao),
            },
            _ => String::from(motivo),
        }
    }

    /// Recusa o aperto: grava na auditoria e encerra.
    fn recusar_aperto(&mut self, chave: Option<[u8; 32]>, codigo: Codigo, motivo: &str) {
        autorizacao::auditar_aperto(self.p, chave, "", codigo, &self.com_o_par(motivo));
        self.terminar(motivo);
    }

    /// O aperto de mão: lê a primeira mensagem, confere o registro, responde.
    fn apertar(&mut self, mensagem: &[u8]) {
        // Antes de qualquer conta: cada aperto custa ao Duke duas trocas
        // Diffie-Hellman e um sorteio, e quem não tem chave registrada pode
        // pedi-los à vontade. A política limita quantos por janela.
        // A janela grava a primeira recusa a mais: esta não vai de novo.
        if !autorizacao::permitir_aperto(self.p) {
            return self.terminar("apertos demais; espere a janela");
        }

        let mut carga = vec![0u8; sigilo::MAIOR_MENSAGEM];
        let lido = crate::identidade::com_chave_do_duke(|chave| {
            Respondedor::novo(sigilo::PROLOGO, chave).ler(mensagem, &mut carga)
        });
        let recebido = match lido {
            None => return self.recusar_aperto(None, Codigo::Error, "o Duke nao tem chave"),
            Some(Err(e)) => {
                return self.recusar_aperto(None, Codigo::DenyNotAuthenticated, e.motivo());
            }
            Some(Ok((_, recebido))) => recebido,
        };

        // Autenticado não é autorizado: a chave provou ser de quem diz, e
        // agora o registro diz se esse alguém pode entrar.
        let chave = recebido.remota();
        let Some(nome) = crate::identidade::agente(&chave) else {
            crate::log_warn!(
                "agent",
                "{}: chave {} fora do registro",
                rotulo(self.canal),
                crate::identidade::impressao(&chave)
            );
            return self.recusar_aperto(
                Some(chave),
                Codigo::DenyNotAuthenticated,
                "chave fora do registro",
            );
        };

        // A credencial suspensa prova ser de quem diz, e não entra — ver
        // `crate::contencao`. Só quem tem a chave ouve isto: o aperto já a
        // conferiu.
        if crate::contencao::chave_suspensa(&chave) {
            return self.recusar_aperto(Some(chave), Codigo::DenyCredential, "credencial suspensa");
        }

        let Ok(efemera) = crate::aleatorio::chave() else {
            return self.recusar_aperto(Some(chave), Codigo::Error, "sem entropia para o aperto");
        };

        // A resposta diz ao agente quem o Duke acha que ele é, e em que
        // sessão: o cliente confere, e não precisa adivinhar.
        let mut carga_resposta = String::new();
        {
            let mut w = super::json::JsonWriter::new(&mut carga_resposta);
            let _ = (|| {
                w.begin_object()?;
                w.field_u64("session", u64::from(self.p))?;
                w.field_str("agent", &nome)?;
                w.end_object()
            })();
        }

        let mut resposta = vec![0u8; sigilo::MAIOR_MENSAGEM];
        let (n, transporte) =
            match recebido.escrever(efemera, carga_resposta.as_bytes(), &mut resposta) {
                Ok(par) => par,
                Err(e) => return self.encerrar(e.motivo()),
            };
        #[cfg(feature = "modo-teste")]
        sessoes::gancho_do_aperto();
        if !mandar_quadro_na_conexao(self.canal, self.geracao, Tipo::Resposta, &resposta[..n]) {
            return self.recusar_aperto(
                Some(chave),
                Codigo::Error,
                "a resposta do aperto nao saiu",
            );
        }
        // No TCP, o aperto só termina quando o agente confirmar a chave —
        // ver [`Cifrada::confirmar`]: até lá, nem a auditoria nem quem lista
        // as sessões o veem como de agente nenhum.
        let par = match self.canal {
            Canal::Tcp(v) => crate::rede::canal::remoto_da_conexao(v, self.geracao),
            Canal::Porta(_) | Canal::Serial => None,
        };
        let confirmada = !matches!(self.canal, Canal::Tcp(_));
        let identificada = sessoes::Identificada {
            nome,
            chave,
            desde_ms: crate::tempo::uptime_ms(),
            geracao: self.geracao,
            par,
            confirmada,
        };
        if confirmada {
            self.entrou(&identificada);
        } else {
            self.a_confirmar = true;
        }
        sessoes::estabelecer(self.p, transporte, identificada);
        self.estado = Estado::Estabelecida;
    }

    /// O aperto terminou: vai à auditoria, e ao log.
    fn entrou(&self, id: &sessoes::Identificada) {
        autorizacao::auditar_aperto(
            self.p,
            Some(id.chave),
            &id.nome,
            Codigo::Allow,
            &self.com_o_par("aperto completo"),
        );
        crate::log_info!(
            "agent",
            "{}: {} entrou ({})",
            rotulo(self.canal),
            id.nome,
            crate::identidade::impressao(&id.chave)
        );
    }

    /// A confirmação da chave, no TCP: o primeiro quadro de dados que abre.
    ///
    /// # Por que o aperto do TCP só termina aqui
    ///
    /// A primeira mensagem do IK pode ser repetida: quem a capturou na rede
    /// a manda de novo, e o Duke responde e estabelece a sessão com a chave
    /// de quem a escreveu. Quem repete não tem a efêmera dela, e não abre a
    /// resposta nem escreve um quadro que abra — a sessão não age. Mas ela
    /// existiria, com o nome de outro, ocupando uma vaga enquanto o
    /// repetidor segurasse a conexão. O primeiro quadro de dados que abre
    /// é a prova de que do outro lado está quem fez o aperto, agora; até
    /// ele, o prazo do aperto continua correndo — ver
    /// [`crate::rede::canal::PRAZO_DO_APERTO_MS`] —, e a conexão não é do
    /// agente para o firewall. Numa porta, o socket é do hospedeiro, e quem
    /// repete precisa estar nele: lá a sessão vale desde a resposta.
    ///
    /// Pelo mesmo motivo, o aperto do TCP vai à auditoria aqui, e não na
    /// resposta: "aperto completo" de um agente, com o par, é o que a
    /// auditoria diz só de quem confirmou. A sessão de quem não confirma
    /// acaba como um aperto recusado — ver [`gravar_sem_confirmacao`].
    fn confirmar(&mut self) {
        let (Canal::Tcp(v), true) = (self.canal, core::mem::take(&mut self.a_confirmar)) else {
            return;
        };
        if let Some(id) = sessoes::confirmar(self.p, self.geracao) {
            crate::rede::canal::identificar(v, self.geracao, id.chave);
            self.entrou(&id);
        }
    }

    /// Decifra um quadro de dados e entrega o texto.
    fn decifrar(&mut self, mensagem: &[u8], texto: &mut impl FnMut(u8)) {
        let Some(mut transporte) = sessoes::tirar(self.p) else {
            // Uma resposta que não saiu já encerrou a sessão do lado de cá.
            return self.encerrar("sessao sem transporte");
        };
        let mut claro = vec![0u8; mensagem.len()];
        match transporte.decifrar(mensagem, &mut claro) {
            Ok(n) => {
                sessoes::devolver(self.p, transporte);
                self.confirmar();
                // Um quadro cujo claro começa com zero é anexo — bytes
                // fora do JSON, para o pedido seguinte, que os declara
                // em `attachment`. O texto JSON nunca tem um zero.
                match claro[..n].split_first() {
                    Some((0, anexo)) => sessoes::acrescentar_anexo(self.p, anexo),
                    _ => {
                        for &b in &claro[..n] {
                            texto(b);
                        }
                    }
                }
                politica::sigiloso::zerar(&mut claro);
            }
            Err(e) => {
                drop(transporte);
                self.encerrar(e.motivo());
            }
        }
    }
}
