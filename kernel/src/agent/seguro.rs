//! A sessão cifrada de uma porta de agente.
//!
//! # Onde fica
//!
//! Entre os bytes crus da porta e o [`super::Montador`]. Para baixo, quadros
//! do [`sigilo::quadro`] com mensagens do Noise; para cima, o mesmo JSON por
//! linha de sempre. O enquadramento por linha, o JSON-RPC e os comandos não
//! mudaram: só passaram a receber o que sobrevive à decifração.
//!
//! ```text
//! porta ── bytes ──> quadros ──> aperto / decifrar ──> texto ──> Montador
//! porta <── bytes ── quadros <── cifrar <──────────── resposta ─┘
//! ```
//!
//! O estado que precisa sobreviver entre uma chamada e outra — quem está em
//! cada porta, e as chaves — mora em [`crate::sessoes`]: lá pode haver
//! travas estáticas, e aqui não há `unsafe`.
//!
//! # A vida de uma sessão
//!
//! 1. **Aguardando**: o primeiro quadro tem de ser o início do aperto.
//! 2. O Duke lê a primeira mensagem do IK e aprende a chave do agente. Se ela
//!    não está no registro, ou falta entropia para a resposta, o Duke manda
//!    uma **recusa** em claro e a porta fica **encerrada**.
//! 3. Senão responde, e a sessão fica **estabelecida**: cada quadro de dados
//!    é decifrado, e o texto vai ao montador.
//! 4. Um quadro que não abre — adulterado, repetido, fora de ordem, ou com
//!    bytes perdidos no caminho — **encerra** a sessão. Não há segunda
//!    tentativa: depois de um erro o contador não sabe mais onde o outro lado
//!    está, e tentar adivinhar é abrir a porta para quem está no meio.
//! 5. Encerrada, a porta ignora tudo até o outro lado reconectar — a geração
//!    do canal muda —, e aí volta ao começo.
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

use crate::sessoes;
use crate::virtio::console;

/// Manda um quadro cru pela porta. Falso se a porta não o aceitou.
fn mandar_quadro(p: u8, tipo: Tipo, corpo: &[u8]) -> bool {
    match quadro::montar(tipo, corpo) {
        Ok(q) => console::enviar(p, &q),
        Err(_) => false,
    }
}

/// Cifra e manda uma resposta pela porta `p`. Falso se não havia sessão, ou
/// se algum quadro não saiu — e nesse caso a sessão acabou: o contador do
/// lado de cá andou e o de lá não, e as próximas mensagens não abririam.
pub fn enviar(p: u8, texto: &[u8]) -> bool {
    let Some(mut transporte) = sessoes::tirar(p) else {
        return false;
    };

    let mut cifrado = vec![0u8; sigilo::MAIOR_MENSAGEM];
    let mut inteiro = true;
    for pedaco in texto.chunks(Transporte::MAIOR_CLARO) {
        let saiu = match transporte.cifrar(pedaco, &mut cifrado) {
            Ok(n) => mandar_quadro(p, Tipo::Dados, &cifrado[..n]),
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
            "porta {}: uma resposta nao saiu inteira; sessao encerrada",
            p
        );
        sessoes::contar_encerrada();
        drop(transporte);
        let _ = sessoes::esquecer(p);
    }
    inteiro
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

/// O lado de dentro de uma porta: remonta os quadros, faz o aperto e
/// decifra. Um por porta, da tarefa que a atende.
pub struct Porta {
    p: u8,
    geracao: u64,
    perdas: u64,
    leitor: Leitor,
    estado: Estado,
}

impl Porta {
    /// A porta `p`, no começo.
    pub fn nova(p: u8) -> Self {
        Self {
            p,
            geracao: console::geracao(p),
            perdas: console::perdidos(p),
            leitor: Leitor::novo(),
            estado: Estado::Aguardando,
        }
    }

    /// Recebe um byte cru da porta, e entrega a `texto` cada byte decifrado.
    pub fn receber(&mut self, byte: u8, mut texto: impl FnMut(u8)) {
        // Uma conexão nova: o que havia era de quem saiu.
        let geracao = console::geracao(self.p);
        if geracao != self.geracao {
            self.geracao = geracao;
            self.leitor.recomecar();
            if self.estado == Estado::Estabelecida {
                crate::log_info!("agent", "porta {}: o agente saiu", self.p);
            }
            self.estado = Estado::Aguardando;
            let _ = sessoes::esquecer(self.p);
        }

        // Um byte perdido na entrada desalinha os quadros, ou corrompe um.
        // Depois do aperto a sessão acabou de qualquer forma — o próximo
        // quadro não abriria —, e dizer agora é melhor do que deixar o agente
        // esperando a resposta de um pedido que nunca chegou inteiro.
        let perdas = console::perdidos(self.p);
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

        match (self.estado, tipo) {
            (Estado::Aguardando, Tipo::Inicio) => self.apertar(&corpo),
            (Estado::Estabelecida, Tipo::Dados) => self.decifrar(&corpo, &mut texto),
            _ => self.encerrar("quadro fora de ordem"),
        }
    }

    /// Encerra a sessão, avisando o outro lado em claro.
    fn encerrar(&mut self, motivo: &str) {
        if self.estado == Estado::Encerrada {
            return;
        }
        if self.estado == Estado::Estabelecida {
            sessoes::contar_encerrada();
        } else {
            sessoes::contar_recusa();
        }
        crate::log_warn!("agent", "porta {}: {}; sessao encerrada", self.p, motivo);
        let _ = sessoes::esquecer(self.p);
        self.estado = Estado::Encerrada;
        mandar_quadro(self.p, Tipo::Recusa, motivo.as_bytes());
    }

    /// O aperto de mão: lê a primeira mensagem, confere o registro, responde.
    fn apertar(&mut self, mensagem: &[u8]) {
        let mut carga = vec![0u8; sigilo::MAIOR_MENSAGEM];
        let lido = crate::identidade::com_chave_do_duke(|chave| {
            Respondedor::novo(sigilo::PROLOGO, chave).ler(mensagem, &mut carga)
        });
        let recebido = match lido {
            None => return self.encerrar("o Duke nao tem chave"),
            Some(Err(e)) => return self.encerrar(e.motivo()),
            Some(Ok((_, recebido))) => recebido,
        };

        // Autenticado não é autorizado: a chave provou ser de quem diz, e
        // agora o registro diz se esse alguém pode entrar.
        let chave = recebido.remota();
        let Some(nome) = crate::identidade::agente(&chave) else {
            crate::log_warn!(
                "agent",
                "porta {}: chave {} fora do registro",
                self.p,
                crate::identidade::impressao(&chave)
            );
            return self.encerrar("chave fora do registro");
        };

        let Ok(efemera) = crate::aleatorio::chave() else {
            return self.encerrar("sem entropia para o aperto");
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
        if !mandar_quadro(self.p, Tipo::Resposta, &resposta[..n]) {
            return self.encerrar("a resposta do aperto nao saiu");
        }

        crate::log_info!(
            "agent",
            "porta {}: {} entrou ({})",
            self.p,
            nome,
            crate::identidade::impressao(&chave)
        );
        sessoes::estabelecer(
            self.p,
            transporte,
            sessoes::Identificada {
                nome,
                chave,
                desde_ms: crate::tempo::uptime_ms(),
            },
        );
        self.estado = Estado::Estabelecida;
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
                for &b in &claro[..n] {
                    texto(b);
                }
            }
            Err(e) => {
                drop(transporte);
                self.encerrar(e.motivo());
            }
        }
    }
}
