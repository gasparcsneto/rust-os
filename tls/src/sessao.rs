//! A sessão: o aperto, o mandar, o receber e o fecho, sobre um
//! [`Transporte`].
//!
//! # A máquina
//!
//! O `rustls` sem `std` é uma máquina de estados que não faz E/S
//! (`UnbufferedClientConnection`): cada volta lê os registros que chegaram
//! e diz o que quer — codificar uma mensagem do aperto, transmitir o que foi
//! codificado, mais bytes do par, ou que o aperto acabou e a conexão aceita
//! dados. Esta sessão dá as voltas e faz a E/S pelo transporte de quem
//! chama — num programa do Duke, cada `net.send` e cada `net.recv`
//! decididos pelo gate.
//!
//! # O que fica na memória
//!
//! O texto claro passa por dois lugares daqui: o buffer de entrada, onde o
//! `rustls` decifra cada registro no lugar, e o que já foi decifrado e
//! ainda não foi entregue. Os dois são apagados quando o que guardam sai — e
//! quando a sessão acaba.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use rustls::client::{Resumption, UnbufferedClientConnection};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::unbuffered::{
    AppDataRecord, ConnectionState, EncodeError, EncryptError, UnbufferedStatus,
};
use rustls::{ClientConfig, RootCertStore};
use zeroize::Zeroize;

use crate::{Falha, SOBRA_DO_REGISTRO, acaso, provedor};

/// O maior registro que chega: 2^14 bytes de texto, mais o que a cifra
/// acrescenta (até 256) e o cabeçalho (RFC 8446, 5.2).
const MAIOR_REGISTRO: usize = (1 << 14) + 256 + 5;

/// O buffer de entrada: um registro inteiro, e a folga de uma leitura.
const ENTRADA: usize = MAIOR_REGISTRO + 4096;

/// Quanto texto claro vai em cada registro que sai: o registro cifrado
/// inteiro tem 4096 bytes — o maior `net.send` do Duke.
pub const CLARO_POR_REGISTRO: usize = 4096 - SOBRA_DO_REGISTRO;

/// Quantas voltas a sessão dá, no máximo, para mandar ao par o alerta de
/// um aperto recusado: as que consomem o resto do voo do servidor — um
/// registro cada —, a que codifica o alerta e a que o transmite.
const VOLTAS_DO_ALERTA: usize = 16;

/// O lado de baixo: a conexão que leva os bytes.
///
/// Num programa do Duke, `net.send` e `net.recv` sobre a conexão que o
/// `net.connect` abriu — cada pedido decidido pelo gate. Uma recusa do gate
/// volta como [`Falha::Transporte`] com o código dele, e a sessão acaba:
/// o TLS não tenta outro caminho.
pub trait Transporte {
    /// Manda `dados` inteiros. Quando a conexão não aceita nada agora,
    /// espera espaço — nunca gira perguntando.
    fn mandar(&mut self, dados: &[u8]) -> Result<(), Falha>;

    /// Recebe o que chegar, até `destino.len()` bytes, esperando por algo.
    /// `Ok(0)`: o outro lado fechou a conexão.
    fn receber(&mut self, destino: &mut [u8]) -> Result<usize, Falha>;
}

/// As raízes em que um programa confia — ver o cabeçalho do pacote.
#[derive(Clone)]
pub struct Ancoras(Arc<RootCertStore>);

impl Ancoras {
    /// As âncoras de um texto PEM: cada bloco `CERTIFICATE` vira uma raiz.
    /// Um texto sem nenhuma, ou com uma que não se lê como certificado, é
    /// [`Falha::Ancoras`]: confiar em menos do que se mandou seria pior que
    /// não confiar em nada.
    pub fn de_pem(pem: &[u8]) -> Result<Ancoras, Falha> {
        let mut raizes = RootCertStore::empty();
        for certificado in CertificateDer::pem_slice_iter(pem) {
            let certificado = certificado.map_err(|_| Falha::Ancoras)?;
            raizes.add(certificado).map_err(|_| Falha::Ancoras)?;
        }
        if raizes.is_empty() {
            return Err(Falha::Ancoras);
        }
        Ok(Ancoras(Arc::new(raizes)))
    }

    /// Quantas raízes.
    pub fn quantas(&self) -> usize {
        self.0.len()
    }
}

/// Um buffer que guarda texto claro, apagado quando sai de cena.
struct Apagavel(Vec<u8>);

impl Drop for Apagavel {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// O que a sessão pede a uma volta, se ela chegar ao estado em que a
/// conexão aceita dados.
#[derive(Clone, Copy)]
enum Pedido<'a> {
    Nada,
    Cifrar(&'a [u8]),
    Fechar,
}

/// O que uma volta deu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Volta {
    /// A conexão aceita dados, e nada foi pedido.
    Pronta,
    /// O pedido foi cifrado e mandado inteiro.
    Mandou,
    /// O `close_notify` foi mandado.
    Fechou,
    /// Chegou texto claro, guardado para quem lê.
    Leu,
    /// Uma mensagem do aperto foi codificada ou transmitida.
    Andou,
    /// Faltam bytes do par.
    Falta,
    /// O par mandou `close_notify`: nada mais vem dele.
    ParFechou,
    /// Fechada dos dois lados.
    Fechada,
}

/// Uma conversa TLS 1.3 com um servidor.
pub struct Sessao<T: Transporte> {
    conexao: UnbufferedClientConnection,
    transporte: T,
    /// Os bytes que chegaram e ainda não foram processados — e, depois de
    /// processados, o texto que o `rustls` decifrou no lugar, até o descarte.
    entrada: Apagavel,
    usados: usize,
    /// O que foi codificado ou cifrado e ainda não foi transmitido.
    saida: Vec<u8>,
    /// O texto decifrado que quem lê ainda não pegou.
    claro: Apagavel,
    par_fechou: bool,
    fechou: bool,
    /// A falha que acabou com a sessão, se uma acabou. Depois dela, nada
    /// mais passa pela máquina: um registro que o transporte recusou já
    /// gastou o número de sequência dele, e o seguinte sairia com um número
    /// que o par não espera — a sessão não tem conserto, e cada pedido
    /// seguinte ouve a mesma falha, com o mesmo código.
    quebrada: Option<Falha>,
}

impl<T: Transporte> Sessao<T> {
    /// Conecta: o aperto inteiro, até o servidor provar quem é. `nome` é o
    /// nome que o certificado precisa ter — e só isso: o destino é o da
    /// conexão que `transporte` já é, decidido pelo gate antes daqui.
    ///
    /// `agora` é o relógio em segundos desde 1970 — zero é "não se sabe", e
    /// o aperto nem começa —, e `semente`, 32 bytes de entropia nova para
    /// esta conexão: ver o cabeçalho do pacote.
    pub fn conectar(
        transporte: T,
        nome: &str,
        ancoras: &Ancoras,
        agora: u64,
        semente: [u8; 32],
    ) -> Result<Sessao<T>, Falha> {
        if agora == 0 {
            return Err(Falha::SemRelogio);
        }
        let nome = ServerName::try_from(nome)
            .map_err(|_| Falha::Nome)?
            .to_owned();
        acaso::semear(semente);
        let mut config = ClientConfig::builder_with_details(
            Arc::new(provedor::provedor()),
            Arc::new(provedor::Relogio(agora)),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Falha::Interna)?
        .with_root_certificates(ancoras.0.clone())
        .with_no_client_auth();
        // Sem retomada: uma sessão não deixa estado para a seguinte, e
        // cada aperto confere o certificado de novo.
        config.resumption = Resumption::disabled();
        let conexao = UnbufferedClientConnection::new(Arc::new(config), nome)
            .map_err(|e| Falha::do_rustls(&e))?;
        let mut sessao = Sessao {
            conexao,
            transporte,
            entrada: Apagavel(vec![0u8; ENTRADA]),
            usados: 0,
            saida: Vec::new(),
            claro: Apagavel(Vec::new()),
            par_fechou: false,
            fechou: false,
            quebrada: None,
        };
        match sessao.aperto() {
            Ok(()) => Ok(sessao),
            Err(f) => {
                // Uma recusa do TLS — o certificado, o protocolo — vai ao
                // par como alerta, se der. Uma do transporte, não: o gate
                // ou a rede já disseram não, e mandar mais seria pedir de
                // novo o que foi recusado.
                if !matches!(f, Falha::Transporte(_)) {
                    sessao.avisar();
                }
                Err(f)
            }
        }
    }

    /// A suíte negociada, como o TLS a escreve.
    pub fn suite(&self) -> Option<&'static str> {
        self.conexao
            .negotiated_cipher_suite()
            .and_then(|s| s.suite().as_str())
    }

    /// O grupo da troca de chaves negociado.
    pub fn grupo(&self) -> Option<&'static str> {
        self.conexao
            .negotiated_key_exchange_group()
            .and_then(|g| g.name().as_str())
    }

    /// Manda `dados` inteiros, cifrados, em registros de até
    /// [`CLARO_POR_REGISTRO`] bytes de texto.
    pub fn mandar(&mut self, dados: &[u8]) -> Result<(), Falha> {
        let r = self.mandar_sem_registro(dados);
        self.registrar(r)
    }

    fn mandar_sem_registro(&mut self, dados: &[u8]) -> Result<(), Falha> {
        if let Some(f) = self.quebrada {
            return Err(f);
        }
        if self.fechou {
            return Err(Falha::Interna);
        }
        if dados.is_empty() {
            return Ok(());
        }
        loop {
            match self.volta(Pedido::Cifrar(dados))? {
                Volta::Mandou => return Ok(()),
                Volta::Falta => self.encher()?,
                Volta::Fechada => return Err(Falha::Interrompida),
                Volta::Pronta | Volta::Fechou | Volta::Leu | Volta::Andou | Volta::ParFechou => {}
            }
        }
    }

    /// Guarda a falha que acabou com a sessão — ver [`Sessao::quebrada`].
    fn registrar<R>(&mut self, r: Result<R, Falha>) -> Result<R, Falha> {
        if let Err(f) = r {
            self.quebrada.get_or_insert(f);
        }
        r
    }

    /// Recebe o texto que o par mandou, até `destino.len()` bytes,
    /// esperando por ele. `Ok(0)`: o par fechou com `close_notify`, e tudo
    /// que ele mandou já foi entregue. O par que fecha a conexão **sem**
    /// `close_notify` é [`Falha::Interrompida`]: o que chegou pode estar
    /// cortado, e quem lê precisa saber.
    pub fn receber(&mut self, destino: &mut [u8]) -> Result<usize, Falha> {
        let r = self.receber_sem_registro(destino);
        self.registrar(r)
    }

    fn receber_sem_registro(&mut self, destino: &mut [u8]) -> Result<usize, Falha> {
        if let Some(f) = self.quebrada {
            return Err(f);
        }
        loop {
            if !self.claro.0.is_empty() {
                let n = destino.len().min(self.claro.0.len());
                destino[..n].copy_from_slice(&self.claro.0[..n]);
                let resto = self.claro.0.len() - n;
                self.claro.0.copy_within(n.., 0);
                self.claro.0[resto..].zeroize();
                self.claro.0.truncate(resto);
                return Ok(n);
            }
            if self.par_fechou {
                return Ok(0);
            }
            match self.volta(Pedido::Nada)? {
                Volta::Pronta | Volta::Falta => self.encher()?,
                Volta::Fechada => return Ok(0),
                Volta::Mandou | Volta::Fechou | Volta::Leu | Volta::Andou | Volta::ParFechou => {}
            }
        }
    }

    /// Fecha: manda `close_notify` e devolve o transporte, para quem chamou
    /// fechar a conexão de baixo. Não espera o `close_notify` do par — o
    /// TLS 1.3 deixa cada lado fechar o seu sentido.
    pub fn fechar(mut self) -> Result<T, Falha> {
        if let Some(f) = self.quebrada {
            return Err(f);
        }
        if !self.fechou {
            loop {
                match self.volta(Pedido::Fechar)? {
                    Volta::Fechou | Volta::Fechada => break,
                    Volta::Falta => self.encher()?,
                    Volta::Pronta
                    | Volta::Mandou
                    | Volta::Leu
                    | Volta::Andou
                    | Volta::ParFechou => {}
                }
            }
        }
        let Sessao { transporte, .. } = self;
        Ok(transporte)
    }

    /// O aperto: voltas até a conexão aceitar dados.
    fn aperto(&mut self) -> Result<(), Falha> {
        loop {
            match self.volta(Pedido::Nada)? {
                Volta::Pronta => return Ok(()),
                Volta::Falta => self.encher()?,
                Volta::Leu | Volta::Andou | Volta::Mandou | Volta::Fechou => {}
                Volta::ParFechou | Volta::Fechada => return Err(Falha::Interrompida),
            }
        }
    }

    /// Manda ao par, se der, o alerta que o `rustls` deixou na fila quando
    /// recusou o aperto. Sem garantia: o par pode já ter ido.
    ///
    /// A máquina que falhou repete a falha a cada registro que ainda esteja
    /// na entrada — o resto do voo do servidor, que chegou junto com o
    /// certificado recusado —, e só chega a transmitir a fila de saída
    /// quando a entrada acaba. Uma volta que falha e consome um registro é
    /// progresso; uma que falha sem consumir nada, não.
    fn avisar(&mut self) {
        for _ in 0..VOLTAS_DO_ALERTA {
            let antes = self.usados;
            match self.volta(Pedido::Nada) {
                Ok(Volta::Andou) => {}
                Err(Falha::Transporte(_)) => break,
                Err(_) if self.usados < antes => {}
                _ => break,
            }
        }
    }

    /// Mais bytes do par, no fim do buffer de entrada.
    fn encher(&mut self) -> Result<(), Falha> {
        // O `rustls` recusa o registro maior que o permitido assim que lê
        // o cabeçalho dele: o buffer, que cabe o maior e mais uma leitura,
        // não enche sem um registro inteiro dentro.
        if self.usados == self.entrada.0.len() {
            return Err(Falha::Aperto);
        }
        let n = self
            .transporte
            .receber(&mut self.entrada.0[self.usados..])?;
        if n == 0 {
            return Err(Falha::Interrompida);
        }
        self.usados += n;
        Ok(())
    }

    /// Uma volta da máquina, e a E/S que ela pede.
    fn volta(&mut self, pedido: Pedido<'_>) -> Result<Volta, Falha> {
        let Sessao {
            conexao,
            transporte,
            entrada,
            usados,
            saida,
            claro,
            par_fechou,
            fechou,
            quebrada: _,
        } = self;
        let UnbufferedStatus { mut discard, state } =
            conexao.process_tls_records(&mut entrada.0[..*usados]);
        let resultado = match state {
            Err(e) => Err(Falha::do_rustls(&e)),
            Ok(ConnectionState::ReadTraffic(mut ler)) => {
                let mut r = Ok(Volta::Leu);
                while let Some(registro) = ler.next_record() {
                    match registro {
                        Ok(AppDataRecord {
                            discard: mais,
                            payload,
                        }) => {
                            discard += mais;
                            claro.0.extend_from_slice(payload);
                        }
                        Err(e) => {
                            r = Err(Falha::do_rustls(&e));
                            break;
                        }
                    }
                }
                r
            }
            Ok(ConnectionState::EncodeTlsData(mut codificar)) => {
                escrever(saida, |b| codificar.encode(b).map_err(Grande::de_codificar))
                    .map(|()| Volta::Andou)
            }
            Ok(ConnectionState::TransmitTlsData(transmitir)) => {
                let r = transporte.mandar(saida);
                saida.clear();
                transmitir.done();
                r.map(|()| Volta::Andou)
            }
            Ok(ConnectionState::BlockedHandshake) => Ok(Volta::Falta),
            Ok(ConnectionState::WriteTraffic(mut cifrar)) => match pedido {
                Pedido::Nada => Ok(Volta::Pronta),
                Pedido::Cifrar(dados) => dados
                    .chunks(CLARO_POR_REGISTRO)
                    .try_for_each(|pedaco| {
                        escrever(saida, |b| {
                            cifrar.encrypt(pedaco, b).map_err(Grande::de_cifrar)
                        })
                    })
                    .and_then(|()| transporte.mandar(saida))
                    .map(|()| {
                        saida.clear();
                        Volta::Mandou
                    }),
                Pedido::Fechar => escrever(saida, |b| {
                    cifrar.queue_close_notify(b).map_err(Grande::de_cifrar)
                })
                .and_then(|()| transporte.mandar(saida))
                .map(|()| {
                    saida.clear();
                    *fechou = true;
                    Volta::Fechou
                }),
            },
            Ok(ConnectionState::PeerClosed) => {
                *par_fechou = true;
                Ok(Volta::ParFechou)
            }
            Ok(ConnectionState::Closed) => Ok(Volta::Fechada),
            // Os dados antecipados são do servidor, e o resto é de versões
            // futuras do `rustls`: nenhum chega a um cliente deste perfil.
            Ok(_) => Err(Falha::Aperto),
        };
        // O descarte: o que a volta processou sai da frente do buffer, e o
        // fim que ficou vago — onde pode ter ficado texto decifrado — é
        // apagado.
        if discard > 0 {
            let resto = *usados - discard;
            entrada.0.copy_within(discard..*usados, 0);
            entrada.0[resto..*usados].zeroize();
            *usados = resto;
        }
        resultado
    }
}

/// O buffer de saída não coube: o tamanho que precisava.
enum Grande {
    Precisa(usize),
    Outra(Falha),
}

impl Grande {
    fn de_codificar(e: EncodeError) -> Grande {
        match e {
            EncodeError::InsufficientSize(i) => Grande::Precisa(i.required_size),
            _ => Grande::Outra(Falha::Interna),
        }
    }

    fn de_cifrar(e: EncryptError) -> Grande {
        match e {
            EncryptError::InsufficientSize(i) => Grande::Precisa(i.required_size),
            _ => Grande::Outra(Falha::Interna),
        }
    }
}

/// Escreve no fim de `saida` o que `f` escreve, crescendo o buffer se ele
/// não couber — uma vez: o `rustls` diz o tamanho que precisa.
fn escrever(
    saida: &mut Vec<u8>,
    mut f: impl FnMut(&mut [u8]) -> Result<usize, Grande>,
) -> Result<(), Falha> {
    let inicio = saida.len();
    // Um registro inteiro de folga: o caso comum cabe na primeira.
    saida.resize(inicio + 4096, 0);
    match f(&mut saida[inicio..]) {
        Ok(n) => {
            saida.truncate(inicio + n);
            Ok(())
        }
        Err(Grande::Precisa(tamanho)) => {
            saida.resize(inicio + tamanho, 0);
            match f(&mut saida[inicio..]) {
                Ok(n) => {
                    saida.truncate(inicio + n);
                    Ok(())
                }
                Err(_) => {
                    saida.truncate(inicio);
                    Err(Falha::Interna)
                }
            }
        }
        Err(Grande::Outra(falha)) => {
            saida.truncate(inicio);
            Err(falha)
        }
    }
}
