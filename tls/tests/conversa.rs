//! A conversa do cliente TLS do Duke com o servidor do `rustls` — com o
//! provedor do *ring*, outra implementação de cada primitiva: as cifras,
//! os resumos, o HKDF, as trocas de chave e as assinaturas daqui só fecham o
//! aperto se fizerem a mesma conta que as de lá.
//!
//! O servidor roda no mesmo fio, sem rede: o transporte dos testes entrega
//! a ele o que o cliente manda, e devolve ao cliente o que ele escreve. É
//! também o lugar de mentir — adulterar um registro, fechar sem aviso,
//! recusar como o gate recusaria.

use std::cell::{Cell, RefCell};
use std::io::{ErrorKind, Read, Write};
use std::rc::Rc;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SignatureAlgorithm,
};
use rustls::crypto::{CryptoProvider, ring as anel};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection};
use tls::{Ancoras, Codigo, Falha, Sessao, Transporte};

/// O nome da bancada.
const NOME: &str = "bancada.duke";

/// 2026-01-01, em segundos desde 1970: dentro da validade dos certificados
/// dos testes.
const AGORA: u64 = 1_767_225_600;

/// Uma semente qualquer: nos testes o que importa é haver uma.
const SEMENTE: [u8; 32] = [0x5e; 32];

// ---------------------------------------------------------------------------
// Os certificados
// ---------------------------------------------------------------------------

/// Uma raiz: o certificado e quem assina com ela.
struct Raiz {
    emissor: CertifiedIssuer<'static, KeyPair>,
}

fn raiz_com(alg: &'static SignatureAlgorithm, nome: &str) -> Raiz {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, nome);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = rcgen::date_time_ymd(2024, 1, 1);
    p.not_after = rcgen::date_time_ymd(2040, 1, 1);
    let chave = KeyPair::generate_for(alg).unwrap();
    Raiz {
        emissor: CertifiedIssuer::self_signed(p, chave).unwrap(),
    }
}

fn raiz() -> Raiz {
    raiz_com(&rcgen::PKCS_ECDSA_P256_SHA256, "Raiz da bancada do Duke")
}

impl Raiz {
    fn pem(&self) -> String {
        self.emissor.pem()
    }
}

/// Uma folha para `nomes`, assinada pela raiz, valendo de `de` a `ate`
/// (anos).
struct Folha {
    cadeia: Vec<CertificateDer<'static>>,
    chave: PrivateKeyDer<'static>,
}

fn folha_com(
    raiz: &Raiz,
    alg: &'static SignatureAlgorithm,
    nomes: &[&str],
    de: i32,
    ate: i32,
) -> Folha {
    let mut p =
        CertificateParams::new(nomes.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
    p.distinguished_name.push(DnType::CommonName, nomes[0]);
    p.not_before = rcgen::date_time_ymd(de, 1, 1);
    p.not_after = rcgen::date_time_ymd(ate, 1, 1);
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let chave = KeyPair::generate_for(alg).unwrap();
    let certificado = p.signed_by(&chave, &raiz.emissor).unwrap();
    Folha {
        cadeia: vec![certificado.der().clone()],
        chave: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(chave.serialize_der())),
    }
}

fn folha(raiz: &Raiz) -> Folha {
    folha_com(raiz, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030)
}

fn ancoras(raiz: &Raiz) -> Ancoras {
    Ancoras::de_pem(raiz.pem().as_bytes()).unwrap()
}

// ---------------------------------------------------------------------------
// O servidor
// ---------------------------------------------------------------------------

fn config_com(provedor: CryptoProvider, folha: Folha) -> ServerConfig {
    let mut c = ServerConfig::builder_with_provider(Arc::new(provedor))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(folha.cadeia, folha.chave)
        .unwrap();
    // Sem tíquetes de retomada: o primeiro registro depois do aperto é o
    // eco, e os testes de adulteração sabem onde mexer.
    c.send_tls13_tickets = 0;
    c
}

fn config(folha: Folha) -> ServerConfig {
    config_com(anel::default_provider(), folha)
}

/// O que a bancada viu, para o teste conferir depois que a sessão — e o
/// transporte dentro dela — já se foi.
#[derive(Default)]
struct Painel {
    /// Quantas vezes o cliente tentou mandar, contando as recusadas.
    tentativas: Cell<usize>,
    /// Por que o servidor recusou, se recusou: o alerta do cliente aparece
    /// aqui.
    erro_do_servidor: RefCell<Option<rustls::Error>>,
}

/// O servidor de eco, e o transporte que o liga ao cliente.
struct Bancada {
    servidor: ServerConnection,
    painel: Rc<Painel>,
    /// O que o servidor escreveu e o cliente ainda não leu.
    para_o_cliente: Vec<u8>,
    /// Quantos bytes o cliente mandou, ao todo.
    recebidos: usize,
    /// Inverter um bit no próximo registro do servidor depois do aperto.
    adulterar: bool,
    /// Fechar a conexão de baixo, sem `close_notify`, depois do eco.
    cortar_depois_do_eco: bool,
    /// Mandar `close_notify` depois do eco.
    avisar_depois_do_eco: bool,
    /// O transporte recusa como o gate recusaria, a partir do envio de
    /// número `n` (contando do zero).
    recusar_a_partir_de: Option<usize>,
    envios: usize,
    /// O transporte de baixo acabou: o servidor fechou a conexão.
    fechada: bool,
}

impl Bancada {
    fn nova(config: ServerConfig) -> Bancada {
        Bancada {
            servidor: ServerConnection::new(Arc::new(config)).unwrap(),
            painel: Rc::new(Painel::default()),
            para_o_cliente: Vec::new(),
            recebidos: 0,
            adulterar: false,
            cortar_depois_do_eco: false,
            avisar_depois_do_eco: false,
            recusar_a_partir_de: None,
            envios: 0,
            fechada: false,
        }
    }

    /// O texto que chegou ao servidor volta ao cliente. Verdadeiro se veio
    /// algum.
    fn ecoar(&mut self) -> bool {
        let mut buf = vec![0u8; 1 << 16];
        let mut ecoou = false;
        loop {
            match self.servidor.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    self.servidor.writer().write_all(&buf[..n]).unwrap();
                    ecoou = true;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        ecoou
    }

    /// O que o servidor quer mandar, para o cliente.
    fn coletar(&mut self) {
        while self.servidor.wants_write() {
            let mut pedaco = Vec::new();
            self.servidor.write_tls(&mut pedaco).unwrap();
            if self.adulterar && !self.servidor.is_handshaking() && !pedaco.is_empty() {
                let ultimo = pedaco.len() - 1;
                pedaco[ultimo] ^= 0x01;
                self.adulterar = false;
            }
            self.para_o_cliente.extend_from_slice(&pedaco);
        }
    }
}

impl Transporte for Bancada {
    fn mandar(&mut self, dados: &[u8]) -> Result<(), Falha> {
        self.painel.tentativas.set(self.painel.tentativas.get() + 1);
        if self.recusar_a_partir_de.is_some_and(|n| self.envios >= n) {
            return Err(Falha::Transporte(Codigo::de("DENY_RESOURCE")));
        }
        self.envios += 1;
        self.recebidos += dados.len();
        let mut leitor = dados;
        let mut ecoou = false;
        while !leitor.is_empty() {
            self.servidor.read_tls(&mut leitor).unwrap();
            if let Err(e) = self.servidor.process_new_packets() {
                // O servidor recusou: o alerta dele vai para o cliente.
                *self.painel.erro_do_servidor.borrow_mut() = Some(e);
                self.coletar();
                return Ok(());
            }
            // O eco, a cada leitura: o que chegou volta, e os buffers do
            // servidor — o do texto que chegou e o do que sai — não enchem.
            ecoou |= self.ecoar();
            self.coletar();
        }
        if ecoou && self.avisar_depois_do_eco {
            self.servidor.send_close_notify();
        }
        self.coletar();
        if ecoou && self.cortar_depois_do_eco {
            self.fechada = true;
        }
        Ok(())
    }

    fn receber(&mut self, destino: &mut [u8]) -> Result<usize, Falha> {
        if self.para_o_cliente.is_empty() {
            if self.fechada {
                return Ok(0);
            }
            // Na rede o cliente esperaria; aqui ninguém mais vai escrever.
            return Err(Falha::Transporte(Codigo::de("SEM_RESPOSTA")));
        }
        let n = destino.len().min(self.para_o_cliente.len());
        destino[..n].copy_from_slice(&self.para_o_cliente[..n]);
        self.para_o_cliente.drain(..n);
        Ok(n)
    }
}

fn conectar(bancada: Bancada, ancoras: &Ancoras) -> Result<Sessao<Bancada>, Falha> {
    Sessao::conectar(bancada, NOME, ancoras, AGORA, SEMENTE)
}

/// Manda `texto`, lê o eco inteiro, e confere.
fn eco(sessao: &mut Sessao<Bancada>, texto: &[u8]) {
    sessao.mandar(texto).unwrap();
    let mut voltou = Vec::new();
    let mut buf = vec![0u8; 3000];
    while voltou.len() < texto.len() {
        let n = sessao.receber(&mut buf).unwrap();
        assert!(n > 0, "o par fechou no meio do eco");
        voltou.extend_from_slice(&buf[..n]);
    }
    assert_eq!(voltou, texto);
}

// ---------------------------------------------------------------------------
// O caminho de ida e volta
// ---------------------------------------------------------------------------

#[test]
fn o_aperto_fecha_e_o_eco_volta() {
    let raiz = raiz();
    let mut s = conectar(Bancada::nova(config(folha(&raiz))), &ancoras(&raiz)).unwrap();
    eco(&mut s, b"o segredo da bancada");
    let bancada = s.fechar().unwrap();
    // O cliente mandou o `close_notify`, e o servidor o leu.
    assert!(bancada.recebidos > 0);
}

/// Cada suíte do perfil, com o servidor restrito a ela: a cifra e o resumo
/// daqui fazem a mesma conta que os do *ring*.
#[test]
fn cada_suite_conversa_com_o_ring() {
    for (suite, nome) in [
        (
            anel::cipher_suite::TLS13_AES_128_GCM_SHA256,
            "TLS13_AES_128_GCM_SHA256",
        ),
        (
            anel::cipher_suite::TLS13_AES_256_GCM_SHA384,
            "TLS13_AES_256_GCM_SHA384",
        ),
        (
            anel::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            "TLS13_CHACHA20_POLY1305_SHA256",
        ),
    ] {
        let raiz = raiz();
        let provedor = CryptoProvider {
            cipher_suites: vec![suite],
            ..anel::default_provider()
        };
        let mut s = conectar(
            Bancada::nova(config_com(provedor, folha(&raiz))),
            &ancoras(&raiz),
        )
        .unwrap();
        assert_eq!(s.suite(), Some(nome));
        eco(&mut s, b"cada suite");
        // Mais que um registro do cliente, e registros grandes do servidor.
        eco(&mut s, &vec![0xa5; 20_000]);
    }
}

/// Cada grupo de troca de chaves. O cliente manda a parte do X25519 no
/// `ClientHello`; com o servidor só em P-256, o servidor pede outra
/// (`HelloRetryRequest`), e o cliente a gera — o caminho do segundo aperto.
#[test]
fn cada_grupo_troca_chaves_com_o_ring() {
    for (grupo, nome) in [
        (anel::kx_group::X25519, "X25519"),
        (anel::kx_group::SECP256R1, "secp256r1"),
    ] {
        let raiz = raiz();
        let provedor = CryptoProvider {
            kx_groups: vec![grupo],
            ..anel::default_provider()
        };
        let mut s = conectar(
            Bancada::nova(config_com(provedor, folha(&raiz))),
            &ancoras(&raiz),
        )
        .unwrap();
        assert_eq!(s.grupo(), Some(nome));
        eco(&mut s, b"cada grupo");
    }
}

/// Uma cadeia Ed25519: a raiz e a folha.
#[test]
fn a_cadeia_ed25519_vale() {
    let raiz = raiz_com(&rcgen::PKCS_ED25519, "Raiz Ed25519 da bancada");
    let f = folha_com(&raiz, &rcgen::PKCS_ED25519, &[NOME], 2025, 2030);
    let mut s = conectar(Bancada::nova(config(f)), &ancoras(&raiz)).unwrap();
    eco(&mut s, b"ed25519");
}

/// Muito texto nos dois sentidos: registros do cliente cortados em
/// `CLARO_POR_REGISTRO`, registros do servidor de até 16 KiB chegando em
/// pedaços.
#[test]
fn muito_texto_vai_e_volta() {
    let raiz = raiz();
    let mut s = conectar(Bancada::nova(config(folha(&raiz))), &ancoras(&raiz)).unwrap();
    let texto: Vec<u8> = (0..100_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
    eco(&mut s, &texto);
}

/// O par que fecha com `close_notify`: o que ele mandou chega inteiro, e
/// depois a leitura dá zero.
#[test]
fn o_fecho_com_aviso_entrega_tudo_e_depois_zero() {
    let raiz = raiz();
    let mut b = Bancada::nova(config(folha(&raiz)));
    b.avisar_depois_do_eco = true;
    let mut s = conectar(b, &ancoras(&raiz)).unwrap();
    eco(&mut s, b"ultima palavra");
    let mut buf = [0u8; 64];
    assert_eq!(s.receber(&mut buf), Ok(0));
    assert_eq!(s.receber(&mut buf), Ok(0));
}

/// O par que fecha a conexão sem `close_notify`: o que chegou pode estar
/// cortado, e a leitura diz isso — e não zero, que seria o fim limpo.
#[test]
fn o_fecho_sem_aviso_e_interrupcao() {
    let raiz = raiz();
    let mut b = Bancada::nova(config(folha(&raiz)));
    b.cortar_depois_do_eco = true;
    let mut s = conectar(b, &ancoras(&raiz)).unwrap();
    eco(&mut s, b"cortado");
    let mut buf = [0u8; 64];
    assert_eq!(s.receber(&mut buf), Err(Falha::Interrompida));
}

// ---------------------------------------------------------------------------
// O servidor que não é quem diz
// ---------------------------------------------------------------------------

/// O nome errado — e o par fica sabendo: o alerta do cliente chega ao
/// servidor.
#[test]
fn o_nome_errado_e_recusado() {
    let raiz = raiz();
    let f = folha_com(
        &raiz,
        &rcgen::PKCS_ECDSA_P256_SHA256,
        &["outro.duke"],
        2025,
        2030,
    );
    let b = Bancada::nova(config(f));
    let painel = b.painel.clone();
    let r = conectar(b, &ancoras(&raiz));
    assert_eq!(r.err(), Some(Falha::NomeErrado));
    assert_eq!(Falha::NomeErrado.codigo(), "TLS_NAME_MISMATCH");
    assert!(
        matches!(
            *painel.erro_do_servidor.borrow(),
            Some(rustls::Error::AlertReceived(_))
        ),
        "o servidor nao recebeu o alerta: {:?}",
        painel.erro_do_servidor.borrow()
    );
}

#[test]
fn a_raiz_desconhecida_e_recusada() {
    let confiavel = raiz();
    let outra = raiz_com(&rcgen::PKCS_ECDSA_P256_SHA256, "Outra raiz");
    let r = conectar(Bancada::nova(config(folha(&outra))), &ancoras(&confiavel));
    assert_eq!(r.err(), Some(Falha::NaoConfiavel));
}

/// Uma raiz falsa com o **mesmo nome** da confiável, e outra chave: o
/// verificador acha a âncora pelo nome, e só a assinatura denuncia. Uma
/// verificação de assinatura que dissesse sempre sim aceitaria esta folha.
#[test]
fn a_raiz_com_o_mesmo_nome_e_outra_chave_e_recusada() {
    for alg in [&rcgen::PKCS_ECDSA_P256_SHA256, &rcgen::PKCS_ED25519] {
        let confiavel = raiz_com(alg, "Raiz da bancada do Duke");
        let falsa = raiz_com(alg, "Raiz da bancada do Duke");
        let f = folha_com(&falsa, alg, &[NOME], 2025, 2030);
        let r = conectar(Bancada::nova(config(f)), &ancoras(&confiavel));
        assert_eq!(r.err(), Some(Falha::NaoConfiavel));
    }
}

/// O servidor apresenta a cadeia certa, e assina o aperto com outra chave:
/// o `CertificateVerify` não confere. Uma verificação que dissesse sempre
/// sim aceitaria quem não tem a chave do certificado.
#[test]
fn o_certificate_verify_de_outra_chave_e_recusado() {
    #[derive(Debug)]
    struct Mentiroso(Arc<CertifiedKey>);
    impl ResolvesServerCert for Mentiroso {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }
    for alg in [&rcgen::PKCS_ECDSA_P256_SHA256, &rcgen::PKCS_ED25519] {
        let raiz = raiz_com(alg, "Raiz da bancada do Duke");
        let verdadeira = folha_com(&raiz, alg, &[NOME], 2025, 2030);
        let outra = KeyPair::generate_for(alg).unwrap();
        let chave = anel::default_provider()
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                outra.serialize_der(),
            )))
            .unwrap();
        let mut c = ServerConfig::builder_with_provider(Arc::new(anel::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Mentiroso(Arc::new(CertifiedKey::new(
                verdadeira.cadeia,
                chave,
            )))));
        c.send_tls13_tickets = 0;
        let r = conectar(Bancada::nova(c), &ancoras(&raiz));
        assert_eq!(r.err(), Some(Falha::NaoConfiavel), "{alg:?}");
    }
}

#[test]
fn o_vencido_e_o_que_ainda_nao_vale_sao_recusados() {
    let raiz = raiz();
    let vencido = folha_com(&raiz, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2020, 2021);
    let r = conectar(Bancada::nova(config(vencido)), &ancoras(&raiz));
    assert_eq!(r.err(), Some(Falha::Vencido));

    let futuro = folha_com(&raiz, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2030, 2035);
    let r = conectar(Bancada::nova(config(futuro)), &ancoras(&raiz));
    assert_eq!(r.err(), Some(Falha::AindaNaoValido));
}

/// O relógio decide a validade: o mesmo certificado, válido hoje, é
/// vencido para um relógio de 2031 — e quem dá o relógio é quem conecta.
#[test]
fn o_relogio_de_quem_conecta_decide_a_validade() {
    let raiz = raiz();
    let r = Sessao::conectar(
        Bancada::nova(config(folha(&raiz))),
        NOME,
        &ancoras(&raiz),
        1_924_992_000, // 2031-01-01
        SEMENTE,
    );
    assert_eq!(r.err(), Some(Falha::Vencido));
}

/// Sem relógio, o aperto nem começa: nada sai para o par.
#[test]
fn sem_relogio_nada_sai() {
    let raiz = raiz();
    let r = Sessao::conectar(
        Bancada::nova(config(folha(&raiz))),
        NOME,
        &ancoras(&raiz),
        0,
        SEMENTE,
    );
    assert_eq!(r.err(), Some(Falha::SemRelogio));
}

/// Uma cadeia com uma raiz fora do perfil — P-384 — não acha conta que a
/// confira: recusada, e não aceita com menos verificação.
#[test]
fn a_raiz_fora_do_perfil_e_recusada() {
    let raiz = raiz_com(&rcgen::PKCS_ECDSA_P384_SHA384, "Raiz P-384");
    let f = folha_com(&raiz, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
    let r = conectar(Bancada::nova(config(f)), &ancoras(&raiz));
    assert_eq!(r.err(), Some(Falha::NaoConfiavel));
}

// ---------------------------------------------------------------------------
// O par que não fala o protocolo, e o caminho adulterado
// ---------------------------------------------------------------------------

#[test]
fn o_servidor_so_de_tls_1_2_e_recusado() {
    let raiz = raiz();
    let f = folha(&raiz);
    let c = ServerConfig::builder_with_provider(Arc::new(anel::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(f.cadeia, f.chave)
        .unwrap();
    let r = conectar(Bancada::nova(c), &ancoras(&raiz));
    assert_eq!(r.err(), Some(Falha::Aperto));
}

/// Um par que não fala TLS — o eco da bancada devolve o `ClientHello`.
#[test]
fn o_par_que_nao_fala_tls_e_recusado() {
    struct Eco(Vec<u8>);
    impl Transporte for Eco {
        fn mandar(&mut self, dados: &[u8]) -> Result<(), Falha> {
            self.0.extend_from_slice(dados);
            Ok(())
        }
        fn receber(&mut self, destino: &mut [u8]) -> Result<usize, Falha> {
            let n = destino.len().min(self.0.len());
            destino[..n].copy_from_slice(&self.0[..n]);
            self.0.drain(..n);
            Ok(n)
        }
    }
    let raiz = raiz();
    let r = Sessao::conectar(Eco(Vec::new()), NOME, &ancoras(&raiz), AGORA, SEMENTE);
    assert_eq!(r.err(), Some(Falha::Aperto));
}

/// Um bit trocado no caminho, num registro depois do aperto: a etiqueta não
/// confere, e a leitura diz que o registro foi adulterado.
#[test]
fn o_registro_adulterado_e_recusado() {
    let raiz = raiz();
    let mut b = Bancada::nova(config(folha(&raiz)));
    b.adulterar = true;
    let mut s = conectar(b, &ancoras(&raiz)).unwrap();
    s.mandar(b"vai e volta trocado").unwrap();
    let mut buf = [0u8; 64];
    assert_eq!(s.receber(&mut buf), Err(Falha::Adulterado));
    assert_eq!(Falha::Adulterado.codigo(), "TLS_TAMPERED");
}

// ---------------------------------------------------------------------------
// O transporte: a recusa de baixo passa adiante como é
// ---------------------------------------------------------------------------

/// O gate recusa no meio da sessão: a sessão acaba com o código do gate, e
/// não com um do TLS.
#[test]
fn a_recusa_do_transporte_passa_adiante_sem_traducao() {
    let raiz = raiz();
    let mut b = Bancada::nova(config(folha(&raiz)));
    // O aperto do cliente são dois envios: o `ClientHello` e o `Finished`.
    b.recusar_a_partir_de = Some(2);
    let mut s = conectar(b, &ancoras(&raiz)).unwrap();
    let r = s.mandar(b"depois da recusa");
    assert_eq!(r, Err(Falha::Transporte(Codigo::de("DENY_RESOURCE"))));
    assert_eq!(r.unwrap_err().codigo(), "DENY_RESOURCE");
}

/// Depois de uma recusa no meio, a sessão não tem conserto: o registro
/// que não saiu já gastou o número dele. Cada pedido seguinte ouve a mesma
/// recusa — sem nada passar pelo transporte, nem a sessão ficar
/// inconsistente com o par.
#[test]
fn a_sessao_que_falhou_nao_volta() {
    let raiz = raiz();
    let mut b = Bancada::nova(config(folha(&raiz)));
    b.recusar_a_partir_de = Some(2);
    let painel = b.painel.clone();
    let mut s = conectar(b, &ancoras(&raiz)).unwrap();
    let recusa = Falha::Transporte(Codigo::de("DENY_RESOURCE"));
    assert_eq!(s.mandar(b"primeira"), Err(recusa));
    let tentativas = painel.tentativas.get();
    let mut buf = [0u8; 16];
    assert_eq!(s.mandar(b"segunda"), Err(recusa));
    assert_eq!(s.receber(&mut buf), Err(recusa));
    assert_eq!(painel.tentativas.get(), tentativas);
    assert!(matches!(s.fechar(), Err(f) if f == recusa));
}

/// A recusa no aperto: o código do gate, e nada mais sai — nem o alerta,
/// que seria pedir de novo o que foi recusado. O `ClientHello` passa, o
/// `Finished` é recusado, e não há terceira tentativa.
#[test]
fn a_recusa_no_aperto_nao_manda_alerta() {
    let raiz = raiz();
    let mut b = Bancada::nova(config(folha(&raiz)));
    b.recusar_a_partir_de = Some(1);
    let painel = b.painel.clone();
    let r = conectar(b, &ancoras(&raiz));
    assert_eq!(
        r.err(),
        Some(Falha::Transporte(Codigo::de("DENY_RESOURCE")))
    );
    assert_eq!(painel.tentativas.get(), 2);
}

// ---------------------------------------------------------------------------
// O que quem chama dá
// ---------------------------------------------------------------------------

#[test]
fn ancoras_que_nao_se_leem_sao_recusadas() {
    assert!(matches!(Ancoras::de_pem(b""), Err(Falha::Ancoras)));
    assert!(matches!(Ancoras::de_pem(b"lixo"), Err(Falha::Ancoras)));
    let quebrado = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    assert!(matches!(
        Ancoras::de_pem(quebrado.as_bytes()),
        Err(Falha::Ancoras)
    ));
    let duas = format!("{}{}", raiz().pem(), raiz().pem());
    assert_eq!(Ancoras::de_pem(duas.as_bytes()).unwrap().quantas(), 2);
}

#[test]
fn o_nome_que_nao_se_escreve_e_pedido_invalido() {
    let raiz = raiz();
    let r = Sessao::conectar(
        Bancada::nova(config(folha(&raiz))),
        "nome com espaco",
        &ancoras(&raiz),
        AGORA,
        SEMENTE,
    );
    assert_eq!(r.err(), Some(Falha::Nome));
    assert_eq!(Falha::Nome.codigo(), "INVALID_REQUEST");
}

/// O código de fora só passa se for um código: o texto de quem implementa
/// o transporte não vira mensagem arbitrária na saída.
#[test]
fn o_codigo_de_fora_so_passa_se_for_codigo() {
    assert_eq!(Codigo::de("DENY_CONTAINED").como_str(), "DENY_CONTAINED");
    assert_eq!(Codigo::de("").como_str(), "TECHNICAL_ERROR");
    assert_eq!(Codigo::de("deny").como_str(), "TECHNICAL_ERROR");
    assert_eq!(Codigo::de("NAO\nE").como_str(), "TECHNICAL_ERROR");
    assert_eq!(Codigo::de(&"X".repeat(33)).como_str(), "TECHNICAL_ERROR");
}
