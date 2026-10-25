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
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::rc::Rc;
use std::sync::{Arc, Mutex, OnceLock};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SignatureAlgorithm,
};
use rustls::crypto::{CryptoProvider, ring as anel};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection, SignatureScheme};
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

/// Uma chave RSA dos testes, de `bits` bits e expoente `e`, gerada de uma
/// semente — a mesma chave a cada rodada —, e uma vez só por processo:
/// gerar uma chave RSA é procurar primos, e os testes usam a mesma em vários
/// papéis. O *ring* não gera chave RSA.
fn rsa_de_teste(bits: usize, e: u64, semente: u8) -> rsa::RsaPrivateKey {
    /// As chaves já geradas: pelo tamanho, pelo expoente e pela semente.
    type Chaves = Mutex<HashMap<(usize, u64, u8), rsa::RsaPrivateKey>>;
    static CHAVES: OnceLock<Chaves> = OnceLock::new();
    let mut chaves = CHAVES.get_or_init(Default::default).lock().unwrap();
    chaves
        .entry((bits, e, semente))
        .or_insert_with(|| {
            use chacha20::rand_core::SeedableRng;
            let mut gerador = chacha20::ChaCha20Rng::from_seed([semente; 32]);
            rsa::RsaPrivateKey::new_with_exp(&mut gerador, bits, e.into()).unwrap()
        })
        .clone()
}

/// O par do `rcgen` — sobre o *ring* — de uma chave RSA dos testes, com o
/// hash de `alg`.
fn par_rsa(chave: &rsa::RsaPrivateKey, alg: &'static SignatureAlgorithm) -> KeyPair {
    use rsa::pkcs8::EncodePrivateKey;
    let der = chave.to_pkcs8_der().unwrap();
    KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(der.as_bytes()), alg).unwrap()
}

/// O par do `rcgen` para `alg`, de chave nova; o RSA, de 2048 bits, da
/// semente dada.
fn par(alg: &'static SignatureAlgorithm, semente: u8) -> KeyPair {
    let rsa = [
        &rcgen::PKCS_RSA_SHA256,
        &rcgen::PKCS_RSA_SHA384,
        &rcgen::PKCS_RSA_SHA512,
    ];
    if rsa.contains(&alg) {
        par_rsa(&rsa_de_teste(2048, 65537, semente), alg)
    } else {
        KeyPair::generate_for(alg).unwrap()
    }
}

/// Quem assina um certificado nos testes: a chave pública, o algoritmo que
/// o certificado diz, e a conta da assinatura. Pelo `rcgen` — sobre o
/// *ring* — quando ele sabe; pelo RustCrypto para o que ele recusa: a
/// chave RSA fora do perfil, e a curva com o hash da outra.
struct Assinante {
    publica: Vec<u8>,
    alg: &'static SignatureAlgorithm,
    conta: Conta,
}

/// A conta de uma assinatura: da mensagem, a assinatura.
type Conta = Box<dyn Fn(&[u8]) -> Vec<u8>>;

impl rcgen::PublicKeyData for Assinante {
    fn der_bytes(&self) -> &[u8] {
        &self.publica
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.alg
    }
}

impl rcgen::SigningKey for Assinante {
    fn sign(&self, mensagem: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok((self.conta)(mensagem))
    }
}

impl Assinante {
    fn do_par(par: KeyPair) -> Assinante {
        use rcgen::PublicKeyData;
        Assinante {
            publica: par.der_bytes().to_vec(),
            alg: par.algorithm(),
            conta: Box::new(move |m| rcgen::SigningKey::sign(&par, m).unwrap()),
        }
    }

    fn de(alg: &'static SignatureAlgorithm, semente: u8) -> Assinante {
        Assinante::do_par(par(alg, semente))
    }

    /// RSA pelo `rsa`, com o PKCS#1 v1.5 e o hash que `alg` diz — de
    /// qualquer tamanho e expoente, até os que o *ring* recusa.
    fn rsa(chave: rsa::RsaPrivateKey, alg: &'static SignatureAlgorithm) -> Assinante {
        use rsa::pkcs1::EncodeRsaPublicKey;
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        let publica = chave.to_public_key().to_pkcs1_der().unwrap().into_vec();
        let conta: Conta = if alg == &rcgen::PKCS_RSA_SHA256 {
            let k = SigningKey::<sha2::Sha256>::new(chave);
            Box::new(move |m| k.sign(m).to_vec())
        } else if alg == &rcgen::PKCS_RSA_SHA384 {
            let k = SigningKey::<sha2::Sha384>::new(chave);
            Box::new(move |m| k.sign(m).to_vec())
        } else if alg == &rcgen::PKCS_RSA_SHA512 {
            let k = SigningKey::<sha2::Sha512>::new(chave);
            Box::new(move |m| k.sign(m).to_vec())
        } else {
            panic!("{alg:?} nao e RSA")
        };
        Assinante {
            publica,
            alg,
            conta,
        }
    }

    /// ECDSA P-384 pelo `p384`: com o SHA-384 e `ecdsa-with-SHA384`, como
    /// deve; ou, `cruzado`, com o SHA-256 e `ecdsa-with-SHA256` — a curva
    /// com o hash da P-256, que o *ring* aceita e o perfil não.
    fn p384(chave: &p384::ecdsa::SigningKey, cruzado: bool) -> Assinante {
        use p384::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::Digest;
        let chave = chave.clone();
        Assinante {
            publica: chave
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
            alg: if cruzado {
                &rcgen::PKCS_ECDSA_P256_SHA256
            } else {
                &rcgen::PKCS_ECDSA_P384_SHA384
            },
            conta: Box::new(move |m| {
                let resumo = if cruzado {
                    sha2::Sha256::digest(m).to_vec()
                } else {
                    sha2::Sha384::digest(m).to_vec()
                };
                let a: p384::ecdsa::Signature = chave.sign_prehash(&resumo).unwrap();
                a.to_der().as_bytes().to_vec()
            }),
        }
    }

    /// ECDSA P-256 pelo `p256`, como [`Assinante::p384`]: o cruzado é com
    /// o SHA-384 e `ecdsa-with-SHA384`.
    fn p256(chave: &p256::ecdsa::SigningKey, cruzado: bool) -> Assinante {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use sha2::Digest;
        let chave = chave.clone();
        Assinante {
            publica: chave
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
            alg: if cruzado {
                &rcgen::PKCS_ECDSA_P384_SHA384
            } else {
                &rcgen::PKCS_ECDSA_P256_SHA256
            },
            conta: Box::new(move |m| {
                let resumo = if cruzado {
                    sha2::Sha384::digest(m).to_vec()
                } else {
                    sha2::Sha256::digest(m).to_vec()
                };
                let a: p256::ecdsa::Signature = chave.sign_prehash(&resumo).unwrap();
                a.to_der().as_bytes().to_vec()
            }),
        }
    }
}

/// Uma chave pública qualquer no certificado — a de um formato torto —,
/// com o algoritmo dela.
struct Publica {
    der: Vec<u8>,
    alg: &'static SignatureAlgorithm,
}

impl rcgen::PublicKeyData for Publica {
    fn der_bytes(&self) -> &[u8] {
        &self.der
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.alg
    }
}

/// Uma autoridade — a raiz ou um intermediário —: o certificado dela,
/// quem assina em nome dela, e os certificados que o servidor manda
/// depois da folha (os intermediários, dela até a raiz, sem a raiz).
struct Raiz {
    certificado: Certificate,
    emissor: Issuer<'static, Assinante>,
    acima: Vec<CertificateDer<'static>>,
}

/// O que uma autoridade tem no certificado, válida de `de` a `ate` (anos).
fn params_de_autoridade(nome: &str, de: i32, ate: i32) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, nome);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p.not_before = rcgen::date_time_ymd(de, 1, 1);
    p.not_after = rcgen::date_time_ymd(ate, 1, 1);
    p
}

/// Uma raiz que se assina com `chave` e assina os de baixo com
/// `assinante` — a mesma chave, quase sempre.
fn raiz_que_assina_com(chave: &Assinante, assinante: Assinante, nome: &str) -> Raiz {
    let p = params_de_autoridade(nome, 2024, 2040);
    Raiz {
        certificado: p.self_signed(chave).unwrap(),
        emissor: Issuer::new(p, assinante),
        acima: Vec::new(),
    }
}

fn raiz_de(assinante: Assinante, nome: &str) -> Raiz {
    let p = params_de_autoridade(nome, 2024, 2040);
    Raiz {
        certificado: p.self_signed(&assinante).unwrap(),
        emissor: Issuer::new(p, assinante),
        acima: Vec::new(),
    }
}

fn raiz_com(alg: &'static SignatureAlgorithm, nome: &str) -> Raiz {
    raiz_de(Assinante::de(alg, 10), nome)
}

fn raiz() -> Raiz {
    raiz_com(&rcgen::PKCS_ECDSA_P256_SHA256, "Raiz da bancada do Duke")
}

impl Raiz {
    fn pem(&self) -> String {
        self.certificado.pem()
    }

    /// Um intermediário assinado por esta autoridade, válido de `de` a
    /// `ate`.
    fn intermediario_de(&self, assinante: Assinante, nome: &str, de: i32, ate: i32) -> Raiz {
        let p = params_de_autoridade(nome, de, ate);
        let certificado = p.signed_by(&assinante, &self.emissor).unwrap();
        let mut acima = vec![certificado.der().clone()];
        acima.extend(self.acima.iter().cloned());
        Raiz {
            certificado,
            emissor: Issuer::new(p, assinante),
            acima,
        }
    }

    fn intermediario(&self, assinante: Assinante, nome: &str) -> Raiz {
        self.intermediario_de(assinante, nome, 2024, 2040)
    }
}

/// Uma folha para `nomes`, assinada por uma autoridade, valendo de `de` a
/// `ate` (anos): a cadeia que o servidor manda — a folha e os
/// intermediários — e a chave dele.
struct Folha {
    cadeia: Vec<CertificateDer<'static>>,
    chave: PrivateKeyDer<'static>,
}

fn params_de_folha(nomes: &[&str], de: i32, ate: i32) -> CertificateParams {
    let mut p =
        CertificateParams::new(nomes.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
    p.distinguished_name.push(DnType::CommonName, nomes[0]);
    p.not_before = rcgen::date_time_ymd(de, 1, 1);
    p.not_after = rcgen::date_time_ymd(ate, 1, 1);
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    p
}

/// A folha com a chave `chave` — a do certificado e a do servidor.
fn folha_de(raiz: &Raiz, chave: KeyPair, nomes: &[&str], de: i32, ate: i32) -> Folha {
    let certificado = params_de_folha(nomes, de, ate)
        .signed_by(&chave, &raiz.emissor)
        .unwrap();
    let mut cadeia = vec![certificado.der().clone()];
    cadeia.extend(raiz.acima.iter().cloned());
    Folha {
        cadeia,
        chave: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(chave.serialize_der())),
    }
}

fn folha_com(
    raiz: &Raiz,
    alg: &'static SignatureAlgorithm,
    nomes: &[&str],
    de: i32,
    ate: i32,
) -> Folha {
    folha_de(raiz, par(alg, 30), nomes, de, ate)
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

/// O ALPN: o cliente oferece, o servidor escolhe — ou não escolhe nada.
#[test]
fn o_protocolo_que_o_servidor_escolhe() {
    let raiz = raiz();
    let oferta: &[&[u8]] = &[b"h2", b"http/1.1"];
    for (do_servidor, oferecidos, escolhido) in [
        (
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            oferta,
            Some(&b"h2"[..]),
        ),
        (vec![b"http/1.1".to_vec()], oferta, Some(&b"http/1.1"[..])),
        // O servidor sem ALPN: nenhum.
        (vec![], oferta, None),
        // O cliente que não oferece: nenhum, mesmo com o servidor querendo.
        (vec![b"h2".to_vec()], &[][..], None),
    ] {
        let mut c = config(folha(&raiz));
        c.alpn_protocols = do_servidor.clone();
        let mut s = Sessao::conectar_com_protocolos(
            Bancada::nova(c),
            NOME,
            &ancoras(&raiz),
            AGORA,
            SEMENTE,
            oferecidos,
        )
        .unwrap();
        assert_eq!(s.protocolo(), escolhido, "{do_servidor:?}");
        // E a conversa segue como sempre.
        eco(&mut s, b"depois do alpn");
    }
    // Nada em comum: o servidor recusa o aperto, e o cliente ouve a recusa
    // como uma falha do TLS.
    let mut c = config(folha(&raiz));
    c.alpn_protocols = vec![b"spdy/3".to_vec()];
    let r = Sessao::conectar_com_protocolos(
        Bancada::nova(c),
        NOME,
        &ancoras(&raiz),
        AGORA,
        SEMENTE,
        oferta,
    );
    assert_eq!(r.err(), Some(Falha::Aperto));
    // A conexão sem oferta continua sem protocolo.
    let s = conectar(Bancada::nova(config(folha(&raiz))), &ancoras(&raiz)).unwrap();
    assert_eq!(s.protocolo(), None);
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

/// A preferência do cliente: o servidor que segue a ordem dele — o do
/// `rustls`, por padrão — escolhe o ChaCha20-Poly1305, o mais rápido em
/// software; o que segue a própria escolhe pela dele, e o cliente aceita
/// qualquer uma do perfil.
#[test]
fn a_preferencia_do_cliente_e_o_chacha20() {
    let raiz = raiz();
    let mut s = conectar(Bancada::nova(config(folha(&raiz))), &ancoras(&raiz)).unwrap();
    assert_eq!(s.suite(), Some("TLS13_CHACHA20_POLY1305_SHA256"));
    eco(&mut s, b"pela ordem do cliente");
    let provedor = CryptoProvider {
        cipher_suites: vec![
            anel::cipher_suite::TLS13_AES_256_GCM_SHA384,
            anel::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ],
        ..anel::default_provider()
    };
    let mut c = config_com(provedor, folha(&raiz));
    c.ignore_client_order = true;
    let mut s = conectar(Bancada::nova(c), &ancoras(&raiz)).unwrap();
    assert_eq!(s.suite(), Some("TLS13_AES_256_GCM_SHA384"));
    eco(&mut s, b"pela ordem do servidor");
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

// ---------------------------------------------------------------------------
// As cadeias das autoridades públicas: P-384 e RSA
// ---------------------------------------------------------------------------

impl Folha {
    fn copia(&self) -> Folha {
        Folha {
            cadeia: self.cadeia.clone(),
            chave: self.chave.clone_key(),
        }
    }
}

/// A chave do servidor restrita a um esquema do `CertificateVerify`: o
/// *ring* escolheria o primeiro que sabe — com uma chave RSA, o PSS com
/// SHA-512. Com ela cada esquema é exercitado, e o aperto só fecha se o
/// cliente o ofereceu.
#[derive(Debug)]
struct SoEsquema {
    chave: Arc<dyn rustls::sign::SigningKey>,
    esquema: SignatureScheme,
}

impl rustls::sign::SigningKey for SoEsquema {
    fn choose_scheme(
        &self,
        oferecidos: &[SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        if oferecidos.contains(&self.esquema) {
            self.chave.choose_scheme(&[self.esquema])
        } else {
            None
        }
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.chave.algorithm()
    }
}

/// A chave privada do servidor, pelo *ring*.
fn chave_do_ring(chave: &PrivateKeyDer<'static>) -> Arc<dyn rustls::sign::SigningKey> {
    anel::default_provider()
        .key_provider
        .load_private_key(chave.clone_key())
        .unwrap()
}

/// O servidor com a cadeia e a chave dadas, sem conferir uma contra a
/// outra nem ler o certificado: o caminho da chave que não é a do
/// certificado, e do certificado torto.
fn config_resolvida(
    cadeia: Vec<CertificateDer<'static>>,
    chave: Arc<dyn rustls::sign::SigningKey>,
) -> ServerConfig {
    #[derive(Debug)]
    struct Fixa(Arc<CertifiedKey>);
    impl ResolvesServerCert for Fixa {
        fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }
    let mut c = ServerConfig::builder_with_provider(Arc::new(anel::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixa(Arc::new(CertifiedKey::new(cadeia, chave)))));
    c.send_tls13_tickets = 0;
    c
}

/// O servidor da folha, assinando o `CertificateVerify` só com `esquema`.
fn config_so(folha: Folha, esquema: SignatureScheme) -> ServerConfig {
    let chave = Arc::new(SoEsquema {
        chave: chave_do_ring(&folha.chave),
        esquema,
    });
    config_resolvida(folha.cadeia, chave)
}

/// O mesmo aperto com o cliente do `rustls` sobre o *ring* — o mesmo
/// verificador de cadeias, com a lista de algoritmos de lá, mais larga que
/// a do perfil —, confiando em `raiz`. Mostra que uma cadeia recusada aqui
/// é recusada pelo algoritmo ou pela chave, e não por outro defeito dela.
fn pelo_ring(raiz: &Raiz, config: ServerConfig) -> Result<(), rustls::Error> {
    #[derive(Debug)]
    struct Agora;
    impl rustls::time_provider::TimeProvider for Agora {
        fn current_time(&self) -> Option<UnixTime> {
            Some(UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                AGORA,
            )))
        }
    }
    let mut raizes = rustls::RootCertStore::empty();
    raizes.add(raiz.certificado.der().clone()).unwrap();
    let cliente = rustls::ClientConfig::builder_with_details(
        Arc::new(anel::default_provider()),
        Arc::new(Agora),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(raizes)
    .with_no_client_auth();
    let mut c = rustls::ClientConnection::new(Arc::new(cliente), NOME.try_into().unwrap()).unwrap();
    let mut s = ServerConnection::new(Arc::new(config)).unwrap();
    while c.is_handshaking() {
        let mut andou = false;
        while c.wants_write() {
            let mut bytes = Vec::new();
            c.write_tls(&mut bytes).unwrap();
            let mut leitor = &bytes[..];
            while !leitor.is_empty() {
                s.read_tls(&mut leitor).unwrap();
                s.process_new_packets()?;
            }
            andou = true;
        }
        while s.wants_write() {
            let mut bytes = Vec::new();
            s.write_tls(&mut bytes).unwrap();
            let mut leitor = &bytes[..];
            while !leitor.is_empty() {
                c.read_tls(&mut leitor).unwrap();
                c.process_new_packets()?;
            }
            andou = true;
        }
        assert!(andou, "o aperto com o ring parou");
    }
    Ok(())
}

/// A raiz RSA de 4096 bits dos testes — a das raízes RSA das autoridades
/// públicas —, assinando com o hash de `alg`.
fn raiz_rsa(alg: &'static SignatureAlgorithm) -> Raiz {
    raiz_de(
        Assinante::do_par(par_rsa(&rsa_de_teste(4096, 65537, 1), alg)),
        "Raiz RSA da bancada",
    )
}

/// Uma cadeia P-384 inteira — a raiz, um intermediário e a folha —, com o
/// `CertificateVerify` da folha em `ecdsa_secp384r1_sha384`. E a raiz P-384
/// assinando uma folha P-256: a P-384 com o SHA-384 na cadeia, a P-256 no
/// aperto.
#[test]
fn a_cadeia_p384_vale() {
    let raiz = raiz_com(&rcgen::PKCS_ECDSA_P384_SHA384, "Raiz P-384");
    let meio = raiz.intermediario(
        Assinante::de(&rcgen::PKCS_ECDSA_P384_SHA384, 0),
        "Intermediario P-384",
    );
    let f = folha_com(&meio, &rcgen::PKCS_ECDSA_P384_SHA384, &[NOME], 2025, 2030);
    assert_eq!(f.cadeia.len(), 2);
    let mut s = conectar(
        Bancada::nova(config_so(f, SignatureScheme::ECDSA_NISTP384_SHA384)),
        &ancoras(&raiz),
    )
    .unwrap();
    eco(&mut s, b"p-384");

    let f = folha_com(&raiz, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
    let mut s = conectar(
        Bancada::nova(config_so(f, SignatureScheme::ECDSA_NISTP256_SHA256)),
        &ancoras(&raiz),
    )
    .unwrap();
    eco(&mut s, b"p-384 sobre p-256");
}

/// RSA: a raiz de 4096 bits, o intermediário de 3072 e a folha de 2048; a
/// cadeia em PKCS#1 v1.5 com cada SHA-2, e o `CertificateVerify` da folha em
/// PSS com cada SHA-2 — o servidor restrito a um esquema por vez.
#[test]
fn cada_rsa_do_perfil_vale() {
    for (alg, esquema) in [
        (&rcgen::PKCS_RSA_SHA256, SignatureScheme::RSA_PSS_SHA256),
        (&rcgen::PKCS_RSA_SHA384, SignatureScheme::RSA_PSS_SHA384),
        (&rcgen::PKCS_RSA_SHA512, SignatureScheme::RSA_PSS_SHA512),
    ] {
        let raiz = raiz_rsa(alg);
        let meio = raiz.intermediario(
            Assinante::do_par(par_rsa(&rsa_de_teste(3072, 65537, 2), alg)),
            "Intermediario RSA",
        );
        let f = folha_de(
            &meio,
            par_rsa(&rsa_de_teste(2048, 65537, 3), alg),
            &[NOME],
            2025,
            2030,
        );
        let mut s =
            conectar(Bancada::nova(config_so(f, esquema)), &ancoras(&raiz)).expect("{esquema:?}");
        eco(&mut s, b"rsa");
    }
}

/// A cadeia como a das autoridades públicas, que mistura os dois: a raiz
/// RSA de 4096 bits, o intermediário P-384 assinado por ela em PKCS#1 v1.5
/// e a folha P-256 assinada por ele com o SHA-384 — a forma da cadeia ECDSA
/// da Let's Encrypt pela raiz X1. E a da Google Trust Services: a raiz
/// P-384, o intermediário P-256, a folha P-256. Sem o intermediário, a
/// cadeia não chega à raiz.
#[test]
fn a_cadeia_mista_das_autoridades_publicas_vale() {
    let raiz = raiz_rsa(&rcgen::PKCS_RSA_SHA256);
    let meio = raiz.intermediario(
        Assinante::de(&rcgen::PKCS_ECDSA_P384_SHA384, 0),
        "Intermediario P-384",
    );
    let f = folha_com(&meio, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
    let so_a_folha = Folha {
        cadeia: f.cadeia[..1].to_vec(),
        chave: f.chave.clone_key(),
    };
    let mut s = conectar(Bancada::nova(config(f)), &ancoras(&raiz)).unwrap();
    eco(&mut s, b"misto");
    let r = conectar(Bancada::nova(config(so_a_folha)), &ancoras(&raiz));
    assert_eq!(r.err(), Some(Falha::NaoConfiavel));

    let raiz = raiz_com(&rcgen::PKCS_ECDSA_P384_SHA384, "Raiz P-384");
    let meio = raiz.intermediario(
        Assinante::de(&rcgen::PKCS_ECDSA_P256_SHA256, 0),
        "Intermediario P-256",
    );
    let f = folha_com(&meio, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
    let mut s = conectar(Bancada::nova(config(f)), &ancoras(&raiz)).unwrap();
    eco(&mut s, b"p-384 e p-256");
}

/// A cadeia que não fecha: o intermediário de outra raiz, e um certificado
/// que não é de autoridade — uma folha — assinando outro.
#[test]
fn a_cadeia_quebrada_e_recusada() {
    let raiz = raiz_rsa(&rcgen::PKCS_RSA_SHA256);
    let outra = raiz_de(
        Assinante::do_par(par_rsa(
            &rsa_de_teste(2048, 65537, 4),
            &rcgen::PKCS_RSA_SHA256,
        )),
        "Outra raiz RSA",
    );
    let meio = outra.intermediario(
        Assinante::de(&rcgen::PKCS_ECDSA_P384_SHA384, 0),
        "Intermediario P-384",
    );
    let f = folha_com(&meio, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
    let r = conectar(Bancada::nova(config(f)), &ancoras(&raiz));
    assert_eq!(r.err(), Some(Falha::NaoConfiavel));

    // A folha `falsa.duke`, da raiz, no lugar de um intermediário.
    let assinante = Assinante::de(&rcgen::PKCS_ECDSA_P384_SHA384, 0);
    let p = params_de_folha(&["falsa.duke"], 2025, 2030);
    let certificado = p.signed_by(&assinante, &raiz.emissor).unwrap();
    let falsa = Raiz {
        acima: vec![certificado.der().clone()],
        certificado,
        emissor: Issuer::new(p, assinante),
    };
    let f = folha_com(&falsa, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
    let r = conectar(Bancada::nova(config(f)), &ancoras(&raiz));
    assert_eq!(r.err(), Some(Falha::NaoConfiavel));
}

/// A assinatura que não confere, nas cadeias novas: a raiz falsa com o
/// mesmo nome e outra chave, P-384 e RSA; um bit trocado na assinatura de
/// um certificado; e o `CertificateVerify` de outra chave, P-384 e RSA.
#[test]
fn a_assinatura_que_nao_confere_nas_cadeias_novas_e_recusada() {
    let confiavel = raiz_com(&rcgen::PKCS_ECDSA_P384_SHA384, "Raiz da bancada do Duke");
    let falsa = raiz_com(&rcgen::PKCS_ECDSA_P384_SHA384, "Raiz da bancada do Duke");
    let f = folha_com(&falsa, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
    let r = conectar(Bancada::nova(config(f)), &ancoras(&confiavel));
    assert_eq!(r.err(), Some(Falha::NaoConfiavel));

    let confiavel = raiz_rsa(&rcgen::PKCS_RSA_SHA256);
    let falsa = raiz_de(
        Assinante::do_par(par_rsa(
            &rsa_de_teste(2048, 65537, 4),
            &rcgen::PKCS_RSA_SHA256,
        )),
        "Raiz RSA da bancada",
    );
    let f = folha_com(&falsa, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
    let r = conectar(Bancada::nova(config(f)), &ancoras(&confiavel));
    assert_eq!(r.err(), Some(Falha::NaoConfiavel));

    // Um bit trocado no fim de cada certificado — o fim da assinatura —:
    // a do intermediário, em PKCS#1 v1.5 pela raiz RSA, e a da folha, em
    // ECDSA P-384 pelo intermediário.
    let meio = confiavel.intermediario(
        Assinante::de(&rcgen::PKCS_ECDSA_P384_SHA384, 0),
        "Intermediario P-384",
    );
    let f = folha_com(&meio, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
    for qual in [0, 1] {
        let mut cadeia = f.cadeia.clone();
        let mut der = cadeia[qual].to_vec();
        let ultimo = der.len() - 1;
        der[ultimo] ^= 0x01;
        cadeia[qual] = CertificateDer::from(der);
        let r = conectar(
            Bancada::nova(config_resolvida(cadeia, chave_do_ring(&f.chave))),
            &ancoras(&confiavel),
        );
        assert_eq!(r.err(), Some(Falha::NaoConfiavel), "certificado {qual}");
    }

    // A cadeia certa, e o aperto assinado por outra chave.
    for (verdadeira, outra) in [
        (
            par(&rcgen::PKCS_ECDSA_P384_SHA384, 0),
            par(&rcgen::PKCS_ECDSA_P384_SHA384, 0),
        ),
        (
            par(&rcgen::PKCS_RSA_SHA256, 3),
            par(&rcgen::PKCS_RSA_SHA256, 4),
        ),
    ] {
        let f = folha_de(&meio, verdadeira, &[NOME], 2025, 2030);
        let chave = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(outra.serialize_der()));
        let r = conectar(
            Bancada::nova(config_resolvida(f.cadeia, chave_do_ring(&chave))),
            &ancoras(&confiavel),
        );
        assert_eq!(r.err(), Some(Falha::NaoConfiavel));
    }
}

/// A validade nas cadeias novas: a folha P-384 vencida, a RSA que ainda não
/// vale, e o intermediário vencido sobre uma folha em dia — cada
/// certificado da cadeia tem a sua validade conferida.
#[test]
fn a_validade_nas_cadeias_novas() {
    let raiz = raiz_rsa(&rcgen::PKCS_RSA_SHA256);
    let vencida = folha_com(&raiz, &rcgen::PKCS_ECDSA_P384_SHA384, &[NOME], 2020, 2021);
    let r = conectar(Bancada::nova(config(vencida)), &ancoras(&raiz));
    assert_eq!(r.err(), Some(Falha::Vencido));

    let futura = folha_de(
        &raiz,
        par_rsa(&rsa_de_teste(2048, 65537, 3), &rcgen::PKCS_RSA_SHA256),
        &[NOME],
        2030,
        2035,
    );
    let r = conectar(Bancada::nova(config(futura)), &ancoras(&raiz));
    assert_eq!(r.err(), Some(Falha::AindaNaoValido));

    let meio = raiz.intermediario_de(
        Assinante::de(&rcgen::PKCS_ECDSA_P384_SHA384, 0),
        "Intermediario vencido",
        2020,
        2021,
    );
    let f = folha_com(&meio, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
    let r = conectar(Bancada::nova(config(f)), &ancoras(&raiz));
    assert_eq!(r.err(), Some(Falha::Vencido));
}

/// O nome errado nas cadeias novas: a folha RSA de outro nome, e a P-384 de
/// um curinga um nível abaixo do nome pedido.
#[test]
fn o_nome_errado_nas_cadeias_novas_e_recusado() {
    let raiz = raiz_rsa(&rcgen::PKCS_RSA_SHA256);
    for f in [
        folha_de(
            &raiz,
            par_rsa(&rsa_de_teste(2048, 65537, 3), &rcgen::PKCS_RSA_SHA256),
            &["outro.duke"],
            2025,
            2030,
        ),
        folha_com(
            &raiz,
            &rcgen::PKCS_ECDSA_P384_SHA384,
            &["*.bancada.duke"],
            2025,
            2030,
        ),
    ] {
        let r = conectar(Bancada::nova(config(f)), &ancoras(&raiz));
        assert_eq!(r.err(), Some(Falha::NomeErrado));
    }
}

/// A autoridade que o servidor apresenta não vira âncora: a cadeia com a
/// raiz dele no fim — uma raiz RSA que o programa não tem — é recusada.
/// Posta nas âncoras ao lado da da bancada, a mesma cadeia fecha: a
/// confiança é a das âncoras dadas, e nada se aprende pela rede.
#[test]
fn a_raiz_que_o_servidor_manda_nao_vira_ancora() {
    let da_bancada = raiz();
    let dele = raiz_de(
        Assinante::do_par(par_rsa(
            &rsa_de_teste(2048, 65537, 4),
            &rcgen::PKCS_RSA_SHA256,
        )),
        "Raiz do servidor",
    );
    let meio = dele.intermediario(
        Assinante::de(&rcgen::PKCS_ECDSA_P384_SHA384, 0),
        "Intermediario P-384",
    );
    let mut f = folha_com(&meio, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
    f.cadeia.push(dele.certificado.der().clone());
    let r = conectar(Bancada::nova(config(f.copia())), &ancoras(&da_bancada));
    assert_eq!(r.err(), Some(Falha::NaoConfiavel));
    // E de novo: a primeira recusa não deixou nada guardado.
    let r = conectar(Bancada::nova(config(f.copia())), &ancoras(&da_bancada));
    assert_eq!(r.err(), Some(Falha::NaoConfiavel));

    let duas = format!("{}{}", da_bancada.pem(), dele.pem());
    let duas = Ancoras::de_pem(duas.as_bytes()).unwrap();
    let mut s = conectar(Bancada::nova(config(f)), &duas).unwrap();
    eco(&mut s, b"com a raiz dada");
}

/// O algoritmo fora do perfil: a raiz P-384 que assina a folha com o
/// SHA-256, e a P-256 que assina com o SHA-384 — a curva com o hash da
/// outra. O cliente do *ring* aceita as duas cadeias; o do Duke, não.
#[test]
fn a_curva_com_o_hash_da_outra_e_recusada() {
    let k384 = p384::ecdsa::SigningKey::from_slice(&[11u8; 48]).unwrap();
    let k256 = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
    for raiz in [
        raiz_que_assina_com(
            &Assinante::p384(&k384, false),
            Assinante::p384(&k384, true),
            "Raiz P-384",
        ),
        raiz_que_assina_com(
            &Assinante::p256(&k256, false),
            Assinante::p256(&k256, true),
            "Raiz P-256",
        ),
    ] {
        let f = folha_com(&raiz, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
        assert_eq!(pelo_ring(&raiz, config(f.copia())), Ok(()));
        let r = conectar(Bancada::nova(config(f)), &ancoras(&raiz));
        assert_eq!(r.err(), Some(Falha::NaoConfiavel));
    }
    // A mesma raiz assinando como deve: fecha nos dois.
    let raiz = raiz_de(Assinante::p384(&k384, false), "Raiz P-384");
    let f = folha_com(&raiz, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
    assert_eq!(pelo_ring(&raiz, config(f.copia())), Ok(()));
    assert!(conectar(Bancada::nova(config(f)), &ancoras(&raiz)).is_ok());
}

// O DER de uma chave torta.

fn tamanho_der(n: usize) -> Vec<u8> {
    match n {
        0..=0x7f => vec![n as u8],
        0x80..=0xff => vec![0x81, n as u8],
        _ => vec![0x82, (n >> 8) as u8, n as u8],
    }
}

fn elemento(etiqueta: u8, conteudo: &[u8]) -> Vec<u8> {
    let mut der = vec![etiqueta];
    der.extend(tamanho_der(conteudo.len()));
    der.extend_from_slice(conteudo);
    der
}

/// A chave pública fora do perfil, numa cadeia que de resto confere: a raiz
/// RSA de 1024 bits; a de expoente 3, que o *ring* aceita; a folha RSA com o
/// módulo em DER fora da forma mínima; e a folha P-256 com o ponto
/// comprimido.
#[test]
fn a_chave_publica_fora_do_perfil_e_recusada() {
    for (chave, o_ring_aceita) in [
        (rsa_de_teste(1024, 65537, 6), false),
        (rsa_de_teste(2048, 3, 7), true),
    ] {
        let raiz = raiz_de(
            Assinante::rsa(chave, &rcgen::PKCS_RSA_SHA256),
            "Raiz RSA fora do perfil",
        );
        let f = folha_com(&raiz, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
        assert_eq!(pelo_ring(&raiz, config(f.copia())).is_ok(), o_ring_aceita);
        let r = conectar(Bancada::nova(config(f)), &ancoras(&raiz));
        assert_eq!(r.err(), Some(Falha::NaoConfiavel));
    }

    // A folha RSA com um zero a mais na frente do módulo. O servidor assina
    // com a chave certa.
    let raiz = raiz();
    let chave = rsa_de_teste(2048, 65537, 3);
    let n = rsa::traits::PublicKeyParts::n(&chave).to_be_bytes();
    let modulo = elemento(0x02, &[&[0x00, 0x00][..], &n].concat());
    let expoente = elemento(0x02, &[0x01, 0x00, 0x01]);
    let torta = Publica {
        der: elemento(0x30, &[modulo, expoente].concat()),
        alg: &rcgen::PKCS_RSA_SHA256,
    };
    let certificado = params_de_folha(&[NOME], 2025, 2030)
        .signed_by(&torta, &raiz.emissor)
        .unwrap();
    let par = par_rsa(&chave, &rcgen::PKCS_RSA_SHA256);
    let privada = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(par.serialize_der()));
    let r = conectar(
        Bancada::nova(config_resolvida(
            vec![certificado.der().clone()],
            chave_do_ring(&privada),
        )),
        &ancoras(&raiz),
    );
    assert_eq!(r.err(), Some(Falha::NaoConfiavel));

    // A folha P-256 com o ponto comprimido: o x, e a paridade do y.
    let par = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let ponto = par.public_key_raw();
    let mut comprimido = vec![0x02 | (ponto[64] & 1)];
    comprimido.extend_from_slice(&ponto[1..33]);
    let comprimida = Publica {
        der: comprimido,
        alg: &rcgen::PKCS_ECDSA_P256_SHA256,
    };
    let certificado = params_de_folha(&[NOME], 2025, 2030)
        .signed_by(&comprimida, &raiz.emissor)
        .unwrap();
    let privada = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(par.serialize_der()));
    let r = conectar(
        Bancada::nova(config_resolvida(
            vec![certificado.der().clone()],
            chave_do_ring(&privada),
        )),
        &ancoras(&raiz),
    );
    assert_eq!(r.err(), Some(Falha::NaoConfiavel));
}

/// O certificado torto — a folha ou o intermediário cortado no fim, ou com
/// um byte a mais —: recusado como não confiável, sem aceitar o que se leu
/// até ali.
#[test]
fn o_certificado_torto_e_recusado() {
    let raiz = raiz_rsa(&rcgen::PKCS_RSA_SHA256);
    let meio = raiz.intermediario(
        Assinante::de(&rcgen::PKCS_ECDSA_P384_SHA384, 0),
        "Intermediario P-384",
    );
    let f = folha_com(&meio, &rcgen::PKCS_ECDSA_P256_SHA256, &[NOME], 2025, 2030);
    for qual in [0, 1] {
        for cortado in [true, false] {
            let mut cadeia = f.cadeia.clone();
            let mut der = cadeia[qual].to_vec();
            if cortado {
                der.truncate(der.len() - 10);
            } else {
                der.push(0);
            }
            cadeia[qual] = CertificateDer::from(der);
            let r = conectar(
                Bancada::nova(config_resolvida(cadeia, chave_do_ring(&f.chave))),
                &ancoras(&raiz),
            );
            assert_eq!(r.err(), Some(Falha::NaoConfiavel), "{qual} {cortado}");
        }
    }
}

/// A cadeia longa demais: seis intermediários ainda fecham — o limite do
/// `webpki` —, sete não. O limite é do verificador, e nenhuma cadeia
/// pública chega perto dele.
#[test]
fn a_cadeia_longa_demais_e_recusada() {
    let raiz = raiz();
    let com = |quantos: usize| {
        let mut meio: Vec<Raiz> = Vec::new();
        for i in 0..quantos {
            let acima = meio.last().unwrap_or(&raiz);
            let novo = acima.intermediario(
                Assinante::de(&rcgen::PKCS_ECDSA_P256_SHA256, 0),
                &format!("Intermediario {i}"),
            );
            meio.push(novo);
        }
        let f = folha_com(
            meio.last().unwrap_or(&raiz),
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &[NOME],
            2025,
            2030,
        );
        assert_eq!(f.cadeia.len(), quantos + 1);
        conectar(Bancada::nova(config(f)), &ancoras(&raiz)).map(|_| ())
    };
    assert_eq!(com(6), Ok(()));
    assert_eq!(com(7), Err(Falha::NaoConfiavel));
}

/// A recusa do transporte no meio da sessão — a do gate — passa adiante
/// sem tradução também nas cadeias novas: o algoritmo da cadeia não muda
/// quem decide o uso da conexão.
#[test]
fn a_recusa_do_transporte_vale_igual_nas_cadeias_novas() {
    let p384 = raiz_com(&rcgen::PKCS_ECDSA_P384_SHA384, "Raiz P-384");
    let rsa = raiz_rsa(&rcgen::PKCS_RSA_SHA256);
    for (raiz, f) in [
        (
            &p384,
            folha_com(&p384, &rcgen::PKCS_ECDSA_P384_SHA384, &[NOME], 2025, 2030),
        ),
        (
            &rsa,
            folha_de(
                &rsa,
                par_rsa(&rsa_de_teste(2048, 65537, 3), &rcgen::PKCS_RSA_SHA256),
                &[NOME],
                2025,
                2030,
            ),
        ),
    ] {
        let mut b = Bancada::nova(config(f));
        b.recusar_a_partir_de = Some(2);
        let mut s = conectar(b, &ancoras(raiz)).unwrap();
        let r = s.mandar(b"depois da recusa");
        assert_eq!(r, Err(Falha::Transporte(Codigo::de("DENY_RESOURCE"))));
    }
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

/// Cada falha do TLS tem o código dela — um `TLS_*`, ou o de quem falta
/// aqui —, e nenhum é do gate: uma recusa do programa não se lê como
/// `ALLOW`, nem como uma recusa da política. O código do gate só passa pelo
/// transporte, como veio.
#[test]
fn os_codigos_do_tls_nao_sao_do_gate() {
    for (falha, codigo) in [
        (Falha::SemAcaso, "ENTROPY_UNAVAILABLE"),
        (Falha::SemRelogio, "CLOCK_UNAVAILABLE"),
        (Falha::Nome, "INVALID_REQUEST"),
        (Falha::Ancoras, "TLS_ANCHORS_INVALID"),
        (Falha::NaoConfiavel, "TLS_UNTRUSTED"),
        (Falha::NomeErrado, "TLS_NAME_MISMATCH"),
        (Falha::Vencido, "TLS_EXPIRED"),
        (Falha::AindaNaoValido, "TLS_NOT_YET_VALID"),
        (Falha::Aperto, "TLS_HANDSHAKE_FAILED"),
        (Falha::Adulterado, "TLS_TAMPERED"),
        (Falha::Interrompida, "TLS_INTERRUPTED"),
        (Falha::SemResposta, "TLS_UNAVAILABLE"),
        (Falha::Interna, "TECHNICAL_ERROR"),
    ] {
        assert_eq!(falha.codigo(), codigo);
        assert!(
            codigo != "ALLOW" && !codigo.starts_with("DENY_"),
            "{codigo}"
        );
    }
    let recusa = Falha::Transporte(Codigo::de("DENY_RESOURCE"));
    assert_eq!(recusa.codigo(), "DENY_RESOURCE");
}
