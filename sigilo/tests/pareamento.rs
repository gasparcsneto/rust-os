//! A cerimônia de pareamento sobre o aperto de verdade.
//!
//! - O resumo do aperto com o prólogo da cerimônia é o que o Noise define:
//!   o `snow`, outra implementação, chega ao mesmo, nos dois papéis — e é
//!   desse resumo que saem os códigos de conferência e o identificador da
//!   relação.
//! - Um vetor fixo: as estáticas, as efêmeras, o desafio e o nonce fixos
//!   dão o mesmo resumo, os mesmos códigos e o mesmo identificador, sempre.
//!   Mudar o prólogo, a carga ou uma efêmera muda tudo.

use politica::pareamento::{codigos, compromisso, relacao, texto_do_codigo};
use sigilo::{Iniciador, Respondedor};

/// O iniciante (o A, que conhece o endereço) e o que aceita (o B).
const A: [u8; 32] = [0xa5; 32];
const B: [u8; 32] = [0x5a; 32];
/// As efêmeras, o nonce do A e o desafio da janela do B.
const EA: [u8; 32] = [0x01; 32];
const EB: [u8; 32] = [0x02; 32];
const N: [u8; 32] = [0x09; 32];
const W: [u8; 16] = [0x07; 16];

const PADRAO: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// A carga da primeira mensagem: o compromisso com o nonce e o desafio da
/// janela.
fn carga() -> String {
    format!(
        r#"{{"commit":"{}","janela":"{}"}}"#,
        sigilo::hex_de(&compromisso(&N)),
        sigilo::hex_de(&W)
    )
}

/// O aperto entre os dois lados do `sigilo`, com `prologo`: devolve o
/// resumo de cada lado e a carga que o B leu.
fn aperto(prologo: &[u8], ea: [u8; 32]) -> ([u8; 32], [u8; 32], Vec<u8>) {
    let mut a = vec![0u8; 1024];
    let mut b = vec![0u8; 1024];
    let (n, aguardando) = Iniciador::novo(prologo, &A, &sigilo::publica_de(&B))
        .escrever(ea, carga().as_bytes(), &mut a)
        .unwrap();
    let (m, recebido) = Respondedor::novo(prologo, &B).ler(&a[..n], &mut b).unwrap();
    let lida = b[..m].to_vec();
    assert_eq!(recebido.remota(), sigilo::publica_de(&A));
    let (n, t_b) = recebido.escrever(EB, b"", &mut a).unwrap();
    let (_, t_a) = aguardando.ler(&a[..n], &mut b).unwrap();
    (t_a.resumo_do_aperto(), t_b.resumo_do_aperto(), lida)
}

/// O vetor fixo da cerimônia. O resumo foi tirado desta implementação, e o
/// caso seguinte o confere contra o `snow`; o compromisso, os códigos e o
/// identificador foram conferidos por fora, com outro BLAKE2s (o `hashlib`
/// do Python), a partir do resumo e do nonce.
#[test]
fn o_vetor_fixo_da_cerimonia() {
    let (h_a, h_b, lida) = aperto(sigilo::PROLOGO_DO_PAREAMENTO, EA);
    assert_eq!(h_a, h_b);
    assert_eq!(lida, carga().as_bytes());
    assert_eq!(sigilo::hex_de(&compromisso(&N)), C_DO_VETOR);
    assert_eq!(sigilo::hex_de(&h_a), H_DO_VETOR);
    let (k_b, k_a) = codigos(&h_a, &N);
    assert_eq!(texto_do_codigo(k_b), K_B_DO_VETOR);
    assert_eq!(texto_do_codigo(k_a), K_A_DO_VETOR);
    assert_eq!(sigilo::hex_de(&relacao(&h_a, &N)), R_DO_VETOR);
    // Outra efêmera, ou outro prólogo: outro resumo, outros códigos.
    let (h2, _, _) = aperto(sigilo::PROLOGO_DO_PAREAMENTO, [0x03; 32]);
    assert_ne!(h2, h_a);
    assert_ne!(codigos(&h2, &N), (k_b, k_a));
    let (h3, _, _) = aperto(sigilo::PROLOGO_DO_ENLACE, EA);
    assert_ne!(h3, h_a);
    assert_ne!(relacao(&h3, &N), relacao(&h_a, &N));
}

const H_DO_VETOR: &str = "99ea2d2eb3b22b3739083a9c61e3d06c819607b29d91ecec5c9c39d951fb1f95";
const K_B_DO_VETOR: &str = "6546 1822";
const K_A_DO_VETOR: &str = "1138 5187";
const R_DO_VETOR: &str = "df1371d438281371cebca1079834677a";
const C_DO_VETOR: &str = "cde43b437186a6ccaf93c72005226dd2b87ea4af2bf202de85823c2875fa531a";

/// O resumo da cerimônia é o do Noise: o `snow` chega ao mesmo, como
/// respondedor e como iniciador.
#[test]
fn o_resumo_da_cerimonia_e_o_do_snow() {
    // O `sigilo` inicia, o `snow` aceita.
    let mut resp = snow::Builder::new(PADRAO.parse().unwrap())
        .prologue(sigilo::PROLOGO_DO_PAREAMENTO)
        .local_private_key(&B)
        .fixed_ephemeral_key_for_testing_only(&EB)
        .build_responder()
        .unwrap();
    let mut a = vec![0u8; 1024];
    let mut b = vec![0u8; 1024];
    let (n, aguardando) =
        Iniciador::novo(sigilo::PROLOGO_DO_PAREAMENTO, &A, &sigilo::publica_de(&B))
            .escrever(EA, carga().as_bytes(), &mut a)
            .unwrap();
    let m = resp.read_message(&a[..n], &mut b).unwrap();
    assert_eq!(&b[..m], carga().as_bytes());
    let n = resp.write_message(b"", &mut a).unwrap();
    let h_snow = resp.get_handshake_hash().to_vec();
    let (_, t) = aguardando.ler(&a[..n], &mut b).unwrap();
    assert_eq!(t.resumo_do_aperto().to_vec(), h_snow);
    assert_eq!(sigilo::hex_de(&h_snow), H_DO_VETOR);

    // O `snow` inicia, o `sigilo` aceita.
    let mut ini = snow::Builder::new(PADRAO.parse().unwrap())
        .prologue(sigilo::PROLOGO_DO_PAREAMENTO)
        .local_private_key(&A)
        .remote_public_key(&sigilo::publica_de(&B))
        .fixed_ephemeral_key_for_testing_only(&EA)
        .build_initiator()
        .unwrap();
    let n = ini.write_message(carga().as_bytes(), &mut a).unwrap();
    let (_, recebido) = Respondedor::novo(sigilo::PROLOGO_DO_PAREAMENTO, &B)
        .ler(&a[..n], &mut b)
        .unwrap();
    let (n, t) = recebido.escrever(EB, b"", &mut a).unwrap();
    ini.read_message(&a[..n], &mut b).unwrap();
    assert_eq!(
        t.resumo_do_aperto().to_vec(),
        ini.get_handshake_hash().to_vec()
    );
    assert_eq!(sigilo::hex_de(&t.resumo_do_aperto()), H_DO_VETOR);
}
