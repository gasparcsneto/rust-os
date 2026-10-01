//! O `sigilo` conferido por fora: vetores publicados e uma implementação
//! independente.
//!
//! Uma implementação conversando consigo mesma concorda mesmo errada — os
//! dois lados erram igual. Os casos daqui não dão essa chance:
//!
//! - os **vetores** fixam as chaves, as efêmeras e as cargas, e dizem byte a
//!   byte o que tem de sair. Um deles é da Cacophony, em Haskell;
//! - o **`snow`** é outra implementação do Noise, em Rust, escrita por outras
//!   pessoas. Os casos o põem de um lado e o `sigilo` do outro, nos dois
//!   papéis.

use serde_json::Value;
use sigilo::{Erro, Iniciador, Respondedor, Transporte};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn chave(v: &Value, campo: &str) -> [u8; 32] {
    hex(v[campo].as_str().unwrap()).try_into().unwrap()
}

/// Roda um vetor: o aperto e as mensagens de transporte, conferindo cada
/// texto cifrado. Devolve quantas mensagens conferiu.
fn rodar(v: &Value) -> usize {
    let prologo = hex(v["init_prologue"].as_str().unwrap());
    assert_eq!(prologo, hex(v["resp_prologue"].as_str().unwrap()));
    let mensagens = v["messages"].as_array().unwrap();

    let ini = Iniciador::novo(
        &prologo,
        &chave(v, "init_static"),
        &chave(v, "init_remote_static"),
    );
    let resp = Respondedor::novo(&prologo, &chave(v, "resp_static"));

    // Primeira mensagem: o agente escreve, o texto confere, o Duke lê.
    let carga = hex(mensagens[0]["payload"].as_str().unwrap());
    let esperado = hex(mensagens[0]["ciphertext"].as_str().unwrap());
    let mut saida = vec![0u8; 65_535];
    let (n, aguardando) = ini
        .escrever(chave(v, "init_ephemeral"), &carga, &mut saida)
        .unwrap();
    assert_eq!(
        hex_str(&saida[..n]),
        hex_str(&esperado),
        "primeira mensagem"
    );
    let mut lida = vec![0u8; 65_535];
    let (m, recebido) = resp.ler(&esperado, &mut lida).unwrap();
    assert_eq!(&lida[..m], &carga[..]);
    assert_eq!(
        recebido.remota(),
        sigilo::publica_de(&chave(v, "init_static")),
        "o Duke aprendeu a chave do agente"
    );

    // Segunda: o Duke responde.
    let carga = hex(mensagens[1]["payload"].as_str().unwrap());
    let esperado = hex(mensagens[1]["ciphertext"].as_str().unwrap());
    let (n, mut t_resp) = recebido
        .escrever(chave(v, "resp_ephemeral"), &carga, &mut saida)
        .unwrap();
    assert_eq!(hex_str(&saida[..n]), hex_str(&esperado), "segunda mensagem");
    let (m, mut t_ini) = aguardando.ler(&esperado, &mut lida).unwrap();
    assert_eq!(&lida[..m], &carga[..]);

    if let Some(h) = v["handshake_hash"].as_str() {
        assert_eq!(hex_str(&t_ini.resumo_do_aperto()), h);
        assert_eq!(hex_str(&t_resp.resumo_do_aperto()), h);
    }

    // O transporte: as mensagens se alternam, começando pelo iniciador.
    for (i, msg) in mensagens.iter().enumerate().skip(2) {
        let carga = hex(msg["payload"].as_str().unwrap());
        let esperado = hex(msg["ciphertext"].as_str().unwrap());
        let (envia, recebe): (&mut Transporte, &mut Transporte) = if i % 2 == 0 {
            (&mut t_ini, &mut t_resp)
        } else {
            (&mut t_resp, &mut t_ini)
        };
        let n = envia.cifrar(&carga, &mut saida).unwrap();
        assert_eq!(hex_str(&saida[..n]), hex_str(&esperado), "mensagem {i}");
        let m = recebe.decifrar(&esperado, &mut lida).unwrap();
        assert_eq!(&lida[..m], &carga[..]);
    }
    mensagens.len()
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn vetores(arquivo: &str) -> Vec<Value> {
    let caminho = format!("{}/tests/vetores/{arquivo}", env!("CARGO_MANIFEST_DIR"));
    let texto = std::fs::read_to_string(caminho).unwrap();
    let v: Value = serde_json::from_str(&texto).unwrap();
    v["vectors"].as_array().unwrap().clone()
}

#[test]
fn vetor_da_cacophony() {
    let vs = vetores("cacophony-ik.json");
    assert_eq!(vs.len(), 1);
    assert_eq!(rodar(&vs[0]), 6);
}

#[test]
fn vetor_do_snow() {
    let vs = vetores("snow-ik.json");
    assert_eq!(vs.len(), 1);
    assert_eq!(rodar(&vs[0]), 2);
}

const PADRAO: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Chaves fixas e válidas para os casos de interoperação.
const DUKE: [u8; 32] = [0x5a; 32];
const AGENTE: [u8; 32] = [0xa5; 32];

/// O `sigilo` como agente, o `snow` como Duke.
#[test]
fn sigilo_inicia_snow_responde() {
    let mut resp = snow::Builder::new(PADRAO.parse().unwrap())
        .prologue(sigilo::PROLOGO)
        .local_private_key(&DUKE)
        .build_responder()
        .unwrap();

    let ini = Iniciador::novo(sigilo::PROLOGO, &AGENTE, &sigilo::publica_de(&DUKE));
    let mut a = vec![0u8; 65_535];
    let mut b = vec![0u8; 65_535];
    let (n, aguardando) = ini.escrever([0x01; 32], b"ola", &mut a).unwrap();
    let m = resp.read_message(&a[..n], &mut b).unwrap();
    assert_eq!(&b[..m], b"ola");
    assert_eq!(
        resp.get_remote_static().unwrap(),
        sigilo::publica_de(&AGENTE)
    );

    let n = resp.write_message(b"bem-vindo", &mut a).unwrap();
    let (m, mut t) = aguardando.ler(&a[..n], &mut b).unwrap();
    assert_eq!(&b[..m], b"bem-vindo");
    let mut resp = resp.into_transport_mode().unwrap();

    for i in 0..5 {
        let texto = format!("pedido {i}");
        let n = t.cifrar(texto.as_bytes(), &mut a).unwrap();
        let m = resp.read_message(&a[..n], &mut b).unwrap();
        assert_eq!(&b[..m], texto.as_bytes());
        let n = resp.write_message(b"resposta", &mut a).unwrap();
        let m = t.decifrar(&a[..n], &mut b).unwrap();
        assert_eq!(&b[..m], b"resposta");
    }
}

/// O `snow` como agente, o `sigilo` como Duke.
#[test]
fn snow_inicia_sigilo_responde() {
    let mut ini = snow::Builder::new(PADRAO.parse().unwrap())
        .prologue(sigilo::PROLOGO)
        .local_private_key(&AGENTE)
        .remote_public_key(&sigilo::publica_de(&DUKE))
        .build_initiator()
        .unwrap();

    let mut a = vec![0u8; 65_535];
    let mut b = vec![0u8; 65_535];
    let n = ini.write_message(b"sou eu", &mut a).unwrap();
    let (m, recebido) = Respondedor::novo(sigilo::PROLOGO, &DUKE)
        .ler(&a[..n], &mut b)
        .unwrap();
    assert_eq!(&b[..m], b"sou eu");
    assert_eq!(recebido.remota(), sigilo::publica_de(&AGENTE));

    let (n, mut t) = recebido.escrever([0x02; 32], b"", &mut a).unwrap();
    let m = ini.read_message(&a[..n], &mut b).unwrap();
    assert_eq!(m, 0);
    let mut ini = ini.into_transport_mode().unwrap();

    let grande = vec![b'x'; Transporte::MAIOR_CLARO];
    let n = ini.write_message(&grande, &mut a).unwrap();
    assert_eq!(n, 65_535);
    let m = t.decifrar(&a[..n], &mut b).unwrap();
    assert_eq!(&b[..m], &grande[..]);
}

/// Um agente que espera outro Duke não passa da primeira mensagem — e o
/// Duke de verdade não aprende quem ele é.
#[test]
fn outro_duke_nao_abre() {
    let ini = Iniciador::novo(sigilo::PROLOGO, &AGENTE, &sigilo::publica_de(&[0x77; 32]));
    let mut a = vec![0u8; 1024];
    let mut b = vec![0u8; 1024];
    let (n, _) = ini.escrever([0x01; 32], b"", &mut a).unwrap();
    let r = Respondedor::novo(sigilo::PROLOGO, &DUKE).ler(&a[..n], &mut b);
    assert_eq!(r.err(), Some(Erro::Autenticacao));
}

/// Outro prólogo — outra versão do protocolo — também não.
#[test]
fn outro_prologo_nao_abre() {
    let ini = Iniciador::novo(
        b"Duke canal do agente v0",
        &AGENTE,
        &sigilo::publica_de(&DUKE),
    );
    let mut a = vec![0u8; 1024];
    let mut b = vec![0u8; 1024];
    let (n, _) = ini.escrever([0x01; 32], b"", &mut a).unwrap();
    let r = Respondedor::novo(sigilo::PROLOGO, &DUKE).ler(&a[..n], &mut b);
    assert_eq!(r.err(), Some(Erro::Autenticacao));
}

/// Um aperto completo entre os dois lados do `sigilo`, para os casos de
/// transporte abaixo.
fn par() -> (Transporte, Transporte) {
    let mut a = vec![0u8; 1024];
    let mut b = vec![0u8; 1024];
    let (n, aguardando) = Iniciador::novo(sigilo::PROLOGO, &AGENTE, &sigilo::publica_de(&DUKE))
        .escrever([0x01; 32], b"", &mut a)
        .unwrap();
    let (_, recebido) = Respondedor::novo(sigilo::PROLOGO, &DUKE)
        .ler(&a[..n], &mut b)
        .unwrap();
    let (n, duke) = recebido.escrever([0x02; 32], b"", &mut a).unwrap();
    let (_, agente) = aguardando.ler(&a[..n], &mut b).unwrap();
    (agente, duke)
}

/// Repetir uma mensagem é recusado: o contador já passou da posição dela.
///
/// Encerrar a sessão depois disso é decisão do kernel, e não deste pacote;
/// aqui se confere só que a repetição não passa.
#[test]
fn repeticao_nao_passa() {
    let (mut agente, mut duke) = par();
    let mut a = vec![0u8; 1024];
    let mut b = vec![0u8; 1024];
    let n = agente.cifrar(b"um", &mut a).unwrap();
    let primeira = a[..n].to_vec();
    assert_eq!(duke.decifrar(&primeira, &mut b).unwrap(), 2);
    assert_eq!(
        duke.decifrar(&primeira, &mut b).err(),
        Some(Erro::Autenticacao)
    );
}

/// Um bit trocado em qualquer posição é recusado.
#[test]
fn adulteracao_nao_passa() {
    let (mut agente, mut duke) = par();
    let mut a = vec![0u8; 1024];
    let mut b = vec![0u8; 1024];
    let n = agente.cifrar(b"agent.ping", &mut a).unwrap();
    for i in 0..n {
        let mut copia = a[..n].to_vec();
        copia[i] ^= 0x01;
        assert_eq!(
            duke.decifrar(&copia, &mut b).err(),
            Some(Erro::Autenticacao),
            "byte {i}"
        );
    }
    // E a original, intacta, ainda abre: as tentativas não andaram o contador.
    assert!(duke.decifrar(&a[..n], &mut b).is_ok());
}

/// Uma chave pública de ordem baixa — aqui, o ponto zero — é recusada no
/// Diffie-Hellman, e não aceita como um segredo que todo mundo sabe.
#[test]
fn chave_de_ordem_baixa_e_recusada() {
    let ini = Iniciador::novo(sigilo::PROLOGO, &AGENTE, &[0u8; 32]);
    let mut a = vec![0u8; 1024];
    assert_eq!(
        ini.escrever([0x01; 32], b"", &mut a).err(),
        Some(Erro::ChaveFraca)
    );
}
