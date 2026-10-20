//! O arquivo de redes.

use std::format;
use std::string::{String, ToString};
use std::vec::Vec;

use super::*;
use crate::icp::bancada::{chave_bls, der_bls};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn chave(semente: u8) -> String {
    format!("bls:{}", hex(&der_bls(&chave_bls(semente))))
}

#[test]
fn o_arquivo_da_bancada() {
    let texto = format!(
        "# as redes do IC em que este Duke confia\n\
         \n\
         rede bancada https://icp.duke:4943 dns {}\n\
         \t rede local   https://icp.duke:4943   10.0.2.100   {}  \n\
         rede padrao https://icp0.io 192.168.0.1 {}\n",
        chave(1),
        chave(2),
        chave(3)
    );
    let redes = ler(&texto).unwrap();
    assert_eq!(redes.len(), 3);
    assert_eq!(redes[0].nome, "bancada");
    assert_eq!(redes[0].host, "icp.duke");
    assert_eq!(redes[0].porta, 4943);
    assert_eq!(redes[0].endereco, None);
    assert_eq!(redes[1].endereco, Some([10, 0, 2, 100]));
    assert_eq!(redes[2].porta, 443);
    assert_eq!(redes[2].host, "icp0.io");
    assert_eq!(
        redes[0].raiz,
        Raiz::de_der(&der_bls(&chave_bls(1))).unwrap()
    );
    assert_eq!(ler("").unwrap(), Vec::new());
    assert_eq!(ler("# nada\n\n").unwrap(), Vec::new());
}

#[test]
fn cada_erro_com_a_linha() {
    let boa = |nome: &str| format!("rede {nome} https://icp.duke:4943 dns {}", chave(1));
    let casos: Vec<(String, &str)> = Vec::from([
        (String::from("rede x"), "a linha nao tem os cinco campos"),
        (
            format!("{} a-mais", boa("a")),
            "a linha nao tem os cinco campos",
        ),
        (
            format!("fonte a https://icp.duke dns {}", chave(1)),
            "linha desconhecida",
        ),
        (boa("Bancada"), "nome de rede invalido"),
        (boa("a_b"), "nome de rede invalido"),
        (boa(&"a".repeat(33)), "nome de rede invalido"),
        (
            format!("{}\n{}", boa("a"), boa("a")),
            "nome de rede repetido",
        ),
        (
            format!("rede a http://icp.duke dns {}", chave(1)),
            "url invalida: so https://host[:porta]",
        ),
        (
            format!("rede a https://icp.duke/api dns {}", chave(1)),
            "url invalida: so https://host[:porta]",
        ),
        (
            format!("rede a https://icp.duke:0 dns {}", chave(1)),
            "url invalida: so https://host[:porta]",
        ),
        (
            format!("rede a https://icp.duke:65536 dns {}", chave(1)),
            "url invalida: so https://host[:porta]",
        ),
        (
            format!("rede a https://icp.duke: dns {}", chave(1)),
            "url invalida: so https://host[:porta]",
        ),
        (
            format!("rede a https://ICP.duke dns {}", chave(1)),
            "url invalida: so https://host[:porta]",
        ),
        (
            format!("rede a https://icp..duke dns {}", chave(1)),
            "url invalida: so https://host[:porta]",
        ),
        (
            format!("rede a https://-icp.duke dns {}", chave(1)),
            "url invalida: so https://host[:porta]",
        ),
        (
            format!("rede a https:// dns {}", chave(1)),
            "url invalida: so https://host[:porta]",
        ),
        (
            format!("rede a https://icp.duke 10.0.2 {}", chave(1)),
            "endereco invalido: dns ou um ipv4",
        ),
        (
            format!("rede a https://icp.duke 10.0.02.1 {}", chave(1)),
            "endereco invalido: dns ou um ipv4",
        ),
        (
            format!("rede a https://icp.duke 256.0.0.1 {}", chave(1)),
            "endereco invalido: dns ou um ipv4",
        ),
        (
            format!("rede a https://icp.duke 1.2.3.4.5 {}", chave(1)),
            "endereco invalido: dns ou um ipv4",
        ),
        (
            format!("rede a https://icp.duke DNS {}", chave(1)),
            "endereco invalido: dns ou um ipv4",
        ),
        (
            format!("rede a https://icp.duke dns {}", &chave(1)[4..]),
            "chave invalida: bls: e o DER em hexadecimal",
        ),
        (
            format!(
                "rede a https://icp.duke dns {}",
                &chave(1)[..chave(1).len() - 2]
            ),
            "chave invalida: bls: e o DER em hexadecimal",
        ),
        (
            format!(
                "rede a https://icp.duke dns {}",
                chave(1).to_ascii_uppercase().replacen("BLS", "bls", 1)
            ),
            "chave invalida: bls: e o DER em hexadecimal",
        ),
        (
            format!("rede a https://icp.duke dns bls:{}", "00".repeat(133)),
            "chave invalida: bls: e o DER em hexadecimal",
        ),
        // O prefixo certo e um ponto que não é da curva.
        (
            format!(
                "rede a https://icp.duke dns {}",
                chave(1)[..4 + 74].to_string() + "9f" + &"8a".repeat(95)
            ),
            "chave invalida: bls: e o DER em hexadecimal",
        ),
    ]);
    for (texto, motivo) in casos {
        let linhas = texto.lines().count();
        let e = ler(&texto).unwrap_err();
        assert_eq!(e.motivo, motivo, "{texto}");
        assert_eq!(e.linha, linhas, "{texto}");
        assert!(e.to_string().is_ascii());
        assert!(e.to_string().contains(CAMINHO));
    }
}

#[test]
fn os_tetos_do_arquivo() {
    let linhas: Vec<String> = (0..=MAIS_REDES)
        .map(|i| format!("rede r{i} https://icp.duke dns {}", chave(1)))
        .collect();
    let e = ler(&linhas.join("\n")).unwrap_err();
    assert_eq!(e.motivo, "redes demais");
    assert_eq!(e.linha, MAIS_REDES + 1);
    assert!(ler(&linhas[..MAIS_REDES].join("\n")).is_ok());
    let grande = "#".repeat(MAIOR_ARQUIVO + 1);
    let e = ler(&grande).unwrap_err();
    assert_eq!(e.linha, 0);
    assert_eq!(e.to_string(), format!("{CAMINHO}: arquivo grande demais"));
}
