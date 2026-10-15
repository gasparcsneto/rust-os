//! Os testes do HPACK e do código de Huffman: os exemplos da RFC 7541
//! (Apêndice C) byte a byte, com a tabela dinâmica depois de cada bloco; a
//! ida e volta de cada byte pelo Huffman; o que o codificador manda; e o
//! que um bloco hostil não consegue — o EOS, o preenchimento torto, o
//! inteiro sem fim, o índice fora das tabelas, a tabela acima do
//! anunciado, a lista acima do teto de quem pediu.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::hpack::{
    Campo, Codificador, Decodificador, ESTATICA, ErroHpack, Representacao, inteiro, por_inteiro,
};
use crate::huffman::{self, ErroHuffman};

pub(crate) fn hex(t: &str) -> Vec<u8> {
    let digitos: Vec<u8> = t.bytes().filter(u8::is_ascii_hexdigit).collect();
    assert!(digitos.len().is_multiple_of(2), "hex ímpar: {t}");
    digitos
        .chunks(2)
        .map(|par| u8::from_str_radix(core::str::from_utf8(par).unwrap(), 16).unwrap())
        .collect()
}

fn campos(lista: &[(&str, &str)]) -> Vec<Campo> {
    lista
        .iter()
        .map(|&(n, v)| Campo {
            nome: n.as_bytes().to_vec(),
            valor: v.as_bytes().to_vec(),
        })
        .collect()
}

/// A tabela dinâmica, da entrada mais nova para a mais velha — lida pelo
/// lado de fora, com representações indexadas (62, 63, ...), que não a
/// mudam.
fn dinamica(d: &mut Decodificador) -> Vec<(String, String)> {
    let mut entradas = Vec::new();
    for i in 62.. {
        let mut bloco = Vec::new();
        por_inteiro(i, 7, 0x80, &mut bloco);
        match d.decodificar(&bloco, usize::MAX) {
            Ok((c, false)) => entradas.push((
                String::from_utf8(c[0].nome.clone()).unwrap(),
                String::from_utf8(c[0].valor.clone()).unwrap(),
            )),
            Err(ErroHpack::Indice) => break,
            outro => panic!("{outro:?}"),
        }
    }
    entradas
}

/// Decodifica o bloco `bloco` (em hexadecimal) sem teto na lista, e confere
/// os campos, a tabela depois — da mais nova para a mais velha — e o
/// tamanho dela.
fn confere(
    d: &mut Decodificador,
    bloco: &str,
    esperados: &[(&str, &str)],
    tabela: &[(&str, &str)],
    ocupado: usize,
) {
    let (lidos, passou) = d.decodificar(&hex(bloco), usize::MAX).unwrap();
    assert!(!passou);
    assert_eq!(lidos, campos(esperados));
    let tabela: Vec<(String, String)> = tabela
        .iter()
        .map(|&(n, v)| (String::from(n), String::from(v)))
        .collect();
    assert_eq!(dinamica(d), tabela);
    assert_eq!(d.tabela(), (tabela.len(), ocupado));
}

// --- O Huffman ---

#[test]
fn as_cadeias_da_rfc_em_huffman() {
    // As cadeias dos exemplos C.4 e C.6 da RFC 7541.
    for (texto, codigo) in [
        ("www.example.com", "f1e3 c2e5 f23a 6ba0 ab90 f4ff"),
        ("no-cache", "a8eb 1064 9cbf"),
        ("custom-key", "25a8 49e9 5ba9 7d7f"),
        ("custom-value", "25a8 49e9 5bb8 e8b4 bf"),
        ("302", "6402"),
        ("307", "640e ff"),
        ("private", "aec3 771a 4b"),
        (
            "Mon, 21 Oct 2013 20:13:21 GMT",
            "d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff",
        ),
        (
            "Mon, 21 Oct 2013 20:13:22 GMT",
            "d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff",
        ),
        (
            "https://www.example.com",
            "9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3",
        ),
        ("gzip", "9bd9 ab"),
        (
            "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
            "94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f \
             9587 3160 65c0 03ed 4ee5 b106 3d50 07",
        ),
    ] {
        let codigo = hex(codigo);
        let mut feito = Vec::new();
        huffman::codificar(texto.as_bytes(), &mut feito);
        assert_eq!(feito, codigo, "{texto}");
        assert_eq!(huffman::tamanho(texto.as_bytes()), codigo.len(), "{texto}");
        assert_eq!(
            huffman::decodificar(&codigo, usize::MAX).unwrap(),
            texto.as_bytes(),
            "{texto}"
        );
    }
}

#[test]
fn cada_byte_vai_e_volta() {
    for b in 0..=255u8 {
        let mut feito = Vec::new();
        huffman::codificar(&[b], &mut feito);
        assert_eq!(huffman::tamanho(&[b]), feito.len());
        assert_eq!(huffman::decodificar(&feito, 1).unwrap(), [b], "{b}");
        // Repetido, para cada fronteira de byte cair num lugar do código.
        let muitos = [b; 9];
        let mut feito = Vec::new();
        huffman::codificar(&muitos, &mut feito);
        assert_eq!(huffman::decodificar(&feito, 9).unwrap(), muitos, "{b}");
    }
    let todos: Vec<u8> = (0..=255u8).chain((0..=255u8).rev()).collect();
    let mut feito = Vec::new();
    huffman::codificar(&todos, &mut feito);
    assert_eq!(huffman::tamanho(&todos), feito.len());
    assert_eq!(huffman::decodificar(&feito, todos.len()).unwrap(), todos);
}

#[test]
fn a_cadeia_vazia() {
    let mut feito = Vec::new();
    huffman::codificar(b"", &mut feito);
    assert!(feito.is_empty());
    assert_eq!(huffman::decodificar(&[], 0).unwrap(), b"");
}

#[test]
fn o_eos_nao_pode_estar_na_cadeia() {
    // Trinta `1`s são o EOS — sozinho, ou depois de um símbolo (`a` é
    // `00011`).
    assert_eq!(
        huffman::decodificar(&[0xff, 0xff, 0xff, 0xff], 9),
        Err(ErroHuffman::Eos)
    );
    assert_eq!(
        huffman::decodificar(&[0x1f, 0xff, 0xff, 0xff, 0xff], 9),
        Err(ErroHuffman::Eos)
    );
}

#[test]
fn o_preenchimento_e_o_comeco_do_eos_com_menos_de_oito_bits() {
    // `a` e três `1`: certo.
    assert_eq!(huffman::decodificar(&[0x1f], 9).unwrap(), b"a");
    // Oito `1`s, sozinhos ou depois de `a`: preenchimento longo demais.
    assert_eq!(
        huffman::decodificar(&[0xff], 9),
        Err(ErroHuffman::Preenchimento)
    );
    assert_eq!(
        huffman::decodificar(&[0x1f, 0xff], 9),
        Err(ErroHuffman::Preenchimento)
    );
    // `a` e `011`: um zero no preenchimento.
    assert_eq!(
        huffman::decodificar(&[0x1b], 9),
        Err(ErroHuffman::Preenchimento)
    );
    // `a` e `000`: o começo de outro símbolo, que não acabou.
    assert_eq!(
        huffman::decodificar(&[0x18], 9),
        Err(ErroHuffman::Preenchimento)
    );
}

#[test]
fn a_cadeia_decodificada_nao_passa_do_teto() {
    let mut feito = Vec::new();
    huffman::codificar(b"abc", &mut feito);
    assert_eq!(huffman::decodificar(&feito, 3).unwrap(), b"abc");
    assert_eq!(huffman::decodificar(&feito, 2), Err(ErroHuffman::Teto));
    assert_eq!(huffman::decodificar(&feito, 0), Err(ErroHuffman::Teto));
}

// --- Os inteiros (RFC 7541, C.1) ---

#[test]
fn os_inteiros_da_rfc() {
    for (valor, prefixo, bytes) in [
        (10, 5, "0a"),
        (1337, 5, "1f9a0a"),
        (42, 8, "2a"),
        (30, 5, "1e"),
        (31, 5, "1f00"),
        (127, 7, "7f00"),
        (126, 7, "7e"),
        (128, 7, "7f01"),
        (255, 8, "ff00"),
    ] {
        let mut feito = Vec::new();
        por_inteiro(valor, prefixo, 0, &mut feito);
        assert_eq!(feito, hex(bytes), "{valor}");
        let mut pos = 0;
        assert_eq!(inteiro(&feito, &mut pos, prefixo), Ok(valor), "{valor}");
        assert_eq!(pos, feito.len());
    }
    // Os bits de cima do primeiro byte são da representação, não do
    // inteiro.
    let mut pos = 0;
    assert_eq!(inteiro(&hex("ea"), &mut pos, 5), Ok(10));
}

#[test]
fn um_inteiro_sem_fim_ou_grande_demais() {
    // 2^28 passa; um a mais não.
    let mut feito = Vec::new();
    por_inteiro(1 << 28, 7, 0, &mut feito);
    assert_eq!(inteiro(&feito, &mut 0, 7), Ok(1 << 28));
    let mut feito = Vec::new();
    por_inteiro((1 << 28) + 1, 7, 0, &mut feito);
    assert_eq!(inteiro(&feito, &mut 0, 7), Err(ErroHpack::Inteiro));
    // Zeros de continuação também contam.
    assert_eq!(inteiro(&hex("7f 8080 8080 00"), &mut 0, 7), Ok(127));
    assert_eq!(
        inteiro(&hex("7f 8080 8080 8000"), &mut 0, 7),
        Err(ErroHpack::Inteiro)
    );
    assert_eq!(
        inteiro(&hex("7f ffff ffff ff0f"), &mut 0, 7),
        Err(ErroHpack::Inteiro)
    );
    // Cortado no meio.
    assert_eq!(inteiro(&hex("7f"), &mut 0, 7), Err(ErroHpack::Cortado));
    assert_eq!(inteiro(&hex("7f 80"), &mut 0, 7), Err(ErroHpack::Cortado));
    assert_eq!(inteiro(&[], &mut 0, 7), Err(ErroHpack::Cortado));
}

// --- Os blocos (RFC 7541, C.2 a C.6) ---

#[test]
fn c2_cada_representacao() {
    // C.2.1: literal com indexação.
    let mut d = Decodificador::novo(4096);
    confere(
        &mut d,
        "400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572",
        &[("custom-key", "custom-header")],
        &[("custom-key", "custom-header")],
        55,
    );
    // C.2.2: literal sem indexação.
    let mut d = Decodificador::novo(4096);
    confere(
        &mut d,
        "040c 2f73 616d 706c 652f 7061 7468",
        &[(":path", "/sample/path")],
        &[],
        0,
    );
    // C.2.3: literal nunca indexado.
    let mut d = Decodificador::novo(4096);
    confere(
        &mut d,
        "1008 7061 7373 776f 7264 0673 6563 7265 74",
        &[("password", "secret")],
        &[],
        0,
    );
    // C.2.4: indexado.
    let mut d = Decodificador::novo(4096);
    confere(&mut d, "82", &[(":method", "GET")], &[], 0);
}

fn pedidos(primeiro: &str, segundo: &str, terceiro: &str) {
    let mut d = Decodificador::novo(4096);
    confere(
        &mut d,
        primeiro,
        &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
        ],
        &[(":authority", "www.example.com")],
        57,
    );
    confere(
        &mut d,
        segundo,
        &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
            ("cache-control", "no-cache"),
        ],
        &[
            ("cache-control", "no-cache"),
            (":authority", "www.example.com"),
        ],
        110,
    );
    confere(
        &mut d,
        terceiro,
        &[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/index.html"),
            (":authority", "www.example.com"),
            ("custom-key", "custom-value"),
        ],
        &[
            ("custom-key", "custom-value"),
            ("cache-control", "no-cache"),
            (":authority", "www.example.com"),
        ],
        164,
    );
}

#[test]
fn c3_pedidos_sem_huffman() {
    pedidos(
        "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
        "8286 84be 5808 6e6f 2d63 6163 6865",
        "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
    );
}

#[test]
fn c4_pedidos_com_huffman() {
    pedidos(
        "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
        "8286 84be 5886 a8eb 1064 9cbf",
        "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
    );
}

/// As três respostas, numa tabela de 256 bytes: a segunda tira o
/// `:status: 302` do fim, a terceira tira três.
fn respostas(primeira: &str, segunda: &str, terceira: &str) {
    let mut d = Decodificador::novo(256);
    let data21 = "Mon, 21 Oct 2013 20:13:21 GMT";
    let data22 = "Mon, 21 Oct 2013 20:13:22 GMT";
    let lugar = "https://www.example.com";
    let biscoito = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1";
    confere(
        &mut d,
        primeira,
        &[
            (":status", "302"),
            ("cache-control", "private"),
            ("date", data21),
            ("location", lugar),
        ],
        &[
            ("location", lugar),
            ("date", data21),
            ("cache-control", "private"),
            (":status", "302"),
        ],
        222,
    );
    confere(
        &mut d,
        segunda,
        &[
            (":status", "307"),
            ("cache-control", "private"),
            ("date", data21),
            ("location", lugar),
        ],
        &[
            (":status", "307"),
            ("location", lugar),
            ("date", data21),
            ("cache-control", "private"),
        ],
        222,
    );
    confere(
        &mut d,
        terceira,
        &[
            (":status", "200"),
            ("cache-control", "private"),
            ("date", data22),
            ("location", lugar),
            ("content-encoding", "gzip"),
            ("set-cookie", biscoito),
        ],
        &[
            ("set-cookie", biscoito),
            ("content-encoding", "gzip"),
            ("date", data22),
        ],
        215,
    );
}

#[test]
fn c5_respostas_sem_huffman() {
    respostas(
        "4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 \
         2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 \
         6c65 2e63 6f6d",
        "4803 3330 37c1 c0bf",
        "88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d \
         54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049 \
         5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e \
         3d31",
    );
}

#[test]
fn c6_respostas_com_huffman() {
    respostas(
        "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 \
         2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
        "4883 640e ffc1 c0bf",
        "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab \
         77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f \
         9587 3160 65c0 03ed 4ee5 b106 3d50 07",
    );
}

// --- O tamanho da tabela ---

#[test]
fn a_tabela_muda_de_tamanho_so_no_comeco_e_ate_o_anunciado() {
    let mut d = Decodificador::novo(4096);
    confere(
        &mut d,
        "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
        &[
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/"),
            (":authority", "www.example.com"),
        ],
        &[(":authority", "www.example.com")],
        57,
    );
    // Até o anunciado, e mais de uma vez no começo: zero esvazia a tabela.
    confere(&mut d, "3fe1 1f 20 82", &[(":method", "GET")], &[], 0);
    assert_eq!(
        d.decodificar(&hex("be"), usize::MAX),
        Err(ErroHpack::Indice)
    );
    // A tabela continua com o máximo de agora, até outra atualização.
    confere(&mut d, "4001 6101 62", &[("a", "b")], &[], 0);
    confere(
        &mut d,
        "3f11 4001 6101 62",
        &[("a", "b")],
        &[("a", "b")],
        34,
    );
    // Um a mais que o anunciado.
    let mut d = Decodificador::novo(4096);
    assert_eq!(
        d.decodificar(&hex("3fe2 1f"), usize::MAX),
        Err(ErroHpack::Tamanho)
    );
    // Depois de um campo.
    let mut d = Decodificador::novo(4096);
    assert_eq!(
        d.decodificar(&hex("8220"), usize::MAX),
        Err(ErroHpack::Tamanho)
    );
}

#[test]
fn baixar_a_tabela_tira_os_mais_velhos() {
    let mut d = Decodificador::novo(4096);
    // Três campos de 34 bytes.
    confere(
        &mut d,
        "4001 6101 31 4001 6101 32 4001 6101 33",
        &[("a", "1"), ("a", "2"), ("a", "3")],
        &[("a", "3"), ("a", "2"), ("a", "1")],
        102,
    );
    // Para 68: o mais velho sai.
    confere(
        &mut d,
        "3f25 82",
        &[(":method", "GET")],
        &[("a", "3"), ("a", "2")],
        68,
    );
}

#[test]
fn um_campo_maior_que_a_tabela_a_esvazia_e_nao_entra() {
    let mut d = Decodificador::novo(40);
    confere(&mut d, "4001 6101 31", &[("a", "1")], &[("a", "1")], 34);
    // 32 + 1 + 8 = 41 > 40.
    confere(
        &mut d,
        "4001 6108 3132 3334 3536 3738",
        &[("a", "12345678")],
        &[],
        0,
    );
    // Exatamente o tamanho: entra.
    confere(
        &mut d,
        "4001 6107 3132 3334 3536 37",
        &[("a", "1234567")],
        &[("a", "1234567")],
        40,
    );
}

// --- O que um bloco hostil não consegue ---

#[test]
fn indices_fora_das_tabelas() {
    let mut d = Decodificador::novo(4096);
    // O índice zero.
    assert_eq!(
        d.decodificar(&hex("80"), usize::MAX),
        Err(ErroHpack::Indice)
    );
    // O 62 com a dinâmica vazia — indexado, e como nome de um literal.
    assert_eq!(
        d.decodificar(&hex("be"), usize::MAX),
        Err(ErroHpack::Indice)
    );
    assert_eq!(
        d.decodificar(&hex("7e 0161"), usize::MAX),
        Err(ErroHpack::Indice)
    );
    assert_eq!(
        d.decodificar(&hex("0f2f 0161"), usize::MAX),
        Err(ErroHpack::Indice)
    );
    // O último da estática é o 61.
    let (c, _) = d.decodificar(&hex("bd"), usize::MAX).unwrap();
    assert_eq!(c, campos(&[("www-authenticate", "")]));
    assert_eq!(ESTATICA.len(), 61);
}

#[test]
fn um_bloco_cortado() {
    let mut d = Decodificador::novo(4096);
    for bloco in [
        // A cadeia diz 15 bytes e tem 14.
        "4110 7777 772e 6578 616d 706c 652e 636f",
        // O nome sem o valor.
        "400a 6375 7374 6f6d 2d6b 6579",
        // O índice no meio.
        "ff",
        // Uma cadeia com o tamanho no meio.
        "407f",
    ] {
        assert_eq!(
            d.decodificar(&hex(bloco), usize::MAX),
            Err(ErroHpack::Cortado),
            "{bloco}"
        );
    }
    // Nada entrou na tabela.
    assert_eq!(d.tabela(), (0, 0));
}

#[test]
fn uma_cadeia_que_nao_e_huffman() {
    let mut d = Decodificador::novo(4096);
    // O nome em Huffman com oito `1`s.
    assert_eq!(
        d.decodificar(&hex("0081 ff01 61"), usize::MAX),
        Err(ErroHpack::Huffman)
    );
    // O valor com o EOS.
    assert_eq!(
        d.decodificar(&hex("0001 6184 ffff ffff"), usize::MAX),
        Err(ErroHpack::Huffman)
    );
}

#[test]
fn a_lista_para_no_teto_e_a_tabela_continua_certa() {
    // Três campos de 34 bytes, com indexação, e um teto de 70: os dois
    // primeiros entram na lista; os três, na tabela.
    let mut d = Decodificador::novo(4096);
    let (c, passou) = d
        .decodificar(&hex("4001 6101 31 4001 6101 32 4001 6101 33"), 70)
        .unwrap();
    assert!(passou);
    assert_eq!(c, campos(&[("a", "1"), ("a", "2")]));
    assert_eq!(
        dinamica(&mut d),
        [
            (String::from("a"), String::from("3")),
            (String::from("a"), String::from("2")),
            (String::from("a"), String::from("1")),
        ]
    );
    // O bloco seguinte aponta para a tabela certa.
    let (c, passou) = d.decodificar(&hex("be"), 70).unwrap();
    assert!(!passou);
    assert_eq!(c, campos(&[("a", "3")]));
    // Exatamente no teto: passa.
    let (c, passou) = d.decodificar(&hex("bebf"), 68).unwrap();
    assert!(!passou);
    assert_eq!(c.len(), 2);
}

#[test]
fn bytes_quaisquer_nos_nomes_e_valores_sao_dados() {
    // O HPACK não confere o que vai num campo: quem confere é a conexão
    // (maiúsculas, controles, pseudo-cabeçalhos).
    let mut d = Decodificador::novo(4096);
    let (c, _) = d
        .decodificar(&hex("0003 4100 0a03 0d0a 00"), usize::MAX)
        .unwrap();
    assert_eq!(
        c,
        vec![Campo {
            nome: vec![b'A', 0, b'\n'],
            valor: vec![b'\r', b'\n', 0],
        }]
    );
}

// --- O codificador ---

/// Codifica `lista` e devolve o bloco.
fn codificado(lista: &[(&str, &[u8], Representacao)]) -> Vec<u8> {
    let mut bloco = Vec::new();
    for &(n, v, como) in lista {
        Codificador::campo(n, v, como, &mut bloco);
    }
    bloco
}

#[test]
fn o_codificador_nao_indexa() {
    use Representacao::*;
    // O par inteiro na estática: indexado.
    assert_eq!(codificado(&[(":method", b"GET", SemIndexar)]), hex("82"));
    assert_eq!(codificado(&[(":path", b"/", SemIndexar)]), hex("84"));
    // O nome na estática: literal sem indexação com o índice dele, e o
    // valor em Huffman (o C.4.1 sem o `0x40`).
    assert_eq!(
        codificado(&[(":authority", b"www.example.com", SemIndexar)]),
        hex("01 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff")
    );
    // O nome fora da estática (o C.4.3 sem o `0x40`).
    assert_eq!(
        codificado(&[("custom-key", b"custom-value", SemIndexar)]),
        hex("00 8825 a849 e95b a97d 7f89 25a8 49e9 5bb8 e8b4 bf")
    );
    // Uma cadeia que o Huffman não encurta vai como veio.
    assert_eq!(
        codificado(&[("x", &[0xff, 0xfe], SemIndexar)]),
        hex("0001 7802 fffe")
    );
}

#[test]
fn o_cookie_vai_nunca_indexado() {
    use Representacao::*;
    // `0001 1111` e `0x11`: nunca indexado, com o nome no índice 32 da
    // estática; o valor, que o Huffman não encurta (17 bits), como veio.
    assert_eq!(
        codificado(&[("cookie", b"a=b", NuncaIndexar)]),
        hex("1f11 0361 3d62")
    );
    // Nunca indexado não vira indexado nem quando o par inteiro está na
    // estática: a marca vai junto.
    assert_eq!(
        codificado(&[(":method", b"GET", NuncaIndexar)]),
        hex("1203 4745 54")
    );
}

#[test]
fn o_que_vai_volta_sem_mudar_a_tabela_de_ninguem() {
    use Representacao::*;
    let longo = [b'v'; 300];
    let lista: [(&str, &[u8], Representacao); 7] = [
        (":method", b"POST", SemIndexar),
        (":scheme", b"https", SemIndexar),
        (":authority", b"bancada.duke", SemIndexar),
        (":path", b"/eco?x=1", SemIndexar),
        ("accept-encoding", b"gzip, deflate", SemIndexar),
        ("cookie", b"sessao=segredo", NuncaIndexar),
        ("x-longo", &longo, SemIndexar),
    ];
    let bloco = codificado(&lista);
    let mut d = Decodificador::novo(4096);
    let (c, passou) = d.decodificar(&bloco, usize::MAX).unwrap();
    assert!(!passou);
    let esperado: Vec<Campo> = lista
        .iter()
        .map(|&(n, v, _)| Campo {
            nome: n.as_bytes().to_vec(),
            valor: v.to_vec(),
        })
        .collect();
    assert_eq!(c, esperado);
    assert_eq!(d.tabela(), (0, 0));
}
