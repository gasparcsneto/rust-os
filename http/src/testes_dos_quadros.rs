//! Os testes dos quadros do HTTP/2: cada tipo lido e escrito, e cada
//! recusa que a RFC 9113 manda — com o código e o alcance certos, a
//! conexão inteira ou só a corrente.

use alloc::vec::Vec;

use crate::quadro::{
    self, CABECA, Cabeca, CodigoH2, ErroDeQuadro, Quadro, bandeira, ler, ler_cabeca, tipo,
};

fn cabeca(tamanho: usize, t: u8, bandeiras: u8, corrente: u32) -> Cabeca {
    Cabeca {
        tamanho,
        tipo: t,
        bandeiras,
        corrente,
    }
}

/// Lê o quadro com a carga `carga`.
fn lido(t: u8, bandeiras: u8, corrente: u32, carga: &[u8]) -> Result<Quadro<'_>, ErroDeQuadro> {
    ler(cabeca(carga.len(), t, bandeiras, corrente), carga)
}

fn da_conexao(codigo: CodigoH2) -> Result<Quadro<'static>, ErroDeQuadro> {
    Err(ErroDeQuadro {
        codigo,
        corrente: None,
    })
}

fn da_corrente(codigo: CodigoH2, corrente: u32) -> Result<Quadro<'static>, ErroDeQuadro> {
    Err(ErroDeQuadro {
        codigo,
        corrente: Some(corrente),
    })
}

/// Os quadros escritos em `bytes`, lidos de volta: a cabeça e a carga de
/// cada um.
fn quadros(bytes: &[u8]) -> Vec<(Cabeca, Vec<u8>)> {
    let mut lidos = Vec::new();
    let mut resto = bytes;
    while !resto.is_empty() {
        let c = ler_cabeca(resto[..CABECA].try_into().unwrap());
        lidos.push((c, resto[CABECA..CABECA + c.tamanho].to_vec()));
        resto = &resto[CABECA + c.tamanho..];
    }
    lidos
}

#[test]
fn a_cabeca_de_nove_bytes() {
    let c = ler_cabeca(&[0x01, 0x02, 0x03, 0x01, 0x25, 0x80, 0x00, 0x00, 0x07]);
    // O bit reservado da corrente é ignorado.
    assert_eq!(c, cabeca(0x010203, tipo::HEADERS, 0x25, 7));
    let mut escrito = Vec::new();
    quadro::por_cabeca(&mut escrito, 0x010203, tipo::HEADERS, 0x25, 0x8000_0007);
    assert_eq!(
        escrito,
        [0x01, 0x02, 0x03, 0x01, 0x25, 0x00, 0x00, 0x00, 0x07]
    );
}

#[test]
fn os_dados_com_e_sem_preenchimento() {
    assert_eq!(
        lido(tipo::DATA, bandeira::END_STREAM, 1, b"abc"),
        Ok(Quadro::Dados {
            corrente: 1,
            dados: b"abc",
            fim: true,
        })
    );
    assert_eq!(
        lido(tipo::DATA, bandeira::PADDED, 3, &[3, b'a', b'b', 0, 0, 0]),
        Ok(Quadro::Dados {
            corrente: 3,
            dados: b"ab",
            fim: false,
        })
    );
    // Só preenchimento.
    assert_eq!(
        lido(tipo::DATA, bandeira::PADDED, 3, &[2, 0, 0]),
        Ok(Quadro::Dados {
            corrente: 3,
            dados: b"",
            fim: false,
        })
    );
    // O preenchimento do tamanho da carga, ou maior.
    assert_eq!(
        lido(tipo::DATA, bandeira::PADDED, 3, &[3, 0, 0]),
        da_conexao(CodigoH2::PROTOCOL_ERROR)
    );
    assert_eq!(
        lido(tipo::DATA, bandeira::PADDED, 3, &[255]),
        da_conexao(CodigoH2::PROTOCOL_ERROR)
    );
    // Sem o byte do tamanho do preenchimento.
    assert_eq!(
        lido(tipo::DATA, bandeira::PADDED, 3, &[]),
        da_conexao(CodigoH2::FRAME_SIZE_ERROR)
    );
    // Na corrente zero.
    assert_eq!(
        lido(tipo::DATA, 0, 0, b"x"),
        da_conexao(CodigoH2::PROTOCOL_ERROR)
    );
    let mut escrito = Vec::new();
    quadro::por_dados(&mut escrito, 5, b"xyz", true);
    assert_eq!(
        quadros(&escrito),
        [(
            cabeca(3, tipo::DATA, bandeira::END_STREAM, 5),
            b"xyz".to_vec()
        )]
    );
}

#[test]
fn os_cabecalhos_com_preenchimento_e_prioridade() {
    assert_eq!(
        lido(
            tipo::HEADERS,
            bandeira::END_HEADERS | bandeira::END_STREAM,
            1,
            b"\x82"
        ),
        Ok(Quadro::Cabecalhos {
            corrente: 1,
            bloco: b"\x82",
            fim_da_corrente: true,
            fim_da_cabeca: true,
        })
    );
    // A prioridade é lida e ignorada.
    assert_eq!(
        lido(
            tipo::HEADERS,
            bandeira::PRIORITY | bandeira::PADDED,
            5,
            &[1, 0, 0, 0, 3, 16, 0x82, 0]
        ),
        Ok(Quadro::Cabecalhos {
            corrente: 5,
            bloco: b"\x82",
            fim_da_corrente: false,
            fim_da_cabeca: false,
        })
    );
    // Uma corrente não depende de si mesma: no `HEADERS`, erro da conexão
    // — o bloco de cabeça que o quadro leva não ficaria sem decodificar.
    assert_eq!(
        lido(
            tipo::HEADERS,
            bandeira::PRIORITY,
            5,
            &[0x80, 0, 0, 5, 16, 0x82]
        ),
        da_conexao(CodigoH2::PROTOCOL_ERROR)
    );
    // A prioridade cortada: o quadro leva um bloco de cabeça, o erro é da
    // conexão.
    assert_eq!(
        lido(tipo::HEADERS, bandeira::PRIORITY, 5, &[0, 0, 0, 3]),
        da_conexao(CodigoH2::FRAME_SIZE_ERROR)
    );
    assert_eq!(
        lido(tipo::HEADERS, bandeira::END_HEADERS, 0, b"\x82"),
        da_conexao(CodigoH2::PROTOCOL_ERROR)
    );
    // O preenchimento do tamanho da carga.
    assert_eq!(
        lido(tipo::HEADERS, bandeira::PADDED, 1, &[2, 0x82]),
        da_conexao(CodigoH2::PROTOCOL_ERROR)
    );
    // Um byte de preenchimento: o bloco fica vazio.
    assert_eq!(
        lido(tipo::HEADERS, bandeira::PADDED, 1, &[1, 0]),
        Ok(Quadro::Cabecalhos {
            corrente: 1,
            bloco: b"",
            fim_da_corrente: false,
            fim_da_cabeca: false,
        })
    );
}

#[test]
fn o_bloco_de_cabeca_dividido_em_continuacoes() {
    let bloco: Vec<u8> = (0..10).collect();
    let mut escrito = Vec::new();
    quadro::por_cabecalhos(&mut escrito, 7, &bloco, true, 4);
    assert_eq!(
        quadros(&escrito),
        [
            (
                cabeca(4, tipo::HEADERS, bandeira::END_STREAM, 7),
                bloco[..4].to_vec()
            ),
            (cabeca(4, tipo::CONTINUATION, 0, 7), bloco[4..8].to_vec()),
            (
                cabeca(2, tipo::CONTINUATION, bandeira::END_HEADERS, 7),
                bloco[8..].to_vec()
            ),
        ]
    );
    // Cabendo, um quadro só; vazio, também.
    let mut escrito = Vec::new();
    quadro::por_cabecalhos(&mut escrito, 9, &bloco, false, 10);
    assert_eq!(
        quadros(&escrito),
        [(
            cabeca(10, tipo::HEADERS, bandeira::END_HEADERS, 9),
            bloco.clone()
        )]
    );
    let mut escrito = Vec::new();
    quadro::por_cabecalhos(&mut escrito, 9, &[], true, 10);
    assert_eq!(
        quadros(&escrito),
        [(
            cabeca(
                0,
                tipo::HEADERS,
                bandeira::END_HEADERS | bandeira::END_STREAM,
                9
            ),
            Vec::new()
        )]
    );
    assert_eq!(
        lido(tipo::CONTINUATION, bandeira::END_HEADERS, 7, b"ab"),
        Ok(Quadro::Continuacao {
            corrente: 7,
            bloco: b"ab",
            fim_da_cabeca: true,
        })
    );
    assert_eq!(
        lido(tipo::CONTINUATION, 0, 0, b"ab"),
        da_conexao(CodigoH2::PROTOCOL_ERROR)
    );
}

#[test]
fn a_prioridade_e_ignorada_depois_de_conferida() {
    assert_eq!(
        lido(tipo::PRIORITY, 0, 3, &[0, 0, 0, 1, 16]),
        Ok(Quadro::Ignorado)
    );
    assert_eq!(
        lido(tipo::PRIORITY, 0, 3, &[0, 0, 0, 1]),
        da_corrente(CodigoH2::FRAME_SIZE_ERROR, 3)
    );
    assert_eq!(
        lido(tipo::PRIORITY, 0, 3, &[0, 0, 0, 3, 16]),
        da_corrente(CodigoH2::PROTOCOL_ERROR, 3)
    );
    assert_eq!(
        lido(tipo::PRIORITY, 0, 0, &[0, 0, 0, 1, 16]),
        da_conexao(CodigoH2::PROTOCOL_ERROR)
    );
}

#[test]
fn o_reinicio_de_uma_corrente() {
    let mut escrito = Vec::new();
    quadro::por_reinicio(&mut escrito, 3, CodigoH2::CANCEL);
    let [(c, carga)] = &quadros(&escrito)[..] else {
        panic!()
    };
    assert_eq!(*c, cabeca(4, tipo::RST_STREAM, 0, 3));
    assert_eq!(
        ler(*c, carga),
        Ok(Quadro::Reinicio {
            corrente: 3,
            codigo: CodigoH2::CANCEL,
        })
    );
    // Um código que a RFC não define é guardado como veio.
    assert_eq!(
        lido(tipo::RST_STREAM, 0, 3, &[0, 0, 1, 0]),
        Ok(Quadro::Reinicio {
            corrente: 3,
            codigo: CodigoH2(256),
        })
    );
    assert_eq!(
        lido(tipo::RST_STREAM, 0, 3, &[0, 0, 8]),
        da_conexao(CodigoH2::FRAME_SIZE_ERROR)
    );
    assert_eq!(
        lido(tipo::RST_STREAM, 0, 0, &[0, 0, 0, 8]),
        da_conexao(CodigoH2::PROTOCOL_ERROR)
    );
}

#[test]
fn os_ajustes_e_o_reconhecimento() {
    let mut escrito = Vec::new();
    quadro::por_ajustes(&mut escrito, &[(2, 0), (4, 65_536)]);
    let [(c, carga)] = &quadros(&escrito)[..] else {
        panic!()
    };
    assert_eq!(*c, cabeca(12, tipo::SETTINGS, 0, 0));
    assert_eq!(
        ler(*c, carga),
        Ok(Quadro::Ajustes {
            ack: false,
            pares: &[0, 2, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0],
        })
    );
    let mut escrito = Vec::new();
    quadro::por_ajustes_ack(&mut escrito);
    assert_eq!(
        quadros(&escrito),
        [(cabeca(0, tipo::SETTINGS, bandeira::ACK, 0), Vec::new())]
    );
    assert_eq!(
        lido(tipo::SETTINGS, bandeira::ACK, 0, &[]),
        Ok(Quadro::Ajustes {
            ack: true,
            pares: &[],
        })
    );
    // O reconhecimento com carga; um par cortado; numa corrente.
    assert_eq!(
        lido(tipo::SETTINGS, bandeira::ACK, 0, &[0, 2, 0, 0, 0, 0]),
        da_conexao(CodigoH2::FRAME_SIZE_ERROR)
    );
    assert_eq!(
        lido(tipo::SETTINGS, 0, 0, &[0, 2, 0, 0, 0]),
        da_conexao(CodigoH2::FRAME_SIZE_ERROR)
    );
    assert_eq!(
        lido(tipo::SETTINGS, 0, 1, &[]),
        da_conexao(CodigoH2::PROTOCOL_ERROR)
    );
}

#[test]
fn o_ping_e_a_resposta() {
    let mut escrito = Vec::new();
    quadro::por_ping_ack(&mut escrito, b"12345678");
    let [(c, carga)] = &quadros(&escrito)[..] else {
        panic!()
    };
    assert_eq!(*c, cabeca(8, tipo::PING, bandeira::ACK, 0));
    assert_eq!(
        ler(*c, carga),
        Ok(Quadro::Ping {
            ack: true,
            dados: *b"12345678",
        })
    );
    assert_eq!(
        lido(tipo::PING, 0, 0, b"1234567"),
        da_conexao(CodigoH2::FRAME_SIZE_ERROR)
    );
    assert_eq!(
        lido(tipo::PING, 0, 0, b"123456789"),
        da_conexao(CodigoH2::FRAME_SIZE_ERROR)
    );
    assert_eq!(
        lido(tipo::PING, 0, 1, b"12345678"),
        da_conexao(CodigoH2::PROTOCOL_ERROR)
    );
}

#[test]
fn o_adeus() {
    let mut escrito = Vec::new();
    quadro::por_adeus(&mut escrito, 0x8000_0005, CodigoH2::NO_ERROR);
    let [(c, carga)] = &quadros(&escrito)[..] else {
        panic!()
    };
    assert_eq!(*c, cabeca(8, tipo::GOAWAY, 0, 0));
    assert_eq!(
        ler(*c, carga),
        Ok(Quadro::Adeus {
            ultima: 5,
            codigo: CodigoH2::NO_ERROR,
        })
    );
    // Com dados de depuração depois, e o bit reservado da última ligado.
    assert_eq!(
        lido(tipo::GOAWAY, 0, 0, &[0x80, 0, 0, 9, 0, 0, 0, 0xb, b'x']),
        Ok(Quadro::Adeus {
            ultima: 9,
            codigo: CodigoH2::ENHANCE_YOUR_CALM,
        })
    );
    assert_eq!(
        lido(tipo::GOAWAY, 0, 0, &[0, 0, 0, 9, 0, 0, 0]),
        da_conexao(CodigoH2::FRAME_SIZE_ERROR)
    );
    assert_eq!(
        lido(tipo::GOAWAY, 0, 1, &[0, 0, 0, 9, 0, 0, 0, 0]),
        da_conexao(CodigoH2::PROTOCOL_ERROR)
    );
}

#[test]
fn a_janela_e_o_incremento_zero() {
    let mut escrito = Vec::new();
    quadro::por_janela(&mut escrito, 3, 1000);
    let [(c, carga)] = &quadros(&escrito)[..] else {
        panic!()
    };
    assert_eq!(*c, cabeca(4, tipo::WINDOW_UPDATE, 0, 3));
    assert_eq!(
        ler(*c, carga),
        Ok(Quadro::Janela {
            corrente: 3,
            incremento: 1000,
        })
    );
    // O bit reservado é ignorado.
    assert_eq!(
        lido(tipo::WINDOW_UPDATE, 0, 0, &[0x80, 0, 0, 1]),
        Ok(Quadro::Janela {
            corrente: 0,
            incremento: 1,
        })
    );
    // O incremento zero: da corrente, ou da conexão.
    assert_eq!(
        lido(tipo::WINDOW_UPDATE, 0, 3, &[0x80, 0, 0, 0]),
        da_corrente(CodigoH2::PROTOCOL_ERROR, 3)
    );
    assert_eq!(
        lido(tipo::WINDOW_UPDATE, 0, 0, &[0, 0, 0, 0]),
        da_conexao(CodigoH2::PROTOCOL_ERROR)
    );
    assert_eq!(
        lido(tipo::WINDOW_UPDATE, 0, 3, &[0, 0, 1]),
        da_conexao(CodigoH2::FRAME_SIZE_ERROR)
    );
}

#[test]
fn o_desconhecido_e_ignorado_e_a_promessa_e_da_conexao() {
    assert_eq!(lido(0xfa, 0xff, 9, b"qualquer"), Ok(Quadro::Ignorado));
    assert_eq!(lido(0xfa, 0, 0, b""), Ok(Quadro::Ignorado));
    assert_eq!(
        lido(
            tipo::PUSH_PROMISE,
            bandeira::END_HEADERS,
            1,
            &[0, 0, 0, 2, 0x82]
        ),
        Ok(Quadro::Promessa)
    );
}

#[test]
fn os_nomes_dos_codigos() {
    for (codigo, nome) in [
        (CodigoH2::NO_ERROR, "NO_ERROR"),
        (CodigoH2::PROTOCOL_ERROR, "PROTOCOL_ERROR"),
        (CodigoH2::INTERNAL_ERROR, "INTERNAL_ERROR"),
        (CodigoH2::FLOW_CONTROL_ERROR, "FLOW_CONTROL_ERROR"),
        (CodigoH2::SETTINGS_TIMEOUT, "SETTINGS_TIMEOUT"),
        (CodigoH2::STREAM_CLOSED, "STREAM_CLOSED"),
        (CodigoH2::FRAME_SIZE_ERROR, "FRAME_SIZE_ERROR"),
        (CodigoH2::REFUSED_STREAM, "REFUSED_STREAM"),
        (CodigoH2::CANCEL, "CANCEL"),
        (CodigoH2::COMPRESSION_ERROR, "COMPRESSION_ERROR"),
        (CodigoH2::CONNECT_ERROR, "CONNECT_ERROR"),
        (CodigoH2::ENHANCE_YOUR_CALM, "ENHANCE_YOUR_CALM"),
        (CodigoH2::INADEQUATE_SECURITY, "INADEQUATE_SECURITY"),
        (CodigoH2::HTTP_1_1_REQUIRED, "HTTP_1_1_REQUIRED"),
        (CodigoH2(0xe), "UNKNOWN"),
        (CodigoH2(u32::MAX), "UNKNOWN"),
    ] {
        assert_eq!(codigo.nome(), nome);
    }
}
