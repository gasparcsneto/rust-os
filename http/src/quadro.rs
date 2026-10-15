//! Os quadros do HTTP/2 (RFC 9113, 4 e 6): como a conexão se divide.
//!
//! Cada quadro tem um cabeçalho de nove bytes — tamanho (24 bits), tipo,
//! bandeiras e a corrente (31 bits) — e a carga. Este módulo só lê e escreve
//! quadros, e confere o que a RFC manda conferir em cada um: a corrente zero
//! onde não pode, o tamanho que cada tipo tem, o preenchimento que não cabe.
//! Cada recusa diz o código do HTTP/2 e o alcance — a conexão inteira, ou
//! só uma corrente ([`ErroDeQuadro`]). O que os quadros significam juntos —
//! estados, janelas, a ordem dos blocos de cabeça — é da conexão
//! ([`crate::h2`]).

use alloc::vec::Vec;

/// O prefácio do cliente (RFC 9113, 3.4): a primeira coisa na conexão.
pub(crate) const PREFACIO: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// O tamanho do cabeçalho de um quadro.
pub(crate) const CABECA: usize = 9;

/// O menor `SETTINGS_MAX_FRAME_SIZE` — o de quem não anuncia outro — e o
/// maior que se pode anunciar.
pub(crate) const QUADRO_PADRAO: usize = 1 << 14;
pub(crate) const QUADRO_MAXIMO: usize = (1 << 24) - 1;

/// A maior janela do controle de fluxo (RFC 9113, 6.9.1).
pub(crate) const JANELA_MAXIMA: i64 = (1 << 31) - 1;

/// A janela de quem não anunciou outra.
pub(crate) const JANELA_PADRAO: i64 = 65_535;

/// Os tipos de quadro.
pub(crate) mod tipo {
    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const PRIORITY: u8 = 0x2;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    pub const PUSH_PROMISE: u8 = 0x5;
    pub const PING: u8 = 0x6;
    pub const GOAWAY: u8 = 0x7;
    pub const WINDOW_UPDATE: u8 = 0x8;
    pub const CONTINUATION: u8 = 0x9;
}

/// As bandeiras.
pub(crate) mod bandeira {
    pub const END_STREAM: u8 = 0x1;
    pub const ACK: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

/// Os ajustes (RFC 9113, 6.5.2).
pub(crate) mod ajuste {
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
}

/// Um código de erro do HTTP/2 (RFC 9113, 7) — o que vai num `RST_STREAM`
/// ou num `GOAWAY`. Um código que a RFC não define é guardado como veio.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodigoH2(pub u32);

impl CodigoH2 {
    pub const NO_ERROR: CodigoH2 = CodigoH2(0x0);
    pub const PROTOCOL_ERROR: CodigoH2 = CodigoH2(0x1);
    pub const INTERNAL_ERROR: CodigoH2 = CodigoH2(0x2);
    pub const FLOW_CONTROL_ERROR: CodigoH2 = CodigoH2(0x3);
    pub const SETTINGS_TIMEOUT: CodigoH2 = CodigoH2(0x4);
    pub const STREAM_CLOSED: CodigoH2 = CodigoH2(0x5);
    pub const FRAME_SIZE_ERROR: CodigoH2 = CodigoH2(0x6);
    pub const REFUSED_STREAM: CodigoH2 = CodigoH2(0x7);
    pub const CANCEL: CodigoH2 = CodigoH2(0x8);
    pub const COMPRESSION_ERROR: CodigoH2 = CodigoH2(0x9);
    pub const CONNECT_ERROR: CodigoH2 = CodigoH2(0xa);
    pub const ENHANCE_YOUR_CALM: CodigoH2 = CodigoH2(0xb);
    pub const INADEQUATE_SECURITY: CodigoH2 = CodigoH2(0xc);
    pub const HTTP_1_1_REQUIRED: CodigoH2 = CodigoH2(0xd);

    /// O nome que a RFC dá ao código.
    pub const fn nome(self) -> &'static str {
        match self.0 {
            0x0 => "NO_ERROR",
            0x1 => "PROTOCOL_ERROR",
            0x2 => "INTERNAL_ERROR",
            0x3 => "FLOW_CONTROL_ERROR",
            0x4 => "SETTINGS_TIMEOUT",
            0x5 => "STREAM_CLOSED",
            0x6 => "FRAME_SIZE_ERROR",
            0x7 => "REFUSED_STREAM",
            0x8 => "CANCEL",
            0x9 => "COMPRESSION_ERROR",
            0xa => "CONNECT_ERROR",
            0xb => "ENHANCE_YOUR_CALM",
            0xc => "INADEQUATE_SECURITY",
            0xd => "HTTP_1_1_REQUIRED",
            _ => "UNKNOWN",
        }
    }
}

/// Um quadro recusado: o código, e se o erro é da conexão inteira (`None`)
/// ou só de uma corrente.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ErroDeQuadro {
    pub codigo: CodigoH2,
    pub corrente: Option<u32>,
}

const fn da_conexao(codigo: CodigoH2) -> ErroDeQuadro {
    ErroDeQuadro {
        codigo,
        corrente: None,
    }
}

const fn da_corrente(codigo: CodigoH2, corrente: u32) -> ErroDeQuadro {
    ErroDeQuadro {
        codigo,
        corrente: Some(corrente),
    }
}

/// O cabeçalho de um quadro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Cabeca {
    pub tamanho: usize,
    pub tipo: u8,
    pub bandeiras: u8,
    pub corrente: u32,
}

/// Lê o cabeçalho de nove bytes. O bit reservado da corrente é ignorado,
/// como a RFC manda.
pub(crate) fn ler_cabeca(b: &[u8; CABECA]) -> Cabeca {
    Cabeca {
        tamanho: (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]),
        tipo: b[3],
        bandeiras: b[4],
        corrente: u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff,
    }
}

/// Um quadro lido e conferido.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Quadro<'a> {
    /// `DATA`: os dados, sem o preenchimento. O controle de fluxo conta a
    /// carga inteira, preenchimento junto — a cabeça já diz quanto.
    Dados {
        corrente: u32,
        dados: &'a [u8],
        fim: bool,
    },
    /// `HEADERS`: o começo de um bloco de cabeça.
    Cabecalhos {
        corrente: u32,
        bloco: &'a [u8],
        fim_da_corrente: bool,
        fim_da_cabeca: bool,
    },
    /// `PRIORITY`, ou um tipo que a RFC não define: conferidos e ignorados.
    Ignorado,
    /// `RST_STREAM`.
    Reinicio { corrente: u32, codigo: CodigoH2 },
    /// `SETTINGS`: os pares (seis bytes cada), ou o reconhecimento.
    Ajustes { ack: bool, pares: &'a [u8] },
    /// `PUSH_PROMISE`.
    Promessa,
    /// `PING`.
    Ping { ack: bool, dados: [u8; 8] },
    /// `GOAWAY`: a última corrente que o servidor processou, e o código.
    Adeus { ultima: u32, codigo: CodigoH2 },
    /// `WINDOW_UPDATE`.
    Janela { corrente: u32, incremento: u32 },
    /// `CONTINUATION`: o resto de um bloco de cabeça.
    Continuacao {
        corrente: u32,
        bloco: &'a [u8],
        fim_da_cabeca: bool,
    },
}

/// O preenchimento de um `DATA` ou `HEADERS` com `PADDED`: tira o byte do
/// tamanho e o preenchimento, ou recusa — sem o byte do tamanho, o quadro é
/// pequeno demais; o preenchimento do tamanho da carga ou maior é erro de
/// protocolo (RFC 9113, 4.2 e 6.1). Os dois, da conexão.
fn sem_preenchimento(carga: &[u8]) -> Result<&[u8], ErroDeQuadro> {
    let (&enchimento, resto) = carga
        .split_first()
        .ok_or(da_conexao(CodigoH2::FRAME_SIZE_ERROR))?;
    let enchimento = usize::from(enchimento);
    if enchimento >= carga.len() {
        return Err(da_conexao(CodigoH2::PROTOCOL_ERROR));
    }
    Ok(&resto[..resto.len() - enchimento])
}

fn u32_de(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Confere e lê a carga de um quadro com a cabeça `c`. A cabeça já passou
/// pelo tamanho máximo anunciado — ver [`crate::h2`].
pub(crate) fn ler(c: Cabeca, carga: &[u8]) -> Result<Quadro<'_>, ErroDeQuadro> {
    let tem = |b: u8| c.bandeiras & b != 0;
    match c.tipo {
        tipo::DATA => {
            if c.corrente == 0 {
                return Err(da_conexao(CodigoH2::PROTOCOL_ERROR));
            }
            let dados = if tem(bandeira::PADDED) {
                sem_preenchimento(carga)?
            } else {
                carga
            };
            Ok(Quadro::Dados {
                corrente: c.corrente,
                dados,
                fim: tem(bandeira::END_STREAM),
            })
        }
        tipo::HEADERS => {
            if c.corrente == 0 {
                return Err(da_conexao(CodigoH2::PROTOCOL_ERROR));
            }
            let mut bloco = if tem(bandeira::PADDED) {
                sem_preenchimento(carga)?
            } else {
                carga
            };
            if tem(bandeira::PRIORITY) {
                // A dependência e o peso: ignorados, como a prioridade
                // inteira — mas a corrente não depende de si mesma. A RFC
                // faz disso um erro só da corrente; aqui ele é da conexão
                // (o que a 5.4.1 permite), porque recusar o quadro deixaria
                // o bloco de cabeça dele sem decodificar, e a tabela do
                // HPACK, sem as entradas que ele traz.
                if bloco.len() < 5 {
                    return Err(da_conexao(CodigoH2::FRAME_SIZE_ERROR));
                }
                if u32_de(bloco) & 0x7fff_ffff == c.corrente {
                    return Err(da_conexao(CodigoH2::PROTOCOL_ERROR));
                }
                bloco = &bloco[5..];
            }
            Ok(Quadro::Cabecalhos {
                corrente: c.corrente,
                bloco,
                fim_da_corrente: tem(bandeira::END_STREAM),
                fim_da_cabeca: tem(bandeira::END_HEADERS),
            })
        }
        tipo::PRIORITY => {
            if c.corrente == 0 {
                return Err(da_conexao(CodigoH2::PROTOCOL_ERROR));
            }
            if carga.len() != 5 {
                return Err(da_corrente(CodigoH2::FRAME_SIZE_ERROR, c.corrente));
            }
            if u32_de(carga) & 0x7fff_ffff == c.corrente {
                return Err(da_corrente(CodigoH2::PROTOCOL_ERROR, c.corrente));
            }
            Ok(Quadro::Ignorado)
        }
        tipo::RST_STREAM => {
            if c.corrente == 0 {
                return Err(da_conexao(CodigoH2::PROTOCOL_ERROR));
            }
            if carga.len() != 4 {
                return Err(da_conexao(CodigoH2::FRAME_SIZE_ERROR));
            }
            Ok(Quadro::Reinicio {
                corrente: c.corrente,
                codigo: CodigoH2(u32_de(carga)),
            })
        }
        tipo::SETTINGS => {
            if c.corrente != 0 {
                return Err(da_conexao(CodigoH2::PROTOCOL_ERROR));
            }
            let ack = tem(bandeira::ACK);
            if (ack && !carga.is_empty()) || !carga.len().is_multiple_of(6) {
                return Err(da_conexao(CodigoH2::FRAME_SIZE_ERROR));
            }
            Ok(Quadro::Ajustes { ack, pares: carga })
        }
        tipo::PUSH_PROMISE => Ok(Quadro::Promessa),
        tipo::PING => {
            if c.corrente != 0 {
                return Err(da_conexao(CodigoH2::PROTOCOL_ERROR));
            }
            let dados: [u8; 8] = carga
                .try_into()
                .map_err(|_| da_conexao(CodigoH2::FRAME_SIZE_ERROR))?;
            Ok(Quadro::Ping {
                ack: tem(bandeira::ACK),
                dados,
            })
        }
        tipo::GOAWAY => {
            if c.corrente != 0 {
                return Err(da_conexao(CodigoH2::PROTOCOL_ERROR));
            }
            if carga.len() < 8 {
                return Err(da_conexao(CodigoH2::FRAME_SIZE_ERROR));
            }
            Ok(Quadro::Adeus {
                ultima: u32_de(carga) & 0x7fff_ffff,
                codigo: CodigoH2(u32_de(&carga[4..])),
            })
        }
        tipo::WINDOW_UPDATE => {
            if carga.len() != 4 {
                return Err(da_conexao(CodigoH2::FRAME_SIZE_ERROR));
            }
            let incremento = u32_de(carga) & 0x7fff_ffff;
            if incremento == 0 {
                return Err(match c.corrente {
                    0 => da_conexao(CodigoH2::PROTOCOL_ERROR),
                    n => da_corrente(CodigoH2::PROTOCOL_ERROR, n),
                });
            }
            Ok(Quadro::Janela {
                corrente: c.corrente,
                incremento,
            })
        }
        tipo::CONTINUATION => {
            if c.corrente == 0 {
                return Err(da_conexao(CodigoH2::PROTOCOL_ERROR));
            }
            Ok(Quadro::Continuacao {
                corrente: c.corrente,
                bloco: carga,
                fim_da_cabeca: tem(bandeira::END_HEADERS),
            })
        }
        // Um tipo que a RFC não define é ignorado (RFC 9113, 4.1).
        _ => Ok(Quadro::Ignorado),
    }
}

/// Acrescenta a `saida` o cabeçalho de um quadro.
pub(crate) fn por_cabeca(
    saida: &mut Vec<u8>,
    tamanho: usize,
    tipo: u8,
    bandeiras: u8,
    corrente: u32,
) {
    debug_assert!(tamanho <= QUADRO_MAXIMO);
    saida.extend_from_slice(&[
        (tamanho >> 16) as u8,
        (tamanho >> 8) as u8,
        tamanho as u8,
        tipo,
        bandeiras,
    ]);
    saida.extend_from_slice(&(corrente & 0x7fff_ffff).to_be_bytes());
}

/// Um `SETTINGS` com `pares`.
pub(crate) fn por_ajustes(saida: &mut Vec<u8>, pares: &[(u16, u32)]) {
    por_cabeca(saida, pares.len() * 6, tipo::SETTINGS, 0, 0);
    for &(id, valor) in pares {
        saida.extend_from_slice(&id.to_be_bytes());
        saida.extend_from_slice(&valor.to_be_bytes());
    }
}

/// O reconhecimento de um `SETTINGS`.
pub(crate) fn por_ajustes_ack(saida: &mut Vec<u8>) {
    por_cabeca(saida, 0, tipo::SETTINGS, bandeira::ACK, 0);
}

/// Um `WINDOW_UPDATE`.
pub(crate) fn por_janela(saida: &mut Vec<u8>, corrente: u32, incremento: u32) {
    por_cabeca(saida, 4, tipo::WINDOW_UPDATE, 0, corrente);
    saida.extend_from_slice(&(incremento & 0x7fff_ffff).to_be_bytes());
}

/// Um `RST_STREAM`.
pub(crate) fn por_reinicio(saida: &mut Vec<u8>, corrente: u32, codigo: CodigoH2) {
    por_cabeca(saida, 4, tipo::RST_STREAM, 0, corrente);
    saida.extend_from_slice(&codigo.0.to_be_bytes());
}

/// A resposta a um `PING`.
pub(crate) fn por_ping_ack(saida: &mut Vec<u8>, dados: &[u8; 8]) {
    por_cabeca(saida, 8, tipo::PING, bandeira::ACK, 0);
    saida.extend_from_slice(dados);
}

/// Um `GOAWAY`.
pub(crate) fn por_adeus(saida: &mut Vec<u8>, ultima: u32, codigo: CodigoH2) {
    por_cabeca(saida, 8, tipo::GOAWAY, 0, 0);
    saida.extend_from_slice(&(ultima & 0x7fff_ffff).to_be_bytes());
    saida.extend_from_slice(&codigo.0.to_be_bytes());
}

/// O bloco de cabeça de uma corrente: um `HEADERS` e, se não couber em
/// `maior` bytes, os `CONTINUATION` que faltam.
pub(crate) fn por_cabecalhos(
    saida: &mut Vec<u8>,
    corrente: u32,
    bloco: &[u8],
    fim_da_corrente: bool,
    maior: usize,
) {
    let mut partes = bloco.chunks(maior.max(1)).peekable();
    let primeira = partes.next().unwrap_or(&[]);
    let mut bandeiras = if fim_da_corrente {
        bandeira::END_STREAM
    } else {
        0
    };
    if partes.peek().is_none() {
        bandeiras |= bandeira::END_HEADERS;
    }
    por_cabeca(saida, primeira.len(), tipo::HEADERS, bandeiras, corrente);
    saida.extend_from_slice(primeira);
    while let Some(parte) = partes.next() {
        let fim = if partes.peek().is_none() {
            bandeira::END_HEADERS
        } else {
            0
        };
        por_cabeca(saida, parte.len(), tipo::CONTINUATION, fim, corrente);
        saida.extend_from_slice(parte);
    }
}

/// Um `DATA`.
pub(crate) fn por_dados(saida: &mut Vec<u8>, corrente: u32, dados: &[u8], fim: bool) {
    let bandeiras = if fim { bandeira::END_STREAM } else { 0 };
    por_cabeca(saida, dados.len(), tipo::DATA, bandeiras, corrente);
    saida.extend_from_slice(dados);
}
