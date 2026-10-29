//! Os testes da cópia de segurança, no hospedeiro: a ida e a volta, e cada
//! jeito de estragar uma cópia — que tem de ser recusada inteira.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use diario::estado::campos;
use diario::{Escritor, Meio, Percorrido, TAM_NONCE, TAM_SETOR};

use crate::copia::*;

const CHAVE: [u8; 32] = [7; 32];
const OUTRA_CHAVE: [u8; 32] = [8; 32];
const ORIGEM: Origem = Origem {
    publica: [0xa1; 32],
    instalacao: [0xb2; 16],
};

/// Uma cópia guardada em memória.
struct Memoria(Vec<u8>);

impl Meio for Memoria {
    fn setores(&self) -> u64 {
        (self.0.len() / TAM_SETOR) as u64
    }
    fn ler(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
        let i = setor as usize * TAM_SETOR;
        destino.copy_from_slice(self.0.get(i..i + destino.len()).ok_or("fora")?);
        Ok(())
    }
    fn escrever(&mut self, _: u64, _: &[u8]) -> Result<(), &'static str> {
        Err("so leitura")
    }
    fn descarregar(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
}

fn nonce(n: u64) -> [u8; TAM_NONCE] {
    let mut v = [0u8; TAM_NONCE];
    v[..8].copy_from_slice(&n.to_le_bytes());
    v
}

fn s(t: &str) -> String {
    String::from(t)
}

/// Um nó a pôr na cópia.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Item {
    Dir(String, u64),
    Arq(String, u64, Vec<u8>),
}

fn cabecalho(raiz: &str, origem: Origem) -> Cabecalho {
    Cabecalho {
        origem,
        raiz: s(raiz),
        versao: 1000,
        geracao: 4,
        tempo: 1_700_000_000,
    }
}

/// Escreve uma cópia pelo escritor do pacote.
fn escrever(
    cab: &Cabecalho,
    itens: &[Item],
    chave: &[u8; 32],
) -> Result<(Vec<u8>, Fechada), &'static str> {
    escrever_desde(cab, itens, chave, 0)
}

/// O mesmo, com os nonces contados a partir de `n`: duas cópias do mesmo
/// conteúdo, como duas cópias de verdade, que sorteiam os seus.
fn escrever_desde(
    cab: &Cabecalho,
    itens: &[Item],
    chave: &[u8; 32],
    mut n: u64,
) -> Result<(Vec<u8>, Fechada), &'static str> {
    let mut saida = Vec::new();
    let mut e = Escrita::comecar(
        chave,
        cab,
        || {
            n += 1;
            Ok(nonce(n))
        },
        |b| {
            saida.extend_from_slice(b);
            Ok(())
        },
    )?;
    for i in itens {
        match i {
            Item::Dir(c, v) => e.diretorio(c, *v)?,
            Item::Arq(c, v, conteudo) => {
                e.arquivo(c, *v, conteudo.len() as u64)?;
                // Em pedaços desiguais, para o escritor juntar e cortar.
                for p in conteudo.chunks(4080) {
                    e.conteudo(p)?;
                }
            }
        }
    }
    let f = e.fechar()?;
    Ok((saida, f))
}

/// O que a leitura entregou, em forma própria.
#[derive(Debug, PartialEq, Eq)]
enum Visto {
    Cab(Cabecalho),
    Dir(String, u64),
    Arq(String, u64, u64),
    Pedaco(Vec<u8>),
    Fim,
}

fn ler_com(
    bytes: &[u8],
    chave: &[u8; 32],
    origem: &Origem,
) -> Result<(Lida, Vec<Visto>), Recusa<()>> {
    let mut vistos = Vec::new();
    let lida = ler(&mut Memoria(bytes.to_vec()), chave, origem, |e| {
        vistos.push(match e {
            Evento::Cabecalho(c) => Visto::Cab(c.clone()),
            Evento::Diretorio { caminho, versao } => Visto::Dir(s(caminho), versao),
            Evento::Arquivo {
                caminho,
                versao,
                tamanho,
            } => Visto::Arq(s(caminho), versao, tamanho),
            Evento::Pedaco(b) => Visto::Pedaco(b.to_vec()),
            Evento::FimDoArquivo => Visto::Fim,
        });
        Ok(())
    })?;
    Ok((lida, vistos))
}

fn ler_aqui(bytes: &[u8]) -> Result<(Lida, Vec<Visto>), Recusa<()>> {
    ler_com(bytes, &CHAVE, &ORIGEM)
}

/// Os itens de volta, juntando os pedaços de cada arquivo.
fn itens_de(vistos: &[Visto]) -> Vec<Item> {
    let mut v: Vec<Item> = Vec::new();
    for x in vistos {
        match x {
            Visto::Cab(_) | Visto::Fim => {}
            Visto::Dir(c, ver) => v.push(Item::Dir(c.clone(), *ver)),
            Visto::Arq(c, ver, _) => v.push(Item::Arq(c.clone(), *ver, Vec::new())),
            Visto::Pedaco(b) => match v.last_mut() {
                Some(Item::Arq(_, _, conteudo)) => conteudo.extend_from_slice(b),
                _ => panic!("pedaco fora de arquivo"),
            },
        }
    }
    v
}

fn bytes_de(n: usize, semente: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(semente))
        .collect()
}

/// Uma árvore com um pouco de tudo: diretórios aninhados, arquivos vazios,
/// pequenos, de exatamente um bloco, e um maior que um pedaço.
fn arvore() -> Vec<Item> {
    vec![
        Item::Dir(s(""), 3),
        Item::Arq(s("a.txt"), 10, b"ola".to_vec()),
        Item::Dir(s("b"), 11),
        Item::Dir(s("b/c"), 13),
        Item::Arq(s("b/c/vazio"), 14, Vec::new()),
        Item::Arq(s("b/grande.bin"), 12, bytes_de(MAIOR_PEDACO * 2 + 77, 5)),
        Item::Arq(s("b/um-bloco"), 15, bytes_de(4080, 9)),
        Item::Arq(s("b0"), 16, bytes_de(1, 1)),
    ]
}

#[test]
fn a_copia_vai_e_volta() {
    let cab = cabecalho("compartilhado/docs", ORIGEM);
    let (bytes, fechada) = escrever(&cab, &arvore(), &CHAVE).unwrap();
    assert_eq!(bytes.len() % TAM_SETOR, 0);
    assert_eq!(fechada.setores, (bytes.len() / TAM_SETOR) as u64);
    let (lida, vistos) = ler_aqui(&bytes).unwrap();
    assert_eq!(lida.cabecalho, cab);
    assert_eq!(
        lida.id, fechada.id,
        "o identificador e o elo do fecho, dos dois lados"
    );
    assert_eq!(lida.totais, fechada.totais);
    assert_eq!(
        lida.totais,
        Totais {
            diretorios: 3,
            arquivos: 5,
            bytes: (3 + MAIOR_PEDACO * 2 + 77 + 4080 + 1) as u64,
        }
    );
    assert_eq!(vistos.first(), Some(&Visto::Cab(cab)));
    assert_eq!(itens_de(&vistos), arvore());
    // Cada arquivo termina com o fim dele, o vazio logo depois de nascer.
    let fins = vistos.iter().filter(|v| **v == Visto::Fim).count();
    assert_eq!(fins, 5);
    // Duas cópias da mesma árvore têm identificadores diferentes: os
    // nonces são outros.
    let mut n = 1000u64;
    let mut outra = Vec::new();
    let mut e = Escrita::comecar(
        &CHAVE,
        &cabecalho("compartilhado/docs", ORIGEM),
        || {
            n += 1;
            Ok(nonce(n))
        },
        |b| {
            outra.extend_from_slice(b);
            Ok(())
        },
    )
    .unwrap();
    e.diretorio("", 3).unwrap();
    let f2 = e.fechar().unwrap();
    assert_ne!(f2.id, fechada.id);
}

#[test]
fn a_copia_de_um_arquivo_so_e_a_vazia() {
    let um = vec![Item::Arq(s(""), 5, b"so eu".to_vec())];
    let (bytes, _) = escrever(&cabecalho("compartilhado/x.txt", ORIGEM), &um, &CHAVE).unwrap();
    assert_eq!(itens_de(&ler_aqui(&bytes).unwrap().1), um);
    let vazia = vec![Item::Dir(s(""), 2)];
    let (bytes, f) = escrever(&cabecalho("compartilhado", ORIGEM), &vazia, &CHAVE).unwrap();
    let (lida, vistos) = ler_aqui(&bytes).unwrap();
    assert_eq!(itens_de(&vistos), vazia);
    assert_eq!(
        lida.totais,
        Totais {
            diretorios: 1,
            arquivos: 0,
            bytes: 0
        }
    );
    assert_eq!(f.totais, lida.totais);
    // O armazém inteiro: a raiz dele é um diretório, nunca um arquivo, e a
    // única com a versão 0 — ela não é nó.
    let inteiro = vec![Item::Dir(s(""), 0), Item::Dir(s("compartilhado"), 2)];
    let (bytes, _) = escrever(&cabecalho("", ORIGEM), &inteiro, &CHAVE).unwrap();
    assert_eq!(itens_de(&ler_aqui(&bytes).unwrap().1), inteiro);
    assert!(
        escrever(
            &cabecalho("", ORIGEM),
            &[Item::Arq(s(""), 1, vec![1])],
            &CHAVE
        )
        .is_err()
    );
}

#[test]
fn o_escritor_nao_deixa_sair_uma_copia_fora_das_regras() {
    let cab = cabecalho("compartilhado", ORIGEM);
    let casos: Vec<(&str, Vec<Item>)> = vec![
        ("sem a raiz", vec![Item::Dir(s("a"), 2)]),
        (
            "fora de ordem",
            vec![
                Item::Dir(s(""), 1),
                Item::Dir(s("b"), 2),
                Item::Dir(s("a"), 3),
            ],
        ),
        (
            "repetido",
            vec![
                Item::Dir(s(""), 1),
                Item::Dir(s("a"), 2),
                Item::Dir(s("a"), 3),
            ],
        ),
        (
            "sem o pai",
            vec![Item::Dir(s(""), 1), Item::Dir(s("a/b"), 2)],
        ),
        (
            "abaixo de um arquivo",
            vec![
                Item::Dir(s(""), 1),
                Item::Arq(s("a"), 2, vec![1]),
                Item::Arq(s("a/b"), 3, vec![1]),
            ],
        ),
        ("versao zero", vec![Item::Dir(s(""), 0)]),
        (
            "versao zero abaixo da raiz",
            vec![Item::Dir(s(""), 1), Item::Dir(s("a"), 0)],
        ),
        ("versao da captura", vec![Item::Dir(s(""), 1000)]),
        (
            "caminho invalido",
            vec![Item::Dir(s(""), 1), Item::Dir(s("a b"), 2)],
        ),
        (
            "ponto ponto",
            vec![Item::Dir(s(""), 1), Item::Dir(s(".."), 2)],
        ),
    ];
    for (nome, itens) in casos {
        assert!(escrever(&cab, &itens, &CHAVE).is_err(), "{nome}");
    }
    // Conteúdo a mais, a menos, e fora de um arquivo.
    let mut n = 0u64;
    let mut saida = Vec::new();
    let mut e = Escrita::comecar(
        &CHAVE,
        &cab,
        || {
            n += 1;
            Ok(nonce(n))
        },
        |b| {
            saida.extend_from_slice(b);
            Ok(())
        },
    )
    .unwrap();
    assert!(e.conteudo(b"x").is_err(), "pedaco sem arquivo");
    e.diretorio("", 1).unwrap();
    e.arquivo("a", 2, 3).unwrap();
    assert!(e.conteudo(b"quatro").is_err(), "alem do tamanho");
    e.conteudo(b"ab").unwrap();
    assert!(e.diretorio("b", 3).is_err(), "no antes do fim do arquivo");
    assert!(e.fechar().is_err(), "fecho antes do fim do arquivo");
    // A raiz fora do armazém, e fundo demais.
    assert!(escrever(&cabecalho("../x", ORIGEM), &[Item::Dir(s(""), 1)], &CHAVE).is_err());
    let funda = "a/b/c/d/e/f/g";
    assert!(
        escrever(
            &cabecalho(funda, ORIGEM),
            &[
                Item::Dir(s(""), 1),
                Item::Dir(s("h"), 2),
                Item::Dir(s("h/i"), 3)
            ],
            &CHAVE
        )
        .is_err(),
        "nove niveis"
    );
}

/// Os registros de uma cópia, pelos cabeçalhos: (começo, setores).
fn registros(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut v = Vec::new();
    let mut i = TAM_SETOR;
    while i < bytes.len() {
        let setores = u32::from_le_bytes(bytes[i + 12..i + 16].try_into().unwrap()) as usize;
        v.push((i, setores * TAM_SETOR));
        i += setores * TAM_SETOR;
    }
    v
}

/// Uma cópia pequena: uma parte e o fecho — cada byte dela se troca.
fn pequena() -> Vec<u8> {
    let itens = vec![
        Item::Dir(s(""), 1),
        Item::Arq(s("a"), 2, b"primeiro".to_vec()),
        Item::Arq(s("b"), 3, bytes_de(700, 3)),
        Item::Arq(s("c"), 4, b"terceiro".to_vec()),
    ];
    escrever(&cabecalho("compartilhado", ORIGEM), &itens, &CHAVE)
        .unwrap()
        .0
}

/// Uma cópia com mais de uma parte: duas, e o fecho.
fn media() -> Vec<u8> {
    media_desde(0)
}

fn media_desde(n: u64) -> Vec<u8> {
    let itens = vec![
        Item::Dir(s(""), 1),
        Item::Arq(s("a"), 2, b"primeiro".to_vec()),
        Item::Arq(s("b"), 3, bytes_de(100_000, 3)),
        Item::Arq(s("c"), 4, b"terceiro".to_vec()),
    ];
    escrever_desde(&cabecalho("compartilhado", ORIGEM), &itens, &CHAVE, n)
        .unwrap()
        .0
}

#[test]
fn cada_byte_trocado_recusa_a_copia() {
    let bytes = pequena();
    assert_eq!(registros(&bytes).len(), 2, "uma parte e o fecho");
    for i in 0..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        match ler_aqui(&b) {
            Ok(_) => panic!("o byte {i} trocado passou"),
            Err(Recusa::Fora(())) => panic!("o byte {i}: recusa de quem leu"),
            Err(_) => {}
        }
    }
}

#[test]
fn o_primeiro_e_o_ultimo_byte_o_cabecalho_e_a_versao() {
    let bytes = pequena();
    let mut b = bytes.clone();
    b[0] ^= 0xff;
    assert_eq!(ler_aqui(&b).unwrap_err(), Recusa::NaoECopia);
    let mut b = bytes.clone();
    let ultimo = b.len() - 1;
    b[ultimo] ^= 0x01;
    assert!(matches!(ler_aqui(&b), Err(Recusa::Estragada(_))));
    let mut b = bytes.clone();
    b[8] = 2;
    assert_eq!(ler_aqui(&b).unwrap_err(), Recusa::Formato);
    let mut b = bytes.clone();
    b[300] = 1;
    assert!(matches!(ler_aqui(&b), Err(Recusa::Estragada(_))));
    // A versão do formato do journal, no cabeçalho do primeiro registro.
    let mut b = bytes.clone();
    b[TAM_SETOR + 8] = 9;
    assert_eq!(ler_aqui(&b).unwrap_err(), Recusa::NaoAbre);
    // O tamanho do texto cifrado do segundo registro.
    let (i, _) = registros(&bytes)[1];
    let mut b = bytes.clone();
    b[i + 32] ^= 0x10;
    assert!(matches!(ler_aqui(&b), Err(Recusa::Estragada(_))));
}

#[test]
fn a_copia_cortada_em_cada_setor_e_recusada() {
    let bytes = media();
    for setores in 0..bytes.len() / TAM_SETOR {
        let r = ler_aqui(&bytes[..setores * TAM_SETOR]);
        assert!(r.is_err(), "cortada em {setores} setores passou");
        assert_eq!(
            r.unwrap_err(),
            Recusa::Incompleta,
            "cortada em {setores} setores"
        );
    }
    assert!(ler_aqui(&bytes).is_ok());
}

#[test]
fn registros_tirados_repetidos_e_trocados_de_lugar() {
    let bytes = media();
    let regs = registros(&bytes);
    assert_eq!(regs.len(), 3, "duas partes e o fecho");
    let pedaco = |k: usize| bytes[regs[k].0..regs[k].0 + regs[k].1].to_vec();
    let montar = |ordem: &[usize]| {
        let mut v = bytes[..TAM_SETOR].to_vec();
        for &k in ordem {
            v.extend_from_slice(&pedaco(k));
        }
        v
    };
    let n = regs.len();
    let todos: Vec<usize> = (0..n).collect();
    assert!(ler_aqui(&montar(&todos)).is_ok());
    for k in 0..n {
        // Tirado.
        let sem: Vec<usize> = todos.iter().copied().filter(|&i| i != k).collect();
        assert!(ler_aqui(&montar(&sem)).is_err(), "sem o registro {k}");
        // Repetido logo depois de si.
        let mut dois = todos.clone();
        dois.insert(k, k);
        assert!(
            ler_aqui(&montar(&dois)).is_err(),
            "o registro {k} duas vezes"
        );
    }
    for a in 0..n {
        for b in a + 1..n {
            let mut trocada = todos.clone();
            trocada.swap(a, b);
            assert!(ler_aqui(&montar(&trocada)).is_err(), "{a} trocado com {b}");
        }
    }
    // O fecho de novo no fim, e um setor de zeros, e um de lixo.
    let mut v = bytes.clone();
    v.extend_from_slice(&pedaco(n - 1));
    assert_eq!(ler_aqui(&v).unwrap_err(), Recusa::Sobra);
    let mut v = bytes.clone();
    v.extend_from_slice(&[0u8; TAM_SETOR]);
    assert_eq!(ler_aqui(&v).unwrap_err(), Recusa::Sobra);
    let mut v = bytes.clone();
    v.extend_from_slice(&[0x5a; TAM_SETOR]);
    assert_eq!(ler_aqui(&v).unwrap_err(), Recusa::Sobra);
    // O bloco do meio de um registro grande zerado.
    let (i, t) = regs[1];
    let mut v = bytes.clone();
    v[i + t / 2..i + t / 2 + 64].fill(0);
    assert!(matches!(ler_aqui(&v), Err(Recusa::Estragada(_))));
    // Os registros de duas cópias misturados: cada um abre, e nenhum no
    // lugar do outro.
    let outra = media_desde(500);
    assert_ne!(outra, bytes, "a outra copia tem os seus nonces");
    let regs2 = registros(&outra);
    let mut v = bytes[..regs[1].0].to_vec();
    v.extend_from_slice(&outra[regs2[1].0..]);
    assert!(ler_aqui(&v).is_err(), "o fim de outra copia");
}

#[test]
fn de_outra_maquina_de_outra_instalacao_com_outra_chave() {
    let bytes = pequena();
    let outra_maquina = Origem {
        publica: [0xc3; 32],
        ..ORIGEM
    };
    assert_eq!(
        ler_com(&bytes, &CHAVE, &outra_maquina).unwrap_err(),
        Recusa::OutraMaquina
    );
    assert_eq!(
        ler_com(&bytes, &OUTRA_CHAVE, &ORIGEM).unwrap_err(),
        Recusa::NaoAbre
    );
    let outra_instalacao = Origem {
        instalacao: [0xd4; 16],
        ..ORIGEM
    };
    assert_eq!(
        ler_com(&bytes, &CHAVE, &outra_instalacao).unwrap_err(),
        Recusa::OutraInstalacao
    );
    // A pública trocada no setor em claro para a desta máquina: abre o
    // primeiro registro e acha a pública verdadeira no cabeçalho cifrado.
    let de_outra = escrever(
        &cabecalho("compartilhado", outra_maquina),
        &[Item::Dir(s(""), 1)],
        &CHAVE,
    )
    .unwrap()
    .0;
    let mut v = de_outra.clone();
    v[16..48].copy_from_slice(&ORIGEM.publica);
    assert!(matches!(ler_aqui(&v), Err(Recusa::Estragada(_))));
}

#[test]
fn quem_le_recusa_e_a_copia_inteira_e_recusada() {
    let bytes = pequena();
    let mut vistos = 0;
    let r = ler(&mut Memoria(bytes), &CHAVE, &ORIGEM, |e| {
        vistos += 1;
        if matches!(e, Evento::Pedaco(_)) {
            return Err("sem lugar");
        }
        Ok(())
    });
    assert_eq!(r.unwrap_err(), Recusa::Fora("sem lugar"));
    assert!(vistos >= 3, "o cabecalho, a raiz e o arquivo vieram antes");
}

/// Uma cópia escrita à mão, com a chave certa, para as regras que o
/// escritor não deixaria passar: o leitor tem de recusar por si.
struct AMao {
    base: diario::Base,
    bytes: Vec<u8>,
    n: u64,
}

impl AMao {
    fn nova(publica: &[u8; 32]) -> AMao {
        let mut bytes = vec![0u8; TAM_SETOR];
        bytes[..8].copy_from_slice(b"DUKECOP1");
        bytes[8..10].copy_from_slice(&FORMATO.to_le_bytes());
        bytes[16..48].copy_from_slice(publica);
        AMao {
            base: Escritor::depois_de(&Percorrido::vazio(), 0, 1 << 30)
                .base(1 << 30)
                .unwrap(),
            bytes,
            n: 0,
        }
    }

    fn parte(&mut self, entradas: &[Vec<u8>]) {
        self.n += 1;
        let dados = campos(&entradas.iter().map(Vec::as_slice).collect::<Vec<_>>()).unwrap();
        let p = self
            .base
            .parte(&CHAVE, nonce(self.n), 0, 0, &dados)
            .unwrap();
        self.bytes.extend_from_slice(&p.bytes);
    }

    fn fechar(mut self, fecho: &[u8]) -> Vec<u8> {
        self.n += 1;
        let f = self
            .base
            .fechar(&CHAVE, nonce(self.n), 0, 0, fecho)
            .unwrap();
        self.bytes.extend_from_slice(&f.bytes);
        self.bytes
    }
}

fn entrada(t: u16, resto: &[&[u8]]) -> Vec<u8> {
    let t = t.to_le_bytes();
    let mut todos: Vec<&[u8]> = vec![&t];
    todos.extend_from_slice(resto);
    campos(&todos).unwrap()
}

fn e_cab(origem: &Origem, raiz: &str, versao: u64) -> Vec<u8> {
    entrada(
        tipo::CABECALHO,
        &[
            &FORMATO.to_le_bytes(),
            &origem.publica,
            &origem.instalacao,
            raiz.as_bytes(),
            &versao.to_le_bytes(),
            &4u64.to_le_bytes(),
            &9u64.to_le_bytes(),
        ],
    )
}

fn e_dir(c: &str, v: u64) -> Vec<u8> {
    entrada(tipo::DIRETORIO, &[c.as_bytes(), &v.to_le_bytes()])
}

fn e_arq(c: &str, v: u64, n: u64) -> Vec<u8> {
    entrada(
        tipo::ARQUIVO,
        &[c.as_bytes(), &v.to_le_bytes(), &n.to_le_bytes()],
    )
}

fn e_ped(b: &[u8]) -> Vec<u8> {
    entrada(tipo::PEDACO, &[b])
}

fn fecho(d: u64, a: u64, b: u64) -> Vec<u8> {
    campos(&[&d.to_le_bytes(), &a.to_le_bytes(), &b.to_le_bytes()]).unwrap()
}

/// As partes de uma cópia à mão: cada uma, as entradas dela.
type Partes = Vec<Vec<Vec<u8>>>;

/// Uma cópia à mão com estas partes e este fecho.
fn a_mao(partes: &[Vec<Vec<u8>>], fecho: &[u8]) -> Vec<u8> {
    let mut m = AMao::nova(&ORIGEM.publica);
    for p in partes {
        m.parte(p);
    }
    m.fechar(fecho)
}

#[test]
fn a_mao_o_que_o_escritor_faria_passa() {
    let v = a_mao(
        &[
            vec![
                e_cab(&ORIGEM, "compartilhado", 50),
                e_dir("", 1),
                e_arq("a", 2, 3),
            ],
            vec![e_ped(b"abc")],
        ],
        &fecho(1, 1, 3),
    );
    let (lida, _) = ler_aqui(&v).unwrap();
    assert_eq!(
        lida.totais,
        Totais {
            diretorios: 1,
            arquivos: 1,
            bytes: 3
        }
    );
}

#[test]
fn a_mao_cada_regra_quebrada_e_recusada() {
    let cab = || e_cab(&ORIGEM, "compartilhado", 50);
    let casos: Vec<(&str, Partes, Vec<u8>)> = vec![
        ("sem cabecalho", vec![vec![e_dir("", 1)]], fecho(1, 0, 0)),
        (
            "dois cabecalhos",
            vec![vec![cab(), cab(), e_dir("", 1)]],
            fecho(1, 0, 0),
        ),
        (
            "cabecalho depois",
            vec![vec![cab(), e_dir("", 1), cab()]],
            fecho(1, 0, 0),
        ),
        (
            "outro formato",
            vec![vec![
                entrada(
                    tipo::CABECALHO,
                    &[
                        &2u16.to_le_bytes(),
                        &ORIGEM.publica,
                        &ORIGEM.instalacao,
                        b"compartilhado",
                        &50u64.to_le_bytes(),
                        &4u64.to_le_bytes(),
                        &9u64.to_le_bytes(),
                    ],
                ),
                e_dir("", 1),
            ]],
            fecho(1, 0, 0),
        ),
        (
            "sem a raiz",
            vec![vec![cab(), e_dir("a", 1)]],
            fecho(1, 0, 0),
        ),
        (
            "fora de ordem",
            vec![vec![cab(), e_dir("", 1), e_dir("b", 2), e_dir("a", 3)]],
            fecho(3, 0, 0),
        ),
        (
            "repetido",
            vec![vec![cab(), e_dir("", 1), e_dir("a", 2), e_dir("a", 3)]],
            fecho(3, 0, 0),
        ),
        (
            "sem o pai",
            vec![vec![cab(), e_dir("", 1), e_dir("a/b", 2)]],
            fecho(2, 0, 0),
        ),
        (
            "abaixo de arquivo",
            vec![vec![
                cab(),
                e_dir("", 1),
                e_arq("a", 2, 0),
                e_arq("a/b", 3, 0),
            ]],
            fecho(1, 2, 0),
        ),
        (
            "abaixo da raiz arquivo",
            vec![vec![cab(), e_arq("", 1, 0), e_arq("b", 2, 0)]],
            fecho(0, 2, 0),
        ),
        (
            "versao da captura",
            vec![vec![cab(), e_dir("", 50)]],
            fecho(1, 0, 0),
        ),
        (
            "versao zero",
            vec![vec![cab(), e_dir("", 0)]],
            fecho(1, 0, 0),
        ),
        (
            "caminho invalido",
            vec![vec![cab(), e_dir("", 1), e_dir("a b", 2)]],
            fecho(2, 0, 0),
        ),
        (
            "pedaco sem arquivo",
            vec![vec![cab(), e_dir("", 1), e_ped(b"x")]],
            fecho(1, 0, 1),
        ),
        (
            "pedaco alem",
            vec![
                vec![cab(), e_dir("", 1), e_arq("a", 2, 2)],
                vec![e_ped(b"abc")],
            ],
            fecho(1, 1, 3),
        ),
        (
            "pedaco vazio",
            vec![vec![cab(), e_dir("", 1), e_arq("a", 2, 2), e_ped(b"")]],
            fecho(1, 1, 0),
        ),
        (
            "pedaco grande demais",
            vec![
                vec![
                    cab(),
                    e_dir("", 1),
                    e_arq("a", 2, (MAIOR_PEDACO + 1) as u64),
                ],
                vec![e_ped(&vec![1; MAIOR_PEDACO + 1])],
            ],
            fecho(1, 1, (MAIOR_PEDACO + 1) as u64),
        ),
        (
            "no antes do fim do arquivo",
            vec![vec![
                cab(),
                e_dir("", 1),
                e_arq("a", 2, 4),
                e_ped(b"ab"),
                e_dir("b", 3),
            ]],
            fecho(2, 1, 2),
        ),
        (
            "fecho antes do fim do arquivo",
            vec![vec![cab(), e_dir("", 1), e_arq("a", 2, 4), e_ped(b"ab")]],
            fecho(1, 1, 2),
        ),
        (
            "totais errados",
            vec![vec![cab(), e_dir("", 1), e_dir("a", 2)]],
            fecho(1, 0, 0),
        ),
        (
            "bytes errados",
            vec![vec![cab(), e_dir("", 1), e_arq("a", 2, 1), e_ped(b"x")]],
            fecho(1, 1, 2),
        ),
        (
            "entrada desconhecida",
            vec![vec![cab(), e_dir("", 1), entrada(99, &[b"x"])]],
            fecho(1, 0, 0),
        ),
        (
            "campos a mais",
            vec![vec![
                cab(),
                entrada(tipo::DIRETORIO, &[b"", &1u64.to_le_bytes(), b"dono"]),
            ]],
            fecho(1, 0, 0),
        ),
        (
            "fecho de outro tamanho",
            vec![vec![cab(), e_dir("", 1)]],
            campos(&[&1u64.to_le_bytes()]).unwrap(),
        ),
        (
            "texto que nao e utf-8",
            vec![vec![
                cab(),
                e_dir("", 1),
                entrada(tipo::DIRETORIO, &[&[0xff, 0xfe], &2u64.to_le_bytes()]),
            ]],
            fecho(2, 0, 0),
        ),
    ];
    for (nome, partes, f) in casos {
        let v = a_mao(&partes, &f);
        let r = ler_aqui(&v);
        assert!(matches!(r, Err(Recusa::Estragada(_))), "{nome}: {r:?}");
    }
    // A raiz do armazém como arquivo, e uma raiz fora do armazém.
    let v = a_mao(
        &[vec![e_cab(&ORIGEM, "", 50), e_arq("", 1, 0)]],
        &fecho(0, 1, 0),
    );
    assert!(matches!(ler_aqui(&v), Err(Recusa::Estragada(_))));
    let v = a_mao(
        &[vec![e_cab(&ORIGEM, "a/../b", 50), e_dir("", 1)]],
        &fecho(1, 0, 0),
    );
    assert!(matches!(ler_aqui(&v), Err(Recusa::Estragada(_))));
    // A cópia sem parte nenhuma: só o fecho.
    let v = a_mao(&[], &fecho(0, 0, 0));
    assert!(matches!(ler_aqui(&v), Err(Recusa::Estragada(_))));
    // A cópia sem o fecho: as partes, e nada mais.
    let mut m = AMao::nova(&ORIGEM.publica);
    m.parte(&[cab(), e_dir("", 1)]);
    assert_eq!(ler_aqui(&m.bytes).unwrap_err(), Recusa::Incompleta);
}
