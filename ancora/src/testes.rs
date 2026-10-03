//! Os casos da âncora contra um TPM simulado.
//!
//! O simulado implementa só o que este pacote manda, com as regras da
//! especificação que importam aqui: o contador só cresce, nasce no maior
//! valor que o TPM já viu, recusa senha errada, e um índice definido e
//! nunca avançado não se lê. Os mesmos casos rodam contra o `swtpm` em
//! `tests/swtpm.rs` — o simulado é rápido e controlável, o `swtpm` é a
//! prova de que o simulado e este pacote entendem o TPM do mesmo jeito.

extern crate std;

use std::vec::Vec;

use super::*;

const INDICE: u32 = 0x0180_D0E0;
const SENHA: [u8; 32] = [0x5A; 32];

/// Um índice de NV no simulado.
struct Indice {
    atributos: u32,
    senha: Vec<u8>,
    tamanho: u16,
    valor: Option<u64>,
}

/// Um TPM de mentira, que entende os comandos deste pacote.
#[derive(Default)]
struct Simulado {
    iniciado: bool,
    indices: Vec<(u32, Indice)>,
    /// O maior valor que qualquer contador já teve.
    maior: u64,
    /// Quantos comandos chegaram, para os casos que contam idas ao TPM.
    comandos: usize,
    /// Quebra a próxima resposta deste jeito, uma vez.
    estragar: Option<fn(&mut Vec<u8>)>,
}

fn cabecalho(etiqueta: u16, codigo: u32, corpo: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&etiqueta.to_be_bytes());
    r.extend_from_slice(&((10 + corpo.len()) as u32).to_be_bytes());
    r.extend_from_slice(&codigo.to_be_bytes());
    r.extend_from_slice(corpo);
    r
}

fn erro(codigo: u32) -> Vec<u8> {
    cabecalho(SEM_SESSOES, codigo, &[])
}

/// A resposta de sucesso de um comando com sessão: parâmetros e a área de
/// autorização da sessão de senha.
fn com_sessao(parametros: &[u8]) -> Vec<u8> {
    let mut corpo = Vec::new();
    corpo.extend_from_slice(&(parametros.len() as u32).to_be_bytes());
    corpo.extend_from_slice(parametros);
    corpo.extend_from_slice(&[0, 0, CONTINUAR_SESSAO, 0, 0]);
    cabecalho(COM_SESSOES, 0, &corpo)
}

struct Ler<'a>(&'a [u8], usize);
impl Ler<'_> {
    fn u16(&mut self) -> u16 {
        let v = u16::from_be_bytes([self.0[self.1], self.0[self.1 + 1]]);
        self.1 += 2;
        v
    }
    fn u32(&mut self) -> u32 {
        let v = u32::from_be_bytes(self.0[self.1..self.1 + 4].try_into().unwrap());
        self.1 += 4;
        v
    }
    fn tpm2b(&mut self) -> Vec<u8> {
        let n = self.u16() as usize;
        let v = self.0[self.1..self.1 + n].to_vec();
        self.1 += n;
        v
    }
    /// A área de autorização: devolve a senha.
    fn sessao(&mut self) -> Vec<u8> {
        let _tamanho = self.u32();
        assert_eq!(self.u32(), SESSAO_DE_SENHA);
        assert!(self.tpm2b().is_empty());
        self.1 += 1;
        self.tpm2b()
    }
}

impl Simulado {
    fn indice(&mut self, n: u32) -> Option<&mut Indice> {
        self.indices
            .iter_mut()
            .find(|(i, _)| *i == n)
            .map(|(_, x)| x)
    }

    fn responder(&mut self, c: &[u8]) -> Vec<u8> {
        let mut l = Ler(c, 0);
        let etiqueta = l.u16();
        let tamanho = l.u32() as usize;
        assert_eq!(tamanho, c.len(), "o tamanho no cabecalho do comando");
        let codigo = l.u32();
        if codigo == comando::STARTUP {
            assert_eq!(etiqueta, SEM_SESSOES);
            let tipo = l.u16();
            assert_eq!(tipo, REINICIO_LIMPO);
            if self.iniciado {
                return erro(codigo::JA_INICIADO);
            }
            self.iniciado = true;
            return erro(0);
        }
        if !self.iniciado {
            return erro(0x100); // TPM_RC_INITIALIZE: não iniciado
        }
        match codigo {
            comando::NV_READ_PUBLIC => {
                let n = l.u32();
                let Some(x) = self.indice(n) else {
                    return erro(codigo::INDICE_INEXISTENTE);
                };
                let mut publico = Vec::new();
                publico.extend_from_slice(&n.to_be_bytes());
                publico.extend_from_slice(&SHA256.to_be_bytes());
                let escrito = if x.valor.is_some() {
                    atributo::ESCRITO
                } else {
                    0
                };
                publico.extend_from_slice(&(x.atributos | escrito).to_be_bytes());
                publico.extend_from_slice(&[0, 0]);
                publico.extend_from_slice(&x.tamanho.to_be_bytes());
                let mut corpo = Vec::new();
                corpo.extend_from_slice(&(publico.len() as u16).to_be_bytes());
                corpo.extend_from_slice(&publico);
                corpo.extend_from_slice(&[0, 2, 0xAB, 0xCD]); // um nome qualquer
                cabecalho(SEM_SESSOES, 0, &corpo)
            }
            comando::NV_DEFINE_SPACE => {
                assert_eq!(l.u32(), DONO);
                assert!(l.sessao().is_empty(), "a senha do dono do simulado e vazia");
                let senha = l.tpm2b();
                let _tam = l.u16();
                let n = l.u32();
                assert_eq!(l.u16(), SHA256);
                let atributos = l.u32();
                assert!(l.tpm2b().is_empty());
                let tamanho = l.u16();
                if self.indice(n).is_some() {
                    return erro(codigo::NV_JA_DEFINIDO);
                }
                self.indices.push((
                    n,
                    Indice {
                        atributos,
                        senha,
                        tamanho,
                        valor: None,
                    },
                ));
                com_sessao(&[])
            }
            comando::NV_UNDEFINE_SPACE => {
                assert_eq!(l.u32(), DONO);
                let n = l.u32();
                l.sessao();
                if self.indice(n).is_none() {
                    return erro(codigo::INDICE_INEXISTENTE);
                }
                self.indices.retain(|(i, _)| *i != n);
                com_sessao(&[])
            }
            comando::NV_WRITE => {
                let a = l.u32();
                let n = l.u32();
                assert_eq!(a, n, "a autorizacao e a do proprio indice");
                let senha = l.sessao();
                let dados = l.tpm2b();
                assert_eq!(l.u16(), 0, "escreve-se do inicio");
                let Some(x) = self.indice(n) else {
                    return erro(codigo::INDICE_INEXISTENTE);
                };
                if senha != x.senha {
                    return erro(codigo::SENHA_ERRADA);
                }
                // Um contador não se escreve: TPM_RC_ATTRIBUTES no handle.
                if x.atributos & atributo::MASCARA_DO_TIPO != 0 {
                    return erro(0x182);
                }
                x.valor = Some(u64::from_be_bytes(dados[..].try_into().unwrap()));
                com_sessao(&[])
            }
            comando::NV_INCREMENT | comando::NV_READ => {
                let a = l.u32();
                let n = l.u32();
                assert_eq!(a, n, "a autorizacao e a do proprio indice");
                let senha = l.sessao();
                let maior = self.maior;
                let Some(x) = self.indice(n) else {
                    return erro(codigo::INDICE_INEXISTENTE);
                };
                if senha != x.senha {
                    return erro(codigo::SENHA_ERRADA);
                }
                if codigo == comando::NV_INCREMENT {
                    // Um índice comum não se incrementa.
                    if x.atributos & atributo::MASCARA_DO_TIPO != atributo::TIPO_CONTADOR {
                        return erro(0x182);
                    }
                    let novo = x.valor.unwrap_or(maior) + 1;
                    x.valor = Some(novo);
                    self.maior = self.maior.max(novo);
                    return com_sessao(&[]);
                }
                let (tam, desloc) = (l.u16(), l.u16());
                assert_eq!((tam, desloc), (8, 0));
                let Some(v) = x.valor else {
                    return erro(codigo::NV_NAO_INICIALIZADO);
                };
                let mut p = std::vec![0, 8];
                p.extend_from_slice(&v.to_be_bytes());
                com_sessao(&p)
            }
            outro => panic!("comando que o simulado nao conhece: {outro:#x}"),
        }
    }
}

impl Tpm for Simulado {
    fn trocar(&mut self, comando: &[u8], resposta: &mut [u8; MAIOR_QUADRO]) -> Result<usize, Erro> {
        self.comandos += 1;
        let mut r = self.responder(comando);
        if let Some(estragar) = self.estragar.take() {
            estragar(&mut r);
        }
        resposta[..r.len()].copy_from_slice(&r);
        Ok(r.len())
    }
}

fn aberta(tpm: &mut Simulado) -> (Ancora, u64) {
    match Ancora::abrir(tpm, INDICE, SENHA).unwrap() {
        Aberta::Presente(a, v) => (a, v),
        Aberta::Ausente => panic!("a ancora devia estar presente"),
    }
}

#[test]
fn o_startup_e_os_bytes_da_especificacao() {
    // TPM2_Startup(TPM_SU_CLEAR), o comando mais citado da especificação:
    // 80 01 | 00 00 00 0c | 00 00 01 44 | 00 00.
    let mut q = Quadro::novo(SEM_SESSOES, comando::STARTUP);
    q.u16(REINICIO_LIMPO);
    assert_eq!(
        q.fechar(),
        &[0x80, 0x01, 0, 0, 0, 0x0c, 0, 0, 0x01, 0x44, 0, 0]
    );
}

#[test]
fn startup_duas_vezes_e_sucesso() {
    let mut tpm = Simulado::default();
    iniciar(&mut tpm).unwrap();
    // A segunda é o caso de todo boot com firmware: ele já iniciou.
    iniciar(&mut tpm).unwrap();
}

#[test]
fn ausente_ate_ser_criada() {
    let mut tpm = Simulado::default();
    assert!(matches!(
        Ancora::abrir(&mut tpm, INDICE, SENHA).unwrap(),
        Aberta::Ausente
    ));
    let (_, v) = Ancora::criar(&mut tpm, INDICE, &[], SENHA).unwrap();
    let (_, lido) = aberta(&mut tpm);
    assert_eq!(lido, v);
}

#[test]
fn so_cresce_de_um_em_um() {
    let mut tpm = Simulado::default();
    let (a, primeiro) = Ancora::criar(&mut tpm, INDICE, &[], SENHA).unwrap();
    let mut anterior = primeiro;
    for _ in 0..10 {
        let novo = a.avancar(&mut tpm).unwrap();
        assert_eq!(novo, anterior + 1);
        anterior = novo;
    }
    assert_eq!(a.ler(&mut tpm).unwrap(), anterior);
}

#[test]
fn recriar_nao_faz_voltar() {
    // Apagar o índice e criá-lo de novo é o que alguém com a senha do dono
    // tentaria para zerar a âncora. Um contador novo nasce no maior valor
    // que o TPM já viu.
    let mut tpm = Simulado::default();
    let (a, _) = Ancora::criar(&mut tpm, INDICE, &[], SENHA).unwrap();
    for _ in 0..5 {
        a.avancar(&mut tpm).unwrap();
    }
    let antes = a.ler(&mut tpm).unwrap();
    apagar(&mut tpm, INDICE, &[]).unwrap();
    let (_, depois) = Ancora::criar(&mut tpm, INDICE, &[], SENHA).unwrap();
    assert!(depois > antes, "{depois} nao passou de {antes}");
}

#[test]
fn senha_errada_nao_le_nem_avanca() {
    let mut tpm = Simulado::default();
    let (a, v) = Ancora::criar(&mut tpm, INDICE, &[], SENHA).unwrap();
    let errada = [0xA5; 32];
    assert_eq!(
        ler_contador(&mut tpm, INDICE, &errada),
        Err(Erro::Codigo(codigo::SENHA_ERRADA))
    );
    assert_eq!(
        incrementar(&mut tpm, INDICE, &errada),
        Err(Erro::Codigo(codigo::SENHA_ERRADA))
    );
    assert_eq!(a.ler(&mut tpm).unwrap(), v, "a senha errada avancou");
    // E abrir com a senha errada não é "ausente": é erro.
    assert!(Ancora::abrir(&mut tpm, INDICE, errada).is_err());
}

#[test]
fn um_indice_que_nao_e_o_nosso_e_recusado() {
    for atributos in [
        // Um índice comum, de dados, no lugar do contador.
        atributo::ESCRITA_COM_SENHA | atributo::LEITURA_COM_SENHA | atributo::SEM_BLOQUEIO,
        // O contador sem a proteção contra bloqueio.
        atributo::DA_ANCORA & !atributo::SEM_BLOQUEIO,
        // O contador com um atributo a mais.
        atributo::DA_ANCORA | (1 << 10),
    ] {
        let mut tpm = Simulado::default();
        iniciar(&mut tpm).unwrap();
        tpm.indices.push((
            INDICE,
            Indice {
                atributos,
                senha: SENHA.to_vec(),
                tamanho: 8,
                valor: Some(7),
            },
        ));
        assert_eq!(
            Ancora::abrir(&mut tpm, INDICE, SENHA).err(),
            Some(Erro::IndiceEstranho),
            "atributos {atributos:#x} passaram"
        );
    }
}

#[test]
fn definido_e_nunca_avancado_se_completa() {
    // A criação interrompida entre a definição e o primeiro avanço — uma
    // queda de energia entre os dois comandos.
    let mut tpm = Simulado::default();
    iniciar(&mut tpm).unwrap();
    definir_contador(&mut tpm, INDICE, &[], &SENHA).unwrap();
    let (a, v) = aberta(&mut tpm);
    assert_eq!(a.ler(&mut tpm).unwrap(), v);
}

#[test]
fn respostas_quebradas_viram_erro_e_nao_valor() {
    let estragos: [fn(&mut Vec<u8>); 5] = [
        // O tamanho do cabeçalho diz outra coisa.
        |r| r[5] = r[5].wrapping_add(1),
        // A resposta veio cortada.
        |r| {
            r.truncate(r.len() - 1);
            let n = (r.len() as u32).to_be_bytes();
            r[2..6].copy_from_slice(&n);
        },
        // Um byte a mais no fim.
        |r| {
            r.push(0);
            let n = (r.len() as u32).to_be_bytes();
            r[2..6].copy_from_slice(&n);
        },
        // Etiqueta trocada.
        |r| r[1] ^= 0x03,
        // O contador com sete bytes.
        |r| {
            r[15] = 7;
            r.remove(16);
            let n = (r.len() as u32).to_be_bytes();
            r[2..6].copy_from_slice(&n);
        },
    ];
    for (i, estrago) in estragos.iter().enumerate() {
        let mut tpm = Simulado::default();
        let (a, _) = Ancora::criar(&mut tpm, INDICE, &[], SENHA).unwrap();
        tpm.estragar = Some(*estrago);
        assert!(
            a.ler(&mut tpm).is_err(),
            "o estrago {i} foi lido como valor"
        );
    }
}

#[test]
fn o_tpm_nao_iniciado_nao_responde_valor() {
    // Sem o Startup, o TPM recusa tudo; `abrir` o faz primeiro, e por isso
    // funciona num TPM que ninguém iniciou — o caso do ARM pela imagem
    // crua, sem firmware.
    let mut tpm = Simulado::default();
    assert!(ler_publico(&mut tpm, INDICE).is_err());
    assert!(matches!(
        Ancora::abrir(&mut tpm, INDICE, SENHA).unwrap(),
        Aberta::Ausente
    ));
}

const NASCIMENTO: u32 = 0x0180_D0E1;

/// O nascimento: ausente até ser registrado, e então o valor do contador
/// naquele momento — que continua o mesmo quando o contador anda.
#[test]
fn o_nascimento_guarda_o_primeiro_valor() {
    let mut tpm = Simulado {
        maior: 500,
        ..Simulado::default()
    };
    let (ancora, v) = Ancora::criar(&mut tpm, INDICE, &[], SENHA).unwrap();
    assert_eq!(ancora.nascimento(&mut tpm, NASCIMENTO).unwrap(), None);
    assert_eq!(
        ancora
            .registrar_nascimento(&mut tpm, NASCIMENTO, &[])
            .unwrap(),
        v
    );
    assert_eq!(ancora.nascimento(&mut tpm, NASCIMENTO).unwrap(), Some(v));
    ancora.avancar(&mut tpm).unwrap();
    ancora.avancar(&mut tpm).unwrap();
    assert_eq!(ancora.nascimento(&mut tpm, NASCIMENTO).unwrap(), Some(v));
    assert_eq!(ancora.ler(&mut tpm).unwrap(), v + 2);
}

/// Definido e nunca escrito é o mesmo que ausente: a criação parou entre
/// os dois comandos, e registrar de novo a completa.
#[test]
fn o_nascimento_definido_e_nunca_escrito_e_ausente() {
    let mut tpm = Simulado::default();
    let (ancora, v) = Ancora::criar(&mut tpm, INDICE, &[], SENHA).unwrap();
    iniciar(&mut tpm).unwrap();
    definir(&mut tpm, NASCIMENTO, &[], &SENHA, atributo::DO_NASCIMENTO).unwrap();
    assert_eq!(ancora.nascimento(&mut tpm, NASCIMENTO).unwrap(), None);
    assert_eq!(
        ancora
            .registrar_nascimento(&mut tpm, NASCIMENTO, &[])
            .unwrap(),
        v
    );
}

/// Um índice no lugar do nascimento que não é o nosso — um contador, por
/// exemplo — não é um nascimento.
#[test]
fn um_nascimento_que_nao_e_o_nosso_e_recusado() {
    let mut tpm = Simulado::default();
    let (ancora, _) = Ancora::criar(&mut tpm, INDICE, &[], SENHA).unwrap();
    definir_contador(&mut tpm, NASCIMENTO, &[], &SENHA).unwrap();
    assert_eq!(
        ancora.nascimento(&mut tpm, NASCIMENTO),
        Err(Erro::IndiceEstranho)
    );
    assert_eq!(
        ancora.registrar_nascimento(&mut tpm, NASCIMENTO, &[]),
        Err(Erro::IndiceEstranho)
    );
}
