//! Os casos do journal, sobre um disco em memória que se corta e se
//! estraga à vontade.

extern crate std;

use alloc::vec::Vec;

use super::*;

const CHAVE: [u8; 32] = [0x42; 32];

/// Um disco em memória, com contadores e uma tesoura: a próxima escrita
/// pode parar depois de `cortar` setores, como uma queda de energia no
/// meio dela.
struct Memoria {
    bytes: Vec<u8>,
    descargas: usize,
    cortar: Option<usize>,
}

impl Memoria {
    fn nova(setores: usize) -> Memoria {
        Memoria {
            bytes: alloc::vec![0; setores * TAM_SETOR],
            descargas: 0,
            cortar: None,
        }
    }
}

impl Meio for Memoria {
    fn setores(&self) -> u64 {
        (self.bytes.len() / TAM_SETOR) as u64
    }
    fn ler(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
        let i = setor as usize * TAM_SETOR;
        destino.copy_from_slice(&self.bytes[i..i + destino.len()]);
        Ok(())
    }
    fn escrever(&mut self, setor: u64, origem: &[u8]) -> Result<(), &'static str> {
        let i = setor as usize * TAM_SETOR;
        let n = match self.cortar.take() {
            Some(setores) => (setores * TAM_SETOR).min(origem.len()),
            None => origem.len(),
        };
        self.bytes[i..i + n].copy_from_slice(&origem[..n]);
        Ok(())
    }
    fn descarregar(&mut self) -> Result<(), &'static str> {
        self.descargas += 1;
        Ok(())
    }
}

/// O TPM, reduzido ao que o journal vê dele: um número.
struct Contador(u64);

/// Um nonce diferente para cada chamada.
fn nonce(n: u64) -> [u8; TAM_NONCE] {
    let mut v = [0u8; TAM_NONCE];
    v[..8].copy_from_slice(&n.to_le_bytes());
    v[8] = 0xA5;
    v
}

fn conteudo(tipo: u16, dados: &[u8]) -> Conteudo<'_> {
    Conteudo {
        tipo,
        geracao: tipo as u64,
        versao_da_politica: 7,
        tempo: 1_900_000_000,
        dados,
    }
}

/// O protocolo inteiro de uma gravação: montar, escrever, descarregar,
/// avançar o contador, confirmar.
fn gravar(m: &mut Memoria, esc: &mut Escritor, tpm: &mut Contador, n: u64, dados: &[u8]) {
    let montado = esc
        .montar(&CHAVE, nonce(n), &conteudo(n as u16, dados))
        .unwrap();
    m.escrever(montado.setor, &montado.bytes).unwrap();
    m.descarregar().unwrap();
    tpm.0 += 1;
    assert_eq!(tpm.0, montado.ancora);
    esc.confirmar(&montado);
}

/// Um journal novo, com `n` registros de tamanhos variados.
fn journal(n: u64) -> (Memoria, Escritor, Contador) {
    let mut m = Memoria::nova(256);
    // O contador nasce num valor qualquer — o maior que o TPM já viu.
    let mut tpm = Contador(1000);
    let lido = ler(&mut m, &CHAVE).unwrap();
    assert_eq!(julgar(lido.ultima_ancora(), None), Veredito::Novo);
    let mut esc = Escritor::continuar(&lido, tpm.0, m.setores());
    for i in 0..n {
        let dados: Vec<u8> = (0..(i * 300) as usize).map(|b| b as u8).collect();
        gravar(&mut m, &mut esc, &mut tpm, i, &dados);
    }
    (m, esc, tpm)
}

#[test]
fn le_de_volta_o_que_escreveu() {
    let (mut m, _, tpm) = journal(8);
    let lido = ler(&mut m, &CHAVE).unwrap();
    assert_eq!(lido.registros.len(), 8);
    assert_eq!(lido.parada, Parada::Fim);
    for (i, r) in lido.registros.iter().enumerate() {
        assert_eq!(r.sequencia, i as u64);
        assert_eq!(r.ancora, 1001 + i as u64);
        assert_eq!(r.tipo, i as u16);
        assert_eq!(r.geracao, i as u64);
        assert_eq!(r.versao_da_politica, 7);
        assert_eq!(r.conteudo.len(), i * 300);
        assert!(r.conteudo.iter().enumerate().all(|(b, &v)| v == b as u8));
    }
    assert_eq!(julgar(lido.ultima_ancora(), Some(tpm.0)), Veredito::Confere);
    assert_eq!(m.descargas, 8, "uma descarga por gravacao");
}

#[test]
fn o_maior_conteudo_cabe_e_um_byte_a_mais_nao() {
    let (mut m, mut esc, mut tpm) = journal(0);
    let grande = alloc::vec![0x33u8; MAIOR_CONTEUDO];
    gravar(&mut m, &mut esc, &mut tpm, 0, &grande);
    let lido = ler(&mut m, &CHAVE).unwrap();
    assert_eq!(lido.registros[0].conteudo, grande);
    let demais = alloc::vec![0u8; MAIOR_CONTEUDO + 1];
    assert!(esc.montar(&CHAVE, nonce(9), &conteudo(1, &demais)).is_err());
}

#[test]
fn a_particao_cheia_recusa_em_vez_de_passar_do_fim() {
    let mut m = Memoria::nova(6);
    let lido = ler(&mut m, &CHAVE).unwrap();
    let mut esc = Escritor::continuar(&lido, 0, m.setores());
    let mut tpm = Contador(0);
    let dados = alloc::vec![1u8; 800]; // dois setores com o cabeçalho
    gravar(&mut m, &mut esc, &mut tpm, 0, &dados);
    gravar(&mut m, &mut esc, &mut tpm, 1, &dados);
    gravar(&mut m, &mut esc, &mut tpm, 2, &dados);
    assert_eq!(esc.livres(), 0);
    assert!(esc.montar(&CHAVE, nonce(3), &conteudo(3, &[])).is_err());
    // Lido até o fim da partição, sem setor de zeros depois: para no fim.
    let lido = ler(&mut m, &CHAVE).unwrap();
    assert_eq!(lido.registros.len(), 3);
    assert_eq!(lido.parada, Parada::Fim);
}

/// A queda de energia no meio de uma gravação, em cada setor: o registro
/// cortado não abre, o contador não chegou a ele, e o journal é o de
/// antes. Com o registro inteiro e o contador sem avançar, ele vale e
/// falta um avanço. E nos dois casos a próxima gravação continua por
/// cima, e tudo se lê.
#[test]
fn a_queda_no_meio_da_gravacao_em_cada_setor() {
    let grande: Vec<u8> = (0..2000u32).map(|b| (b * 7) as u8).collect();
    let setores = setores_para(TAM_PREFIXO + grande.len()) as usize;
    assert!(setores >= 4);
    for cortado_em in 0..=setores {
        let (mut m, esc, tpm) = journal(3);
        let antes = tpm.0;
        let montado = esc
            .montar(&CHAVE, nonce(50), &conteudo(9, &grande))
            .unwrap();
        m.cortar = Some(cortado_em);
        m.escrever(montado.setor, &montado.bytes).unwrap();
        // A energia cai: não há descarga, nem avanço do contador.

        let lido = ler(&mut m, &CHAVE).unwrap();
        let veredito = julgar(lido.ultima_ancora(), Some(antes));
        let mut tpm = Contador(antes);
        if cortado_em < setores {
            assert_eq!(lido.registros.len(), 3, "cortado em {cortado_em}");
            assert_eq!(veredito, Veredito::Confere, "cortado em {cortado_em}");
            if cortado_em > 0 {
                assert!(matches!(lido.parada, Parada::Ilegivel { .. }));
            }
        } else {
            assert_eq!(lido.registros.len(), 4);
            assert_eq!(veredito, Veredito::Completar);
            tpm.0 += 1;
        }

        // A vida continua: um registro pequeno por cima da cauda.
        let mut esc = Escritor::continuar(&lido, tpm.0, m.setores());
        gravar(&mut m, &mut esc, &mut tpm, 60, b"depois da queda");
        let lido = ler(&mut m, &CHAVE).unwrap();
        let ultimo = lido.registros.last().unwrap();
        assert_eq!(ultimo.conteudo, b"depois da queda");
        assert_eq!(julgar(lido.ultima_ancora(), Some(tpm.0)), Veredito::Confere);
    }
}

/// Cada bit do journal, trocado um de cada vez: o registro que o contém não
/// abre, e com ele os seguintes. Nenhum bit troca o conteúdo sem ser visto,
/// e o julgamento contra a âncora recusa sempre.
#[test]
fn cada_bit_trocado_e_visto() {
    let (m, esc, tpm) = journal(3);
    let usados = esc.proximo_setor as usize * TAM_SETOR;
    let original = m.bytes.clone();
    for byte in 0..usados {
        for bit in 0..8 {
            let mut estragado = Memoria {
                bytes: original.clone(),
                descargas: 0,
                cortar: None,
            };
            estragado.bytes[byte] ^= 1 << bit;
            let lido = ler(&mut estragado, &CHAVE).unwrap();
            assert!(
                lido.registros.len() < 3,
                "o bit {bit} do byte {byte} passou despercebido"
            );
            assert!(
                matches!(
                    julgar(lido.ultima_ancora(), Some(tpm.0)),
                    Veredito::Recusado(_)
                ),
                "o bit {bit} do byte {byte} foi aceito pela ancora"
            );
        }
    }
}

/// Um registro autêntico de outro journal, com a mesma chave, a mesma
/// sequência, a mesma âncora e no mesmo lugar, não entra: o elo é o do
/// journal dele, e o nonce também.
#[test]
fn um_registro_de_outro_journal_nao_entra() {
    let (mut a, _, _) = journal(3);
    // Outro journal com os mesmos conteúdos e outros nonces.
    let mut b = Memoria::nova(256);
    let mut esc_b = Escritor::continuar(&ler(&mut b, &CHAVE).unwrap(), 1000, 256);
    for i in 0..3u64 {
        let dados: Vec<u8> = (0..(i * 300) as usize).map(|b| b as u8).collect();
        let montado = esc_b
            .montar(&CHAVE, nonce(i + 100), &conteudo(i as u16, &dados))
            .unwrap();
        b.escrever(montado.setor, &montado.bytes).unwrap();
        esc_b.confirmar(&montado);
    }
    assert_eq!(ler(&mut b, &CHAVE).unwrap().registros.len(), 3);
    // O segundo registro de B (um setor, logo depois do primeiro) no lugar
    // do segundo de A.
    let segundo = TAM_SETOR..2 * TAM_SETOR;
    a.bytes[segundo.clone()].copy_from_slice(&b.bytes[segundo]);
    let lido = ler(&mut a, &CHAVE).unwrap();
    assert_eq!(
        lido.registros.len(),
        1,
        "um registro de outro journal abriu"
    );
}

/// Dois registros trocados de lugar não abrem.
#[test]
fn registros_fora_de_ordem_nao_abrem() {
    let (mut m, _, _) = journal(0);
    let mut esc = Escritor::continuar(&ler(&mut m, &CHAVE).unwrap(), 0, m.setores());
    let mut tpm = Contador(0);
    gravar(&mut m, &mut esc, &mut tpm, 0, b"primeiro");
    gravar(&mut m, &mut esc, &mut tpm, 1, b"segundo!");
    // Os dois têm um setor cada.
    let (um, dois) = m.bytes.split_at_mut(TAM_SETOR);
    um.swap_with_slice(&mut dois[..TAM_SETOR]);
    let lido = ler(&mut m, &CHAVE).unwrap();
    assert!(lido.registros.is_empty());
}

/// Com outra chave nada abre — e um journal que não abre, diante de uma
/// âncora, é recusado: não é um sistema novo.
#[test]
fn com_outra_chave_nada_abre() {
    let (mut m, _, tpm) = journal(3);
    let lido = ler(&mut m, &[0x43; 32]).unwrap();
    assert!(lido.registros.is_empty());
    assert!(matches!(lido.parada, Parada::Ilegivel { setor: 0, .. }));
    assert_eq!(
        julgar(lido.ultima_ancora(), Some(tpm.0)),
        Veredito::Recusado(Recusa::JournalApagado { ancora: tpm.0 })
    );
}

/// O nonce sorteado é o que entra: o mesmo registro com dois nonces dá dois
/// textos cifrados diferentes.
#[test]
fn o_nonce_e_o_sorteado() {
    let (_, esc, _) = journal(1);
    let a = esc
        .montar(&CHAVE, nonce(1), &conteudo(5, b"igual"))
        .unwrap();
    let b = esc
        .montar(&CHAVE, nonce(2), &conteudo(5, b"igual"))
        .unwrap();
    assert_ne!(a.bytes[TAM_CABECALHO..], b.bytes[TAM_CABECALHO..]);
    assert_eq!(&a.bytes[40..64], &nonce(1));
}

/// O conteúdo, o tipo e a geração não aparecem em claro no disco.
#[test]
fn o_conteudo_nao_fica_em_claro() {
    let (mut m, mut esc, mut tpm) = journal(0);
    let segredo = b"um corpo de mensagem que nao pode aparecer no disco";
    gravar(&mut m, &mut esc, &mut tpm, 0, segredo);
    assert!(
        !m.bytes.windows(segredo.len()).any(|w| w == segredo),
        "o conteudo esta em claro no disco"
    );
}

#[test]
fn o_julgamento_contra_a_ancora() {
    use Veredito::*;
    assert_eq!(julgar(None, None), Novo);
    assert_eq!(julgar(Some(5), Some(5)), Confere);
    assert_eq!(julgar(Some(6), Some(5)), Completar);
    assert_eq!(
        julgar(Some(4), Some(5)),
        Recusado(Recusa::DiscoAtrasado {
            disco: 4,
            ancora: 5
        })
    );
    assert_eq!(
        julgar(Some(1), Some(900)),
        Recusado(Recusa::DiscoAtrasado {
            disco: 1,
            ancora: 900
        })
    );
    assert_eq!(
        julgar(Some(7), Some(5)),
        Recusado(Recusa::AncoraAtrasada {
            disco: 7,
            ancora: 5
        })
    );
    assert_eq!(julgar(Some(5), None), Recusado(Recusa::AncoraAusente));
    assert_eq!(
        julgar(None, Some(5)),
        Recusado(Recusa::JournalApagado { ancora: 5 })
    );
    // Sem transbordo no topo.
    assert_eq!(julgar(Some(u64::MAX), Some(u64::MAX - 1)), Completar);
    assert_eq!(
        julgar(Some(0), Some(u64::MAX)),
        Recusado(Recusa::DiscoAtrasado {
            disco: 0,
            ancora: u64::MAX
        })
    );
}

/// Um disco devolvido a uma fotografia antiga: os registros abrem todos —
/// são autênticos —, e a âncora recusa.
#[test]
fn a_fotografia_antiga_abre_e_e_recusada() {
    let (mut m, mut esc, mut tpm) = journal(3);
    let foto = m.bytes.clone();
    gravar(&mut m, &mut esc, &mut tpm, 10, b"a lapide");
    m.bytes = foto;
    let lido = ler(&mut m, &CHAVE).unwrap();
    assert_eq!(lido.registros.len(), 3);
    assert_eq!(
        julgar(lido.ultima_ancora(), Some(tpm.0)),
        Veredito::Recusado(Recusa::DiscoAtrasado {
            disco: tpm.0 - 1,
            ancora: tpm.0
        })
    );
}

#[test]
fn o_relogio_nunca_volta() {
    let mut r = Relogio::novo(1000);
    assert_eq!(r.agora(Some(2000)), 2000);
    // O RTC volta: o tempo lógico fica.
    assert_eq!(r.agora(Some(1500)), 2000);
    assert_eq!(r.agora(Some(10)), 2000);
    // Sem RTC: o piso.
    assert_eq!(r.agora(None), 2000);
    // O RTC passa do piso: anda de novo.
    assert_eq!(r.agora(Some(2001)), 2001);
    assert_eq!(r.piso(), 2001);
    // Um piso do journal acima do RTC: o piso vale.
    let mut r = Relogio::novo(5000);
    assert_eq!(r.agora(Some(4000)), 5000);
}

#[test]
fn os_campos_vao_e_voltam() {
    let c = estado::campos(&[b"um", b"", &[0u8; 300]]).unwrap();
    let v = estado::ler_campos(&c).unwrap();
    assert_eq!(v, alloc::vec![&b"um"[..], &b""[..], &[0u8; 300][..]]);
    assert!(estado::exatamente::<3>(&c).is_ok());
    assert!(estado::exatamente::<2>(&c).is_err());
    // Cortado em cada byte: só o vazio e o inteiro se leem.
    for n in 1..c.len() {
        let lido = estado::ler_campos(&c[..n]);
        assert!(
            lido.is_err() || lido.unwrap().len() < 3,
            "cortado em {n} leu os tres campos"
        );
    }
    assert!(estado::campos(&[&alloc::vec![0u8; 70_000]]).is_err());
}
