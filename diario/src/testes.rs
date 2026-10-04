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
        versao_da_politica: 7,
        tempo: 1_900_000_000,
        dados,
    }
}

/// O tipo do registro de número `n` de um journal de teste: o próprio
/// número, menos os da base, que só a base escreve; o primeiro é a
/// abertura, como num journal de verdade.
fn tipo_de_teste(n: u64) -> u16 {
    if n == 0 {
        estado::tipo::ABERTURA
    } else if n >= estado::tipo::BASE as u64 {
        n as u16 + 100
    } else {
        n as u16
    }
}

/// O protocolo inteiro de uma gravação: montar, escrever, descarregar,
/// avançar o contador, confirmar.
fn gravar(m: &mut Memoria, esc: &mut Escritor, tpm: &mut Contador, n: u64, dados: &[u8]) {
    let montado = esc
        .montar(&CHAVE, nonce(n), &conteudo(tipo_de_teste(n), dados))
        .unwrap();
    m.escrever(montado.setor, &montado.bytes).unwrap();
    m.descarregar().unwrap();
    tpm.0 += 1;
    esc.confirmar(&montado, tpm.0).unwrap();
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
        assert_eq!(r.tipo, tipo_de_teste(i as u64));
        // Os tipos são 0, 1, 2…: só o 3 é uma operação, e sobe a geração.
        assert_eq!(r.geracao, u64::from(i >= estado::tipo::OPERACAO as usize));
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
        esc_b.confirmar(&montado, 1001 + i).unwrap();
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

/// Refaz a cifra de um registro depois de `mexer` no cabeçalho e no texto
/// claro, como faria um escritor com a chave e um defeito: o registro
/// continua autêntico, e o que precisa recusá-lo é a conferência, não a
/// cifra.
fn reselar(m: &mut Memoria, setor: usize, elo: [u8; 32], mexer: impl Fn(&mut [u8], &mut [u8])) {
    let i = setor * TAM_SETOR;
    let tamanho = u32_em(&m.bytes[i..], 32) as usize;
    let fim = TAM_CABECALHO + tamanho;
    let aead = XChaCha20Poly1305::new(&CHAVE.into());
    let nonce: [u8; TAM_NONCE] = m.bytes[i + 40..i + 64].try_into().unwrap();
    let mut aad = [0u8; TAM_CABECALHO + 32];
    aad[..TAM_CABECALHO].copy_from_slice(&m.bytes[i..i + TAM_CABECALHO]);
    aad[TAM_CABECALHO..].copy_from_slice(&elo);
    let etiqueta: [u8; TAM_ETIQUETA] = m.bytes[i + fim..i + fim + TAM_ETIQUETA].try_into().unwrap();
    let mut claro = m.bytes[i + TAM_CABECALHO..i + fim].to_vec();
    aead.decrypt_inout_detached(
        &nonce.into(),
        &aad,
        claro.as_mut_slice().into(),
        &etiqueta.into(),
    )
    .unwrap();
    mexer(&mut m.bytes[i..i + TAM_CABECALHO], &mut claro);
    aad[..TAM_CABECALHO].copy_from_slice(&m.bytes[i..i + TAM_CABECALHO]);
    let etiqueta = aead
        .encrypt_inout_detached(&nonce.into(), &aad, claro.as_mut_slice().into())
        .unwrap();
    m.bytes[i + TAM_CABECALHO..i + fim].copy_from_slice(&claro);
    m.bytes[i + fim..i + fim + TAM_ETIQUETA].copy_from_slice(&etiqueta);
}

/// O leitor não confia no escritor: um registro autêntico com a sequência
/// errada, a âncora fora do passo, um reservado preenchido ou a geração
/// fora da regra para a leitura ali, com o motivo certo. A cifra sozinha
/// não pegaria nenhum deles — o escritor tinha a chave.
#[test]
fn um_registro_autentico_com_cabecalho_errado_e_recusado() {
    type Mexida = fn(&mut [u8], &mut [u8]);
    let casos: [(&str, Mexida); 7] = [
        // A sequência repetida, e a pulada.
        ("sequencia fora de ordem", |c, _| c[16] ^= 1),
        ("sequencia fora de ordem", |c, _| c[16] = 2),
        ("a ancora nao segue a do registro anterior", |c, _| {
            c[24] ^= 2
        }),
        ("reservado diferente de zero", |c, _| c[10] = 1),
        ("reservado diferente de zero", |c, _| c[36] = 1),
        // A geração do segundo é a do primeiro: um salto, e uma volta.
        ("geracao fora de sequencia", |_, t| t[2] = 1),
        ("geracao fora de sequencia", |_, t| {
            t[2..10].copy_from_slice(&u64::MAX.to_le_bytes())
        }),
    ];
    for (motivo_esperado, mexer) in casos {
        let (mut m, _, _) = journal(0);
        let mut esc = Escritor::continuar(&ler(&mut m, &CHAVE).unwrap(), 0, m.setores());
        let mut tpm = Contador(0);
        gravar(&mut m, &mut esc, &mut tpm, 0, b"primeiro");
        let elo = esc.elo;
        gravar(&mut m, &mut esc, &mut tpm, 1, b"segundo!");
        reselar(&mut m, 1, elo, mexer);
        let lido = ler(&mut m, &CHAVE).unwrap();
        assert_eq!(lido.registros.len(), 1, "{motivo_esperado}");
        match lido.parada {
            Parada::Ilegivel { setor: 1, motivo } => assert_eq!(motivo, motivo_esperado),
            outra => panic!("{motivo_esperado}: parou em {outra:?}"),
        }
    }
}

/// A geração é a do tipo, e não a de quem escreve: uma operação sobe um,
/// o resto repete — e continua de onde o journal parou.
#[test]
fn a_geracao_conta_as_operacoes() {
    use estado::tipo::{BOOT, OPERACAO};
    let (mut m, _, _) = journal(0);
    let mut esc = Escritor::continuar(&ler(&mut m, &CHAVE).unwrap(), 0, m.setores());
    let mut tpm = Contador(0);
    let tipos = [
        estado::tipo::ABERTURA,
        BOOT,
        OPERACAO,
        OPERACAO,
        BOOT,
        OPERACAO,
    ];
    let mut esperadas = Vec::new();
    for (n, &t) in tipos.iter().enumerate() {
        let montado = esc
            .montar(&CHAVE, nonce(n as u64), &conteudo(t, b"x"))
            .unwrap();
        esperadas.push(montado.geracao);
        m.escrever(montado.setor, &montado.bytes).unwrap();
        tpm.0 += 1;
        esc.confirmar(&montado, tpm.0).unwrap();
    }
    assert_eq!(esperadas, [0, 0, 1, 2, 2, 3]);
    let lido = ler(&mut m, &CHAVE).unwrap();
    let lidas: Vec<u64> = lido.registros.iter().map(|r| r.geracao).collect();
    assert_eq!(lidas, esperadas);
    // Um escritor que continua o journal continua a contagem.
    let esc = Escritor::continuar(&lido, tpm.0, m.setores());
    let proximo = esc
        .montar(&CHAVE, nonce(99), &conteudo(OPERACAO, b"y"))
        .unwrap();
    assert_eq!(proximo.geracao, 4);
}

/// Só a âncora do registro confirma a gravação. Um contador que voltou com
/// outro valor — avançado por mais alguém, ou de outro TPM — não confirma
/// nada: o escritor fica onde estava, e o próximo registro ainda é o mesmo.
#[test]
fn so_a_ancora_do_registro_confirma() {
    let (mut m, mut esc, tpm) = journal(1);
    let montado = esc.montar(&CHAVE, nonce(50), &conteudo(2, b"x")).unwrap();
    m.escrever(montado.setor, &montado.bytes).unwrap();
    for errado in [tpm.0, tpm.0 + 2, 0, u64::MAX] {
        assert!(esc.confirmar(&montado, errado).is_err(), "{errado}");
    }
    let de_novo = esc.montar(&CHAVE, nonce(51), &conteudo(2, b"x")).unwrap();
    assert_eq!(
        (de_novo.setor, de_novo.ancora),
        (montado.setor, montado.ancora),
        "uma confirmacao recusada moveu o escritor"
    );
    esc.confirmar(&montado, tpm.0 + 1).unwrap();
    assert_eq!(esc.ancora(), tpm.0 + 1);
}

/// Percorrer entrega os mesmos registros que ler, na mesma ordem, e para
/// no mesmo lugar — também num journal estragado no meio. O escritor que
/// continua de um ou de outro é o mesmo.
#[test]
fn percorrer_e_ler_dao_o_mesmo() {
    let (mut m, _, tpm) = journal(8);
    // Estraga o quinto registro: os dois param nele.
    let lido = ler(&mut m, &CHAVE).unwrap();
    let mut setor = 0usize;
    for r in &lido.registros[..5] {
        let n = setores_para(TAM_PREFIXO + r.conteudo.len()) as usize;
        if r.sequencia < 4 {
            setor += n;
        }
    }
    let mut estragado = Memoria::nova(256);
    estragado.bytes.copy_from_slice(&m.bytes);
    estragado.bytes[setor * TAM_SETOR + 200] ^= 1;
    for meio in [&mut m, &mut estragado] {
        let lido = ler(meio, &CHAVE).unwrap();
        let mut vistos = Vec::new();
        let p = percorrer(meio, &CHAVE, |r| {
            vistos.push(r);
            Ok::<(), ()>(())
        })
        .unwrap();
        assert_eq!(vistos, lido.registros);
        assert_eq!(p, lido.percorrido());
        assert_eq!(p.ultima_ancora(), lido.ultima_ancora());
        let a = Escritor::continuar(&lido, tpm.0, 256);
        let b = Escritor::depois_de(&p, tpm.0, 256);
        assert_eq!(
            a.montar(&CHAVE, nonce(99), &conteudo(2, b"x"))
                .unwrap()
                .bytes,
            b.montar(&CHAVE, nonce(99), &conteudo(2, b"x"))
                .unwrap()
                .bytes
        );
    }
    assert_eq!(ler(&mut estragado, &CHAVE).unwrap().registros.len(), 4);
}

/// Quem recebe os registros pode recusar um: o percurso para ali, e diz
/// qual. Os anteriores foram entregues; os seguintes, não.
#[test]
fn percorrer_para_no_registro_recusado() {
    let (mut m, _, _) = journal(6);
    let mut vistos = Vec::new();
    let r = percorrer(&mut m, &CHAVE, |r| {
        if r.sequencia == 3 {
            return Err("nao se reaplica");
        }
        vistos.push(r.sequencia);
        Ok(())
    });
    assert_eq!(
        r,
        Err(Interrompido::Recusado {
            sequencia: 3,
            motivo: "nao se reaplica"
        })
    );
    assert_eq!(vistos, [0, 1, 2]);
}

/// Escreve uma base de `partes` partes, e o fecho, numa região nova, a
/// partir do escritor `esc`. Devolve a base fechada, ainda não confirmada.
fn escrever_base(
    destino: &mut Memoria,
    esc: &Escritor,
    partes: usize,
    com_fecho: bool,
) -> Option<BaseFechada> {
    let mut base = esc.base(destino.setores()).unwrap();
    for i in 0..partes {
        let dados: Vec<u8> = (0..(700 + i * 300)).map(|b| b as u8).collect();
        let p = base
            .parte(&CHAVE, nonce(500 + i as u64), 7, 1_900_000_100, &dados)
            .unwrap();
        destino.escrever(p.setor, &p.bytes).unwrap();
    }
    if !com_fecho {
        return None;
    }
    let f = base
        .fechar(&CHAVE, nonce(600), 7, 1_900_000_100, b"fecho")
        .unwrap();
    destino.escrever(f.setor, &f.bytes).unwrap();
    destino.descarregar().unwrap();
    Some(f)
}

/// A base inteira vale: as partes e o fecho com a mesma âncora — a
/// seguinte à do journal velho —, na mesma geração; o contador avança uma
/// vez, e o journal continua na região nova. A região velha, depois disso,
/// é anterior ao que o TPM viu, e não é escolhida.
#[test]
fn a_base_inteira_vale_e_continua() {
    use estado::tipo::{BASE, BASE_FIM, OPERACAO};
    let (mut a, esc_a, mut tpm) = journal(6);
    let mut b = Memoria::nova(256);
    let geracao = esc_a.geracao();
    let fechada = escrever_base(&mut b, &esc_a, 3, true).unwrap();
    let ancora = fechada.ancora;
    assert_eq!(ancora, tpm.0 + 1);

    // Descarregada e não confirmada: a base é a gravação que falta.
    let pa = ler(&mut a, &CHAVE).unwrap().percorrido();
    let lido_b = ler(&mut b, &CHAVE).unwrap();
    let pb = lido_b.percorrido();
    assert!(pa.inteiro() && pb.inteiro());
    assert_eq!(escolher(&[pa, pb]), Some(1));
    assert_eq!(julgar(pb.ultima_ancora(), Some(tpm.0)), Veredito::Completar);
    assert_eq!(lido_b.registros.len(), 4);
    for (i, r) in lido_b.registros.iter().enumerate() {
        assert_eq!(r.ancora, ancora, "registro {i}");
        assert_eq!(r.geracao, geracao);
        assert_eq!(r.tipo, if i < 3 { BASE } else { BASE_FIM });
    }

    // Um contador que não é o da base não confirma.
    assert!(
        escrever_base(&mut Memoria::nova(256), &esc_a, 1, true)
            .unwrap()
            .confirmar(tpm.0)
            .is_err()
    );
    tpm.0 += 1;
    let mut esc_b = fechada.confirmar(tpm.0).unwrap();
    gravar(
        &mut b,
        &mut esc_b,
        &mut tpm,
        OPERACAO as u64,
        b"depois da base",
    );
    let lido_b = ler(&mut b, &CHAVE).unwrap();
    assert_eq!(lido_b.registros.len(), 5);
    let ultimo = lido_b.registros.last().unwrap();
    assert_eq!(ultimo.ancora, ancora + 1);
    assert_eq!(ultimo.geracao, geracao + 1);
    let pb = lido_b.percorrido();
    assert_eq!(escolher(&[pa, pb]), Some(1));
    assert_eq!(julgar(pb.ultima_ancora(), Some(tpm.0)), Veredito::Confere);
    // A velha, sozinha, é um disco atrasado.
    assert!(matches!(
        julgar(pa.ultima_ancora(), Some(tpm.0)),
        Veredito::Recusado(Recusa::DiscoAtrasado { .. })
    ));
}

/// A região percorrida como o kernel a percorre, em fluxo — e o mesmo que
/// a leitura inteira diz dela, inclusive se começa inteira.
fn percorrido(m: &mut Memoria) -> Percorrido {
    let p = percorrer(m, &CHAVE, |_| Ok::<(), ()>(())).unwrap();
    assert_eq!(p, ler(m, &CHAVE).unwrap().percorrido());
    p
}

/// A compactação cortada em qualquer setor — a queda no meio da escrita da
/// base — deixa uma região que não vale: a velha continua a escolhida, e
/// confere com o contador. Só a base inteira, com o fecho, troca de região.
#[test]
fn a_base_cortada_em_cada_setor_nao_vale() {
    let (mut a, esc_a, tpm) = journal(4);
    let mut cheia = Memoria::nova(256);
    escrever_base(&mut cheia, &esc_a, 2, true).unwrap();
    let tamanho = cheia.bytes.iter().rposition(|&b| b != 0).unwrap() / TAM_SETOR + 1;
    let pa = ler(&mut a, &CHAVE).unwrap().percorrido();
    for corte in 0..=tamanho {
        let mut b = Memoria::nova(256);
        b.bytes[..corte * TAM_SETOR].copy_from_slice(&cheia.bytes[..corte * TAM_SETOR]);
        let pb = percorrido(&mut b);
        let escolhida = escolher(&[pa, pb]);
        if corte == tamanho {
            assert_eq!(escolhida, Some(1), "inteira");
        } else {
            assert!(!pb.inteiro(), "cortada em {corte}");
            assert_eq!(escolhida, Some(0), "cortada em {corte}");
            assert_eq!(julgar(pa.ultima_ancora(), Some(tpm.0)), Veredito::Confere);
        }
    }
    // As partes sem fecho, todas inteiras, também não valem.
    let mut b = Memoria::nova(256);
    assert!(escrever_base(&mut b, &esc_a, 3, false).is_none());
    let pb = percorrido(&mut b);
    assert!(!pb.inteiro());
    assert_eq!(escolher(&[pa, pb]), Some(0));
}

/// O leitor não aceita a base fora do lugar: uma parte depois de um
/// registro comum, um registro comum depois de uma parte, ou uma parte com
/// a âncora seguinte em vez da mesma.
#[test]
fn a_base_fora_do_lugar_e_recusada() {
    use estado::tipo::{BASE, BOOT};
    // Uma parte depois de um registro comum.
    let (mut m, mut esc, mut tpm) = journal(0);
    gravar(&mut m, &mut esc, &mut tpm, BOOT as u64, b"primeiro");
    let elo = esc.elo;
    gravar(&mut m, &mut esc, &mut tpm, BOOT as u64, b"segundo!");
    reselar(&mut m, 1, elo, |_, t| {
        t[0..2].copy_from_slice(&BASE.to_le_bytes())
    });
    let lido = ler(&mut m, &CHAVE).unwrap();
    assert_eq!(lido.registros.len(), 1);
    assert_eq!(
        lido.parada,
        Parada::Ilegivel {
            setor: 1,
            motivo: "base fora do comeco da regiao"
        }
    );

    // Uma base de duas partes, e o fecho trocado por um registro comum.
    let (_, esc_a, _) = journal(2);
    let mut b = Memoria::nova(256);
    let setor_do_fecho = escrever_base(&mut b, &esc_a, 2, true).unwrap().setor as usize;
    let lido = ler(&mut b, &CHAVE).unwrap();
    let elo_da_segunda = {
        let mut uma = Memoria::nova(256);
        uma.bytes[..setor_do_fecho * TAM_SETOR]
            .copy_from_slice(&b.bytes[..setor_do_fecho * TAM_SETOR]);
        ler(&mut uma, &CHAVE).unwrap().elo
    };
    assert_eq!(lido.registros.len(), 3);
    let mut trocado = Memoria::nova(256);
    trocado.bytes.copy_from_slice(&b.bytes);
    reselar(&mut trocado, setor_do_fecho, elo_da_segunda, |_, t| {
        t[0..2].copy_from_slice(&BOOT.to_le_bytes())
    });
    let lido = ler(&mut trocado, &CHAVE).unwrap();
    assert_eq!(lido.registros.len(), 2);
    assert!(matches!(
        lido.parada,
        Parada::Ilegivel {
            motivo: "base sem fecho",
            ..
        }
    ));

    // O fecho com a âncora seguinte, e não a mesma.
    let mut adiante = Memoria::nova(256);
    adiante.bytes.copy_from_slice(&b.bytes);
    reselar(&mut adiante, setor_do_fecho, elo_da_segunda, |c, _| {
        c[24] += 1
    });
    let lido = ler(&mut adiante, &CHAVE).unwrap();
    assert_eq!(lido.registros.len(), 2);
    assert!(matches!(
        lido.parada,
        Parada::Ilegivel {
            motivo: "a ancora nao segue a do registro anterior",
            ..
        }
    ));
}

/// As regiões: duas, do mesmo tamanho, a primeira no setor zero, sem se
/// sobrepor e sem chegar à reserva do fim; o limite encolhe as duas sem
/// mudar onde a segunda começa.
#[test]
fn as_regioes_dividem_a_particao() {
    let total = 32_768;
    let [(a, ta), (b, tb)] = regioes(total, None);
    assert_eq!(a, 0);
    assert_eq!(ta, tb);
    assert_eq!(b, ta);
    assert!(b + tb <= total - RESERVA_NO_FIM);
    let [(a2, t2), (b2, u2)] = regioes(total, Some(100));
    assert_eq!((a2, t2, b2, u2), (0, 100, b, 100));
    assert_eq!(regioes(total, Some(total)), regioes(total, None));
    assert_eq!(regioes(10, None), [(0, 0), (0, 0)]);
}

/// A escolha: só as inteiras contam, a de âncora maior vence, e duas com a
/// mesma âncora não se resolvem escolhendo.
#[test]
fn a_escolha_da_regiao() {
    let (mut a, esc_a, _) = journal(3);
    let pa = ler(&mut a, &CHAVE).unwrap().percorrido();
    let mut vazia = Memoria::nova(64);
    let pv = ler(&mut vazia, &CHAVE).unwrap().percorrido();
    assert!(!pv.inteiro());
    assert_eq!(escolher(&[pa, pv]), Some(0));
    assert_eq!(escolher(&[pv, pa]), Some(1));
    assert_eq!(escolher(&[pv, pv]), None);
    assert_eq!(escolher(&[pa, pa]), None);
    // Um journal que começa por um registro que não é a abertura nem a
    // base não é inteiro.
    let mut m = Memoria::nova(64);
    let lido = ler(&mut m, &CHAVE).unwrap();
    let mut esc = Escritor::continuar(&lido, 0, m.setores());
    let mut tpm = Contador(0);
    gravar(
        &mut m,
        &mut esc,
        &mut tpm,
        estado::tipo::BOOT as u64,
        b"sem abertura",
    );
    assert!(!ler(&mut m, &CHAVE).unwrap().percorrido().inteiro());
    let _ = esc_a;
}

/// A base se monta pela base, e não pelo registro comum.
#[test]
fn a_base_nao_se_monta_como_registro() {
    let (_, esc, _) = journal(1);
    for t in [estado::tipo::BASE, estado::tipo::BASE_FIM] {
        assert!(esc.montar(&CHAVE, nonce(1), &conteudo(t, b"x")).is_err());
    }
}

/// O journal vazio continua do elo inicial: o primeiro registro escrito
/// depois dele se lê, como o de um journal lido do disco vazio.
#[test]
fn o_vazio_continua_do_comeco() {
    let mut m = Memoria::nova(64);
    let lido = ler(&mut m, &CHAVE).unwrap();
    assert_eq!(Percorrido::vazio(), lido.percorrido());
    let mut esc = Escritor::depois_de(&Percorrido::vazio(), 0, m.setores());
    let mut tpm = Contador(0);
    gravar(&mut m, &mut esc, &mut tpm, 0, b"abertura");
    assert_eq!(ler(&mut m, &CHAVE).unwrap().registros.len(), 1);
}
