use std::format;
use std::string::{String, ToString};
use std::vec::Vec;

use ed25519_dalek::SigningKey;
use politica::{Codigo, Permissao, Politica};

use super::*;
use crate::intervalo::Amostra;
use crate::quorum::{self, Desfecho};

/// A raiz pública de uma fonte de teste, de uma semente fixa.
fn raiz(semente: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[semente; 32])
        .verifying_key()
        .to_bytes()
}

fn hex(chave: &[u8; 32]) -> String {
    chave.iter().map(|b| format!("{b:02x}")).collect()
}

fn linha(nome: &str, destino: &str, semente: u8) -> String {
    format!("fonte {nome} {destino} ed25519:{}\n", hex(&raiz(semente)))
}

/// O registro da bancada: três fontes, dois de três.
fn bancada() -> String {
    format!(
        "# as fontes da bancada\n{}{}{}quorum 2\n",
        linha("bancada-a", "udp:10.0.2.2:5319", 1),
        linha("bancada-b", "udp:10.0.2.2:5320", 2),
        linha("bancada-c", "udp:10.0.2.2:5321", 3),
    )
}

fn erro(texto: &str) -> Erro {
    Registro::ler(texto).expect_err("o registro devia ser recusado")
}

fn padrao() -> Politica {
    Politica::ler(politica::PADRAO).unwrap()
}

#[test]
fn o_registro_da_bancada() {
    let r = Registro::ler(&bancada()).unwrap();
    let nomes: Vec<_> = r.fontes().iter().map(|f| f.nome()).collect();
    assert_eq!(nomes, ["bancada-a", "bancada-b", "bancada-c"]);
    let destinos: Vec<_> = r.fontes().iter().map(|f| f.destino()).collect();
    assert_eq!(
        destinos,
        [
            "udp:10.0.2.2:5319",
            "udp:10.0.2.2:5320",
            "udp:10.0.2.2:5321"
        ]
    );
    for (i, f) in r.fontes().iter().enumerate() {
        assert_eq!(f.chave(), &raiz(i as u8 + 1));
        assert_eq!(f.endereco().protocolo, Protocolo::Udp);
        assert_eq!(f.endereco().ip, [10, 0, 2, 2]);
        assert_eq!(f.endereco().porta, 5319 + i as u16);
    }
    let (i, b) = r.fonte_de_nome("bancada-b").unwrap();
    assert_eq!((i, b.destino()), (1, "udp:10.0.2.2:5320"));
    assert!(r.fonte_de_nome("bancada-d").is_none());
    assert!(r.fonte_de_nome("").is_none());
    assert_eq!(r.quorum(), 2);
    assert!(r.move_o_relogio());
    // Sem as linhas, os tetos do desenho: um dia e 60 s.
    assert_eq!((r.salto_s(), r.incerteza_s()), (86_400, 60));
    assert_eq!(r.parametros(), Parametros::PADRAO);
    // O texto volta igual.
    let texto = r.to_string();
    assert!(texto.contains("quorum 2\nsalto 86400\nincerteza 60\n"));
    assert_eq!(Registro::ler(&texto).unwrap(), r);
}

/// k ≥ 2 sempre: um quórum de uma chave, ou de nenhuma, recusa o registro
/// inteiro — e diz a linha.
#[test]
fn quorum_abaixo_de_dois_e_recusado() {
    for k in [0u64, 1] {
        let texto = format!("{}quorum {k}\n", linha("a", "udp:10.0.2.2:5319", 1));
        assert_eq!(
            erro(&texto),
            Erro {
                linha: 2,
                tipo: ErroTipo::QuorumAbaixoDoMinimo(k)
            },
            "k={k}"
        );
    }
    // Nem escrito de outro jeito.
    for valor in [
        "-1",
        "01",
        "+2",
        "2.0",
        "dois",
        "0x2",
        "18446744073709551616",
    ] {
        let texto = format!("{}quorum {valor}\n", linha("a", "udp:10.0.2.2:5319", 1));
        assert_eq!(erro(&texto).tipo, ErroTipo::Numero, "{valor}");
    }
    // A mensagem diz por quê.
    let texto = format!("{}quorum 1\n", linha("a", "udp:10.0.2.2:5319", 1));
    let motivo = erro(&texto).to_string();
    assert!(motivo.starts_with("linha 2: quorum 1"), "{motivo}");
    assert!(motivo.contains("nunca move o relogio"), "{motivo}");
}

/// Sem a linha `quorum`, o registro não diz quantas chaves movem o
/// relógio: recusado, e não lido com um padrão.
#[test]
fn sem_quorum_e_recusado() {
    let texto = format!(
        "{}{}",
        linha("a", "udp:10.0.2.2:5319", 1),
        linha("b", "udp:10.0.2.2:5320", 2)
    );
    assert_eq!(
        erro(&texto),
        Erro {
            linha: 0,
            tipo: ErroTipo::SemQuorum
        }
    );
    assert_eq!(
        erro(&format!("{texto}quorum 2\nquorum 2\n")).tipo,
        ErroTipo::Repetida("quorum")
    );
}

/// k maior que o número de fontes: o registro vale — as respostas são
/// conferidas e registradas —, e o relógio nunca se move. Uma fonte
/// isolada nunca o move.
#[test]
fn quorum_maior_que_as_fontes_so_confere() {
    let uma = Registro::ler(&format!(
        "{}quorum 2\n",
        linha("so", "udp:10.0.2.2:5319", 1)
    ))
    .unwrap();
    assert_eq!((uma.fontes().len(), uma.quorum()), (1, 2));
    assert!(!uma.move_o_relogio());
    let tres = Registro::ler(&bancada().replace("quorum 2", "quorum 4")).unwrap();
    assert!(!tres.move_o_relogio());
    // E é o quórum que impede: as respostas de todas as fontes, todas de
    // acordo, não dão acordo com k maior que elas.
    let amostras: Vec<Amostra> = tres
        .fontes()
        .iter()
        .map(|f| Amostra {
            chave: *f.chave(),
            cedo_ms: 1_000_000,
            tarde_ms: 1_002_000,
            instante_ms: 0,
        })
        .collect();
    assert!(matches!(
        quorum::acordo(&amostras, tres.quorum() as usize),
        Desfecho::SemQuorum { .. }
    ));
    assert!(matches!(
        quorum::acordo(&amostras[..1], uma.quorum() as usize),
        Desfecho::SemQuorum { .. }
    ));
    // Com k ≤ n, as mesmas amostras dão acordo.
    assert!(matches!(quorum::acordo(&amostras, 2), Desfecho::Acordo(_)));
    // Acima do maior número de fontes, nunca haveria acordo: recusado.
    assert_eq!(
        erro(&bancada().replace("quorum 2", "quorum 9")).tipo,
        ErroTipo::QuorumAcimaDoMaximo(9)
    );
    assert!(Registro::ler(&bancada().replace("quorum 2", "quorum 8")).is_ok());
}

/// A chave: `ed25519:` e 64 dígitos minúsculos, de um ponto da curva que
/// não é de ordem pequena.
#[test]
fn chaves_invalidas() {
    let boa = hex(&raiz(1));
    let fonte = |chave: &str| format!("fonte a udp:10.0.2.2:5319 {chave}\nquorum 2\n");
    assert!(Registro::ler(&fonte(&format!("ed25519:{boa}"))).is_ok());
    for ruim in [
        boa.clone(),
        format!("ED25519:{boa}"),
        format!("ed25519:{}", boa.to_uppercase()),
        format!("ed25519:{}", &boa[..63]),
        format!("ed25519:{boa}0"),
        format!("ed25519:{}g", &boa[..63]),
        format!("x25519:{boa}"),
        "ed25519:".to_string(),
        format!("ed25519: {boa}"),
    ] {
        let texto = fonte(&ruim);
        // Um espaço a mais vira um campo a mais.
        let esperado = if ruim.contains(' ') {
            ErroTipo::Sintaxe
        } else {
            ErroTipo::ChaveInvalida
        };
        assert_eq!(
            erro(&texto),
            Erro {
                linha: 1,
                tipo: esperado
            },
            "{ruim}"
        );
    }
    // As de ordem pequena: a identidade e o ponto de ordem dois, entre
    // outras; e uma que nem é ponto da curva.
    let mut identidade = [0u8; 32];
    identidade[0] = 1;
    let mut fora_da_curva = None;
    for y in 2u8..=255 {
        let mut c = [0u8; 32];
        c[0] = y;
        if curve25519_dalek::edwards::CompressedEdwardsY(c)
            .decompress()
            .is_none()
        {
            fora_da_curva = Some(c);
            break;
        }
    }
    let fora_da_curva = fora_da_curva.expect("algum y pequeno fora da curva");
    let mut ordem_dois = [0u8; 32];
    // y = -1 (p - 1), o ponto (0, -1): ordem dois.
    ordem_dois[0] = 0xec;
    ordem_dois[1..31].fill(0xff);
    ordem_dois[31] = 0x7f;
    for fraca in [identidade, ordem_dois, [0u8; 32], fora_da_curva] {
        assert!(!chave_aceitavel(&fraca), "{}", hex(&fraca));
        assert_eq!(
            erro(&fonte(&format!("ed25519:{}", hex(&fraca)))).tipo,
            ErroTipo::ChaveFraca,
            "{}",
            hex(&fraca)
        );
    }
    assert!(chave_aceitavel(&raiz(1)));
}

/// O destino: UDP, na forma normal da política, e nada que se pareça.
#[test]
fn destinos() {
    let fonte = |destino: &str| format!("fonte a {destino} ed25519:{}\nquorum 2\n", hex(&raiz(1)));
    assert_eq!(
        erro(&fonte("tcp:10.0.2.2:5319")).tipo,
        ErroTipo::DestinoNaoUdp
    );
    for ruim in [
        "udp:10.0.2.2:05319",
        "udp:10.0.2.02:5319",
        "udp:10.0.2.2",
        "udp:10.0.2.2:0",
        "udp:10.0.2.2:65536",
        "UDP:10.0.2.2:5319",
        "udp:10.0.2.256:5319",
        "udp:bancada:5319",
        "udp:10.0.2.2:*",
        "10.0.2.2:5319",
        "udp:10.0.2.2:5319:1",
        "udp::5319",
    ] {
        assert_eq!(
            erro(&fonte(ruim)),
            Erro {
                linha: 1,
                tipo: ErroTipo::DestinoInvalido
            },
            "{ruim}"
        );
    }
    assert!(Registro::ler(&fonte("udp:192.0.2.7:2002")).is_ok());
}

/// Nome, destino e chave não se repetem — e a linha da repetição é a dita.
#[test]
fn repetidos() {
    let base = linha("a", "udp:10.0.2.2:5319", 1);
    let casos = [
        (linha("a", "udp:10.0.2.2:5320", 2), ErroTipo::NomeRepetido),
        (
            linha("b", "udp:10.0.2.2:5319", 2),
            ErroTipo::DestinoRepetido,
        ),
        (linha("b", "udp:10.0.2.2:5320", 1), ErroTipo::ChaveRepetida),
    ];
    for (segunda, tipo) in casos {
        let texto = format!("{base}# outra\n{segunda}quorum 2\n");
        assert_eq!(erro(&texto), Erro { linha: 3, tipo }, "{segunda}");
    }
}

/// Até oito fontes; a nona recusa o registro.
#[test]
fn fontes_demais() {
    let mut texto = String::new();
    for i in 0..MAIS_FONTES as u8 {
        texto.push_str(&linha(
            &format!("f{i}"),
            &format!("udp:10.0.2.2:{}", 6000 + u32::from(i)),
            i + 1,
        ));
    }
    texto.push_str("quorum 2\n");
    assert_eq!(Registro::ler(&texto).unwrap().fontes().len(), MAIS_FONTES);
    texto.push_str(&linha("f8", "udp:10.0.2.2:6008", 9));
    assert_eq!(
        erro(&texto),
        Erro {
            linha: MAIS_FONTES + 2,
            tipo: ErroTipo::FontesDemais
        }
    );
}

/// Os tetos do salto e da incerteza, nas pontas e uma além delas.
#[test]
fn os_tetos_nos_limites() {
    let com = |linhas: &str| format!("{}{linhas}", bancada());
    for (s, vale) in [(0, false), (1, true), (86_400, true), (86_401, false)] {
        let r = Registro::ler(&com(&format!("salto {s}\n")));
        if vale {
            let r = r.unwrap();
            assert_eq!(r.salto_s(), s);
            assert_eq!(r.parametros().salto_maximo_ms, s * 1000);
            assert!(r.parametros().validos());
        } else {
            assert_eq!(r.unwrap_err().tipo, ErroTipo::SaltoForaDosLimites(s));
        }
    }
    for (s, vale) in [
        (0, false),
        (9, false),
        (10, true),
        (600, true),
        (601, false),
    ] {
        let r = Registro::ler(&com(&format!("incerteza {s}\n")));
        if vale {
            let r = r.unwrap();
            assert_eq!(r.incerteza_s(), s);
            assert_eq!(r.parametros().teto_da_incerteza_ms, s * 1000);
        } else {
            assert_eq!(r.unwrap_err().tipo, ErroTipo::IncertezaForaDosLimites(s));
        }
    }
    assert_eq!(
        erro(&com("salto 60\nsalto 60\n")).tipo,
        ErroTipo::Repetida("salto")
    );
    assert_eq!(
        erro(&com("incerteza 60\nincerteza 60\n")).tipo,
        ErroTipo::Repetida("incerteza")
    );
    // Os outros parâmetros da disciplina não mudam pelo registro.
    let r = Registro::ler(&com("salto 3600\nincerteza 30\n")).unwrap();
    let p = r.parametros();
    assert_eq!(
        (p.limiar_minimo_ms, p.taxa_gradual_por_mil, p.deriva_ppm),
        (10_000, 50, 500)
    );
}

/// A forma das linhas: palavras conhecidas, campos contados, comentários e
/// linhas vazias ignorados.
#[test]
fn a_forma_das_linhas() {
    let r = Registro::ler(&format!(
        "\n   \n# so comentario\n{}  quorum 2   # duas chaves\n\r\n",
        linha("a", "udp:10.0.2.2:5319", 1).replace('\n', "  # a primeira\n")
    ))
    .unwrap();
    assert_eq!(r.fontes().len(), 1);
    for (texto, tipo) in [
        ("fontes a b c\n", ErroTipo::LinhaDesconhecida),
        (
            "servidor a udp:10.0.2.2:5319 x\n",
            ErroTipo::LinhaDesconhecida,
        ),
        ("Quorum 2\n", ErroTipo::LinhaDesconhecida),
        ("fonte a udp:10.0.2.2:5319\n", ErroTipo::Sintaxe),
        ("fonte\n", ErroTipo::Sintaxe),
        ("quorum\n", ErroTipo::Sintaxe),
        ("quorum 2 3\n", ErroTipo::Sintaxe),
        ("salto\n", ErroTipo::Sintaxe),
    ] {
        assert_eq!(erro(texto), Erro { linha: 1, tipo }, "{texto}");
    }
    let sobra = format!("{} extra\n", linha("a", "udp:10.0.2.2:5319", 1).trim_end());
    assert_eq!(erro(&sobra).tipo, ErroTipo::Sintaxe);
    for nome in ["A", "a b", "fonte/1", "", "a*"] {
        let texto = format!(
            "fonte {nome} udp:10.0.2.2:5319 ed25519:{}\nquorum 2\n",
            hex(&raiz(1))
        );
        let tipo = erro(&texto).tipo;
        assert!(
            matches!(tipo, ErroTipo::NomeInvalido | ErroTipo::Sintaxe),
            "{nome}: {tipo:?}"
        );
    }
    let longo = "a".repeat(33);
    let texto = format!(
        "fonte {longo} udp:10.0.2.2:5319 ed25519:{}\nquorum 2\n",
        hex(&raiz(1))
    );
    assert_eq!(erro(&texto).tipo, ErroTipo::NomeInvalido);
    let no_limite = "a".repeat(32);
    let texto = format!(
        "fonte {no_limite} udp:10.0.2.2:5319 ed25519:{}\nquorum 2\n",
        hex(&raiz(1))
    );
    assert_eq!(Registro::ler(&texto).unwrap().fontes()[0].nome(), no_limite);
    // Vazio: nenhuma fonte.
    for vazio in ["", "\n", "# nada\n", "quorum 2\n"] {
        assert_eq!(
            erro(vazio),
            Erro {
                linha: 0,
                tipo: ErroTipo::SemFontes
            },
            "{vazio:?}"
        );
    }
}

/// Um erro em qualquer linha recusa tudo: não há registro meio lido — nem
/// as fontes boas antes do erro, nem as depois.
#[test]
fn um_erro_recusa_o_registro_inteiro() {
    let boa = bancada();
    for ruim in [
        "quorum 1\n",
        "fonte x tcp:10.0.2.2:1 ed25519:00\n",
        "salto 0\n",
        "outra coisa\n",
    ] {
        for texto in [format!("{ruim}{boa}"), format!("{boa}{ruim}")] {
            assert!(Registro::ler(&texto).is_err(), "{texto}");
        }
    }
}

/// A coerência com a política padrão: o serviço de hora tem o papel
/// `tempo`, que tem `time.sync` e alcança cada fonte da bancada.
#[test]
fn coerente_com_a_padrao() {
    let r = Registro::ler(&bancada()).unwrap();
    let p = padrao();
    assert_eq!(r.conferir_com(&p), Ok(()));
    assert_eq!(r.fontes_sem_destino(&p).count(), 0);
}

/// Uma fonte registrada sem destino na política: incoerente, com o nome, o
/// destino e o código da decisão — o mesmo que o gate daria ao serviço.
#[test]
fn fonte_sem_destino_na_politica() {
    let texto = format!("{}{}", bancada(), linha("intrusa", "udp:10.0.2.2:5399", 9));
    let r = Registro::ler(&texto).unwrap();
    let p = padrao();
    let incoerencia = r.conferir_com(&p).unwrap_err();
    let Incoerencia::DestinoNaoAutorizado {
        papel,
        fonte,
        codigo,
    } = incoerencia
    else {
        panic!("{incoerencia:?}");
    };
    assert_eq!(
        (papel, fonte.nome(), codigo),
        ("tempo", "intrusa", Codigo::DenyResource)
    );
    assert_eq!(
        p.decidir(
            p.servico("hora"),
            Permissao::NetConnect,
            Some(fonte.destino())
        ),
        Codigo::DenyResource
    );
    let motivo = incoerencia.to_string();
    assert!(
        motivo.contains("`intrusa`") && motivo.contains("udp:10.0.2.2:5399"),
        "{motivo}"
    );
    let sem: Vec<_> = r
        .fontes_sem_destino(&p)
        .map(|(f, c)| (f.nome(), c))
        .collect();
    assert_eq!(sem, [("intrusa", Codigo::DenyResource)]);
    // Uma fonte que o sistema alcança, mas o tempo não: o alcance que vale
    // é o do papel do serviço.
    let tftp = Registro::ler(&format!(
        "{}quorum 2\n",
        linha("tftp", "udp:10.0.2.2:69", 4)
    ))
    .unwrap();
    assert_eq!(
        p.decidir(
            Some("sistema"),
            Permissao::NetConnect,
            Some("udp:10.0.2.2:69")
        ),
        Codigo::Allow
    );
    assert!(matches!(
        tftp.conferir_com(&p),
        Err(Incoerencia::DestinoNaoAutorizado {
            codigo: Codigo::DenyResource,
            ..
        })
    ));
}

/// Sem a linha `servico hora` — a política de emergência —, o serviço não
/// tem papel: incoerente, e cada fonte é recusada por papel.
#[test]
fn sem_o_servico_na_politica() {
    let r = Registro::ler(&bancada()).unwrap();
    let e = Politica::emergencia();
    assert_eq!(r.conferir_com(&e), Err(Incoerencia::SemServico));
    let sem: Vec<_> = r.fontes_sem_destino(&e).map(|(_, c)| c).collect();
    assert_eq!(sem, [Codigo::DenyRole; 3]);
    assert!(Incoerencia::SemServico.to_string().contains("servico hora"));
}

/// O papel do serviço sem `time.sync` — revogada por `policy.write` —, e
/// sem um destino: a coerência segue a política de agora.
#[test]
fn a_coerencia_segue_a_politica_de_agora() {
    let r = Registro::ler(&bancada()).unwrap();
    let p = padrao();
    let protegidos = ["administrador", "sistema"];
    let sem_sync = p
        .com_linha("papel tempo net.connect", "administrador", &protegidos)
        .unwrap();
    assert_eq!(
        r.conferir_com(&sem_sync),
        Err(Incoerencia::SemPermissao {
            papel: "tempo",
            codigo: Codigo::DenyPermission
        })
    );
    let estreito = p
        .com_linha(
            "recurso tempo net.connect udp:10.0.2.2:5319 udp:10.0.2.2:5320",
            "administrador",
            &protegidos,
        )
        .unwrap();
    let sem: Vec<_> = r
        .fontes_sem_destino(&estreito)
        .map(|(f, _)| f.nome())
        .collect();
    assert_eq!(sem, ["bancada-c"]);
    assert!(matches!(
        r.conferir_com(&estreito),
        Err(Incoerencia::DestinoNaoAutorizado { fonte, .. }) if fonte.nome() == "bancada-c"
    ));
}

/// O serviço sem papel na política lida: `servico hora` apontando para um
/// papel sem `net.connect` — recusado a cada fonte, por permissão.
#[test]
fn um_papel_que_nao_conecta() {
    let texto = politica::PADRAO.replace("servico hora tempo", "servico hora observador");
    let p = Politica::ler(&texto).unwrap();
    let r = Registro::ler(&bancada()).unwrap();
    assert_eq!(
        r.conferir_com(&p),
        Err(Incoerencia::SemPermissao {
            papel: "observador",
            codigo: Codigo::DenyPermission
        })
    );
    let sem: Vec<_> = r.fontes_sem_destino(&p).map(|(_, c)| c).collect();
    assert_eq!(sem, [Codigo::DenyPermission; 3]);
}
