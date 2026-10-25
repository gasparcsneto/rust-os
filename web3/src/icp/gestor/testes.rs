//! O pedido, as proteções, o registro e o plano do gestor de canisters.

use std::format;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use super::*;
use crate::icp::bancada::Sorteio;
use crate::icp::resumo::sha256;

const CANISTER: &str = "lxzze-o7777-77777-aaaaa-cai";
const OUTRO: &str = "qpsvj-4l777-77775-qaaaa-cai";
/// O Principal auto-autenticado de uma chave Ed25519 qualquer.
const DA_CHAVE: &str = "hpikg-6exdt-jn33w-ndty3-fc7jc-tl2lr-buih3-cs3y7-tftkp-sfp62-gqe";
/// O SHA-256 de um módulo, como o pedido o diz.
const SHA: &str = "sha256 9b6cc41ff390673f7c41030d1764a945419bff2dd7260bf37e8cb6a4e82d6590";

fn p(texto: &str) -> Principal {
    Principal::de_texto(texto).unwrap()
}

fn pedido(linhas: &[&str]) -> Result<Pedido, Erro> {
    ler_pedido(&linhas.join("\n"))
}

fn base(acao: &str) -> Vec<String> {
    vec![
        format!("acao {acao}"),
        String::from("rede bancada"),
        String::from("chave chave:bancada"),
    ]
}

fn com(acao: &str, mais: &[&str]) -> Result<Pedido, Erro> {
    let mut l = base(acao);
    l.extend(mais.iter().map(|s| s.to_string()));
    ler_pedido(&l.join("\n"))
}

#[test]
fn cada_acao_com_o_que_ela_pede() {
    let saldo = com("saldo", &[]).unwrap();
    assert_eq!(saldo.acao, Acao::Saldo);
    assert_eq!(saldo.rede, "bancada");
    assert_eq!(saldo.chave, "chave:bancada");
    assert_eq!(saldo.canister, None);

    let criar = com(
        "criar",
        &["ciclos 1000000000000", "confirmar 1000000000000"],
    )
    .unwrap();
    assert_eq!(criar.ciclos, Some(1_000_000_000_000));

    let instalar = com(
        "instalar",
        &[
            &format!("canister {CANISTER}"),
            "modulo /dados/icp/modulos/a.wasm",
            SHA,
            "modo upgrade",
        ],
    )
    .unwrap();
    assert_eq!(instalar.canister, Some(p(CANISTER)));
    assert_eq!(
        instalar.modulo.as_deref(),
        Some("/dados/icp/modulos/a.wasm")
    );
    assert_eq!(
        instalar.sha256.map(|h| h[..2].to_vec()),
        Some(vec![0x9b, 0x6c])
    );
    assert_eq!(instalar.modo, Some(Modo::Atualizar));
    // Sem argumento, o vazio do Candid.
    assert_eq!(instalar.argumento, VAZIO);

    let com_argumento = com(
        "instalar",
        &[
            &format!("canister {CANISTER}"),
            "modulo /armazem/compartilhado/m.wasm",
            SHA,
            "modo install",
            "argumento 4449444c00017107616263646566",
        ],
    )
    .unwrap();
    assert_eq!(com_argumento.modo, Some(Modo::Instalar));
    assert_eq!(com_argumento.argumento, b"DIDL\x00\x01\x71\x07abcdef");

    let reinstalar = com(
        "instalar",
        &[
            &format!("canister {CANISTER}"),
            "modulo /m.wasm",
            SHA,
            "modo reinstall",
            &format!("confirmar {CANISTER}"),
        ],
    )
    .unwrap();
    assert_eq!(reinstalar.modo, Some(Modo::Reinstalar));

    for acao in ["estado", "parar", "iniciar"] {
        let pedido = com(acao, &[&format!("canister {CANISTER}")]).unwrap();
        assert_eq!(pedido.acao.nome(), acao);
        assert_eq!(pedido.canister, Some(p(CANISTER)));
    }

    let controladores = com(
        "controladores",
        &[
            &format!("canister {CANISTER}"),
            &format!("controlador {DA_CHAVE}"),
            &format!("controlador {OUTRO}"),
            &format!("confirmar {CANISTER}"),
        ],
    )
    .unwrap();
    assert_eq!(controladores.controladores, vec![p(DA_CHAVE), p(OUTRO)]);

    let congelamento = com(
        "congelamento",
        &[&format!("canister {CANISTER}"), "congelamento 2592000"],
    )
    .unwrap();
    assert_eq!(congelamento.congelamento, Some(2_592_000));

    for acao in ["desinstalar", "apagar"] {
        let pedido = com(
            acao,
            &[
                &format!("canister {CANISTER}"),
                &format!("confirmar {CANISTER}"),
            ],
        )
        .unwrap();
        assert_eq!(pedido.acao.nome(), acao);
    }

    let carregar = com(
        "carregar",
        &[
            &format!("canister {CANISTER}"),
            "ciclos 500000000000",
            "confirmar 500000000000",
        ],
    )
    .unwrap();
    assert_eq!(carregar.ciclos, Some(500_000_000_000));

    let recarregar = com(
        "recarregar",
        &[
            &format!("canister {CANISTER}"),
            "icp 100000000",
            "confirmar 100000000",
        ],
    )
    .unwrap();
    assert_eq!(recarregar.icp, Some(100_000_000));

    // As âncoras e o resolvedor, em qualquer ação; comentários, linhas
    // vazias e o CRLF não atrapalham.
    let opcoes = ler_pedido(
        "# um pedido\r\nacao saldo\r\n\r\nrede mainnet\nchave chave:x\nancoras /dados/tls/publicas.pem\ndns udp:10.0.2.3:53\n",
    )
    .unwrap();
    assert_eq!(opcoes.ancoras.as_deref(), Some("/dados/tls/publicas.pem"));
    assert_eq!(opcoes.dns.as_deref(), Some("udp:10.0.2.3:53"));
    assert_eq!(opcoes.rede, "mainnet");
}

#[test]
fn o_que_falta_recusa() {
    assert_eq!(
        pedido(&["rede bancada", "chave chave:bancada"]),
        Err(Erro {
            linha: 0,
            motivo: "pedido sem acao"
        })
    );
    assert_eq!(
        pedido(&["acao saldo", "chave chave:bancada"])
            .unwrap_err()
            .motivo,
        "pedido sem rede"
    );
    assert_eq!(
        pedido(&["acao saldo", "rede bancada"]).unwrap_err().motivo,
        "pedido sem chave"
    );
    assert_eq!(
        com("estado", &[]).unwrap_err().motivo,
        "pedido sem canister"
    );
    assert_eq!(
        com("criar", &["confirmar 1"]).unwrap_err().motivo,
        "pedido sem ciclos"
    );
    let c = format!("canister {CANISTER}");
    assert_eq!(
        com("instalar", &[&c, "modo upgrade"]).unwrap_err().motivo,
        "pedido sem modulo"
    );
    assert_eq!(
        com("instalar", &[&c, "modulo /m.wasm", "modo upgrade"])
            .unwrap_err()
            .motivo,
        "pedido sem sha256"
    );
    assert_eq!(
        com("instalar", &[&c, "modulo /m.wasm", SHA])
            .unwrap_err()
            .motivo,
        "pedido sem modo"
    );
    assert_eq!(
        com("controladores", &[&c, &format!("confirmar {CANISTER}")])
            .unwrap_err()
            .motivo,
        "pedido sem controlador"
    );
    assert_eq!(
        com("congelamento", &[&c]).unwrap_err().motivo,
        "pedido sem congelamento"
    );
    assert_eq!(
        com("recarregar", &[&c, "confirmar 1"]).unwrap_err().motivo,
        "pedido sem icp"
    );
}

#[test]
fn o_que_sobra_ou_se_repete_recusa_com_a_linha() {
    // Um campo que a ação não usa.
    assert_eq!(
        com("saldo", &[&format!("canister {CANISTER}")]),
        Err(Erro {
            linha: 4,
            motivo: "campo que a acao nao usa"
        })
    );
    assert_eq!(
        com(
            "estado",
            &[&format!("canister {CANISTER}"), "modulo /m.wasm"]
        ),
        Err(Erro {
            linha: 5,
            motivo: "campo que a acao nao usa"
        })
    );
    assert_eq!(
        com("criar", &["ciclos 1", "confirmar 1", "icp 1"])
            .unwrap_err()
            .motivo,
        "campo que a acao nao usa"
    );
    // Repetido.
    assert_eq!(
        pedido(&["acao saldo", "rede a", "rede b", "chave chave:x"]),
        Err(Erro {
            linha: 3,
            motivo: "campo repetido"
        })
    );
    // Desconhecido.
    assert_eq!(
        com("saldo", &["dono pessoa:1"]),
        Err(Erro {
            linha: 4,
            motivo: "campo desconhecido"
        })
    );
    // Sem valor, valor com espaço.
    assert_eq!(
        com("saldo", &["dns"]).unwrap_err().motivo,
        "linha sem valor"
    );
    assert_eq!(
        com("saldo", &["dns a b"]).unwrap_err().motivo,
        "valor fora da forma"
    );
}

#[test]
fn os_valores_fora_da_forma() {
    let fora = |l: &[&str]| pedido(l).unwrap_err().motivo;
    assert_eq!(fora(&["acao voar"]), "acao desconhecida");
    assert_eq!(fora(&["rede Bancada"]), "nome de rede fora da forma");
    assert_eq!(fora(&["rede ../x"]), "nome de rede fora da forma");
    assert_eq!(
        fora(&[&format!("rede {}", "a".repeat(33))]),
        "nome de rede fora da forma"
    );
    assert_eq!(fora(&["chave bancada"]), "chave sem o prefixo chave:");
    assert_eq!(fora(&["chave chave:"]), "nome de chave fora da forma");
    let c = format!("canister {CANISTER}");
    let em = |mais: &str| com("instalar", &[&c, "modo upgrade", "modulo /m", SHA, mais]);
    for sha in [
        "sha256 9b6c",
        "sha256 XX",
        &format!("sha256 {}", "0".repeat(66)),
    ] {
        assert_eq!(
            com("instalar", &[&c, "modo upgrade", "modulo /m", sha])
                .unwrap_err()
                .motivo,
            "sha256 fora da forma",
            "{sha}"
        );
    }
    // O sha256 é só da instalação.
    assert_eq!(
        com("estado", &[&c, SHA]).unwrap_err().motivo,
        "campo que a acao nao usa"
    );
    assert_eq!(
        com("estado", &["canister nao-e-principal"])
            .unwrap_err()
            .motivo,
        "canister fora da forma"
    );
    assert_eq!(
        com("instalar", &[&c, "modo upgrade", "modulo m.wasm"])
            .unwrap_err()
            .motivo,
        "modulo sem caminho absoluto"
    );
    assert_eq!(
        com("instalar", &[&c, "modulo /m", "modo atualizar"])
            .unwrap_err()
            .motivo,
        "modo desconhecido"
    );
    assert_eq!(
        em("argumento 4449444").unwrap_err().motivo,
        "argumento fora do hexadecimal"
    );
    assert_eq!(
        em("argumento 4449444C0000").unwrap_err().motivo,
        "argumento fora do hexadecimal"
    );
    assert_eq!(
        em("argumento 00112233").unwrap_err().motivo,
        "argumento que nao e candid"
    );
    let grande = format!("argumento 4449444c{}", "00".repeat(MAIOR_ARGUMENTO));
    assert_eq!(
        em(&grande).unwrap_err().motivo,
        "argumento que nao e candid"
    );
    for ciclos in [
        "0",
        "01",
        "1e9",
        "-1",
        "340282366920938463463374607431768211456",
    ] {
        assert_eq!(
            com("criar", &[&format!("ciclos {ciclos}"), "confirmar 1"])
                .unwrap_err()
                .motivo,
            "ciclos fora da forma",
            "{ciclos}"
        );
    }
    assert_eq!(
        com(
            "recarregar",
            &[&c, "icp 18446744073709551616", "confirmar 1"]
        )
        .unwrap_err()
        .motivo,
        "icp fora da forma"
    );
    assert_eq!(
        com(
            "controladores",
            &[&c, "controlador x", &format!("confirmar {CANISTER}")]
        )
        .unwrap_err()
        .motivo,
        "controlador fora da forma"
    );
    assert_eq!(
        com(
            "controladores",
            &[
                &c,
                &format!("controlador {OUTRO}"),
                &format!("controlador {OUTRO}"),
                &format!("confirmar {CANISTER}"),
            ]
        ),
        Err(Erro {
            linha: 6,
            motivo: "controlador repetido"
        })
    );
    assert_eq!(
        com("congelamento", &[&c, "congelamento 0"])
            .unwrap_err()
            .motivo,
        "congelamento fora da forma"
    );
    assert_eq!(
        com("saldo", &["ancoras tls.pem"]).unwrap_err().motivo,
        "ancoras sem caminho absoluto"
    );
    for dns in [
        "10.0.2.3:53",
        "udp:10.0.2.3",
        "udp:10.0.2:53",
        "udp:10.0.2.300:53",
        "tcp:10.0.2.3:53",
        "udp:10.0.2.3:0",
    ] {
        assert_eq!(
            com("saldo", &[&format!("dns {dns}")]).unwrap_err().motivo,
            "dns fora da forma udp:<ipv4>:<porta>",
            "{dns}"
        );
    }
    // O pedido grande demais.
    let enorme = format!("acao saldo\n#{}", "x".repeat(MAIOR_PEDIDO));
    assert_eq!(
        ler_pedido(&enorme).unwrap_err().motivo,
        "pedido grande demais"
    );
}

#[test]
fn onze_controladores_recusam() {
    let mut s = Sorteio::novo(71);
    let mut l = base("controladores");
    l.push(format!("canister {CANISTER}"));
    for _ in 0..=MAIS_CONTROLADORES {
        let c = Principal::de_bytes(&s.bytes(29)).unwrap();
        l.push(format!("controlador {}", c.texto()));
    }
    l.push(format!("confirmar {CANISTER}"));
    assert_eq!(
        ler_pedido(&l.join("\n")),
        Err(Erro {
            linha: 15,
            motivo: "mais de 10 controladores"
        })
    );
}

#[test]
fn a_confirmacao_e_o_que_a_acao_mexe() {
    let c = format!("canister {CANISTER}");
    // Sem ela, onde é pedida.
    for (acao, mais) in [
        ("criar", vec!["ciclos 5"]),
        ("carregar", vec![c.as_str(), "ciclos 5"]),
        ("recarregar", vec![c.as_str(), "icp 5"]),
        ("desinstalar", vec![c.as_str()]),
        ("apagar", vec![c.as_str()]),
    ] {
        assert_eq!(
            com(acao, &mais).unwrap_err().motivo,
            "pedido sem confirmar",
            "{acao}"
        );
    }
    assert_eq!(
        com("controladores", &[&c, &format!("controlador {DA_CHAVE}")])
            .unwrap_err()
            .motivo,
        "pedido sem confirmar"
    );
    assert_eq!(
        com("instalar", &[&c, "modulo /m", SHA, "modo reinstall"])
            .unwrap_err()
            .motivo,
        "pedido sem confirmar"
    );
    // A de outro canister, ou de outra quantia.
    assert_eq!(
        com("apagar", &[&c, &format!("confirmar {OUTRO}")]),
        Err(Erro {
            linha: 5,
            motivo: "confirmar nao e o que a acao mexe"
        })
    );
    assert_eq!(
        com("criar", &["ciclos 5", "confirmar 50"])
            .unwrap_err()
            .motivo,
        "confirmar nao e o que a acao mexe"
    );
    // A quantia confirma a quantia, e não o canister.
    assert_eq!(
        com(
            "carregar",
            &[&c, "ciclos 5", &format!("confirmar {CANISTER}")]
        )
        .unwrap_err()
        .motivo,
        "confirmar nao e o que a acao mexe"
    );
    // Onde não se pede, sobra.
    for (acao, mais) in [
        ("saldo", vec![]),
        ("estado", vec![c.as_str()]),
        ("parar", vec![c.as_str()]),
        ("congelamento", vec![c.as_str(), "congelamento 9"]),
    ] {
        let mut mais = mais.clone();
        mais.push("confirmar x");
        assert_eq!(
            com(acao, &mais).unwrap_err().motivo,
            "confirmar numa acao que nao pede",
            "{acao}"
        );
    }
    assert_eq!(
        com(
            "instalar",
            &[
                &c,
                "modulo /m",
                SHA,
                "modo upgrade",
                &format!("confirmar {CANISTER}")
            ]
        )
        .unwrap_err()
        .motivo,
        "confirmar numa acao que nao pede"
    );
}

#[test]
fn os_controladores_novos_incluem_a_chave() {
    let c = format!("canister {CANISTER}");
    let sem = com(
        "controladores",
        &[
            &c,
            &format!("controlador {OUTRO}"),
            &format!("confirmar {CANISTER}"),
        ],
    )
    .unwrap();
    assert_eq!(
        conferir_controladores(&sem, &p(DA_CHAVE)),
        Err("os controladores novos nao incluem a propria chave")
    );
    let com_ela = com(
        "controladores",
        &[
            &c,
            &format!("controlador {OUTRO}"),
            &format!("controlador {DA_CHAVE}"),
            &format!("confirmar {CANISTER}"),
        ],
    )
    .unwrap();
    assert_eq!(conferir_controladores(&com_ela, &p(DA_CHAVE)), Ok(()));
    // Só a troca de controladores tem a regra.
    let estado = com("estado", &[&c]).unwrap();
    assert_eq!(conferir_controladores(&estado, &p(DA_CHAVE)), Ok(()));
}

fn registro_sorteado(s: &mut Sorteio) -> Registro {
    let situacoes = [Situacao::Ativo, Situacao::Parado, Situacao::Apagado];
    let mut r = Registro::default();
    for _ in 0..s.ate(12) {
        let id = Principal::de_bytes(&s.bytes_ate(29)).unwrap();
        let _ = r.anotar(Canister {
            id,
            situacao: situacoes[s.ate(3) as usize],
            modulo: (s.ate(2) == 1).then(|| sha256(&s.bytes(8))),
            ns: s.proximo(),
        });
    }
    if s.ate(2) == 1 {
        let acoes: Vec<Acao> = ACOES
            .iter()
            .map(|(a, _)| *a)
            .filter(|a| !a.so_le())
            .collect();
        let acao = acoes[s.ate(acoes.len() as u64) as usize];
        // Em andamento, o texto vai junto, e o resumo é o dele.
        let texto = format!("acao {}\nrede bancada\n# {}\n", acao.nome(), s.proximo());
        let (fase, resumo) = if s.ate(2) == 1 {
            (Fase::Feito, sha256(&s.bytes(8)))
        } else {
            (Fase::Andamento(texto.clone()), sha256(texto.as_bytes()))
        };
        r.ultimo = Some(Ultimo {
            pedido: s.proximo(),
            acao,
            fase,
            criado_em_ns: s.proximo(),
            resumo,
        });
    }
    r
}

#[test]
fn o_registro_vai_e_volta() {
    let mut s = Sorteio::novo(72);
    for _ in 0..300 {
        let r = registro_sorteado(&mut s);
        assert_eq!(ler_registro(&r.texto()), Ok(r));
    }
    // O vazio é só o cabeçalho.
    assert_eq!(Registro::default().texto(), format!("{CABECALHO}\n"));
    assert_eq!(ler_registro(CABECALHO), Ok(Registro::default()));
}

#[test]
fn o_registro_que_nao_se_entende_e_recusado() {
    let hex = |b: &[u8]| -> String { b.iter().map(|b| format!("{b:02x}")).collect() };
    let h = sha256(b"x");
    let hh = hex(&h);
    // O texto do pedido em andamento: o do resumo, e o que não é.
    let texto = "acao criar\n";
    let ht = hex(&sha256(texto.as_bytes()));
    let texto_hex = hex(texto.as_bytes());
    let invalido = [0xffu8, 0xfe];
    let hi = hex(&sha256(&invalido));
    let longo = "#".repeat(MAIOR_PEDIDO + 1);
    let hl = hex(&sha256(longo.as_bytes()));
    let bom_canister = format!("canister {CANISTER} ativo nenhum 5");
    let casos: Vec<(String, usize, &str)> = vec![
        (String::new(), 1, "registro sem o cabecalho"),
        (String::from("# outro"), 1, "registro sem o cabecalho"),
        (format!("{CABECALHO}\nlixo"), 2, "linha fora da forma"),
        (
            format!("{CABECALHO}\ncanister x ativo nenhum 5"),
            2,
            "canister fora da forma",
        ),
        (
            format!("{CABECALHO}\n{bom_canister}\n{bom_canister}"),
            3,
            "canister repetido",
        ),
        (
            format!("{CABECALHO}\ncanister {CANISTER} vivo nenhum 5"),
            2,
            "situacao desconhecida",
        ),
        (
            format!("{CABECALHO}\ncanister {CANISTER} ativo abcd 5"),
            2,
            "hash do modulo fora da forma",
        ),
        (
            format!("{CABECALHO}\ncanister {CANISTER} ativo nenhum -5"),
            2,
            "hora fora da forma",
        ),
        (
            format!("{CABECALHO}\nultimo 1 criar feito 2 {hh}\n{bom_canister}"),
            3,
            "canister depois do ultimo",
        ),
        (
            format!("{CABECALHO}\nultimo 1 criar feito 2 {hh}\nultimo 1 criar feito 2 {hh}"),
            3,
            "ultimo repetido",
        ),
        (
            format!("{CABECALHO}\nultimo 1 voar feito 2 {hh}"),
            2,
            "acao desconhecida",
        ),
        (
            format!("{CABECALHO}\nultimo 1 estado feito 2 {hh}"),
            2,
            "ultimo de uma acao que so le",
        ),
        (
            format!("{CABECALHO}\nultimo 1 criar talvez 2 {hh}"),
            2,
            "estado do ultimo desconhecido",
        ),
        (
            format!("{CABECALHO}\nultimo x criar feito 2 {hh}"),
            2,
            "versao fora da forma",
        ),
        (
            format!("{CABECALHO}\nultimo 1 criar feito 2 abc"),
            2,
            "resumo do pedido fora da forma",
        ),
        // Em andamento sem o texto, e feito com um.
        (
            format!("{CABECALHO}\nultimo 1 criar andamento 2 {ht}"),
            2,
            "linha fora da forma",
        ),
        (
            format!("{CABECALHO}\nultimo 1 criar feito 2 {ht} {texto_hex}"),
            2,
            "linha fora da forma",
        ),
        (
            format!("{CABECALHO}\nultimo 1 criar andamento 2 {ht} {texto_hex} {texto_hex}"),
            2,
            "linha fora da forma",
        ),
        // O texto que não é o do resumo, o vazio, o grande, o que não é
        // UTF-8 e o que não é hexadecimal.
        (
            format!("{CABECALHO}\nultimo 1 criar andamento 2 {hh} {texto_hex}"),
            2,
            "o texto do pedido nao e o do resumo",
        ),
        (
            format!("{CABECALHO}\nultimo 1 criar andamento 2 {ht} "),
            2,
            "texto do pedido fora da forma",
        ),
        (
            format!(
                "{CABECALHO}\nultimo 1 criar andamento 2 {hl} {}",
                hex(longo.as_bytes())
            ),
            2,
            "texto do pedido fora da forma",
        ),
        (
            format!(
                "{CABECALHO}\nultimo 1 criar andamento 2 {hi} {}",
                hex(&invalido)
            ),
            2,
            "texto do pedido fora da forma",
        ),
        (
            format!("{CABECALHO}\nultimo 1 criar andamento 2 {ht} xyz"),
            2,
            "texto do pedido fora da forma",
        ),
    ];
    for (texto, linha, motivo) in casos {
        assert_eq!(ler_registro(&texto), Err(Erro { linha, motivo }), "{texto}");
    }
    // Canisters demais, e o registro grande demais.
    let mut s = Sorteio::novo(73);
    let mut texto = format!("{CABECALHO}\n");
    for _ in 0..=MAIS_CANISTERS {
        let id = Principal::de_bytes(&s.bytes(10)).unwrap();
        texto.push_str(&format!("canister {} ativo nenhum 1\n", id.texto()));
    }
    assert_eq!(
        ler_registro(&texto).unwrap_err().motivo,
        "o registro tem canisters demais"
    );
    let enorme = format!("{CABECALHO}\n#{}", "x".repeat(MAIOR_REGISTRO));
    assert_eq!(
        ler_registro(&enorme).unwrap_err().motivo,
        "registro grande demais"
    );
}

#[test]
fn anotar_troca_ou_acrescenta_ate_o_teto() {
    let mut r = Registro::default();
    let a = Canister {
        id: p(CANISTER),
        situacao: Situacao::Ativo,
        modulo: None,
        ns: 1,
    };
    r.anotar(a.clone()).unwrap();
    let parado = Canister {
        situacao: Situacao::Parado,
        ns: 2,
        ..a.clone()
    };
    r.anotar(parado.clone()).unwrap();
    assert_eq!(r.canisters, vec![parado.clone()]);
    assert_eq!(r.canister(&p(CANISTER)), Some(&parado));
    assert_eq!(r.canister(&p(OUTRO)), None);
    let mut s = Sorteio::novo(74);
    while r.canisters.len() < MAIS_CANISTERS {
        let id = Principal::de_bytes(&s.bytes(12)).unwrap();
        r.anotar(Canister { id, ..a.clone() }).unwrap();
    }
    let mais_um = Canister {
        id: Principal::de_bytes(&s.bytes(13)).unwrap(),
        ..a.clone()
    };
    assert_eq!(r.anotar(mais_um), Err("o registro tem canisters demais"));
    // O que já está continua anotável com o registro cheio.
    assert_eq!(r.anotar(a), Ok(()));
}

#[test]
fn o_plano_de_cada_pedido() {
    let resumo = sha256(b"acao criar");
    let outro_resumo = sha256(b"acao carregar");
    let agora = 1_000;
    let antes = 10;
    let vazio = Registro::default();
    let executar = Plano::Executar {
        criado_em_ns: agora,
    };
    // Sem último: executa com a hora de agora.
    assert_eq!(planejar(7, Acao::Criar, &resumo, &vazio, agora), executar);
    let com_ultimo = |feito: bool, pedido, resumo| Registro {
        canisters: vec![],
        ultimo: Some(Ultimo {
            pedido,
            acao: Acao::Criar,
            fase: if feito {
                Fase::Feito
            } else {
                Fase::Andamento(String::from("acao criar"))
            },
            criado_em_ns: antes,
            resumo,
        }),
    };
    // Em andamento, o mesmo texto retoma com a hora de antes — da mesma
    // versão, ou regravado.
    for versao in [7, 8] {
        assert_eq!(
            planejar(
                versao,
                Acao::Criar,
                &resumo,
                &com_ultimo(false, 7, resumo),
                agora
            ),
            Plano::Retomar {
                criado_em_ns: antes
            }
        );
    }
    // Em andamento, outro texto não executa.
    assert_eq!(
        planejar(
            8,
            Acao::Carregar,
            &outro_resumo,
            &com_ultimo(false, 7, resumo),
            agora
        ),
        Plano::Bloqueado {
            pendente: Acao::Criar,
            versao: 7
        }
    );
    // Feito: a mesma versão não executa de novo; outra versão — mesmo do
    // mesmo texto — é outro pedido.
    assert_eq!(
        planejar(7, Acao::Criar, &resumo, &com_ultimo(true, 7, resumo), agora),
        Plano::JaFeito
    );
    assert_eq!(
        planejar(8, Acao::Criar, &resumo, &com_ultimo(true, 7, resumo), agora),
        executar
    );
    // O que só lê executa sempre, mesmo com outro em andamento.
    for acao in [Acao::Saldo, Acao::Estado] {
        assert_eq!(
            planejar(7, acao, &resumo, &com_ultimo(false, 7, outro_resumo), agora),
            executar
        );
        assert!(acao.so_le());
    }
}

#[test]
fn os_nomes_e_as_mensagens() {
    for (acao, nome) in ACOES {
        assert_eq!(acao.nome(), nome);
        assert_eq!(Acao::de(nome), Some(acao));
    }
    assert_eq!(Acao::de("Saldo"), None);
    for s in [Situacao::Ativo, Situacao::Parado, Situacao::Apagado] {
        assert_eq!(Situacao::de(s.nome()), Some(s));
    }
    let e = Erro {
        linha: 3,
        motivo: "campo repetido",
    };
    assert_eq!(e.to_string(), "linha 3: campo repetido");
    assert_eq!(
        Erro {
            linha: 0,
            motivo: "pedido sem acao"
        }
        .to_string(),
        "pedido sem acao"
    );
    // Toda mensagem do módulo é ASCII.
    let fonte = include_str!("../gestor.rs");
    for linha in fonte
        .lines()
        .filter(|l| l.contains("erro(") || l.contains("Err(\""))
    {
        if let Some(i) = linha.find('"') {
            let resto = &linha[i + 1..];
            let fim = resto.find('"').unwrap_or(resto.len());
            assert!(resto[..fim].is_ascii(), "{linha}");
        }
    }
}
