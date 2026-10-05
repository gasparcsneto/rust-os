use super::*;
use alloc::vec;

/// Prepara e aplica, como o kernel faz depois de gravar.
fn gravar(a: &mut Armazem, c: &str, esperada: u64, dados: &[u8]) -> Result<u64, Recusa> {
    let m = a.preparar_gravacao(c, esperada, dados)?;
    a.aplicar(&m)?;
    Ok(m.versao())
}

fn apagar(a: &mut Armazem, c: &str, esperada: u64) -> Result<u64, Recusa> {
    let m = a.preparar_remocao(c, esperada)?;
    a.aplicar(&m)?;
    Ok(m.versao())
}

#[test]
fn criar_exige_versao_zero_e_substituir_a_de_agora() {
    let mut a = Armazem::novo();
    assert_eq!(gravar(&mut a, "notas.txt", 0, b"um"), Ok(1));
    assert_eq!(a.versao("notas.txt"), 1);
    // Criar de novo: já existe.
    assert_eq!(
        gravar(&mut a, "notas.txt", 0, b"outro"),
        Err(Recusa::Versao { atual: 1 })
    );
    // Substituir contra uma versão que não é a de agora.
    assert_eq!(
        gravar(&mut a, "notas.txt", 7, b"outro"),
        Err(Recusa::Versao { atual: 1 })
    );
    assert_eq!(gravar(&mut a, "notas.txt", 1, b"dois"), Ok(2));
    assert_eq!(a.objeto("notas.txt").unwrap().dados(), b"dois");
    // Substituir o que não existe: a versão de agora é 0.
    assert_eq!(
        gravar(&mut a, "outro.txt", 1, b"x"),
        Err(Recusa::Versao { atual: 0 })
    );
}

#[test]
fn a_recusa_nao_muda_nada() {
    let mut a = Armazem::novo();
    gravar(&mut a, "a", 0, b"um").unwrap();
    let antes = (a.proxima(), a.ocupacao(), a.versao("a"));
    let _ = gravar(&mut a, "a", 0, b"x");
    let _ = gravar(&mut a, "a/b", 0, b"x");
    let _ = gravar(&mut a, "../a", 0, b"x");
    let _ = apagar(&mut a, "a", 9);
    let _ = a.preparar_acrescimo("a", 9, b"x");
    assert_eq!(antes, (a.proxima(), a.ocupacao(), a.versao("a")));
    assert_eq!(a.objeto("a").unwrap().dados(), b"um");
}

#[test]
fn preparar_nao_aplica() {
    let mut a = Armazem::novo();
    let m = a.preparar_gravacao("a", 0, b"um").unwrap();
    assert_eq!(a.tipo("a"), None);
    assert_eq!(a.proxima(), 1);
    // Duas preparações seguidas levam a mesma versão: só uma aplica.
    let n = a.preparar_gravacao("b", 0, b"dois").unwrap();
    assert_eq!(m.versao(), n.versao());
    a.aplicar(&m).unwrap();
    assert_eq!(a.aplicar(&n), Err(Recusa::ForaDeOrdem));
    assert_eq!(a.tipo("b"), None);
}

#[test]
fn a_versao_e_do_armazem_e_so_cresce() {
    let mut a = Armazem::novo();
    assert_eq!(gravar(&mut a, "a", 0, b"1"), Ok(1));
    assert_eq!(gravar(&mut a, "b", 0, b"1"), Ok(2));
    assert_eq!(gravar(&mut a, "a", 1, b"2"), Ok(3));
    assert_eq!(apagar(&mut a, "a", 3), Ok(4));
    assert_eq!(a.versao("a"), 0);
    // Criado de novo, não volta a uma versão já vista.
    assert_eq!(gravar(&mut a, "a", 0, b"novo"), Ok(5));
    assert_eq!(
        gravar(&mut a, "a", 3, b"de quem leu o antigo"),
        Err(Recusa::Versao { atual: 5 })
    );
}

#[test]
fn acrescimo_e_remocao_exigem_a_versao_de_agora() {
    let mut a = Armazem::novo();
    assert_eq!(a.preparar_acrescimo("log", 0, b"x"), Err(Recusa::NaoExiste));
    assert_eq!(a.preparar_remocao("log", 0), Err(Recusa::NaoExiste));
    gravar(&mut a, "log", 0, b"um\n").unwrap();
    assert_eq!(
        a.preparar_acrescimo("log", 0, b"x"),
        Err(Recusa::Versao { atual: 1 })
    );
    let m = a.preparar_acrescimo("log", 1, b"dois\n").unwrap();
    a.aplicar(&m).unwrap();
    assert_eq!(a.objeto("log").unwrap().dados(), b"um\ndois\n");
    assert_eq!(a.versao("log"), 2);
    assert_eq!(
        a.preparar_remocao("log", 1),
        Err(Recusa::Versao { atual: 2 })
    );
    assert_eq!(apagar(&mut a, "log", 2), Ok(3));
    assert_eq!(a.ocupacao(), (0, 0));
}

#[test]
fn diretorios_sao_implicitos() {
    let mut a = Armazem::novo();
    assert_eq!(a.tipo(""), Some(Tipo::Diretorio));
    assert_eq!(a.tipo("d"), None);
    gravar(&mut a, "d/e/f.txt", 0, b"x").unwrap();
    assert_eq!(a.tipo("d"), Some(Tipo::Diretorio));
    assert_eq!(a.tipo("d/e"), Some(Tipo::Diretorio));
    assert_eq!(a.tipo("d/e/f.txt"), Some(Tipo::Arquivo));
    // Um prefixo do nome não é diretório.
    assert_eq!(a.tipo("d/e/f"), None);
    gravar(&mut a, "d-irma", 0, b"x").unwrap();
    assert_eq!(a.tipo("d-irma"), Some(Tipo::Arquivo));
    // Um arquivo não toma o nome de um diretório, nem fica abaixo de um
    // arquivo.
    assert_eq!(gravar(&mut a, "d/e", 0, b"x"), Err(Recusa::EhDiretorio));
    assert_eq!(gravar(&mut a, "d", 0, b"x"), Err(Recusa::EhDiretorio));
    assert_eq!(
        gravar(&mut a, "d/e/f.txt/g", 0, b"x"),
        Err(Recusa::PaiEhArquivo)
    );
    assert_eq!(
        gravar(&mut a, "d-irma/g", 0, b"x"),
        Err(Recusa::PaiEhArquivo)
    );
    // Apagado o único arquivo, os diretórios somem.
    apagar(&mut a, "d/e/f.txt", 1).unwrap();
    assert_eq!(a.tipo("d"), None);
    assert_eq!(gravar(&mut a, "d", 0, b"agora pode"), Ok(4));
}

#[test]
fn filhos_em_ordem_de_nome() {
    let mut a = Armazem::novo();
    for c in ["b/x", "b/y/z", "a", "c", "b-c", "b/y/w"] {
        gravar(&mut a, c, 0, b"1").unwrap();
    }
    let nomes = |d: &str| -> Vec<(String, Tipo)> { a.filhos(d) };
    assert_eq!(
        nomes(""),
        vec![
            ("a".into(), Tipo::Arquivo),
            ("b".into(), Tipo::Diretorio),
            ("b-c".into(), Tipo::Arquivo),
            ("c".into(), Tipo::Arquivo),
        ]
    );
    assert_eq!(
        nomes("b"),
        vec![("x".into(), Tipo::Arquivo), ("y".into(), Tipo::Diretorio)]
    );
    assert_eq!(
        nomes("b/y"),
        vec![("w".into(), Tipo::Arquivo), ("z".into(), Tipo::Arquivo)]
    );
    assert!(nomes("a").is_empty());
    assert!(nomes("nada").is_empty());
}

#[test]
fn caminhos_invalidos() {
    let mut a = Armazem::novo();
    let longo = "x".repeat(MAIOR_COMPONENTE + 1);
    let fundo = ["d"; MAIS_NIVEIS + 1].join("/");
    let raso = ["d"; MAIS_NIVEIS].join("/");
    for c in [
        "",
        "/a",
        "a/",
        "a//b",
        ".",
        "..",
        "a/../b",
        "a/./b",
        "a b",
        "á",
        "a\0",
        "a\\b",
        longo.as_str(),
        fundo.as_str(),
    ] {
        assert!(!caminho_valido(c), "{c:?}");
        assert_eq!(
            gravar(&mut a, c, 0, b"x"),
            Err(Recusa::CaminhoInvalido),
            "{c:?}"
        );
        assert_eq!(a.preparar_remocao(c, 0), Err(Recusa::CaminhoInvalido));
        assert_eq!(
            a.preparar_acrescimo(c, 0, b"x"),
            Err(Recusa::CaminhoInvalido)
        );
    }
    let no_teto = "x".repeat(MAIOR_COMPONENTE);
    for c in ["a", "A.b_c-9", "...", no_teto.as_str(), raso.as_str()] {
        assert!(caminho_valido(c), "{c:?}");
    }
    assert_eq!(gravar(&mut a, &raso, 0, b"x"), Ok(1));
}

#[test]
fn teto_de_um_arquivo() {
    let mut a = Armazem::novo();
    let cheio = vec![b'x'; MAIOR_ARQUIVO];
    assert_eq!(gravar(&mut a, "a", 0, &cheio), Ok(1));
    assert_eq!(a.preparar_acrescimo("a", 1, b"y"), Err(Recusa::Grande));
    assert_eq!(
        gravar(&mut a, "b", 0, &vec![b'x'; MAIOR_ARQUIVO + 1]),
        Err(Recusa::Grande)
    );
    // Substituir por algo menor libera.
    assert_eq!(gravar(&mut a, "a", 1, b"pouco"), Ok(2));
    assert_eq!(a.ocupacao(), (1, 5));
}

#[test]
fn teto_de_arquivos() {
    let mut a = Armazem::novo();
    for i in 0..MAIS_ARQUIVOS {
        gravar(&mut a, &alloc::format!("f{i}"), 0, b"").unwrap();
    }
    assert_eq!(gravar(&mut a, "mais", 0, b""), Err(Recusa::Cheio));
    // Substituir um que existe não conta como mais um, mesmo vazio.
    let v = a.versao("f0");
    assert!(gravar(&mut a, "f0", v, b"agora tem").is_ok());
    let v = a.versao("f1");
    assert!(gravar(&mut a, "f1", v, b"").is_ok());
    // Apagar um abre lugar.
    let v = a.versao("f2");
    apagar(&mut a, "f2", v).unwrap();
    assert!(gravar(&mut a, "mais", 0, b"").is_ok());
}

#[test]
fn teto_de_bytes() {
    let mut a = Armazem::novo();
    let cheio = vec![b'x'; MAIOR_ARQUIVO];
    let quantos = MAIOR_ARMAZEM / MAIOR_ARQUIVO;
    for i in 0..quantos {
        gravar(&mut a, &alloc::format!("f{i}"), 0, &cheio).unwrap();
    }
    assert_eq!(a.ocupacao(), (quantos, MAIOR_ARMAZEM));
    assert_eq!(gravar(&mut a, "mais", 0, b"x"), Err(Recusa::Cheio));
    // Trocar um pelo mesmo tamanho cabe: os bytes antigos saem da conta.
    let v = a.versao("f0");
    assert!(gravar(&mut a, "f0", v, &cheio).is_ok());
    let v = a.versao("f1");
    assert!(gravar(&mut a, "f1", v, b"menos").is_ok());
    assert!(gravar(&mut a, "mais", 0, b"x").is_ok());
}

#[test]
fn aplicar_e_a_reposicao_do_boot() {
    // O que o kernel grava, na ordem.
    let mut a = Armazem::novo();
    let mut gravadas = Vec::new();
    for (c, dados) in [("a", &b"1"[..]), ("d/b", b"2"), ("a", b"3")] {
        let v = a.versao(c);
        let m = a.preparar_gravacao(c, v, dados).unwrap();
        a.aplicar(&m).unwrap();
        gravadas.push(m);
    }
    let m = a.preparar_remocao("d/b", 2).unwrap();
    a.aplicar(&m).unwrap();
    gravadas.push(m);

    // O boot repõe o mesmo estado, sem preparar nada.
    let mut b = Armazem::novo();
    for m in &gravadas {
        b.aplicar(m).unwrap();
    }
    assert_eq!(b.proxima(), a.proxima());
    assert_eq!(b.ocupacao(), a.ocupacao());
    assert_eq!(b.objeto("a").unwrap().dados(), b"3");
    assert_eq!(b.versao("a"), 3);
    assert_eq!(b.tipo("d"), None);

    // Repetida, ou fora de ordem, uma mudança é recusada.
    assert_eq!(b.aplicar(&gravadas[0]), Err(Recusa::ForaDeOrdem));
    assert_eq!(b.aplicar(&gravadas[3]), Err(Recusa::ForaDeOrdem));
    // Uma remoção do que não existe também.
    let nada = Mudanca::Apagado {
        caminho: "nada".into(),
        versao: 99,
    };
    assert_eq!(b.aplicar(&nada), Err(Recusa::NaoExiste));
    assert_eq!(b.proxima(), a.proxima());
    // E uma gravação que o lugar ou os tetos não aceitam.
    let ruim = Mudanca::Gravado {
        caminho: "a/x".into(),
        versao: 99,
        dados: vec![],
    };
    assert_eq!(b.aplicar(&ruim), Err(Recusa::PaiEhArquivo));
    let grande = Mudanca::Gravado {
        caminho: "g".into(),
        versao: 99,
        dados: vec![0; MAIOR_ARQUIVO + 1],
    };
    assert_eq!(b.aplicar(&grande), Err(Recusa::Grande));
    assert_eq!(b.proxima(), a.proxima());
}

#[test]
fn a_base_repoe_a_proxima_versao() {
    // Depois de uma compactação, a base diz a próxima versão: as que já
    // foram dadas a objetos apagados não voltam.
    let mut a = Armazem::novo();
    gravar(&mut a, "a", 0, b"1").unwrap();
    apagar(&mut a, "a", 1).unwrap();
    let mut b = Armazem::novo();
    b.fixar_proxima(a.proxima());
    assert_eq!(b.proxima(), 3);
    b.fixar_proxima(1);
    assert_eq!(b.proxima(), 3);
    assert_eq!(gravar(&mut b, "a", 0, b"novo"), Ok(3));
}

#[test]
fn a_versao_reencontra_um_conteudo_so() {
    let mut a = Armazem::novo();
    gravar(&mut a, "a", 0, b"1").unwrap();
    assert_eq!(
        a.por_versao(1).map(|(c, o)| (c, o.dados())),
        Some(("a", &b"1"[..]))
    );
    // Mudado, a versão antiga não acha mais nada: quem a guardou não lê
    // metade de um conteúdo e metade de outro.
    gravar(&mut a, "a", 1, b"2").unwrap();
    assert!(a.por_versao(1).is_none());
    assert_eq!(a.por_versao(2).map(|(c, _)| c), Some("a"));
    apagar(&mut a, "a", 2).unwrap();
    assert!(a.por_versao(2).is_none());
    assert!(a.coerente());
}

#[test]
fn diretorios_tem_numero_enquanto_existem() {
    let mut a = Armazem::novo();
    assert_eq!(a.id_do_diretorio(""), Some(0));
    assert_eq!(a.diretorio(0), Some(""));
    gravar(&mut a, "d/e/f", 0, b"x").unwrap();
    gravar(&mut a, "d/g", 0, b"x").unwrap();
    let d = a.id_do_diretorio("d").unwrap();
    let e = a.id_do_diretorio("d/e").unwrap();
    assert_ne!(d, e);
    assert_ne!(d, 0);
    assert_eq!(a.diretorio(d), Some("d"));
    assert_eq!(a.diretorio(e), Some("d/e"));
    // Mudar um arquivo não muda o número do diretório.
    gravar(&mut a, "d/e/f", 1, b"y").unwrap();
    assert_eq!(a.id_do_diretorio("d/e"), Some(e));
    // Vazio, ele sai; o de cima continua, com o mesmo número.
    apagar(&mut a, "d/e/f", 3).unwrap();
    assert_eq!(a.id_do_diretorio("d/e"), None);
    assert_eq!(a.diretorio(e), None);
    assert_eq!(a.id_do_diretorio("d"), Some(d));
    assert!(a.coerente());
    // De volta, é outro número: o de antes não aponta para o novo.
    gravar(&mut a, "d/e/h", 0, b"x").unwrap();
    assert_ne!(a.id_do_diretorio("d/e"), Some(e));
    assert_eq!(a.diretorio(e), None);
    assert!(a.coerente());
}

#[test]
fn as_contas_ficam_coerentes() {
    let mut a = Armazem::novo();
    let caminhos = ["a/b/c", "a/b/d", "a/e", "f", "g/h/i/j"];
    for (n, c) in caminhos.iter().enumerate() {
        gravar(&mut a, c, 0, &alloc::vec![b'x'; n]).unwrap();
        assert!(a.coerente());
    }
    for c in caminhos.iter().rev() {
        let v = a.versao(c);
        let m = a.preparar_acrescimo(c, v, b"mais").unwrap();
        a.aplicar(&m).unwrap();
        assert!(a.coerente());
    }
    for c in caminhos {
        let v = a.versao(c);
        apagar(&mut a, c, v).unwrap();
        assert!(a.coerente());
    }
    assert_eq!(a.ocupacao(), (0, 0));
    assert!(a.filhos("").is_empty());
}

#[test]
fn a_versao_tem_teto() {
    let mut a = Armazem::novo();
    gravar(&mut a, "a", 0, b"1").unwrap();
    a.fixar_proxima(MAIOR_VERSAO);
    assert_eq!(gravar(&mut a, "b", 0, b"1"), Ok(MAIOR_VERSAO));
    assert_eq!(gravar(&mut a, "c", 0, b"1"), Err(Recusa::Cheio));
    assert_eq!(a.preparar_remocao("a", 1), Err(Recusa::Cheio));
    let alem = Mudanca::Apagado {
        caminho: "a".into(),
        versao: MAIOR_VERSAO + 1,
    };
    assert_eq!(a.aplicar(&alem), Err(Recusa::Cheio));
}

#[test]
fn todos_em_ordem() {
    let mut a = Armazem::novo();
    for c in ["z", "a/b", "m"] {
        gravar(&mut a, c, 0, c.as_bytes()).unwrap();
    }
    let v: Vec<&str> = a.todos().map(|(c, _)| c).collect();
    assert_eq!(v, ["a/b", "m", "z"]);
}
