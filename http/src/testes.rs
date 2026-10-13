//! Os testes do cliente contra um transporte de mentira, que entrega o que
//! o roteiro manda em pedaços do tamanho que o teste escolhe — de um byte
//! a uma leitura inteira —, para cada fronteira cair num lugar diferente.

use alloc::string::String;
use alloc::vec::Vec;

use crate::testes_da_codificacao::{OLA_GZIP, OLA_ZLIB, TEXTO_9, em_gzip, texto};
use crate::{
    Aceitas, Cliente, Codificacao, Defeito, Enquadramento, Erro, Fluxo, Limite, Limites, Metodo,
    Motivo, Pedido, Resposta, Url, Versao,
};

/// Uma falha do transporte de mentira: um código, como o do gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FalhaDeTeste(&'static str);

/// O transporte de mentira.
struct Roteiro {
    chegada: Vec<u8>,
    lidos: usize,
    pedaco: usize,
    /// Depois de a chegada acabar: o fecho limpo (`None`) ou esta falha.
    fim: Option<FalhaDeTeste>,
    /// Uma falha no meio da chegada, depois de tantos bytes.
    falha_em: Option<(usize, FalhaDeTeste)>,
    falha_ao_mandar: Option<FalhaDeTeste>,
    mandado: Vec<u8>,
    recebimentos: usize,
    /// Como um servidor de verdade: a chegada até `rodadas[k]` só fica
    /// disponível depois do pedido `k + 1`. Vazio, ela toda está lá desde
    /// o começo.
    rodadas: Vec<usize>,
    pedidos: usize,
}

impl Roteiro {
    fn novo(chegada: &[u8], pedaco: usize) -> Roteiro {
        Roteiro {
            chegada: chegada.to_vec(),
            lidos: 0,
            pedaco,
            fim: None,
            falha_em: None,
            falha_ao_mandar: None,
            mandado: Vec::new(),
            recebimentos: 0,
            rodadas: Vec::new(),
            pedidos: 0,
        }
    }

    /// Até onde a chegada já está disponível.
    fn liberado(&self) -> usize {
        match self.pedidos.min(self.rodadas.len()) {
            _ if self.rodadas.is_empty() => self.chegada.len(),
            0 => 0,
            k => self.rodadas[k - 1],
        }
    }
}

impl Fluxo for Roteiro {
    type Falha = FalhaDeTeste;

    fn mandar(&mut self, dados: &[u8]) -> Result<(), FalhaDeTeste> {
        if let Some(f) = self.falha_ao_mandar {
            return Err(f);
        }
        self.mandado.extend_from_slice(dados);
        self.pedidos += 1;
        Ok(())
    }

    fn receber(&mut self, destino: &mut [u8]) -> Result<usize, FalhaDeTeste> {
        self.recebimentos += 1;
        if let Some((em, f)) = self.falha_em
            && self.lidos >= em
        {
            return Err(f);
        }
        if self.lidos >= self.chegada.len() {
            return match self.fim {
                Some(f) => Err(f),
                None => Ok(0),
            };
        }
        // Um servidor de verdade não manda a resposta antes do pedido: ler
        // aqui seria esperar para sempre.
        let liberado = self.liberado();
        assert!(
            self.lidos < liberado,
            "o cliente esperou o que não foi pedido"
        );
        let mut n = self.pedaco.min(destino.len()).min(liberado - self.lidos);
        if let Some((em, _)) = self.falha_em {
            n = n.min(em - self.lidos);
        }
        destino[..n].copy_from_slice(&self.chegada[self.lidos..self.lidos + n]);
        self.lidos += n;
        Ok(n)
    }
}

/// Os tamanhos de pedaço com que cada resposta é entregue.
const PEDACOS: [usize; 8] = [1, 2, 3, 5, 7, 13, 64, 4096];

fn get(url: &str) -> Pedido {
    Pedido::novo(Metodo::Get, Url::ler(url).unwrap())
}

/// Uma troca de `metodo` com a `chegada` entregue em pedaços de `pedaco`.
fn trocar_com(
    chegada: &[u8],
    pedaco: usize,
    metodo: Metodo,
    limites: &Limites,
) -> Result<Resposta, Erro<FalhaDeTeste>> {
    let mut c = Cliente::novo(Roteiro::novo(chegada, pedaco));
    let p = Pedido::novo(metodo, Url::ler("http://bancada.duke/").unwrap());
    c.trocar(&p, limites)
}

/// A mesma troca com cada tamanho de pedaço: o resultado não pode depender
/// de onde a chegada foi partida.
fn em_todo_pedaco(
    chegada: &[u8],
    metodo: Metodo,
    limites: &Limites,
) -> Result<Resposta, Erro<FalhaDeTeste>> {
    let primeiro = trocar_com(chegada, PEDACOS[0], metodo, limites);
    for pedaco in &PEDACOS[1..] {
        let outro = trocar_com(chegada, *pedaco, metodo, limites);
        assert_eq!(outro, primeiro, "pedaco {pedaco}: {chegada:?}");
    }
    primeiro
}

fn ok(chegada: &str) -> Resposta {
    em_todo_pedaco(chegada.as_bytes(), Metodo::Get, &Limites::default())
        .unwrap_or_else(|e| panic!("{chegada:?}: {e:?}"))
}

fn falha(chegada: &str) -> Erro<FalhaDeTeste> {
    match em_todo_pedaco(chegada.as_bytes(), Metodo::Get, &Limites::default()) {
        Ok(r) => panic!("{chegada:?} foi aceita: {r:?}"),
        Err(e) => e,
    }
}

#[test]
fn o_corpo_pelo_tamanho() {
    let r = ok("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Duke: sim\r\n\r\nolaaa");
    assert_eq!(r.versao, Versao::Http11);
    assert_eq!(r.status, 200);
    assert_eq!(r.motivo, "OK");
    assert_eq!(r.corpo, b"olaaa");
    assert_eq!(r.enquadramento, Enquadramento::Tamanho(5));
    assert_eq!(r.cabecalho("x-duke"), Some("sim"));
    assert_eq!(r.cabecalho("X-DUKE"), Some("sim"));
    assert!(r.reutilizavel);
    // O espaço opcional em volta do valor sai; o do meio fica.
    let r = ok("HTTP/1.1 200 OK\r\nContent-Length:   2 \t\r\nX-A:  a  b  \r\n\r\nab");
    assert_eq!(r.cabecalho("x-a"), Some("a  b"));
    // Sem motivo depois do status.
    assert_eq!(ok("HTTP/1.1 204\r\n\r\n").motivo, "");
    assert_eq!(ok("HTTP/1.1 404 \r\nContent-Length: 0\r\n\r\n").status, 404);
}

#[test]
fn o_corpo_em_pedacos_com_extensoes_e_trailers() {
    let r = ok("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                2\r\num\r\n4;ext=1\r\ndois\r\n000A ;x\r\n0123456789\r\n0\r\nX-Fim: sim\r\n\r\n");
    assert_eq!(r.corpo, b"umdois0123456789");
    assert_eq!(r.enquadramento, Enquadramento::Pedacos);
    assert!(r.reutilizavel);
    let r = ok("HTTP/1.1 200 OK\r\nTransfer-Encoding: CHUNKED\r\n\r\n0\r\n\r\n");
    assert!(r.corpo.is_empty());
}

#[test]
fn o_corpo_ate_o_fecho_nao_deixa_a_conexao() {
    let r = ok("HTTP/1.1 200 OK\r\n\r\ntudo ate o fim");
    assert_eq!(r.corpo, b"tudo ate o fim");
    assert_eq!(r.enquadramento, Enquadramento::AteFechar);
    assert!(!r.reutilizavel);
}

#[test]
fn sem_corpo_diga_o_que_disser_o_tamanho() {
    let r = em_todo_pedaco(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n",
        Metodo::Head,
        &Limites::default(),
    )
    .unwrap();
    assert!(r.corpo.is_empty());
    assert!(r.reutilizavel);
    for status in ["204 No Content", "304 Not Modified"] {
        let r = ok(&alloc::format!(
            "HTTP/1.1 {status}\r\nContent-Length: 10\r\n\r\n"
        ));
        assert!(r.corpo.is_empty());
        assert_eq!(r.enquadramento, Enquadramento::Nenhum);
    }
}

#[test]
fn as_informativas_ficam_para_tras_e_a_troca_de_protocolo_nao() {
    let r = ok(
        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n\
                HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.corpo, b"ok");
    assert_eq!(
        falha("HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n"),
        Erro::Protocolo(Motivo::Troca)
    );
    let muitas = "HTTP/1.1 100 Continue\r\n\r\n".repeat(9) + "HTTP/1.1 200 OK\r\n\r\n";
    assert_eq!(falha(&muitas), Erro::Protocolo(Motivo::Informativas));
}

#[test]
fn a_linha_de_status_e_conferida() {
    for (chegada, motivo) in [
        ("HTTP/2.0 200 OK\r\n\r\n", Motivo::Versao),
        ("HTTP/1.2 200 OK\r\n\r\n", Motivo::Versao),
        ("HTTP/0.9 200 OK\r\n\r\n", Motivo::Versao),
        ("http/1.1 200 OK\r\n\r\n", Motivo::LinhaDeStatus),
        ("ICY 200 OK\r\n\r\n", Motivo::LinhaDeStatus),
        ("HTTP/1.1  200 OK\r\n\r\n", Motivo::LinhaDeStatus),
        ("HTTP/1.1 2OO OK\r\n\r\n", Motivo::LinhaDeStatus),
        ("HTTP/1.1 20\r\n\r\n", Motivo::LinhaDeStatus),
        ("HTTP/1.1 2000 OK\r\n\r\n", Motivo::LinhaDeStatus),
        ("HTTP/1.10 200 OK\r\n\r\n", Motivo::LinhaDeStatus),
        ("HTTP/1.1 099 Antes\r\n\r\n", Motivo::Status),
        ("HTTP/1.1 600 Depois\r\n\r\n", Motivo::Status),
        ("HTTP/1.1 200 O\u{1}K\r\n\r\n", Motivo::LinhaDeStatus),
    ] {
        assert_eq!(falha(chegada), Erro::Protocolo(motivo), "{chegada:?}");
    }
}

#[test]
fn o_fim_de_linha_e_crlf_e_nada_mais() {
    assert_eq!(
        falha("HTTP/1.1 200 OK\nContent-Length: 0\n\n"),
        Erro::Protocolo(Motivo::FimDeLinha)
    );
    assert_eq!(
        falha("HTTP/1.1 200 OK\r\nX-A: a\rb\r\nContent-Length: 0\r\n\r\n"),
        Erro::Protocolo(Motivo::FimDeLinha)
    );
    assert_eq!(
        falha("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\n"),
        Erro::Protocolo(Motivo::FimDeLinha)
    );
}

#[test]
fn os_cabecalhos_sao_conferidos() {
    for (chegada, motivo) in [
        (
            "HTTP/1.1 200 OK\r\nSemDoisPontos\r\n\r\n",
            Motivo::Cabecalho,
        ),
        ("HTTP/1.1 200 OK\r\n: vazio\r\n\r\n", Motivo::Cabecalho),
        ("HTTP/1.1 200 OK\r\nX-A : a\r\n\r\n", Motivo::Cabecalho),
        ("HTTP/1.1 200 OK\r\nX(A): a\r\n\r\n", Motivo::Cabecalho),
        ("HTTP/1.1 200 OK\r\nX-A: a\0b\r\n\r\n", Motivo::Cabecalho),
        (
            "HTTP/1.1 200 OK\r\nX-A: a\u{7f}b\r\n\r\n",
            Motivo::Cabecalho,
        ),
        ("HTTP/1.1 200 OK\r\nX-A: a\r\n b\r\n\r\n", Motivo::Dobra),
        ("HTTP/1.1 200 OK\r\nX-A: a\r\n\tb\r\n\r\n", Motivo::Dobra),
    ] {
        assert_eq!(falha(chegada), Erro::Protocolo(motivo), "{chegada:?}");
    }
}

#[test]
fn o_enquadramento_ambiguo_e_recusado() {
    for (chegada, motivo) in [
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
            Motivo::Ambiguo,
        ),
        (
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            Motivo::Codificacao,
        ),
        (
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            Motivo::Codificacao,
        ),
        (
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            Motivo::Codificacao,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 3, 4\r\n\r\nabcd",
            Motivo::Tamanho,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd",
            Motivo::Tamanho,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            Motivo::Tamanho,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: +3\r\n\r\nabc",
            Motivo::Tamanho,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 0x3\r\n\r\nabc",
            Motivo::Tamanho,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n",
            Motivo::Tamanho,
        ),
        (
            "HTTP/1.1 200 OK\r\nContent-Length: 3 3\r\n\r\nabc",
            Motivo::Tamanho,
        ),
    ] {
        assert_eq!(falha(chegada), Erro::Protocolo(motivo), "{chegada:?}");
    }
    // Repetido e igual, vale: a RFC 9112 deixa.
    let r = ok("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3, 3\r\n\r\nabc");
    assert_eq!(r.corpo, b"abc");
}

#[test]
fn os_pedacos_malformados_sao_recusados() {
    let base = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    for pedacos in [
        "g\r\nabc\r\n0\r\n\r\n",
        "\r\n0\r\n\r\n",
        " 3\r\nabc\r\n0\r\n\r\n",
        "3\r\nabcX\r\n0\r\n\r\n",
        "3\r\nabc\n0\r\n\r\n",
        "3;\u{1}\r\nabc\r\n0\r\n\r\n",
    ] {
        let chegada = alloc::format!("{base}{pedacos}");
        assert_eq!(
            falha(&chegada),
            Erro::Protocolo(Motivo::Pedaco),
            "{pedacos:?}"
        );
    }
    // Um trailer malformado também.
    let chegada = alloc::format!("{base}0\r\nsem dois pontos\r\n\r\n");
    assert_eq!(falha(&chegada), Erro::Protocolo(Motivo::Cabecalho));
}

#[test]
fn os_limites_param_a_leitura() {
    let pequeno = Limites {
        linha: 32,
        cabeca: 96,
        cabecalhos: 3,
        corpo: 10,
        ..Limites::default()
    };
    let falha_com =
        |chegada: &str| em_todo_pedaco(chegada.as_bytes(), Metodo::Get, &pequeno).unwrap_err();
    // Uma linha grande demais, com e sem o fim de linha ter chegado.
    let longa = alloc::format!("HTTP/1.1 200 OK\r\nX-A: {}\r\n\r\n", "a".repeat(40));
    assert_eq!(falha_com(&longa), Erro::Limite(Limite::Linha));
    let sem_fim = alloc::format!("HTTP/1.1 200 OK\r\nX-A: {}", "a".repeat(400));
    assert_eq!(falha_com(&sem_fim), Erro::Limite(Limite::Linha));
    // A cabeça inteira.
    let cabeca = "HTTP/1.1 200 OK\r\nX-A: 0123456789012345678\r\nX-B: 0123456789012345678\r\n\
                  X-C: 0123456789012345678\r\n\r\n";
    assert_eq!(falha_com(cabeca), Erro::Limite(Limite::Cabeca));
    // Cabeçalhos demais.
    assert_eq!(
        falha_com("HTTP/1.1 200 OK\r\nA: 1\r\nB: 2\r\nC: 3\r\nD: 4\r\n\r\n"),
        Erro::Limite(Limite::Cabecalhos)
    );
    // O corpo, pelo tamanho anunciado — sem esperar ele chegar —, em
    // pedaços e até o fecho.
    assert_eq!(
        falha_com("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n"),
        Erro::Limite(Limite::Corpo)
    );
    // Um tamanho que nem cabe num u64 também — com a linha folgada, para
    // ser o corpo, e não a linha, o limite que ele passa.
    let folgado = Limites {
        corpo: 10,
        ..Limites::default()
    };
    assert_eq!(
        em_todo_pedaco(
            b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n",
            Metodo::Get,
            &folgado
        )
        .unwrap_err(),
        Erro::Limite(Limite::Corpo)
    );
    assert_eq!(
        falha_com(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nabcdef\r\n6\r\nabcdef\r\n0\r\n\r\n"
        ),
        Erro::Limite(Limite::Corpo)
    );
    assert_eq!(
        falha_com("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFF\r\n"),
        Erro::Limite(Limite::Corpo)
    );
    assert_eq!(
        falha_com("HTTP/1.1 200 OK\r\n\r\n01234567890"),
        Erro::Limite(Limite::Corpo)
    );
    // No limite exato, passa.
    let r = em_todo_pedaco(
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789",
        Metodo::Get,
        &pequeno,
    )
    .unwrap();
    assert_eq!(r.corpo.len(), 10);
}

#[test]
fn o_tamanho_anunciado_grande_demais_nao_espera_o_corpo() {
    let limites = Limites {
        corpo: 10,
        ..Limites::default()
    };
    let mut c = Cliente::novo(Roteiro::novo(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n",
        4096,
    ));
    // O roteiro acabaria com uma falha se o cliente pedisse o corpo.
    c.fluxo().fim = Some(FalhaDeTeste("NAO_LEU"));
    let e = c.trocar(&get("http://h/"), &limites).unwrap_err();
    assert_eq!(e, Erro::Limite(Limite::Corpo));
}

#[test]
fn o_servidor_que_fecha_cedo_nao_entrega_resposta() {
    for chegada in [
        "",
        "HTTP/1.1 200",
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n12345",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-A: 1\r\n",
    ] {
        assert_eq!(falha(chegada), Erro::Fechada, "{chegada:?}");
    }
}

#[test]
fn a_falha_de_baixo_passa_como_veio() {
    // No meio da cabeça, no meio do corpo, e no lugar do fecho limpo.
    for (em, chegada) in [
        (10, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd"),
        (40, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd"),
    ] {
        for pedaco in PEDACOS {
            let mut roteiro = Roteiro::novo(chegada.as_bytes(), pedaco);
            roteiro.falha_em = Some((em, FalhaDeTeste("DENY_RESOURCE")));
            let mut c = Cliente::novo(roteiro);
            let e = c
                .trocar(&get("http://h/"), &Limites::default())
                .unwrap_err();
            assert_eq!(e, Erro::Baixo(FalhaDeTeste("DENY_RESOURCE")));
            assert_eq!(e.codigo(), None);
            assert!(!c.pronto());
        }
    }
    // O corpo até o fecho que não foi limpo — o TLS sem `close_notify` —
    // não vira resposta: o que chegou pode estar cortado.
    let mut roteiro = Roteiro::novo(b"HTTP/1.1 200 OK\r\n\r\nparte", 3);
    roteiro.fim = Some(FalhaDeTeste("TLS_INTERRUPTED"));
    let e = Cliente::novo(roteiro)
        .trocar(&get("http://h/"), &Limites::default())
        .unwrap_err();
    assert_eq!(e, Erro::Baixo(FalhaDeTeste("TLS_INTERRUPTED")));
    // E no envio: a resposta nem é lida.
    let mut roteiro = Roteiro::novo(b"HTTP/1.1 200 OK\r\n\r\n", 3);
    roteiro.falha_ao_mandar = Some(FalhaDeTeste("FIREWALL_BLOCKED"));
    let mut c = Cliente::novo(roteiro);
    let e = c
        .trocar(&get("http://h/"), &Limites::default())
        .unwrap_err();
    assert_eq!(e, Erro::Baixo(FalhaDeTeste("FIREWALL_BLOCKED")));
    assert_eq!(c.fluxo().recebimentos, 0);
}

#[test]
fn nenhuma_falha_vira_resposta() {
    // O que o protocolo recusa, recusa em cada pedaço: o resultado de uma
    // chegada partida em qualquer lugar é o mesmo — `em_todo_pedaco` o
    // confere — e não é nunca uma resposta.
    let malformadas = [
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc",
        "HTTP/1.1 200 OK\nContent-Length: 3\n\nabc",
        "HTTP/1.1 999 OK\r\nContent-Length: 3\r\n\r\nabc",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc",
        "HTTP/1.1 200 OK\r\nX-A : 1\r\nContent-Length: 3\r\n\r\nabc",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\nabc\r\n0\r\n\r\n",
    ];
    for chegada in malformadas {
        assert!(
            em_todo_pedaco(chegada.as_bytes(), Metodo::Get, &Limites::default()).is_err(),
            "{chegada:?}"
        );
    }
}

#[test]
fn a_conexao_leva_o_pedido_seguinte_quando_a_resposta_deixa() {
    for pedaco in PEDACOS {
        let chegada = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\num1\
                       HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\ndo2\r\n0\r\n\r\n\
                       HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntr3";
        let mut roteiro = Roteiro::novo(chegada.as_bytes(), pedaco);
        // Cada resposta só sai depois do pedido dela.
        let fins: Vec<usize> = chegada
            .match_indices("HTTP/1.1 200")
            .skip(1)
            .map(|(i, _)| i)
            .chain([chegada.len()])
            .collect();
        roteiro.rodadas = fins;
        let mut c = Cliente::novo(roteiro);
        let mut corpos = Vec::new();
        for _ in 0..3 {
            let r = c.trocar(&get("http://h/"), &Limites::default()).unwrap();
            corpos.push(String::from_utf8(r.corpo).unwrap());
        }
        assert_eq!(corpos, ["um1", "do2", "tr3"], "pedaco {pedaco}");
        assert!(!c.pronto());
        assert_eq!(c.trocas(), 3);
        assert_eq!(
            c.trocar(&get("http://h/"), &Limites::default()),
            Err(Erro::Esgotada)
        );
        // Os três pedidos saíram, um depois de cada resposta.
        let mandado = String::from_utf8(c.fluxo().mandado.clone()).unwrap();
        assert_eq!(mandado.matches("GET / HTTP/1.1\r\n").count(), 3);
    }
}

#[test]
fn o_que_chega_sem_pedido_nao_vira_a_resposta_seguinte() {
    // Bytes colados depois de uma resposta inteira, antes de o pedido
    // seguinte sair: um servidor dessincronizado — ou alguém no meio
    // tentando que a resposta de um pedido seja lida como a de outro. O
    // que já chegou junto é visto, e a conexão não leva o próximo pedido.
    let chegada = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\num1\
                    HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxx2";
    let mut c = Cliente::novo(Roteiro::novo(chegada, 4096));
    let r = c.trocar(&get("http://h/"), &Limites::default()).unwrap();
    assert_eq!(r.corpo, b"um1");
    assert!(!r.reutilizavel);
    assert!(!c.pronto());
    assert_eq!(
        c.trocar(&get("http://h/"), &Limites::default()),
        Err(Erro::Esgotada)
    );
}

#[test]
fn o_que_nao_deixa_a_conexao_para_o_pedido_seguinte() {
    let limites = Limites::default();
    for chegada in [
        // HTTP/1.0 sem pedir para manter.
        "HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\na",
        // Fechar, em qualquer caixa e numa lista.
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: Keep-Alive, CLOSE\r\n\r\na",
        // O corpo até o fecho.
        "HTTP/1.1 200 OK\r\n\r\na",
    ] {
        let mut c = Cliente::novo(Roteiro::novo(chegada.as_bytes(), 7));
        let r = c.trocar(&get("http://h/"), &limites).unwrap();
        assert!(!r.reutilizavel, "{chegada:?}");
        assert_eq!(
            c.trocar(&get("http://h/"), &limites),
            Err(Erro::Esgotada),
            "{chegada:?}"
        );
    }
    // HTTP/1.0 que pede para manter, mantém.
    let mut c = Cliente::novo(Roteiro::novo(
        b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\nConnection: keep-alive\r\n\r\na",
        7,
    ));
    assert!(c.trocar(&get("http://h/"), &limites).unwrap().reutilizavel);
    // Quem pediu para fechar não reaproveita, diga o servidor o que disser.
    let mut c = Cliente::novo(Roteiro::novo(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na",
        7,
    ));
    let mut p = get("http://h/");
    p.fechar = true;
    assert!(!c.trocar(&p, &limites).unwrap().reutilizavel);
    assert!(!c.pronto());
    // Bytes a mais depois da resposta: o servidor falou fora de hora.
    let mut c = Cliente::novo(Roteiro::novo(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naLIXO",
        4096,
    ));
    assert!(!c.trocar(&get("http://h/"), &limites).unwrap().reutilizavel);
    // E a troca que falhou no meio deixa a conexão sem uso.
    let mut c = Cliente::novo(Roteiro::novo(b"HTTP/1.1 200 OK\r\nX-A : 1\r\n\r\n", 7));
    assert!(c.trocar(&get("http://h/"), &limites).is_err());
    assert_eq!(c.trocar(&get("http://h/"), &limites), Err(Erro::Esgotada));
}

#[test]
fn o_corpo_grande_chega_inteiro() {
    let corpo: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let mut chegada =
        alloc::format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", corpo.len()).into_bytes();
    chegada.extend_from_slice(&corpo);
    for pedaco in [1000, 4096] {
        let r = trocar_com(&chegada, pedaco, Metodo::Get, &Limites::default()).unwrap();
        assert_eq!(r.corpo, corpo);
    }
    // E em pedaços.
    let mut chegada = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for parte in corpo.chunks(7777) {
        chegada.extend_from_slice(alloc::format!("{:x}\r\n", parte.len()).as_bytes());
        chegada.extend_from_slice(parte);
        chegada.extend_from_slice(b"\r\n");
    }
    chegada.extend_from_slice(b"0\r\n\r\n");
    let r = trocar_com(&chegada, 4096, Metodo::Get, &Limites::default()).unwrap();
    assert_eq!(r.corpo, corpo);
}

#[test]
fn o_pedido_vai_inteiro_pelo_fluxo() {
    let mut c = Cliente::novo(Roteiro::novo(
        b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n",
        7,
    ));
    let mut p = Pedido::novo(
        Metodo::Post,
        Url::ler("https://bancada.duke:8443/eco").unwrap(),
    );
    p.corpo = alloc::vec![7u8; 10_000];
    let r = c.trocar(&p, &Limites::default()).unwrap();
    assert_eq!(r.status, 201);
    let mandado = &c.fluxo().mandado;
    let cabeca =
        b"POST /eco HTTP/1.1\r\nHost: bancada.duke:8443\r\nAccept-Encoding: gzip, deflate\r\n\
                   Content-Length: 10000\r\n\r\n";
    assert_eq!(&mandado[..cabeca.len()], cabeca);
    assert_eq!(mandado.len(), cabeca.len() + 10_000);
}

/// A resposta `200` com o corpo `corpo` e os cabeçalhos `extras`, pelo
/// tamanho.
fn com_corpo(extras: &str, corpo: &[u8]) -> Vec<u8> {
    let mut v = alloc::format!(
        "HTTP/1.1 200 OK\r\n{extras}Content-Length: {}\r\n\r\n",
        corpo.len()
    )
    .into_bytes();
    v.extend_from_slice(corpo);
    v
}

#[test]
fn o_corpo_comprimido_chega_decodificado() {
    let ola = b"ola, Duke\n";
    for (extras, corpo, codificacao) in [
        (
            "Content-Encoding: gzip\r\n",
            &OLA_GZIP[..],
            Codificacao::Gzip,
        ),
        (
            "Content-Encoding: x-gzip\r\n",
            &OLA_GZIP[..],
            Codificacao::Gzip,
        ),
        (
            "Content-Encoding: deflate\r\n",
            &OLA_ZLIB[..],
            Codificacao::Deflate,
        ),
        (
            "Content-Encoding: identity, GZIP\r\n",
            &OLA_GZIP[..],
            Codificacao::Gzip,
        ),
    ] {
        let r = em_todo_pedaco(&com_corpo(extras, corpo), Metodo::Get, &Limites::default())
            .unwrap_or_else(|e| panic!("{extras:?}: {e:?}"));
        assert_eq!(r.corpo, ola, "{extras:?}");
        assert_eq!(r.codificacao, Some(codificacao));
        assert_eq!(r.no_fio, corpo.len());
        assert_eq!(r.enquadramento, Enquadramento::Tamanho(corpo.len() as u64));
        // Os cabeçalhos ficam como vieram: falam do corpo no fio.
        assert_eq!(
            r.cabecalho("content-length"),
            Some(&*alloc::format!("{}", corpo.len()))
        );
        assert!(r.reutilizavel);
    }
    // Em pedaços, e até o fecho.
    let t = texto(2048);
    let corpo = em_gzip(&TEXTO_9, &t);
    let mut chegada =
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for parte in corpo.chunks(100) {
        chegada.extend_from_slice(alloc::format!("{:x}\r\n", parte.len()).as_bytes());
        chegada.extend_from_slice(parte);
        chegada.extend_from_slice(b"\r\n");
    }
    chegada.extend_from_slice(b"0\r\n\r\n");
    let r = em_todo_pedaco(&chegada, Metodo::Get, &Limites::default()).unwrap();
    assert!(r.corpo == t);
    assert_eq!(r.no_fio, corpo.len());
    let mut chegada = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
    chegada.extend_from_slice(&corpo);
    let r = em_todo_pedaco(&chegada, Metodo::Get, &Limites::default()).unwrap();
    assert!(r.corpo == t);
    assert!(!r.reutilizavel);
    // Sem codificação, o corpo é o do fio.
    let r = ok("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc");
    assert_eq!(r.codificacao, None);
    assert_eq!(r.no_fio, 3);
}

#[test]
fn o_pedido_diz_o_que_aceita() {
    let mut c = Cliente::novo(Roteiro::novo(&com_corpo("", b""), 7));
    c.trocar(&get("http://h/"), &Limites::default()).unwrap();
    let mandado = String::from_utf8(c.fluxo().mandado.clone()).unwrap();
    assert!(
        mandado.contains("\r\nAccept-Encoding: gzip, deflate\r\n"),
        "{mandado:?}"
    );
    let mut c = Cliente::novo(Roteiro::novo(&com_corpo("", b""), 7));
    let mut p = get("http://h/");
    p.aceitas = Aceitas::NENHUMA;
    c.trocar(&p, &Limites::default()).unwrap();
    let mandado = String::from_utf8(c.fluxo().mandado.clone()).unwrap();
    assert!(
        mandado.contains("\r\nAccept-Encoding: identity\r\n"),
        "{mandado:?}"
    );
}

#[test]
fn a_codificacao_que_o_pedido_nao_aceitou_nao_le_o_corpo() {
    for (aceitas, extras) in [
        (Aceitas::NENHUMA, "Content-Encoding: gzip\r\n"),
        (
            Aceitas {
                gzip: true,
                deflate: false,
            },
            "Content-Encoding: deflate\r\n",
        ),
        (Aceitas::TODAS, "Content-Encoding: br\r\n"),
        (Aceitas::TODAS, "Content-Encoding: gzip, gzip\r\n"),
        (
            Aceitas::TODAS,
            "Content-Encoding: gzip\r\nContent-Encoding: deflate\r\n",
        ),
    ] {
        // Só a cabeça chega: ler o corpo seria pedir ao transporte o que o
        // roteiro recusa.
        let cabeca = alloc::format!("HTTP/1.1 200 OK\r\n{extras}Content-Length: 30\r\n\r\n");
        let mut roteiro = Roteiro::novo(cabeca.as_bytes(), 4096);
        roteiro.fim = Some(FalhaDeTeste("NAO_LEU"));
        let mut c = Cliente::novo(roteiro);
        let mut p = get("http://h/");
        p.aceitas = aceitas;
        let e = c.trocar(&p, &Limites::default()).unwrap_err();
        assert_eq!(e, Erro::Conteudo(Defeito::Codificacao), "{extras:?}");
        assert_eq!(e.codigo(), Some("HTTP_UNACCEPTED_ENCODING"));
        assert!(!c.pronto());
    }
}

#[test]
fn sem_corpo_a_codificacao_nao_importa() {
    // O `Content-Encoding` de um `HEAD`, de um `204` e de um `304` fala da
    // representação, e não há corpo para decodificar.
    let r = em_todo_pedaco(
        b"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: 30\r\n\r\n",
        Metodo::Head,
        &Limites::default(),
    )
    .unwrap();
    assert_eq!((r.codificacao, r.corpo.len()), (None, 0));
    for status in ["204 No Content", "304 Not Modified"] {
        let r = ok(&alloc::format!(
            "HTTP/1.1 {status}\r\nContent-Encoding: compress\r\n\r\n"
        ));
        assert_eq!(r.codificacao, None);
    }
    // O corpo vazio é a representação vazia: não há fluxo para conferir.
    let r = ok("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(
        (r.codificacao, r.corpo.len(), r.no_fio),
        (Some(Codificacao::Gzip), 0, 0)
    );
}

#[test]
fn o_conteudo_que_nao_se_decodifica_nao_vira_resposta() {
    let n = OLA_GZIP.len();
    let mut soma = OLA_GZIP.to_vec();
    soma[n - 5] ^= 1;
    let mut sobra = OLA_GZIP.to_vec();
    sobra.push(0);
    for (corpo, defeito) in [
        (&soma[..], Defeito::Soma),
        (&OLA_GZIP[..n - 1], Defeito::Cortado),
        (&sobra[..], Defeito::Sobra),
        (&OLA_ZLIB[..], Defeito::Cabecalho),
        (&OLA_GZIP[..10], Defeito::Cortado),
    ] {
        let chegada = com_corpo("Content-Encoding: gzip\r\n", corpo);
        let e = em_todo_pedaco(&chegada, Metodo::Get, &Limites::default()).unwrap_err();
        assert_eq!(e, Erro::Conteudo(defeito));
        assert_eq!(e.codigo(), Some("HTTP_CORRUPT_CONTENT"));
        // A mensagem chegou inteira, e a troca falhou: a conexão não leva
        // outro pedido.
        let mut c = Cliente::novo(Roteiro::novo(&chegada, 4096));
        assert!(c.trocar(&get("http://h/"), &Limites::default()).is_err());
        assert!(!c.pronto());
        assert_eq!(
            c.trocar(&get("http://h/"), &Limites::default()),
            Err(Erro::Esgotada)
        );
    }
}

#[test]
fn o_teto_do_corpo_decodificado_na_troca() {
    let t = texto(2048);
    let chegada = com_corpo("Content-Encoding: gzip\r\n", &em_gzip(&TEXTO_9, &t));
    let limites = |descomprimido| Limites {
        descomprimido,
        ..Limites::default()
    };
    assert!(
        em_todo_pedaco(&chegada, Metodo::Get, &limites(2048))
            .unwrap()
            .corpo
            == t
    );
    let e = em_todo_pedaco(&chegada, Metodo::Get, &limites(2047)).unwrap_err();
    assert_eq!(e, Erro::Limite(Limite::Descomprimido));
    assert_eq!(e.codigo(), Some("HTTP_TOO_LARGE"));
    // O limite do corpo vale para o que veio, antes de descomprimir: o
    // comprimido grande demais nem é lido.
    let pequeno = Limites {
        corpo: 100,
        ..Limites::default()
    };
    assert_eq!(
        em_todo_pedaco(&chegada, Metodo::Get, &pequeno).unwrap_err(),
        Erro::Limite(Limite::Corpo)
    );
    // E o corpo que veio como é não passa pelo decodificador: o limite
    // dele é o do corpo.
    let r = em_todo_pedaco(&com_corpo("", &t), Metodo::Get, &limites(10)).unwrap();
    assert_eq!(r.corpo.len(), 2048);
}
