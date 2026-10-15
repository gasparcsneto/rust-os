//! O cliente HTTP/2 contra o `nghttpd`, o servidor da nghttp2 — a mesma
//! biblioteca de HTTP/2 do `curl`, escrita por outras pessoas, em outra
//! língua.
//!
//! O servidor de mentira dos testes de unidade foi escrito junto com o
//! cliente, e os dois concordam até onde entenderam a RFC do mesmo jeito.
//! Este arquivo é o que diz se o entendimento é o de quem implementou para
//! valer: o prefácio, os ajustes, o HPACK com a tabela dinâmica do servidor,
//! as janelas apertadas, o preenchimento, os *trailers*, a recusa de
//! correntes.
//!
//! Precisa do `nghttpd` no `PATH` (pacote `nghttp2-server`). Sem ele o teste
//! **falha**, e não pula: um teste que passa quando o que ele testa não
//! existe é um teste que mente.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use http::{
    AjustesH2, ClienteH2, Enquadramento, Erro, Fluxo, Limite, Limites, Metodo, Pedido, Url, Versao,
};

/// A conexão TCP como transporte do HTTP.
struct Tcp(TcpStream);

impl Fluxo for Tcp {
    type Falha = ErrorKind;

    fn mandar(&mut self, dados: &[u8]) -> Result<(), ErrorKind> {
        self.0.write_all(dados).map_err(|e| e.kind())
    }

    fn receber(&mut self, destino: &mut [u8]) -> Result<usize, ErrorKind> {
        self.0.read(destino).map_err(|e| e.kind())
    }
}

/// Um diretório temporário apagado no fim.
struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// O que a raiz do servidor tem.
const PEQUENO: &[u8] = b"ola, nghttpd\n";

fn padrao(n: usize) -> Vec<u8> {
    (0..n).map(|i| b'a' + (i % 23) as u8).collect()
}

/// Um `nghttpd` sem TLS (h2c com conhecimento prévio), numa porta livre, com
/// a raiz num diretório próprio.
struct Nghttpd {
    processo: Child,
    porta: u16,
    _dir: Dir,
}

impl Nghttpd {
    fn novo(nome: &str, opcoes: &[&str]) -> Nghttpd {
        let dir = std::env::temp_dir().join(format!("http-{nome}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pequeno"), PEQUENO).unwrap();
        std::fs::write(dir.join("vazio"), b"").unwrap();
        std::fs::write(dir.join("medio"), padrao(100 * 1024)).unwrap();
        std::fs::write(dir.join("grande"), padrao(3 * 1024 * 1024)).unwrap();
        // Quem é este servidor: os testes rodam juntos, e a porta livre de
        // um pode ser pega pelo servidor de outro antes do dele.
        let marca = format!("{}:{nome}", std::process::id());
        std::fs::write(dir.join("quem"), &marca).unwrap();
        let mut dir = Dir(dir);
        for _ in 0..20 {
            let porta = TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let processo = Command::new("nghttpd")
                .args(["--no-tls", "-a", "127.0.0.1", "-d"])
                .arg(&dir.0)
                .args(opcoes)
                .arg(porta.to_string())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("o nghttpd precisa estar no PATH (pacote nghttp2-server)");
            let mut servidor = Nghttpd {
                processo,
                porta,
                _dir: dir,
            };
            if servidor.e_este(&marca) {
                return servidor;
            }
            // Outro pegou a porta: este sai, e tenta outra.
            let _ = servidor.processo.kill();
            let _ = servidor.processo.wait();
            dir = Dir(std::mem::take(&mut servidor._dir.0));
        }
        panic!("o nghttpd nao abriu uma porta que fosse dele");
    }

    /// O servidor que responde na porta é este: está vivo, e serve a marca
    /// dele.
    fn e_este(&mut self, marca: &str) -> bool {
        let limite = Instant::now() + Duration::from_secs(10);
        while TcpStream::connect(("127.0.0.1", self.porta)).is_err() {
            if self.processo.try_wait().unwrap().is_some() || Instant::now() > limite {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // A porta pode ter sido de outro servidor, que já foi embora: a
        // conexão recusada também diz que não é este.
        let Ok(tcp) = TcpStream::connect(("127.0.0.1", self.porta)) else {
            return false;
        };
        tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut c = ClienteH2::novo(Tcp(tcp));
        let quem = c.trocar(&self.get("/quem"), &Limites::default());
        self.processo.try_wait().unwrap().is_none()
            && quem.is_ok_and(|r| r.corpo == marca.as_bytes())
    }

    fn conectar(&self) -> ClienteH2<Tcp> {
        self.conectar_com(AjustesH2::default())
    }

    fn conectar_com(&self, ajustes: AjustesH2) -> ClienteH2<Tcp> {
        let tcp = TcpStream::connect(("127.0.0.1", self.porta)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        ClienteH2::com(Tcp(tcp), ajustes)
    }

    fn url(&self, caminho: &str) -> Url {
        Url::ler(&format!("http://127.0.0.1:{}{caminho}", self.porta)).unwrap()
    }

    fn get(&self, caminho: &str) -> Pedido {
        Pedido::novo(Metodo::Get, self.url(caminho))
    }
}

impl Drop for Nghttpd {
    fn drop(&mut self) {
        let _ = self.processo.kill();
        let _ = self.processo.wait();
    }
}

#[test]
fn uma_troca_e_varias_ao_mesmo_tempo() {
    let servidor = Nghttpd::novo("varias", &[]);
    let mut c = servidor.conectar();
    let r = c
        .trocar(&servidor.get("/pequeno"), &Limites::default())
        .unwrap();
    assert_eq!(r.versao, Versao::Http2);
    assert_eq!(r.status, 200);
    assert_eq!(r.corpo, PEQUENO);
    assert_eq!(r.enquadramento, Enquadramento::Quadros);
    assert_eq!(r.cabecalho("content-length"), Some("13"));
    // Dezesseis de 100 KiB ao mesmo tempo — cada uma além da janela
    // inicial dela —, recebidas de trás para a frente.
    let correntes: Vec<_> = (0..16)
        .map(|_| {
            c.enviar(&servidor.get("/medio"), &Limites::default())
                .unwrap()
        })
        .collect();
    for corrente in correntes.into_iter().rev() {
        let r = c.receber(corrente).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.corpo, padrao(100 * 1024));
    }
    let r = c
        .trocar(&servidor.get("/vazio"), &Limites::default())
        .unwrap();
    assert_eq!((r.status, r.corpo.len()), (200, 0));
    let r = c
        .trocar(&servidor.get("/nao-existe"), &Limites::default())
        .unwrap();
    assert_eq!(r.status, 404);
    assert_eq!(c.trocas(), 19);
    assert!(c.pronto());
    c.fechar().unwrap();
}

#[test]
fn a_tabela_dinamica_do_servidor_ao_longo_da_conexao() {
    // O `nghttpd` indexa os cabeçalhos que repete (`server`, `date`,
    // `content-type`...): cada resposta depois da primeira aponta para a
    // tabela que as anteriores montaram.
    let servidor = Nghttpd::novo("tabela", &[]);
    let mut c = servidor.conectar();
    let primeira = c
        .trocar(&servidor.get("/pequeno"), &Limites::default())
        .unwrap();
    for _ in 0..50 {
        let r = c
            .trocar(&servidor.get("/pequeno"), &Limites::default())
            .unwrap();
        assert_eq!(r.corpo, PEQUENO);
        assert_eq!(r.cabecalho("server"), primeira.cabecalho("server"));
        assert_eq!(r.cabecalho("content-length"), Some("13"));
    }
}

#[test]
fn a_tabela_deste_lado_com_zero_bytes_no_servidor() {
    // O servidor decodifica com a tabela em zero: o primeiro bloco deste
    // lado já diz que a dele tem zero.
    let servidor = Nghttpd::novo("tabela-zero", &["-c", "0"]);
    let mut c = servidor.conectar();
    for _ in 0..3 {
        let r = c
            .trocar(&servidor.get("/pequeno"), &Limites::default())
            .unwrap();
        assert_eq!(r.corpo, PEQUENO);
    }
}

#[test]
fn o_corpo_alem_do_limite_e_so_da_corrente() {
    let servidor = Nghttpd::novo("limite", &[]);
    let mut c = servidor.conectar();
    assert_eq!(
        c.trocar(&servidor.get("/grande"), &Limites::default()),
        Err(Erro::Limite(Limite::Corpo))
    );
    // A conexão continua: a corrente foi reiniciada, e só ela.
    let r = c
        .trocar(&servidor.get("/pequeno"), &Limites::default())
        .unwrap();
    assert_eq!(r.corpo, PEQUENO);
    // Com o limite que cabe, o grande passa inteiro.
    let limites = Limites {
        corpo: 4 * 1024 * 1024,
        ..Limites::default()
    };
    let r = c.trocar(&servidor.get("/grande"), &limites).unwrap();
    assert_eq!(r.corpo, padrao(3 * 1024 * 1024));
}

#[test]
fn o_eco_com_as_janelas_apertadas_do_servidor() {
    // A janela de cada corrente do servidor em 1023 bytes, e a da conexão
    // em 65 535: o corpo do pedido sai aos pedaços, cada um esperando o
    // servidor reabrir a janela.
    let servidor = Nghttpd::novo("eco", &["--echo-upload", "-w", "10", "-W", "16"]);
    let mut c = servidor.conectar();
    let corpo: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut p = Pedido::novo(Metodo::Post, servidor.url("/eco"));
    p.corpo = corpo.clone();
    let r = c.trocar(&p, &Limites::default()).unwrap();
    assert_eq!(r.status, 200);
    assert_eq!(r.corpo, corpo);
    // Duas ao mesmo tempo, recebidas fora de ordem.
    let a = c.enviar(&p, &Limites::default()).unwrap();
    let b = c
        .enviar(&servidor.get("/medio"), &Limites::default())
        .unwrap();
    assert_eq!(c.receber(b).unwrap().corpo, padrao(100 * 1024));
    assert_eq!(c.receber(a).unwrap().corpo, corpo);
}

#[test]
fn a_janela_pequena_deste_lado() {
    // Cada corrente parada segura 1 KiB: as outras continuam chegando.
    let servidor = Nghttpd::novo("janela", &[]);
    let mut c = servidor.conectar_com(AjustesH2 {
        janela: 1024,
        ..AjustesH2::default()
    });
    let correntes: Vec<_> = (0..8)
        .map(|_| {
            c.enviar(&servidor.get("/medio"), &Limites::default())
                .unwrap()
        })
        .collect();
    for corrente in correntes {
        assert_eq!(c.receber(corrente).unwrap().corpo, padrao(100 * 1024));
    }
}

#[test]
fn o_preenchimento_e_os_trailers_do_servidor() {
    let servidor = Nghttpd::novo("trailers", &["-b", "255", "--trailer", "x-duke: sim"]);
    let mut c = servidor.conectar();
    for caminho in ["/pequeno", "/medio"] {
        let r = c
            .trocar(&servidor.get(caminho), &Limites::default())
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(
            r.corpo.len(),
            if caminho == "/pequeno" {
                13
            } else {
                100 * 1024
            }
        );
        // Os *trailers* são conferidos e largados.
        assert_eq!(r.cabecalho("x-duke"), None);
    }
}

#[test]
fn head_sem_corpo() {
    let servidor = Nghttpd::novo("head", &[]);
    let mut c = servidor.conectar();
    let mut head = servidor.get("/medio");
    head.metodo = Metodo::Head;
    let r = c.trocar(&head, &Limites::default()).unwrap();
    assert_eq!(r.status, 200);
    assert!(r.corpo.is_empty());
    assert_eq!(r.enquadramento, Enquadramento::Nenhum);
    assert_eq!(r.codificacao, None);
    // A conexão segue para o próximo.
    let r = c
        .trocar(&servidor.get("/pequeno"), &Limites::default())
        .unwrap();
    assert_eq!(r.corpo, PEQUENO);
}

#[test]
fn o_servidor_que_aceita_poucas_correntes() {
    let servidor = Nghttpd::novo("poucas", &["-m", "2"]);
    let mut c = servidor.conectar();
    // A primeira troca traz os ajustes do servidor.
    c.trocar(&servidor.get("/pequeno"), &Limites::default())
        .unwrap();
    let a = c
        .enviar(&servidor.get("/medio"), &Limites::default())
        .unwrap();
    let b = c
        .enviar(&servidor.get("/medio"), &Limites::default())
        .unwrap();
    assert_eq!(
        c.enviar(&servidor.get("/medio"), &Limites::default()),
        Err(Erro::Limite(Limite::Correntes))
    );
    assert_eq!(c.receber(a).unwrap().corpo.len(), 100 * 1024);
    assert_eq!(c.receber(b).unwrap().corpo.len(), 100 * 1024);
    // Antes dos ajustes do servidor, este lado não sabe do limite: o que
    // passa dele o servidor recusa — e a recusa pode ir noutra conexão.
    let mut c = servidor.conectar();
    let correntes: Vec<_> = (0..4)
        .map(|_| {
            c.enviar(&servidor.get("/pequeno"), &Limites::default())
                .unwrap()
        })
        .collect();
    let resultados: Vec<_> = correntes.into_iter().map(|k| c.receber(k)).collect();
    let recusadas = resultados
        .iter()
        .filter(|r| matches!(r, Err(Erro::Recusada) | Err(Erro::Reiniciada(_))))
        .count();
    let entregues = resultados.iter().filter(|r| r.is_ok()).count();
    assert_eq!(recusadas + entregues, 4, "{resultados:?}");
    assert!(entregues >= 2, "{resultados:?}");
}

#[test]
fn o_servidor_que_nao_fala_http2() {
    // Um servidor HTTP/1.1 qualquer: responde ao prefácio com uma linha de
    // status.
    let ouvinte = TcpListener::bind("127.0.0.1:0").unwrap();
    let porta = ouvinte.local_addr().unwrap().port();
    let servidor = std::thread::spawn(move || {
        let (mut s, _) = ouvinte.accept().unwrap();
        let mut b = [0u8; 1024];
        let _ = s.read(&mut b);
        let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        // Lê tudo até o cliente fechar: um soquete fechado com bytes por
        // ler sai com RST, e o cliente poderia ver o reinício no lugar da
        // linha de status.
        while matches!(s.read(&mut b), Ok(n) if n > 0) {}
    });
    let tcp = TcpStream::connect(("127.0.0.1", porta)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut c = ClienteH2::novo(Tcp(tcp));
    let url = Url::ler(&format!("http://127.0.0.1:{porta}/")).unwrap();
    assert_eq!(
        c.trocar(&Pedido::novo(Metodo::Get, url), &Limites::default()),
        Err(Erro::Protocolo(http::Motivo::Prefacio))
    );
    drop(c);
    servidor.join().unwrap();
}

#[test]
fn o_adeus_deste_lado() {
    let servidor = Nghttpd::novo("adeus", &[]);
    let mut c = servidor.conectar();
    c.trocar(&servidor.get("/pequeno"), &Limites::default())
        .unwrap();
    c.fechar().unwrap();
    assert_eq!(
        c.enviar(&servidor.get("/pequeno"), &Limites::default()),
        Err(Erro::Esgotada)
    );
    // O servidor fecha a conexão depois do `GOAWAY`.
    let mut tcp = c.devolver().0;
    let mut b = [0u8; 64];
    let limite = Instant::now() + Duration::from_secs(10);
    loop {
        match tcp.read(&mut b) {
            Ok(0) => break,
            Ok(_) => assert!(Instant::now() < limite),
            Err(e) => panic!("{e:?}"),
        }
    }
}
