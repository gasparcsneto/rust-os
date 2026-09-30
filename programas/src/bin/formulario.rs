//! Um formulário feito com o toolkit: dois campos e dois botões.
//!
//! É o outro lado do caso da suíte que confere o toolkit dentro do Duke: a
//! janela com interface do runtime, o campo de texto, e o caminho de um
//! agente até ele — o `set_value`, que deixa o texto no kernel e avisa, e a
//! chamada `valor`, que o traz. A suíte age pela árvore e pelo teclado, e
//! confere pelo que o programa diz no log — `formulario: ...` — e pela
//! descrição que a janela publica.
//!
//! Sai com [`CODIGO`] quando a suíte pede o fim.
//!
//! A suíte também pode pedir, com um evento de teste — ver [`SONDAR`] —,
//! que o próximo texto seja lido primeiro num buffer pequeno demais: a
//! chamada `valor` recusa, e o texto continua na fila para a janela.

#![no_std]
#![no_main]

use programas::escreverln;
use programas::janela::{Gesto, Janela};
use programas::sistema::{self, erro};
use protocolo::usuario::evento::{BOTAO_ESQUERDO, Evento, acao, tipo};
use toolkit::{Botao, Campo, Coluna, Interface, Linha, Rotulo};

/// O código de saída quando tudo conferiu.
const CODIGO: i64 = 71;

/// O canal da entrada, e o que a suíte publica para pedir o fim.
const CANAL: &str = "teste-formulario";

/// Os códigos que o programa dá ao que se aciona.
const NOME: u32 = 1;
const SOBRENOME: u32 = 2;
const OK: u32 = 3;
const LIMPAR: u32 = 4;

/// A base dos identificadores desta janela na árvore.
const BASE: i64 = 1000;

/// O `a` do evento de teste com que a suíte arma a sonda. Os outros eventos
/// de teste — os que ela usa para encher o canal — têm `a` zero.
const SONDAR: i64 = 1;

fn valores(janela: &Janela) -> (&str, &str) {
    // Os campos são o segundo e o terceiro filhos da coluna, e o toolkit os
    // acha pelo índice na árvore: 2 e 3.
    let mut nome = "";
    let mut sobrenome = "";
    if let Some(ui) = janela.interface() {
        toolkit::arvore::percorrer(ui.raiz(), Default::default(), &mut |i, w, _| {
            if let Some(s) = w.semantica() {
                match i {
                    2 => nome = s.valor,
                    3 => sobrenome = s.valor,
                    _ => {}
                }
            }
        });
    }
    (nome, sobrenome)
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let canal = sistema::escutar(CANAL);
    if canal < 0 {
        return 1;
    }
    let canal = canal as u64;

    let interface = Interface::nova(
        Coluna::nova()
            .recuo(10)
            .espaco(8)
            .fundo(aparencia::uso::FUNDO_DO_CONTEUDO.argb())
            .com(Rotulo::novo("instrucao", "Quem é você?"))
            .com(Campo::novo("nome", 20, NOME))
            .com(Campo::novo("sobrenome", 20, SOBRENOME))
            .com(
                Linha::nova()
                    .espaco(6)
                    .com(Botao::novo("OK", OK))
                    .com(Botao::novo("Limpar", LIMPAR)),
            ),
    );
    let mut janela = match Janela::com_interface("Formulário", interface, BASE, 60, 80) {
        Ok(j) => j,
        Err(e) => {
            escreverln!("formulario: sem janela: {}", e);
            return 2;
        }
    };

    // A chamada `valor` recusa o que não é superfície, e diz quando não há
    // texto esperando.
    let mut bytes = [0u8; 8];
    if sistema::valor(canal, &mut bytes) != erro::DESCRITOR_INVALIDO {
        return 3;
    }
    if sistema::valor(janela.descritor(), &mut bytes) != erro::NAO_ENCONTRADO {
        return 4;
    }

    if janela.superficie().entrada(canal).is_err()
        || janela.mostrar().is_err()
        || janela.superficie().focar().is_err()
    {
        return 5;
    }
    janela.focar(true);
    escreverln!("formulario: pronto");

    let mut botoes = 0;
    let mut sondar = false;
    let mut eventos = [Evento::default(); 16];
    loop {
        let n = match sistema::ler_eventos(canal, &mut eventos) {
            Ok(n) => n,
            Err(_) => return 6,
        };
        for e in &eventos[..n] {
            let gesto = match e.tipo {
                tipo::PONTEIRO => {
                    let apertou = e.c & BOTAO_ESQUERDO != 0 && botoes & BOTAO_ESQUERDO == 0;
                    botoes = e.c;
                    if apertou {
                        janela.apertar_em(e.a, e.b)
                    } else {
                        Gesto::Nada
                    }
                }
                tipo::TECLA => match u32::try_from(e.a).ok().and_then(char::from_u32) {
                    Some(c) => janela.tecla(c),
                    None => Gesto::Nada,
                },
                tipo::TESTE => {
                    sondar |= e.a == SONDAR;
                    Gesto::Nada
                }
                tipo::ACAO => {
                    if sondar && e.b == acao::DEFINIR_VALOR {
                        sondar = false;
                        let mut um = [0u8; 1];
                        let r = sistema::valor(janela.descritor(), &mut um);
                        escreverln!("formulario: sonda {}", r);
                    }
                    janela.acao(e.a, e.b).unwrap_or(Gesto::Nada)
                }
                tipo::ENCERRAR => {
                    escreverln!("formulario: encerrado");
                    return CODIGO;
                }
                _ => Gesto::Nada,
            };
            let (nome, sobrenome) = valores(&janela);
            let _ = match gesto {
                Gesto::Acionado(c) => {
                    escreverln!("formulario: acionado {} [{}] [{}]", c, nome, sobrenome)
                }
                Gesto::Redesenhada => {
                    escreverln!("formulario: agora [{}] [{}]", nome, sobrenome)
                }
                Gesto::Fechar => escreverln!("formulario: fechar"),
                _ => 0,
            };
        }
    }
}
