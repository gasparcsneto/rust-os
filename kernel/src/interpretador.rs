//! O interpretador: operar o Duke digitando.
//!
//! # Por que ele não tem comandos próprios
//!
//! Porque já existe uma lista de comandos, e ela é a mesma que o canal do
//! agente publica em `agent.describe`. Um interpretador com o seu próprio
//! conjunto seria uma segunda superfície para manter — e as duas divergiriam
//! na primeira que alguém esquecesse de atualizar, com o sintoma de uma
//! pessoa e um agente vendo máquinas diferentes.
//!
//! Aqui o que se digita é despachado pelo **mesmo** registro, com os mesmos
//! handlers. O que muda é só a renderização: o agente lê uma linha de JSON
//! compacto, e uma pessoa lê o mesmo JSON quebrado em linhas. É a mesma ideia
//! que o log estruturado defende desde o começo — o texto legível é uma
//! renderização, e não a fonte da verdade.
//!
//! # Onde a saída aparece
//!
//! No console humano, que é a tela nas duas arquiteturas e também a COM1 no
//! x86. Não no canal do agente: as duas conversas são independentes, e
//! misturá-las quebraria o enquadramento de quem está do outro lado.

// Em `modo-teste` o laço do agente é trocado pelo executor da suíte, e o
// interpretador — que é uma tarefa desse laço — não é lançado. O que sobra do
// módulo é [`separar`], que a suíte exercita; o resto não existe nessa
// compilação, em vez de existir sem chamador.
#[cfg(not(feature = "modo-teste"))]
use core::fmt;

#[cfg(not(feature = "modo-teste"))]
use crate::agent::json::{Json, JsonWriter};
#[cfg(not(feature = "modo-teste"))]
use crate::agent::registry;

/// O maior comando que se pode digitar.
///
/// Não há heap no caminho de uma tecla, então a linha é um buffer fixo. Cento
/// e vinte caracteres cobrem o maior comando com parâmetros que este kernel
/// tem; o que passar disso é recusado com aviso, e não truncado em silêncio.
#[cfg(not(feature = "modo-teste"))]
const LINHA_MAX: usize = 120;

/// O que aparece antes do que se digita.
#[cfg(not(feature = "modo-teste"))]
const PROMPT: &str = "duke> ";

/// Lê o teclado e executa o que for digitado. Nunca retorna.
///
/// É uma tarefa do executor cooperativo, ao lado do canal do agente. Entre uma
/// tecla e outra ela devolve `Pending`, e o núcleo dorme: uma pessoa digitando
/// é a coisa mais lenta que este kernel espera, e girar à toa por causa dela
/// seria gastar todo o núcleo com o que não chega.
#[cfg(not(feature = "modo-teste"))]
pub async fn atender() {
    crate::serial_println!();
    crate::serial_print!("{PROMPT}");

    let mut linha = [0u8; LINHA_MAX];
    let mut tam = 0usize;

    loop {
        let c = crate::teclado::proxima_tecla().await;

        match c {
            '\n' => {
                crate::serial_println!();
                // `from_utf8` não falha: só entram aqui bytes ASCII
                // imprimíveis, filtrados abaixo. O `unwrap_or` existe para
                // que um dia em que isso mude vire uma linha vazia, e não um
                // pânico dentro do interpretador.
                executar(core::str::from_utf8(&linha[..tam]).unwrap_or(""));
                tam = 0;
                crate::serial_print!("{PROMPT}");
            }

            // O apagar precisa apagar na tela também, e não só no buffer.
            // Uma tela que mostra o que foi apagado é pior que nenhuma: ela
            // afirma algo falso sobre o que será executado.
            '\u{8}' => {
                if tam > 0 {
                    tam -= 1;
                    crate::serial_print!("\u{8}");
                }
            }

            // Só o que é texto entra na linha. Teclas sem caractere já não
            // chegam aqui, mas o controle que sobra — um tab, por exemplo —
            // desalinharia a conta entre o que está no buffer e o que está
            // desenhado.
            c if c.is_ascii_graphic() || c == ' ' => {
                if tam < LINHA_MAX {
                    linha[tam] = c as u8;
                    tam += 1;
                    crate::serial_print!("{c}");
                } else {
                    crate::serial_println!();
                    crate::serial_println!("linha longa demais; ate {} caracteres", LINHA_MAX);
                    tam = 0;
                    crate::serial_print!("{PROMPT}");
                }
            }

            _ => {}
        }
    }
}

/// Separa o nome do comando dos parâmetros.
///
/// O nome vai até o primeiro espaço; o resto são os parâmetros, em JSON. É a
/// mesma separação que o `cargo xtask agent` faz, para que quem aprendeu um
/// saiba o outro.
///
/// Fica numa função sua, e não no meio de [`executar`], porque é a única
/// lógica deste módulo que não depende de hardware — e portanto a única que a
/// suíte alcança. Ter a de verdade aqui é o que impede o caso de teste de
/// exercitar uma cópia enquanto o interpretador usa outra.
///
/// Parâmetros ausentes viram `{}`, e não string vazia: um `Json` sobre bytes
/// vazios não é um objeto, e todo handler que consulta um campo opcional veria
/// ausência onde deveria ver um objeto sem campos.
pub fn separar(linha: &str) -> (&str, &str) {
    let linha = linha.trim();
    match linha.find(' ') {
        Some(i) => {
            let resto = linha[i + 1..].trim();
            (&linha[..i], if resto.is_empty() { "{}" } else { resto })
        }
        None => (linha, "{}"),
    }
}

/// Executa uma linha digitada.
#[cfg(not(feature = "modo-teste"))]
fn executar(linha: &str) {
    let linha = linha.trim();
    if linha.is_empty() {
        return;
    }

    let (nome, params) = separar(linha);

    match nome {
        "ajuda" => ajuda(),
        _ => despachar(nome, params),
    }
}

/// Manda o comando ao registro do agente e desenha a resposta.
#[cfg(not(feature = "modo-teste"))]
fn despachar(nome: &str, params: &str) {
    let Some(comando) = registry::encontrar(nome) else {
        crate::serial_println!("comando desconhecido: {}", nome);
        crate::serial_println!("`ajuda` lista os {} que existem", registry::todos().len());
        return;
    };

    // No log, e não só na tela, porque é o que torna o interpretador
    // observável de fora: o canal do agente lê `log.tail` e vê o que foi
    // digitado na máquina. É também o que permite a uma sonda conferir que a
    // tecla virou comando, sem precisar enxergar a tela.
    crate::log_info!("console", "executado: {}", nome);

    let mut saida = SaidaHumana::nova();
    let mut escritor = JsonWriter::new(&mut saida);
    if (comando.handler)(Json(params.as_bytes()), &mut escritor).is_err() {
        crate::serial_println!("a resposta nao coube");
    }
    crate::serial_println!();
}

/// Lista os comandos que existem.
///
/// Sai do mesmo registro que `agent.describe` publica. Uma lista escrita à
/// mão aqui seria a segunda superfície que este módulo existe para não ter.
#[cfg(not(feature = "modo-teste"))]
fn ajuda() {
    crate::log_info!("console", "executado: ajuda");
    for comando in registry::todos() {
        crate::serial_println!("  {:<18} {}", comando.nome, comando.resumo);
    }
    crate::serial_println!("  {:<18} {}", "ajuda", "Esta lista.");
}

/// Desenha JSON de um jeito que uma pessoa consiga ler.
///
/// # Por que reformatar, e não interpretar
///
/// Porque interpretar exigiria um segundo leitor de JSON — e um leitor que
/// discordasse do escritor produziria uma tela que não corresponde ao que o
/// agente recebe. Isto aqui não entende nada: conta chaves, respeita strings,
/// e quebra linha onde a leitura pede. O conteúdo é byte a byte o que sai no
/// canal.
#[cfg(not(feature = "modo-teste"))]
struct SaidaHumana {
    profundidade: u32,
    dentro_de_string: bool,
    escapado: bool,
}

#[cfg(not(feature = "modo-teste"))]
impl SaidaHumana {
    fn nova() -> SaidaHumana {
        SaidaHumana {
            profundidade: 0,
            dentro_de_string: false,
            escapado: false,
        }
    }

    fn quebrar(&self) {
        crate::serial_println!();
        for _ in 0..self.profundidade {
            crate::serial_print!("  ");
        }
    }

    fn caractere(&mut self, c: char) {
        // Dentro de uma string, nada é pontuação: uma chave entre aspas não
        // abre nível nenhum. Sem esta distinção, um valor que contivesse `{`
        // desalinharia a indentação de tudo que viesse depois.
        if self.dentro_de_string {
            crate::serial_print!("{c}");
            if self.escapado {
                self.escapado = false;
            } else if c == '\\' {
                self.escapado = true;
            } else if c == '"' {
                self.dentro_de_string = false;
            }
            return;
        }

        match c {
            '"' => {
                self.dentro_de_string = true;
                crate::serial_print!("{c}");
            }
            '{' | '[' => {
                crate::serial_print!("{c}");
                self.profundidade += 1;
                self.quebrar();
            }
            '}' | ']' => {
                self.profundidade = self.profundidade.saturating_sub(1);
                self.quebrar();
                crate::serial_print!("{c}");
            }
            ',' => {
                crate::serial_print!("{c}");
                self.quebrar();
            }
            ':' => crate::serial_print!("{c} "),
            _ => crate::serial_print!("{c}"),
        }
    }
}

#[cfg(not(feature = "modo-teste"))]
impl fmt::Write for SaidaHumana {
    fn write_str(&mut self, pedaco: &str) -> fmt::Result {
        for c in pedaco.chars() {
            self.caractere(c);
        }
        Ok(())
    }
}
