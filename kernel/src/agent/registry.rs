//! Registro de comandos auto-descritivo.
//!
//! # A ideia central
//!
//! Um agente que precisa *adivinhar* o que o sistema aceita é um agente que
//! erra. Por isso cada comando aqui carrega, junto com a implementação, a
//! descrição formal dos seus parâmetros. Essa descrição não é documentação
//! solta num README que envelhece — é a mesma estrutura de dados que o
//! despachante usa para validar as chamadas.
//!
//! Isso dá duas garantias que valem muito na prática:
//!
//! 1. **A documentação não pode divergir do código**, porque é o código.
//! 2. **O agente pode descobrir a superfície inteira em tempo de execução**,
//!    via `agent.describe`, do mesmo jeito que um cliente MCP lista as
//!    ferramentas de um servidor antes de usá-las.
//!
//! O resultado é que adicionar um comando ao kernel automaticamente o torna
//! visível e utilizável pelo agente, sem nenhum passo extra.

use core::fmt;

use super::json::{Json, JsonWriter};

/// Tipo aceito por um parâmetro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TipoParam {
    Inteiro,
    Texto,
    Booleano,
    /// Uma lista JSON — as operações de um lote.
    Lista,
    /// Um texto numa forma fechada — ver [`Formato`]. Para o protocolo, um
    /// `string`; a forma vai na descrição do parâmetro.
    Formatado(Formato),
}

impl TipoParam {
    /// Nome exposto no protocolo.
    pub const fn nome(self) -> &'static str {
        match self {
            TipoParam::Inteiro => "integer",
            TipoParam::Texto | TipoParam::Formatado(_) => "string",
            TipoParam::Booleano => "boolean",
            TipoParam::Lista => "array",
        }
    }
}

/// A forma fechada de um texto que vai, como veio, para a auditoria — o que
/// um programa declara (`audit.declare`). Conferida aqui, antes do gate,
/// como o tipo: fora da forma, o pedido é `INVALID_ARGUMENT`, e nada chega
/// à decisão.
///
/// Toda forma é ASCII imprimível, sem espaço, sem aspas, sem barra
/// invertida e sem `;`: o texto do pedido é o texto gravado — não há
/// escape a resolver, porque `Json::as_str` devolve os bytes crus —, as
/// partes se separam por espaço sem ambiguidade, e nenhuma se confunde com
/// o separador dos recursos de um registro (` ; `).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Formato {
    /// Um nome de evento, `<espaco>.<nome>[.<nome>…]`: partes de
    /// minúsculas, dígitos e `_`, cada uma começando por letra, até
    /// [`MAIOR_EVENTO`] bytes. O espaço não é o de um comando do registro:
    /// uma declaração não se passa por um comando.
    Evento,
    /// Uma palavra: minúsculas, dígitos e `_`, começando por letra, até
    /// [`MAIOR_PALAVRA`] bytes.
    Palavra,
    /// Um símbolo: ASCII imprimível sem espaço, aspas, barra invertida nem
    /// `;`, de 1 a [`MAIOR_SIMBOLO`] bytes.
    Simbolo,
    /// Uma intenção da malha, `<espaço>.<nome>[.<nome>…]`: partes de
    /// minúsculas, dígitos e `_`, cada uma começando por letra, até
    /// [`politica::malha::MAIOR_INTENCAO`] bytes, sem curinga — a mesma
    /// forma que a política enumera. Ver [`crate::malha`].
    Intencao,
}

/// O maior nome de evento.
pub const MAIOR_EVENTO: usize = 32;
/// A maior palavra.
pub const MAIOR_PALAVRA: usize = 24;
/// O maior símbolo.
pub const MAIOR_SIMBOLO: usize = 64;

/// Minúsculas, dígitos e `_`, começando por letra.
fn palavra(texto: &str) -> bool {
    let b = texto.as_bytes();
    b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

impl Formato {
    /// Se `texto` está na forma.
    pub fn confere(self, texto: &str) -> bool {
        match self {
            Formato::Evento => {
                let mut partes = texto.split('.');
                let espaco = partes.next().unwrap_or("");
                texto.len() <= MAIOR_EVENTO
                    && texto.contains('.')
                    && palavra(espaco)
                    && partes.all(palavra)
                    && !todos()
                        .iter()
                        .any(|c| c.nome.split('.').next() == Some(espaco))
            }
            Formato::Palavra => texto.len() <= MAIOR_PALAVRA && palavra(texto),
            Formato::Simbolo => {
                (1..=MAIOR_SIMBOLO).contains(&texto.len())
                    && texto
                        .bytes()
                        .all(|c| c.is_ascii_graphic() && !matches!(c, b'"' | b'\\' | b';'))
            }
            Formato::Intencao => politica::malha::intencao_valida(texto),
        }
    }
}

/// A descrição formal de um parâmetro.
pub struct ParamSpec {
    pub nome: &'static str,
    pub tipo: TipoParam,
    pub obrigatorio: bool,
    pub descricao: &'static str,
}

/// Assinatura de um handler de comando.
///
/// Recebe os parâmetros já validados e escreve **apenas o valor de `result`**
/// — o envelope JSON-RPC ao redor é responsabilidade do despachante.
///
/// Note que é um ponteiro de função comum, não uma closure em caixa: a tabela
/// de comandos é `static` e o kernel ainda não tem heap, então não há como
/// alocar um `Box<dyn Fn>`.
///
/// Handlers são **infalíveis** por design. A validação de parâmetros acontece
/// antes, em [`validar`], o que evita o problema de um handler falhar *depois*
/// de já termos escrito `"result":` no stream e não haver como voltar atrás
/// para emitir um erro — a escrita é em streaming e não tem desfazer.
pub type Handler = fn(Json<'_>, &mut JsonWriter<'_>) -> fmt::Result;

/// O que um comando exige de quem pede.
///
/// Todo comando declara o seu, e não há valor padrão: um comando novo sem
/// esta linha não compila. É a primeira metade da cadeia
/// `identidade → sessão → papel → permissão → operação` — a operação diz a
/// permissão; a política, quem a tem; e [`crate::autorizacao`] decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acesso {
    /// A permissão que o papel de quem pede precisa ter.
    Exige(politica::Permissao),
    /// Nenhuma permissão de sessão: a autenticação é a prova do
    /// administrador, conferida dentro da própria operação — ver
    /// [`super::administracao`]. Só `admin.challenge` e `admin.execute`.
    PorProva,
}

/// Que orçamento a decisão de um comando consome.
///
/// Todo comando declara o seu, como declara o [`Acesso`]: não há padrão, e
/// um comando novo sem esta linha não compila.
///
/// # Exercício de autoridade, e operação sobre o que já foi autorizado
///
/// Abrir uma conexão, associar um destino, abrir um arquivo, lançar um
/// processo, mandar uma mensagem, administrar: cada um é um **exercício de
/// autoridade** — o papel de quem pede decide, e a taxa do papel limita
/// quantos por segundo ([`Plano::Controle`]).
///
/// Usar um recurso que um exercício desses já abriu — mandar e ler pela
/// conexão aberta, fechá-la — é outra coisa: a operação do **plano de
/// dados** sobre um recurso já autorizado. Ela continua uma decisão do
/// mesmo gate, com a mesma identidade, a mesma autoridade, a mesma
/// política, a contenção, o firewall e o registro na auditoria; o que muda
/// é o orçamento. O recurso já pagou a ficha do papel ao abrir; o que
/// limita a operação sobre ele é a capacidade — a do recurso, a
/// contrapressão dele, e a do caminho da auditoria (ver
/// [`crate::oleoduto`]).
///
/// O plano não dá nada a ninguém: um comando de [`Plano::Dados`] ou
/// [`Plano::Fecho`] só sai do orçamento do papel quando o gate resolve o
/// recurso para **quem pede** — vivo, dele, com quem pede não contido — e
/// autoriza o pedido. Sem isso, o pedido segue o caminho de qualquer
/// exercício de autoridade, e paga a ficha.
///
/// O recurso é nomeado pelo número que a abertura devolveu, no parâmetro
/// que o comando declara em `recurso`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plano {
    /// Exercício de autoridade: a taxa do papel.
    Controle,
    /// Mover dados por um recurso já aberto e autorizado: a capacidade do
    /// recurso e a da auditoria, com contrapressão.
    Dados,
    /// Fechar um recurso já aberto: devolve capacidade, e nunca espera
    /// orçamento — a taxa gasta não prende o recurso aberto.
    Fecho,
}

impl Plano {
    /// O nome, como `agent.describe` e `security.metrics` o escrevem.
    pub const fn nome(self) -> &'static str {
        match self {
            Plano::Controle => "control",
            Plano::Dados => "data",
            Plano::Fecho => "release",
        }
    }
}

/// Um comando exposto ao agente.
pub struct Command {
    pub nome: &'static str,
    pub resumo: &'static str,
    pub params: &'static [ParamSpec],
    /// A permissão que o comando exige.
    pub acesso: Acesso,
    /// O parâmetro que nomeia o recurso, quando há um: o caminho, o setor, o
    /// elemento. Vai para a auditoria, e é o que a política limita nas
    /// permissões de caminho.
    pub recurso: Option<&'static str>,
    /// Os outros caminhos que o comando muda, além do de `recurso` — ver
    /// [`Mais`]. O gate decide **cada um**, pela mesma permissão, e o
    /// handler só muda o que o gate decidiu.
    pub mais: Mais,
    /// O orçamento que a decisão consome — ver [`Plano`].
    pub plano: Plano,
    pub handler: Handler,
}

/// Os recursos de um comando além do primeiro.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mais {
    /// Nenhum: só o de `recurso`.
    Nada,
    /// O valor de mais um parâmetro — o destino de um `fs.rename`.
    Parametro(&'static str),
    /// Os caminhos de uma lista de operações — o `ops` de um `fs.batch`:
    /// em cada uma, os campos `path` e `to`.
    Lote(&'static str),
}

/// Todos os comandos, na ordem em que foram declarados.
///
/// Existe para quem precisa **listar**, e não procurar: `agent.describe`, que
/// publica a superfície para um agente, e o interpretador, que a lista para
/// uma pessoa. Os dois saem daqui pela mesma razão — uma segunda lista seria
/// a que esquece de ser atualizada.
pub fn todos() -> &'static [Command] {
    super::commands::COMANDOS
}

/// Procura um comando pelo nome.
///
/// Busca linear: com algumas dezenas de comandos, uma tabela hash custaria
/// mais em complexidade do que economizaria em ciclos.
pub fn encontrar(nome: &str) -> Option<&'static Command> {
    super::commands::COMANDOS.iter().find(|c| c.nome == nome)
}

/// Valida os parâmetros recebidos contra a especificação do comando.
///
/// Devolve o nome do parâmetro problemático em caso de erro, para que a
/// resposta diga ao agente *exatamente* o que corrigir em vez de um genérico
/// "parâmetros inválidos".
pub fn validar<'a>(cmd: &Command, params: Json<'a>) -> Result<(), &'a str> {
    // Um campo que o comando não conhece é recusado, e não ignorado.
    //
    // Ignorar parecia tolerância e era o contrário. Medido contra um kernel de
    // pé: `user.run {"name":"nao_existe"}` respondia `{"launched":true}` —
    // `user.run` não declara parâmetro nenhum, o `name` foi jogado fora, e o
    // agente recebeu sucesso por um pedido que o kernel não honrou.
    //
    // Num sistema em que o cliente **descobre** a interface em tempo de
    // execução, e portanto às vezes chuta, recusar é a única resposta útil:
    // `agent.describe` diz exatamente quais campos existem, e um erro manda o
    // agente lê-lo em vez de acreditar num sucesso que não houve.
    let mut desconhecido: Option<&'a str> = None;
    params.para_cada_chave(|chave| {
        if desconhecido.is_none() && !cmd.params.iter().any(|p| p.nome == chave) {
            desconhecido = Some(chave);
        }
    });
    if let Some(chave) = desconhecido {
        return Err(chave);
    }

    for spec in cmd.params {
        match params.member(spec.nome) {
            None => {
                if spec.obrigatorio {
                    return Err(spec.nome);
                }
            }
            Some(valor) => {
                let tipo_confere = match spec.tipo {
                    TipoParam::Inteiro => valor.as_u64().is_some(),
                    TipoParam::Texto => valor.as_str().is_some(),
                    TipoParam::Formatado(f) => valor.as_str().is_some_and(|t| f.confere(t)),
                    TipoParam::Booleano => valor.as_bool().is_some(),
                    TipoParam::Lista => valor.0.first() == Some(&b'['),
                };
                if !tipo_confere {
                    return Err(spec.nome);
                }
            }
        }
    }
    Ok(())
}
