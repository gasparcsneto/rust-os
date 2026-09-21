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
}

impl TipoParam {
    /// Nome exposto no protocolo.
    pub const fn nome(self) -> &'static str {
        match self {
            TipoParam::Inteiro => "integer",
            TipoParam::Texto => "string",
            TipoParam::Booleano => "boolean",
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

/// Um comando exposto ao agente.
pub struct Command {
    pub nome: &'static str,
    pub resumo: &'static str,
    pub params: &'static [ParamSpec],
    pub handler: Handler,
}

/// Procura um comando pelo nome.
///
/// Busca linear: com uma dezena de comandos, uma tabela hash custaria mais em
/// complexidade do que economizaria em ciclos.
pub fn encontrar(nome: &str) -> Option<&'static Command> {
    super::commands::COMANDOS.iter().find(|c| c.nome == nome)
}

/// Valida os parâmetros recebidos contra a especificação do comando.
///
/// Devolve o nome do parâmetro problemático em caso de erro, para que a
/// resposta diga ao agente *exatamente* o que corrigir em vez de um genérico
/// "parâmetros inválidos".
pub fn validar(cmd: &Command, params: Json) -> Result<(), &'static str> {
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
                    TipoParam::Booleano => valor.as_bool().is_some(),
                };
                if !tipo_confere {
                    return Err(spec.nome);
                }
            }
        }
    }
    Ok(())
}
