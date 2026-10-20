//! A árvore de hash de um certificado: a leitura, a raiz e a procura —
//! **especificação**, *Certification*, *Lookup* e *Encoding of
//! certificates*.
//!
//! A forma em CBOR: `[0]` vazia, `[1, esq, dir]` bifurcação, `[2, rótulo,
//! sub]` rotulada, `[3, valor]` folha, `[4, hash]` podada. A raiz é
//! reconstruída com SHA-256 e os separadores de domínio
//! `ic-hashtree-empty`, `-fork`, `-labeled` e `-leaf`; um galho podado já
//! é o hash dele. A procura segue o algoritmo da especificação ao pé da
//! letra: um caminho é achado, ausente, desconhecido (podado) ou um erro.
//!
//! O IC só produz árvores bem formadas (**especificação**: os rótulos de
//! uma floresta em ordem estritamente crescente, sem folha misturada), e
//! a procura só faz sentido nelas. Este lado confere a forma antes de
//! procurar qualquer coisa: uma árvore mal formada é recusada inteira.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest, Sha256};

use super::cbor::Valor;
use super::resumo::Hash;

/// Uma árvore de hash, emprestando os bytes do certificado.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arvore<'a> {
    /// `[0]`.
    Vazia,
    /// `[1, esquerda, direita]`.
    Bifurcacao(Box<Arvore<'a>>, Box<Arvore<'a>>),
    /// `[2, rótulo, subárvore]`.
    Rotulada(&'a [u8], Box<Arvore<'a>>),
    /// `[3, valor]`.
    Folha(&'a [u8]),
    /// `[4, hash]`: um galho podado, de 32 bytes.
    Podada(&'a [u8]),
}

/// Por que uma árvore não se lê.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// Um nó que não é nenhuma das cinco formas.
    Forma,
    /// Um galho podado sem os 32 bytes de um hash.
    HashPodado,
    /// Rótulos fora de ordem, repetidos, ou uma folha numa floresta.
    MalFormada,
}

impl fmt::Display for Erro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Erro::Forma => "no da arvore de hash fora da forma",
            Erro::HashPodado => "galho podado sem 32 bytes",
            Erro::MalFormada => "arvore de hash mal formada",
        })
    }
}

/// O resultado de procurar um caminho.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Procura<'a> {
    /// O caminho tem este valor.
    Achou(&'a [u8]),
    /// O caminho não está na árvore.
    Ausente,
    /// Não dá para saber: o caminho pode estar num galho podado.
    Desconhecida,
    /// O caminho está na árvore, mas não termina num valor.
    Erro,
}

/// O resultado de procurar uma subárvore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sub<'t, 'a> {
    /// A subárvore sob o caminho.
    Achou(&'t Arvore<'a>),
    /// O caminho não está na árvore.
    Ausente,
    /// Não dá para saber: o caminho pode estar num galho podado.
    Desconhecida,
}

fn separador(h: &mut Sha256, nome: &[u8]) {
    h.update([nome.len() as u8]);
    h.update(nome);
}

impl<'a> Arvore<'a> {
    /// A árvore de um item CBOR, já conferida como bem formada.
    pub fn de_cbor(v: Valor<'a>) -> Result<Arvore<'a>, Erro> {
        let arvore = Arvore::converter(v)?;
        if !arvore.bem_formada() {
            return Err(Erro::MalFormada);
        }
        Ok(arvore)
    }

    fn converter(v: Valor<'a>) -> Result<Arvore<'a>, Erro> {
        let Valor::Lista(itens) = v else {
            return Err(Erro::Forma);
        };
        let mut itens = itens.into_iter();
        let forma = itens.next().and_then(|t| t.nat()).ok_or(Erro::Forma)?;
        let arvore = match (forma, itens.len()) {
            (0, 0) => Arvore::Vazia,
            (1, 2) => {
                let esquerda = Arvore::converter(itens.next().ok_or(Erro::Forma)?)?;
                let direita = Arvore::converter(itens.next().ok_or(Erro::Forma)?)?;
                Arvore::Bifurcacao(Box::new(esquerda), Box::new(direita))
            }
            (2, 2) => {
                let rotulo = itens.next().and_then(|r| r.bytes()).ok_or(Erro::Forma)?;
                let sub = Arvore::converter(itens.next().ok_or(Erro::Forma)?)?;
                Arvore::Rotulada(rotulo, Box::new(sub))
            }
            (3, 1) => Arvore::Folha(itens.next().and_then(|v| v.bytes()).ok_or(Erro::Forma)?),
            (4, 1) => {
                let hash = itens.next().and_then(|h| h.bytes()).ok_or(Erro::Forma)?;
                if hash.len() != 32 {
                    return Err(Erro::HashPodado);
                }
                Arvore::Podada(hash)
            }
            _ => return Err(Erro::Forma),
        };
        Ok(arvore)
    }

    /// A raiz reconstruída — **especificação**, `reconstruct`.
    pub fn raiz(&self) -> Hash {
        match self {
            Arvore::Podada(h) => {
                let mut raiz = [0u8; 32];
                raiz.copy_from_slice(h);
                raiz
            }
            Arvore::Vazia => {
                let mut h = Sha256::new();
                separador(&mut h, b"ic-hashtree-empty");
                h.finalize().into()
            }
            Arvore::Bifurcacao(esquerda, direita) => {
                let mut h = Sha256::new();
                separador(&mut h, b"ic-hashtree-fork");
                h.update(esquerda.raiz());
                h.update(direita.raiz());
                h.finalize().into()
            }
            Arvore::Rotulada(rotulo, sub) => {
                let mut h = Sha256::new();
                separador(&mut h, b"ic-hashtree-labeled");
                h.update(rotulo);
                h.update(sub.raiz());
                h.finalize().into()
            }
            Arvore::Folha(valor) => {
                let mut h = Sha256::new();
                separador(&mut h, b"ic-hashtree-leaf");
                h.update(valor);
                h.finalize().into()
            }
        }
    }

    /// As árvores sob as bifurcações, da esquerda para a direita —
    /// **especificação**, `flatten_forks`. A vazia some.
    pub fn floresta(&self) -> Vec<&Arvore<'a>> {
        let mut saida = Vec::new();
        self.achatar(&mut saida);
        saida
    }

    fn achatar<'t>(&'t self, saida: &mut Vec<&'t Arvore<'a>>) {
        match self {
            Arvore::Vazia => {}
            Arvore::Bifurcacao(esquerda, direita) => {
                esquerda.achatar(saida);
                direita.achatar(saida);
            }
            outra => saida.push(outra),
        }
    }

    /// **Especificação**, `well_formed`.
    pub fn bem_formada(&self) -> bool {
        if let Arvore::Folha(_) = self {
            return true;
        }
        let mut anterior: Option<&[u8]> = None;
        for arvore in self.floresta() {
            match arvore {
                Arvore::Folha(_) => return false,
                Arvore::Rotulada(rotulo, sub) => {
                    if anterior.is_some_and(|a| a >= *rotulo) {
                        return false;
                    }
                    anterior = Some(rotulo);
                    if !sub.bem_formada() {
                        return false;
                    }
                }
                _ => {}
            }
        }
        true
    }

    /// Procura o valor de um caminho — **especificação**, `lookup_path`.
    pub fn procurar(&self, caminho: &[&[u8]]) -> Procura<'a> {
        let Some((rotulo, resto)) = caminho.split_first() else {
            return match self {
                Arvore::Vazia => Procura::Ausente,
                Arvore::Folha(v) => Procura::Achou(v),
                Arvore::Podada(_) => Procura::Desconhecida,
                Arvore::Rotulada(..) | Arvore::Bifurcacao(..) => Procura::Erro,
            };
        };
        match achar(rotulo, &self.floresta()) {
            Sub::Achou(sub) => sub.procurar(resto),
            Sub::Ausente => Procura::Ausente,
            Sub::Desconhecida => Procura::Desconhecida,
        }
    }

    /// Procura a subárvore sob um caminho.
    pub fn subarvore<'t>(&'t self, caminho: &[&[u8]]) -> Sub<'t, 'a> {
        let mut atual = self;
        for rotulo in caminho {
            match achar(rotulo, &atual.floresta()) {
                Sub::Achou(sub) => atual = sub,
                outro => return outro,
            }
        }
        Sub::Achou(atual)
    }
}

/// **Especificação**, `find_label`: numa floresta bem formada, o rótulo
/// achado, ou ausente quando os vizinhos provam que ele não está, ou
/// desconhecido quando um galho podado pode escondê-lo.
fn achar<'t, 'a>(rotulo: &[u8], floresta: &[&'t Arvore<'a>]) -> Sub<'t, 'a> {
    if floresta.is_empty() || matches!(floresta, [Arvore::Folha(_)]) {
        return Sub::Ausente;
    }
    for arvore in floresta {
        if let Arvore::Rotulada(r, sub) = arvore
            && *r == rotulo
        {
            return Sub::Achou(sub);
        }
    }
    fn rotulo_de<'a>(a: &Arvore<'a>) -> Option<&'a [u8]> {
        match a {
            Arvore::Rotulada(r, _) => Some(r),
            _ => None,
        }
    }
    // Antes do primeiro rótulo, que vem primeiro na floresta.
    if rotulo_de(floresta[0]).is_some_and(|primeiro| rotulo < primeiro) {
        return Sub::Ausente;
    }
    // Depois do último, que vem por último.
    if rotulo_de(floresta[floresta.len() - 1]).is_some_and(|ultimo| ultimo < rotulo) {
        return Sub::Ausente;
    }
    // Entre dois rótulos vizinhos, sem galho podado no meio.
    for par in floresta.windows(2) {
        if let (Some(antes), Some(depois)) = (rotulo_de(par[0]), rotulo_de(par[1]))
            && antes < rotulo
            && rotulo < depois
        {
            return Sub::Ausente;
        }
    }
    Sub::Desconhecida
}

#[cfg(test)]
mod testes;
