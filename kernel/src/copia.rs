//! A cópia de segurança do armazém, e a restauração dela: `fs.backup` e
//! `fs.restore`.
//!
//! # O que se copia, e o que não
//!
//! Só os dados do armazém: uma subárvore de `/armazem` — ou ele inteiro —,
//! com os diretórios, os arquivos e o conteúdo deles, como estavam num
//! instante. Nada do estado de autoridade — pessoas, credenciais, política,
//! lápides, chaves de assinatura, mensagens, auditoria, a atualização —, que
//! mora no journal de estado, e que a âncora do TPM existe para nunca voltar
//! atrás; nem a identidade do Duke, nem segredo nenhum. O formato e as
//! regras são os do pacote `armazem` ([`armazem::copia`]).
//!
//! # A chave, e para quem a cópia abre
//!
//! A cópia sai cifrada e autenticada pela chave da cópia: derivada da chave
//! do Duke por um rótulo próprio — como as do journal e as do volume —,
//! calculada quando é usada e zerada depois; nunca guardada, nunca
//! exportada. E presa à instalação: o cabeçalho cifrado leva a pública do
//! Duke e o identificador que o journal sorteou ao nascer. Só esta máquina,
//! nesta instalação, a abre — outra com a mesma imagem não, e esta mesma
//! reinstalada também não. A cópia não leva a identidade: não clona a
//! máquina, não migra nada, não cria autoridade.
//!
//! # A cópia (`fs.backup`)
//!
//! Uma leitura: o gate decide `fs.read` no caminho, com o alcance de
//! sempre — a cópia não revela nada que a leitura não revele, e sai
//! cifrada. Com a ordem das gravações na mão do começo ao fim, a fotografia
//! é de um instante: nenhum lote entra no meio, e nenhum bloco lido é
//! solto. A cópia fica num rascunho de quem pede — no volume, na cota dele,
//! com o prazo dos rascunhos — e sai em pedaços.
//!
//! # A restauração (`fs.restore`)
//!
//! Uma permissão própria, de caminho: trocar uma subárvore inteira por uma
//! cópia é destrutivo de outro tamanho que uma escrita. A cópia chega como
//! um rascunho enviado por `fs.draft` para o mesmo caminho, e, com a ordem
//! das gravações na mão:
//!
//! 1. a persistência e o volume de pé, nenhum desligamento a caminho, a
//!    autoridade de quem pediu decidida de novo — como num lote —, os
//!    arrendamentos de tudo abaixo do caminho, e a versão esperada dele;
//! 2. a cópia lida e conferida **inteira** — a origem, cada registro, as
//!    regras, o fecho —, com o conteúdo de cada arquivo indo para blocos
//!    livres do volume, que nenhum metadado aponta. Qualquer recusa solta
//!    esses blocos, e nada mudou;
//! 3. o armazém prepara o lote — apagar a subárvore de agora, do mais fundo
//!    para cima, e criar a da cópia —: versões novas, nunca uma já vista; o
//!    dono é quem restaura; a cota dele e o teto dos metadados;
//! 4. a auditoria registra o que vai ser feito, com a decisão do gate;
//! 5. o armazém resultante vai ao volume como uma **base** na outra região
//!    do journal dos metadados, e o journal de estado a confirma num
//!    registro só, com a auditoria — **o ponto de commit**
//!    ([`crate::volume::substituir`]). Antes dele nada mudou; depois, tudo.
//!    Uma queda no meio deixa um ou outro, nunca uma mistura;
//! 6. só então o lote vale em memória, os blocos do que saiu voltam a ser
//!    livres, e o rascunho da cópia some.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::Cell;

use ::armazem::bloco::{CARGA, TAM_BLOCO};
use ::armazem::copia::{self, Cabecalho, Evento, Origem, Recusa, Totais};
use ::armazem::{Conteudo, Faixas, Op, Tipo};
use politica::Codigo;

use crate::armazem::{ConteudoNovo, Falha};

/// O sal e o rótulo da chave da cópia: nenhuma outra chave os usa.
const SAL: &[u8] = b"Duke copia v1";
const ROTULO: &[u8] = b"copia: registros";

/// O maior pedaço de uma cópia numa resposta de `fs.backup`: em base64, um
/// terço a mais.
pub const MAIOR_LEITURA: u64 = 48 * 1024;

/// Roda `f` com a chave da cópia desta máquina, zerada depois.
fn com_a_chave<R>(f: impl FnOnce(&[u8; 32]) -> R) -> Result<R, Falha> {
    let mut chave =
        crate::identidade::com_chave_do_duke(|k| sigilo::resumo::hkdf_rfc5869(SAL, k, &[ROTULO]))
            .ok_or(Falha::Persistencia("sem a chave do Duke"))?;
    let r = f(&chave);
    sigilo::zeroize::Zeroize::zeroize(&mut chave);
    Ok(r)
}

/// De que máquina esta é: a pública do Duke e a instalação.
fn origem() -> Result<Origem, Falha> {
    Ok(Origem {
        publica: crate::identidade::publica_do_duke()
            .ok_or(Falha::Persistencia("sem a chave do Duke"))?,
        instalacao: crate::persistencia::instalacao()
            .ok_or(Falha::Persistencia("o journal nao tem a instalacao"))?,
    })
}

fn nonce() -> Result<[u8; diario::TAM_NONCE], &'static str> {
    let mut n = [0u8; diario::TAM_NONCE];
    crate::aleatorio::preencher(&mut n).map_err(|_| "sem entropia para o nonce")?;
    Ok(n)
}

/// O identificador de uma cópia, curto, para a auditoria e o log: os oito
/// primeiros bytes do elo do fecho, em hexadecimal. A resposta leva ele
/// inteiro.
pub fn curto(id: &[u8; 32]) -> String {
    hex(&id[..8])
}

/// Bytes em hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITOS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITOS[usize::from(b >> 4)]));
        s.push(char::from(DIGITOS[usize::from(b & 0xf)]));
    }
    s
}

/// O que a cópia e a restauração conferem antes de começar, com a ordem
/// das gravações na mão: a persistência e o volume — com a autoridade do
/// boot —, nenhum reinício ou desligamento a caminho, e a autoridade de
/// quem pediu, decidida de novo pela política de agora.
fn pronta() -> Result<(), Falha> {
    crate::persistencia::exigir()
        .and_then(|()| crate::volume::exigir())
        .map_err(Falha::Persistencia)?;
    if crate::energia::pedida().is_some() {
        return Err(Falha::Desligando);
    }
    crate::autorizacao::reconfirmar().map_err(|(c, m)| Falha::Revogada(c, m))
}

/// O caminho de `c`, relativo à raiz do armazém, dentro da cópia de
/// `relativo`: vazio é a raiz da cópia.
fn dentro_da_copia<'a>(c: &'a str, relativo: &str) -> &'a str {
    if relativo.is_empty() {
        c
    } else if c == relativo {
        ""
    } else {
        &c[relativo.len() + 1..]
    }
}

// ---------------------------------------------------------------------------
// A cópia
// ---------------------------------------------------------------------------

/// Uma cópia feita.
#[derive(Clone, Copy, Debug)]
pub struct Feita {
    /// O rascunho que a guarda, de quem pediu.
    pub numero: u64,
    /// Quantos bytes ela tem.
    pub tamanho: u64,
    /// O identificador: o elo do fecho, que nomeia exatamente esta cópia.
    pub id: [u8; 32],
    /// A versão da captura: todo nó da cópia tem uma anterior a ela.
    pub versao: u64,
    pub totais: Totais,
}

/// Faz a cópia de `caminho` — `/armazem` inteiro, ou um nó abaixo dele —
/// num rascunho de quem pede, para ele baixar com [`ler`]. O comando em
/// execução neste fio é o autorizado pelo gate.
pub fn fazer(caminho: &str) -> Result<Feita, Falha> {
    let (normal, relativo) = crate::armazem::conferido_ou_raiz(caminho)
        .map_err(|f| crate::armazem::recusada(caminho, f))?;
    let Some(dono) = crate::autorizacao::dono_no_armazem() else {
        return Err(crate::armazem::recusada(
            &normal,
            Falha::Caminho("quem pediu nao tem dono no armazem"),
        ));
    };
    crate::persistencia::em_ordem(|| fazer_em_ordem(&normal, &relativo, &dono))
        .map_err(|f| crate::armazem::recusada(&normal, f))
}

fn fazer_em_ordem(normal: &str, relativo: &str, dono: &str) -> Result<Feita, Falha> {
    pronta()?;
    crate::armazem::sumir_rascunhos_vencidos();
    let origem = origem()?;
    // A fotografia: os nós da subárvore em ordem de caminho — a raiz dela
    // primeiro —, com o conteúdo de cada arquivo. Com a ordem na mão nenhum
    // lote muda o armazém, e nenhum bloco destes é solto.
    let (versao, nos) = crate::armazem::com_o_armazem(|a| {
        let nos: Vec<(String, Option<Conteudo>, u64)> = a
            .todos()
            .filter(|(c, _)| *c == relativo || ::armazem::abaixo_de(c, relativo))
            .map(|(c, n)| (String::from(c), n.conteudo().cloned(), n.versao()))
            .collect();
        (a.proxima(), nos)
    });
    // Na suíte: o que tenta mudar o armazém no meio da cópia — e que espera
    // por ela, porque a ordem está na mão.
    #[cfg(feature = "modo-teste")]
    crate::armazem::rodar_no_meio_da_copia();
    if !relativo.is_empty() && nos.first().map(|(c, ..)| c.as_str()) != Some(relativo) {
        return Err(Falha::Armazem(::armazem::Recusa::NaoExiste));
    }
    let cabecalho = Cabecalho {
        origem,
        raiz: String::from(relativo),
        versao,
        geracao: crate::persistencia::geracao(),
        tempo: crate::persistencia::agora(),
    };
    let numero = crate::armazem::abrir_copia(dono, normal)?;
    let escrita = com_a_chave(|chave| escrever(chave, &cabecalho, relativo, &nos, numero, dono))
        .and_then(|r| r);
    let (fechada, tamanho) = match escrita {
        Ok(e) => e,
        Err(f) => {
            crate::armazem::descartar_numero(numero);
            return Err(f);
        }
    };
    let t = fechada.totais;
    // Curto, como o da restauração: o número da decisão tem de caber.
    let execucao = crate::autorizacao::auditar_execucao(
        normal,
        Codigo::Allow,
        &format!("feita a copia {}", curto(&fechada.id)),
    );
    if execucao == 0 {
        crate::armazem::descartar_numero(numero);
        return Err(Falha::SemAuditoria);
    }
    crate::log_info!(
        "armazem",
        "copia {} de {}: {} diretorios, {} arquivos, {} bytes de conteudo, {} bytes",
        curto(&fechada.id),
        normal,
        t.diretorios,
        t.arquivos,
        t.bytes,
        tamanho
    );
    Ok(Feita {
        numero,
        tamanho,
        id: fechada.id,
        versao,
        totais: t,
    })
}

/// Escreve a cópia de `nos` no rascunho `numero`, de `dono`: cada setor
/// pronto vai ao rascunho na hora — os blocos cheios, ao volume —, contado
/// na cota do dono. Devolve a cópia fechada e o tamanho do rascunho.
fn escrever(
    chave: &[u8; 32],
    cabecalho: &Cabecalho,
    relativo: &str,
    nos: &[(String, Option<Conteudo>, u64)],
    numero: u64,
    dono: &str,
) -> Result<(copia::Fechada, u64), Falha> {
    let cota = crate::autorizacao::cota_no_armazem();
    // O que deu errado do lado do rascunho: a escrita da cópia só sabe o
    // motivo em palavras.
    let falha: Cell<Option<Falha>> = Cell::new(None);
    let tamanho = Cell::new(0u64);
    let entregues = Cell::new(0u32);
    let saida = |bytes: &[u8]| -> Result<(), &'static str> {
        // A cota: o que o dono tem, mais os rascunhos dele — esta cópia
        // junto —, mais isto.
        let usado = crate::armazem::com_o_armazem(|a| a.uso(dono).bytes)
            + crate::armazem::reservado_em_rascunhos(dono, &[]);
        if usado.saturating_add(bytes.len() as u64) > cota.bytes {
            falha.set(Some(Falha::Armazem(::armazem::Recusa::Cota)));
            return Err("a copia nao cabe na cota");
        }
        match crate::armazem::acrescentar_a_copia(numero, bytes) {
            Ok(t) => tamanho.set(t),
            Err(f) => {
                falha.set(Some(f));
                return Err("o rascunho da copia recusou");
            }
        }
        entregues.set(entregues.get() + 1);
        // O setor em claro e a primeira parte no rascunho, e o resto não.
        #[cfg(feature = "quedas")]
        if entregues.get() == 2 {
            crate::quedas::aqui(crate::quedas::Ponto::CopiaNoMeio);
        }
        Ok(())
    };
    let erro = |m: &'static str| falha.take().unwrap_or(Falha::Persistencia(m));
    let mut e = copia::Escrita::comecar(chave, cabecalho, nonce, saida).map_err(erro)?;
    let mut bloco: Box<[u8; TAM_BLOCO]> = Box::new([0; TAM_BLOCO]);
    let escrito = (|| {
        // A raiz do armazém não é nó: a cópia dele começa por ela, um
        // diretório com a versão 0.
        if relativo.is_empty() {
            e.diretorio("", 0)?;
        }
        for (c, conteudo, versao) in nos {
            let dentro = dentro_da_copia(c, relativo);
            let Some(ct) = conteudo else {
                e.diretorio(dentro, *versao)?;
                continue;
            };
            e.arquivo(dentro, *versao, ct.tamanho)?;
            for k in 0..ct.blocos() {
                let (b, id) = ct.onde(k).ok_or("fora das extensoes")?;
                crate::volume::ler_bloco(b, &id, k, &mut bloco)?;
                let n = (ct.tamanho - k * CARGA as u64).min(CARGA as u64) as usize;
                e.conteudo(&bloco[..n])?;
            }
        }
        Ok(())
    })();
    politica::sigiloso::zerar(&mut bloco[..]);
    escrito.map_err(erro)?;
    let fechada = e.fechar().map_err(erro)?;
    Ok((fechada, tamanho.get()))
}

/// Lê até `quanto` bytes da cópia `numero` — de quem pede, feita de
/// `caminho` —, a partir do byte `de`: menos no fim, nada depois dele.
/// Devolve os bytes e o tamanho da cópia. O prazo do rascunho se renova.
pub fn ler(caminho: &str, numero: u64, de: u64, quanto: u64) -> Result<(Vec<u8>, u64), Falha> {
    let (normal, _) = crate::armazem::conferido_ou_raiz(caminho)?;
    let dono = crate::autorizacao::dono_no_armazem()
        .ok_or(Falha::Caminho("quem pediu nao tem dono no armazem"))?;
    crate::persistencia::em_ordem(|| {
        let tamanho = crate::armazem::rascunho_de(numero, &dono, &normal, true)?;
        let n = quanto.min(MAIOR_LEITURA).min(tamanho.saturating_sub(de)) as usize;
        let mut v = alloc::vec![0u8; n];
        let lido = crate::armazem::ler_do_rascunho(numero, de, &mut v)?;
        v.truncate(lido);
        Ok((v, tamanho))
    })
}

/// Descarta a cópia `numero` — de quem pede, feita de `caminho` —, com os
/// blocos dela.
pub fn descartar(caminho: &str, numero: u64) -> Result<(), Falha> {
    let (normal, _) = crate::armazem::conferido_ou_raiz(caminho)?;
    let dono = crate::autorizacao::dono_no_armazem()
        .ok_or(Falha::Caminho("quem pediu nao tem dono no armazem"))?;
    crate::persistencia::em_ordem(|| {
        crate::armazem::rascunho_de(numero, &dono, &normal, true)?;
        crate::armazem::descartar_numero(numero);
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// A restauração
// ---------------------------------------------------------------------------

/// Uma restauração feita.
#[derive(Clone, Copy, Debug)]
pub struct Restaurada {
    /// A cópia que voltou: o identificador, a versão da captura e os
    /// totais.
    pub id: [u8; 32],
    pub versao_da_copia: u64,
    pub totais: Totais,
    /// Quantos nós de antes saíram.
    pub removidos: u64,
    /// A versão que o caminho restaurado tem agora — 0 na raiz do armazém.
    pub versao: u64,
}

/// O rascunho enviado, como o meio de onde a cópia se lê: setores de 512
/// bytes, só para ler.
struct NoRascunho {
    numero: u64,
    setores: u64,
}

impl diario::Meio for NoRascunho {
    fn setores(&self) -> u64 {
        self.setores
    }

    fn ler(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
        let de = setor
            .checked_mul(diario::TAM_SETOR as u64)
            .ok_or("um setor fora da copia")?;
        let lido =
            crate::armazem::ler_do_rascunho(self.numero, de, destino).map_err(Falha::motivo)?;
        if lido != destino.len() {
            return Err("um setor fora da copia");
        }
        Ok(())
    }

    fn escrever(&mut self, _: u64, _: &[u8]) -> Result<(), &'static str> {
        Err("uma copia se le, e nao se escreve")
    }

    fn descarregar(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
}

/// Troca `caminho` — `/armazem` inteiro, ou um nó abaixo dele — pela cópia
/// do rascunho `numero`, que quem pede enviou para esse caminho. `esperada`
/// é a versão do caminho agora: 0 se não há nó lá, e sempre 0 na raiz. Ver
/// a ordem no topo do módulo.
pub fn restaurar(caminho: &str, numero: u64, esperada: u64) -> Result<Restaurada, Falha> {
    let (normal, relativo) = crate::armazem::conferido_ou_raiz(caminho)
        .map_err(|f| crate::armazem::recusada(caminho, f))?;
    let Some(dono) = crate::autorizacao::dono_no_armazem() else {
        return Err(crate::armazem::recusada(
            &normal,
            Falha::Caminho("quem pediu nao tem dono no armazem"),
        ));
    };
    let titular = crate::armazem::titular();
    crate::persistencia::em_ordem(|| {
        restaurar_em_ordem(&normal, &relativo, numero, esperada, &dono, titular)
    })
    .map_err(|f| crate::armazem::recusada(&normal, f))
}

fn restaurar_em_ordem(
    normal: &str,
    relativo: &str,
    numero: u64,
    esperada: u64,
    dono: &str,
    titular: Option<politica::arrendamento::Titular>,
) -> Result<Restaurada, Falha> {
    // Na suíte: o que acontece entre a decisão do gate e o commit — uma
    // revogação, uma política nova —, com a ordem já na mão.
    #[cfg(feature = "modo-teste")]
    crate::armazem::rodar_antes_do_commit();
    pronta()?;
    crate::armazem::conferir_arrendamentos(normal, titular, true)?;
    let atual = crate::armazem::com_o_armazem(|a| a.versao(relativo));
    if atual != esperada {
        return Err(Falha::Versao { atual });
    }
    crate::armazem::sumir_rascunhos_vencidos();
    let tamanho = crate::armazem::rascunho_de(numero, dono, normal, false)?;
    if tamanho % diario::TAM_SETOR as u64 != 0 {
        return Err(Falha::Copia("a copia nao tem setores inteiros"));
    }
    let origem = origem()?;
    // A cópia inteira, conferida; o conteúdo de cada arquivo, em blocos
    // livres que nenhum metadado aponta.
    let mut meio = NoRascunho {
        numero,
        setores: tamanho / diario::TAM_SETOR as u64,
    };
    let mut reservadas: Faixas = Vec::new();
    let mut aberto: Option<(String, ConteudoNovo)> = None;
    let mut criar: Vec<Op> = Vec::new();
    let lida = com_a_chave(|chave| {
        copia::ler(&mut meio, chave, &origem, |e| {
            receber(e, relativo, &mut aberto, &mut criar, &mut reservadas)
        })
    });
    // Um arquivo pela metade é de uma cópia recusada: os blocos dele voltam.
    if let Some((_, c)) = aberto.take() {
        c.soltar();
    }
    let soltar = |reservadas: Faixas| crate::volume::soltar(&::armazem::normalizar(reservadas));
    let lida = match lida {
        Ok(Ok(l)) => l,
        Ok(Err(r)) => {
            soltar(reservadas);
            return Err(match r {
                Recusa::Fora(f) => f,
                Recusa::Meio(m) => Falha::Persistencia(m),
                outra => Falha::Copia(outra.motivo()),
            });
        }
        Err(f) => {
            soltar(reservadas);
            return Err(f);
        }
    };
    #[cfg(feature = "quedas")]
    crate::quedas::aqui(crate::quedas::Ponto::RestauracaoConferida);
    // O lote: a subárvore de agora sai, do mais fundo para cima — na ordem
    // dos caminhos ao contrário, cada nó vem antes do pai —, e a da cópia
    // entra, cada pai antes dos filhos.
    let mut ops: Vec<Op> = crate::armazem::com_o_armazem(|a| {
        a.todos()
            .filter(|(c, _)| *c == relativo || ::armazem::abaixo_de(c, relativo))
            .map(|(c, n)| {
                let caminho = String::from(c);
                let esperada = n.versao();
                match n.tipo() {
                    Tipo::Arquivo => Op::Apagar { caminho, esperada },
                    Tipo::Diretorio => Op::RemoverDiretorio { caminho, esperada },
                }
            })
            .collect()
    });
    ops.reverse();
    let removidos = ops.len() as u64;
    ops.append(&mut criar);
    let lote = match crate::armazem::preparar(&ops, dono, &[numero]) {
        Ok(l) => l,
        Err((_, f)) => {
            soltar(reservadas);
            return Err(f);
        }
    };
    // O que o comando vai fazer, em nome de quem o gate autorizou: no mesmo
    // registro do journal de estado que a confirmação. Curto: o detalhe tem
    // teto, e o número da decisão, que vem no fim, tem de caber — com o
    // prefixo do processo que pediu, quando é um.
    let primeira = crate::armazem::com_o_armazem(|a| a.proxima());
    let execucao = crate::autorizacao::auditar_execucao(
        normal,
        Codigo::Allow,
        &format!("restaurada a copia {}", curto(&lida.id)),
    );
    if execucao == 0 {
        soltar(reservadas);
        return Err(Falha::SemAuditoria);
    }
    // O armazém como fica, para a base: o de agora com o lote. Com a ordem
    // na mão nada mais o muda até o lote valer em memória.
    let mut novo = crate::armazem::com_o_armazem(|a| a.clone());
    if let Err(r) = novo.aplicar(&lote) {
        soltar(reservadas);
        return Err(Falha::Armazem(r));
    }
    // O ponto de commit.
    if let Err(m) = crate::volume::substituir(&novo, execucao) {
        // Pode ter chegado ao disco: os blocos ficam reservados até o boot,
        // que decide pelo que o journal de estado tem.
        return Err(Falha::Persistencia(m));
    }
    drop(novo);
    crate::armazem::aplicar_confirmado(&lote, &reservadas, &[numero])?;
    #[cfg(feature = "quedas")]
    crate::quedas::aqui(crate::quedas::Ponto::RestauracaoGravada);
    crate::log_info!(
        "armazem",
        "copia {} restaurada em {}: {} nos sairam, {} diretorios, {} arquivos, {} bytes, versoes {}..{}",
        curto(&lida.id),
        normal,
        removidos,
        lida.totais.diretorios,
        lida.totais.arquivos,
        lida.totais.bytes,
        primeira,
        lote.proxima
    );
    Ok(Restaurada {
        id: lida.id,
        versao_da_copia: lida.cabecalho.versao,
        totais: lida.totais,
        removidos,
        versao: crate::armazem::com_o_armazem(|a| a.versao(relativo)),
    })
}

/// O que a leitura da cópia entrega, recebido: o cabeçalho conferido contra
/// o caminho da restauração, cada diretório e arquivo virando uma operação,
/// e o conteúdo indo para blocos livres. O que vem aqui só vale se a cópia
/// inteira for aceita.
fn receber(
    e: Evento<'_>,
    relativo: &str,
    aberto: &mut Option<(String, ConteudoNovo)>,
    criar: &mut Vec<Op>,
    reservadas: &mut Faixas,
) -> Result<(), Falha> {
    match e {
        Evento::Cabecalho(c) => {
            if c.raiz != relativo {
                return Err(Falha::Copia("a copia e de outro caminho"));
            }
        }
        Evento::Diretorio { caminho, .. } => {
            let completo = copia::no_armazem(relativo, caminho);
            // A raiz do armazém não é nó: ela já existe.
            if !completo.is_empty() {
                criar.push(Op::CriarDiretorio { caminho: completo });
            }
        }
        Evento::Arquivo { caminho, .. } => {
            *aberto = Some((copia::no_armazem(relativo, caminho), ConteudoNovo::novo()?));
        }
        Evento::Pedaco(bytes) => {
            let (_, c) = aberto
                .as_mut()
                .ok_or(Falha::Copia("um pedaco fora de um arquivo"))?;
            c.escrever(bytes)?;
        }
        Evento::FimDoArquivo => {
            let (caminho, c) = aberto
                .take()
                .ok_or(Falha::Copia("o fim de um arquivo que nao comecou"))?;
            let conteudo = c.fechar(reservadas)?;
            criar.push(Op::Gravar {
                caminho,
                esperada: 0,
                conteudo,
            });
        }
    }
    Ok(())
}

/// Só para a suíte: os nós de uma cópia aberta, pelo caminho relativo à
/// raiz dela, com o conteúdo de cada arquivo.
#[cfg(feature = "modo-teste")]
pub type NosDeTeste = Vec<(String, Option<Vec<u8>>)>;

/// Só para a suíte: a cópia `bytes`, aberta com a chave desta máquina — o
/// cabeçalho, e cada nó pelo caminho relativo à raiz dela, com o conteúdo
/// de cada arquivo —, ou o motivo da recusa. Lê como a restauração lê, e
/// não toca em nada.
#[cfg(feature = "modo-teste")]
pub fn abrir_de_teste(bytes: &[u8]) -> Result<(Cabecalho, NosDeTeste), &'static str> {
    struct NaMemoria<'a>(&'a [u8]);
    impl diario::Meio for NaMemoria<'_> {
        fn setores(&self) -> u64 {
            (self.0.len() / diario::TAM_SETOR) as u64
        }
        fn ler(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
            let de = (setor as usize)
                .checked_mul(diario::TAM_SETOR)
                .ok_or("um setor fora da copia")?;
            let fatia = self
                .0
                .get(de..de + destino.len())
                .ok_or("um setor fora da copia")?;
            destino.copy_from_slice(fatia);
            Ok(())
        }
        fn escrever(&mut self, _: u64, _: &[u8]) -> Result<(), &'static str> {
            Err("uma copia se le, e nao se escreve")
        }
        fn descarregar(&mut self) -> Result<(), &'static str> {
            Ok(())
        }
    }
    let origem = origem().map_err(Falha::motivo)?;
    let mut nos: NosDeTeste = Vec::new();
    let mut cabecalho = None;
    let lida = com_a_chave(|chave| {
        copia::ler(
            &mut NaMemoria(bytes),
            chave,
            &origem,
            |e| -> Result<(), ()> {
                match e {
                    Evento::Cabecalho(c) => cabecalho = Some(c.clone()),
                    Evento::Diretorio { caminho, .. } => nos.push((String::from(caminho), None)),
                    Evento::Arquivo { caminho, .. } => {
                        nos.push((String::from(caminho), Some(Vec::new())));
                    }
                    Evento::Pedaco(b) => {
                        if let Some((_, Some(v))) = nos.last_mut() {
                            v.extend_from_slice(b);
                        }
                    }
                    Evento::FimDoArquivo => {}
                }
                Ok(())
            },
        )
    })
    .map_err(Falha::motivo)?;
    lida.map_err(|r| r.motivo())?;
    Ok((cabecalho.ok_or("a copia nao tem cabecalho")?, nos))
}

/// Só para a suíte: `texto` leva um pedaço — doze bytes seguidos — da
/// chave da cópia desta máquina, crua ou em hexadecimal? A pergunta é
/// respondida aqui dentro: a chave não sai de [`com_a_chave`].
#[cfg(feature = "modo-teste")]
pub fn leva_a_chave_de_teste(texto: &[u8]) -> bool {
    com_a_chave(|chave| {
        let mut escrita = hex(chave);
        let leva = [&chave[..], escrita.as_bytes()]
            .iter()
            .any(|k| k.windows(12).any(|p| texto.windows(12).any(|t| t == p)));
        sigilo::zeroize::Zeroize::zeroize(&mut escrita);
        leva
    })
    .unwrap_or(false)
}
