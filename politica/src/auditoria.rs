//! A auditoria encadeada.
//!
//! # O que um registro diz
//!
//! Quem (que tipo de titular, sessão, identificador, chave pública, papel),
//! o quê (método e recurso),
//! o desfecho (o resultado em uma palavra e o código), quando (sequência e
//! milissegundos desde o boot), um BLAKE2s dos parâmetros e um detalhe curto.
//! Os parâmetros não entram por inteiro: podem trazer o que um agente
//! escreveu num campo, ou uma prova administrativa. O resumo prova o que foi
//! pedido para quem tem o pedido, e não o revela para quem só tem a
//! auditoria.
//!
//! # Pessoa não é agente
//!
//! O [`Titular`] diz que tipo de identidade agiu, e entra no elo: um
//! registro de pessoa não vira um de agente trocando o texto do nome. O
//! identificador de uma pessoa é `pessoa:<16 hex>` — com um `:` que nenhum
//! nome de agente tem — e a sessão dela, sorteada no login, vai no campo
//! próprio: a mesma pessoa em dois consoles são duas sessões, e duas
//! pessoas no mesmo console, uma depois da outra, também.
//!
//! # A cadeia
//!
//! Cada registro carrega o elo do anterior, e o seu elo é o BLAKE2s do elo
//! anterior com a codificação do registro:
//!
//! ```text
//! elo(n) = BLAKE2s("Duke auditoria v2" || elo(n-1) || codificacao(n))
//! ```
//!
//! Mudar, tirar ou reordenar um registro muda todos os elos dali para a
//! frente. A cabeça — o elo do último — é o que se ancora fora da máquina:
//! quem guardou a cabeça de ontem confere que a cadeia de hoje a contém.
//!
//! # A memória e o disco
//!
//! A cadeia mora num anel de tamanho fixo; quando um registro sai pela
//! ponta, o elo dele fica guardado como **âncora**, e a janela que sobra
//! continua verificável a partir dela.
//!
//! Com a persistência, cada registro vai também para o journal — ver
//! [`codificar`] e [`Cadeia::a_gravar`] —, e o boot refaz a cadeia a partir
//! dele com [`Cadeia::repor`]: a mesma sequência, os mesmos elos, e a
//! cadeia continua de onde parou. O que saiu do anel antes de chegar ao
//! journal não some em silêncio: vira uma **lacuna**, com a primeira e a
//! última sequência perdidas e o elo da última — ver [`Cadeia::pular`].
//! A cadeia continua verificável depois dela, como depois da âncora do
//! anel, e a lacuna diz exatamente o que falta.
//!
//! # O tempo não volta
//!
//! O tempo de um registro nunca é menor que o do anterior: o anel o sobe
//! até lá, se for preciso. Com o tempo lógico da persistência — o relógio
//! civil com o piso do journal — isso só acontece com os registros de um
//! boot feitos antes de o journal ser lido, e garante que uma cadeia que
//! atravessa boots nunca anda para trás no tempo. A reposição recusa um
//! tempo que volte: ele não sai de um journal autêntico.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use blake2::{Blake2s256, Digest};

use crate::codigo::Codigo;

/// O rótulo do elo, para ele nunca coincidir com outro resumo do sistema.
///
/// A v2 acrescentou o titular e a sessão de pessoa: um elo da v1 não é
/// refeito pela conta da v2, e nem deve ser.
const ROTULO: &[u8] = b"Duke auditoria v2";

/// O elo antes do primeiro registro.
pub const GENESE: [u8; 32] = [0; 32];

/// O maior detalhe, em bytes.
pub const MAIOR_DETALHE: usize = 96;

/// O que fica, na descrição do programa que pediu, no lugar do nome — e do
/// editor — que [`detalhe_composto`] tirou acima do teto; e, no fim de um
/// texto que perdeu o fim, no lugar das palavras que saíram (ver
/// [`MARCA_DO_CORTE`]). Nenhum nome de programa nem de editor é `?`: os
/// dois são de `a-z`, `0-9`, `-`, `_` e `.`. Por isso a descrição abreviada
/// nunca é a inteira de outro programa — ver [`descricao_abreviada`] —, e o
/// texto cortado nunca termina num nome, nem num número, que não estava lá.
pub const OMITIDO: &str = "?";

/// O fim de um texto que [`detalhe_composto`] cortou no teto: um espaço e
/// [`OMITIDO`], depois da última palavra que coube inteira. Quem lê o
/// texto para reconhecer o que ele diz tira a marca antes — ver
/// [`crate::procedencia::Falta::do_motivo`].
pub const MARCA_DO_CORTE: &str = " ?";

/// O detalhe de um registro, composto: quem pediu, quando foi um processo
/// (`pelo`, o processo e o programa), o `texto` e a `citacao` no fim — o
/// número da decisão que uma execução cita. É o formato de sempre: `pelo`
/// sozinho, `pelo: texto` ou `texto`, com a citação colada no texto.
///
/// # Acima do teto
///
/// Acima de [`MAIOR_DETALHE`], o detalhe encolhe aqui, com a citação ou
/// sem ela, e nunca chega ao corte do anel ([`Cadeia::anexar`]), que leva o
/// fim às cegas. A citação fica inteira no fim: um pedaço do número é o
/// número de outro registro. O que encolhe é o que vem antes dela, e nesta
/// ordem — cada passo só quando o anterior não bastou:
///
/// 1. o **nome** do programa sai da descrição de quem pediu: `pelo
///    processo N (<nome> <resumo> de <editor>)` vira `pelo processo N (?
///    <resumo> de <editor>)`. O nome é o que o programa diz ser, escolhido
///    por quem o escreveu, até 32 bytes: um nome longo não tira da
///    auditoria nem o texto nem quem selou o código;
/// 2. o **editor** sai também: `(? <resumo> de ?)`. O `de` fica — o código
///    de fora da imagem não passa pelo da imagem;
/// 3. o **texto** perde o fim, numa fronteira de palavra: o corte recua até
///    o espaço antes da palavra que não coube, e [`MARCA_DO_CORTE`] fica no
///    lugar do que saiu — `…no editor ?`, `…de ?`. Nenhuma palavra fica pela
///    metade: o pedaço de um nome é o nome válido de outro editor ou
///    programa, e o de um número, outro número. Um texto de uma palavra só,
///    maior que o lugar, vira [`OMITIDO`].
///
/// O texto vem antes da descrição porque é ele que diz o que o registro
/// conta, e quem lê a auditoria o reconhece — o NSF vê o código adulterado
/// pelo motivo (ver [`crate::procedencia::Falta::do_motivo`]), a recusa do
/// manifesto por `o manifesto nao declara`, o nascimento pelo `processo N
/// lancado` e pelo `filho N` —, e o `)` da descrição, mesmo abreviada, é o
/// que diz de que processo o registro é. O começo do resumo — o que o
/// programa **é** — fica sempre, e o lugar do que saiu fica com
/// [`OMITIDO`]: a abreviada nunca é a descrição inteira de outro programa,
/// nem a de um código da imagem. Quem pediu sem a forma `pelo processo N
/// (…)` com o resumo — a relação de outro dispositivo, o processo
/// `(kernel)` ou `(sem imagem)` — não encolhe: o texto encolhe direto.
///
/// # Com e sem citação
///
/// A regra é a mesma. Com a citação — a execução de uma decisão —, a
/// descrição inteira está no registro da decisão que ela aponta. Sem
/// citação — a decisão do gate, a bifurcação, o pedido inválido —, a
/// decisão que permite tem o texto vazio e guarda a descrição inteira
/// sempre que ela cabe no teto; o `pelo` sozinho passa dele só no código de
/// fora da imagem com nome e editor longos, e então vai abreviado, com o
/// `)`. A recusa guarda o motivo antes da descrição: é ele que diz o que
/// faltou.
///
/// Quem confere uma decisão pelo começo do detalhe — a âncora de uma
/// declaração, `autorizacao::decisao_de_quem_pede` no kernel — a compara
/// com o `pelo` inteiro: um registro abreviado não serve de âncora, e o
/// processo cuja descrição passa do teto não se ancora em decisão
/// nenhuma — como já não se ancorava quando o anel cortava a decisão dele.
///
/// Um `pelo` que não cabe nem com o texto todo omitido — o kernel não
/// escreve um: o maior, abreviado, tem 52 bytes — perde o fim numa
/// fronteira de caractere, antes da citação.
pub fn detalhe_composto(pelo: Option<&str>, texto: &str, citacao: &str) -> String {
    let inteiro = composto(pelo, texto, citacao);
    if inteiro.len() <= MAIOR_DETALHE || citacao.len() > MAIOR_DETALHE {
        return inteiro;
    }
    // A descrição do programa encolhe antes do texto: o nome, depois o
    // editor — cada passo só se o anterior não coube.
    let mut pelo = pelo.map(String::from);
    for sem_o_editor in [false, true] {
        let Some(curto) = pelo.as_deref().and_then(|p| abreviado(p, sem_o_editor)) else {
            continue;
        };
        let d = composto(Some(&curto), texto, citacao);
        if d.len() <= MAIOR_DETALHE {
            return d;
        }
        pelo = Some(curto);
    }
    // Ainda acima do teto: o texto perde o fim numa fronteira de palavra, e
    // a citação fica inteira. O lugar do texto é o que sobra de quem pediu
    // — com o `: ` — e da citação.
    let de_quem_pediu = pelo.as_deref().map_or(0, |p| p.len() + ": ".len());
    if let Some(lugar) = MAIOR_DETALHE.checked_sub(de_quem_pediu + citacao.len())
        && lugar >= OMITIDO.len()
    {
        return composto(pelo.as_deref(), &sem_o_fim(texto, lugar), citacao);
    }
    // Quem pediu não cabe nem sem o texto: perde o fim, antes da citação.
    let inteiro = composto(pelo.as_deref(), texto, citacao);
    let mut antes = String::from(&inteiro[..inteiro.len() - citacao.len()]);
    let mut fim = MAIOR_DETALHE - citacao.len();
    while !antes.is_char_boundary(fim) {
        fim -= 1;
    }
    antes.truncate(fim);
    antes.push_str(citacao);
    antes
}

/// `texto` sem o fim, em até `lugar` bytes — `texto` não cabe nele, e o
/// lugar tem pelo menos o de [`OMITIDO`]: as palavras inteiras que cabem
/// com [`MARCA_DO_CORTE`] depois delas, ou só [`OMITIDO`], quando nem a
/// primeira cabe. A palavra vai até o espaço: o corte cai sempre num
/// espaço, que é ASCII — uma fronteira de caractere.
fn sem_o_fim(texto: &str, lugar: usize) -> String {
    let fim = texto
        .bytes()
        .enumerate()
        .take_while(|&(i, _)| i + MARCA_DO_CORTE.len() <= lugar)
        .filter(|&(_, b)| b == b' ')
        .map(|(i, _)| i)
        .last();
    match fim
        .map(|i| texto[..i].trim_end_matches(' '))
        .filter(|antes| !antes.is_empty())
    {
        Some(antes) => alloc::format!("{antes}{MARCA_DO_CORTE}"),
        None => String::from(OMITIDO),
    }
}

/// `pelo: texto`, com a citação colada no texto — o formato de sempre, sem
/// teto.
fn composto(pelo: Option<&str>, texto: &str, citacao: &str) -> String {
    let corpo = alloc::format!("{texto}{citacao}");
    match pelo {
        Some(p) if corpo.is_empty() => String::from(p),
        Some(p) => alloc::format!("{p}: {corpo}"),
        None => corpo,
    }
}

/// `pelo`, com a descrição do programa abreviada: o nome no lugar de
/// [`OMITIDO`] e, com `sem_o_editor`, o editor também. `None` quando não
/// muda nada, ou quando `pelo` não é `pelo processo N (<descrição>)` com
/// uma descrição que tem o resumo — ver [`resumo_e_editor`].
fn abreviado(pelo: &str, sem_o_editor: bool) -> Option<String> {
    let (fio, descricao) = do_processo(pelo)?;
    let (resumo, editor) = resumo_e_editor(descricao)?;
    let editor = if sem_o_editor {
        editor.map(|_| OMITIDO)
    } else {
        editor
    };
    let mut curto = alloc::format!("pelo processo {fio} ({OMITIDO} {resumo}");
    if let Some(e) = editor {
        curto.push_str(" de ");
        curto.push_str(e);
    }
    curto.push(')');
    (curto != pelo).then_some(curto)
}

/// O fio e a descrição do programa de `pelo processo <fio> (<descrição>)`,
/// a forma com que o kernel grava um processo.
fn do_processo(pelo: &str) -> Option<(&str, &str)> {
    let (fio, descricao) = pelo.strip_prefix("pelo processo ")?.split_once(" (")?;
    let descricao = descricao.strip_suffix(')')?;
    let fio_certo = !fio.is_empty() && fio.bytes().all(|b| b.is_ascii_digit());
    (fio_certo && !descricao.contains(['(', ')'])).then_some((fio, descricao))
}

/// O começo do resumo e o editor de uma descrição de programa com imagem:
/// `<nome> <resumo>[ de <editor>]`, em que o nome pode ser `sem
/// manifesto`, ou [`OMITIDO`] numa já abreviada. `None` para a descrição
/// sem resumo — `kernel`, `sem imagem` — e para o que não tem essa forma.
fn resumo_e_editor(descricao: &str) -> Option<(&str, Option<&str>)> {
    let depois_do_nome = match descricao.strip_prefix("sem manifesto ") {
        Some(resto) => resto,
        None => descricao.split_once(' ')?.1,
    };
    let (resumo, editor) = match depois_do_nome.split_once(' ') {
        None => (depois_do_nome, None),
        Some((resumo, resto)) => (resumo, Some(resto.strip_prefix("de ")?)),
    };
    let resumo_certo = resumo.len() == 8
        && resumo
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let editor_certo = editor.is_none_or(|e| !e.is_empty() && !e.contains(' '));
    (resumo_certo && editor_certo).then_some((resumo, editor))
}

/// Se a descrição de um programa — a de `pelo processo N (<descrição>)` —
/// é uma que [`detalhe_composto`] abreviou: o nome, ou também o editor, no
/// lugar de [`OMITIDO`]. A descrição inteira nunca é: nenhum nome é `?`.
///
/// Quem lê a auditoria a usa para não tomar a abreviada por outro programa:
/// é o mesmo processo, com o programa que o registro da decisão citada
/// descreve inteiro.
pub fn descricao_abreviada(descricao: &str) -> bool {
    descricao.split(' ').any(|parte| parte == OMITIDO)
}

/// O começo do resumo — os 8 dígitos hexadecimais — da descrição de um
/// programa com imagem, inteira ou abreviada: `<nome> <resumo>[ de
/// <editor>]`, `sem manifesto <resumo>…` ou `? <resumo>…`. `None` para a
/// descrição sem resumo — `kernel`, `sem imagem` — e para o que não tem
/// essa forma.
///
/// É o que o programa **é**, e fica na abreviada: quem lê a auditoria
/// compara uma descrição abreviada com a inteira que já conhece por ele —
/// o mesmo resumo é o mesmo programa; outro resumo, outro programa.
pub fn resumo_da_descricao(descricao: &str) -> Option<&str> {
    resumo_e_editor(descricao).map(|(resumo, _)| resumo)
}

/// O editor da descrição de um programa com imagem, inteira ou abreviada —
/// o que vem depois do ` de ` —: `Some(None)` para a descrição sem `de` (o
/// código da imagem), `Some(Some(editor))` para a do código de fora — o
/// editor, ou [`OMITIDO`] na abreviada que o tirou —, e `None` para o que
/// não tem a forma de [`resumo_da_descricao`].
///
/// O resumo tem 32 bits: dois programas com o mesmo nome, o mesmo editor e
/// os mesmos quatro primeiros bytes do resumo têm a mesma descrição. Quem
/// compara uma abreviada com a que já conhece confere também o `de` e o
/// editor — ver `seguranca::grafo`.
pub fn editor_da_descricao(descricao: &str) -> Option<Option<&str>> {
    resumo_e_editor(descricao).map(|(_, editor)| editor)
}

/// Que tipo de identidade agiu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Titular {
    /// O próprio kernel, no boot: carregar a chave, o registro e a política.
    Kernel = 0,
    /// Um processo do sistema — o servidor de janelas, o Terminal.
    Sistema = 1,
    /// A serial: o canal de controle e emergência, sem identidade de pessoa.
    Serial = 2,
    /// Um agente, pela chave que provou o aperto.
    Agente = 3,
    /// Uma pessoa do registro, pela sessão que abriu com a credencial dela.
    Pessoa = 4,
    /// Um administrador, pela prova de uma operação administrativa.
    Administrador = 5,
    /// Ninguém ainda: uma porta sem aperto, um console sem login.
    Anonimo = 6,
    /// Um serviço do sistema com identidade própria — o tecido de
    /// segurança, `nsf`, e o de hora, `hora` —, pelo papel que a linha
    /// `servico` da política lhe dá. Entrou depois dos outros, no fim: o
    /// número de cada um é o que já está nos journals.
    Servico = 7,
    /// Outro dispositivo, pela chave que provou o aperto do enlace e pela
    /// relação dele com uma pessoa desta máquina — um pedido remoto. Também
    /// no fim, pelo mesmo motivo.
    Dispositivo = 8,
}

impl Titular {
    /// Todos, na ordem do número.
    pub const TODOS: [Titular; 9] = [
        Titular::Kernel,
        Titular::Sistema,
        Titular::Serial,
        Titular::Agente,
        Titular::Pessoa,
        Titular::Administrador,
        Titular::Anonimo,
        Titular::Servico,
        Titular::Dispositivo,
    ];

    /// O nome, como `audit.tail` o escreve.
    pub const fn nome(self) -> &'static str {
        match self {
            Titular::Kernel => "kernel",
            Titular::Sistema => "system",
            Titular::Serial => "serial",
            Titular::Agente => "agent",
            Titular::Pessoa => "person",
            Titular::Administrador => "admin",
            Titular::Anonimo => "anonymous",
            Titular::Servico => "service",
            Titular::Dispositivo => "device",
        }
    }

    /// O caminho de volta de [`Titular::nome`].
    pub fn de_nome(nome: &str) -> Option<Titular> {
        Titular::TODOS.into_iter().find(|t| t.nome() == nome)
    }
}

/// O que um registro diz, antes de entrar na cadeia.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evento {
    pub ts_ms: u64,
    pub titular: Titular,
    /// A sessão do canal: a serial, uma porta, ou a da autoridade local.
    pub sessao: u8,
    /// A sessão de pessoa, sorteada no login. Só para [`Titular::Pessoa`],
    /// e para o login recusado de um console, que diz qual console era.
    pub sessao_de_pessoa: Option<[u8; 8]>,
    /// O identificador de quem agiu: o nome do agente ou do administrador,
    /// `pessoa:<16 hex>`, `serial`, `kernel`.
    pub agente: String,
    pub chave: Option<[u8; 32]>,
    pub papel: String,
    pub metodo: String,
    pub recurso: String,
    pub codigo: Codigo,
    pub parametros: [u8; 32],
    pub detalhe: String,
}

/// Um registro na cadeia.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registro {
    pub seq: u64,
    pub evento: Evento,
    /// O elo do registro anterior.
    pub anterior: [u8; 32],
    /// O elo deste.
    pub elo: [u8; 32],
}

/// O BLAKE2s dos parâmetros de um pedido.
pub fn resumo_dos_parametros(parametros: &[u8]) -> [u8; 32] {
    Blake2s256::digest(parametros).into()
}

/// Um registro como vai para o journal: a sequência e o evento, campo a
/// campo, os variáveis com dois bytes de tamanho. O elo não vai: quem lê
/// refaz a conta, e um elo gravado seria só mais um campo a conferir.
pub fn codificar(seq: u64, e: &Evento) -> Vec<u8> {
    let mut v = Vec::with_capacity(tamanho_codificado(e));
    codificar_em(&mut v, seq, e);
    v
}

/// [`codificar`], acrescentando ao fim de `v` em vez de num vetor novo — a
/// mesma codificação, byte a byte: [`codificar`] é esta, num vetor do
/// tamanho certo, e não há outra.
///
/// # Para quem copia com uma trava na mão
///
/// Com o lugar reservado antes — ao menos [`tamanho_codificado`] bytes
/// livres em `v` —, nada aqui pede memória: são só cópias de campos para
/// dentro do que já existe. É assim que o journal copia os registros do
/// anel da auditoria com a trava dele na mão, sem chamar o alocador lá
/// dentro — ver "A cópia", em `kernel/src/persistencia.rs`.
pub fn codificar_em(v: &mut Vec<u8>, seq: u64, e: &Evento) {
    // Os textos do kernel têm teto bem abaixo disso; o corte, se um dia
    // acontecer, fica numa fronteira de caractere, para o registro
    // continuar se lendo — ver [`corte_do_texto`].
    fn texto(v: &mut Vec<u8>, t: &str) {
        let n = corte_do_texto(t);
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v.extend_from_slice(&t.as_bytes()[..n]);
    }
    v.extend_from_slice(&seq.to_le_bytes());
    v.extend_from_slice(&e.ts_ms.to_le_bytes());
    v.push(e.titular as u8);
    v.push(e.sessao);
    match &e.sessao_de_pessoa {
        Some(s) => {
            v.push(1);
            v.extend_from_slice(s);
        }
        None => v.push(0),
    }
    match &e.chave {
        Some(k) => {
            v.push(1);
            v.extend_from_slice(k);
        }
        None => v.push(0),
    }
    v.push(e.codigo as u8);
    v.extend_from_slice(&e.parametros);
    texto(v, &e.agente);
    texto(v, &e.papel);
    texto(v, &e.metodo);
    texto(v, &e.recurso);
    texto(v, &e.detalhe);
}

/// Quantos bytes de um texto vão ao journal: ele inteiro, ou cortado no
/// teto de um campo de dois bytes de tamanho, numa fronteira de caractere.
fn corte_do_texto(t: &str) -> usize {
    let mut n = t.len().min(u16::MAX as usize);
    while !t.is_char_boundary(n) {
        n -= 1;
    }
    n
}

/// O menor registro codificado: os campos fixos — a sequência, o tempo, o
/// titular, a sessão, as duas marcas de presença, o código e o resumo dos
/// parâmetros — e os cinco textos vazios, só com o tamanho.
pub const MENOR_CODIFICADO: usize = 8 + 8 + 1 + 1 + 1 + 1 + 1 + 32 + 5 * 2;

/// Quantos bytes [`codificar`] dá para `e`, sem codificar: a conta dos
/// mesmos campos, com o mesmo corte dos textos. É o que deixa quem copia
/// registros reservar o lugar antes, e saber, registro a registro, se o
/// próximo ainda cabe.
pub fn tamanho_codificado(e: &Evento) -> usize {
    let texto = |t: &str| 2 + corte_do_texto(t);
    MENOR_CODIFICADO - 5 * 2
        + e.sessao_de_pessoa.map_or(0, |s| s.len())
        + e.chave.map_or(0, |k| k.len())
        + texto(&e.agente)
        + texto(&e.papel)
        + texto(&e.metodo)
        + texto(&e.recurso)
        + texto(&e.detalhe)
}

/// O caminho de volta de [`codificar`]. Recusa o que não termina
/// exatamente no fim, um titular ou um código que não existem, uma marca
/// de presença que não é 0 nem 1, e texto que não é UTF-8.
pub fn decodificar(b: &[u8]) -> Result<(u64, Evento), &'static str> {
    struct Leitor<'a>(&'a [u8]);
    impl<'a> Leitor<'a> {
        fn bytes(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
            if self.0.len() < n {
                return Err("registro da auditoria cortado");
            }
            let (a, b) = self.0.split_at(n);
            self.0 = b;
            Ok(a)
        }
        fn u8(&mut self) -> Result<u8, &'static str> {
            Ok(self.bytes(1)?[0])
        }
        fn u64(&mut self) -> Result<u64, &'static str> {
            let mut a = [0u8; 8];
            a.copy_from_slice(self.bytes(8)?);
            Ok(u64::from_le_bytes(a))
        }
        fn opcional<const N: usize>(&mut self) -> Result<Option<[u8; N]>, &'static str> {
            match self.u8()? {
                0 => Ok(None),
                1 => {
                    let mut a = [0u8; N];
                    a.copy_from_slice(self.bytes(N)?);
                    Ok(Some(a))
                }
                _ => Err("marca de presenca invalida no registro da auditoria"),
            }
        }
        fn texto(&mut self) -> Result<String, &'static str> {
            let n = self.bytes(2)?;
            let n = u16::from_le_bytes([n[0], n[1]]) as usize;
            let t = core::str::from_utf8(self.bytes(n)?)
                .map_err(|_| "texto que nao e UTF-8 no registro da auditoria")?;
            Ok(String::from(t))
        }
    }
    let mut l = Leitor(b);
    let seq = l.u64()?;
    let ts_ms = l.u64()?;
    let titular = *Titular::TODOS
        .get(l.u8()? as usize)
        .ok_or("titular desconhecido no registro da auditoria")?;
    let sessao = l.u8()?;
    let sessao_de_pessoa = l.opcional::<8>()?;
    let chave = l.opcional::<32>()?;
    let codigo = *Codigo::TODOS
        .get(l.u8()? as usize)
        .ok_or("codigo desconhecido no registro da auditoria")?;
    let mut parametros = [0u8; 32];
    parametros.copy_from_slice(l.bytes(32)?);
    let evento = Evento {
        ts_ms,
        titular,
        sessao,
        sessao_de_pessoa,
        agente: l.texto()?,
        chave,
        papel: l.texto()?,
        metodo: l.texto()?,
        recurso: l.texto()?,
        codigo,
        parametros,
        detalhe: l.texto()?,
    };
    if !l.0.is_empty() {
        return Err("bytes sobrando no registro da auditoria");
    }
    Ok((seq, evento))
}

fn campo(h: &mut Blake2s256, bytes: &[u8]) {
    h.update((bytes.len() as u32).to_le_bytes());
    h.update(bytes);
}

/// O elo de um registro, dado o anterior.
///
/// A codificação é a mesma de [`crate::Politica`] para os dois lados: cada
/// campo variável com o tamanho na frente, para dois registros diferentes
/// nunca virarem os mesmos bytes.
pub fn elo(anterior: &[u8; 32], seq: u64, e: &Evento) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(ROTULO);
    h.update(anterior);
    h.update(seq.to_le_bytes());
    h.update(e.ts_ms.to_le_bytes());
    h.update([e.titular as u8]);
    h.update([e.sessao]);
    match &e.sessao_de_pessoa {
        Some(s) => {
            h.update([1]);
            h.update(s);
        }
        None => h.update([0]),
    }
    campo(&mut h, e.agente.as_bytes());
    match &e.chave {
        Some(k) => {
            h.update([1]);
            h.update(k);
        }
        None => h.update([0]),
    }
    campo(&mut h, e.papel.as_bytes());
    campo(&mut h, e.metodo.as_bytes());
    campo(&mut h, e.recurso.as_bytes());
    h.update([e.codigo as u8]);
    h.update(e.parametros);
    campo(&mut h, e.detalhe.as_bytes());
    h.finalize().into()
}

/// Os registros que perderam o anel antes de chegar ao journal: da
/// sequência `primeira` à `ultima`, e o elo da última.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lacuna {
    pub primeira: u64,
    pub ultima: u64,
    pub elo: [u8; 32],
}

/// O que falta gravar: a lacuna, se o anel perdeu algum registro antes de
/// ele ser gravado, e os registros que ainda estão no anel, em ordem.
pub struct AGravar<'a> {
    pub lacuna: Option<Lacuna>,
    pub registros: alloc::vec::Vec<&'a Registro>,
}

/// A cadeia, num anel.
pub struct Cadeia {
    registros: VecDeque<Registro>,
    capacidade: usize,
    /// O elo do último que saiu pela ponta; [`GENESE`] enquanto nenhum saiu.
    ancora: [u8; 32],
    proximo_seq: u64,
    /// O tempo do último registro, mesmo que ele tenha saído do anel.
    ultimo_ts: u64,
}

impl Cadeia {
    /// Uma cadeia vazia que guarda até `capacidade` registros.
    pub fn nova(capacidade: usize) -> Cadeia {
        Cadeia {
            registros: VecDeque::new(),
            capacidade: capacidade.max(1),
            ancora: GENESE,
            proximo_seq: 1,
            ultimo_ts: 0,
        }
    }

    /// A cabeça: o elo do último registro.
    pub fn cabeca(&self) -> [u8; 32] {
        self.registros.back().map_or(self.ancora, |r| r.elo)
    }

    /// O número do último registro, zero sem nenhum.
    pub fn ultima_seq(&self) -> u64 {
        self.proximo_seq - 1
    }

    /// O elo de onde a janela guardada parte.
    pub fn ancora(&self) -> [u8; 32] {
        self.ancora
    }

    /// Acrescenta um registro e devolve o número dele.
    pub fn anexar(&mut self, mut evento: Evento) -> u64 {
        // O detalhe tem teto, cortado numa fronteira de caractere.
        if evento.detalhe.len() > MAIOR_DETALHE {
            let mut fim = MAIOR_DETALHE;
            while !evento.detalhe.is_char_boundary(fim) {
                fim -= 1;
            }
            evento.detalhe.truncate(fim);
        }
        // O tempo não volta: um registro feito antes de o piso do relógio
        // ser conhecido sobe até o do anterior.
        evento.ts_ms = evento.ts_ms.max(self.ultimo_ts);
        self.ultimo_ts = evento.ts_ms;
        let anterior = self.cabeca();
        let seq = self.proximo_seq;
        let elo = elo(&anterior, seq, &evento);
        if self.registros.len() == self.capacidade
            && let Some(saiu) = self.registros.pop_front()
        {
            self.ancora = saiu.elo;
        }
        self.registros.push_back(Registro {
            seq,
            evento,
            anterior,
            elo,
        });
        self.proximo_seq += 1;
        seq
    }

    /// Repõe um registro lido do journal, no boot: a sequência tem de ser a
    /// seguinte, o tempo não pode voltar, e o detalhe cabe no teto. Um
    /// journal autêntico nunca traz outra coisa — a cadeia foi gravada por
    /// [`Cadeia::anexar`] —, e o que não confere é recusado, e não
    /// consertado: consertar daria outro elo.
    pub fn repor(&mut self, seq: u64, evento: Evento) -> Result<(), &'static str> {
        if seq != self.proximo_seq {
            return Err("registro da auditoria fora de sequencia");
        }
        if evento.ts_ms < self.ultimo_ts {
            return Err("registro da auditoria com o tempo voltando");
        }
        if evento.detalhe.len() > MAIOR_DETALHE {
            return Err("registro da auditoria com detalhe maior que o teto");
        }
        self.anexar(evento);
        Ok(())
    }

    /// Repõe uma lacuna lida do journal: os registros de `l.primeira` a
    /// `l.ultima` não foram gravados, e a cadeia continua do elo do último
    /// deles. A janela recomeça ali, como depois da âncora do anel.
    pub fn pular(&mut self, l: Lacuna) -> Result<(), &'static str> {
        if l.primeira != self.proximo_seq || l.ultima < l.primeira {
            return Err("lacuna da auditoria fora de sequencia");
        }
        self.registros.clear();
        self.ancora = l.elo;
        self.proximo_seq = l.ultima + 1;
        Ok(())
    }

    /// O que falta gravar depois da sequência `gravada`: uma lacuna, se o
    /// anel já perdeu registros posteriores a ela, e os que ele ainda tem.
    pub fn a_gravar(&self, gravada: u64) -> AGravar<'_> {
        AGravar {
            lacuna: self.lacuna_depois_de(gravada),
            registros: self.guardados_depois_de(gravada).collect(),
        }
    }

    /// A lacuna depois da sequência `gravada`: os registros posteriores a
    /// ela que o anel já perdeu — do seguinte a ela até o de antes do
    /// primeiro guardado, com o elo deste último, que é a âncora —, ou
    /// `None`, se o anel não perdeu nenhum.
    pub fn lacuna_depois_de(&self, gravada: u64) -> Option<Lacuna> {
        let primeira_no_anel = self.registros.front().map_or(self.proximo_seq, |r| r.seq);
        // A seguinte à gravada, sem dar a volta: quem grava nunca passa da
        // última, mas a função é pública, e `u64::MAX` não tem seguinte —
        // nem lacuna depois dele.
        let seguinte = gravada.saturating_add(1);
        (seguinte < primeira_no_anel).then_some(Lacuna {
            primeira: seguinte,
            ultima: primeira_no_anel - 1,
            elo: self.ancora,
        })
    }

    /// Os registros guardados de sequência maior que `gravada`, do mais
    /// antigo ao mais novo — os mesmos que o filtro pela sequência daria,
    /// sem passar pelos de antes: as sequências da janela são seguidas, e o
    /// primeiro deles fica à distância de `gravada + 1` ao primeiro
    /// guardado. Nada aqui pede memória.
    pub fn guardados_depois_de(&self, gravada: u64) -> impl Iterator<Item = &Registro> {
        self.registros.range(self.posicao_depois_de(gravada)..)
    }

    /// Os registros guardados de sequência até `gravada`, inclusive, do
    /// mais antigo ao mais novo: o começo da janela. Nada aqui pede memória.
    pub fn guardados_ate(&self, gravada: u64) -> impl Iterator<Item = &Registro> {
        self.registros.range(..self.posicao_depois_de(gravada))
    }

    /// Quantos dos guardados têm sequência até `gravada`: o lugar, na
    /// janela, do seguinte a ela.
    fn posicao_depois_de(&self, gravada: u64) -> usize {
        let primeira = self.registros.front().map_or(self.proximo_seq, |r| r.seq);
        usize::try_from(gravada.saturating_add(1).saturating_sub(primeira))
            .unwrap_or(usize::MAX)
            .min(self.registros.len())
    }

    /// Acrescenta, nesta cadeia, os eventos que a `outra` tem no anel, na
    /// ordem: cada um ganha a sequência, o elo e o tempo daqui. É o boot
    /// que continua a cadeia do journal com o que ele mesmo registrou antes
    /// de ler o journal.
    pub fn continuar_com(&mut self, outra: &Cadeia) {
        for r in &outra.registros {
            self.anexar(r.evento.clone());
        }
    }

    /// Os últimos `n` registros, do mais antigo ao mais novo.
    pub fn ultimos(&self, n: usize) -> impl Iterator<Item = &Registro> {
        let pular = self.registros.len().saturating_sub(n);
        self.registros.iter().skip(pular)
    }

    /// Quantos registros a janela guarda.
    pub fn guardados(&self) -> usize {
        self.registros.len()
    }

    /// O registro de número `seq`, se ele ainda está na janela: os números
    /// são seguidos, e o lugar dele é a distância até o primeiro guardado.
    pub fn registro(&self, seq: u64) -> Option<&Registro> {
        let primeiro = self.registros.front()?.seq;
        let i = usize::try_from(seq.checked_sub(primeiro)?).ok()?;
        self.registros.get(i).filter(|r| r.seq == seq)
    }

    /// Refaz a cadeia guardada a partir da âncora. Devolve a cabeça, ou o
    /// número do primeiro registro que não confere.
    pub fn verificar(&self) -> Result<[u8; 32], u64> {
        verificar(self.ancora, self.registros.iter())
    }
}

/// Refaz uma sequência de registros a partir de um elo. É a conta que o
/// `xtask` faz do lado de fora, com os registros que o kernel mostrou.
pub fn verificar<'a>(
    ancora: [u8; 32],
    registros: impl Iterator<Item = &'a Registro>,
) -> Result<[u8; 32], u64> {
    let mut anterior = ancora;
    let mut seq_esperada: Option<u64> = None;
    for r in registros {
        if r.anterior != anterior || seq_esperada.is_some_and(|s| s != r.seq) {
            return Err(r.seq);
        }
        if elo(&anterior, r.seq, &r.evento) != r.elo {
            return Err(r.seq);
        }
        anterior = r.elo;
        seq_esperada = Some(r.seq + 1);
    }
    Ok(anterior)
}

/// Os registros, para quem precisa de uma cópia.
pub fn copiar<'a>(registros: impl Iterator<Item = &'a Registro>) -> Vec<Registro> {
    registros.cloned().collect()
}

#[cfg(test)]
mod testes {
    use super::*;
    use alloc::string::ToString;

    fn evento(i: u64) -> Evento {
        Evento {
            ts_ms: i * 10,
            titular: Titular::Agente,
            sessao: 2,
            sessao_de_pessoa: None,
            agente: "agente-2".to_string(),
            chave: Some([7; 32]),
            papel: "operador".to_string(),
            metodo: "fs.read".to_string(),
            recurso: "/dados/x".to_string(),
            codigo: Codigo::Allow,
            parametros: resumo_dos_parametros(b"{}"),
            detalhe: String::new(),
        }
    }

    /// Um registro se acha pelo número enquanto está na janela; o que
    /// saiu dela, e o que ainda não existe, não.
    #[test]
    fn o_registro_pelo_numero() {
        let mut c = Cadeia::nova(4);
        assert!(c.registro(1).is_none());
        for i in 1..=6 {
            assert_eq!(c.anexar(evento(i)), i);
        }
        // Na janela: 3, 4, 5 e 6.
        for seq in 3..=6 {
            let r = c.registro(seq).unwrap();
            assert_eq!(r.seq, seq);
            assert_eq!(r.evento.ts_ms, seq * 10);
        }
        for fora in [0, 1, 2, 7, u64::MAX] {
            assert!(c.registro(fora).is_none(), "{fora}");
        }
    }

    #[test]
    fn cadeia_inteira_confere() {
        let mut c = Cadeia::nova(100);
        for i in 0..10 {
            c.anexar(evento(i));
        }
        assert_eq!(c.verificar(), Ok(c.cabeca()));
        assert_eq!(c.ultima_seq(), 10);
    }

    /// Cada campo, mudado sozinho num registro do meio, quebra a cadeia
    /// ali.
    #[test]
    fn qualquer_mudanca_quebra() {
        let mut c = Cadeia::nova(100);
        for i in 0..5 {
            c.anexar(evento(i));
        }
        let original: Vec<Registro> = copiar(c.ultimos(5));
        let mudancas: [fn(&mut Evento); 10] = [
            |e| e.ts_ms += 1,
            |e| e.titular = Titular::Pessoa,
            |e| e.sessao = 3,
            |e| e.sessao_de_pessoa = Some([0; 8]),
            |e| e.agente.push('x'),
            |e| e.chave = None,
            |e| e.papel = "sistema".to_string(),
            |e| e.codigo = Codigo::DenyPermission,
            |e| e.parametros[0] ^= 1,
            |e| e.detalhe.push('x'),
        ];
        for (i, mudar) in mudancas.iter().enumerate() {
            let mut copia = original.clone();
            mudar(&mut copia[2].evento);
            assert_eq!(verificar(GENESE, copia.iter()), Err(3), "mudanca {i}");
        }
        // Tirar um registro do meio também.
        let mut sem = original.clone();
        sem.remove(2);
        assert!(verificar(GENESE, sem.iter()).is_err());
    }

    /// Com o anel cheio, os mais velhos saem e a janela que sobra confere a
    /// partir da âncora.
    #[test]
    fn anel_guarda_a_ancora() {
        let mut c = Cadeia::nova(4);
        for i in 0..10 {
            c.anexar(evento(i));
        }
        assert_eq!(c.guardados(), 4);
        assert_ne!(c.ancora(), GENESE);
        assert_eq!(c.verificar(), Ok(c.cabeca()));
        assert_eq!(c.ultimos(10).next().map(|r| r.seq), Some(7));
    }

    /// O nome do titular vai e volta, e o número de cada um é a posição
    /// dele: é o número que entra no elo.
    #[test]
    fn titular_vai_e_volta() {
        for (i, t) in Titular::TODOS.into_iter().enumerate() {
            assert_eq!(t as usize, i);
            assert_eq!(Titular::de_nome(t.nome()), Some(t));
        }
        assert_eq!(Titular::de_nome("pessoa"), None);
    }

    fn variado(i: u64) -> Evento {
        let mut e = evento(i);
        if i.is_multiple_of(2) {
            e.titular = Titular::Pessoa;
            e.sessao_de_pessoa = Some([i as u8; 8]);
            e.chave = None;
            e.agente = "pessoa:00112233aabbccdd".to_string();
        }
        if i.is_multiple_of(3) {
            e.codigo = Codigo::TODOS[(i as usize) % Codigo::TODOS.len()];
            e.detalhe = "ação recusada é".to_string();
            e.recurso = String::new();
        }
        e
    }

    /// Um registro vai ao journal e volta igual, com cada campo opcional
    /// presente e ausente, e texto que não é ASCII.
    #[test]
    fn o_registro_vai_e_volta() {
        for i in 0..12 {
            let e = variado(i);
            let b = codificar(i + 40, &e);
            assert_eq!(decodificar(&b), Ok((i + 40, e)), "registro {i}");
        }
    }

    /// Cortado em qualquer ponto, ou com um byte a mais, não se lê. Um
    /// titular, um código ou uma marca de presença que não existem, e
    /// texto que não é UTF-8, também não.
    #[test]
    fn o_registro_estragado_nao_se_le() {
        let e = variado(6);
        let b = codificar(9, &e);
        for n in 0..b.len() {
            assert!(decodificar(&b[..n]).is_err(), "cortado em {n}");
        }
        let mut mais = b.clone();
        mais.push(0);
        assert!(decodificar(&mais).is_err());

        // Os deslocamentos: seq 8, ts 8, titular, sessão, marca da sessão
        // de pessoa.
        let mut b2 = b.clone();
        b2[16] = Titular::TODOS.len() as u8;
        assert!(decodificar(&b2).is_err(), "titular");
        let mut b2 = b.clone();
        b2[18] = 2;
        assert!(decodificar(&b2).is_err(), "marca");
        // Sem sessão de pessoa e sem chave, o código vem logo depois das
        // duas marcas.
        let mut e3 = evento(1);
        e3.chave = None;
        let b3 = codificar(1, &e3);
        let mut b4 = b3.clone();
        b4[20] = Codigo::TODOS.len() as u8;
        assert!(decodificar(&b4).is_err(), "codigo");
        let mut b4 = b3.clone();
        b4[19] = 7;
        assert!(decodificar(&b4).is_err(), "marca da chave");
        // O primeiro byte do nome do agente, trocado por um que não abre
        // caractere UTF-8.
        let mut b4 = b3.clone();
        b4[21 + 32 + 2] = 0xFF;
        assert!(decodificar(&b4).is_err(), "utf-8");
        assert!(decodificar(&b3).is_ok());
    }

    /// O journal refaz a mesma cadeia: a mesma sequência, os mesmos elos,
    /// e o registro seguinte ganha o mesmo elo dos dois lados.
    #[test]
    fn a_cadeia_reposta_e_a_mesma() {
        let mut a = Cadeia::nova(100);
        for i in 0..10 {
            a.anexar(variado(i));
        }
        let gravado: Vec<Vec<u8>> = a.ultimos(10).map(|r| codificar(r.seq, &r.evento)).collect();
        let mut b = Cadeia::nova(100);
        for g in &gravado {
            let (seq, e) = decodificar(g).unwrap();
            b.repor(seq, e).unwrap();
        }
        assert_eq!(b.cabeca(), a.cabeca());
        assert_eq!(b.ultima_seq(), a.ultima_seq());
        assert_eq!(a.anexar(evento(99)), b.anexar(evento(99)));
        assert_eq!(a.cabeca(), b.cabeca());
    }

    /// A reposição recusa o que um journal autêntico não traz: a sequência
    /// pulada ou repetida, o tempo que volta, o detalhe acima do teto.
    #[test]
    fn repor_fora_da_regra_e_recusado() {
        let mut c = Cadeia::nova(10);
        c.repor(1, evento(5)).unwrap();
        assert!(c.repor(1, evento(6)).is_err(), "repetida");
        assert!(c.repor(3, evento(6)).is_err(), "pulada");
        assert!(c.repor(2, evento(4)).is_err(), "tempo voltando");
        let mut longo = evento(6);
        longo.detalhe = "x".repeat(MAIOR_DETALHE + 1);
        assert!(c.repor(2, longo).is_err(), "detalhe");
        let mut no_teto = evento(6);
        no_teto.detalhe = "x".repeat(MAIOR_DETALHE);
        c.repor(2, no_teto).unwrap();
        // O mesmo tempo do anterior vale.
        c.repor(3, evento(6)).unwrap();
        assert_eq!(c.ultima_seq(), 3);
    }

    /// O detalhe composto é o de sempre quando cabe; acima do teto, o texto
    /// encolhe — numa fronteira de caractere — e a citação da decisão fica
    /// inteira no fim, sem nunca virar o número de outro registro.
    #[test]
    fn o_detalhe_composto_guarda_a_citacao() {
        let pelo = "pelo processo 1707 (fluxos 91d8d1d6)";
        // Cabe: o formato de sempre.
        assert_eq!(detalhe_composto(None, "", ""), "");
        assert_eq!(detalhe_composto(None, "x", ""), "x");
        assert_eq!(detalhe_composto(Some(pelo), "", ""), pelo);
        assert_eq!(
            detalhe_composto(Some(pelo), "x", "; decisao 9"),
            alloc::format!("{pelo}: x; decisao 9")
        );
        assert_eq!(
            detalhe_composto(Some(pelo), "", "; decisao 9"),
            alloc::format!("{pelo}: ; decisao 9")
        );
        assert_eq!(detalhe_composto(None, "x", "; decisao 9"), "x; decisao 9");
        // O caso da suíte completa: o texto da gravação, longo, e a decisão
        // 55876 — o corte do fim a deixava `decisao 5587`. O nome do
        // programa sai antes do texto, que fica inteiro: o corte o deixava
        // `versoes 581..5`, outro número também.
        let texto = "lote a gravar: 1 operacoes, versoes 581..582";
        let d = detalhe_composto(Some(pelo), texto, "; decisao 55876");
        assert_eq!(
            d,
            "pelo processo 1707 (? 91d8d1d6): lote a gravar: 1 operacoes, versoes 581..582; decisao 55876"
        );
        let mut c = Cadeia::nova(4);
        let mut e = evento(1);
        e.detalhe = d.clone();
        let n = c.anexar(e);
        assert_eq!(
            c.ultimos(1)
                .next()
                .map(|r| (r.seq, r.evento.detalhe.clone())),
            Some((n, d))
        );
        // Sem processo, o mesmo: o texto perde o fim numa palavra inteira,
        // com a marca, e a citação fica.
        let longo = "yy ".repeat(MAIOR_DETALHE / 3);
        let d = detalhe_composto(None, &longo, "; decisao 18446744073709551615");
        assert_eq!(
            d,
            alloc::format!("{}?; decisao 18446744073709551615", "yy ".repeat(21))
        );
        // A palavra seguinte, com a marca, não caberia.
        assert!(d.len() <= MAIOR_DETALHE && d.len() + "yy ".len() > MAIOR_DETALHE);
        // O corte cai num espaço — uma fronteira de caractere: `ç` e `ã` têm
        // dois bytes. O nome já saiu, e o texto ainda não cabia.
        for extra in 0..4 {
            let texto = alloc::format!("{}{}", "a".repeat(extra), "ação ".repeat(30));
            let d = detalhe_composto(Some(pelo), &texto, "; decisao 123");
            assert!(d.len() <= MAIOR_DETALHE, "{d}");
            assert!(d.ends_with(" ?; decisao 123"), "{d}");
            assert!(d.starts_with("pelo processo 1707 (? 91d8d1d6): "), "{d}");
            let guardado = texto_de(&d, "; decisao 123")
                .strip_suffix(MARCA_DO_CORTE)
                .expect("a marca do corte");
            assert!(texto.starts_with(&alloc::format!("{guardado} ")), "{d}");
            // A palavra seguinte, com a marca, não caberia.
            assert!(d.len() + "ação ".len() > MAIOR_DETALHE, "{d}");
        }
        // Sem citação, igual: a descrição encolhe antes, e o texto perde o
        // fim numa palavra inteira, com a marca — o anel não corta nada.
        let d = detalhe_composto(Some(pelo), &longo, "");
        assert_eq!(
            d,
            alloc::format!("pelo processo 1707 (? 91d8d1d6): {}?", "yy ".repeat(20))
        );
        // Uma palavra só, maior que o lugar: nada dela fica.
        let d = detalhe_composto(Some(pelo), &"z".repeat(MAIOR_DETALHE), "; decisao 12");
        assert_eq!(d, "pelo processo 1707 (? 91d8d1d6): ?; decisao 12");
        // Quem pediu sem a forma de um processo não encolhe pela
        // descrição: o texto todo some antes de quem pediu encolher; e quem
        // pediu encolhe antes da citação, que nunca encolhe.
        let d = detalhe_composto(Some(&"p".repeat(74)), "texto", "; decisao 1234567890");
        assert_eq!(
            d,
            alloc::format!("{}: ; decisao 1234567890", "p".repeat(74))
        );
        let d = detalhe_composto(Some(&"p".repeat(90)), "texto", "; decisao 1234567890");
        assert_eq!(d, alloc::format!("{}; decisao 1234567890", "p".repeat(76)));
    }

    /// O texto de um detalhe composto com `citacao`: o que vem depois de
    /// quem pediu e antes da citação — como o NSF o lê.
    fn texto_de<'a>(d: &'a str, citacao: &str) -> &'a str {
        let antes = d.strip_suffix(citacao).expect("a citacao no fim");
        antes.split_once("): ").map_or(antes, |(_, texto)| texto)
    }

    /// O achado F1: acima do teto, a descrição do programa que pediu
    /// encolhe antes do texto — o nome, depois o editor —, e o motivo da
    /// execução chega inteiro, reconhecido, com a decisão de seis dígitos ou
    /// mais; o corte de antes o levava, e o NSF não via o código
    /// adulterado.
    #[test]
    fn a_descricao_encolhe_antes_do_motivo() {
        use crate::procedencia::{Falta, nao_confiado};
        // O cenário do achado: `loja`, de `duke-oficial`, no fio 1234, com
        // a decisão 123456. O nome sai, e o editor fica.
        let d = detalhe_composto(
            Some("pelo processo 1234 (loja abcd1234 de duke-oficial)"),
            Falta::NaoConfere.motivo(),
            "; decisao 123456",
        );
        assert_eq!(
            d,
            "pelo processo 1234 (? abcd1234 de duke-oficial): o selo nao confere com o codigo; decisao 123456"
        );
        assert_eq!(d.len(), MAIOR_DETALHE);
        // O nome e o editor mais longos que se aceitam: os dois saem.
        let nome = "n".repeat(crate::manifesto::MAIOR_NOME);
        let editor = "e".repeat(crate::arquivo::MAIOR_NOME);
        let motivos = [
            String::from(Falta::SemSelo.motivo()),
            String::from(Falta::NaoConfere.motivo()),
            String::from(Falta::EditorDesconhecido.motivo()),
            nao_confiado("outro"),
        ];
        for (descricao, abreviada) in [
            (
                alloc::format!("{nome} abcd1234 de {editor}"),
                "? abcd1234 de ?",
            ),
            (
                alloc::format!("sem manifesto abcd1234 de {editor}"),
                "? abcd1234 de ?",
            ),
            (alloc::format!("{nome} abcd1234"), "? abcd1234"),
            (String::from("sem manifesto abcd1234"), "? abcd1234"),
        ] {
            let pelo = alloc::format!("pelo processo 1234 ({descricao})");
            for decisao in [123_456u64, 12_345_678] {
                let citacao = alloc::format!("; decisao {decisao}");
                for (f, motivo) in Falta::TODAS.into_iter().zip(&motivos) {
                    let d = detalhe_composto(Some(&pelo), motivo, &citacao);
                    // Só o que não cabe encolhe; o que encolhe leva o
                    // motivo inteiro.
                    let inteiro = composto(Some(&pelo), motivo, &citacao);
                    if inteiro.len() <= MAIOR_DETALHE {
                        assert_eq!(d, inteiro);
                    } else {
                        assert_eq!(
                            d,
                            alloc::format!("pelo processo 1234 ({abreviada}): {motivo}{citacao}")
                        );
                    }
                    assert!(d.len() <= MAIOR_DETALHE, "{d}");
                    assert_eq!(Falta::do_motivo(texto_de(&d, &citacao)), Some(f), "{d}");
                }
            }
        }
        // O nome sozinho basta quando cabe: o editor fica.
        let pelo = alloc::format!("pelo processo 1234 ({nome} abcd1234 de bancada)");
        let d = detalhe_composto(Some(&pelo), Falta::NaoConfere.motivo(), "; decisao 123456");
        assert_eq!(
            d,
            "pelo processo 1234 (? abcd1234 de bancada): o selo nao confere com o codigo; decisao 123456"
        );
        // Quem pediu sem descrição com resumo não encolhe: o texto perde o
        // fim, numa palavra inteira, com a marca.
        for pelo in [
            "pelo processo 1234 (kernel)",
            "pelo processo 1234 (sem imagem)",
            "pela relacao 5a5a5a5a, atestado 01020304",
            "pelo processo 1234 (loja abcd123 de duke)",
            "pelo processo x (loja abcd1234)",
        ] {
            let texto = "tt ".repeat(MAIOR_DETALHE / 3);
            for citacao in ["; decisao 123456", ""] {
                let d = detalhe_composto(Some(pelo), &texto, citacao);
                assert!(d.len() <= MAIOR_DETALHE, "{d}");
                assert!(d.len() + "tt ".len() > MAIOR_DETALHE, "{d}");
                assert!(d.starts_with(&alloc::format!("{pelo}: tt tt")), "{d}");
                assert!(d.ends_with(&alloc::format!("tt ?{citacao}")), "{d}");
            }
        }
        // Sem citação, a descrição encolhe igual: o motivo vai inteiro.
        let d = detalhe_composto(Some(&pelo), Falta::NaoConfere.motivo(), "");
        assert_eq!(
            d,
            alloc::format!(
                "pelo processo 1234 (? abcd1234 de bancada): {}",
                Falta::NaoConfere.motivo()
            )
        );
    }

    /// A descrição abreviada nunca é a de outro programa: o lugar do que
    /// saiu fica com `?`, que nenhum nome tem, e o resumo fica. E compor de
    /// novo a partir do que foi gravado dá o mesmo registro — quem confere
    /// uma execução a refaz assim.
    #[test]
    fn a_descricao_abreviada_nao_e_a_de_outro_programa() {
        use crate::procedencia::Falta;
        assert!(!crate::arquivo::nome_valido(OMITIDO));
        for inteira in [
            "kernel",
            "sem imagem",
            "loja abcd1234",
            "abcd1234 abcd1234",
            "sem manifesto abcd1234",
            "loja abcd1234 de duke-oficial",
            "loja abcd1234 de desconhecido",
            "sem manifesto abcd1234 de duke-oficial",
        ] {
            assert!(!descricao_abreviada(inteira), "{inteira}");
        }
        for abreviada in [
            "? abcd1234",
            "? abcd1234 de duke-oficial",
            "? abcd1234 de ?",
        ] {
            assert!(descricao_abreviada(abreviada), "{abreviada}");
        }
        let nome = "n".repeat(crate::manifesto::MAIOR_NOME);
        let editor = "e".repeat(crate::arquivo::MAIOR_NOME);
        for descricao in [
            alloc::format!("{nome} abcd1234 de {editor}"),
            alloc::format!("{nome} abcd1234 de bancada"),
            alloc::format!("{nome} abcd1234"),
            String::from("fluxos 91d8d1d6"),
        ] {
            let pelo = alloc::format!("pelo processo 1707 ({descricao})");
            for (texto, citacao) in [
                (Falta::NaoConfere.motivo(), "; decisao 55876"),
                (
                    "lote a gravar: 1 operacoes, versoes 581..582",
                    "; decisao 55876",
                ),
                (
                    "o dispositivo recusou ou devolveu algo sem sentido",
                    "; decisao 123456",
                ),
                (Falta::NaoConfere.motivo(), "; decisao 18446744073709551615"),
            ] {
                let d = detalhe_composto(Some(&pelo), texto, citacao);
                let (gravado, _) = d
                    .strip_prefix("pelo processo 1707 (")
                    .and_then(|r| r.split_once("): "))
                    .expect("o processo e o programa na frente");
                if d.len() < composto(Some(&pelo), texto, citacao).len() {
                    assert!(descricao_abreviada(gravado), "{d}");
                    assert!(gravado.contains(" abcd1234") || gravado.contains(" 91d8d1d6"));
                }
                // O código de fora da imagem não passa pelo da imagem, nem o
                // da imagem pelo de fora.
                assert_eq!(gravado.contains(" de "), descricao.contains(" de "), "{d}");
                let de_novo = detalhe_composto(
                    Some(&alloc::format!("pelo processo 1707 ({gravado})")),
                    texto,
                    citacao,
                );
                assert_eq!(de_novo, d);
            }
        }
    }

    /// O motivo que perde o fim mesmo com a descrição toda encolhida — o
    /// fio de sete dígitos e a maior decisão — ainda diz a falta: o
    /// reconhecimento guarda o começo essencial, e não pede o motivo
    /// inteiro.
    #[test]
    fn o_motivo_cortado_ainda_diz_a_falta() {
        use crate::procedencia::{Falta, nao_confiado};
        let editor = "e".repeat(crate::arquivo::MAIOR_NOME);
        let pelo = alloc::format!("pelo processo 1234567 (loja abcd1234 de {editor})");
        let citacao = "; decisao 18446744073709551615";
        let motivos = [
            String::from(Falta::SemSelo.motivo()),
            String::from(Falta::NaoConfere.motivo()),
            String::from(Falta::EditorDesconhecido.motivo()),
            nao_confiado(&editor),
        ];
        let mut cortados = 0;
        for (f, motivo) in Falta::TODAS.into_iter().zip(&motivos) {
            let d = detalhe_composto(Some(&pelo), motivo, citacao);
            assert!(d.len() <= MAIOR_DETALHE, "{d}");
            assert!(
                d.starts_with("pelo processo 1234567 (? abcd1234 de ?): "),
                "{d}"
            );
            assert!(d.ends_with(citacao), "{d}");
            let texto = texto_de(&d, citacao);
            if texto != motivo.as_str() {
                cortados += 1;
                // Cortado numa palavra inteira do motivo, com a marca.
                let guardado = texto
                    .strip_suffix(MARCA_DO_CORTE)
                    .expect("a marca do corte");
                assert!(motivo.starts_with(&alloc::format!("{guardado} ")), "{d}");
            }
            assert_eq!(Falta::do_motivo(texto), Some(f), "{d}");
        }
        // O motivo do código adulterado é um dos cortados: sem o começo
        // essencial, o NSF não o veria.
        let d = detalhe_composto(Some(&pelo), Falta::NaoConfere.motivo(), citacao);
        let texto = texto_de(&d, citacao);
        assert!(!texto.starts_with(Falta::NaoConfere.motivo()), "{d}");
        assert!(cortados >= 3, "{cortados}");
    }

    /// O resíduo do F1: acima do teto, a descrição do programa encolhe
    /// também no registro sem citação — a decisão do gate, a bifurcação —,
    /// e o texto chega inteiro: `o manifesto nao declara` (o achado 1 do
    /// adversário), o `filho N` (achado 2), o `)` da decisão cujo `pelo`
    /// sozinho passa do teto (achado 3) e o `teto` (7a). O anel cortava o
    /// fim de cada um.
    #[test]
    fn a_descricao_encolhe_tambem_sem_citacao() {
        let nome = "n".repeat(crate::manifesto::MAIOR_NOME);
        let editor = "e".repeat(crate::arquivo::MAIOR_NOME);
        // A recusa do manifesto de um código de fora de nome longo: o
        // `pelo` tem 78 bytes, e o anel deixava `o manifesto nao `.
        let pelo = alloc::format!("pelo processo 1234 ({nome} abcd1234 de duke-oficial)");
        assert_eq!(pelo.len(), 78);
        for permissao in [
            "fs.read",
            "key.sign",
            "net.observe",
            "credential.change_self",
        ] {
            let texto = alloc::format!("o manifesto nao declara {permissao}");
            assert!(composto(Some(&pelo), &texto, "").len() > MAIOR_DETALHE);
            assert_eq!(
                detalhe_composto(Some(&pelo), &texto, ""),
                alloc::format!("pelo processo 1234 (? abcd1234 de duke-oficial): {texto}")
            );
        }
        // A bifurcação, com os editores de 19 e de 21 bytes do ataque: o
        // anel deixava `filho 123` e `filho 5`. O filho vai inteiro, com
        // qualquer número de dígitos.
        for de in ["fornecedor-externo1", "fornecedor-externo-ab"] {
            let pelo = alloc::format!("pelo processo 1234 ({nome} abcd1234 de {de})");
            for filho in [1235u64, 5000, u64::MAX] {
                let texto = alloc::format!("filho {filho}");
                assert!(composto(Some(&pelo), &texto, "").len() > MAIOR_DETALHE);
                assert_eq!(
                    detalhe_composto(Some(&pelo), &texto, ""),
                    alloc::format!("pelo processo 1234 (? abcd1234 de {de}): {texto}")
                );
            }
        }
        // O `pelo` sozinho acima do teto — o maior nome e o maior editor,
        // com o fio de três dígitos ou mais: a decisão que permite, de texto
        // vazio, vai abreviada e termina no `)`; a que recusa, com o motivo
        // inteiro.
        for fio in [123u64, 1234, u64::MAX] {
            let pelo = alloc::format!("pelo processo {fio} ({nome} abcd1234 de {editor})");
            assert!(pelo.len() > MAIOR_DETALHE);
            assert_eq!(
                detalhe_composto(Some(&pelo), "", ""),
                alloc::format!("pelo processo {fio} (? abcd1234 de {editor})")
            );
            let motivo = "recurso fora do alcance do papel";
            let d = detalhe_composto(Some(&pelo), motivo, "");
            assert!(
                d == alloc::format!("pelo processo {fio} (? abcd1234 de {editor}): {motivo}")
                    || d == alloc::format!("pelo processo {fio} (? abcd1234 de ?): {motivo}"),
                "{d}"
            );
            assert!(d.len() <= MAIOR_DETALHE, "{d}");
        }
        // O motivo do teto, com o nome de 32 bytes e o editor de 13: a
        // descrição encolhe toda, e o texto perde só a última palavra — o
        // `teto` fica.
        let pelo = alloc::format!("pelo processo 1234 ({nome} abcd1234 de {})", &editor[..13]);
        let d = detalhe_composto(
            Some(&pelo),
            "o papel e o teto de um administrador: delega, nao se exerce",
            "",
        );
        assert_eq!(
            d,
            "pelo processo 1234 (? abcd1234 de ?): o papel e o teto de um administrador: delega, nao se ?"
        );
        // O que cabe não muda: a descrição inteira, com o texto.
        let pelo = "pelo processo 1234 (loja abcd1234 de duke-oficial)";
        assert_eq!(
            detalhe_composto(Some(pelo), "o manifesto nao declara fs.read", ""),
            alloc::format!("{pelo}: o manifesto nao declara fs.read")
        );
    }

    /// O achado 4 do adversário do F1: o texto que perde o fim não deixa
    /// uma palavra pela metade — o pedaço de um nome é o nome válido de
    /// outro editor, e o de um número, outro número. O corte recua até o
    /// espaço, a marca fica no lugar do que saiu, e a falta continua
    /// reconhecida.
    #[test]
    fn o_corte_nao_deixa_palavra_pela_metade() {
        use crate::procedencia::{Falta, nao_confiado};
        assert_eq!(MARCA_DO_CORTE, alloc::format!(" {OMITIDO}"));
        // O editor em quem o papel não confia, de 25 bytes, no motivo: o
        // corte de caractere deixava `fornecedor-ex`.
        let editor = "fornecedor-externo-abcdef";
        let d = detalhe_composto(
            Some(&alloc::format!(
                "pelo processo 1234 (loja abcd1234 de {editor})"
            )),
            &nao_confiado(editor),
            "; decisao 123456",
        );
        assert_eq!(
            d,
            "pelo processo 1234 (? abcd1234 de ?): o papel nao confia no editor ?; decisao 123456"
        );
        assert_eq!(
            Falta::do_motivo(texto_de(&d, "; decisao 123456")),
            Some(Falta::NaoConfiado)
        );
        // O nascimento de um código de fora, pedido por um da imagem: o
        // corte deixava `de duke-of`.
        let d = detalhe_composto(
            Some("pelo processo 94 (instalador 0a1b2c3d)"),
            "processo 1234 lancado: codigo abcd1234 de duke-oficial",
            "; decisao 123456",
        );
        assert_eq!(
            d,
            "pelo processo 94 (? 0a1b2c3d): processo 1234 lancado: codigo abcd1234 de ?; decisao 123456"
        );
        // Um número no fim: sai inteiro — o corte deixava `581..5`.
        let d = detalhe_composto(
            Some("pelo processo 1707 (fluxos 91d8d1d6)"),
            "lote a gravar: 1 operacoes, versoes 581..582",
            "; decisao 12345678901",
        );
        assert_eq!(
            d,
            "pelo processo 1707 (? 91d8d1d6): lote a gravar: 1 operacoes, versoes ?; decisao 12345678901"
        );
        // Em qualquer combinação: o detalhe cabe, a citação fica inteira no
        // fim, e o texto que perdeu o fim é um começo dele que termina numa
        // palavra inteira, com a marca — ou só a marca —, e a palavra
        // seguinte não caberia.
        let nome = "n".repeat(crate::manifesto::MAIOR_NOME);
        let maior = "e".repeat(crate::arquivo::MAIOR_NOME);
        let textos = [
            String::from(Falta::NaoConfere.motivo()),
            String::from(Falta::EditorDesconhecido.motivo()),
            nao_confiado(&maior),
            alloc::format!("processo {} lancado: codigo abcd1234 de {maior}", u64::MAX),
            String::from("o manifesto nao declara credential.change_self"),
            String::from("adiada: a ordem das gravacoes com outro fio"),
            "ação ".repeat(30),
            "z".repeat(120),
            alloc::format!("filho {}", u64::MAX),
        ];
        let pelos = [
            None,
            Some(String::from("pelo processo 7 (kernel)")),
            Some(String::from("pela relacao 5a5a5a5a, atestado 01020304")),
            Some(alloc::format!(
                "pelo processo 1234567 ({nome} abcd1234 de {maior})"
            )),
            Some(alloc::format!(
                "pelo processo {} ({nome} abcd1234)",
                u64::MAX
            )),
        ];
        for texto in &textos {
            for pelo in &pelos {
                for citacao in ["", "; decisao 123456", "; decisao 18446744073709551615"] {
                    let d = detalhe_composto(pelo.as_deref(), texto, citacao);
                    assert!(d.len() <= MAIOR_DETALHE, "{d}");
                    let antes = d.strip_suffix(citacao).expect("a citacao no fim");
                    let gravado = match pelo.as_deref() {
                        Some(p) if p.starts_with("pelo processo ") => {
                            antes.split_once("): ").expect("quem pediu").1
                        }
                        Some(p) => antes
                            .strip_prefix(&alloc::format!("{p}: "))
                            .expect("quem pediu"),
                        None => antes,
                    };
                    if gravado == texto.as_str() {
                        continue;
                    }
                    if gravado == OMITIDO {
                        let primeira = texto.split(' ').next().unwrap_or_default();
                        assert!(
                            d.len() - OMITIDO.len() + primeira.len() + MARCA_DO_CORTE.len()
                                > MAIOR_DETALHE,
                            "{d}"
                        );
                        continue;
                    }
                    let guardado = gravado.strip_suffix(MARCA_DO_CORTE).expect("a marca");
                    assert!(
                        texto.starts_with(&alloc::format!("{guardado} ")),
                        "{d} / {texto}"
                    );
                    if let Some(proximo) = texto[guardado.len() + 1..].find(' ') {
                        assert!(d.len() + proximo + 1 > MAIOR_DETALHE, "{d} / {texto}");
                    }
                }
            }
        }
    }

    /// O começo do resumo de uma descrição, inteira ou abreviada; nenhum
    /// para a descrição sem resumo ou fora da forma.
    #[test]
    fn o_resumo_da_descricao() {
        for (descricao, resumo) in [
            ("loja abcd1234", Some("abcd1234")),
            ("loja abcd1234 de duke-oficial", Some("abcd1234")),
            ("sem manifesto abcd1234", Some("abcd1234")),
            ("sem manifesto abcd1234 de duke", Some("abcd1234")),
            ("? abcd1234", Some("abcd1234")),
            ("? abcd1234 de duke-oficial", Some("abcd1234")),
            ("? abcd1234 de ?", Some("abcd1234")),
            ("kernel", None),
            ("sem imagem", None),
            ("loja abcd123", None),
            ("loja abcd1234 do x", None),
            ("loja ABCD1234", None),
        ] {
            assert_eq!(resumo_da_descricao(descricao), resumo, "{descricao}");
        }
    }

    /// O tempo de um registro nunca fica abaixo do anterior, nem depois de
    /// o anterior sair do anel.
    #[test]
    fn o_tempo_nao_volta() {
        let mut c = Cadeia::nova(1);
        c.anexar(evento(10));
        c.anexar(evento(3));
        assert_eq!(c.ultimos(1).next().unwrap().evento.ts_ms, 100);
        c.anexar(evento(20));
        assert_eq!(c.ultimos(1).next().unwrap().evento.ts_ms, 200);
    }

    /// O que sai do anel antes de ser gravado vira uma lacuna, com o elo
    /// do último perdido; o journal com a lacuna refaz a mesma cabeça.
    #[test]
    fn o_anel_que_perde_deixa_uma_lacuna() {
        let mut a = Cadeia::nova(4);
        for i in 0..10 {
            a.anexar(variado(i));
        }
        // Gravados até a 2: a 3 a 6 saíram do anel sem chegar ao journal.
        let falta = a.a_gravar(2);
        let lacuna = falta.lacuna.unwrap();
        assert_eq!((lacuna.primeira, lacuna.ultima), (3, 6));
        assert_eq!(lacuna.elo, a.ancora());
        let seqs: Vec<u64> = falta.registros.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, [7, 8, 9, 10]);

        let mut b = Cadeia::nova(4);
        for i in 0..2 {
            b.repor(i + 1, variado(i)).unwrap();
        }
        assert!(
            b.pular(Lacuna {
                primeira: 4,
                ..lacuna
            })
            .is_err(),
            "fora de sequencia"
        );
        assert!(
            b.pular(Lacuna {
                ultima: 2,
                ..lacuna
            })
            .is_err(),
            "ao contrario"
        );
        b.pular(lacuna).unwrap();
        for r in &falta.registros {
            b.repor(r.seq, r.evento.clone()).unwrap();
        }
        assert_eq!(b.cabeca(), a.cabeca());
        assert_eq!(b.verificar(), Ok(a.cabeca()));

        // Sem nada perdido, não há lacuna; com tudo gravado, nada falta.
        assert!(a.a_gravar(6).lacuna.is_none());
        assert_eq!(a.a_gravar(6).registros.len(), 4);
        assert!(a.a_gravar(10).registros.is_empty());
        assert!(a.a_gravar(10).lacuna.is_none());
    }

    /// O boot continua a cadeia do journal com o que registrou antes de
    /// lê-lo: as sequências seguem, e o tempo sobe ao do journal.
    #[test]
    fn continuar_com_o_que_veio_antes() {
        let mut journal = Cadeia::nova(10);
        for i in 0..3 {
            journal.anexar(evento(i + 50));
        }
        let mut boot = Cadeia::nova(10);
        boot.anexar(evento(1));
        boot.anexar(evento(2));
        journal.continuar_com(&boot);
        assert_eq!(journal.ultima_seq(), 5);
        let ultimos: Vec<&Registro> = journal.ultimos(2).collect();
        assert_eq!(ultimos[0].evento.metodo, "fs.read");
        assert!(ultimos.iter().all(|r| r.evento.ts_ms == 520));
        assert_eq!(journal.verificar(), Ok(journal.cabeca()));
    }

    #[test]
    fn detalhe_tem_teto() {
        let mut c = Cadeia::nova(4);
        let mut e = evento(0);
        e.detalhe = "é".repeat(100);
        c.anexar(e);
        let d = &c.ultimos(1).next().unwrap().evento.detalhe;
        assert!(d.len() <= MAIOR_DETALHE);
    }

    /// Eventos de todos os tamanhos: cada campo opcional presente e
    /// ausente, texto que não é ASCII, os cinco textos vazios — o menor — e
    /// um texto acima do teto de um campo, com um caractere de dois bytes
    /// em cima do corte.
    fn de_todos_os_tamanhos() -> Vec<Evento> {
        let mut v: Vec<Evento> = (0..12).map(variado).collect();
        let mut menor = evento(0);
        menor.sessao_de_pessoa = None;
        menor.chave = None;
        menor.agente = String::new();
        menor.papel = String::new();
        menor.metodo = String::new();
        menor.recurso = String::new();
        menor.detalhe = String::new();
        v.push(menor);
        let mut enorme = evento(1);
        enorme.recurso = "x".repeat(u16::MAX as usize - 1) + "é" + "fim";
        v.push(enorme);
        v
    }

    /// O tamanho dito é o da codificação, para todo evento — com o corte
    /// do texto acima do teto inclusive —, e nunca menos que o menor; o
    /// evento de textos vazios e sem os opcionais é o menor.
    #[test]
    fn o_tamanho_codificado_e_o_da_codificacao() {
        let eventos = de_todos_os_tamanhos();
        for (i, e) in eventos.iter().enumerate() {
            let n = codificar(i as u64 + 1, e).len();
            assert_eq!(tamanho_codificado(e), n, "evento {i}");
            assert!(n >= MENOR_CODIFICADO, "evento {i}");
        }
        assert_eq!(tamanho_codificado(&eventos[12]), MENOR_CODIFICADO);
        // O texto acima do teto vai cortado antes do caractere que o
        // atravessaria: os 65 534 `x`, e nada do `é`.
        let enorme = &eventos[13];
        assert_eq!(
            tamanho_codificado(enorme) - tamanho_codificado(&evento(1)),
            u16::MAX as usize - 1 - evento(1).recurso.len()
        );
    }

    /// `codificar_em` acrescenta exatamente o que `codificar` dá, um
    /// depois do outro, sem mexer no que já estava; e, com o lugar
    /// reservado antes pelo tamanho dito, não troca de memória: nenhum
    /// pedido ao alocador no meio.
    #[test]
    fn codificar_em_acrescenta_o_mesmo_sem_alocar() {
        let eventos = de_todos_os_tamanhos();
        let total: usize = 3 + eventos.iter().map(tamanho_codificado).sum::<usize>();
        let mut v = Vec::with_capacity(total);
        v.extend_from_slice(b"abc");
        let antes = v.as_ptr();
        let mut esperado = b"abc".to_vec();
        for (i, e) in eventos.iter().enumerate() {
            codificar_em(&mut v, i as u64 + 7, e);
            esperado.extend_from_slice(&codificar(i as u64 + 7, e));
        }
        assert_eq!(v, esperado);
        assert_eq!(v.len(), total);
        assert_eq!(v.as_ptr(), antes, "a codificacao trocou de memoria");
        // E volta: cada um, lido do lugar dele, é o evento de antes — o
        // de texto acima do teto, cortado.
        let mut inicio = 3;
        for (i, e) in eventos.iter().enumerate().take(13) {
            let fim = inicio + tamanho_codificado(e);
            assert_eq!(decodificar(&v[inicio..fim]), Ok((i as u64 + 7, e.clone())));
            inicio = fim;
        }
    }

    /// Os guardados depois de uma sequência e até ela, achados pela
    /// posição — sem passar pela janela —, são os mesmos que o filtro pela
    /// sequência dá: sem nenhum guardado, com a janela pela metade, depois
    /// de o anel dar a volta e depois de uma lacuna reposta. E a lacuna
    /// depois de uma sequência é a de [`Cadeia::a_gravar`].
    #[test]
    fn antes_e_depois_pela_posicao_sao_os_do_filtro() {
        fn confere(c: &Cadeia, ate: u64) {
            let todos: Vec<u64> = c.ultimos(usize::MAX).map(|r| r.seq).collect();
            for g in 0..=ate + 2 {
                let depois: Vec<u64> = c.guardados_depois_de(g).map(|r| r.seq).collect();
                let antes: Vec<u64> = c.guardados_ate(g).map(|r| r.seq).collect();
                let filtro = |f: &dyn Fn(u64) -> bool| -> Vec<u64> {
                    todos.iter().copied().filter(|s| f(*s)).collect()
                };
                assert_eq!(depois, filtro(&|s: u64| s > g), "depois de {g}");
                assert_eq!(antes, filtro(&|s: u64| s <= g), "ate {g}");
                let falta = c.a_gravar(g);
                let seqs: Vec<u64> = falta.registros.iter().map(|r| r.seq).collect();
                assert_eq!(seqs, depois, "a gravar depois de {g}");
                assert_eq!(falta.lacuna, c.lacuna_depois_de(g), "lacuna depois de {g}");
            }
            // A sequência mais alta que há não passa do fim, nem dá a volta.
            assert_eq!(c.guardados_depois_de(u64::MAX).count(), 0);
            assert_eq!(c.guardados_ate(u64::MAX).count(), todos.len());
            assert_eq!(c.lacuna_depois_de(u64::MAX), None);
            assert!(c.a_gravar(u64::MAX).lacuna.is_none());
        }
        let mut c = Cadeia::nova(4);
        confere(&c, 0);
        for i in 0..3 {
            c.anexar(variado(i));
        }
        confere(&c, 3);
        for i in 3..10 {
            c.anexar(variado(i));
        }
        confere(&c, 10);
        assert_eq!(
            c.lacuna_depois_de(2).map(|l| (l.primeira, l.ultima)),
            Some((3, 6))
        );
        let mut b = Cadeia::nova(4);
        b.pular(Lacuna {
            primeira: 1,
            ultima: 5,
            elo: [3; 32],
        })
        .unwrap();
        confere(&b, 6);
        b.anexar(variado(1));
        confere(&b, 7);
    }
}
