//! O que os registros do estado administrativo dizem.
//!
//! # Resultados, e não pedidos
//!
//! Um registro guarda o **resultado** de uma mudança de autoridade — o
//! agente registrado, a política inteira em vigor depois do
//! `policy.write`, a credencial revogada — e não o pedido que a causou.
//! Reaplicar um pedido no boot exigiria que tudo em volta dele estivesse
//! igual ao que era: a política da imagem, as regras de quem pode mudar o
//! quê. Reaplicar um resultado é só pô-lo de volta.
//!
//! # O formato
//!
//! O conteúdo de um registro é uma lista de campos, cada um com dois bytes
//! de tamanho e os bytes. Os campos de cada tipo e o que significam estão
//! em [`tipo`]; quem os interpreta é o kernel, com os mesmos leitores que
//! leem os arquivos da imagem — a linha de um agente é a linha do arquivo
//! de agentes, a política é o texto do arquivo de política. Um segundo
//! formato para a mesma coisa seria um segundo leitor, e o primeiro a
//! divergir.

use alloc::vec::Vec;

/// Os tipos de registro, e os campos de cada um.
pub mod tipo {
    /// O primeiro registro do journal: `[instalação (16 bytes)]`. O
    /// identificador da instalação é sorteado quando o journal nasce.
    pub const ABERTURA: u16 = 1;
    /// Um boot: `[quantos boots, u64 LE]`. Mantém o piso do relógio, e
    /// conta os boots.
    pub const BOOT: u16 = 2;
    /// Uma operação de autoridade e o que ela mudou: uma lista de entradas,
    /// cada uma com o tipo (dois bytes) e os campos dela — os tipos abaixo.
    /// A primeira entrada é sempre esta mesma, `[operação, recurso]`: o que
    /// foi pedido e sobre o quê, para o journal contar a operação mesmo
    /// quando ela não deixa rastro no estado.
    ///
    /// Uma operação, um registro: as mudanças dela entram juntas ou não
    /// entram.
    pub const OPERACAO: u16 = 3;
    /// O que uma operação de mensagem mudou: as entradas
    /// [`MENSAGEM_CRIADA`] e [`MENSAGEM_ESTADO`], na ordem em que
    /// aconteceram. Não sobe a geração: uma mensagem não é autoridade.
    pub const MENSAGENS: u16 = 4;
    /// Só auditoria: os registros da cadeia que nenhum outro registro
    /// levou ainda — [`AUDITORIA_EVENTO`] e [`AUDITORIA_LACUNA`]. Não sobe a
    /// geração.
    ///
    /// Todo registro do journal, de qualquer tipo, leva também, no fim, as
    /// entradas da auditoria que ainda não estão no disco, na ordem da
    /// cadeia: a decisão que autorizou uma operação vai no registro da
    /// operação. Este tipo é para quando nada mais é gravado.
    ///
    /// É o único tipo que **não avança** o contador do TPM — ver
    /// [`avanca_a_ancora`]: ele leva a mesma âncora do registro anterior.
    pub const AUDITORIA: u16 = 5;
    /// Uma parte da base de uma região: uma lista de entradas, como as de
    /// [`OPERACAO`]. A base é o que uma compactação escreve no começo da
    /// região nova — o estado inteiro, de uma vez — e tem uma ou mais
    /// partes, todas com a mesma âncora, e um fecho. Ver [`BASE_FIM`].
    pub const BASE: u16 = 6;
    /// O fecho da base: `[instalação (16), quantos boots (8), quantas
    /// compactações (8)]`. Uma região que começa por uma base só vale com o
    /// fecho: sem ele, a compactação não terminou, e a região é ignorada.
    pub const BASE_FIM: u16 = 7;

    /// Um agente entrou no registro: `[a linha do arquivo de agentes]`.
    pub const AGENTE_REGISTRADO: u16 = 10;
    /// Um agente saiu do registro: `[a chave X25519]`.
    pub const AGENTE_REVOGADO: u16 = 11;
    /// O papel de um agente mudou: `[nome, papel]`.
    pub const PAPEL_ATRIBUIDO: u16 = 12;
    /// A política em vigor: `[o texto inteiro]`.
    pub const POLITICA: u16 = 13;
    /// Uma pessoa entrou no registro: `[a linha do arquivo de pessoas]`.
    pub const PESSOA_REGISTRADA: u16 = 14;
    /// Uma pessoa foi revogada: `[o identificador, 8 bytes]`.
    pub const PESSOA_REVOGADA: u16 = 15;
    /// A credencial de uma pessoa mudou: `[a linha do arquivo de pessoas,
    /// já com a nova]`.
    pub const CREDENCIAL_ROTACIONADA: u16 = 16;
    /// Uma sessão de pessoa foi encerrada: `[o identificador, 8 bytes]`.
    ///
    /// As sessões não sobrevivem a um boot, e o registro não muda nada ao
    /// ser relido. Ele existe porque a operação mudou o estado de
    /// autoridade enquanto o sistema estava de pé, e a geração conta isso.
    pub const SESSAO_REVOGADA: u16 = 17;
    /// A lápide de uma credencial administrativa: `[a chave X25519, a
    /// pública Ed25519 ou nada]`. Permanente: nenhum registro a desfaz,
    /// nenhuma imagem a apaga. Quem revogou e por quê não está aqui: está
    /// na auditoria, que guarda a decisão do quórum.
    pub const LAPIDE: u16 = 18;

    /// Uma mensagem aceita: `[id (8 bytes), remetente, destinatário, criada
    /// em ms (8), vence em ms (8), corpo]`. Os titulares vão como um byte
    /// de tipo e a chave ou o identificador. Nasce pendente, na versão 1.
    ///
    /// O corpo vai no registro como qualquer outro campo — cifrado com ele:
    /// o disco não vê o texto de uma mensagem.
    pub const MENSAGEM_CRIADA: u16 = 20;
    /// Uma mensagem mudou de estado: `[id (8), estado (1 byte), versão
    /// (8)]`. Num estado final, o corpo some — dali em diante o journal
    /// só lembra que ela existiu.
    pub const MENSAGEM_ESTADO: u16 = 21;

    /// Um registro da cadeia da auditoria: `[o registro codificado]`, como
    /// `politica::auditoria::codificar` o escreve — a sequência e o evento;
    /// o elo, quem lê refaz. Os parâmetros do pedido vão só como
    /// resumo, como na memória.
    pub const AUDITORIA_EVENTO: u16 = 22;
    /// Registros da auditoria que saíram do anel da memória antes de chegar
    /// ao disco: `[primeira sequência (8), última (8), elo da última
    /// (32)]`. A cadeia continua desse elo, e a lacuna diz o que falta.
    pub const AUDITORIA_LACUNA: u16 = 23;
    /// Na base de uma região: a cadeia da auditoria começa depois daqui —
    /// `[primeira (8), última (8), elo da última (32)]`, como a lacuna. Os
    /// registros de antes estavam no journal, e a compactação os deixou na
    /// região velha; a cadeia continua verificável a partir do elo.
    pub const AUDITORIA_COMPACTADA: u16 = 24;
    /// Na base de uma região: a decisão que autorizou uma mudança de
    /// autoridade que a base leva — `[o registro da auditoria codificado]`.
    /// Ela vai na mesma parte que a mudança: uma mudança de autoridade não
    /// fica no journal sem a decisão dela, nem depois de compactada. Não
    /// volta para a cadeia — a cadeia continua de outro ponto —, e está ali
    /// para quem lê o journal.
    pub const AUDITORIA_HISTORICA: u16 = 25;
    /// Na base: uma mensagem que já saiu, para o `message.status` — `[id
    /// (8), remetente, destinatário, estado (1), versão (8)]`.
    pub const MENSAGEM_LAPIDE: u16 = 26;
    /// Na base: o próximo id de mensagem — `[id (8)]`. Os ids não se
    /// repetem, nem depois de as mensagens que os usaram saírem.
    pub const MENSAGENS_PROXIMO: u16 = 27;
    /// Na abertura e no registro de boot: o ponto público da chave de
    /// endosso do TPM com que o journal fala — `[x ‖ y (64)]`. A EK que
    /// um boot encontra tem de ser esta: outra é outro TPM, ou alguém no
    /// barramento fingindo ser ele. O fecho de uma base leva o mesmo ponto
    /// como quarto campo.
    pub const CHAVE_DO_TPM: u16 = 28;

    /// Se um registro de tipo `tipo` avança o contador do TPM — se ele é uma
    /// transição do estado que a âncora protege.
    ///
    /// O journal e a auditoria são persistência e histórico; o contador é
    /// a monotonicidade do estado de segurança. Avançam o contador os
    /// registros cuja volta a um estado anterior seria um rollback desse
    /// estado: a abertura, cada boot, cada operação de autoridade, cada
    /// mudança de mensagem — e a base, no fecho, que troca a região que
    /// vale. Um registro só de auditoria — leituras, recusas, o que o
    /// coletor grava de tempos em tempos — não muda estado protegido, e não
    /// gasta o contador: um TPM físico aguenta um número finito de escritas
    /// no NV.
    ///
    /// Quem decide é o tipo, e não quem grava: o leitor exige a mesma
    /// âncora num registro só de auditoria e a seguinte em todo outro, e o
    /// escritor só confirma sem o contador um registro que não o avança.
    pub const fn avanca_a_ancora(tipo: u16) -> bool {
        tipo != AUDITORIA
    }
}

/// Monta o conteúdo de um registro a partir dos campos.
pub fn campos(lista: &[&[u8]]) -> Result<Vec<u8>, &'static str> {
    let mut v = Vec::new();
    for c in lista {
        let n = u16::try_from(c.len()).map_err(|_| "campo maior que 64 KiB")?;
        v.extend_from_slice(&n.to_le_bytes());
        v.extend_from_slice(c);
    }
    Ok(v)
}

/// Os campos de um conteúdo. Recusa o que não termina exatamente no fim
/// do último campo.
pub fn ler_campos(conteudo: &[u8]) -> Result<Vec<&[u8]>, &'static str> {
    let mut v = Vec::new();
    let mut i = 0usize;
    while i < conteudo.len() {
        let tamanho = conteudo.get(i..i + 2).ok_or("campo sem tamanho inteiro")?;
        let n = u16::from_le_bytes([tamanho[0], tamanho[1]]) as usize;
        i += 2;
        let campo = conteudo.get(i..i + n).ok_or("campo maior que o conteudo")?;
        v.push(campo);
        i += n;
    }
    Ok(v)
}

/// Os campos de um conteúdo, exigindo exatamente `N`.
pub fn exatamente<const N: usize>(conteudo: &[u8]) -> Result<[&[u8]; N], &'static str> {
    let v = ler_campos(conteudo)?;
    v.try_into()
        .map_err(|_| "numero de campos errado para o tipo")
}
