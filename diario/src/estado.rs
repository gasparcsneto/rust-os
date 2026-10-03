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
    /// pública Ed25519 ou nada, o resumo do desafio do quórum (32 bytes),
    /// o motivo]`. Permanente: nenhum registro a desfaz, nenhuma imagem a
    /// apaga.
    pub const LAPIDE: u16 = 18;
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
