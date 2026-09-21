//! JSON sem alocação, para uso dentro do kernel.
//!
//! # Por que não usar `serde_json`
//!
//! Nesta fase o kernel ainda **não tem heap**. O alocador só entra na fase 0
//! tardia, depois da paginação — mas o canal do agente precisa funcionar
//! muito antes disso, justamente para nos ajudar a depurar a paginação.
//!
//! Então este módulo resolve o problema com duas estratégias que dispensam
//! completamente alocação dinâmica:
//!
//! - **Escrita em streaming** ([`JsonWriter`]): serializamos direto para a
//!   porta serial, token a token. Nunca existe um documento montado em
//!   memória, então não há o que alocar. O custo é que a estrutura precisa
//!   ser escrita em ordem — não dá para voltar atrás.
//!
//! - **Leitura por varredura** ([`Json`]): em vez de construir uma árvore de
//!   nós, guardamos apenas uma fatia dos bytes originais e procuramos as
//!   chaves sob demanda. `member("method")` varre o texto e devolve outra
//!   fatia. Zero cópias, zero alocações.
//!
//! Quando o heap existir, dá para trocar por `serde` sem mudar o protocolo.

use core::fmt;

// ---------------------------------------------------------------------------
// Escrita
// ---------------------------------------------------------------------------

/// Serializador JSON em streaming.
///
/// Escreve direto num sink (na prática, a COM2). O tipo do sink é
/// `&mut dyn fmt::Write` em vez de um parâmetro genérico de propósito: os
/// handlers de comando são guardados como ponteiros de função numa tabela
/// estática, e ponteiros de função não podem ser genéricos.
pub struct JsonWriter<'w> {
    sink: &'w mut dyn fmt::Write,
    /// Nível de aninhamento atual.
    depth: u32,
    /// Um bit por nível: ligado quando já escrevemos ao menos um elemento
    /// naquele nível, ou seja, o próximo precisa de uma vírgula antes.
    ///
    /// Um `u32` como bitmask evita manter uma pilha (que precisaria de
    /// alocação) e ainda nos dá 32 níveis de aninhamento — muito além do que
    /// qualquer resposta nossa precisa.
    pending: u32,
    /// Acabamos de escrever uma chave, então o próximo token é o valor dela e
    /// *não* deve ser precedido de vírgula.
    expect_value: bool,
}

impl<'w> JsonWriter<'w> {
    pub fn new(sink: &'w mut dyn fmt::Write) -> Self {
        Self {
            sink,
            depth: 0,
            pending: 0,
            expect_value: false,
        }
    }

    /// Emite a vírgula separadora quando necessário.
    fn sep(&mut self) -> fmt::Result {
        if self.expect_value {
            self.expect_value = false;
            return Ok(());
        }
        let bit = 1u32 << (self.depth & 31);
        if self.pending & bit != 0 {
            self.sink.write_str(",")?;
        } else {
            self.pending |= bit;
        }
        Ok(())
    }

    pub fn begin_object(&mut self) -> fmt::Result {
        self.sep()?;
        self.sink.write_str("{")?;
        self.depth += 1;
        self.pending &= !(1u32 << (self.depth & 31));
        Ok(())
    }

    pub fn end_object(&mut self) -> fmt::Result {
        self.depth = self.depth.saturating_sub(1);
        self.sink.write_str("}")
    }

    pub fn begin_array(&mut self) -> fmt::Result {
        self.sep()?;
        self.sink.write_str("[")?;
        self.depth += 1;
        self.pending &= !(1u32 << (self.depth & 31));
        Ok(())
    }

    pub fn end_array(&mut self) -> fmt::Result {
        self.depth = self.depth.saturating_sub(1);
        self.sink.write_str("]")
    }

    /// Escreve uma chave de objeto. O próximo token escrito será o valor.
    pub fn key(&mut self, nome: &str) -> fmt::Result {
        self.sep()?;
        self.escrever_string(nome)?;
        self.sink.write_str(":")?;
        self.expect_value = true;
        Ok(())
    }

    pub fn str_value(&mut self, valor: &str) -> fmt::Result {
        self.sep()?;
        self.escrever_string(valor)
    }

    pub fn u64_value(&mut self, valor: u64) -> fmt::Result {
        self.sep()?;
        write!(self.sink, "{valor}")
    }

    pub fn i64_value(&mut self, valor: i64) -> fmt::Result {
        self.sep()?;
        write!(self.sink, "{valor}")
    }

    pub fn bool_value(&mut self, valor: bool) -> fmt::Result {
        self.sep()?;
        self.sink.write_str(if valor { "true" } else { "false" })
    }

    pub fn null_value(&mut self) -> fmt::Result {
        self.sep()?;
        self.sink.write_str("null")
    }

    /// Escreve JSON já serializado, sem validar nem escapar.
    ///
    /// Usado para ecoar o `id` da requisição de volta exatamente como veio —
    /// o JSON-RPC exige que o `id` da resposta seja idêntico ao do pedido,
    /// preservando o tipo (número ou string).
    pub fn raw_value(&mut self, bruto: &str) -> fmt::Result {
        self.sep()?;
        self.sink.write_str(bruto)
    }

    /// Escreve um valor formatado como string JSON.
    pub fn fmt_value(&mut self, args: fmt::Arguments) -> fmt::Result {
        self.sep()?;
        self.sink.write_str("\"")?;
        // O sink recebe o texto já formatado. Não escapamos aqui porque os
        // usos internos (versões, nomes de formato de pixel) não contêm
        // caracteres especiais. Para dados vindos de fora, use `str_value`.
        self.sink.write_fmt(args)?;
        self.sink.write_str("\"")
    }

    // -- atalhos ------------------------------------------------------------

    pub fn field_str(&mut self, chave: &str, valor: &str) -> fmt::Result {
        self.key(chave)?;
        self.str_value(valor)
    }

    pub fn field_u64(&mut self, chave: &str, valor: u64) -> fmt::Result {
        self.key(chave)?;
        self.u64_value(valor)
    }

    pub fn field_bool(&mut self, chave: &str, valor: bool) -> fmt::Result {
        self.key(chave)?;
        self.bool_value(valor)
    }

    /// Serializa uma string com o escape exigido pelo JSON.
    fn escrever_string(&mut self, s: &str) -> fmt::Result {
        self.sink.write_str("\"")?;
        for c in s.chars() {
            match c {
                '"' => self.sink.write_str("\\\"")?,
                '\\' => self.sink.write_str("\\\\")?,
                '\n' => self.sink.write_str("\\n")?,
                '\r' => self.sink.write_str("\\r")?,
                '\t' => self.sink.write_str("\\t")?,
                // Caracteres de controle precisam da forma \u00XX; o JSON não
                // permite que apareçam crus dentro de uma string.
                c if (c as u32) < 0x20 => write!(self.sink, "\\u{:04x}", c as u32)?,
                c => self.sink.write_char(c)?,
            }
        }
        self.sink.write_str("\"")
    }
}

// ---------------------------------------------------------------------------
// Leitura
// ---------------------------------------------------------------------------

/// Uma fatia de JSON ainda não interpretada.
///
/// Não é uma árvore de nós: é só um empréstimo dos bytes originais. Os
/// acessores varrem esses bytes sob demanda, o que mantém o custo em zero
/// alocações ao preço de uma varredura por consulta. Como nossas requisições
/// têm poucos campos, a troca compensa largamente.
#[derive(Clone, Copy, Debug)]
pub struct Json<'a>(pub &'a [u8]);

impl<'a> Json<'a> {
    /// Os bytes crus deste valor.
    pub fn raw(&self) -> &'a [u8] {
        self.0
    }

    /// Os bytes crus como `&str`, se forem UTF-8 válido.
    pub fn raw_str(&self) -> Option<&'a str> {
        core::str::from_utf8(self.0).ok()
    }

    /// Busca um membro pelo nome, assumindo que este valor é um objeto.
    ///
    /// Só considera chaves do nível imediato: strings e objetos aninhados são
    /// pulados por inteiro, então uma chave `"method"` dentro de `params` não
    /// é confundida com a `"method"` do envelope.
    pub fn member(&self, chave: &str) -> Option<Json<'a>> {
        let b = self.0;
        let mut i = pular_espacos(b, 0);
        if *b.get(i)? != b'{' {
            return None;
        }
        i += 1;

        loop {
            i = pular_espacos(b, i);
            match *b.get(i)? {
                b'}' => return None,
                b',' => {
                    i += 1;
                    continue;
                }
                b'"' => {}
                _ => return None,
            }

            let inicio_chave = i;
            let fim_chave = pular_string(b, i)?;
            i = pular_espacos(b, fim_chave);
            if *b.get(i)? != b':' {
                return None;
            }
            i = pular_espacos(b, i + 1);

            let inicio_valor = i;
            let fim_valor = pular_valor(b, i)?;

            // As aspas delimitadoras ficam de fora na comparação.
            if &b[inicio_chave + 1..fim_chave - 1] == chave.as_bytes() {
                return Some(Json(&b[inicio_valor..fim_valor]));
            }
            i = fim_valor;
        }
    }

    /// O conteúdo de uma string JSON, sem as aspas e sem desescapar.
    ///
    /// Não desescapamos porque os campos que lemos (nomes de método, níveis de
    /// log) são identificadores que nunca contêm escapes. Aceitar escapes
    /// exigiria um buffer de destino, ou seja, alocação.
    pub fn as_str(&self) -> Option<&'a str> {
        let b = self.0;
        if b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"' {
            core::str::from_utf8(&b[1..b.len() - 1]).ok()
        } else {
            None
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        let s = core::str::from_utf8(self.0).ok()?.trim();
        s.parse().ok()
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self.0 {
            b"true" => Some(true),
            b"false" => Some(false),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        self.0 == b"null"
    }
}

fn pular_espacos(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// Devolve o índice logo após a aspa de fechamento.
fn pular_string(b: &[u8], mut i: usize) -> Option<usize> {
    if *b.get(i)? != b'"' {
        return None;
    }
    i += 1;
    while i < b.len() {
        match b[i] {
            // Uma barra invertida consome o próximo byte, seja ele qual for.
            // É isso que impede que `\"` seja lido como fim da string.
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// Devolve o índice logo após o fim do valor que começa em `i`.
fn pular_valor(b: &[u8], i: usize) -> Option<usize> {
    let i = pular_espacos(b, i);
    match *b.get(i)? {
        b'"' => pular_string(b, i),
        b'{' => pular_container(b, i, b'{', b'}'),
        b'[' => pular_container(b, i, b'[', b']'),
        _ => {
            // Número, `true`, `false` ou `null`: vai até o próximo delimitador.
            let mut j = i;
            while j < b.len()
                && !matches!(b[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
            {
                j += 1;
            }
            (j > i).then_some(j)
        }
    }
}

/// Pula um objeto ou array inteiro, respeitando aninhamento e strings.
fn pular_container(b: &[u8], mut i: usize, abre: u8, fecha: u8) -> Option<usize> {
    let mut nivel = 0usize;
    while i < b.len() {
        let c = b[i];
        if c == b'"' {
            // Strings são puladas inteiras: uma chave como `"a}b"` não pode
            // ser confundida com o fechamento do objeto.
            i = pular_string(b, i)?;
            continue;
        }
        if c == abre {
            nivel += 1;
        } else if c == fecha {
            nivel -= 1;
            if nivel == 0 {
                return Some(i + 1);
            }
        }
        i += 1;
    }
    None
}
