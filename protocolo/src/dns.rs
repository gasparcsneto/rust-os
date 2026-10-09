//! DNS: a pergunta pelo endereço IPv4 de um nome, e a resposta.
//!
//! # O que é, e o que não é
//!
//! O formato da RFC 1035 — o cabeçalho, a pergunta, os registros —, só no
//! que o Duke usa: o tipo `A` (um IPv4), a classe `IN`, e o `CNAME` que leva
//! de um nome a outro. Lido e escrito num buffer, sem alocar, para caber em
//! quem não tem alocador.
//!
//! Quem resolve nomes no Duke é um **programa** — ou um agente, do lado de
//! fora —, sobre a associação UDP com o servidor, que o gate decide como
//! decide qualquer destino. O kernel não resolve nome nenhum, e um nome não
//! é recurso da política: o endereço que uma resposta traz é só um número,
//! e conversar com ele é um `net.connect` que o gate decide de novo. Ver
//! `docs/SEGURANCA.md`.
//!
//! # Por que mora aqui
//!
//! Porque são três os que leem e escrevem DNS: o programa que resolve, o
//! tecido de segurança, que lê as respostas que viu passar para ligar o
//! nome à conexão pedida em seguida, e a bancada da suíte, que responde.
//! Um formato, uma declaração.
//!
//! # Entrada hostil
//!
//! Uma resposta vem da rede. A leitura recusa — sem pânico, sem laço — o que
//! não termina onde diz que termina, um rótulo de mais de 63 bytes, um nome
//! de mais de 253, um ponteiro de compressão que não aponta para **trás**
//! (é o que impede o laço: cada salto vai para antes de onde estava), mais
//! saltos que [`MAIS_SALTOS`], e um nome com bytes fora do alfabeto dos
//! nomes de máquina. Um registro `A` de um nome que não é o perguntado nem
//! um apelido dele não entra na resposta: é contado em
//! [`Mensagem::alheios`] — é a cara de uma resposta envenenada.

/// A porta do servidor.
pub const PORTA: u16 = 53;

/// A maior mensagem sobre UDP sem extensões: o que um servidor manda, e o
/// que a leitura aceita.
pub const MAIOR_MENSAGEM: usize = 512;

/// O maior nome, em texto: 253 bytes, sem o ponto final.
pub const MAIOR_NOME: usize = 253;

/// O maior rótulo.
pub const MAIOR_ROTULO: usize = 63;

/// Quantos endereços uma resposta lida guarda. Os que passam disso são
/// contados em [`Mensagem::sobra`].
pub const MAIS_ENDERECOS: usize = 8;

/// Quantos saltos de compressão um nome pode dar.
pub const MAIS_SALTOS: usize = 16;

/// Quantos apelidos (`CNAME`) a leitura segue a partir do nome perguntado.
pub const MAIS_APELIDOS: usize = 4;

/// O tipo de um registro de endereço IPv4.
pub const TIPO_A: u16 = 1;
/// O tipo de um apelido.
pub const TIPO_CNAME: u16 = 5;
/// A classe da Internet.
pub const CLASSE_IN: u16 = 1;

/// O código de resposta: sem erro.
pub const SEM_ERRO: u8 = 0;
/// O código de resposta: o nome não existe.
pub const NOME_INEXISTENTE: u8 = 3;

/// O tamanho do cabeçalho.
const CABECALHO: usize = 12;

/// Por que uma mensagem não se lê, ou não se escreve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// Menor que o cabeçalho.
    Curta,
    /// Acaba antes do que ela mesma diz ter.
    Cortada,
    /// Maior que [`MAIOR_MENSAGEM`].
    Grande,
    /// Um rótulo vazio no meio, de mais de 63 bytes, ou com um byte fora
    /// do alfabeto dos nomes de máquina.
    Rotulo,
    /// Um nome de mais de [`MAIOR_NOME`] bytes.
    NomeLongo,
    /// Um ponteiro de compressão que não aponta para trás, ou para fora.
    Ponteiro,
    /// Mais saltos de compressão que [`MAIS_SALTOS`].
    Saltos,
    /// Os bits de rótulo reservados (`01` e `10`).
    TipoDeRotulo,
    /// Mais de uma pergunta.
    Perguntas,
    /// Um registro `A` cujo dado não tem 4 bytes.
    RegistroA,
    /// O buffer de saída não comporta a mensagem.
    Espaco,
}

impl Erro {
    /// Uma frase, para o log e para a resposta.
    pub const fn motivo(self) -> &'static str {
        match self {
            Erro::Curta => "mensagem DNS menor que o cabecalho",
            Erro::Cortada => "mensagem DNS cortada",
            Erro::Grande => "mensagem DNS maior que 512 bytes",
            Erro::Rotulo => "rotulo DNS invalido",
            Erro::NomeLongo => "nome DNS longo demais",
            Erro::Ponteiro => "ponteiro de compressao DNS invalido",
            Erro::Saltos => "saltos de compressao DNS demais",
            Erro::TipoDeRotulo => "tipo de rotulo DNS reservado",
            Erro::Perguntas => "mais de uma pergunta DNS",
            Erro::RegistroA => "registro A com dado de tamanho errado",
            Erro::Espaco => "a mensagem DNS nao cabe no buffer",
        }
    }
}

/// Um nome de máquina, em minúsculas, com os rótulos separados por ponto e
/// sem o ponto final. O alfabeto é o dos nomes de máquina — letras,
/// dígitos, `-` e `_` —: o que uma pessoa lê é o que a comparação compara.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Nome {
    bytes: [u8; MAIOR_NOME],
    tamanho: u8,
}

impl core::fmt::Debug for Nome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Nome({:?})", self.texto())
    }
}

/// Se o byte é do alfabeto de um rótulo.
const fn do_alfabeto(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

impl Nome {
    /// O nome vazio: a raiz.
    pub const RAIZ: Nome = Nome {
        bytes: [0; MAIOR_NOME],
        tamanho: 0,
    };

    /// Lê um nome escrito como texto: rótulos separados por ponto, com ou
    /// sem o ponto final; maiúsculas viram minúsculas.
    pub fn de_texto(texto: &str) -> Result<Nome, Erro> {
        let texto = texto.strip_suffix('.').unwrap_or(texto);
        let mut nome = Nome::RAIZ;
        if texto.is_empty() {
            return Ok(nome);
        }
        for rotulo in texto.split('.') {
            nome.acrescentar(rotulo.as_bytes())?;
        }
        Ok(nome)
    }

    /// Acrescenta um rótulo no fim.
    fn acrescentar(&mut self, rotulo: &[u8]) -> Result<(), Erro> {
        if rotulo.is_empty()
            || rotulo.len() > MAIOR_ROTULO
            || !rotulo.iter().all(|&b| do_alfabeto(b))
        {
            return Err(Erro::Rotulo);
        }
        let ponto = usize::from(self.tamanho > 0);
        let novo = usize::from(self.tamanho) + ponto + rotulo.len();
        if novo > MAIOR_NOME {
            return Err(Erro::NomeLongo);
        }
        let mut i = usize::from(self.tamanho);
        if ponto == 1 {
            self.bytes[i] = b'.';
            i += 1;
        }
        for &b in rotulo {
            self.bytes[i] = b.to_ascii_lowercase();
            i += 1;
        }
        self.tamanho = novo as u8;
        Ok(())
    }

    /// O nome como texto.
    pub fn texto(&self) -> &str {
        // Só entra aqui o que passou pelo alfabeto: ASCII.
        core::str::from_utf8(&self.bytes[..usize::from(self.tamanho)]).unwrap_or("")
    }

    /// Os rótulos, em ordem.
    fn rotulos(&self) -> impl Iterator<Item = &[u8]> {
        let texto = &self.bytes[..usize::from(self.tamanho)];
        texto.split(|&b| b == b'.').filter(|r| !r.is_empty())
    }

    /// Quantos bytes o nome ocupa na mensagem, sem compressão.
    fn tamanho_na_mensagem(&self) -> usize {
        self.rotulos().map(|r| 1 + r.len()).sum::<usize>() + 1
    }
}

/// Uma mensagem lida.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mensagem {
    pub id: u16,
    /// É uma resposta (`QR`), e não uma pergunta.
    pub resposta: bool,
    /// O servidor cortou a resposta (`TC`): o que veio não é tudo.
    pub truncada: bool,
    /// O código de resposta — [`SEM_ERRO`], [`NOME_INEXISTENTE`]…
    pub codigo: u8,
    /// O nome perguntado, o tipo e a classe — se há pergunta.
    pub pergunta: Option<(Nome, u16, u16)>,
    /// Os endereços que a resposta dá ao nome perguntado — por ele ou por
    /// um apelido dele —, até [`MAIS_ENDERECOS`].
    pub enderecos: [[u8; 4]; MAIS_ENDERECOS],
    pub quantos: usize,
    /// Endereços além de [`MAIS_ENDERECOS`].
    pub sobra: usize,
    /// O menor TTL dos endereços guardados, em segundos.
    pub ttl: u32,
    /// Os apelidos seguidos, a partir do nome perguntado.
    pub apelidos: [Nome; MAIS_APELIDOS],
    pub quantos_apelidos: usize,
    /// Registros de endereço de nomes que não são o perguntado nem um
    /// apelido dele: não entram na resposta.
    pub alheios: usize,
    /// Quantos registros de resposta o cabeçalho declara.
    pub declarados: u16,
}

impl Mensagem {
    /// Os endereços guardados.
    pub fn enderecos(&self) -> &[[u8; 4]] {
        &self.enderecos[..self.quantos]
    }

    /// Os apelidos seguidos.
    pub fn apelidos(&self) -> &[Nome] {
        &self.apelidos[..self.quantos_apelidos]
    }

    /// O nome perguntado, se há pergunta.
    pub fn nome(&self) -> Option<&Nome> {
        self.pergunta.as_ref().map(|(n, _, _)| n)
    }
}

/// Um leitor sobre a mensagem inteira — a compressão aponta para qualquer
/// lugar antes.
struct Leitor<'a> {
    m: &'a [u8],
    pos: usize,
}

impl<'a> Leitor<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Erro> {
        let fim = self.pos.checked_add(n).ok_or(Erro::Cortada)?;
        let b = self.m.get(self.pos..fim).ok_or(Erro::Cortada)?;
        self.pos = fim;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, Erro> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, Erro> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Um nome, seguindo a compressão. O leitor avança só o que o nome
    /// ocupa onde ele começa: até o primeiro ponteiro, inclusive.
    fn nome(&mut self) -> Result<Nome, Erro> {
        let mut nome = Nome::RAIZ;
        // Onde a leitura está, e se já saltou (então `self.pos` não anda
        // mais).
        let mut aqui = self.pos;
        let mut saltou = false;
        let mut saltos = 0;
        loop {
            let tamanho = *self.m.get(aqui).ok_or(Erro::Cortada)?;
            match tamanho >> 6 {
                0b00 => {
                    let n = usize::from(tamanho);
                    if n == 0 {
                        if !saltou {
                            self.pos = aqui + 1;
                        }
                        return Ok(nome);
                    }
                    let rotulo = self.m.get(aqui + 1..aqui + 1 + n).ok_or(Erro::Cortada)?;
                    nome.acrescentar(rotulo)?;
                    aqui += 1 + n;
                }
                0b11 => {
                    let baixo = *self.m.get(aqui + 1).ok_or(Erro::Cortada)?;
                    let alvo = (usize::from(tamanho & 0x3F) << 8) | usize::from(baixo);
                    // Só para trás: cada salto vai para antes de onde
                    // estava, e a leitura não volta ao mesmo lugar.
                    if alvo >= aqui {
                        return Err(Erro::Ponteiro);
                    }
                    saltos += 1;
                    if saltos > MAIS_SALTOS {
                        return Err(Erro::Saltos);
                    }
                    if !saltou {
                        self.pos = aqui + 2;
                        saltou = true;
                    }
                    aqui = alvo;
                }
                _ => return Err(Erro::TipoDeRotulo),
            }
        }
    }
}

/// Lê uma mensagem — uma pergunta ou uma resposta.
pub fn ler(m: &[u8]) -> Result<Mensagem, Erro> {
    if m.len() < CABECALHO {
        return Err(Erro::Curta);
    }
    if m.len() > MAIOR_MENSAGEM {
        return Err(Erro::Grande);
    }
    let mut l = Leitor { m, pos: 0 };
    let id = l.u16()?;
    let bandeiras = l.u16()?;
    let perguntas = l.u16()?;
    let respostas = l.u16()?;
    let _autoridade = l.u16()?;
    let _adicionais = l.u16()?;
    if perguntas > 1 {
        return Err(Erro::Perguntas);
    }
    let pergunta = if perguntas == 1 {
        let nome = l.nome()?;
        let tipo = l.u16()?;
        let classe = l.u16()?;
        Some((nome, tipo, classe))
    } else {
        None
    };
    let mut msg = Mensagem {
        id,
        resposta: bandeiras & 0x8000 != 0,
        truncada: bandeiras & 0x0200 != 0,
        codigo: (bandeiras & 0x000F) as u8,
        pergunta,
        enderecos: [[0; 4]; MAIS_ENDERECOS],
        quantos: 0,
        sobra: 0,
        ttl: u32::MAX,
        apelidos: [Nome::RAIZ; MAIS_APELIDOS],
        quantos_apelidos: 0,
        alheios: 0,
        declarados: respostas,
    };
    for _ in 0..respostas {
        let dono = l.nome()?;
        let tipo = l.u16()?;
        let classe = l.u16()?;
        let ttl = l.u32()?;
        let n = usize::from(l.u16()?);
        let inicio = l.pos;
        let dado = l.bytes(n)?;
        if classe != CLASSE_IN {
            continue;
        }
        // O nome perguntado e os apelidos já seguidos são os donos que
        // contam.
        let do_nome = msg.nome().is_some_and(|p| *p == dono) || msg.apelidos().contains(&dono);
        match tipo {
            TIPO_A => {
                if n != 4 {
                    return Err(Erro::RegistroA);
                }
                if !do_nome {
                    msg.alheios += 1;
                } else if msg.quantos < MAIS_ENDERECOS {
                    msg.enderecos[msg.quantos] = [dado[0], dado[1], dado[2], dado[3]];
                    msg.quantos += 1;
                    msg.ttl = msg.ttl.min(ttl);
                } else {
                    msg.sobra += 1;
                }
            }
            TIPO_CNAME if do_nome && msg.quantos_apelidos < MAIS_APELIDOS => {
                // O alvo do apelido, lido de dentro do dado — a compressão
                // aponta para a mensagem inteira, e o dado tem de conter o
                // nome inteiro, ou o primeiro ponteiro dele.
                let mut dentro = Leitor { m, pos: inicio };
                let alvo = dentro.nome()?;
                if dentro.pos > inicio + n {
                    return Err(Erro::Cortada);
                }
                msg.apelidos[msg.quantos_apelidos] = alvo;
                msg.quantos_apelidos += 1;
            }
            _ => {}
        }
    }
    if msg.quantos == 0 {
        msg.ttl = 0;
    }
    Ok(msg)
}

/// Um escritor no buffer de saída.
struct Escritor<'a> {
    b: &'a mut [u8],
    pos: usize,
}

impl Escritor<'_> {
    fn bytes(&mut self, dados: &[u8]) -> Result<(), Erro> {
        let fim = self.pos + dados.len();
        if fim > self.b.len() || fim > MAIOR_MENSAGEM {
            return Err(Erro::Espaco);
        }
        self.b[self.pos..fim].copy_from_slice(dados);
        self.pos = fim;
        Ok(())
    }

    fn u16(&mut self, v: u16) -> Result<(), Erro> {
        self.bytes(&v.to_be_bytes())
    }

    fn nome(&mut self, nome: &Nome) -> Result<(), Erro> {
        if self.pos + nome.tamanho_na_mensagem() > self.b.len() {
            return Err(Erro::Espaco);
        }
        for rotulo in nome.rotulos() {
            self.bytes(&[rotulo.len() as u8])?;
            self.bytes(rotulo)?;
        }
        self.bytes(&[0])
    }

    fn cabecalho(&mut self, id: u16, bandeiras: u16, respostas: u16) -> Result<(), Erro> {
        self.u16(id)?;
        self.u16(bandeiras)?;
        self.u16(1)?;
        self.u16(respostas)?;
        self.u16(0)?;
        self.u16(0)
    }
}

/// Escreve em `saida` a pergunta `id` pelo endereço IPv4 de `nome`, pedindo
/// recursão. Devolve o tamanho.
pub fn pergunta(id: u16, nome: &Nome, saida: &mut [u8]) -> Result<usize, Erro> {
    let mut w = Escritor { b: saida, pos: 0 };
    w.cabecalho(id, 0x0100, 0)?;
    w.nome(nome)?;
    w.u16(TIPO_A)?;
    w.u16(CLASSE_IN)?;
    Ok(w.pos)
}

/// Escreve em `saida` a resposta à pergunta `id` por `nome`: os endereços,
/// cada um com `ttl`, e o `codigo`. O nome de cada registro é um ponteiro
/// para o da pergunta. Devolve o tamanho.
pub fn resposta(
    id: u16,
    nome: &Nome,
    enderecos: &[[u8; 4]],
    ttl: u32,
    codigo: u8,
    saida: &mut [u8],
) -> Result<usize, Erro> {
    let quantos = u16::try_from(enderecos.len()).map_err(|_| Erro::Espaco)?;
    let mut w = Escritor { b: saida, pos: 0 };
    // Resposta, pergunta pedia recursão, recursão disponível, e o código.
    w.cabecalho(id, 0x8180 | u16::from(codigo & 0x0F), quantos)?;
    w.nome(nome)?;
    w.u16(TIPO_A)?;
    w.u16(CLASSE_IN)?;
    for e in enderecos {
        // O nome da pergunta começa logo depois do cabeçalho.
        w.u16(0xC000 | CABECALHO as u16)?;
        w.u16(TIPO_A)?;
        w.u16(CLASSE_IN)?;
        w.bytes(&ttl.to_be_bytes())?;
        w.u16(4)?;
        w.bytes(e)?;
    }
    Ok(w.pos)
}

#[cfg(test)]
mod testes {
    use super::*;

    fn nome(t: &str) -> Nome {
        Nome::de_texto(t).unwrap()
    }

    #[test]
    fn o_nome_em_texto() {
        assert_eq!(nome("Eco.Duke.").texto(), "eco.duke");
        assert_eq!(nome("").texto(), "");
        assert_eq!(Nome::de_texto("a..b"), Err(Erro::Rotulo));
        assert_eq!(Nome::de_texto("a b"), Err(Erro::Rotulo));
        assert_eq!(Nome::de_texto(&"a".repeat(64)), Err(Erro::Rotulo));
        assert!(Nome::de_texto(&"a".repeat(63)).is_ok());
        // 4 rótulos de 63 com os pontos: 255 — passa de 253.
        let longo = [&"a".repeat(63)[..]; 4].join(".");
        assert_eq!(Nome::de_texto(&longo), Err(Erro::NomeLongo));
        let limite = format!("{}.{}", [&"a".repeat(63)[..]; 3].join("."), "a".repeat(61));
        assert_eq!(limite.len(), 253);
        assert_eq!(nome(&limite).texto(), limite);
    }

    #[test]
    fn a_pergunta_vai_e_volta() {
        let mut b = [0u8; MAIOR_MENSAGEM];
        let n = pergunta(0xBEEF, &nome("permitido.duke"), &mut b).unwrap();
        assert_eq!(n, 12 + 16 + 4);
        let m = ler(&b[..n]).unwrap();
        assert_eq!(m.id, 0xBEEF);
        assert!(!m.resposta && !m.truncada);
        assert_eq!(
            m.pergunta,
            Some((nome("permitido.duke"), TIPO_A, CLASSE_IN))
        );
        assert_eq!(m.quantos, 0);
    }

    #[test]
    fn a_resposta_vai_e_volta() {
        let mut b = [0u8; MAIOR_MENSAGEM];
        let ips = [[10, 0, 2, 100], [10, 0, 2, 101]];
        let n = resposta(7, &nome("eco.duke"), &ips, 300, SEM_ERRO, &mut b).unwrap();
        let m = ler(&b[..n]).unwrap();
        assert!(m.resposta);
        assert_eq!(m.codigo, SEM_ERRO);
        assert_eq!(m.enderecos(), &ips);
        assert_eq!(m.ttl, 300);
        assert_eq!(m.alheios, 0);
        let n = resposta(8, &nome("nada.duke"), &[], 0, NOME_INEXISTENTE, &mut b).unwrap();
        let m = ler(&b[..n]).unwrap();
        assert_eq!((m.codigo, m.quantos, m.ttl), (NOME_INEXISTENTE, 0, 0));
    }

    /// Cortada em qualquer ponto, não se lê — e não entra em pânico.
    #[test]
    fn cortada_em_qualquer_ponto() {
        let mut b = [0u8; MAIOR_MENSAGEM];
        let n = resposta(1, &nome("a.b.c"), &[[1, 2, 3, 4]; 3], 9, 0, &mut b).unwrap();
        for corte in 0..n {
            assert!(ler(&b[..corte]).is_err(), "cortada em {corte}");
        }
        assert!(ler(&b[..n]).is_ok());
    }

    /// Uma resposta montada à mão, com o apelido e a compressão.
    fn com_apelido() -> Vec<u8> {
        let mut m = vec![0, 9, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0];
        // Pergunta: www.duke A IN, em 12.
        m.extend([
            3, b'w', b'w', b'w', 4, b'd', b'u', b'k', b'e', 0, 0, 1, 0, 1,
        ]);
        // www.duke CNAME eco.duke (eco + ponteiro para "duke", em 16).
        m.extend([0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6]);
        m.extend([3, b'e', b'c', b'o', 0xC0, 16]);
        // eco.duke A 10.0.2.100, pelo ponteiro para o alvo do apelido.
        let alvo = 12 + 14 + 12;
        m.extend([
            0xC0, alvo as u8, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 10, 0, 2, 100,
        ]);
        // outro.duke A 6.6.6.6: alheio.
        m.extend([
            5, b'o', b'u', b't', b'r', b'o', 0xC0, 16, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4,
        ]);
        m.extend([6, 6, 6, 6]);
        m[7] = 3;
        m
    }

    #[test]
    fn o_apelido_e_o_alheio() {
        let m = com_apelido();
        let lido = ler(&m).unwrap();
        assert_eq!(lido.apelidos(), &[nome("eco.duke")]);
        // O cabeçalho declara 3, e há 3: o terceiro é de outro nome, e não
        // entra.
        assert_eq!(lido.enderecos(), &[[10, 0, 2, 100]]);
        assert_eq!(lido.alheios, 1);
        let mut m4 = m.clone();
        m4[7] = 4;
        assert_eq!(ler(&m4), Err(Erro::Cortada));
    }

    #[test]
    fn o_ponteiro_so_para_tras() {
        // Um ponteiro para si mesmo, e um para a frente.
        let mut m = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([0xC0, 12, 0, 1, 0, 1]);
        assert_eq!(ler(&m), Err(Erro::Ponteiro));
        let mut m = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([0xC0, 20, 0, 1, 0, 1, 0, 0, 1, b'a', 0]);
        assert_eq!(ler(&m), Err(Erro::Ponteiro));
        // Os bits reservados do rótulo.
        let mut m = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend([0x40, 0, 0, 1, 0, 1]);
        assert_eq!(ler(&m), Err(Erro::TipoDeRotulo));
    }

    /// Uma corrente de ponteiros, cada um para trás, mais longa que o teto.
    /// Ela mora no dado de um registro de outro tipo — que a leitura pula —,
    /// e o nome do registro seguinte salta para o fim dela.
    #[test]
    fn saltos_demais() {
        let mut corrente = vec![1, b'a', 0];
        let inicio = 12 + 1 + 10;
        let mut anterior = inicio as u16;
        for _ in 0..(MAIS_SALTOS + 2) {
            let aqui = (inicio + corrente.len()) as u16;
            corrente.extend((0xC000 | anterior).to_be_bytes());
            anterior = aqui;
        }
        let mut m = vec![0, 1, 0x81, 0x80, 0, 0, 0, 2, 0, 0, 0, 0];
        // O primeiro: a raiz, tipo 99, com a corrente no dado.
        m.extend([0, 0, 99, 0, 1, 0, 0, 0, 0]);
        m.extend((corrente.len() as u16).to_be_bytes());
        m.extend(&corrente);
        // O segundo: o nome salta para o último ponteiro.
        m.extend((0xC000 | anterior).to_be_bytes());
        m.extend([0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        assert_eq!(ler(&m), Err(Erro::Saltos));
        // Com a corrente no teto, lê: o nome do segundo é `a`, que ninguém
        // perguntou.
        let mut curta = vec![1, b'a', 0];
        let mut anterior = inicio as u16;
        for _ in 0..(MAIS_SALTOS - 1) {
            let aqui = (inicio + curta.len()) as u16;
            curta.extend((0xC000 | anterior).to_be_bytes());
            anterior = aqui;
        }
        let mut m = vec![0, 1, 0x81, 0x80, 0, 0, 0, 2, 0, 0, 0, 0];
        m.extend([0, 0, 99, 0, 1, 0, 0, 0, 0]);
        m.extend((curta.len() as u16).to_be_bytes());
        m.extend(&curta);
        m.extend((0xC000 | anterior).to_be_bytes());
        m.extend([0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        assert_eq!(ler(&m).map(|l| l.alheios), Ok(1));
    }

    #[test]
    fn o_registro_a_tem_quatro_bytes() {
        let mut m = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        m.extend([1, b'a', 0, 0, 1, 0, 1]);
        m.extend([0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 5, 1, 2, 3, 4, 5]);
        assert_eq!(ler(&m), Err(Erro::RegistroA));
    }

    #[test]
    fn mais_de_uma_pergunta() {
        let m = [0, 1, 0x81, 0x80, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
        assert_eq!(ler(&m), Err(Erro::Perguntas));
    }

    #[test]
    fn grande_demais() {
        let mut b = [0u8; MAIOR_MENSAGEM + 1];
        b[5] = 0;
        assert_eq!(ler(&b), Err(Erro::Grande));
        // E o escritor não passa do teto, nem do buffer.
        let mut pequeno = [0u8; 20];
        assert_eq!(
            pergunta(1, &nome("um.nome.longo"), &mut pequeno),
            Err(Erro::Espaco)
        );
        let muitos = [[1, 1, 1, 1]; 40];
        let mut b = [0u8; 1024];
        assert_eq!(
            resposta(1, &nome("a"), &muitos, 1, 0, &mut b),
            Err(Erro::Espaco)
        );
    }

    /// Endereços além do teto são contados, não guardados.
    #[test]
    fn a_sobra() {
        let mut b = [0u8; MAIOR_MENSAGEM];
        let ips = [[10, 0, 0, 1]; MAIS_ENDERECOS + 3];
        let n = resposta(1, &nome("muitos"), &ips, 5, 0, &mut b).unwrap();
        let m = ler(&b[..n]).unwrap();
        assert_eq!((m.quantos, m.sobra), (MAIS_ENDERECOS, 3));
    }

    /// Bytes ao acaso, e uma resposta boa com bytes trocados: a leitura
    /// devolve uma mensagem ou um erro — nunca entra em pânico, nunca fica
    /// presa.
    #[test]
    fn entrada_hostil_nao_derruba() {
        let mut semente = 0x2545_F491_4F6C_DD1Du64;
        let mut proximo = || {
            semente ^= semente << 13;
            semente ^= semente >> 7;
            semente ^= semente << 17;
            semente
        };
        let mut boa = [0u8; MAIOR_MENSAGEM];
        let n = resposta(3, &nome("eco.duke"), &[[10, 0, 2, 100]], 9, 0, &mut boa).unwrap();
        let apelido = com_apelido();
        for i in 0..20_000 {
            let tamanho = (proximo() % 80) as usize;
            let aleatorio: Vec<u8> = (0..tamanho).map(|_| proximo() as u8).collect();
            let _ = ler(&aleatorio);
            let mut trocada = if i % 2 == 0 {
                boa[..n].to_vec()
            } else {
                apelido.clone()
            };
            for _ in 0..(1 + proximo() % 3) {
                let p = (proximo() as usize) % trocada.len();
                trocada[p] = proximo() as u8;
            }
            let _ = ler(&trocada);
        }
    }
}
