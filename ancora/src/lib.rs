//! A âncora da persistência: um contador monotônico num TPM 2.0.
//!
//! # Para que serve
//!
//! O journal do Duke mora no disco, e um disco se copia e se devolve. Uma
//! cópia antiga do journal é consistente em si mesma — autenticada, elo a
//! elo —, e o kernel, olhando só para o disco, não tem como distinguir a
//! cópia da verdadeira. É preciso um número fora do disco, que só cresce, e
//! que o journal acompanhe: se o disco diz menos do que o número, o disco é
//! velho. Este pacote é esse número.
//!
//! # Por que um contador de NV do TPM
//!
//! Porque o TPM 2.0 tem exatamente isto como primitiva: um índice de NV do
//! tipo *contador* só sabe crescer, de um em um, e nem quem tem a senha
//! consegue fazê-lo voltar. Apagar o índice e criá-lo de novo também não o
//! zera: um contador novo nasce no maior valor que qualquer contador daquele
//! TPM já teve. E o valor mora no chip, não no disco — é a propriedade que
//! importa.
//!
//! # O que este pacote faz e o que não faz
//!
//! Monta os comandos do TPM byte a byte e lê as respostas, e decide o que
//! um contador ausente, estranho ou ilegível quer dizer. Não fala com o
//! chip: recebe um [`Tpm`], que leva bytes de comando e traz bytes de
//! resposta. O kernel implementa esse transporte sobre o TIS; os testes,
//! sobre um TPM simulado e sobre o `swtpm`.
//!
//! Também não decide **quando** avançar o contador nem o que fazer com um
//! disco atrasado em relação a ele: isso é do journal, que sabe o que cada
//! valor significa.
//!
//! # A autorização
//!
//! O contador é criado com uma senha (o `authValue` do índice), e só quem
//! a tem o avança. A senha vai pelo barramento em claro, numa sessão de
//! senha (`TPM_RS_PW`): contra quem escuta o barramento entre a CPU e o
//! chip, isto não protege. Num TPM emulado não há barramento; num físico,
//! a resposta é uma sessão autenticada por HMAC — fica para quando houver
//! um TPM físico (a fase 7.7 de `docs/PERSISTENCIA.md`).
//!
//! Quem não tem a senha só consegue o que não ajuda a ninguém: não lê, não
//! avança. E mesmo que avançasse, o efeito seria o disco parecer velho — a
//! administração bloqueada, e não uma credencial de volta.
//!
//! # O nascimento
//!
//! Ao lado do contador mora um segundo índice, comum, de oito bytes: o
//! valor que o contador tinha quando nasceu. Ele responde a uma pergunta
//! que o contador sozinho não responde. Um journal vazio diante de um
//! contador presente é um disco apagado — a menos que o contador nunca
//! tenha passado do valor com que nasceu, e então nenhum registro chegou a
//! ser confirmado: a criação foi interrompida por uma queda, e retomá-la
//! não perde nada. Sem o nascimento, as duas coisas são o mesmo par de
//! números, e a segunda — uma queda na primeira instalação — viraria uma
//! recusa para sempre.

#![no_std]

use zeroize::Zeroize;

/// O maior comando ou resposta que este pacote troca com o TPM.
///
/// Os comandos daqui são todos pequenos — o maior é a definição do índice,
/// com umas sete dezenas de bytes. Um teto fixo, e não `alloc`, porque o
/// pacote roda no kernel antes de qualquer coisa que dependa do journal.
pub const MAIOR_QUADRO: usize = 256;

/// O transporte até o TPM: manda um comando, devolve a resposta.
pub trait Tpm {
    /// Manda `comando` inteiro e escreve a resposta em `resposta`,
    /// devolvendo quantos bytes ela tem.
    fn trocar(&mut self, comando: &[u8], resposta: &mut [u8; MAIOR_QUADRO]) -> Result<usize, Erro>;
}

/// O que pode dar errado.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Erro {
    /// O transporte não conseguiu levar ou trazer os bytes.
    Transporte(&'static str),
    /// O TPM respondeu com este código de erro.
    Codigo(u32),
    /// A resposta não tem o formato que o comando promete.
    RespostaMalformada(&'static str),
    /// O índice existe, mas não é um contador como o que este pacote cria:
    /// outro tipo, outros atributos, outro tamanho. Alguém definiu outra
    /// coisa no lugar da âncora — e o valor dela não significa nada.
    IndiceEstranho,
}

impl Erro {
    /// Uma frase para o log e para a recusa.
    pub fn motivo(&self) -> &'static str {
        match self {
            Erro::Transporte(m) | Erro::RespostaMalformada(m) => m,
            Erro::Codigo(codigo::SENHA_ERRADA) => "o TPM recusou a senha da ancora",
            Erro::Codigo(codigo::NV_JA_DEFINIDO) => "o indice da ancora ja existe",
            Erro::Codigo(_) => "o TPM recusou o comando",
            Erro::IndiceEstranho => "o indice da ancora nao e o contador que o Duke cria",
        }
    }
}

/// Os códigos de resposta que este pacote distingue.
///
/// Um código do TPM 2.0 tem formato: os de "formato 1" carregam no bit 8 e
/// acima **qual** parâmetro, handle ou sessão causou o erro. Os valores
/// abaixo são os que este pacote recebe de verdade, com esse número já
/// somado — conferidos contra o `swtpm`, e não deduzidos da especificação.
pub mod codigo {
    /// Deu certo.
    pub const SUCESSO: u32 = 0x000;
    /// `TPM2_Startup` num TPM que já foi iniciado: o firmware já o fez.
    pub const JA_INICIADO: u32 = 0x100;
    /// `TPM_RC_HANDLE` no primeiro handle: o índice não existe.
    pub const INDICE_INEXISTENTE: u32 = 0x18B;
    /// `TPM_RC_NV_UNINITIALIZED`: o contador foi definido e nunca avançado.
    pub const NV_NAO_INICIALIZADO: u32 = 0x14A;
    /// `TPM_RC_NV_DEFINED`: já existe um índice neste número.
    pub const NV_JA_DEFINIDO: u32 = 0x14C;
    /// `TPM_RC_BAD_AUTH` na primeira sessão: a senha não é a do índice.
    ///
    /// Não é o `TPM_RC_AUTH_FAIL` (`0x98E`) que a primeira versão deste
    /// pacote esperava, e o simulado dos testes concordava com ela — os dois
    /// escritos pela mesma pessoa. O `swtpm` respondeu `0x9A2`: num índice
    /// com [`super::atributo::SEM_BLOQUEIO`], a especificação manda `BAD_AUTH`, e
    /// reserva `AUTH_FAIL` para os que contam para o bloqueio.
    pub const SENHA_ERRADA: u32 = 0x9A2;
}

/// Os comandos, pelo código que a especificação lhes dá.
mod comando {
    pub const STARTUP: u32 = 0x0000_0144;
    pub const NV_UNDEFINE_SPACE: u32 = 0x0000_0122;
    pub const NV_DEFINE_SPACE: u32 = 0x0000_012A;
    pub const NV_INCREMENT: u32 = 0x0000_0134;
    pub const NV_READ: u32 = 0x0000_014E;
    pub const NV_WRITE: u32 = 0x0000_0137;
    pub const NV_READ_PUBLIC: u32 = 0x0000_0169;
}

/// Um comando sem área de autorização.
const SEM_SESSOES: u16 = 0x8001;
/// Um comando com área de autorização.
const COM_SESSOES: u16 = 0x8002;
/// `TPM_SU_CLEAR`: o reinício de um TPM recém-ligado.
const REINICIO_LIMPO: u16 = 0x0000;
/// A hierarquia do dono: quem pode definir índices de NV.
const DONO: u32 = 0x4000_0001;
/// A sessão de senha: a autorização vai como texto, sem HMAC.
const SESSAO_DE_SENHA: u32 = 0x4000_0009;
/// `continueSession`: a sessão de senha não acaba, mas o bit é o que todo
/// cliente manda, e um TPM pode recusar sem ele.
const CONTINUAR_SESSAO: u8 = 0x01;
/// SHA-256, o algoritmo do nome do índice.
const SHA256: u16 = 0x000B;

/// Os atributos do índice da âncora (`TPMA_NV`).
pub mod atributo {
    /// Quem tem a senha do índice escreve nele — aqui, avança.
    pub const ESCRITA_COM_SENHA: u32 = 1 << 2;
    /// O tipo, nos bits 7 a 4: 1 é contador.
    pub const TIPO_CONTADOR: u32 = 1 << 4;
    /// A máscara do tipo.
    pub const MASCARA_DO_TIPO: u32 = 0xF << 4;
    /// Quem tem a senha do índice lê.
    pub const LEITURA_COM_SENHA: u32 = 1 << 18;
    /// Uma senha errada não conta para o bloqueio contra força bruta do TPM.
    ///
    /// A senha tem trinta e dois bytes sorteados; adivinhá-la não é o
    /// risco. O risco é o contrário: um processo qualquer errando a senha de
    /// propósito até o TPM bloquear todo uso com senha — e a persistência
    /// do Duke ficar indisponível por isso.
    pub const SEM_BLOQUEIO: u32 = 1 << 25;
    /// Ligado pelo próprio TPM depois da primeira escrita. Não se pede.
    pub const ESCRITO: u32 = 1 << 29;

    /// Os atributos com que a âncora é criada, e os únicos que ela pode ter.
    pub const DA_ANCORA: u32 = ESCRITA_COM_SENHA | TIPO_CONTADOR | LEITURA_COM_SENHA | SEM_BLOQUEIO;
    /// Os do índice do nascimento: um índice comum (tipo 0), com a mesma
    /// senha e as mesmas regras de leitura e escrita da âncora.
    pub const DO_NASCIMENTO: u32 = ESCRITA_COM_SENHA | LEITURA_COM_SENHA | SEM_BLOQUEIO;
}

/// O tamanho de um contador: oito bytes, sempre.
const TAMANHO_DO_CONTADOR: u16 = 8;

/// Um comando sendo montado.
struct Quadro {
    bytes: [u8; MAIOR_QUADRO],
    tam: usize,
}

impl Quadro {
    /// Abre um comando com a etiqueta e o código. O tamanho é escrito no
    /// fim, por [`Quadro::fechar`].
    fn novo(etiqueta: u16, codigo: u32) -> Quadro {
        let mut q = Quadro {
            bytes: [0; MAIOR_QUADRO],
            tam: 0,
        };
        q.u16(etiqueta);
        q.u32(0);
        q.u32(codigo);
        q
    }

    fn bytes(&mut self, b: &[u8]) {
        // Os comandos deste pacote cabem com folga; passar daqui é erro de
        // programação, não de entrada, e por isso não é `Result`.
        self.bytes[self.tam..self.tam + b.len()].copy_from_slice(b);
        self.tam += b.len();
    }

    fn u8(&mut self, v: u8) {
        self.bytes(&[v]);
    }

    fn u16(&mut self, v: u16) {
        self.bytes(&v.to_be_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.bytes(&v.to_be_bytes());
    }

    /// Um `TPM2B`: dois bytes de tamanho e os bytes.
    fn tpm2b(&mut self, b: &[u8]) {
        self.u16(b.len() as u16);
        self.bytes(b);
    }

    /// A área de autorização com uma sessão de senha.
    fn sessao_de_senha(&mut self, senha: &[u8]) {
        // handle (4) + nonce vazio (2) + atributos (1) + senha (2 + n)
        self.u32(4 + 2 + 1 + 2 + senha.len() as u32);
        self.u32(SESSAO_DE_SENHA);
        self.tpm2b(&[]);
        self.u8(CONTINUAR_SESSAO);
        self.tpm2b(senha);
    }

    /// Escreve o tamanho no cabeçalho e devolve o comando pronto.
    fn fechar(&mut self) -> &[u8] {
        let tam = (self.tam as u32).to_be_bytes();
        self.bytes[2..6].copy_from_slice(&tam);
        &self.bytes[..self.tam]
    }
}

/// Uma resposta sendo lida.
struct Leitor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Leitor<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], Erro> {
        let fim = self
            .pos
            .checked_add(n)
            .filter(|&f| f <= self.bytes.len())
            .ok_or(Erro::RespostaMalformada(
                "resposta do TPM mais curta que o formato",
            ))?;
        let b = &self.bytes[self.pos..fim];
        self.pos = fim;
        Ok(b)
    }

    fn u8(&mut self) -> Result<u8, Erro> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Erro> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, Erro> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn tpm2b(&mut self) -> Result<&'a [u8], Erro> {
        let n = self.u16()? as usize;
        self.bytes(n)
    }

    fn fim(&self) -> Result<(), Erro> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(Erro::RespostaMalformada(
                "resposta do TPM mais longa que o formato",
            ))
        }
    }
}

/// Manda `comando` e confere o cabeçalho da resposta. Devolve o código e
/// o corpo depois do cabeçalho.
fn trocar<'r, T: Tpm>(
    tpm: &mut T,
    comando: &[u8],
    resposta: &'r mut [u8; MAIOR_QUADRO],
) -> Result<(u32, Leitor<'r>), Erro> {
    let n = tpm.trocar(comando, resposta)?;
    let bytes = resposta.get(..n).ok_or(Erro::Transporte(
        "o transporte disse mais bytes do que cabem",
    ))?;
    let mut leitor = Leitor { bytes, pos: 0 };
    let etiqueta = leitor.u16()?;
    let tamanho = leitor.u32()?;
    let codigo = leitor.u32()?;
    if tamanho as usize != n {
        return Err(Erro::RespostaMalformada(
            "o tamanho no cabecalho da resposta nao e o que chegou",
        ));
    }
    if etiqueta != SEM_SESSOES && etiqueta != COM_SESSOES {
        return Err(Erro::RespostaMalformada(
            "etiqueta de resposta desconhecida",
        ));
    }
    if codigo == codigo::SUCESSO && etiqueta != esperada(comando) {
        // Um comando com sessão volta com sessão; sem, sem. Uma etiqueta
        // trocada é o TPM dizendo que entendeu outro comando.
        return Err(Erro::RespostaMalformada(
            "a etiqueta da resposta nao e a do comando",
        ));
    }
    if codigo != codigo::SUCESSO && n != 10 {
        // Um erro é só o cabeçalho.
        return Err(Erro::RespostaMalformada("resposta de erro com corpo"));
    }
    Ok((codigo, leitor))
}

/// A etiqueta que a resposta a `comando` tem de ter.
fn esperada(comando: &[u8]) -> u16 {
    u16::from_be_bytes([comando[0], comando[1]])
}

/// Lê a área de autorização de uma resposta com sessão de senha, que é
/// sempre a mesma: nonce vazio, atributos, e autorização vazia.
fn ler_sessao_de_resposta(leitor: &mut Leitor) -> Result<(), Erro> {
    leitor.tpm2b()?;
    leitor.u8()?;
    leitor.tpm2b()?;
    leitor.fim()
}

/// `TPM2_Startup(CLEAR)`. Num TPM que o firmware já iniciou, o TPM
/// responde que já foi — e isso é sucesso.
pub fn iniciar<T: Tpm>(tpm: &mut T) -> Result<(), Erro> {
    let mut q = Quadro::novo(SEM_SESSOES, comando::STARTUP);
    q.u16(REINICIO_LIMPO);
    let mut r = [0; MAIOR_QUADRO];
    let (codigo, leitor) = trocar(tpm, q.fechar(), &mut r)?;
    match codigo {
        codigo::SUCESSO => leitor.fim(),
        codigo::JA_INICIADO => Ok(()),
        outro => Err(Erro::Codigo(outro)),
    }
}

/// O que o TPM diz de um índice de NV.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Publico {
    pub atributos: u32,
    pub algoritmo_do_nome: u16,
    /// Se o índice tem política de autorização. A âncora não tem: a única
    /// autorização dela é a senha.
    pub tem_politica: bool,
    pub tamanho: u16,
}

/// `TPM2_NV_ReadPublic`: o que o índice é, ou `None` se não existe.
pub fn ler_publico<T: Tpm>(tpm: &mut T, indice: u32) -> Result<Option<Publico>, Erro> {
    let mut q = Quadro::novo(SEM_SESSOES, comando::NV_READ_PUBLIC);
    q.u32(indice);
    let mut r = [0; MAIOR_QUADRO];
    let (codigo, mut leitor) = trocar(tpm, q.fechar(), &mut r)?;
    match codigo {
        codigo::SUCESSO => {}
        codigo::INDICE_INEXISTENTE => return Ok(None),
        outro => return Err(Erro::Codigo(outro)),
    }
    let publico = leitor.tpm2b()?;
    let mut p = Leitor {
        bytes: publico,
        pos: 0,
    };
    if p.u32()? != indice {
        return Err(Erro::RespostaMalformada("o TPM descreveu outro indice"));
    }
    let algoritmo_do_nome = p.u16()?;
    let atributos = p.u32()?;
    let tem_politica = !p.tpm2b()?.is_empty();
    let tamanho = p.u16()?;
    p.fim()?;
    // O nome do índice. Não interessa aqui — a senha é o que autoriza —,
    // mas faz parte da resposta, e uma resposta que não termina onde o
    // formato diz é uma resposta que não se entendeu.
    leitor.tpm2b()?;
    leitor.fim()?;
    Ok(Some(Publico {
        atributos,
        algoritmo_do_nome,
        tem_politica,
        tamanho,
    }))
}

/// `TPM2_NV_DefineSpace`: cria o contador `indice` com a `senha`, pela
/// hierarquia do dono (cuja senha é `senha_do_dono`).
pub fn definir_contador<T: Tpm>(
    tpm: &mut T,
    indice: u32,
    senha_do_dono: &[u8],
    senha: &[u8],
) -> Result<(), Erro> {
    definir(tpm, indice, senha_do_dono, senha, atributo::DA_ANCORA)
}

/// `TPM2_NV_DefineSpace` de um índice de oito bytes com estes `atributos`.
fn definir<T: Tpm>(
    tpm: &mut T,
    indice: u32,
    senha_do_dono: &[u8],
    senha: &[u8],
    atributos: u32,
) -> Result<(), Erro> {
    let mut q = Quadro::novo(COM_SESSOES, comando::NV_DEFINE_SPACE);
    q.u32(DONO);
    q.sessao_de_senha(senha_do_dono);
    q.tpm2b(senha);
    // TPM2B_NV_PUBLIC: índice, algoritmo do nome, atributos, política
    // vazia, tamanho.
    q.u16(4 + 2 + 4 + 2 + 2);
    q.u32(indice);
    q.u16(SHA256);
    q.u32(atributos);
    q.tpm2b(&[]);
    q.u16(TAMANHO_DO_CONTADOR);
    sem_parametros(tpm, q.fechar())
}

/// `TPM2_NV_UndefineSpace`, pela hierarquia do dono. Só os testes apagam.
pub fn apagar<T: Tpm>(tpm: &mut T, indice: u32, senha_do_dono: &[u8]) -> Result<(), Erro> {
    let mut q = Quadro::novo(COM_SESSOES, comando::NV_UNDEFINE_SPACE);
    q.u32(DONO);
    q.u32(indice);
    q.sessao_de_senha(senha_do_dono);
    sem_parametros(tpm, q.fechar())
}

/// `TPM2_NV_Increment`, autorizado pela senha do próprio índice.
pub fn incrementar<T: Tpm>(tpm: &mut T, indice: u32, senha: &[u8]) -> Result<(), Erro> {
    let mut q = Quadro::novo(COM_SESSOES, comando::NV_INCREMENT);
    q.u32(indice);
    q.u32(indice);
    q.sessao_de_senha(senha);
    sem_parametros(tpm, q.fechar())
}

/// `TPM2_NV_Write` dos oito bytes de um índice comum, a partir do início.
pub fn escrever<T: Tpm>(tpm: &mut T, indice: u32, senha: &[u8], valor: u64) -> Result<(), Erro> {
    let mut q = Quadro::novo(COM_SESSOES, comando::NV_WRITE);
    q.u32(indice);
    q.u32(indice);
    q.sessao_de_senha(senha);
    q.tpm2b(&valor.to_be_bytes());
    q.u16(0);
    sem_parametros(tpm, q.fechar())
}

/// `TPM2_NV_Read` dos oito bytes do contador — ou de um índice comum do
/// mesmo tamanho, como o do nascimento.
pub fn ler_contador<T: Tpm>(tpm: &mut T, indice: u32, senha: &[u8]) -> Result<u64, Erro> {
    let mut q = Quadro::novo(COM_SESSOES, comando::NV_READ);
    q.u32(indice);
    q.u32(indice);
    q.sessao_de_senha(senha);
    q.u16(TAMANHO_DO_CONTADOR);
    q.u16(0);
    let mut r = [0; MAIOR_QUADRO];
    let (codigo, mut leitor) = trocar(tpm, q.fechar(), &mut r)?;
    if codigo != codigo::SUCESSO {
        return Err(Erro::Codigo(codigo));
    }
    let tamanho_dos_parametros = leitor.u32()? as usize;
    let dados = leitor.tpm2b()?;
    if tamanho_dos_parametros != 2 + dados.len() {
        return Err(Erro::RespostaMalformada(
            "o tamanho dos parametros nao e o do buffer lido",
        ));
    }
    let dados: [u8; 8] = dados
        .try_into()
        .map_err(|_| Erro::RespostaMalformada("o contador nao veio com oito bytes"))?;
    ler_sessao_de_resposta(&mut leitor)?;
    Ok(u64::from_be_bytes(dados))
}

/// Um comando com sessão cuja resposta não tem parâmetros.
fn sem_parametros<T: Tpm>(tpm: &mut T, comando: &[u8]) -> Result<(), Erro> {
    let mut r = [0; MAIOR_QUADRO];
    let (codigo, mut leitor) = trocar(tpm, comando, &mut r)?;
    if codigo != codigo::SUCESSO {
        return Err(Erro::Codigo(codigo));
    }
    if leitor.u32()? != 0 {
        return Err(Erro::RespostaMalformada("o comando nao devolve parametros"));
    }
    ler_sessao_de_resposta(&mut leitor)
}

/// O contador da âncora: um índice de NV do TPM e a senha dele.
pub struct Ancora {
    indice: u32,
    senha: [u8; 32],
}

/// O que se encontra ao abrir a âncora.
pub enum Aberta {
    /// O contador existe, é o nosso, e vale isto.
    Presente(Ancora, u64),
    /// Não há índice nenhum neste número: o TPM nunca teve âncora — ou
    /// foi limpo. Quem decide qual dos dois é o journal.
    Ausente,
}

impl Ancora {
    /// Inicia o TPM e procura o contador `indice`.
    ///
    /// Um índice que existe mas não é exatamente o contador que
    /// [`Ancora::criar`] faz é [`Erro::IndiceEstranho`], e não um contador
    /// a aproveitar: um valor que outra pessoa pôs ali, com outras regras,
    /// não ancora nada.
    pub fn abrir<T: Tpm>(tpm: &mut T, indice: u32, senha: [u8; 32]) -> Result<Aberta, Erro> {
        iniciar(tpm)?;
        let Some(publico) = ler_publico(tpm, indice)? else {
            return Ok(Aberta::Ausente);
        };
        if publico.atributos & !atributo::ESCRITO != atributo::DA_ANCORA
            || publico.algoritmo_do_nome != SHA256
            || publico.tem_politica
            || publico.tamanho != TAMANHO_DO_CONTADOR
        {
            return Err(Erro::IndiceEstranho);
        }
        let ancora = Ancora { indice, senha };
        // Definido e nunca avançado: a criação foi interrompida entre os
        // dois comandos. Avançar agora a completa — o primeiro avanço é o
        // que dá valor a um contador.
        let valor = match ler_contador(tpm, indice, &ancora.senha) {
            Err(Erro::Codigo(codigo::NV_NAO_INICIALIZADO)) => ancora.avancar(tpm)?,
            outro => outro?,
        };
        Ok(Aberta::Presente(ancora, valor))
    }

    /// Cria o contador e dá a ele o primeiro valor.
    ///
    /// O primeiro valor **não** é zero nem um: um contador novo nasce no
    /// maior valor que qualquer contador daquele TPM já teve. Apagar a
    /// âncora e criá-la de novo, portanto, não a faz voltar.
    pub fn criar<T: Tpm>(
        tpm: &mut T,
        indice: u32,
        senha_do_dono: &[u8],
        senha: [u8; 32],
    ) -> Result<(Ancora, u64), Erro> {
        iniciar(tpm)?;
        definir_contador(tpm, indice, senha_do_dono, &senha)?;
        let ancora = Ancora { indice, senha };
        let valor = ancora.avancar(tpm)?;
        Ok((ancora, valor))
    }

    /// O valor atual.
    pub fn ler<T: Tpm>(&self, tpm: &mut T) -> Result<u64, Erro> {
        ler_contador(tpm, self.indice, &self.senha)
    }

    /// Avança um e devolve o valor novo, lido de volta do TPM.
    ///
    /// Ler de volta, e não somar um ao que se sabia, porque o valor que
    /// importa é o do chip: se outro avanço aconteceu no meio — um que este
    /// kernel não fez —, é ele que precisa aparecer.
    pub fn avancar<T: Tpm>(&self, tpm: &mut T) -> Result<u64, Erro> {
        incrementar(tpm, self.indice, &self.senha)?;
        self.ler(tpm)
    }

    /// O índice de NV.
    pub fn indice(&self) -> u32 {
        self.indice
    }

    /// O valor com que o contador nasceu, guardado no índice `indice`, ou
    /// `None` se ainda não foi guardado — o índice não existe, ou existe e
    /// nunca foi escrito.
    ///
    /// Um índice que existe e não é o que [`Ancora::registrar_nascimento`]
    /// faz é [`Erro::IndiceEstranho`], pela mesma razão que o da âncora.
    pub fn nascimento<T: Tpm>(&self, tpm: &mut T, indice: u32) -> Result<Option<u64>, Erro> {
        let Some(publico) = ler_publico(tpm, indice)? else {
            return Ok(None);
        };
        if publico.atributos & !atributo::ESCRITO != atributo::DO_NASCIMENTO
            || publico.algoritmo_do_nome != SHA256
            || publico.tem_politica
            || publico.tamanho != TAMANHO_DO_CONTADOR
        {
            return Err(Erro::IndiceEstranho);
        }
        match ler_contador(tpm, indice, &self.senha) {
            Err(Erro::Codigo(codigo::NV_NAO_INICIALIZADO)) => Ok(None),
            outro => outro.map(Some),
        }
    }

    /// Guarda no índice `indice` o valor do contador **agora**, como o do
    /// nascimento, e o devolve. Define o índice se ele não existe.
    ///
    /// Quem chama garante que o contador ainda não passou do valor com que
    /// nasceu — que nenhum registro foi confirmado contra ele. É o caso na
    /// criação, e na retomada de uma criação interrompida com o journal
    /// vazio.
    pub fn registrar_nascimento<T: Tpm>(
        &self,
        tpm: &mut T,
        indice: u32,
        senha_do_dono: &[u8],
    ) -> Result<u64, Erro> {
        match definir(
            tpm,
            indice,
            senha_do_dono,
            &self.senha,
            atributo::DO_NASCIMENTO,
        ) {
            Ok(()) | Err(Erro::Codigo(codigo::NV_JA_DEFINIDO)) => {}
            Err(e) => return Err(e),
        }
        // Definido por outro alguém com outras regras não serve.
        if let Some(p) = ler_publico(tpm, indice)?
            && p.atributos & !atributo::ESCRITO != atributo::DO_NASCIMENTO
        {
            return Err(Erro::IndiceEstranho);
        }
        let valor = self.ler(tpm)?;
        escrever(tpm, indice, &self.senha, valor)?;
        Ok(valor)
    }
}

impl Drop for Ancora {
    /// A senha sai da memória com a âncora.
    fn drop(&mut self) {
        self.senha.zeroize();
    }
}

#[cfg(test)]
mod testes;
