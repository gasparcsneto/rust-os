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
//! # A autorização, e o barramento
//!
//! O contador é criado com uma senha (o `authValue` do índice), e só quem
//! a tem o lê e o avança. A senha **não passa pelo barramento**: todo
//! comando que a usa vai numa sessão HMAC (parte 1 da especificação,
//! capítulo 19), que prova que quem pede conhece a senha sem mostrá-la — um
//! HMAC do comando, com a chave da sessão e a senha, e dois nonces que
//! mudam a cada comando. A resposta volta com o HMAC do TPM, e é conferida:
//! um valor de contador forjado, adulterado ou repetido de antes não passa.
//!
//! A sessão é **salgada** com a chave de endosso do TPM (a EK, criada pelo
//! modelo padrão do TCG, sempre a mesma num mesmo TPM): um segredo sorteado
//! aqui, cifrado por ECDH para a EK, que só o TPM decifra. Sem o sal, a
//! chave da sessão seria derivável de quem escuta; com ele, nem a senha do
//! dono vazia — a que define o índice — expõe a senha nova, que vai
//! cifrada no parâmetro, em AES-128-CFB.
//!
//! Quem se põe no meio do barramento e troca a EK por uma sua leria o sal.
//! Por isso a EK é uma chave **fixada**: quem usa este pacote guarda o
//! ponto dela da primeira vez, e diz qual espera — uma EK diferente é
//! [`Erro::ChaveDoTpmTrocada`]. A primeira vez é confiança na primeira
//! vez; conferir a EK pelo certificado do fabricante fica para depois.
//!
//! Quem não tem a senha só consegue o que não ajuda a ninguém: não lê, não
//! avança, e não fabrica resposta que passe. Pode, no barramento, derrubar
//! comandos e respostas — e o efeito é a persistência indisponível, nunca
//! um valor falso aceito.

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

mod cripto;

use cripto::{ChaveDeHmac, TAM};

/// O maior comando ou resposta que este pacote troca com o TPM.
///
/// Os comandos daqui são pequenos; a maior resposta é a da criação da
/// chave de endosso, com umas três centenas de bytes. Um teto fixo, e não
/// `alloc`, porque o pacote roda no kernel antes de qualquer coisa que
/// dependa do journal.
pub const MAIOR_QUADRO: usize = 1024;

/// O transporte até o TPM: manda um comando, devolve a resposta.
pub trait Tpm {
    /// Manda `comando` inteiro e escreve a resposta em `resposta`,
    /// devolvendo quantos bytes ela tem.
    fn trocar(&mut self, comando: &[u8], resposta: &mut [u8; MAIOR_QUADRO]) -> Result<usize, Erro>;
}

/// De onde vêm os nonces e o par efêmero da sessão: um gerador
/// criptográfico.
pub trait Sorteio {
    fn sortear(&mut self, destino: &mut [u8]) -> Result<(), Erro>;
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
    /// A resposta não traz o HMAC que só o TPM, com a senha e a sessão,
    /// faria: forjada, adulterada, ou repetida de antes.
    RespostaNaoAutenticada,
    /// A chave de endosso não é a que se esperava: outro TPM, ou alguém no
    /// barramento fingindo ser ele.
    ChaveDoTpmTrocada,
    /// O gerador não deu os bytes.
    SemEntropia,
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
            Erro::RespostaNaoAutenticada => "a resposta do TPM nao confere com a sessao",
            Erro::ChaveDoTpmTrocada => "a chave de endosso do TPM nao e a que o journal conhece",
            Erro::SemEntropia => "sem entropia para a sessao com o TPM",
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
    pub const CREATE_PRIMARY: u32 = 0x0000_0131;
    pub const START_AUTH_SESSION: u32 = 0x0000_0176;
    pub const FLUSH_CONTEXT: u32 = 0x0000_0165;
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
/// A hierarquia de endosso: onde a EK nasce.
const ENDOSSO: u32 = 0x4000_000B;
/// `TPM_RH_NULL`: a sessão não é vinculada a entidade nenhuma.
const NULO: u32 = 0x4000_0007;
/// `TPM_SE_HMAC`.
const SESSAO_HMAC: u8 = 0x00;
/// A cifra simétrica da sessão e da EK: AES-128 em CFB.
const AES: u16 = 0x0006;
const CFB: u16 = 0x0043;
const ALG_NULO: u16 = 0x0010;
const ECC: u16 = 0x0023;
const P256: u16 = 0x0003;
/// O atributo de sessão que diz que o primeiro parâmetro do comando vai
/// cifrado.
const DECIFRAR: u8 = 0x20;

/// A EK de ECC P-256 pelo modelo L-1 do *TCG EK Credential Profile 2.0*: a
/// mesma chave em todo boot, e a que o certificado do fabricante descreve.
mod ek {
    /// `fixedTPM | fixedParent | sensitiveDataOrigin | adminWithPolicy |
    /// restricted | decrypt`.
    pub const ATRIBUTOS: u32 = 0x0003_00B2;
    /// `PolicySecret(TPM_RH_ENDORSEMENT)`, a política de administração do
    /// modelo.
    pub const POLITICA: [u8; 32] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7,
        0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
        0x69, 0xAA,
    ];
}

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
    // O nome do índice. Não é usado: o nome que entra no HMAC é calculado
    // dos atributos que o índice tem de ter — ver [`nome_do_indice`] —,
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

/// O nome de um índice de NV (parte 1, 16): o algoritmo e o SHA-256 da
/// parte pública. É o que entra no `cpHash` de todo comando sobre o índice
/// — e é calculado aqui, dos atributos que o índice **tem de ter**, e não
/// copiado do que o TPM diz: um índice com outros atributos tem outro nome,
/// e o TPM recusa o HMAC do comando.
pub fn nome_do_indice(indice: u32, atributos: u32) -> [u8; 2 + TAM] {
    let mut publico = [0u8; 4 + 2 + 4 + 2 + 2];
    publico[..4].copy_from_slice(&indice.to_be_bytes());
    publico[4..6].copy_from_slice(&SHA256.to_be_bytes());
    publico[6..10].copy_from_slice(&atributos.to_be_bytes());
    // política vazia: tamanho zero
    publico[12..14].copy_from_slice(&TAMANHO_DO_CONTADOR.to_be_bytes());
    let mut nome = [0u8; 2 + TAM];
    nome[..2].copy_from_slice(&SHA256.to_be_bytes());
    nome[2..].copy_from_slice(&cripto::resumo(&[&publico]));
    nome
}

/// O nome de um handle permanente — a hierarquia do dono: o próprio
/// handle, em quatro bytes.
fn nome_permanente(handle: u32) -> [u8; 4] {
    handle.to_be_bytes()
}

/// `TPM2_NV_UndefineSpace`, pela hierarquia do dono, numa sessão de senha
/// — a senha do dono, que é vazia, e por isso nada vaza. Só os testes
/// apagam.
pub fn apagar<T: Tpm>(tpm: &mut T, indice: u32, senha_do_dono: &[u8]) -> Result<(), Erro> {
    let mut q = Quadro::novo(COM_SESSOES, comando::NV_UNDEFINE_SPACE);
    q.u32(DONO);
    q.u32(indice);
    q.sessao_de_senha(senha_do_dono);
    sem_parametros(tpm, q.fechar())
}

/// Um comando com sessão de senha cuja resposta não tem parâmetros.
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

/// `TPM2_FlushContext`: tira do TPM uma sessão ou um objeto carregado. O
/// erro não importa a quem chama — um handle que o TPM já esqueceu (um
/// reinício, um erro que fechou a sessão) é o mesmo que um apagado.
pub fn esquecer<T: Tpm>(tpm: &mut T, handle: u32) -> Result<(), Erro> {
    let mut q = Quadro::novo(SEM_SESSOES, comando::FLUSH_CONTEXT);
    q.u32(handle);
    let mut r = [0; MAIOR_QUADRO];
    let (codigo, leitor) = trocar(tpm, q.fechar(), &mut r)?;
    if codigo != codigo::SUCESSO {
        return Err(Erro::Codigo(codigo));
    }
    leitor.fim()
}

/// A chave de endosso carregada: o handle e o ponto público.
pub struct ChaveDoTpm {
    handle: u32,
    x: [u8; TAM],
    y: [u8; TAM],
}

impl ChaveDoTpm {
    /// O ponto público, `x ‖ y`: o que se fixa.
    pub fn ponto(&self) -> [u8; 2 * TAM] {
        let mut p = [0; 2 * TAM];
        p[..TAM].copy_from_slice(&self.x);
        p[TAM..].copy_from_slice(&self.y);
        p
    }
}

/// A parte pública da EK, como vai no `TPM2_CreatePrimary` e como tem de
/// voltar — menos o ponto, que no pedido vai zerado.
fn publico_da_ek(q: &mut Quadro, x: &[u8; TAM], y: &[u8; TAM]) {
    q.u16(ECC);
    q.u16(SHA256);
    q.u32(ek::ATRIBUTOS);
    q.tpm2b(&ek::POLITICA);
    q.u16(AES);
    q.u16(128);
    q.u16(CFB);
    q.u16(ALG_NULO); // esquema
    q.u16(P256);
    q.u16(ALG_NULO); // kdf
    q.tpm2b(x);
    q.tpm2b(y);
}

/// `TPM2_CreatePrimary` da EK na hierarquia de endosso, com a senha de
/// endosso vazia. A mesma EK sai em todo boot de um mesmo TPM: ela deriva
/// da semente de endosso, que só muda quando o TPM é limpo de fábrica.
///
/// A resposta não é autenticada — não há com o que autenticá-la ainda. É a
/// fixação, por quem chama, que diz se esta é a EK que se conhece.
pub fn criar_chave_do_tpm<T: Tpm>(tpm: &mut T) -> Result<ChaveDoTpm, Erro> {
    let mut publico = Quadro {
        bytes: [0; MAIOR_QUADRO],
        tam: 0,
    };
    publico_da_ek(&mut publico, &[0; TAM], &[0; TAM]);
    let mut q = Quadro::novo(COM_SESSOES, comando::CREATE_PRIMARY);
    q.u32(ENDOSSO);
    q.sessao_de_senha(&[]);
    // TPM2B_SENSITIVE_CREATE: sem senha da chave e sem dados.
    q.u16(4);
    q.tpm2b(&[]);
    q.tpm2b(&[]);
    q.tpm2b(&publico.bytes[..publico.tam]);
    q.tpm2b(&[]); // outsideInfo
    q.u32(0); // nenhuma seleção de PCR
    let mut r = [0; MAIOR_QUADRO];
    let (codigo, mut leitor) = trocar(tpm, q.fechar(), &mut r)?;
    if codigo != codigo::SUCESSO {
        return Err(Erro::Codigo(codigo));
    }
    let handle = leitor.u32()?;
    let tamanho = leitor.u32()? as usize;
    let inicio = leitor.pos;
    let p = leitor.tpm2b()?;
    let mut lp = Leitor { bytes: p, pos: 0 };
    let mut esperado = Quadro {
        bytes: [0; MAIOR_QUADRO],
        tam: 0,
    };
    // O que a EK tem de ser, tirado o ponto: confere byte a byte.
    let prefixo = publico.tam - 2 * (2 + TAM);
    publico_da_ek(&mut esperado, &[0; TAM], &[0; TAM]);
    if lp.bytes(prefixo)? != &esperado.bytes[..prefixo] {
        return Err(Erro::RespostaMalformada(
            "a chave que o TPM criou nao e a EK do modelo",
        ));
    }
    let x: [u8; TAM] = lp
        .tpm2b()?
        .try_into()
        .map_err(|_| Erro::RespostaMalformada("o x da EK nao tem 32 bytes"))?;
    let y: [u8; TAM] = lp
        .tpm2b()?
        .try_into()
        .map_err(|_| Erro::RespostaMalformada("o y da EK nao tem 32 bytes"))?;
    lp.fim()?;
    cripto::ponto(&x, &y)?;
    // O resto — dados e resumo da criação, o tíquete, o nome — não é usado,
    // mas tem de terminar onde o tamanho dos parâmetros diz.
    leitor.tpm2b()?;
    leitor.tpm2b()?;
    leitor.u16()?;
    leitor.u32()?;
    leitor.tpm2b()?;
    leitor.tpm2b()?;
    if leitor.pos - inicio != tamanho {
        return Err(Erro::RespostaMalformada(
            "o tamanho dos parametros nao e o dos parametros",
        ));
    }
    ler_sessao_de_resposta(&mut leitor)?;
    Ok(ChaveDoTpm { handle, x, y })
}

/// Uma sessão HMAC salgada, aberta no TPM.
pub struct Sessao {
    handle: u32,
    chave: [u8; TAM],
    /// O último nonce do TPM: o mais velho, no próximo comando.
    nonce_tpm: [u8; TAM],
}

impl Drop for Sessao {
    fn drop(&mut self) {
        self.chave.zeroize();
    }
}

/// `TPM2_StartAuthSession`: uma sessão HMAC, sem vínculo, salgada pela EK,
/// com AES-128-CFB para a cifra de parâmetro e SHA-256.
pub fn abrir_sessao<T: Tpm>(
    tpm: &mut T,
    chave: &ChaveDoTpm,
    sorteio: &mut dyn Sorteio,
) -> Result<Sessao, Erro> {
    let mut nonce_caller = [0u8; TAM];
    sorteio.sortear(&mut nonce_caller)?;
    let sal = cripto::salgar(&chave.x, &chave.y, sorteio)?;
    let mut q = Quadro::novo(SEM_SESSOES, comando::START_AUTH_SESSION);
    q.u32(chave.handle);
    q.u32(NULO);
    q.tpm2b(&nonce_caller);
    // TPM2B_ENCRYPTED_SECRET com o TPMS_ECC_POINT efêmero.
    q.u16(2 * (2 + TAM as u16));
    q.tpm2b(&sal.x);
    q.tpm2b(&sal.y);
    q.u8(SESSAO_HMAC);
    q.u16(AES);
    q.u16(128);
    q.u16(CFB);
    q.u16(SHA256);
    let mut r = [0; MAIOR_QUADRO];
    // O sal se apaga sozinho ao sair, por erro ou não.
    let (codigo, mut leitor) = trocar(tpm, q.fechar(), &mut r)?;
    if codigo != codigo::SUCESSO {
        return Err(Erro::Codigo(codigo));
    }
    let handle = leitor.u32()?;
    let nonce_tpm: [u8; TAM] = leitor
        .tpm2b()?
        .try_into()
        .map_err(|_| Erro::RespostaMalformada("o nonce do TPM nao tem 32 bytes"))?;
    leitor.fim()?;
    Ok(Sessao {
        handle,
        chave: cripto::chave_da_sessao(&sal.sal, &nonce_tpm, &nonce_caller),
        nonce_tpm,
    })
}

/// Um handle de comando e o nome dele, para o `cpHash`.
struct Entidade<'a> {
    handle: u32,
    nome: &'a [u8],
}

/// Um comando a mandar pela sessão: o código, as entidades — a primeira é
/// a autorizada —, a senha dela, os parâmetros, e se o primeiro vai
/// cifrado.
struct Pedido<'a> {
    codigo: u32,
    entidades: &'a [Entidade<'a>],
    senha: &'a [u8],
    parametros: &'a mut [u8],
    cifrar_o_primeiro: bool,
}

/// Um comando pela sessão: autoriza `entidades[0]` com `senha`, manda,
/// confere a resposta e devolve os parâmetros dela em `saida`.
///
/// # O que se confere
///
/// - O comando leva `HMAC(chave da sessão ‖ senha, cpHash ‖ nonceCaller ‖
///   nonceTPM ‖ atributos)`, com um `nonceCaller` sorteado agora.
/// - A resposta tem de trazer `HMAC(chave ‖ senha, rpHash ‖ nonceTPM novo ‖
///   nonceCaller ‖ atributos)`. Uma resposta forjada não tem a chave; uma
///   adulterada não tem o `rpHash`; uma repetida de antes foi feita para
///   outro `nonceCaller`. Nenhuma das três passa.
/// - Com `cifrar_o_primeiro`, o primeiro parâmetro (um `TPM2B`) vai em
///   AES-128-CFB com a chave do `KDFa(…, "CFB", nonceCaller, nonceTPM)`.
///
/// Qualquer erro — do TPM ou da conferência — fecha a sessão: um erro não
/// gira os nonces, e não há como saber em que pé ela ficou.
fn pela_sessao<T: Tpm>(
    tpm: &mut T,
    sessao: &mut Sessao,
    sorteio: &mut dyn Sorteio,
    pedido: Pedido,
    saida: &mut [u8; MAIOR_QUADRO],
) -> Result<usize, Erro> {
    let Pedido {
        codigo: codigo_do_comando,
        entidades,
        senha,
        parametros,
        cifrar_o_primeiro,
    } = pedido;
    let mut nonce_caller = [0u8; TAM];
    sorteio.sortear(&mut nonce_caller)?;
    let chave = ChaveDeHmac::nova(&sessao.chave, senha);
    let mut atributos = CONTINUAR_SESSAO;
    if cifrar_o_primeiro {
        atributos |= DECIFRAR;
        let n = u16::from_be_bytes([parametros[0], parametros[1]]) as usize;
        cripto::cfb(
            &chave,
            &nonce_caller,
            &sessao.nonce_tpm,
            &mut parametros[2..2 + n],
            false,
        );
    }
    let mut nomes = [0u8; 2 * (2 + TAM)];
    let mut tam_nomes = 0;
    for e in entidades {
        nomes[tam_nomes..tam_nomes + e.nome.len()].copy_from_slice(e.nome);
        tam_nomes += e.nome.len();
    }
    let cp = cripto::resumo(&[
        &codigo_do_comando.to_be_bytes(),
        &nomes[..tam_nomes],
        parametros,
    ]);
    let hmac = cripto::hmac(
        chave.como_bytes(),
        &[&cp, &nonce_caller, &sessao.nonce_tpm, &[atributos]],
    );
    let mut q = Quadro::novo(COM_SESSOES, codigo_do_comando);
    for e in entidades {
        q.u32(e.handle);
    }
    // handle (4) + nonce (2 + 32) + atributos (1) + hmac (2 + 32)
    q.u32(4 + 2 + TAM as u32 + 1 + 2 + TAM as u32);
    q.u32(sessao.handle);
    q.tpm2b(&nonce_caller);
    q.u8(atributos);
    q.tpm2b(&hmac);
    q.bytes(parametros);
    let mut r = [0; MAIOR_QUADRO];
    let (codigo, mut leitor) = trocar(tpm, q.fechar(), &mut r)?;
    if codigo != codigo::SUCESSO {
        return Err(Erro::Codigo(codigo));
    }
    let n = leitor.u32()? as usize;
    let rp = leitor.bytes(n)?;
    let nonce_novo: [u8; TAM] = leitor
        .tpm2b()?
        .try_into()
        .map_err(|_| Erro::RespostaMalformada("o nonce do TPM nao tem 32 bytes"))?;
    let atributos_da_resposta = leitor.u8()?;
    let hmac_da_resposta = leitor.tpm2b()?;
    leitor.fim()?;
    let rph = cripto::resumo(&[
        &codigo::SUCESSO.to_be_bytes(),
        &codigo_do_comando.to_be_bytes(),
        rp,
    ]);
    let esperado = cripto::hmac(
        chave.como_bytes(),
        &[&rph, &nonce_novo, &nonce_caller, &[atributos_da_resposta]],
    );
    if !cripto::iguais(&esperado, hmac_da_resposta) || atributos_da_resposta & CONTINUAR_SESSAO == 0
    {
        return Err(Erro::RespostaNaoAutenticada);
    }
    sessao.nonce_tpm = nonce_novo;
    saida[..n].copy_from_slice(rp);
    Ok(n)
}

/// O contador da âncora, falando com o TPM por uma sessão autenticada.
pub struct Ancora {
    indice: u32,
    senha: [u8; 32],
    chave: ChaveDoTpm,
    sessao: Option<Sessao>,
    /// Se o contador já foi escrito (avançado): o atributo que o TPM liga
    /// na primeira escrita, e que muda o nome do índice. `None` quando não
    /// se sabe — depois de um erro no meio de um avanço.
    escrito: Option<bool>,
}

impl Ancora {
    /// Inicia o TPM, cria a EK e a confere com `esperada`, se houver uma —
    /// a fixada da última vez. Sem `esperada`, a EK é aceita como é, e quem
    /// chama a fixa com [`Ancora::ponto_do_tpm`].
    ///
    /// Nada aqui toca no contador: a sessão abre no primeiro comando.
    pub fn conectar<T: Tpm>(
        tpm: &mut T,
        indice: u32,
        senha: [u8; 32],
        esperada: Option<&[u8; 2 * TAM]>,
    ) -> Result<Ancora, Erro> {
        iniciar(tpm)?;
        let chave = criar_chave_do_tpm(tpm)?;
        if let Some(e) = esperada
            && !cripto::iguais(e, &chave.ponto())
        {
            let _ = esquecer(tpm, chave.handle);
            return Err(Erro::ChaveDoTpmTrocada);
        }
        Ok(Ancora {
            indice,
            senha,
            chave,
            sessao: None,
            escrito: None,
        })
    }

    /// O ponto da EK com que esta âncora fala: o que se fixa.
    pub fn ponto_do_tpm(&self) -> [u8; 2 * TAM] {
        self.chave.ponto()
    }

    /// O índice de NV.
    pub fn indice(&self) -> u32 {
        self.indice
    }

    /// Se o contador existe. Um índice que existe mas não é exatamente o
    /// contador que [`Ancora::definir`] faz é [`Erro::IndiceEstranho`]: um
    /// valor que outra pessoa pôs ali, com outras regras, não ancora nada.
    pub fn existe<T: Tpm>(&mut self, tpm: &mut T) -> Result<bool, Erro> {
        let Some(publico) = ler_publico(tpm, self.indice)? else {
            return Ok(false);
        };
        conferir(&publico, atributo::DA_ANCORA)?;
        self.escrito = Some(publico.atributos & atributo::ESCRITO != 0);
        Ok(true)
    }

    /// Define o contador, pela hierarquia do dono, com a senha desta
    /// âncora — que vai cifrada no parâmetro, e não em claro.
    pub fn definir<T: Tpm>(
        &mut self,
        tpm: &mut T,
        senha_do_dono: &[u8],
        sorteio: &mut dyn Sorteio,
    ) -> Result<(), Erro> {
        let indice = self.indice;
        self.definir_indice(tpm, indice, senha_do_dono, atributo::DA_ANCORA, sorteio)?;
        self.escrito = Some(false);
        Ok(())
    }

    /// O valor do contador. Definido e nunca avançado — a criação parou
    /// entre os dois —, avança agora: o primeiro avanço é o que dá valor a
    /// um contador.
    pub fn valor<T: Tpm>(&mut self, tpm: &mut T, sorteio: &mut dyn Sorteio) -> Result<u64, Erro> {
        match self.ler(tpm, sorteio) {
            Err(Erro::Codigo(codigo::NV_NAO_INICIALIZADO)) => self.avancar(tpm, sorteio),
            outro => outro,
        }
    }

    /// O valor atual, lido pela sessão: a resposta é do TPM, ou é erro.
    pub fn ler<T: Tpm>(&mut self, tpm: &mut T, sorteio: &mut dyn Sorteio) -> Result<u64, Erro> {
        let (indice, atributos) = (self.indice, self.atributos(tpm)?);
        self.ler_indice(tpm, indice, atributos, sorteio)
    }

    /// Avança um. Não diz o valor novo: quem quer saber lê — ver
    /// [`Ancora::avancar`].
    pub fn incrementar<T: Tpm>(
        &mut self,
        tpm: &mut T,
        sorteio: &mut dyn Sorteio,
    ) -> Result<(), Erro> {
        let atributos = self.atributos(tpm)?;
        let nome = nome_do_indice(self.indice, atributos);
        let entidades = [
            Entidade {
                handle: self.indice,
                nome: &nome,
            },
            Entidade {
                handle: self.indice,
                nome: &nome,
            },
        ];
        let mut saida = [0; MAIOR_QUADRO];
        // Daqui até a resposta conferida, não se sabe se o contador andou.
        self.escrito = None;
        let n = self.comando(
            tpm,
            sorteio,
            comando::NV_INCREMENT,
            &entidades,
            &mut [],
            &mut saida,
        )?;
        if n != 0 {
            return Err(Erro::RespostaMalformada("o comando nao devolve parametros"));
        }
        self.escrito = Some(true);
        Ok(())
    }

    /// Avança um e devolve o valor novo, lido de volta do TPM.
    ///
    /// Ler de volta, e não somar um ao que se sabia, porque o valor que
    /// importa é o do chip: se outro avanço aconteceu no meio — um que este
    /// kernel não fez —, é ele que precisa aparecer.
    pub fn avancar<T: Tpm>(&mut self, tpm: &mut T, sorteio: &mut dyn Sorteio) -> Result<u64, Erro> {
        self.incrementar(tpm, sorteio)?;
        self.ler(tpm, sorteio)
    }

    /// O valor com que o contador nasceu, guardado no índice `indice`, ou
    /// `None` se ainda não foi guardado — o índice não existe, ou existe e
    /// nunca foi escrito. Um índice que não é o que
    /// [`Ancora::registrar_nascimento`] faz é [`Erro::IndiceEstranho`].
    pub fn nascimento<T: Tpm>(
        &mut self,
        tpm: &mut T,
        indice: u32,
        sorteio: &mut dyn Sorteio,
    ) -> Result<Option<u64>, Erro> {
        let Some(publico) = ler_publico(tpm, indice)? else {
            return Ok(None);
        };
        conferir(&publico, atributo::DO_NASCIMENTO)?;
        if publico.atributos & atributo::ESCRITO == 0 {
            return Ok(None);
        }
        self.ler_indice(tpm, indice, publico.atributos, sorteio)
            .map(Some)
    }

    /// Guarda no índice `indice` o valor do contador **agora**, como o do
    /// nascimento, e o devolve. Define o índice se ele não existe.
    ///
    /// Quem chama garante que o contador ainda não passou do valor com que
    /// nasceu — que nenhum registro foi confirmado contra ele. É o caso na
    /// criação, e na retomada de uma criação interrompida com o journal
    /// vazio.
    pub fn registrar_nascimento<T: Tpm>(
        &mut self,
        tpm: &mut T,
        indice: u32,
        senha_do_dono: &[u8],
        sorteio: &mut dyn Sorteio,
    ) -> Result<u64, Erro> {
        let atributos = match ler_publico(tpm, indice)? {
            Some(p) => {
                // Definido por outro alguém com outras regras não serve.
                conferir(&p, atributo::DO_NASCIMENTO)?;
                p.atributos
            }
            None => {
                self.definir_indice(tpm, indice, senha_do_dono, atributo::DO_NASCIMENTO, sorteio)?;
                atributo::DO_NASCIMENTO
            }
        };
        let valor = self.ler(tpm, sorteio)?;
        let nome = nome_do_indice(indice, atributos);
        let entidades = [
            Entidade {
                handle: indice,
                nome: &nome,
            },
            Entidade {
                handle: indice,
                nome: &nome,
            },
        ];
        let mut parametros = [0u8; 2 + 8 + 2];
        parametros[..2].copy_from_slice(&8u16.to_be_bytes());
        parametros[2..10].copy_from_slice(&valor.to_be_bytes());
        let mut saida = [0; MAIOR_QUADRO];
        let n = self.comando(
            tpm,
            sorteio,
            comando::NV_WRITE,
            &entidades,
            &mut parametros,
            &mut saida,
        )?;
        if n != 0 {
            return Err(Erro::RespostaMalformada("o comando nao devolve parametros"));
        }
        Ok(valor)
    }

    /// Fecha a sessão e tira a EK do TPM. O que não sair — um TPM que já
    /// esqueceu os dois — não importa.
    pub fn encerrar<T: Tpm>(mut self, tpm: &mut T) {
        if let Some(s) = self.sessao.take() {
            let _ = esquecer(tpm, s.handle);
        }
        let _ = esquecer(tpm, self.chave.handle);
    }

    /// Os atributos do contador como o TPM os tem agora, para o nome.
    fn atributos<T: Tpm>(&mut self, tpm: &mut T) -> Result<u32, Erro> {
        let escrito = match self.escrito {
            Some(e) => e,
            None => {
                if !self.existe(tpm)? {
                    return Err(Erro::Codigo(codigo::INDICE_INEXISTENTE));
                }
                self.escrito.unwrap_or(false)
            }
        };
        Ok(atributo::DA_ANCORA | if escrito { atributo::ESCRITO } else { 0 })
    }

    /// `TPM2_NV_Read` dos oito bytes de `indice`, com estes `atributos`.
    fn ler_indice<T: Tpm>(
        &mut self,
        tpm: &mut T,
        indice: u32,
        atributos: u32,
        sorteio: &mut dyn Sorteio,
    ) -> Result<u64, Erro> {
        let nome = nome_do_indice(indice, atributos);
        let entidades = [
            Entidade {
                handle: indice,
                nome: &nome,
            },
            Entidade {
                handle: indice,
                nome: &nome,
            },
        ];
        let mut parametros = [0u8; 4];
        parametros[..2].copy_from_slice(&TAMANHO_DO_CONTADOR.to_be_bytes());
        let mut saida = [0; MAIOR_QUADRO];
        let n = self.comando(
            tpm,
            sorteio,
            comando::NV_READ,
            &entidades,
            &mut parametros,
            &mut saida,
        )?;
        let mut l = Leitor {
            bytes: &saida[..n],
            pos: 0,
        };
        let dados: [u8; 8] = l
            .tpm2b()?
            .try_into()
            .map_err(|_| Erro::RespostaMalformada("o contador nao veio com oito bytes"))?;
        l.fim()?;
        Ok(u64::from_be_bytes(dados))
    }

    /// `TPM2_NV_DefineSpace` de um índice de oito bytes, pela hierarquia
    /// do dono, com a senha desta âncora cifrada no parâmetro.
    fn definir_indice<T: Tpm>(
        &mut self,
        tpm: &mut T,
        indice: u32,
        senha_do_dono: &[u8],
        atributos: u32,
        sorteio: &mut dyn Sorteio,
    ) -> Result<(), Erro> {
        let mut p = Quadro {
            bytes: [0; MAIOR_QUADRO],
            tam: 0,
        };
        p.tpm2b(&self.senha);
        // TPM2B_NV_PUBLIC: índice, algoritmo do nome, atributos, política
        // vazia, tamanho.
        p.u16(4 + 2 + 4 + 2 + 2);
        p.u32(indice);
        p.u16(SHA256);
        p.u32(atributos);
        p.tpm2b(&[]);
        p.u16(TAMANHO_DO_CONTADOR);
        let nome = nome_permanente(DONO);
        let entidades = [Entidade {
            handle: DONO,
            nome: &nome,
        }];
        let mut saida = [0; MAIOR_QUADRO];
        let tam = p.tam;
        let resultado = self.pela_sessao(
            tpm,
            sorteio,
            Pedido {
                codigo: comando::NV_DEFINE_SPACE,
                entidades: &entidades,
                senha: senha_do_dono,
                parametros: &mut p.bytes[..tam],
                cifrar_o_primeiro: true,
            },
            &mut saida,
        );
        // A senha esteve aqui em claro antes de cifrada.
        p.bytes.zeroize();
        if resultado? != 0 {
            return Err(Erro::RespostaMalformada("o comando nao devolve parametros"));
        }
        Ok(())
    }

    /// Um comando autorizado pela senha desta âncora.
    fn comando<T: Tpm>(
        &mut self,
        tpm: &mut T,
        sorteio: &mut dyn Sorteio,
        codigo: u32,
        entidades: &[Entidade],
        parametros: &mut [u8],
        saida: &mut [u8; MAIOR_QUADRO],
    ) -> Result<usize, Erro> {
        let mut senha = self.senha;
        let r = self.pela_sessao(
            tpm,
            sorteio,
            Pedido {
                codigo,
                entidades,
                senha: &senha,
                parametros,
                cifrar_o_primeiro: false,
            },
            saida,
        );
        senha.zeroize();
        r
    }

    /// Um pedido pela sessão — aberta agora, se não houver uma. Um erro
    /// fecha a sessão.
    fn pela_sessao<T: Tpm>(
        &mut self,
        tpm: &mut T,
        sorteio: &mut dyn Sorteio,
        pedido: Pedido,
        saida: &mut [u8; MAIOR_QUADRO],
    ) -> Result<usize, Erro> {
        if self.sessao.is_none() {
            self.sessao = Some(abrir_sessao(tpm, &self.chave, sorteio)?);
        }
        let sessao = self.sessao.as_mut().expect("aberta acima");
        let r = pela_sessao(tpm, sessao, sorteio, pedido, saida);
        if r.is_err()
            && let Some(s) = self.sessao.take()
        {
            let _ = esquecer(tpm, s.handle);
        }
        r
    }
}

/// Confere que um índice é exatamente o que este pacote define.
fn conferir(publico: &Publico, atributos: u32) -> Result<(), Erro> {
    if publico.atributos & !atributo::ESCRITO != atributos
        || publico.algoritmo_do_nome != SHA256
        || publico.tem_politica
        || publico.tamanho != TAMANHO_DO_CONTADOR
    {
        return Err(Erro::IndiceEstranho);
    }
    Ok(())
}

impl Drop for Ancora {
    /// A senha sai da memória com a âncora.
    fn drop(&mut self) {
        self.senha.zeroize();
    }
}

#[cfg(test)]
mod testes;
