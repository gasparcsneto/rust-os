//! O cofre: as sementes das chaves seladas no TPM, e o índice de geração
//! que as mata.
//!
//! # O que guarda
//!
//! Uma semente de 32 bytes por objeto selado — um *keyedhash* sem uso de
//! chave, o "sealed data" da especificação —, filho de um primário de
//! armazenamento que o TPM deriva da semente do dono: o mesmo primário a
//! cada boot, recriado, e nunca gravado no NV. O objeto volta do
//! `TPM2_Create` como dois blocos — a parte pública e a privada, esta
//! cifrada e autenticada com uma chave que só este TPM deriva, do primário
//! — e são eles que o journal guarda. Fora deste TPM não abrem: outro TPM
//! tem outro primário, e `fixedTPM` com `fixedParent` impede duplicá-los.
//!
//! # A política: o índice de geração
//!
//! O objeto não tem senha que valha: `userWithAuth` desligado e
//! `adminWithPolicy` ligado — todo uso passa pela política, e a política é
//! uma só: `TPM2_PolicyNV` sobre o índice de geração, com o valor **igual**
//! ao que o contador tinha quando o objeto foi selado. O índice é um
//! contador de NV como a âncora: só cresce, e um recriado nasce no maior
//! valor que o TPM já viu. Avançá-lo mata de uma vez todo objeto selado
//! antes — inclusive os de uma cópia antiga do disco, que o journal já
//! esqueceu. A geração não está fora do objeto, num campo que se troque: a
//! política entra na parte pública, a parte pública no nome, e o nome na
//! integridade do bloco privado. Um selado com outra geração escrita ao
//! lado não carrega.
//!
//! O `TPM2_PolicyNV` é autorizado pela senha do índice, pela sessão salgada
//! da âncora — como uma leitura dele. Quem não tem a senha não prova a
//! geração, e não abre nada.
//!
//! # O barramento
//!
//! A semente nunca passa em claro. No `TPM2_Create` ela é o primeiro
//! parâmetro, cifrado pela sessão salgada da âncora — o mesmo caminho da
//! senha de um índice novo. No `TPM2_Unseal` ela volta cifrada pela sessão
//! de política, também salgada com a EK, e a resposta inteira autenticada
//! pelo HMAC dessa sessão, que cobre o texto cifrado. O comando leva o HMAC
//! da sessão de política sobre o `cpHash`, que tem o nome do objeto: o TPM
//! recusa abrir outro objeto posto no mesmo handle.
//!
//! # O bloqueio
//!
//! O primário e o objeto selado têm `noDA`, e o índice de geração é
//! [`atributo::SEM_BLOQUEIO`]: nenhuma autorização errada neles conta para
//! o bloqueio contra força bruta do TPM, e um TPM bloqueado por outra
//! entidade continua abrindo os selados. Conferido contra o `swtpm`: o
//! primário sem `noDA` recusa o `TPM2_Create` e o `TPM2_Load` com o TPM
//! bloqueado. O selado, que só se usa pela política — sem senha nenhuma —,
//! abriria do mesmo jeito sem o bit; ele está lá para o objeto não depender
//! disso.
//!
//! # O que este módulo não decide
//!
//! Quem pode assinar, quando selar, quando avançar a geração, o que fazer
//! com um objeto que não abre: tudo isso é do kernel. O TPM aqui é custódia
//! — guarda e devolve —, não autoridade.

use zeroize::Zeroize;

use crate::cripto::{self, TAM};
use crate::{
    AES, ALG_NULO, Ancora, CFB, DONO, ECC, Entidade, Erro, Leitor, MAIOR_QUADRO, P256, Pedido,
    Quadro, SEM_SESSOES, SESSAO_POLITICA, SHA256, Sessao, Sorteio, Tpm, abrir_sessao_do_tipo,
    atributo, codigo, comando, conferir, esquecer, ler_publico, nome_do_indice, nome_permanente,
    pela_sessao, trocar,
};

/// `TPM_ALG_KEYEDHASH`: o tipo do objeto selado.
const KEYEDHASH: u16 = 0x0008;
/// `TPM_EO_EQ`: a comparação do `TPM2_PolicyNV` — igual.
const IGUAL: u16 = 0x0000;

/// Os bits de `TPMA_OBJECT` que o cofre usa (parte 2, 8.3).
pub mod objeto {
    /// `fixedTPM`: o objeto não sai deste TPM, nem por um ancestral
    /// duplicado.
    pub const FIXO_NO_TPM: u32 = 1 << 1;
    /// `fixedParent`: o objeto não troca de pai.
    pub const FIXO_NO_PAI: u32 = 1 << 4;
    /// `sensitiveDataOrigin`: o TPM sorteia o segredo. Num objeto selado o
    /// segredo vem de fora, e o TPM recusa o bit ligado.
    pub const SEGREDO_DO_TPM: u32 = 1 << 5;
    /// `userWithAuth`: a senha do objeto autoriza o uso. Desligado no
    /// selado: só a política autoriza.
    pub const USO_COM_SENHA: u32 = 1 << 6;
    /// `adminWithPolicy`: a administração do objeto também só pela política.
    pub const ADMINISTRACAO_PELA_POLITICA: u32 = 1 << 7;
    /// `noDA`: uma autorização errada não conta para o bloqueio do TPM.
    pub const SEM_BLOQUEIO: u32 = 1 << 10;
    /// `restricted`: a chave só serve a usos restritos — aqui, ser pai.
    pub const RESTRITO: u32 = 1 << 16;
    /// `decrypt`: num pai restrito, o que protege os filhos.
    pub const DECIFRA: u32 = 1 << 17;

    /// O primário de armazenamento, com os atributos do modelo de SRK do
    /// TCG.
    pub const DO_PRIMARIO: u32 = FIXO_NO_TPM
        | FIXO_NO_PAI
        | SEGREDO_DO_TPM
        | USO_COM_SENHA
        | SEM_BLOQUEIO
        | RESTRITO
        | DECIFRA;
    /// O objeto selado.
    pub const DO_SELADO: u32 =
        FIXO_NO_TPM | FIXO_NO_PAI | ADMINISTRACAO_PELA_POLITICA | SEM_BLOQUEIO;
}

/// O maior bloco privado de um objeto selado que o cofre aceita. O tamanho
/// depende do TPM — a `libtpms` devolve 158 bytes: a integridade, um vetor
/// de inicialização e a parte sensível, com a senha completada até o
/// tamanho do resumo —, e o teto deixa folga para outro.
pub const MAIOR_PRIVADO: usize = 256;

/// O primário de armazenamento carregado, e a sessão de política com que
/// os objetos selados se abrem.
pub struct Cofre {
    handle: u32,
    nome: [u8; 2 + TAM],
    /// Aberta na primeira abertura e recomeçada em cada uma; sai do TPM
    /// num erro, ou com [`Cofre::fechar_a_politica`].
    politica: Option<Sessao>,
}

impl Cofre {
    /// O nome do primário: o mesmo em todo boot de um mesmo TPM.
    pub fn nome(&self) -> &[u8; 2 + TAM] {
        &self.nome
    }

    /// Tira do TPM só a sessão de política. O boot abre todos os selados
    /// de uma vez; depois dele, ela não serve a mais nada, e ocupa uma das
    /// poucas vagas de sessão do TPM.
    pub fn fechar_a_politica<T: Tpm>(&mut self, tpm: &mut T) {
        if let Some(s) = self.politica.take() {
            let _ = esquecer(tpm, s.handle);
        }
    }

    /// Tira do TPM o primário e a sessão de política. O que não sair — um
    /// TPM que já os esqueceu — não importa.
    pub fn fechar<T: Tpm>(mut self, tpm: &mut T) {
        self.fechar_a_politica(tpm);
        let _ = esquecer(tpm, self.handle);
    }
}

/// O índice de geração: um contador de NV como a âncora, com a senha dele.
pub struct Geracao {
    indice: u32,
    senha: [u8; 32],
    /// Se já foi escrito: o atributo que o TPM liga na primeira escrita, e
    /// que muda o nome do índice. `None` quando não se sabe.
    escrito: Option<bool>,
}

impl Geracao {
    pub fn nova(indice: u32, senha: [u8; 32]) -> Geracao {
        Geracao {
            indice,
            senha,
            escrito: None,
        }
    }

    /// O índice de NV.
    pub fn indice(&self) -> u32 {
        self.indice
    }
}

impl Drop for Geracao {
    /// A senha sai da memória com o índice.
    fn drop(&mut self) {
        self.senha.zeroize();
    }
}

/// Um objeto selado como o journal o guarda: a geração a que está preso, o
/// `unique` da parte pública — o resto dela o cofre refaz, do modelo e da
/// geração —, e o bloco privado, cifrado e autenticado pelo TPM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selado {
    geracao: u64,
    unico: [u8; TAM],
    privado: [u8; MAIOR_PRIVADO],
    tam: usize,
}

impl Selado {
    /// O selado a partir do que o journal guarda. Só os tamanhos se
    /// conferem aqui: o resto, quem confere é o TPM, no `TPM2_Load`.
    pub fn de_partes(geracao: u64, unico: &[u8], privado: &[u8]) -> Result<Selado, Erro> {
        let unico: [u8; TAM] = unico.try_into().map_err(|_| Erro::SeladoEstranho)?;
        if privado.is_empty() || privado.len() > MAIOR_PRIVADO {
            return Err(Erro::SeladoEstranho);
        }
        let mut p = [0; MAIOR_PRIVADO];
        p[..privado.len()].copy_from_slice(privado);
        Ok(Selado {
            geracao,
            unico,
            privado: p,
            tam: privado.len(),
        })
    }

    /// A geração do índice a que o objeto está preso.
    pub fn geracao(&self) -> u64 {
        self.geracao
    }

    /// O `unique` da parte pública: o resumo que o TPM fez da semente com
    /// um sal dele — não diz nada da semente.
    pub fn unico(&self) -> &[u8; TAM] {
        &self.unico
    }

    /// O bloco privado, cifrado pelo TPM.
    pub fn privado(&self) -> &[u8] {
        &self.privado[..self.tam]
    }
}

/// Uma semente aberta, apagada da memória quando sai de uso.
pub struct Semente([u8; TAM]);

impl Semente {
    pub fn como_bytes(&self) -> &[u8; TAM] {
        &self.0
    }
}

impl Drop for Semente {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A política de um objeto selado na geração `geracao` do índice `indice`
/// (parte 3, 23.9): o `TPM2_PolicyNV` com o valor do contador igual a
/// `geracao`, a partir da sessão zerada —
/// `H(0…0 ‖ TPM_CC_PolicyNV ‖ H(geracao ‖ deslocamento ‖ EQ) ‖ nome)`, com
/// o nome do índice já escrito, que é como ele está quando se sela.
pub fn politica_da_geracao(indice: u32, geracao: u64) -> [u8; TAM] {
    let nome = nome_do_indice(indice, atributo::DA_ANCORA | atributo::ESCRITO);
    let argumentos = cripto::resumo(&[
        &geracao.to_be_bytes(),
        &0u16.to_be_bytes(),
        &IGUAL.to_be_bytes(),
    ]);
    cripto::resumo(&[
        &[0u8; TAM],
        &comando::POLICY_NV.to_be_bytes(),
        &argumentos,
        &nome,
    ])
}

/// O nome de um objeto (parte 1, 16): o algoritmo e o SHA-256 da parte
/// pública.
fn nome_do_publico(publico: &[u8]) -> [u8; 2 + TAM] {
    let mut nome = [0u8; 2 + TAM];
    nome[..2].copy_from_slice(&SHA256.to_be_bytes());
    nome[2..].copy_from_slice(&cripto::resumo(&[publico]));
    nome
}

/// A parte pública do primário: ECC P-256, sem política, AES-128-CFB para
/// proteger os filhos, e o `unique` com 32 bytes zerados — o mesmo pedido
/// dá a mesma chave, porque o primário deriva da semente do dono e do
/// modelo inteiro. Na resposta, o `unique` volta com o ponto.
fn publico_do_primario(q: &mut Quadro, x: &[u8], y: &[u8]) {
    q.u16(ECC);
    q.u16(SHA256);
    q.u32(objeto::DO_PRIMARIO);
    q.tpm2b(&[]);
    q.u16(AES);
    q.u16(128);
    q.u16(CFB);
    q.u16(ALG_NULO); // esquema
    q.u16(P256);
    q.u16(ALG_NULO); // kdf
    q.tpm2b(x);
    q.tpm2b(y);
}

/// A parte pública de um objeto selado: *keyedhash* sem esquema — dados, e
/// não chave —, presa à política `politica`, com o `unique` que o TPM deu
/// (vazio no pedido).
fn publico_do_selado(q: &mut Quadro, politica: &[u8; TAM], unico: &[u8]) {
    q.u16(KEYEDHASH);
    q.u16(SHA256);
    q.u32(objeto::DO_SELADO);
    q.tpm2b(politica);
    q.u16(ALG_NULO); // esquema
    q.tpm2b(unico);
}

/// Confere a resposta do `TPM2_CreatePrimary`: a parte pública é a do
/// modelo, com um ponto de P-256, e o nome que o TPM diz é o dela. Devolve
/// o nome.
fn primario_da_resposta(modelo: &Quadro, resposta: &[u8]) -> Result<[u8; 2 + TAM], Erro> {
    let mut l = Leitor {
        bytes: resposta,
        pos: 0,
    };
    let publico = l.tpm2b()?;
    let mut lp = Leitor {
        bytes: publico,
        pos: 0,
    };
    let prefixo = modelo.tam - 2 * (2 + TAM);
    if lp.bytes(prefixo)? != &modelo.bytes[..prefixo] {
        return Err(Erro::RespostaMalformada(
            "o primario que o TPM criou nao e o do modelo",
        ));
    }
    let x: [u8; TAM] = lp
        .tpm2b()?
        .try_into()
        .map_err(|_| Erro::RespostaMalformada("o x do primario nao tem 32 bytes"))?;
    let y: [u8; TAM] = lp
        .tpm2b()?
        .try_into()
        .map_err(|_| Erro::RespostaMalformada("o y do primario nao tem 32 bytes"))?;
    lp.fim()?;
    cripto::ponto(&x, &y)?;
    // Os dados e o resumo da criação e o tíquete não são usados, mas a
    // resposta tem de terminar onde o formato diz.
    l.tpm2b()?;
    l.tpm2b()?;
    l.u16()?;
    l.u32()?;
    l.tpm2b()?;
    let nome = l.tpm2b()?;
    l.fim()?;
    let calculado = nome_do_publico(publico);
    if nome != calculado {
        return Err(Erro::RespostaMalformada(
            "o nome do primario nao e o da parte publica",
        ));
    }
    Ok(calculado)
}

/// Confere a resposta do `TPM2_Create`: o bloco privado cabe, e a parte
/// pública é a do modelo com um `unique` de 32 bytes. Devolve o selado.
fn selado_da_resposta(modelo: &Quadro, geracao: u64, resposta: &[u8]) -> Result<Selado, Erro> {
    let mut l = Leitor {
        bytes: resposta,
        pos: 0,
    };
    let privado = l.tpm2b()?;
    let publico = l.tpm2b()?;
    l.tpm2b()?;
    l.tpm2b()?;
    l.u16()?;
    l.u32()?;
    l.tpm2b()?;
    l.fim()?;
    // O modelo termina no `unique` vazio: dois bytes de tamanho zero.
    let prefixo = modelo.tam - 2;
    let unico = match publico.split_at_checked(prefixo) {
        Some((cabeca, resto)) if cabeca == &modelo.bytes[..prefixo] => resto,
        _ => return Err(Erro::SeladoEstranho),
    };
    let mut lu = Leitor {
        bytes: unico,
        pos: 0,
    };
    let unico = lu.tpm2b()?;
    lu.fim()?;
    Selado::de_partes(geracao, unico, privado)
}

/// `TPM2_PolicyRestart`: a sessão de política volta ao resumo zerado, e a
/// próxima abertura prova a geração do começo.
fn recomecar<T: Tpm>(tpm: &mut T, sessao: &Sessao) -> Result<(), Erro> {
    let mut q = Quadro::novo(SEM_SESSOES, comando::POLICY_RESTART);
    q.u32(sessao.handle);
    let mut r = [0; MAIOR_QUADRO];
    let (codigo, leitor) = trocar(tpm, q.fechar(), &mut r)?;
    if codigo != codigo::SUCESSO {
        return Err(Erro::Codigo(codigo));
    }
    leitor.fim()
}

impl Ancora {
    /// `TPM2_CreatePrimary` do primário de armazenamento, na hierarquia do
    /// dono, pela sessão salgada: a resposta — a parte pública e o nome —
    /// volta autenticada. O mesmo primário sai em todo boot de um mesmo
    /// TPM; ele só muda quando o TPM é limpo, e então nenhum selado abre
    /// mais.
    pub fn abrir_cofre<T: Tpm>(
        &mut self,
        tpm: &mut T,
        senha_do_dono: &[u8],
        sorteio: &mut dyn Sorteio,
    ) -> Result<Cofre, Erro> {
        let mut modelo = Quadro::vazio();
        publico_do_primario(&mut modelo, &[0; TAM], &[0; TAM]);
        let mut p = Quadro::vazio();
        // TPM2B_SENSITIVE_CREATE: sem senha e sem dados.
        p.u16(4);
        p.tpm2b(&[]);
        p.tpm2b(&[]);
        p.tpm2b(&modelo.bytes[..modelo.tam]);
        p.tpm2b(&[]); // outsideInfo
        p.u32(0); // nenhuma seleção de PCR
        let nome_do_dono = nome_permanente(DONO);
        let entidades = [Entidade {
            handle: DONO,
            nome: &nome_do_dono,
        }];
        let mut alca = 0u32;
        let mut saida = [0; MAIOR_QUADRO];
        let tam = p.tam;
        let r = self.pela_sessao(
            tpm,
            sorteio,
            Pedido {
                codigo: comando::CREATE_PRIMARY,
                entidades: &entidades,
                senha: senha_do_dono,
                parametros: &mut p.bytes[..tam],
                cifrar_o_primeiro: false,
                alca_da_resposta: Some(&mut alca),
                decifrar_a_resposta: false,
            },
            &mut saida,
        );
        match r.and_then(|n| primario_da_resposta(&modelo, &saida[..n])) {
            Ok(nome) => Ok(Cofre {
                handle: alca,
                nome,
                politica: None,
            }),
            Err(e) => {
                if alca != 0 {
                    let _ = esquecer(tpm, alca);
                }
                Err(e)
            }
        }
    }

    /// `TPM2_Create` de um objeto selado com `semente`, filho do primário
    /// do `cofre`, preso à geração `valor` do índice `geracao`. A semente
    /// vai cifrada pela sessão salgada, e a resposta volta autenticada por
    /// ela. Devolve o que o journal guarda.
    pub fn selar<T: Tpm>(
        &mut self,
        tpm: &mut T,
        cofre: &Cofre,
        geracao: &Geracao,
        valor: u64,
        semente: &[u8; TAM],
        sorteio: &mut dyn Sorteio,
    ) -> Result<Selado, Erro> {
        let politica = politica_da_geracao(geracao.indice, valor);
        let mut modelo = Quadro::vazio();
        publico_do_selado(&mut modelo, &politica, &[]);
        let mut p = Quadro::vazio();
        // TPM2B_SENSITIVE_CREATE — o primeiro parâmetro, que vai cifrado:
        // sem senha, e a semente como os dados.
        p.u16(2 + 2 + TAM as u16);
        p.tpm2b(&[]);
        p.tpm2b(semente);
        p.tpm2b(&modelo.bytes[..modelo.tam]);
        p.tpm2b(&[]); // outsideInfo
        p.u32(0); // nenhuma seleção de PCR
        let entidades = [Entidade {
            handle: cofre.handle,
            nome: &cofre.nome,
        }];
        let mut saida = [0; MAIOR_QUADRO];
        let tam = p.tam;
        let r = self.pela_sessao(
            tpm,
            sorteio,
            Pedido {
                codigo: comando::CREATE,
                entidades: &entidades,
                senha: &[],
                parametros: &mut p.bytes[..tam],
                cifrar_o_primeiro: true,
                alca_da_resposta: None,
                decifrar_a_resposta: false,
            },
            &mut saida,
        );
        // A semente esteve aqui em claro antes de cifrada.
        p.bytes.zeroize();
        selado_da_resposta(&modelo, valor, &saida[..r?])
    }

    /// Abre um objeto selado: `TPM2_Load` sob o primário, `TPM2_PolicyNV`
    /// na sessão de política — o índice de geração igual à geração do
    /// selado —, e `TPM2_Unseal`, com a semente voltando cifrada pela
    /// sessão de política e a resposta autenticada por ela. O objeto sai
    /// do TPM no fim, aberto ou não.
    ///
    /// Um selado de outra geração não passa do `TPM2_PolicyNV`; um de outro
    /// primário, ou mexido, não passa do `TPM2_Load`. Nenhum dos dois é
    /// motivo para tentar outro caminho: o erro volta como veio.
    pub fn abrir<T: Tpm>(
        &mut self,
        tpm: &mut T,
        cofre: &mut Cofre,
        geracao: &mut Geracao,
        selado: &Selado,
        sorteio: &mut dyn Sorteio,
    ) -> Result<Semente, Erro> {
        let politica = politica_da_geracao(geracao.indice, selado.geracao);
        let mut publico = Quadro::vazio();
        publico_do_selado(&mut publico, &politica, &selado.unico);
        let nome = nome_do_publico(&publico.bytes[..publico.tam]);
        let mut p = Quadro::vazio();
        p.tpm2b(selado.privado());
        p.tpm2b(&publico.bytes[..publico.tam]);
        let entidades = [Entidade {
            handle: cofre.handle,
            nome: &cofre.nome,
        }];
        let mut alca = 0u32;
        let mut saida = [0; MAIOR_QUADRO];
        let tam = p.tam;
        let carregado = self.pela_sessao(
            tpm,
            sorteio,
            Pedido {
                codigo: comando::LOAD,
                entidades: &entidades,
                senha: &[],
                parametros: &mut p.bytes[..tam],
                cifrar_o_primeiro: false,
                alca_da_resposta: Some(&mut alca),
                decifrar_a_resposta: false,
            },
            &mut saida,
        );
        // O nome que o TPM deu ao objeto, autenticado com a resposta: o da
        // parte pública que foi.
        let carregado = carregado.and_then(|n| {
            let mut l = Leitor {
                bytes: &saida[..n],
                pos: 0,
            };
            let lido = l.tpm2b()?;
            l.fim()?;
            if lido == nome {
                Ok(())
            } else {
                Err(Erro::SeladoEstranho)
            }
        });
        let aberto = match carregado {
            Ok(()) => {
                self.abrir_carregado(tpm, cofre, geracao, alca, &nome, selado.geracao, sorteio)
            }
            Err(e) => Err(e),
        };
        if alca != 0 {
            let _ = esquecer(tpm, alca);
        }
        aberto
    }

    /// O objeto `alca`, carregado, de nome `nome`: a política, numa sessão
    /// recomeçada ou nova, e o `TPM2_Unseal`. Um erro tira a sessão do TPM.
    #[allow(clippy::too_many_arguments)]
    fn abrir_carregado<T: Tpm>(
        &mut self,
        tpm: &mut T,
        cofre: &mut Cofre,
        geracao: &mut Geracao,
        alca: u32,
        nome: &[u8; 2 + TAM],
        valor: u64,
        sorteio: &mut dyn Sorteio,
    ) -> Result<Semente, Erro> {
        let mut politica = match cofre.politica.take() {
            Some(s) => {
                if let Err(e) = recomecar(tpm, &s) {
                    let _ = esquecer(tpm, s.handle);
                    return Err(e);
                }
                s
            }
            None => abrir_sessao_do_tipo(tpm, &self.chave, SESSAO_POLITICA, sorteio)?,
        };
        match self.provar_e_abrir(tpm, &mut politica, geracao, alca, nome, valor, sorteio) {
            Ok(s) => {
                cofre.politica = Some(politica);
                Ok(s)
            }
            Err(e) => {
                let _ = esquecer(tpm, politica.handle);
                Err(e)
            }
        }
    }

    /// O `TPM2_PolicyNV` na sessão `politica` e o `TPM2_Unseal` por ela.
    #[allow(clippy::too_many_arguments)]
    fn provar_e_abrir<T: Tpm>(
        &mut self,
        tpm: &mut T,
        politica: &mut Sessao,
        geracao: &mut Geracao,
        alca: u32,
        nome: &[u8; 2 + TAM],
        valor: u64,
        sorteio: &mut dyn Sorteio,
    ) -> Result<Semente, Erro> {
        // O índice autoriza com a senha dele, pela sessão salgada da
        // âncora; a sessão de política entra só como handle — e com o
        // handle como nome, no `cpHash`.
        let atributos = self.atributos_da_geracao(tpm, geracao)?;
        let nome_do_indice = nome_do_indice(geracao.indice, atributos);
        let nome_da_sessao = politica.handle.to_be_bytes();
        let entidades = [
            Entidade {
                handle: geracao.indice,
                nome: &nome_do_indice,
            },
            Entidade {
                handle: geracao.indice,
                nome: &nome_do_indice,
            },
            Entidade {
                handle: politica.handle,
                nome: &nome_da_sessao,
            },
        ];
        // operandB (o valor, oito bytes), o deslocamento zero e a operação.
        let mut parametros = [0u8; 2 + 8 + 2 + 2];
        parametros[..2].copy_from_slice(&8u16.to_be_bytes());
        parametros[2..10].copy_from_slice(&valor.to_be_bytes());
        parametros[12..].copy_from_slice(&IGUAL.to_be_bytes());
        let mut saida = [0; MAIOR_QUADRO];
        let n = self.comando(
            tpm,
            sorteio,
            comando::POLICY_NV,
            &entidades,
            &geracao.senha,
            &mut parametros,
            &mut saida,
        )?;
        if n != 0 {
            return Err(Erro::RespostaMalformada("o comando nao devolve parametros"));
        }
        let entidades = [Entidade { handle: alca, nome }];
        let r = pela_sessao(
            tpm,
            politica,
            sorteio,
            Pedido {
                codigo: comando::UNSEAL,
                entidades: &entidades,
                senha: &[],
                parametros: &mut [],
                cifrar_o_primeiro: false,
                alca_da_resposta: None,
                decifrar_a_resposta: true,
            },
            &mut saida,
        )
        .and_then(|n| {
            let mut l = Leitor {
                bytes: &saida[..n],
                pos: 0,
            };
            let dados: [u8; TAM] = l.tpm2b()?.try_into().map_err(|_| Erro::SeladoEstranho)?;
            l.fim()?;
            Ok(Semente(dados))
        });
        // A semente esteve aqui, decifrada.
        saida.zeroize();
        r
    }

    /// Se o índice de geração existe. Um índice que existe e não é
    /// exatamente o contador que [`Ancora::definir_geracao`] faz é
    /// [`Erro::IndiceEstranho`].
    pub fn geracao_existe<T: Tpm>(
        &mut self,
        tpm: &mut T,
        geracao: &mut Geracao,
    ) -> Result<bool, Erro> {
        let Some(publico) = ler_publico(tpm, geracao.indice)? else {
            geracao.escrito = None;
            return Ok(false);
        };
        conferir(&publico, atributo::DA_ANCORA)?;
        geracao.escrito = Some(publico.atributos & atributo::ESCRITO != 0);
        Ok(true)
    }

    /// Define o índice de geração pela hierarquia do dono, com a senha dele
    /// cifrada no parâmetro. Ele nasce sem valor: o primeiro avanço é o que
    /// dá — ver [`Ancora::valor_da_geracao`].
    pub fn definir_geracao<T: Tpm>(
        &mut self,
        tpm: &mut T,
        geracao: &mut Geracao,
        senha_do_dono: &[u8],
        sorteio: &mut dyn Sorteio,
    ) -> Result<(), Erro> {
        self.definir_indice(
            tpm,
            geracao.indice,
            &geracao.senha,
            senha_do_dono,
            atributo::DA_ANCORA,
            sorteio,
        )?;
        geracao.escrito = Some(false);
        Ok(())
    }

    /// O valor da geração. Definido e nunca avançado — a definição parou
    /// entre os dois —, avança agora, como a âncora.
    pub fn valor_da_geracao<T: Tpm>(
        &mut self,
        tpm: &mut T,
        geracao: &mut Geracao,
        sorteio: &mut dyn Sorteio,
    ) -> Result<u64, Erro> {
        match self.ler_geracao(tpm, geracao, sorteio) {
            Err(Erro::Codigo(codigo::NV_NAO_INICIALIZADO)) => {
                self.avancar_geracao(tpm, geracao, sorteio)
            }
            outro => outro,
        }
    }

    /// O valor da geração, lido pela sessão: a resposta é do TPM, ou é
    /// erro.
    pub fn ler_geracao<T: Tpm>(
        &mut self,
        tpm: &mut T,
        geracao: &mut Geracao,
        sorteio: &mut dyn Sorteio,
    ) -> Result<u64, Erro> {
        let atributos = self.atributos_da_geracao(tpm, geracao)?;
        self.ler_indice(tpm, geracao.indice, atributos, &geracao.senha, sorteio)
    }

    /// Avança a geração um. Não diz o valor novo: quem quer saber lê — ver
    /// [`Ancora::avancar_geracao`].
    pub fn incrementar_geracao<T: Tpm>(
        &mut self,
        tpm: &mut T,
        geracao: &mut Geracao,
        sorteio: &mut dyn Sorteio,
    ) -> Result<(), Erro> {
        let atributos = self.atributos_da_geracao(tpm, geracao)?;
        // Daqui até a resposta conferida, não se sabe se o contador andou.
        geracao.escrito = None;
        self.incrementar_indice(tpm, geracao.indice, atributos, &geracao.senha, sorteio)?;
        geracao.escrito = Some(true);
        Ok(())
    }

    /// Avança a geração um e devolve o valor novo, lido de volta do TPM.
    pub fn avancar_geracao<T: Tpm>(
        &mut self,
        tpm: &mut T,
        geracao: &mut Geracao,
        sorteio: &mut dyn Sorteio,
    ) -> Result<u64, Erro> {
        self.incrementar_geracao(tpm, geracao, sorteio)?;
        self.ler_geracao(tpm, geracao, sorteio)
    }

    /// Os atributos do índice de geração como o TPM os tem agora, para o
    /// nome.
    fn atributos_da_geracao<T: Tpm>(
        &mut self,
        tpm: &mut T,
        geracao: &mut Geracao,
    ) -> Result<u32, Erro> {
        let escrito = match geracao.escrito {
            Some(e) => e,
            None => {
                if !self.geracao_existe(tpm, geracao)? {
                    return Err(Erro::Codigo(codigo::INDICE_INEXISTENTE));
                }
                geracao.escrito.unwrap_or(false)
            }
        };
        Ok(atributo::DA_ANCORA | if escrito { atributo::ESCRITO } else { 0 })
    }
}
