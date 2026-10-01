//! O aperto de mão `Noise_IK_25519_ChaChaPoly_BLAKE2s`, e o transporte que
//! sai dele.
//!
//! # O padrão
//!
//! ```text
//! IK:
//!   <- s
//!   ...
//!   -> e, es, s, ss
//!   <- e, ee, se
//! ```
//!
//! A linha antes das reticências diz que o agente (quem inicia) **já
//! conhece** a chave estática do Duke (quem responde) — ela foi provisionada.
//! É o mesmo padrão do WireGuard. Com isso:
//!
//! - basta uma ida e volta: o agente manda a primeira mensagem já cifrada
//!   para o Duke, e a resposta fecha o aperto;
//! - a chave estática do agente, que é a identidade dele, viaja **cifrada**
//!   desde a primeira mensagem — quem escuta o canal não aprende quem está
//!   falando;
//! - os dois lados se autenticam: o agente prova que tem a chave privada
//!   dele (`ss`, `se`), e o Duke a dele (`es`, `ss`). Um Duke falso não
//!   consegue abrir a primeira mensagem, e um agente falso não consegue
//!   produzir uma que abra.
//!
//! # Os estados, como tipos
//!
//! Cada passo **consome** o estado anterior e devolve o próximo:
//! [`Iniciador`] → [`Aguardando`] → [`Transporte`] de um lado,
//! [`Respondedor`] → [`Recebido`] → [`Transporte`] do outro. Um aperto que
//! falhou no meio deixou o resumo e a chave de encadeamento num estado que
//! não vale mais nada — e, com os passos consumindo o estado, não há como
//! tentar de novo com ele: o compilador não deixa. A alternativa, uma
//! bandeira de "estragado" conferida em cada método, é uma conferência que
//! alguém esquece.
//!
//! # As chaves efêmeras vêm de fora
//!
//! Quem chama passa a chave efêmera, em vez de este pacote sorteá-la. Não é
//! comodidade: é o que permite conferir o aperto contra os vetores
//! publicados, que fixam as efêmeras. E deixa a origem da aleatoriedade com
//! quem a tem — o kernel, com o `virtio-rng`; o cliente, com o sistema dele.

use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::cifra::{Cifra, TAM_ETIQUETA};
use crate::resumo::{TAM_RESUMO, hkdf2, resumir};
use crate::{Erro, MAIOR_MENSAGEM, NOME_DO_PROTOCOLO, TAM_CHAVE};

/// A chave pública de uma chave privada.
pub fn publica_de(secreta: &[u8; TAM_CHAVE]) -> [u8; TAM_CHAVE] {
    PublicKey::from(&StaticSecret::from(*secreta)).to_bytes()
}

/// O acordo de Diffie-Hellman.
///
/// Um resultado todo zerado quer dizer que a chave pública do outro lado é
/// de ordem baixa: qualquer chave privada dá o mesmo segredo com ela, e o
/// "segredo" é público. A especificação deixa recusar ou não; recusamos, como
/// o WireGuard, porque aceitar é deixar um lado escolher o segredo dos dois.
pub(crate) fn dh(secreta: &[u8; TAM_CHAVE], publica: &[u8; TAM_CHAVE]) -> Result<[u8; 32], Erro> {
    let compartilhado = StaticSecret::from(*secreta).diffie_hellman(&PublicKey::from(*publica));
    if !compartilhado.was_contributory() {
        return Err(Erro::ChaveFraca);
    }
    Ok(compartilhado.to_bytes())
}

/// O estado simétrico: a chave de encadeamento, o resumo da conversa e a
/// cifra corrente. É o `SymmetricState` da seção 5.2.
struct Simetrico {
    encadeamento: [u8; TAM_RESUMO],
    resumo: [u8; TAM_RESUMO],
    cifra: Cifra,
}

impl Simetrico {
    fn novo() -> Self {
        // Um nome maior que o resumo é resumido; um menor seria completado
        // com zeros. O deste canal tem 33 bytes, e cai no primeiro caso.
        let resumo = if NOME_DO_PROTOCOLO.len() <= TAM_RESUMO {
            let mut r = [0u8; TAM_RESUMO];
            r[..NOME_DO_PROTOCOLO.len()].copy_from_slice(NOME_DO_PROTOCOLO);
            r
        } else {
            resumir(&[NOME_DO_PROTOCOLO])
        };
        Self {
            encadeamento: resumo,
            resumo,
            cifra: Cifra::vazia(),
        }
    }

    fn misturar_chave(&mut self, material: &[u8]) {
        let (encadeamento, chave) = hkdf2(&self.encadeamento, material);
        self.encadeamento = encadeamento;
        self.cifra = Cifra::com_chave(chave);
    }

    fn misturar_resumo(&mut self, dados: &[u8]) {
        self.resumo = resumir(&[&self.resumo, dados]);
    }

    /// Cifra com o resumo como dado associado, e mistura o cifrado no
    /// resumo. É o que amarra cada mensagem a toda a conversa anterior.
    fn cifrar_e_resumir(&mut self, claro: &[u8], saida: &mut [u8]) -> Result<usize, Erro> {
        let ad = self.resumo;
        let n = self.cifra.cifrar(&ad, claro, saida)?;
        self.misturar_resumo(&saida[..n]);
        Ok(n)
    }

    fn decifrar_e_resumir(&mut self, cifrado: &[u8], saida: &mut [u8]) -> Result<usize, Erro> {
        let ad = self.resumo;
        let n = self.cifra.decifrar(&ad, cifrado, saida)?;
        self.misturar_resumo(cifrado);
        Ok(n)
    }

    /// As duas cifras do transporte: a primeira é a do iniciador para o
    /// respondedor, a segunda a do sentido contrário.
    fn dividir(mut self) -> (Cifra, Cifra, [u8; TAM_RESUMO]) {
        let (k1, k2) = hkdf2(&self.encadeamento, &[]);
        let resumo = self.resumo;
        self.encadeamento.zeroize();
        (Cifra::com_chave(k1), Cifra::com_chave(k2), resumo)
    }
}

impl Drop for Simetrico {
    fn drop(&mut self) {
        self.encadeamento.zeroize();
    }
}

/// O tamanho da chave estática cifrada na primeira mensagem.
const ESTATICA_CIFRADA: usize = TAM_CHAVE + TAM_ETIQUETA;

/// O menor tamanho possível da primeira mensagem: a efêmera, a estática
/// cifrada e a etiqueta de uma carga vazia.
pub const MENOR_PRIMEIRA: usize = TAM_CHAVE + ESTATICA_CIFRADA + TAM_ETIQUETA;

/// O menor tamanho possível da segunda: a efêmera e a etiqueta.
pub const MENOR_SEGUNDA: usize = TAM_CHAVE + TAM_ETIQUETA;

/// O agente, antes da primeira mensagem.
pub struct Iniciador {
    simetrico: Simetrico,
    estatica: [u8; TAM_CHAVE],
    remota: [u8; TAM_CHAVE],
}

/// O agente, depois de mandar a primeira mensagem e antes da resposta.
pub struct Aguardando {
    simetrico: Simetrico,
    estatica: [u8; TAM_CHAVE],
    efemera: [u8; TAM_CHAVE],
}

/// O Duke, antes da primeira mensagem.
pub struct Respondedor {
    simetrico: Simetrico,
    estatica: [u8; TAM_CHAVE],
}

/// O Duke, depois de ler a primeira mensagem: já sabe quem é o agente, e
/// ainda não respondeu. É aqui que ele confere o registro.
pub struct Recebido {
    simetrico: Simetrico,
    remota: [u8; TAM_CHAVE],
    efemera_remota: [u8; TAM_CHAVE],
}

impl Iniciador {
    /// `estatica` é a chave privada do agente; `remota`, a pública do Duke.
    pub fn novo(prologo: &[u8], estatica: &[u8; TAM_CHAVE], remota: &[u8; TAM_CHAVE]) -> Self {
        let mut simetrico = Simetrico::novo();
        simetrico.misturar_resumo(prologo);
        // A pré-mensagem `<- s`: a chave do Duke entra no resumo antes de
        // qualquer byte trafegar. Um agente que espera outro Duke deriva
        // outro resumo, e nada do que vier depois abre.
        simetrico.misturar_resumo(remota);
        Self {
            simetrico,
            estatica: *estatica,
            remota: *remota,
        }
    }

    /// Escreve `-> e, es, s, ss` com `carga`, e devolve o tamanho escrito.
    pub fn escrever(
        mut self,
        efemera: [u8; TAM_CHAVE],
        carga: &[u8],
        saida: &mut [u8],
    ) -> Result<(usize, Aguardando), Erro> {
        let total = MENOR_PRIMEIRA + carga.len();
        if total > MAIOR_MENSAGEM {
            return Err(Erro::Grande);
        }
        if saida.len() < total {
            return Err(Erro::Espaco);
        }

        let publica = publica_de(&efemera);
        saida[..TAM_CHAVE].copy_from_slice(&publica);
        self.simetrico.misturar_resumo(&publica);
        self.simetrico.misturar_chave(&dh(&efemera, &self.remota)?);
        let mut n = TAM_CHAVE;
        n += self
            .simetrico
            .cifrar_e_resumir(&publica_de(&self.estatica), &mut saida[n..])?;
        self.simetrico
            .misturar_chave(&dh(&self.estatica, &self.remota)?);
        n += self.simetrico.cifrar_e_resumir(carga, &mut saida[n..])?;

        Ok((
            n,
            Aguardando {
                simetrico: core::mem::replace(&mut self.simetrico, Simetrico::novo()),
                estatica: self.estatica,
                efemera,
            },
        ))
    }
}

impl Drop for Iniciador {
    fn drop(&mut self) {
        self.estatica.zeroize();
    }
}

impl Aguardando {
    /// Lê `<- e, ee, se`, põe a carga em `carga` e devolve o transporte.
    pub fn ler(mut self, mensagem: &[u8], carga: &mut [u8]) -> Result<(usize, Transporte), Erro> {
        if mensagem.len() < MENOR_SEGUNDA {
            return Err(Erro::Curta);
        }
        if mensagem.len() > MAIOR_MENSAGEM {
            return Err(Erro::Grande);
        }
        let efemera_remota: [u8; TAM_CHAVE] = mensagem[..TAM_CHAVE].try_into().unwrap();
        self.simetrico.misturar_resumo(&efemera_remota);
        self.simetrico
            .misturar_chave(&dh(&self.efemera, &efemera_remota)?);
        self.simetrico
            .misturar_chave(&dh(&self.estatica, &efemera_remota)?);
        let n = self
            .simetrico
            .decifrar_e_resumir(&mensagem[TAM_CHAVE..], carga)?;

        let simetrico = core::mem::replace(&mut self.simetrico, Simetrico::novo());
        let (para_o_duke, para_o_agente, resumo) = simetrico.dividir();
        Ok((
            n,
            Transporte {
                envio: para_o_duke,
                recepcao: para_o_agente,
                resumo,
            },
        ))
    }
}

impl Drop for Aguardando {
    fn drop(&mut self) {
        self.estatica.zeroize();
        self.efemera.zeroize();
    }
}

impl Respondedor {
    /// `estatica` é a chave privada do Duke.
    pub fn novo(prologo: &[u8], estatica: &[u8; TAM_CHAVE]) -> Self {
        let mut simetrico = Simetrico::novo();
        simetrico.misturar_resumo(prologo);
        simetrico.misturar_resumo(&publica_de(estatica));
        Self {
            simetrico,
            estatica: *estatica,
        }
    }

    /// Lê `-> e, es, s, ss` e põe a carga em `carga`.
    ///
    /// A etiqueta que abre a chave estática do agente só confere se ele
    /// cifrou para **esta** chave do Duke; a da carga só confere se ele tem a
    /// chave privada que diz ter. Passar daqui é estar autenticado — mas não
    /// autorizado: isso é o registro, que quem chama confere em
    /// [`Recebido::remota`] antes de responder.
    pub fn ler(mut self, mensagem: &[u8], carga: &mut [u8]) -> Result<(usize, Recebido), Erro> {
        if mensagem.len() < MENOR_PRIMEIRA {
            return Err(Erro::Curta);
        }
        if mensagem.len() > MAIOR_MENSAGEM {
            return Err(Erro::Grande);
        }
        let efemera_remota: [u8; TAM_CHAVE] = mensagem[..TAM_CHAVE].try_into().unwrap();
        self.simetrico.misturar_resumo(&efemera_remota);
        self.simetrico
            .misturar_chave(&dh(&self.estatica, &efemera_remota)?);

        let mut remota = [0u8; TAM_CHAVE];
        let fim = TAM_CHAVE + ESTATICA_CIFRADA;
        self.simetrico
            .decifrar_e_resumir(&mensagem[TAM_CHAVE..fim], &mut remota)?;
        self.simetrico.misturar_chave(&dh(&self.estatica, &remota)?);
        let n = self.simetrico.decifrar_e_resumir(&mensagem[fim..], carga)?;

        Ok((
            n,
            Recebido {
                simetrico: core::mem::replace(&mut self.simetrico, Simetrico::novo()),
                remota,
                efemera_remota,
            },
        ))
    }
}

impl Drop for Respondedor {
    fn drop(&mut self) {
        self.estatica.zeroize();
    }
}

impl Recebido {
    /// A chave pública estática do agente: quem ele provou ser.
    pub fn remota(&self) -> [u8; TAM_CHAVE] {
        self.remota
    }

    /// Escreve `<- e, ee, se` com `carga`, e devolve o transporte.
    pub fn escrever(
        mut self,
        efemera: [u8; TAM_CHAVE],
        carga: &[u8],
        saida: &mut [u8],
    ) -> Result<(usize, Transporte), Erro> {
        let total = MENOR_SEGUNDA + carga.len();
        if total > MAIOR_MENSAGEM {
            return Err(Erro::Grande);
        }
        if saida.len() < total {
            return Err(Erro::Espaco);
        }
        let mut efemera = efemera;
        let publica = publica_de(&efemera);
        saida[..TAM_CHAVE].copy_from_slice(&publica);
        self.simetrico.misturar_resumo(&publica);
        let resultado = (|| {
            self.simetrico
                .misturar_chave(&dh(&efemera, &self.efemera_remota)?);
            self.simetrico.misturar_chave(&dh(&efemera, &self.remota)?);
            self.simetrico
                .cifrar_e_resumir(carga, &mut saida[TAM_CHAVE..])
        })();
        efemera.zeroize();
        let n = TAM_CHAVE + resultado?;

        let simetrico = core::mem::replace(&mut self.simetrico, Simetrico::novo());
        let (do_agente, para_o_agente, resumo) = simetrico.dividir();
        Ok((
            n,
            Transporte {
                envio: para_o_agente,
                recepcao: do_agente,
                resumo,
            },
        ))
    }
}

/// O canal depois do aperto: uma cifra para cada sentido.
pub struct Transporte {
    envio: Cifra,
    recepcao: Cifra,
    resumo: [u8; TAM_RESUMO],
}

impl Transporte {
    /// O maior texto que cabe numa mensagem.
    pub const MAIOR_CLARO: usize = MAIOR_MENSAGEM - TAM_ETIQUETA;

    /// Cifra uma mensagem. Devolve o tamanho cifrado.
    pub fn cifrar(&mut self, claro: &[u8], saida: &mut [u8]) -> Result<usize, Erro> {
        if claro.len() > Self::MAIOR_CLARO {
            return Err(Erro::Grande);
        }
        self.envio.cifrar(&[], claro, saida)
    }

    /// Abre uma mensagem. Devolve o tamanho do texto.
    ///
    /// Um erro aqui — etiqueta errada, mensagem repetida, fora de ordem ou
    /// adulterada — é o fim da sessão: o contador não avançou, e a próxima
    /// mensagem legítima também não abriria.
    pub fn decifrar(&mut self, cifrado: &[u8], saida: &mut [u8]) -> Result<usize, Erro> {
        if cifrado.len() > MAIOR_MENSAGEM {
            return Err(Erro::Grande);
        }
        self.recepcao.decifrar(&[], cifrado, saida)
    }

    /// O resumo do aperto: igual nos dois lados, e único por sessão. É o que
    /// amarra a sessão a outras coisas — o vetor publicado confere por ele.
    pub fn resumo_do_aperto(&self) -> [u8; TAM_RESUMO] {
        self.resumo
    }

    /// Quantas mensagens já foram enviadas e recebidas.
    pub fn contadores(&self) -> (u64, u64) {
        (self.envio.contador(), self.recepcao.contador())
    }
}
