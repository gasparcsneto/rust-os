//! O estado de uma cifra: uma chave e um contador.
//!
//! É o `CipherState` da seção 5.1 da especificação do Noise. Cada mensagem é
//! cifrada com ChaCha20-Poly1305 sob a chave, com o contador como nonce, e o
//! contador sobe uma vez por mensagem.
//!
//! # Por que o contador é o que impede a repetição
//!
//! Os dois lados contam as mensagens, e cada uma só abre com o nonce do seu
//! lugar na sequência. Uma mensagem repetida por quem está no meio chega com
//! o nonce de uma posição que já passou: a etiqueta não confere, e ela é
//! recusada como se fosse lixo. Não há tabela de mensagens vistas — a ordem é
//! a defesa, e por isso o transporte por baixo precisa entregar em ordem e
//! sem perda, como o `virtio-console` e o TCP entregam.

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use zeroize::Zeroize;

use crate::Erro;

/// O tamanho da etiqueta de autenticação que cada mensagem cifrada carrega.
pub const TAM_ETIQUETA: usize = 16;

/// Uma chave e o número da próxima mensagem.
pub struct Cifra {
    chave: Option<[u8; 32]>,
    contador: u64,
}

impl Cifra {
    /// Uma cifra ainda sem chave: cifrar devolve o texto como veio.
    pub const fn vazia() -> Self {
        Self {
            chave: None,
            contador: 0,
        }
    }

    /// Uma cifra com chave, a partir da primeira mensagem.
    pub fn com_chave(chave: [u8; 32]) -> Self {
        Self {
            chave: Some(chave),
            contador: 0,
        }
    }

    /// Se já há chave. Antes dela, o Noise manda os dados em claro.
    pub fn tem_chave(&self) -> bool {
        self.chave.is_some()
    }

    /// O nonce do ChaCha20-Poly1305 para a mensagem de número `n`: quatro
    /// bytes zerados e o contador em little-endian, como na seção 12.3.
    fn nonce(n: u64) -> chacha20poly1305::Nonce {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&n.to_le_bytes());
        nonce.into()
    }

    /// Cifra `claro` em `saida`, com `ad` autenticado junto. Devolve quantos
    /// bytes escreveu: o texto e a etiqueta.
    pub fn cifrar(&mut self, ad: &[u8], claro: &[u8], saida: &mut [u8]) -> Result<usize, Erro> {
        let Some(chave) = &self.chave else {
            let destino = saida.get_mut(..claro.len()).ok_or(Erro::Espaco)?;
            destino.copy_from_slice(claro);
            return Ok(claro.len());
        };
        // O último valor é reservado pela especificação: ele nunca é usado
        // como nonce, e chegar a ele quer dizer que a sessão tem de acabar.
        if self.contador == u64::MAX {
            return Err(Erro::Contador);
        }
        let total = claro.len() + TAM_ETIQUETA;
        let destino = saida.get_mut(..total).ok_or(Erro::Espaco)?;
        let (corpo, etiqueta) = destino.split_at_mut(claro.len());
        corpo.copy_from_slice(claro);

        let aead = ChaCha20Poly1305::new(&(*chave).into());
        let feita = aead
            .encrypt_inout_detached(&Self::nonce(self.contador), ad, corpo.into())
            .map_err(|_| Erro::Espaco)?;
        etiqueta.copy_from_slice(&feita);
        self.contador += 1;
        Ok(total)
    }

    /// Abre `cifrado` em `saida`. Devolve o tamanho do texto.
    ///
    /// Uma etiqueta que não confere não avança o contador, como a
    /// especificação pede — mas quem usa este canal encerra a sessão nesse
    /// caso, e não tenta a próxima.
    pub fn decifrar(&mut self, ad: &[u8], cifrado: &[u8], saida: &mut [u8]) -> Result<usize, Erro> {
        let Some(chave) = &self.chave else {
            let destino = saida.get_mut(..cifrado.len()).ok_or(Erro::Espaco)?;
            destino.copy_from_slice(cifrado);
            return Ok(cifrado.len());
        };
        if self.contador == u64::MAX {
            return Err(Erro::Contador);
        }
        let tamanho = cifrado.len().checked_sub(TAM_ETIQUETA).ok_or(Erro::Curta)?;
        let (corpo, etiqueta) = cifrado.split_at(tamanho);
        let destino = saida.get_mut(..tamanho).ok_or(Erro::Espaco)?;
        destino.copy_from_slice(corpo);

        let aead = ChaCha20Poly1305::new(&(*chave).into());
        let etiqueta: [u8; TAM_ETIQUETA] = etiqueta.try_into().map_err(|_| Erro::Curta)?;
        if aead
            .decrypt_inout_detached(
                &Self::nonce(self.contador),
                ad,
                (&mut *destino).into(),
                &etiqueta.into(),
            )
            .is_err()
        {
            // O que foi copiado não pode sair daqui como se fosse texto.
            destino.zeroize();
            return Err(Erro::Autenticacao);
        }
        self.contador += 1;
        Ok(tamanho)
    }

    /// O número da próxima mensagem. Para os testes e o relatório.
    pub fn contador(&self) -> u64 {
        self.contador
    }
}

impl Drop for Cifra {
    fn drop(&mut self) {
        if let Some(chave) = &mut self.chave {
            chave.zeroize();
        }
    }
}
