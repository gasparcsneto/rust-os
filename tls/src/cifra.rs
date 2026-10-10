//! A cifra dos registros do TLS 1.3 (RFC 8446, 5.2): AES-128-GCM,
//! AES-256-GCM e ChaCha20-Poly1305, do RustCrypto.
//!
//! O registro cifrado leva o conteúdo, o tipo verdadeiro num byte depois
//! dele e a etiqueta de 16 bytes; o cabeçalho do registro — tipo
//! `application_data`, versão `0x0303` e o tamanho cifrado — é o dado
//! associado. O nonce é o IV da chave com o número de sequência do registro
//! misturado no fim: nunca se repete numa chave, porque o `rustls` troca a
//! chave antes de a sequência dar a volta.
//!
//! A montagem do registro segue a do exemplo de provedor do `rustls`
//! (`provider-example/src/aead.rs`) — ver `THIRD_PARTY.md` —, genérica nas
//! três cifras e só do TLS 1.3.

use alloc::boxed::Box;
use core::marker::PhantomData;

use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{self, AeadInOut, KeyInit};
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, Tls13AeadAlgorithm,
    UnsupportedOperationError, make_tls13_aad,
};
use rustls::{ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion};

/// O tamanho da etiqueta das três cifras.
const ETIQUETA: usize = 16;

/// Uma cifra autenticada do TLS 1.3.
pub(crate) struct Aead<A> {
    tamanho_da_chave: usize,
    segredos: fn(AeadKey, Iv) -> ConnectionTrafficSecrets,
    _a: PhantomData<fn() -> A>,
}

pub(crate) static AES_128_GCM: Aead<Aes128Gcm> = Aead {
    tamanho_da_chave: 16,
    segredos: |key, iv| ConnectionTrafficSecrets::Aes128Gcm { key, iv },
    _a: PhantomData,
};

pub(crate) static AES_256_GCM: Aead<Aes256Gcm> = Aead {
    tamanho_da_chave: 32,
    segredos: |key, iv| ConnectionTrafficSecrets::Aes256Gcm { key, iv },
    _a: PhantomData,
};

pub(crate) static CHACHA20_POLY1305: Aead<ChaCha20Poly1305> = Aead {
    tamanho_da_chave: 32,
    segredos: |key, iv| ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
    _a: PhantomData,
};

impl<A> Tls13AeadAlgorithm for Aead<A>
where
    A: AeadInOut + KeyInit + Send + Sync + 'static,
{
    fn encrypter(&self, chave: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Registro::<A> {
            // O `rustls` entrega a chave com o tamanho de `key_len`: um
            // tamanho errado é defeito daqui, e não do par.
            aead: A::new_from_slice(chave.as_ref()).expect("a chave tem o tamanho da cifra"),
            iv,
        })
    }

    fn decrypter(&self, chave: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Registro::<A> {
            aead: A::new_from_slice(chave.as_ref()).expect("a chave tem o tamanho da cifra"),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        self.tamanho_da_chave
    }

    fn extract_keys(
        &self,
        chave: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok((self.segredos)(chave, iv))
    }
}

/// A cifra de um sentido da conexão, com a chave e o IV dele.
struct Registro<A> {
    aead: A,
    iv: Iv,
}

impl<A> MessageEncrypter for Registro<A>
where
    A: AeadInOut + Send + Sync,
{
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total = self.encrypted_payload_len(msg.payload.len());
        let mut carga = PrefixedPayload::with_capacity(total);
        carga.extend_from_chunks(&msg.payload);
        carga.extend_from_slice(&msg.typ.to_array());
        let nonce = Nonce::new(&self.iv, seq).0;
        let nonce = <&aead::Nonce<A>>::try_from(&nonce[..]).map_err(|_| Error::EncryptError)?;
        let etiqueta = self
            .aead
            .encrypt_inout_detached(nonce, &make_tls13_aad(total), carga.as_mut().into())
            .map_err(|_| Error::EncryptError)?;
        carga.extend_from_slice(&etiqueta);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            // Todo registro cifrado do TLS 1.3 diz 0x0303 no cabeçalho — ver
            // a RFC 8446, 5.1.
            ProtocolVersion::TLSv1_2,
            carga,
        ))
    }

    fn encrypted_payload_len(&self, tamanho: usize) -> usize {
        tamanho + 1 + ETIQUETA
    }
}

impl<A> MessageDecrypter for Registro<A>
where
    A: AeadInOut + Send + Sync,
{
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let carga = &mut msg.payload;
        let total = carga.len();
        let Some(corpo) = total.checked_sub(ETIQUETA) else {
            return Err(Error::DecryptError);
        };
        let nonce = Nonce::new(&self.iv, seq).0;
        let nonce = <&aead::Nonce<A>>::try_from(&nonce[..]).map_err(|_| Error::DecryptError)?;
        let (texto, etiqueta) = carga.split_at_mut(corpo);
        let etiqueta = <&aead::Tag<A>>::try_from(&*etiqueta).map_err(|_| Error::DecryptError)?;
        if self
            .aead
            .decrypt_inout_detached(nonce, &make_tls13_aad(total), texto.into(), etiqueta)
            .is_err()
        {
            return Err(Error::DecryptError);
        }
        carga.truncate(corpo);
        msg.into_tls13_unpadded_message()
    }
}
