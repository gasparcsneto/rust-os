//! Texto que sai da memória zerado: o corpo de uma mensagem e o que o
//! carrega até o fio.
//!
//! # Por que um módulo para isto
//!
//! Porque zerar só a tabela não basta. O corpo de uma mensagem passa por
//! três lugares depois dela: a cópia que a leitura devolve, o texto JSON da
//! resposta, e cada bloco que esse texto deixou para trás ao crescer — um
//! `String` que cresce copia o conteúdo para um bloco maior e devolve o
//! antigo ao alocador **com o texto dentro**. O próximo dono do bloco o
//! lê.
//!
//! Aqui moram os três: [`zerar`], que apaga sem o compilador poder tirar a
//! escrita; [`Corpo`], o texto de uma mensagem, que se apaga ao sair; e
//! [`Texto`], um texto que cresce apagando cada bloco que larga.

use alloc::vec::Vec;
use core::fmt;

/// Zera `bytes`, de um jeito que o compilador não pode apagar.
///
/// Uma escrita comum numa memória que vai ser liberada é uma escrita
/// morta, e o otimizador a remove. A volátil não.
pub fn zerar(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` é um `&mut u8` válido deste slice; a escrita volátil
        // só impede o compilador de remover o zeramento.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

/// Zera o bloco inteiro de `v` — a capacidade, e não só o comprimento.
///
/// O que está além do comprimento também pode ser texto: o que um
/// `truncate` ou um `clear` deixou para trás. E o bloco volta ao alocador
/// inteiro, com o que houver nele. Foi o vigia dos testes que mostrou: com
/// só o comprimento zerado, um bloco reaproveitado voltava com o rabo
/// sujo.
pub fn zerar_bloco(v: &mut Vec<u8>) {
    let capacidade = v.capacity();
    let p = v.as_mut_ptr();
    for i in 0..capacidade {
        // SAFETY: `p..p+capacidade` é o bloco que o `Vec` alocou; escrever
        // um `u8` em qualquer posição dele é válido, inclusive além do
        // comprimento, que é memória alocada e ainda não lida. A escrita
        // volátil impede o compilador de removê-la.
        unsafe { core::ptr::write_volatile(p.add(i), 0) };
    }
}

/// O texto de uma mensagem fora da tabela — a cópia que a leitura
/// devolve. Se apaga ao sair, como a guardada.
#[derive(Clone, PartialEq, Eq)]
pub struct Corpo(Vec<u8>);

impl Corpo {
    pub fn como_texto(&self) -> &str {
        // Só entra texto: `From<&str>` é o único jeito de fazer um.
        core::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl From<&str> for Corpo {
    fn from(texto: &str) -> Corpo {
        Corpo(Vec::from(texto.as_bytes()))
    }
}

impl core::ops::Deref for Corpo {
    type Target = str;
    fn deref(&self) -> &str {
        self.como_texto()
    }
}

/// O tamanho, e não o conteúdo: um corpo não vai para log por engano.
impl fmt::Debug for Corpo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Corpo({} bytes)", self.0.len())
    }
}

impl Drop for Corpo {
    fn drop(&mut self) {
        zerar_bloco(&mut self.0);
    }
}

/// Um texto que cresce, e que apaga cada bloco que larga — ao crescer e ao
/// sair. É onde a resposta de um pedido é montada antes de ser cifrada.
#[derive(Default)]
pub struct Texto {
    bytes: Vec<u8>,
}

impl Texto {
    pub const fn novo() -> Texto {
        Texto { bytes: Vec::new() }
    }

    pub fn como_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Acrescenta `mais`, crescendo à mão se não cabe: o bloco novo recebe
    /// a cópia, e o antigo é zerado antes de voltar ao alocador.
    pub fn acrescentar(&mut self, mais: &[u8]) {
        let preciso = self.bytes.len() + mais.len();
        if preciso > self.bytes.capacity() {
            let antigo = self.crescer(preciso);
            drop(antigo);
        }
        self.bytes.extend_from_slice(mais);
    }

    /// Troca o bloco por um com pelo menos `preciso` bytes, copia o texto e
    /// devolve o antigo, já zerado — separado de `acrescentar` para os
    /// testes conferirem o que sai.
    fn crescer(&mut self, preciso: usize) -> Vec<u8> {
        let capacidade = preciso.max(self.bytes.capacity().saturating_mul(2)).max(64);
        let mut novo = Vec::with_capacity(capacidade);
        novo.extend_from_slice(&self.bytes);
        let mut antigo = core::mem::replace(&mut self.bytes, novo);
        // O bloco inteiro, e não só o usado: ver `zerar_bloco`.
        zerar_bloco(&mut antigo);
        antigo
    }
}

impl fmt::Write for Texto {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.acrescentar(s.as_bytes());
        Ok(())
    }
}

impl Drop for Texto {
    fn drop(&mut self) {
        zerar_bloco(&mut self.bytes);
    }
}

#[cfg(test)]
pub(crate) mod testes {
    extern crate std;

    use super::*;
    use core::fmt::Write;
    use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::alloc::{GlobalAlloc, Layout, System};

    /// Um alocador que, para um bloco vigiado, diz se ele voltou zerado:
    /// 1 zerado, 2 com algo dentro. É o único jeito de ver o que sobra num
    /// bloco depois de ele sair — ler um ponteiro solto seria indefinido.
    struct Vigia;

    static VIGIADO: AtomicUsize = AtomicUsize::new(0);
    static VEREDITO: AtomicU8 = AtomicU8::new(0);
    /// Um caso de cada vez com o vigia: ele vigia um bloco só. Os casos de
    /// outros módulos que o usam tomam a mesma tranca.
    pub(crate) static UM_DE_CADA_VEZ: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // SAFETY: repassa tudo ao alocador do sistema; só lê o bloco vigiado
    // antes de devolvê-lo, enquanto ele ainda é válido.
    unsafe impl GlobalAlloc for Vigia {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            // SAFETY: o contrato de `alloc` é o mesmo, e é repassado.
            unsafe { System.alloc(l) }
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            if !p.is_null() && p as usize == VIGIADO.load(Ordering::SeqCst) {
                // SAFETY: o bloco ainda é válido: só é devolvido abaixo.
                let zerado = (0..l.size()).all(|i| unsafe { *p.add(i) } == 0);
                VEREDITO.store(if zerado { 1 } else { 2 }, Ordering::SeqCst);
                VIGIADO.store(0, Ordering::SeqCst);
            }
            // SAFETY: `p` veio de `System.alloc` com este `l`, por `alloc`
            // acima; é devolvido uma vez.
            unsafe { System.dealloc(p, l) }
        }
    }

    #[global_allocator]
    static ALOCADOR: Vigia = Vigia;

    /// Vigia o bloco em `p`, roda `f`, e diz como ele voltou.
    pub(crate) fn ao_sair(p: *const u8, f: impl FnOnce()) -> u8 {
        VEREDITO.store(0, Ordering::SeqCst);
        VIGIADO.store(p as usize, Ordering::SeqCst);
        f();
        VIGIADO.store(0, Ordering::SeqCst);
        VEREDITO.load(Ordering::SeqCst)
    }

    #[test]
    fn o_corpo_sai_zerado() {
        let _vez = UM_DE_CADA_VEZ.lock().unwrap_or_else(|e| e.into_inner());
        let corpo = Corpo::from("segredo do corpo");
        assert_eq!(&*corpo, "segredo do corpo");
        assert!(!alloc::format!("{corpo:?}").contains("segredo"));
        let p = corpo.0.as_ptr();
        assert_eq!(ao_sair(p, move || drop(corpo)), 1);
    }

    #[test]
    fn o_texto_zera_o_bloco_que_larga_ao_crescer() {
        let _vez = UM_DE_CADA_VEZ.lock().unwrap_or_else(|e| e.into_inner());
        let mut t = Texto::novo();
        t.write_str("{\"body\":\"segredo\"").unwrap();
        let primeiro = t.como_bytes().as_ptr();
        let capacidade = t.bytes.capacity();
        // Um pedaço maior que o que cabe: o texto cresce, e o bloco antigo
        // tem de voltar zerado.
        let grande = "x".repeat(capacidade + 1);
        assert_eq!(ao_sair(primeiro, || t.write_str(&grande).unwrap()), 1);
        assert!(t.como_bytes().starts_with(b"{\"body\":\"segredo\""));
        assert_eq!(t.len(), 17 + capacidade + 1);
        let atual = t.como_bytes().as_ptr();
        assert_eq!(ao_sair(atual, move || drop(t)), 1);
    }

    #[test]
    fn crescer_devolve_o_antigo_zerado() {
        let mut t = Texto::novo();
        t.acrescentar(b"abc");
        let antigo = t.crescer(1024);
        assert!(antigo.iter().all(|&b| b == 0));
        // O bloco inteiro, também além do comprimento.
        // SAFETY: lê dentro da capacidade do `Vec`, que `zerar_bloco`
        // escreveu inteira.
        let inteiro = unsafe { core::slice::from_raw_parts(antigo.as_ptr(), antigo.capacity()) };
        assert!(inteiro.iter().all(|&b| b == 0));
        assert_eq!(t.como_bytes(), b"abc");
        assert!(t.bytes.capacity() >= 1024);
    }

    /// O controle do vigia: um `Vec` comum volta ao alocador com o texto —
    /// sem isto, um vigia quebrado aprovaria tudo.
    #[test]
    fn um_vec_comum_sai_com_o_texto() {
        let _vez = UM_DE_CADA_VEZ.lock().unwrap_or_else(|e| e.into_inner());
        let v = Vec::from(&b"segredo"[..]);
        let p = v.as_ptr();
        assert_eq!(ao_sair(p, move || drop(v)), 2);
    }
}
