//! O canal do agente por TCP, do lado do hospedeiro: a porta que o emulador
//! encaminha à do canal no hóspede, e a ponte que leva a suíte — de dentro
//! do hóspede — até ela, pela rede do emulador.
//!
//! # A porta
//!
//! O kernel escuta o canal na porta [`PORTA_NO_HOSPEDE`] (ver
//! `kernel/src/rede/canal.rs`). O emulador a expõe em `127.0.0.1:<porta>` —
//! um `hostfwd` —, numa porta livre escolhida a cada máquina e gravada em
//! [`caminho_da_porta`], de onde `cargo xtask agent --tcp` e a fumaça a
//! leem. Só no endereço local: a porta não é oferecida à rede do hospedeiro.
//!
//! # A ponte
//!
//! A suíte roda dentro do kernel, e precisa chegar ao canal como um agente de
//! fora. O `guestfwd` de [`DESTINO_DA_PONTE`] roda, a cada conexão,
//! [`PONTE`], que a liga ao `hostfwd` — e de volta ao hóspede, pela porta do
//! canal. A conversa atravessa a pilha IP do kernel duas vezes, a rede do
//! emulador e o hospedeiro: nenhum atalho até o canal, e nenhum que a suíte
//! tenha e um agente de fora não tenha.

use std::path::PathBuf;

/// A porta do canal no hóspede: a mesma de `rede::canal::PORTA` — a
/// conferência das invariantes compara as duas.
pub(crate) const PORTA_NO_HOSPEDE: u16 = 7070;

/// Para onde a suíte conecta, de dentro do hóspede, para chegar à ponte.
pub(crate) const DESTINO_DA_PONTE: &str = "10.0.2.100:7070";

/// O script da ponte, relativo à raiz do projeto.
pub(crate) const PONTE: &str = "xtask/bancada/ponte.py";

/// Onde a porta do hospedeiro da máquina de `arch` fica gravada.
pub(crate) fn caminho_da_porta(arch: &str) -> PathBuf {
    super::raiz_do_projeto()
        .join("target")
        .join(format!("agente-tcp-{arch}.porta"))
}

/// A porta do hospedeiro em que o canal TCP da máquina de `arch` atende,
/// como a última máquina a gravou.
pub(crate) fn porta(arch: &str) -> Result<u16, String> {
    let caminho = caminho_da_porta(arch);
    let texto = std::fs::read_to_string(&caminho).map_err(|e| {
        format!(
            "não foi possível ler {}: {e}\n\
             dica: a porta é escolhida quando a máquina sobe — inicie \
             `cargo xtask run --arch {arch}` em outro terminal",
            caminho.display()
        )
    })?;
    texto
        .trim()
        .parse()
        .map_err(|_| format!("{} não tem uma porta", caminho.display()))
}

/// Escolhe a porta do hospedeiro para a máquina de `arch`, grava-a, e
/// devolve as opções da rede do emulador: o `hostfwd` do canal e o
/// `guestfwd` da ponte.
///
/// A porta é uma que o sistema dá livre a quem pede a zero, e que o
/// emulador pega logo em seguida: entre uma coisa e outra, outro processo
/// pode pegá-la, e o emulador não sobe — é o mesmo risco de qualquer
/// bancada que escolhe porta, e o erro dele diz qual foi.
pub(crate) fn preparar(arch: &str) -> Result<String, String> {
    let porta = std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| format!("nenhuma porta livre no hospedeiro para o canal TCP: {e}"))?;
    let caminho = caminho_da_porta(arch);
    if let Some(dir) = caminho.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("não foi possível criar {}: {e}", dir.display()))?;
    }
    std::fs::write(&caminho, format!("{porta}\n"))
        .map_err(|e| format!("não foi possível gravar {}: {e}", caminho.display()))?;
    let ponte = super::raiz_do_projeto().join(PONTE);
    let ponte = ponte.display().to_string();
    if ponte.contains([',', ' ']) {
        return Err(format!(
            "o caminho da ponte do canal TCP não cabe na opção do emulador: {ponte}"
        ));
    }
    Ok(format!(
        "hostfwd=tcp:127.0.0.1:{porta}-:{PORTA_NO_HOSPEDE},\
         guestfwd=tcp:{DESTINO_DA_PONTE}-cmd:python3 {ponte} {porta}"
    ))
}

/// Confere que a porta do canal aqui é a do kernel: um encaminhamento para
/// a porta errada deixaria a fumaça e a suíte falando com ninguém, e o erro
/// diria só que a conexão não foi aceita.
pub(crate) fn conferir_a_porta() -> Result<(), String> {
    let fonte = super::raiz_do_projeto().join("kernel/src/rede/canal.rs");
    let texto = std::fs::read_to_string(&fonte)
        .map_err(|e| format!("não foi possível ler {}: {e}", fonte.display()))?;
    let esperado = format!("pub const PORTA: u16 = {PORTA_NO_HOSPEDE};");
    if texto.lines().any(|l| l.trim() == esperado) {
        Ok(())
    } else {
        Err(format!(
            "a porta do canal TCP do xtask ({PORTA_NO_HOSPEDE}) não é a do kernel: \
             `{esperado}` não está em {}",
            fonte.display()
        ))
    }
}
