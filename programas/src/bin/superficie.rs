//! Desenha numa superfície do compositor, e confere as recusas do kernel.
//!
//! É o outro lado do caso da suíte que confere as superfícies de processo.
//! O programa cria uma, pinta, mostra e bifurca; a suíte olha a tela. Depois
//! de um evento no canal `teste-superficie`, ele fecha a primeira, abre uma
//! segunda e sai **sem** fechá-la — a suíte confere que o coletor a tira da
//! tela.
//!
//! Sai com [`CODIGO`] quando tudo confere, e com um código menor que diz o
//! quê, quando não.

#![no_std]
#![no_main]

use programas::escreverln;
use programas::monte::FIM_DO_MONTE;
use programas::sistema::{self, erro};
use programas::superficie::Superficie;
use protocolo::usuario::evento::Evento;
use protocolo::usuario::superficie::{self as abi, operacao};
use protocolo::usuario::{MAPEAVEL, PAGINA};

/// O código de saída quando tudo conferiu. A suíte do kernel o procura.
const CODIGO: i64 = 66;

/// O canal por onde a suíte diz que já olhou a tela.
const CANAL: &str = "teste-superficie";

// A geometria e as cores que a suíte confere — ver o caso dela.
const X: i32 = 200;
const Y: i32 = 200;
const LARGURA: u32 = 64;
const ALTURA: u32 = 32;
// Com o byte alto cheio: a janela se mistura por alfa, e um pixel de alfa
// zero não apareceria.
const ANTES: u32 = 0xFF20_C040;
const DEPOIS: u32 = 0xFFD0_3030;
const SEGUNDA: u32 = 0x0030_60D0;

/// O programa que o filho zumbi executa antes de morrer.
#[cfg(target_arch = "x86_64")]
const HERDEIRA: &str = "/programas/x86_64/herdeira";
#[cfg(target_arch = "aarch64")]
const HERDEIRA: &str = "/programas/aarch64/herdeira";

/// O canal que o pai segura enquanto o filho não pode seguir.
const TRAVA: &str = "teste-superficie-trava";

/// O filho do `fork`: herda os descritores, e nem a camada nem a memória.
/// Zero quando tudo confere.
fn filho(fd_janela: u64, fd_temporaria: u64, endereco: u64) -> i64 {
    // `controlar` pelo descritor herdado é recusado, e a faixa da janela
    // está livre no espaço dele — mapear ali dá certo.
    if sistema::controlar(fd_janela, operacao::MOVER, 0) != erro::DESCRITOR_INVALIDO {
        return 1;
    }
    if sistema::mapear(endereco, PAGINA) != 0 {
        return 2;
    }
    // Fechar o descritor herdado não fecha a camada do pai — a suíte a vê
    // na tela depois.
    sistema::fechar(fd_janela);

    // Espera o pai fechar a temporária.
    loop {
        match sistema::escutar(TRAVA) {
            r if r >= 0 => break,
            erro::OCUPADO => sistema::ceder(),
            _ => return 3,
        }
    }
    // Uma superfície do filho, que cai na vaga que a temporária deixou. O
    // descritor herdado da temporária aponta para essa vaga, e é **dele**
    // agora — mas não é para esta superfície que ele apontava: continua
    // recusado. Sem a geração na chave, ele controlaria a janela nova, e
    // fechá-lo a fecharia.
    let minha = match Superficie::nova(8, 8) {
        Ok(s) => s,
        Err(_) => return 4,
    };
    if sistema::controlar(fd_temporaria, operacao::MOVER, 0) != erro::DESCRITOR_INVALIDO {
        return 5;
    }
    sistema::fechar(fd_temporaria);
    if minha.mover(1, 1).is_err() {
        return 6;
    }
    0
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    // As recusas que não dependem de haver uma superfície.
    if sistema::superficie(0, 10, MAPEAVEL.1 - 16 * PAGINA) != erro::TAMANHO_INVALIDO {
        return 1;
    }
    if sistema::superficie(abi::MAIOR_LADO + 1, 1, MAPEAVEL.1 - 16 * PAGINA)
        != erro::TAMANHO_INVALIDO
    {
        return 2;
    }
    // Dois lados dentro do limite, e o produto acima do teto de bytes.
    if sistema::superficie(abi::MAIOR_LADO, abi::MAIOR_LADO, MAPEAVEL.0) != erro::TAMANHO_INVALIDO {
        return 3;
    }
    if sistema::superficie(8, 8, MAPEAVEL.1 - 16 * PAGINA + 8) != erro::ENDERECO_INVALIDO {
        return 4;
    }
    // Abaixo da faixa mapeável: o código do próprio programa mora ali.
    if sistema::superficie(8, 8, MAPEAVEL.0 - PAGINA) != erro::ENDERECO_INVALIDO {
        return 5;
    }

    let mut janela = match Superficie::nova(LARGURA, ALTURA) {
        Ok(s) => s,
        Err(e) => {
            escreverln!("superficie devolveu {}", e);
            return 6;
        }
    };
    // Por cima dela mesma: a faixa já está em uso.
    if sistema::superficie(8, 8, janela.endereco()) != erro::JA_MAPEADO {
        return 7;
    }

    // As recusas de `controlar`.
    let fd = janela.descritor();
    if sistema::controlar(fd, 99, 0) != erro::ARGUMENTO_INVALIDO {
        return 8;
    }
    if sistema::controlar(fd, operacao::OPACIDADE, 256) != erro::ARGUMENTO_INVALIDO {
        return 9;
    }
    if sistema::controlar(fd, operacao::MISTURA, 7) != erro::ARGUMENTO_INVALIDO {
        return 10;
    }
    // Um dano que passa da borda da superfície, por dois pixels.
    if sistema::controlar(fd, operacao::DANO, abi::retangulo(60, 0, 6, 1))
        != erro::ARGUMENTO_INVALIDO
    {
        return 11;
    }
    // O foco: pedido e devolvido — a suíte confere que ele não ficou com
    // este processo —, e um argumento que não é nem um nem outro.
    if sistema::controlar(fd, operacao::FOCO, 1) != 0
        || sistema::controlar(fd, operacao::FOCO, 0) != 0
    {
        return 27;
    }
    if sistema::controlar(fd, operacao::FOCO, 2) != erro::ARGUMENTO_INVALIDO {
        return 28;
    }
    // A saída padrão não é uma superfície.
    if sistema::controlar(sistema::SAIDA, operacao::MOVER, 0) != erro::DESCRITOR_INVALIDO {
        return 12;
    }

    // Uma que nunca se mostra: a suíte confere que ela nasceu invisível, e
    // que a janela, trazida para a frente, ficou acima dela.
    let oculta = match Superficie::nova(8, 8) {
        Ok(s) => s,
        Err(_) => return 24,
    };

    janela.pixels().fill(ANTES);
    if janela.mover(X, Y).is_err()
        || janela.transparente(true).is_err()
        || janela.trazer_para_frente().is_err()
        || janela.mostrar().is_err()
        || janela.danificar_tudo().is_err()
    {
        return 13;
    }

    // Uma segunda superfície, só para o filho herdar o descritor dela — e
    // um canal que o pai segura como trava: o filho só segue quando
    // conseguir escutá-lo, isto é, quando o pai o tiver largado.
    let temporaria = match Superficie::nova(8, 8) {
        Ok(s) => s,
        Err(_) => return 22,
    };
    let trava = sistema::escutar(TRAVA);
    if trava < 0 {
        return 23;
    }

    let (fd_janela, fd_temporaria) = (fd, temporaria.descritor());
    match sistema::bifurcar() {
        0 => sistema::sair(filho(fd_janela, fd_temporaria, janela.endereco())),
        filho if filho < 0 => return 14,
        _ => {}
    }
    // Fecha a temporária e só então solta a trava: quando o filho seguir, a
    // vaga dela no kernel já está livre.
    drop(temporaria);
    sistema::fechar(trava as u64);
    match sistema::esperar(0) {
        Ok((_, Some(0))) => {}
        outro => {
            escreverln!("o filho deu {:?}", outro);
            return 15;
        }
    }

    // Depois do `fork`, o pai ainda desenha na memória que o compositor lê:
    // a suíte procura esta cor, e não a de antes.
    janela.pixels().fill(DEPOIS);
    if janela.danificar_tudo().is_err() {
        return 16;
    }

    // Um filho que cria uma superfície e sai sem fechá-la — e que o pai só
    // colhe depois do evento da suíte. Enquanto isso ele é um zumbi: morto
    // para o coletor, que tira a camada dele da tela, e com o espaço de
    // endereços ainda de pé, porque o pai pode perguntar por ele. É a ordem
    // em que a memória da camada solta os frames **antes** do espaço — e a
    // suíte espera o coletor passar antes de publicar.
    //
    // Antes de morrer, ele troca de imagem: a superfície que ele cria aqui
    // fica aberta para o `herdeira`, que põe a própria no mesmo endereço e
    // fecha o que herdou — ver o programa.
    match sistema::bifurcar() {
        0 => {
            // Livre no espaço do filho: a janela do pai não veio com o `fork`.
            if sistema::superficie(8, 8, FIM_DO_MONTE) < 0 {
                sistema::sair(1);
            }
            sistema::executar(HERDEIRA);
            sistema::sair(2);
        }
        filho if filho < 0 => return 25,
        _ => {}
    }

    let canal = sistema::escutar(CANAL);
    if canal < 0 {
        return 17;
    }
    escreverln!("superficie: pronta");
    let mut evento = [Evento::default(); 1];
    if sistema::ler_eventos(canal as u64, &mut evento) != Ok(1) {
        return 18;
    }
    // O zumbi, agora sim.
    match sistema::esperar(0) {
        Ok((_, Some(0))) => {}
        outro => {
            escreverln!("o zumbi deu {:?}", outro);
            return 26;
        }
    }

    // A segunda, que o programa não fecha: é o coletor quem a tira da tela.
    // Criada antes de a primeira fechar, para cair em outra faixa — a da
    // primeira vai ser mapeada à mão logo abaixo.
    let mut segunda = match Superficie::nova(16, 16) {
        Ok(s) => s,
        Err(_) => return 19,
    };
    segunda.pixels().fill(SEGUNDA);
    if segunda.mover(X + 100, Y).is_err()
        || segunda.mostrar().is_err()
        || segunda.danificar_tudo().is_err()
    {
        return 20;
    }

    // Fechar tira a memória do processo: a faixa volta a ser mapeável.
    let (endereco, bytes) = (janela.endereco(), (LARGURA * ALTURA * 4) as u64);
    drop(janela);
    drop(oculta);
    if sistema::mapear(endereco, bytes.div_ceil(PAGINA) * PAGINA) != 0 {
        return 21;
    }

    core::mem::forget(segunda);
    escreverln!("superficie: segunda");
    CODIGO
}
