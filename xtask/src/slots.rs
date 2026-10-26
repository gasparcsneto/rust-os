//! A atualização A/B do lado do hospedeiro: a imagem de um slot — o
//! manifesto assinado, o kernel e o pacote —, o slot A e o controle de boot
//! do disco de testes, e o que a bancada lê e escreve neles.
//!
//! Os formatos são do crate `atualizacao`, os mesmos que o iniciador e o
//! kernel leem: o que se monta aqui é conferido lá, byte a byte.
//!
//! # O disco de testes
//!
//! O kernel não vai mais para a ESP: vai para o slot A, com um manifesto
//! assinado pela chave de atualização da bancada, e o controle de boot
//! aponta para ele — ver [`instalar_no_slot_a`]. A ESP leva só o iniciador.
//! O slot B começa vazio; é onde a bancada da atualização escreve a versão
//! nova.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use atualizacao::cabecalho::{self, KERNEL_EM};
use atualizacao::controle::{self, Controle, Falha};
use atualizacao::disco::COPIA_EM;
use atualizacao::manifesto::{self, Manifesto, Parte};
use atualizacao::{Arquitetura as ArqDoSlot, Slot, pacote};

use super::{Arquitetura, disco};

/// O nome da chave de atualização da bancada, no registro da imagem.
pub(crate) const CHAVE_DA_BANCADA: &str = "bancada";

/// A versão e a geração da imagem que o disco de testes leva no slot A.
pub(crate) const VERSAO_DA_BANCADA: &str = "bancada";
pub(crate) const GERACAO_DA_BANCADA: u64 = 1;

/// O formato de estado que as imagens da bancada leem: o do kernel —
/// `FORMATO_DO_ESTADO` em `kernel/src/slots.rs`.
pub(crate) const FORMATO_DO_ESTADO: u32 = 1;

const fn arquitetura(arch: Arquitetura) -> ArqDoSlot {
    match arch {
        Arquitetura::X86_64 => ArqDoSlot::X86_64,
        Arquitetura::Aarch64 => ArqDoSlot::Aarch64,
    }
}

/// O que se pede de uma imagem.
pub(crate) struct Pedido<'a> {
    pub arch: Arquitetura,
    pub kernel: &'a [u8],
    pub pacote: &'a [u8],
    pub versao: &'a str,
    pub geracao: u64,
    /// O formato de estado mínimo e máximo que a imagem diz ler.
    pub estado: (u32, u32),
}

/// Uma imagem de slot montada: os bytes, o manifesto e o resumo dele.
pub(crate) struct Imagem {
    pub bytes: Vec<u8>,
    pub manifesto: Vec<u8>,
    pub resumo: [u8; 32],
}

/// O manifesto de um pedido, em texto canônico — conferido pelo leitor.
pub(crate) fn manifesto_de(p: &Pedido) -> Result<Vec<u8>, String> {
    let m = Manifesto {
        arquitetura: arquitetura(p.arch),
        versao: p.versao,
        geracao: p.geracao,
        estado_minimo: p.estado.0,
        estado_maximo: p.estado.1,
        kernel: Parte {
            tamanho: p.kernel.len() as u64,
            resumo: atualizacao::resumo(p.kernel),
        },
        pacote: Parte {
            tamanho: p.pacote.len() as u64,
            resumo: atualizacao::resumo(p.pacote),
        },
    };
    let texto = m.escrever();
    Manifesto::ler(&texto).map_err(|(linha, motivo)| {
        format!("o manifesto montado nao se le (linha {linha}): {motivo}")
    })?;
    Ok(texto)
}

/// A imagem de `manifesto` assinado por `privada`: o cabeçalho, o kernel e
/// o pacote, no lugar de cada um, e o tamanho arredondado ao setor.
pub(crate) fn imagem_com(
    manifesto: &[u8],
    privada: &[u8; 32],
    kernel: &[u8],
    pacote: &[u8],
) -> Result<Imagem, String> {
    let assinatura = manifesto::assinar(manifesto, privada);
    let publica = manifesto::publica_de(privada);
    let cab = cabecalho::montar(manifesto, &assinatura, &publica)
        .ok_or("o manifesto nao cabe no cabecalho do slot")?;
    let em = cabecalho::pacote_em(kernel.len() as u64) as usize;
    let mut bytes = vec![0u8; (em + pacote.len()).next_multiple_of(512)];
    bytes[..cab.len()].copy_from_slice(&cab);
    bytes[KERNEL_EM as usize..KERNEL_EM as usize + kernel.len()].copy_from_slice(kernel);
    bytes[em..em + pacote.len()].copy_from_slice(pacote);
    Ok(Imagem {
        bytes,
        manifesto: manifesto.to_vec(),
        resumo: manifesto::resumo_do_manifesto(manifesto),
    })
}

/// A imagem de um pedido, assinada por `privada`.
pub(crate) fn imagem(p: &Pedido, privada: &[u8; 32]) -> Result<Imagem, String> {
    let manifesto = manifesto_de(p)?;
    let i = imagem_com(&manifesto, privada, p.kernel, p.pacote)?;
    if i.bytes.len() as u64 > disco::SLOT_SETORES * 512 {
        return Err(format!(
            "a imagem tem {} bytes, e o slot, {}",
            i.bytes.len(),
            disco::SLOT_SETORES * 512
        ));
    }
    Ok(i)
}

/// Um pacote sem arquivo nenhum: a imagem da bancada, cuja raiz já tem
/// tudo.
pub(crate) fn pacote_vazio() -> Vec<u8> {
    pacote::vazio().to_vec()
}

fn abrir(disco: &Path) -> Result<std::fs::File, String> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(disco)
        .map_err(|e| format!("não foi possível abrir {}: {e}", disco.display()))
}

/// Escreve `bytes` a partir do byte `em` do disco, e descarrega.
pub(crate) fn escrever_em(disco: &Path, em: u64, bytes: &[u8]) -> Result<(), String> {
    let mut f = abrir(disco)?;
    f.seek(SeekFrom::Start(em))
        .and_then(|_| f.write_all(bytes))
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("não foi possível escrever em {}: {e}", disco.display()))
}

/// Lê `n` bytes a partir do byte `em` do disco.
pub(crate) fn ler_em(disco: &Path, em: u64, n: usize) -> Result<Vec<u8>, String> {
    let mut f = abrir(disco)?;
    let mut v = vec![0u8; n];
    f.seek(SeekFrom::Start(em))
        .and_then(|_| f.read_exact(&mut v))
        .map_err(|e| format!("não foi possível ler {}: {e}", disco.display()))?;
    Ok(v)
}

/// Escreve uma imagem no slot `s`.
pub(crate) fn escrever_no_slot(disco: &Path, s: Slot, imagem: &[u8]) -> Result<(), String> {
    if imagem.len() as u64 > disco::SLOT_SETORES * 512 {
        return Err("a imagem nao cabe no slot".into());
    }
    escrever_em(disco, disco::slot_em(s) * 512, imagem)
}

/// Apaga o cabeçalho do slot `s`: sem a magia, o slot não tem imagem.
pub(crate) fn esvaziar_o_slot(disco: &Path, s: Slot) -> Result<(), String> {
    escrever_em(
        disco,
        disco::slot_em(s) * 512,
        &[0u8; cabecalho::TAM_CABECALHO],
    )
}

/// As duas cópias do controle, como estão no disco.
pub(crate) fn copias(disco: &Path) -> Result<[Option<Controle>; 2], String> {
    let mut c = [None, None];
    for (i, em) in COPIA_EM.iter().enumerate() {
        let b = ler_em(disco, disco::CONTROLE_EM * 512 + em, 512)?;
        c[i] = controle::ler(&b);
    }
    Ok(c)
}

/// O controle que vale no disco, e a cópia dele.
pub(crate) fn controle_valido(disco: &Path) -> Result<Option<(usize, Controle)>, String> {
    Ok(controle::escolher(copias(disco)?))
}

/// Escreve `c` na cópia `i`, como está — a bancada forja controles assim.
pub(crate) fn escrever_copia(disco: &Path, i: usize, c: &Controle) -> Result<(), String> {
    escrever_em(
        disco,
        disco::CONTROLE_EM * 512 + COPIA_EM[i],
        &controle::escrever(c),
    )
}

/// Estraga a cópia `i`: um byte trocado no meio, que o resumo pega.
pub(crate) fn estragar_copia(disco: &Path, i: usize) -> Result<(), String> {
    let em = disco::CONTROLE_EM * 512 + COPIA_EM[i] + 100;
    let mut b = ler_em(disco, em, 1)?;
    b[0] ^= 0x5A;
    escrever_em(disco, em, &b)
}

/// O controle do disco recém-provisionado: o slot A, com `manifesto`, e
/// nada mais — a primeira cópia com a sequência 1, a segunda apagada.
pub(crate) fn controle_inicial(disco: &Path, manifesto: [u8; 32]) -> Result<(), String> {
    let c = Controle {
        sequencia: 1,
        bom: Slot::A,
        tentativa: None,
        restantes: 0,
        falha: Falha::Nenhuma,
        manifestos: [manifesto, [0; 32]],
        sintetizado: false,
    };
    escrever_copia(disco, 0, &c)?;
    escrever_em(disco, disco::CONTROLE_EM * 512 + COPIA_EM[1], &[0u8; 512])
}

/// Põe uma imagem pronta — `bytes`, com o manifesto de resumo `resumo` —
/// no slot A, esvazia o B e aponta o controle para o A: o disco de uma
/// máquina que nunca bootou.
pub(crate) fn escrever_imagem_no_slot_a(
    disco_img: &Path,
    bytes: &[u8],
    resumo: [u8; 32],
) -> Result<(), String> {
    escrever_no_slot(disco_img, Slot::A, bytes)?;
    esvaziar_o_slot(disco_img, Slot::B)?;
    controle_inicial(disco_img, resumo)
}

/// Onde fica a imagem do slot A da última instalação desta arquitetura
/// neste disco — a que [`restaurar_o_slot_a`] põe de volta. Ao lado do
/// disco, e por disco: o de testes e os das outras bancadas — a da hora, a
/// da rede principal — têm cada um a sua, e uma instalação num não muda o
/// que o outro restaura.
fn guardada(arch: Arquitetura, disco: &Path) -> PathBuf {
    disco.with_extension(format!("slot-a-{}", arch.nome()))
}

/// Põe `kernel` — o ELF sem depuração — no slot A do disco, num manifesto
/// assinado pela chave de atualização da bancada, com o pacote vazio; o
/// controle aponta para ele, e o slot B fica vazio. Devolve o resumo do
/// manifesto.
pub(crate) fn instalar_no_slot_a(
    arch: Arquitetura,
    disco_img: &Path,
    kernel: &Path,
) -> Result<[u8; 32], String> {
    let bytes = std::fs::read(kernel)
        .map_err(|e| format!("não foi possível ler {}: {e}", kernel.display()))?;
    let chaves = super::chaves::Chaves::garantir()?;
    let pacote = pacote_vazio();
    let i = imagem(
        &Pedido {
            arch,
            kernel: &bytes,
            pacote: &pacote,
            versao: VERSAO_DA_BANCADA,
            geracao: GERACAO_DA_BANCADA,
            estado: (FORMATO_DO_ESTADO, FORMATO_DO_ESTADO),
        },
        &chaves.atualizacao,
    )?;
    escrever_imagem_no_slot_a(disco_img, &i.bytes, i.resumo)?;
    std::fs::write(guardada(arch, disco_img), &i.bytes)
        .map_err(|e| format!("não foi possível guardar a imagem do slot A: {e}"))?;
    println!(
        "[xtask] {} -> slot A ({} KiB, geracao {}, manifesto {})",
        kernel.file_name().unwrap_or_default().display(),
        i.bytes.len() / 1024,
        GERACAO_DA_BANCADA,
        &sigilo::hex(&i.resumo)[..16]
    );
    Ok(i.resumo)
}

/// O disco de volta ao que [`instalar_no_slot_a`] deixou: a imagem do slot
/// A — reescrita só se o cabeçalho mudou —, o controle apontando para ela,
/// e o slot B vazio. A bancada da atualização escreve nos slots e no
/// controle; o cenário seguinte começa daqui, como do estado zerado.
pub(crate) fn restaurar_o_slot_a(arch: Arquitetura, disco_img: &Path) -> Result<(), String> {
    let Ok(imagem) = std::fs::read(guardada(arch, disco_img)) else {
        // Nenhuma instalação desta arquitetura ainda: nada a restaurar.
        return Ok(());
    };
    let cab = &imagem[..cabecalho::TAM_CABECALHO];
    let no_disco = ler_em(disco_img, disco::SLOT_A_EM * 512, cabecalho::TAM_CABECALHO)?;
    if no_disco != cab {
        escrever_no_slot(disco_img, Slot::A, &imagem)?;
    }
    let c = cabecalho::ler(cab).map_err(|m| format!("a imagem guardada do slot A: {m}"))?;
    esvaziar_o_slot(disco_img, Slot::B)?;
    controle_inicial(disco_img, manifesto::resumo_do_manifesto(c.manifesto))
}

/// Uma imagem de slot conferida no hospedeiro, como o kernel a confere: o
/// que o operador e a bancada precisam saber dela.
pub(crate) struct Conferida {
    pub resumo: [u8; 32],
    /// O nome, no registro, da chave que assinou.
    pub chave: String,
    pub versao: String,
    pub geracao: u64,
    pub kernel: u64,
    pub pacote: u64,
}

/// Confere `bytes` — uma imagem de slot inteira — como o kernel confere a
/// do slot antes de instalá-la: o cabeçalho, o manifesto, a assinatura com
/// uma chave de `registro` (o texto de `/etc/duke/atualizacao`), a
/// arquitetura, o formato do estado, o tamanho no slot, o kernel e o
/// pacote pelos resumos, e o índice do pacote.
pub(crate) fn conferir_imagem(
    bytes: &[u8],
    registro: &str,
    arch: Arquitetura,
) -> Result<Conferida, String> {
    let c = cabecalho::ler(bytes).map_err(|m| format!("o cabecalho do slot: {m}"))?;
    let m = Manifesto::ler(c.manifesto)
        .map_err(|(linha, motivo)| format!("o manifesto, linha {linha}: {motivo}"))?;
    let mut chave = None;
    for (n, linha) in registro.lines().enumerate() {
        match sigilo::registro::ler_linha_de_editor(linha) {
            Ok(Some((publica, nome))) if publica == c.chave => chave = Some(nome.to_string()),
            Ok(_) => {}
            Err(e) => {
                return Err(format!(
                    "o registro de atualizacao, linha {}: {}",
                    n + 1,
                    e.motivo()
                ));
            }
        }
    }
    let chave = chave.ok_or_else(|| {
        format!(
            "a chave que assinou ({}) nao esta no registro de atualizacao",
            sigilo::hex(&c.chave)
        )
    })?;
    if !manifesto::conferir(c.manifesto, &c.assinatura, &c.chave) {
        return Err("a assinatura do manifesto nao confere".into());
    }
    if m.arquitetura != arquitetura(arch) {
        return Err(format!(
            "a imagem e de {}, e a maquina, de {}",
            m.arquitetura.nome(),
            arch.nome()
        ));
    }
    if !m.le_o_estado(FORMATO_DO_ESTADO) {
        return Err(format!(
            "a imagem le os formatos de estado {} a {}, e a maquina grava o {FORMATO_DO_ESTADO}",
            m.estado_minimo, m.estado_maximo
        ));
    }
    let tamanho = cabecalho::tamanho_da_imagem(&m).ok_or("o manifesto diz tamanhos impossiveis")?;
    if tamanho > disco::SLOT_SETORES * 512 || tamanho > bytes.len() as u64 {
        return Err(format!(
            "a imagem do manifesto tem {tamanho} bytes: o arquivo tem {}, e o slot, {}",
            bytes.len(),
            disco::SLOT_SETORES * 512
        ));
    }
    let k = KERNEL_EM as usize;
    let kernel = &bytes[k..k + m.kernel.tamanho as usize];
    if atualizacao::resumo(kernel) != m.kernel.resumo {
        return Err("o kernel nao bate com o manifesto".into());
    }
    let em = cabecalho::pacote_em(m.kernel.tamanho) as usize;
    let p = &bytes[em..em + m.pacote.tamanho as usize];
    if atualizacao::resumo(p) != m.pacote.resumo {
        return Err("o pacote nao bate com o manifesto".into());
    }
    let indice = pacote::cabecalho(p)
        .map_err(|e| format!("o pacote: {e}"))?
        .indice as usize;
    pacote::conferir(
        p.get(..indice)
            .ok_or("o indice do pacote passa do fim dele")?,
        m.pacote.tamanho,
    )
    .map_err(|e| format!("o pacote: {e}"))?;
    Ok(Conferida {
        resumo: manifesto::resumo_do_manifesto(c.manifesto),
        chave,
        versao: m.versao.to_string(),
        geracao: m.geracao,
        kernel: m.kernel.tamanho,
        pacote: m.pacote.tamanho,
    })
}

/// O kernel de uma imagem de slot — os bytes que o manifesto resume.
pub(crate) fn kernel_da_imagem(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let c = cabecalho::ler(bytes).map_err(|m| format!("o cabecalho do slot: {m}"))?;
    let m = Manifesto::ler(c.manifesto)
        .map_err(|(linha, motivo)| format!("o manifesto, linha {linha}: {motivo}"))?;
    let k = KERNEL_EM as usize;
    bytes
        .get(k..k + m.kernel.tamanho as usize)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| "o kernel passa do fim da imagem".to_string())
}

/// A imagem inteira do slot `s` do disco, até o fim do que o manifesto
/// dela diz.
pub(crate) fn imagem_do_slot(disco_img: &Path, s: Slot) -> Result<Vec<u8>, String> {
    let em = disco::slot_em(s) * 512;
    let cab = ler_em(disco_img, em, cabecalho::TAM_CABECALHO)?;
    let c = cabecalho::ler(&cab).map_err(|m| format!("o slot {}: {m}", s.nome()))?;
    let m = Manifesto::ler(c.manifesto)
        .map_err(|(linha, motivo)| format!("o manifesto, linha {linha}: {motivo}"))?;
    let tamanho = cabecalho::tamanho_da_imagem(&m).ok_or("o manifesto diz tamanhos impossiveis")?;
    ler_em(disco_img, em, tamanho as usize)
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn a_imagem_da_bancada_e_a_que_o_crate_le() {
        let kernel = b"\x7fELF um kernel de mentira".repeat(100);
        let pacote = pacote::montar(&[("programas/x86_64/livro", b"livro")]).unwrap();
        let privada = [11u8; 32];
        let p = Pedido {
            arch: Arquitetura::X86_64,
            kernel: &kernel,
            pacote: &pacote,
            versao: "b1.2",
            geracao: 2,
            estado: (1, 1),
        };
        let i = imagem(&p, &privada).unwrap();
        let c = cabecalho::ler(&i.bytes).unwrap();
        assert_eq!(c.manifesto, &i.manifesto[..]);
        assert!(manifesto::conferir(c.manifesto, &c.assinatura, &c.chave));
        let m = Manifesto::ler(c.manifesto).unwrap();
        assert_eq!((m.geracao, m.versao), (2, "b1.2"));
        let k = KERNEL_EM as usize;
        assert_eq!(&i.bytes[k..k + kernel.len()], &kernel[..]);
        let em = cabecalho::pacote_em(kernel.len() as u64) as usize;
        assert_eq!(&i.bytes[em..em + pacote.len()], &pacote[..]);
        assert_eq!(
            atualizacao::resumo(&i.bytes[k..k + kernel.len()]),
            m.kernel.resumo
        );
        assert_eq!(i.bytes.len() % 512, 0);
        assert_eq!(cabecalho::tamanho_da_imagem(&m), Some(i.bytes.len() as u64));
    }
}
