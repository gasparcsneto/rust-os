//! Os casos `zumbis:` — a cota de processos do titular, pela decisão 14.1
//! com a alternativa 1 da decisão sobre o achado A1 (8 de novembro de
//! 2026): a cota conta toda vaga que um processo do titular ocupa na tabela
//! de fios — os vivos, os que estão nascendo, os zumbis (o filho que saiu e
//! que o pai, vivo, ainda não colheu) e os mortos que não são zumbis (o
//! filho colhido, o órfão, o do `user.run`) —, até o coletor recolher o
//! morto. A cota limita o que o titular ocupa da tabela.
//!
//! Com a conta de antes da 14.1, só dos vivos, os sete primeiros casos
//! reprovam: um titular de cota 2 enchia a tabela inteira com zumbis, e daí
//! em diante não nascia fio nenhum, de ninguém. Com a da 14.1 antes da
//! alternativa 1 — os vivos, os que nascem e os zumbis —, três dos que
//! seguram o coletor reprovam (a MC1 do README): `zumbis: o morto conta na
//! cota ate o recolhimento`, `zumbis: o laco que bifurca e colhe nao passa
//! da cota` e `zumbis: o processo do user.run conta ate o recolhimento`. Com
//! o coletor segurado, os estados que ele desfaria num tique duram o caso
//! inteiro. E dois conferem as pontas da conta: `zumbis: a recusa grava os
//! mortos acima da cota`, o gate que conta os mortos — também com o coletor
//! segurado —, e `zumbis: os fios do kernel nao contam na cota`, o filtro de
//! quem é processo.
//!
//! O pai dos zumbis é o `colhedor` (`programas/src/bin/colhedor.rs`):
//! bifurca quando a suíte manda — o filho sai na hora, com 71, e fica
//! zumbi —, e só colhe quando ela manda.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst};

use super::{
    Resultado, encerrar_os_encerraveis, energia_entregue, esperar_ate, esperar_cedendo, fs_numero,
    fs_pedir, fs_texto, linhas_do_programa, nucleos_secundarios, sistema_aqui, ultimo_com_metodo,
};
use crate::autorizacao::Autoridade;
use crate::fios::Categorias;
use protocolo::usuario::erro;
use protocolo::usuario::evento::{Evento, tipo};

/// O canal do `colhedor`, e os passos dele.
pub(super) const CANAL: &str = "teste-colhedor";
pub(super) const BIFURCAR: i64 = 1;
pub(super) const COLHER: i64 = 2;
/// O código com que o filho do colhedor sai.
pub(super) const DO_FILHO: i64 = 71;

/// O `colhedor`, lançado por um titular: o pai dos zumbis destes casos.
pub(super) struct Colhedor {
    pub(super) fio: u64,
}

/// O que um passo de bifurcar deu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Bifurcou {
    /// O filho nasceu, saiu, e é zumbi.
    Filho(u64),
    /// O colhedor ouviu este erro do `bifurcar`.
    Erro(i64),
}

impl Colhedor {
    /// Lança o colhedor como `autoridade` e espera ele escutar o canal.
    pub(super) fn lancar(autoridade: Autoridade) -> Result<Self, &'static str> {
        let desde = crate::log::total_emitidos();
        let programa = alloc::format!("{}/colhedor", crate::usuario::DIRETORIO_DOS_COMPILADOS);
        let fio = crate::usuario::lancar_como(Some(&programa), autoridade)?;
        esperar_ate(|| linhas_do_programa(desde, "colhedor: pronto") >= 1, 600)
            .map_err(|_| "o colhedor nao ficou pronto")?;
        Ok(Colhedor { fio })
    }

    /// Publica um evento no canal do colhedor, insistindo enquanto a fila
    /// dele estiver cheia — e enquanto ele a andar.
    ///
    /// # Pelo progresso, e não por um prazo fixo
    ///
    /// A fila guarda [`crate::eventos::CAPACIDADE`] passos, e o colhedor os
    /// tira no ritmo da tela: cada passo é uma linha dele no log, e na tela
    /// do virtio-gpu uma linha leva dezenas de milissegundos — de 32 a 61 ms
    /// no local, conforme o arranjo do código no kernel de debug, sem
    /// mudança na lógica (o README, nas mutações do zumbi na cota). Um prazo
    /// fixo para ele andar a fila mediria a tela, e não o colhedor: na CI
    /// 448, o caso da concorrência reprovou assim, no fim — os 600 tiques de
    /// [`Colhedor::encerrar`], do pedido do fim à saída, não bastaram para
    /// as linhas dos passos que ainda estavam na fila. Aqui o prazo
    /// recomeça a cada leitura em que o colhedor tira passos da fila — até
    /// oito de uma vez ([`passos_tirados`]) —; o caso reprova só se ele
    /// passar o prazo inteiro sem tirar nenhum — parado, e não devagar. A
    /// espera não tem teto próprio: o que a limita é a janela do `xtask`,
    /// de dez minutos sem caso terminado.
    fn publicar(tipo: u32, a: i64) -> Resultado {
        loop {
            let tirados = passos_tirados();
            let mut publicado = false;
            let _ = esperar_cedendo(
                || {
                    publicado = crate::eventos::publicar(
                        CANAL,
                        Evento {
                            tipo,
                            a,
                            ..Default::default()
                        },
                    )
                    .is_ok();
                    publicado || passos_tirados() > tirados
                },
                600,
            );
            if publicado {
                return Ok(());
            }
            if passos_tirados() <= tirados {
                return Err("o canal do colhedor nao recebeu o passo");
            }
        }
    }

    /// A primeira linha do colhedor desde `desde` que começa com
    /// `prefixo`: o resto dela.
    fn primeira(desde: u64, prefixo: &str) -> Option<String> {
        let mut visto = None;
        crate::log::ultimos(64, crate::log::Level::Trace, |r| {
            if visto.is_none()
                && r.seq >= desde
                && r.subsistema == "usuario"
                && let Some(resto) = r.mensagem().strip_prefix(prefixo)
            {
                visto = Some(String::from(resto));
            }
        });
        visto
    }

    /// Um passo de bifurcar: o filho — já zumbi quando volta —, ou o erro.
    pub(super) fn bifurcar(&self) -> Result<Bifurcou, &'static str> {
        let desde = crate::log::total_emitidos();
        Self::publicar(tipo::ACAO, BIFURCAR)?;
        let mut visto = None;
        esperar_ate(
            || {
                visto = Self::primeira(desde, "colhedor: bifurc");
                visto.is_some()
            },
            600,
        )
        .map_err(|_| "o colhedor nao respondeu ao bifurcar")?;
        let linha = visto.unwrap_or_default();
        if let Some(filho) = linha
            .strip_prefix("ou ")
            .and_then(|n| n.trim().parse::<u64>().ok())
        {
            esperar_ate(|| crate::fios::zumbi_de_teste(filho), 600)
                .map_err(|_| "o filho do colhedor nao virou zumbi")?;
            return Ok(Bifurcou::Filho(filho));
        }
        if let Some(e) = linha
            .strip_prefix("ar ")
            .and_then(|n| n.trim().parse::<i64>().ok())
        {
            return Ok(Bifurcou::Erro(e));
        }
        crate::log_error!("teste", "colhedor: bifurc{}", linha);
        Err("o colhedor disse algo inesperado ao bifurcar")
    }

    /// Um passo de colher: o filho colhido e o código dele, ou o erro do
    /// `esperar`.
    pub(super) fn colher(&self) -> Result<Result<(u64, i64), i64>, &'static str> {
        let desde = crate::log::total_emitidos();
        Self::publicar(tipo::ACAO, COLHER)?;
        let mut visto: Option<(bool, String)> = None;
        esperar_ate(
            || {
                visto = Self::primeira(desde, "colhedor: colheu ")
                    .map(|r| (true, r))
                    .or_else(|| Self::primeira(desde, "colhedor: esperar ").map(|r| (false, r)));
                visto.is_some()
            },
            600,
        )
        .map_err(|_| "o colhedor nao respondeu ao colher")?;
        let (colheu, resto) = visto.unwrap_or_default();
        if colheu {
            let mut partes = resto.split(" com ");
            let filho = partes.next().and_then(|n| n.trim().parse::<u64>().ok());
            let codigo = partes.next().and_then(|n| n.trim().parse::<i64>().ok());
            return match (filho, codigo) {
                (Some(f), Some(c)) => Ok(Ok((f, c))),
                _ => {
                    crate::log_error!("teste", "colhedor: colheu {}", resto);
                    Err("o colhedor colheu sem dizer o codigo")
                }
            };
        }
        resto
            .trim()
            .parse::<i64>()
            .map(Err)
            .map_err(|_| "o colhedor disse um erro ilegivel ao colher")
    }

    /// Pede o fim e espera o colhedor sair. Os zumbis dele deixam de ser
    /// zumbis — o pai morreu — e o coletor os recolhe.
    ///
    /// O fim é lido depois dos passos que já estão na fila: a espera anda
    /// com ela, como a de [`Colhedor::publicar`] — o prazo recomeça a cada
    /// leitura em que o colhedor tira passos. Reprova só se ele passar o
    /// prazo inteiro vivo e sem tirar passo nenhum.
    pub(super) fn encerrar(&self) -> Resultado {
        let _ = Self::publicar(tipo::ENCERRAR, 0);
        loop {
            let tirados = passos_tirados();
            esperar_ate(
                || !crate::fios::vivo(self.fio) || passos_tirados() > tirados,
                600,
            )
            .map_err(|_| "o colhedor nao saiu")?;
            if !crate::fios::vivo(self.fio) {
                return Ok(());
            }
        }
    }
}

/// Quantos passos o colhedor já tirou da fila do canal dele — `None` sem
/// ninguém escutando. É o progresso pelo qual as esperas de
/// [`Colhedor::publicar`] e [`Colhedor::encerrar`] recomeçam o prazo: só o
/// ouvinte tira passos da fila — até oito numa leitura —, e a conta só
/// cresce; um canal que fechou (`None`) não é progresso. A primeira espera
/// já acha a conta: [`Colhedor::lancar`] espera o colhedor escutar.
fn passos_tirados() -> Option<u64> {
    crate::eventos::estado(CANAL).map(|e| e.entregues)
}

/// A política padrão com a cota do operador em `cota`.
pub(super) fn politica_com_a_cota(cota: u32) -> Resultado {
    let texto = politica::PADRAO.replace(
        "processos operador 8",
        &alloc::format!("processos operador {cota}"),
    );
    if texto == politica::PADRAO {
        return Err("a politica padrao nao tem a cota do operador");
    }
    let p = politica::Politica::ler(&texto).map_err(|_| "a politica do caso nao vale")?;
    crate::autorizacao::trocar_politica(p);
    Ok(())
}

/// Uma pessoa de papel operador, entrada no console `console`.
pub(super) fn operador(console: u16, nome: &str) -> Autoridade {
    let sessao = crate::pessoas::sessao_de_teste(
        crate::pessoas::Console::Terminal(console),
        nome,
        "operador",
    );
    Autoridade::Pessoa { sessao }
}

/// O fim dos casos `zumbis:` do colhedor: o colhedor sai — se não sai, é
/// encerrado sem o gate —, os `encerravel` também, a tabela fica sem
/// zumbi, e a política e as pessoas voltam ao que eram.
pub(super) fn limpar(colhedor: Option<u64>) {
    let _ = crate::eventos::publicar(
        CANAL,
        Evento {
            tipo: tipo::ENCERRAR,
            ..Default::default()
        },
    );
    if let Some(fio) = colhedor
        && esperar_ate(|| !crate::fios::vivo(fio), 600).is_err()
    {
        let _ = crate::contencao::encerrar_processo(fio);
        let _ = esperar_ate(|| !crate::fios::vivo(fio), 600);
    }
    encerrar_os_encerraveis();
    let _ = esperar_ate(|| crate::fios::colheita().1 == 0, 600);
    crate::autorizacao::carregar();
    crate::pessoas::esquecer_registradas();
}

/// Bifurca até o colhedor ouvir um erro, sem colher: quantos filhos
/// nasceram — todos zumbis — e o erro em que parou.
fn bifurcar_ate_parar(c: &Colhedor) -> Result<(usize, Option<i64>), &'static str> {
    let mut nascidos = 0usize;
    for _ in 0..crate::fios::MAX_FIOS + 2 {
        match c.bifurcar()? {
            Bifurcou::Filho(_) => nascidos += 1,
            Bifurcou::Erro(e) => return Ok((nascidos, Some(e))),
        }
    }
    Ok((nascidos, None))
}

/// A recusa da cota de `process.fork` na auditoria: a última, pela política,
/// com o motivo da cota.
fn recusa_da_cota_gravada() -> bool {
    ultimo_com_metodo("process.fork").is_some_and(|e| {
        e.codigo == politica::Codigo::DenyPolicy
            && e.detalhe.starts_with("cota de processos do papel")
    })
}

/// Um fio do kernel que nasce e sai: o que `energia`, `pareamento` e os
/// fluxos fazem quando a máquina precisa deles.
extern "C" fn fio_curto(_argumento: u64) -> ! {
    crate::fios::terminar()
}

/// A reprodução: um titular com `process.run` e a cota em 2 lança o
/// `colhedor`, que bifurca até ouvir um erro, sem colher — cada filho sai
/// na hora e fica zumbi.
///
/// Com os zumbis fora da cota (o código de `5bf5307`), o colhedor só para
/// quando a tabela de fios acaba (`SEM_VAGA_DE_FIO`): o titular ocupa a
/// tabela inteira com a cota em 2. Com os zumbis na cota (a alternativa A),
/// o segundo bifurcar ouve `NEGADO` — o colhedor e um zumbi enchem a cota
/// —, e a recusa vai para a auditoria pela política.
pub(super) fn zumbis_um_titular_nao_esgota_a_tabela() -> Resultado {
    if crate::fios::colheita().1 != 0 {
        return Err("a tabela ja tinha zumbi antes do caso comecar");
    }
    politica_com_a_cota(2)?;
    let titular = operador(0, "pessoa-dos-zumbis");
    let livres_antes = crate::fios::vagas_livres_de_teste();
    let mut fio = None;
    let resultado = (|| -> Resultado {
        let c = Colhedor::lancar(titular)?;
        fio = Some(c.fio);
        let (nascidos, parou) = bifurcar_ate_parar(&c)?;
        let ocupadas = crate::fios::ocupadas_de_teste(titular);
        let livres = crate::fios::vagas_livres_de_teste();
        crate::log_info!(
            "teste",
            "zumbis: cota 2; {} filhos nasceram e ficaram zumbis; o bifurcar parou com {:?}; \
             o titular ocupa {} vagas; {} livres de {} antes",
            nascidos,
            parou,
            ocupadas,
            livres,
            livres_antes
        );
        if parou == Some(erro::SEM_VAGA_DE_FIO) {
            return Err("os zumbis de um titular esgotaram a tabela de fios");
        }
        if parou != Some(erro::NEGADO) || nascidos != 1 || ocupadas != 2 {
            return Err("o titular passou da cota de processos com zumbis");
        }
        if !recusa_da_cota_gravada() {
            return Err("a recusa pela cota nao foi gravada");
        }
        Ok(())
    })();
    limpar(fio);
    resultado
}

/// Com um titular parado na cota dele com zumbis, o sistema segue: um fio
/// do kernel nasce, o sistema lança um processo, outro titular lança o
/// dele, e o `system.reboot` é aceito e chega ao fim. Com o código de
/// `5bf5307`, o titular enche a tabela antes, e nada disso nasce — o
/// `system.reboot` responde que não há vaga para o fio da energia.
pub(super) fn zumbis_com_um_titular_no_teto_o_sistema_segue() -> Resultado {
    if crate::fios::colheita().1 != 0 {
        return Err("a tabela ja tinha zumbi antes do caso comecar");
    }
    politica_com_a_cota(2)?;
    let titular = operador(0, "pessoa-dos-zumbis");
    let outro = operador(1, "outra-pessoa");
    let dir = crate::usuario::DIRETORIO_DOS_COMPILADOS;
    let mut fio = None;
    let resultado = (|| -> Resultado {
        let c = Colhedor::lancar(titular)?;
        fio = Some(c.fio);
        let (nascidos, parou) = bifurcar_ate_parar(&c)?;
        let do_kernel = crate::fios::criar("teste-essencial", fio_curto, 0).map(|_| ());
        let do_sistema = crate::usuario::lancar(Some(&alloc::format!("{dir}/ola"))).map(|_| ());
        let de_outro =
            crate::usuario::lancar_como(Some(&alloc::format!("{dir}/encerravel")), outro)
                .map(|_| ());
        let segura = crate::energia::Segura::de_teste();
        let r = fs_pedir(sistema_aqui(), "system.reboot", "{}");
        let aceito = fs_numero(&r, "record").is_some();
        drop(segura);
        let entregue = if aceito { energia_entregue() } else { None };
        crate::log_info!(
            "teste",
            "zumbis: {} filhos, parou com {:?}; fio do kernel {:?}; processo do sistema {:?}; \
             processo de outro titular {:?}; system.reboot {}",
            nascidos,
            parou,
            do_kernel,
            do_sistema,
            de_outro,
            if aceito { "aceito" } else { r.as_str() }
        );
        do_kernel.map_err(|_| "um fio do kernel nao nasceu com um titular no teto")?;
        do_sistema.map_err(|_| "o sistema nao lancou um processo com um titular no teto")?;
        de_outro.map_err(|_| "outro titular nao lancou um processo com um titular no teto")?;
        if !aceito || entregue != Some(crate::energia::Acao::Reiniciar) {
            return Err("o system.reboot nao foi aceito e entregue com um titular no teto");
        }
        Ok(())
    })();
    limpar(fio);
    resultado
}

/// Os zumbis de um titular não tomam a cota de outro: com a cota em 2, o
/// primeiro titular bifurca até parar; o segundo, do mesmo papel, lança
/// os dois processos da cota dele — nem um a menos —, e o terceiro é
/// recusado pela cota dele, e não por falta de vaga.
pub(super) fn zumbis_os_de_um_titular_nao_tomam_a_cota_de_outro() -> Resultado {
    if crate::fios::colheita().1 != 0 {
        return Err("a tabela ja tinha zumbi antes do caso comecar");
    }
    politica_com_a_cota(2)?;
    let primeiro = operador(0, "pessoa-dos-zumbis");
    let segundo = operador(1, "outra-pessoa");
    let encerravel = alloc::format!("{}/encerravel", crate::usuario::DIRETORIO_DOS_COMPILADOS);
    let mut fio = None;
    let resultado = (|| -> Resultado {
        let c = Colhedor::lancar(primeiro)?;
        fio = Some(c.fio);
        let (nascidos, parou) = bifurcar_ate_parar(&c)?;
        let ocupadas_do_primeiro = crate::fios::ocupadas_de_teste(primeiro);
        let mut lancados = Vec::new();
        for _ in 0..3 {
            lancados.push(crate::usuario::lancar_como(Some(&encerravel), segundo));
        }
        crate::log_info!(
            "teste",
            "zumbis: o primeiro titular, {} filhos e parou com {:?}, ocupa {}; o segundo: {:?}",
            nascidos,
            parou,
            ocupadas_do_primeiro,
            lancados
        );
        if lancados[0].is_err() || lancados[1].is_err() {
            return Err("os zumbis de um titular tomaram a cota de outro");
        }
        if lancados[2] != Err(crate::fios::COTA_ESGOTADA) {
            return Err("o terceiro processo do segundo titular nao ouviu a cota dele");
        }
        if crate::fios::ocupadas_de_teste(primeiro) > 2 {
            return Err("o primeiro titular passou da cota dele");
        }
        Ok(())
    })();
    limpar(fio);
    resultado
}

/// A cota volta na colheita, na saída do pai e no término do pai: com a
/// cota em 2, o colhedor e um zumbi enchem a cota, e o segundo bifurcar
/// ouve `NEGADO`; colhido o zumbi — com o código dele —, ele deixa de ser
/// zumbi e conta até o coletor o recolher, e o bifurcar seguinte nasce
/// depois disso; o pai sai com um zumbi, e a cota e a vaga do zumbi voltam;
/// e o `process.terminate` no pai faz o mesmo.
pub(super) fn zumbis_a_colheita_e_o_fim_do_pai_devolvem_a_cota() -> Resultado {
    if crate::fios::colheita().1 != 0 {
        return Err("a tabela ja tinha zumbi antes do caso comecar");
    }
    politica_com_a_cota(2)?;
    let titular = operador(0, "pessoa-dos-zumbis");
    let mut fio = None;
    let resultado = (|| -> Resultado {
        // A colheita.
        let c = Colhedor::lancar(titular)?;
        fio = Some(c.fio);
        let Bifurcou::Filho(primeiro) = c.bifurcar()? else {
            return Err("o primeiro filho nao nasceu");
        };
        if c.bifurcar()? != Bifurcou::Erro(erro::NEGADO) {
            return Err("o zumbi nao contou na cota");
        }
        match c.colher()? {
            Ok((filho, DO_FILHO)) if filho == primeiro => {}
            outro => {
                crate::log_error!("teste", "zumbis: a colheita deu {:?}", outro);
                return Err("o pai nao colheu o filho com o codigo dele");
            }
        }
        // O colhido conta até o coletor recolhê-lo (a alternativa 1).
        esperar_ate(|| !crate::fios::na_tabela_de_teste(primeiro), 600)
            .map_err(|_| "o coletor nao recolheu o filho colhido")?;
        let Bifurcou::Filho(segundo) = c.bifurcar()? else {
            return Err("a colheita nao devolveu a cota");
        };

        // A saída do pai, com um zumbi.
        c.encerrar()?;
        esperar_ate(
            || {
                crate::fios::ocupadas_de_teste(titular) == 0
                    && !crate::fios::na_tabela_de_teste(segundo)
            },
            600,
        )
        .map_err(|_| "a saida do pai nao devolveu a cota e a vaga do zumbi")?;

        // O término do pai, com um zumbi.
        let c = Colhedor::lancar(titular)?;
        fio = Some(c.fio);
        let Bifurcou::Filho(terceiro) = c.bifurcar()? else {
            return Err("o filho do segundo colhedor nao nasceu");
        };
        let r = fs_pedir(
            sistema_aqui(),
            "process.terminate",
            &alloc::format!(r#"{{"process":{}}}"#, c.fio),
        );
        if fs_texto(&r, "state").as_deref() != Some("terminating") {
            crate::log_error!("teste", "{}", r);
            return Err("o termino do pai nao foi aceito");
        }
        esperar_ate(
            || {
                crate::fios::ocupadas_de_teste(titular) == 0
                    && !crate::fios::na_tabela_de_teste(terceiro)
            },
            600,
        )
        .map_err(|_| "o termino do pai nao devolveu a cota e a vaga do zumbi")?;

        // E a cota inteira de novo.
        let c = Colhedor::lancar(titular)?;
        fio = Some(c.fio);
        if !matches!(c.bifurcar()?, Bifurcou::Filho(_)) {
            return Err("a cota nao voltou inteira depois do fim do pai");
        }
        Ok(())
    })();
    limpar(fio);
    resultado
}

/// Quem colhe tarde ouve a cota e segue: com a cota em 3, o colhedor
/// bifurca dois filhos e não colhe — os dois zumbis e ele enchem a cota —,
/// e o terceiro bifurcar ouve `NEGADO`; o programa não cai: colhe os dois,
/// cada um com o código dele, e a cota volta inteira quando o coletor os
/// recolhe — dois filhos nascem de novo.
pub(super) fn zumbis_quem_colhe_tarde_ouve_a_cota_e_segue() -> Resultado {
    if crate::fios::colheita().1 != 0 {
        return Err("a tabela ja tinha zumbi antes do caso comecar");
    }
    politica_com_a_cota(3)?;
    let titular = operador(0, "pessoa-dos-zumbis");
    let mut fio = None;
    let resultado = (|| -> Resultado {
        let c = Colhedor::lancar(titular)?;
        fio = Some(c.fio);
        let mut filhos = Vec::new();
        for _ in 0..2 {
            match c.bifurcar()? {
                Bifurcou::Filho(f) => filhos.push(f),
                Bifurcou::Erro(e) => {
                    crate::log_error!("teste", "zumbis: bifurcar {}", e);
                    return Err("um filho dentro da cota nao nasceu");
                }
            }
        }
        let terceiro = c.bifurcar()?;
        if terceiro != Bifurcou::Erro(erro::NEGADO) {
            crate::log_error!("teste", "zumbis: o terceiro deu {:?}", terceiro);
            return Err("quem colhe tarde passou da cota com zumbis");
        }
        let mut colhidos = Vec::new();
        for _ in 0..2 {
            match c.colher()? {
                Ok((f, DO_FILHO)) => colhidos.push(f),
                outro => {
                    crate::log_error!("teste", "zumbis: a colheita deu {:?}", outro);
                    return Err("a colheita tardia nao devolveu o codigo do filho");
                }
            }
        }
        colhidos.sort_unstable();
        filhos.sort_unstable();
        if colhidos != filhos {
            return Err("a colheita tardia colheu outros filhos");
        }
        // Os colhidos contam até o coletor recolhê-los (a alternativa 1).
        esperar_ate(
            || {
                colhidos
                    .iter()
                    .all(|f| !crate::fios::na_tabela_de_teste(*f))
            },
            600,
        )
        .map_err(|_| "o coletor nao recolheu os filhos colhidos")?;
        for _ in 0..2 {
            if !matches!(c.bifurcar()?, Bifurcou::Filho(_)) {
                return Err("a cota nao voltou inteira depois da colheita tardia");
            }
        }
        Ok(())
    })();
    limpar(fio);
    resultado
}

/// A recusa grava o que o titular ocupa, zumbis inclusive: com a cota em
/// 3, o colhedor bifurca dois filhos e não colhe; com a cota rebaixada a 2,
/// o bifurcar ouve `NEGADO`, e a recusa diz "3 de 2" — o gate contou o
/// colhedor e os dois zumbis. Se só a recontagem do nascimento contasse os
/// zumbis, o gate deixaria o pedido passar, o espaço seria copiado à toa, e
/// a recusa diria "2 de 2".
pub(super) fn zumbis_a_recusa_grava_os_zumbis_acima_da_cota() -> Resultado {
    if crate::fios::colheita().1 != 0 {
        return Err("a tabela ja tinha zumbi antes do caso comecar");
    }
    politica_com_a_cota(3)?;
    let titular = operador(0, "pessoa-dos-zumbis");
    let mut fio = None;
    let resultado = (|| -> Resultado {
        let c = Colhedor::lancar(titular)?;
        fio = Some(c.fio);
        for _ in 0..2 {
            if !matches!(c.bifurcar()?, Bifurcou::Filho(_)) {
                return Err("um filho dentro da cota nao nasceu");
            }
        }
        politica_com_a_cota(2)?;
        let rebaixada = c.bifurcar()?;
        let gravada = ultimo_com_metodo("process.fork").map(|e| e.detalhe);
        crate::log_info!(
            "teste",
            "zumbis: a cota rebaixada a 2, com o colhedor e dois zumbis; o bifurcar deu {:?}; \
             a recusa gravou {:?}",
            rebaixada,
            gravada
        );
        if rebaixada != Bifurcou::Erro(erro::NEGADO) {
            return Err("o titular acima da cota rebaixada bifurcou");
        }
        if gravada.as_deref() != Some("cota de processos do papel: 3 de 2") {
            return Err("a recusa da cota nao gravou os zumbis acima dela");
        }
        Ok(())
    })();
    limpar(fio);
    resultado
}

/// O morto conta na cota do titular até o coletor recolhê-lo — o zumbi, e
/// também o que não é zumbi: o filho colhido e o órfão. Com o coletor
/// segurado, em cada passo as duas contas (`fios::contas_da_cota_de_teste`)
/// têm de ser iguais, e as categorias da definição
/// (`fios::ocupadas_por_categoria_de_teste`), as esperadas:
///
/// - o colhedor e dois zumbis: um vivo e dois zumbis;
/// - um filho colhido, ainda na tabela: um vivo, um zumbi e um morto;
/// - o colhedor encerrado: três mortos — o pai, o órfão e o colhido;
/// - um colhedor novo nasce, o quarto de quatro, e o bifurcar dele ouve a
///   recusa da cota, com os três mortos contando;
/// - solto o coletor, os três saem da tabela, e o bifurcar passa.
///
/// Com a conta da 14.1 antes da alternativa 1, o colhido e o órfão não
/// contavam: a conta da cota divergia da definição, e o colhedor novo
/// bifurcava.
pub(super) fn zumbis_o_morto_conta_ate_o_recolhimento() -> Resultado {
    if crate::fios::colheita().1 != 0 {
        return Err("a tabela ja tinha zumbi antes do caso comecar");
    }
    super::sem_mortos_por_recolher();
    politica_com_a_cota(4)?;
    let titular = operador(0, "pessoa-dos-mortos");
    let conferir = |passo: &str, esperado: Categorias| -> Resultado {
        let (da_cota, da_definicao) = crate::fios::contas_da_cota_de_teste(titular);
        let categorias = crate::fios::ocupadas_por_categoria_de_teste(titular);
        crate::log_info!(
            "teste",
            "zumbis: {}: a conta da cota diz {}, a definicao {} ({:?}), o esperado {:?}",
            passo,
            da_cota,
            da_definicao,
            categorias,
            esperado
        );
        if categorias != esperado {
            return Err("as categorias da definicao nao foram as esperadas");
        }
        if da_cota != da_definicao {
            return Err("a conta da cota divergiu da definicao");
        }
        Ok(())
    };
    let mut fio = None;
    let mut segurado = None;
    let resultado = (|| -> Resultado {
        let c = Colhedor::lancar(titular)?;
        fio = Some(c.fio);
        segurado = Some(super::vagas::ColetorSegurado::segurar());
        let mut filhos = Vec::new();
        for _ in 0..2 {
            match c.bifurcar()? {
                Bifurcou::Filho(f) => filhos.push(f),
                Bifurcou::Erro(_) => return Err("um filho dentro da cota nao nasceu"),
            }
        }
        conferir(
            "o colhedor e dois zumbis",
            Categorias {
                vivos: 1,
                zumbis: 2,
                mortos: 0,
            },
        )?;
        let colhido = match c.colher()? {
            Ok((f, DO_FILHO)) => f,
            _ => return Err("o colhedor nao colheu o filho com o codigo dele"),
        };
        if !crate::fios::na_tabela_de_teste(colhido) {
            return Err("o colhido saiu da tabela com o coletor segurado");
        }
        conferir(
            "um filho colhido e ainda na tabela",
            Categorias {
                vivos: 1,
                zumbis: 1,
                mortos: 1,
            },
        )?;
        let sobrou = filhos
            .iter()
            .copied()
            .find(|&f| f != colhido)
            .ok_or("o colhedor colheu um filho que nao era dele")?;
        c.encerrar()?;
        if !crate::fios::na_tabela_de_teste(c.fio) || !crate::fios::na_tabela_de_teste(sobrou) {
            return Err("o pai morto ou o filho dele saiu da tabela com o coletor segurado");
        }
        conferir(
            "o pai morto, o orfao e o colhido, ainda na tabela",
            Categorias {
                vivos: 0,
                zumbis: 0,
                mortos: 3,
            },
        )?;
        let novo = Colhedor::lancar(titular)?;
        fio = Some(novo.fio);
        conferir(
            "um colhedor novo com os tres mortos",
            Categorias {
                vivos: 1,
                zumbis: 0,
                mortos: 3,
            },
        )?;
        if novo.bifurcar()? != Bifurcou::Erro(erro::NEGADO) {
            return Err("o titular bifurcou com os mortos dele enchendo a cota");
        }
        if !recusa_da_cota_gravada() {
            return Err("a recusa pela cota nao foi gravada");
        }
        drop(segurado.take());
        for morto in [colhido, sobrou, c.fio] {
            esperar_ate(|| !crate::fios::na_tabela_de_teste(morto), 600)
                .map_err(|_| "o coletor solto nao recolheu um morto do titular")?;
        }
        conferir(
            "o colhedor novo, recolhidos os mortos",
            Categorias {
                vivos: 1,
                zumbis: 0,
                mortos: 0,
            },
        )?;
        if !matches!(novo.bifurcar()?, Bifurcou::Filho(_)) {
            return Err("a cota nao voltou depois do recolhimento");
        }
        Ok(())
    })();
    drop(segurado);
    limpar(fio);
    resultado
}

/// O laço do achado A1, com o coletor segurado: o colhedor bifurca e colhe
/// em seguida, um filho por vez. Cada filho colhido deixa de ser zumbi e
/// guarda a vaga até a passada do coletor, que não vem. Com a cota em 3, o
/// colhedor e dois colhidos enchem a cota: o terceiro bifurcar ouve a
/// recusa da cota, que vai para a auditoria, e o titular nunca ocupa mais
/// que três vagas. Outro titular ainda lança o dele. Solto o coletor, os
/// colhidos saem, e o laço segue.
///
/// Com a conta da 14.1 antes da alternativa 1, o colhido não contava: o laço
/// seguia até a tabela acabar (`SEM_VAGA_DE_FIO`), e daí em diante não
/// nascia fio de ninguém enquanto o coletor não passasse.
pub(super) fn zumbis_o_laco_que_bifurca_e_colhe_nao_passa_da_cota() -> Resultado {
    const COTA: usize = 3;
    if crate::fios::colheita().1 != 0 {
        return Err("a tabela ja tinha zumbi antes do caso comecar");
    }
    super::sem_mortos_por_recolher();
    politica_com_a_cota(COTA as u32)?;
    let titular = operador(0, "pessoa-do-laco");
    let outro = operador(1, "outra-pessoa");
    let encerravel = alloc::format!("{}/encerravel", crate::usuario::DIRETORIO_DOS_COMPILADOS);
    let mut fio = None;
    let mut segurado = None;
    let resultado = (|| -> Resultado {
        let c = Colhedor::lancar(titular)?;
        fio = Some(c.fio);
        segurado = Some(super::vagas::ColetorSegurado::segurar());
        let mut voltas = 0usize;
        let mut maior = 0usize;
        let parou = loop {
            if voltas > crate::fios::MAX_FIOS {
                break None;
            }
            match c.bifurcar()? {
                Bifurcou::Filho(filho) => {
                    match c.colher()? {
                        Ok((f, DO_FILHO)) if f == filho => {}
                        _ => return Err("o colhedor nao colheu o filho com o codigo dele"),
                    }
                    voltas += 1;
                    maior = maior.max(crate::fios::ocupadas_de_teste(titular));
                }
                Bifurcou::Erro(e) => break Some(e),
            }
        };
        let categorias = crate::fios::ocupadas_por_categoria_de_teste(titular);
        let (da_cota, da_definicao) = crate::fios::contas_da_cota_de_teste(titular);
        let gravada = recusa_da_cota_gravada();
        let do_outro = crate::usuario::lancar_como(Some(&encerravel), outro);
        crate::log_info!(
            "teste",
            "zumbis: cota {}; {} voltas de bifurcar e colher; o bifurcar parou com {:?}; \
             maior ocupacao {}; {:?}; a conta da cota diz {}, a definicao {}; \
             o outro titular lancou: {:?}",
            COTA,
            voltas,
            parou,
            maior,
            categorias,
            da_cota,
            da_definicao,
            do_outro
        );
        if parou == Some(erro::SEM_VAGA_DE_FIO) {
            return Err("o laco de bifurcar e colher esgotou a tabela de fios");
        }
        if parou != Some(erro::NEGADO) || voltas != COTA - 1 || maior > COTA {
            return Err("o laco de bifurcar e colher passou da cota");
        }
        let esperado = Categorias {
            vivos: 1,
            zumbis: 0,
            mortos: COTA - 1,
        };
        if categorias != esperado || da_cota != da_definicao {
            return Err("a conta da cota nao contou os filhos colhidos");
        }
        if !gravada {
            return Err("a recusa pela cota nao foi gravada");
        }
        if do_outro.is_err() {
            return Err("os mortos de um titular barraram o lancamento de outro");
        }
        drop(segurado.take());
        esperar_ate(|| crate::fios::ocupadas_de_teste(titular) == 1, 600)
            .map_err(|_| "o coletor solto nao recolheu os filhos colhidos")?;
        match c.bifurcar()? {
            Bifurcou::Filho(filho) => match c.colher()? {
                Ok((f, DO_FILHO)) if f == filho => Ok(()),
                _ => Err("o colhedor nao colheu o filho depois do recolhimento"),
            },
            Bifurcou::Erro(_) => Err("o laco nao seguiu depois do recolhimento"),
        }
    })();
    drop(segurado);
    limpar(fio);
    resultado
}

/// A recusa da cota de `process.run` na auditoria: a última, pela política,
/// com o motivo da cota.
fn recusa_do_lancamento_gravada() -> bool {
    ultimo_com_metodo("process.run").is_some_and(|e| {
        e.codigo == politica::Codigo::DenyPolicy
            && e.detalhe.starts_with("cota de processos do papel")
    })
}

/// O processo do `user.run` nasce sem pai e, quando sai, não é zumbi de
/// ninguém: guarda a vaga até a passada do coletor, e conta na cota do
/// titular até lá. Com o coletor segurado e a cota em 2, dois `ola` nascem
/// e saem; o terceiro lançamento ouve a recusa da cota (`COTA_ESGOTADA`),
/// que vai para a auditoria. Solto o coletor, os dois saem da tabela, e o
/// lançamento passa.
///
/// Com a conta da 14.1 antes da alternativa 1, o `ola` que saiu não contava,
/// e o terceiro nascia.
pub(super) fn zumbis_o_processo_do_user_run_conta_ate_o_recolhimento() -> Resultado {
    if crate::fios::colheita().1 != 0 {
        return Err("a tabela ja tinha zumbi antes do caso comecar");
    }
    super::sem_mortos_por_recolher();
    politica_com_a_cota(2)?;
    let titular = operador(0, "pessoa-do-ola");
    let ola = alloc::format!("{}/ola", crate::usuario::DIRETORIO_DOS_COMPILADOS);
    let mut segurado = Some(super::vagas::ColetorSegurado::segurar());
    let resultado = (|| -> Resultado {
        let mut mortos = Vec::new();
        for _ in 0..2 {
            let id = crate::usuario::lancar_como(Some(&ola), titular)
                .map_err(|_| "um ola dentro da cota nao nasceu")?;
            esperar_ate(|| !crate::fios::vivo(id), 600).map_err(|_| "o ola nao saiu")?;
            mortos.push(id);
        }
        let categorias = crate::fios::ocupadas_por_categoria_de_teste(titular);
        let terceiro = crate::usuario::lancar_como(Some(&ola), titular);
        crate::log_info!(
            "teste",
            "zumbis: cota 2; dois ola sairam: {:?}; o terceiro lancamento deu {:?}",
            categorias,
            terceiro
        );
        let esperado = Categorias {
            vivos: 0,
            zumbis: 0,
            mortos: 2,
        };
        if categorias != esperado {
            return Err("os ola que sairam nao contaram como mortos do titular");
        }
        if terceiro != Err(crate::fios::COTA_ESGOTADA) {
            return Err("o titular lancou com os mortos dele enchendo a cota");
        }
        if !recusa_do_lancamento_gravada() {
            return Err("a recusa pela cota do lancamento nao foi gravada");
        }
        drop(segurado.take());
        for id in &mortos {
            esperar_ate(|| !crate::fios::na_tabela_de_teste(*id), 600)
                .map_err(|_| "o coletor solto nao recolheu um ola")?;
        }
        let id = crate::usuario::lancar_como(Some(&ola), titular)
            .map_err(|_| "a cota nao voltou depois do recolhimento")?;
        esperar_ate(|| !crate::fios::vivo(id), 600).map_err(|_| "o ultimo ola nao saiu")
    })();
    drop(segurado);
    crate::autorizacao::carregar();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// A recusa grava o que o titular ocupa, mortos inclusive: com o coletor
/// segurado e a cota em 4, o colhedor bifurca dois filhos e os colhe — os
/// dois colhidos guardam a vaga até o recolhimento —; com a cota rebaixada
/// a 2, o bifurcar ouve `NEGADO`, e a recusa diz "3 de 2": o gate contou o
/// colhedor e os dois mortos. Se o gate contasse como a 14.1 antes da
/// alternativa 1 — os vivos, os que nascem e os zumbis —, deixaria o pedido
/// passar, o espaço do colhedor seria copiado à toa, e a recusa, do
/// nascimento, diria "2 de 2".
pub(super) fn zumbis_a_recusa_grava_os_mortos_acima_da_cota() -> Resultado {
    if crate::fios::colheita().1 != 0 {
        return Err("a tabela ja tinha zumbi antes do caso comecar");
    }
    super::sem_mortos_por_recolher();
    politica_com_a_cota(4)?;
    let titular = operador(0, "pessoa-dos-mortos");
    let mut fio = None;
    let mut segurado = None;
    let resultado = (|| -> Resultado {
        let c = Colhedor::lancar(titular)?;
        fio = Some(c.fio);
        segurado = Some(super::vagas::ColetorSegurado::segurar());
        for _ in 0..2 {
            if !matches!(c.bifurcar()?, Bifurcou::Filho(_)) {
                return Err("um filho dentro da cota nao nasceu");
            }
        }
        for _ in 0..2 {
            if !matches!(c.colher()?, Ok((_, DO_FILHO))) {
                return Err("o colhedor nao colheu o filho com o codigo dele");
            }
        }
        politica_com_a_cota(2)?;
        let rebaixada = c.bifurcar()?;
        let gravada = ultimo_com_metodo("process.fork").map(|e| e.detalhe);
        crate::log_info!(
            "teste",
            "zumbis: a cota rebaixada a 2, com o colhedor e dois colhidos; o bifurcar deu {:?}; \
             a recusa gravou {:?}",
            rebaixada,
            gravada
        );
        if rebaixada != Bifurcou::Erro(erro::NEGADO) {
            return Err("o titular acima da cota rebaixada bifurcou");
        }
        if gravada.as_deref() != Some("cota de processos do papel: 3 de 2") {
            return Err("a recusa da cota nao gravou os mortos acima dela");
        }
        Ok(())
    })();
    drop(segurado);
    limpar(fio);
    resultado
}

/// Só um processo conta na cota, e não um fio do kernel com a autoridade do
/// titular — os do kernel nascem com a do sistema ou a de um serviço, e a
/// suíte cria alguns com a de uma pessoa, como a sonda da autoridade. Com a
/// cota em 2 e três fios do kernel da pessoa vivos, as duas contas
/// (`fios::contas_da_cota_de_teste`) dizem zero, e a pessoa ainda lança os
/// dois `ola` da cota. Sem o filtro do nome na conta, os três fios
/// encheriam a cota, e o primeiro `ola` ouviria a recusa.
pub(super) fn zumbis_os_fios_do_kernel_nao_contam_na_cota() -> Resultado {
    static SOLTAR: AtomicBool = AtomicBool::new(false);
    extern "C" fn espera(_argumento: u64) -> ! {
        while !SOLTAR.load(SeqCst) {
            crate::fios::ceder();
        }
        crate::fios::terminar()
    }
    super::sem_mortos_por_recolher();
    politica_com_a_cota(2)?;
    let titular = operador(0, "pessoa-dos-fios");
    SOLTAR.store(false, SeqCst);
    let mut fios = Vec::new();
    let resultado = (|| -> Resultado {
        for _ in 0..3 {
            let id = crate::fios::criar_como("teste-fio-da-pessoa", espera, 0, titular)?;
            fios.push(id.numero());
        }
        let contas = crate::fios::contas_da_cota_de_teste(titular);
        crate::log_info!(
            "teste",
            "zumbis: tres fios do kernel da pessoa; as contas da cota e da definicao: {:?}",
            contas
        );
        if contas != (0, 0) {
            return Err("os fios do kernel contaram na cota do titular");
        }
        let ola = alloc::format!("{}/ola", crate::usuario::DIRETORIO_DOS_COMPILADOS);
        let mut lancados = Vec::new();
        for _ in 0..2 {
            let id = crate::usuario::lancar_como(Some(&ola), titular)
                .map_err(|_| "os fios do kernel tomaram a cota do titular")?;
            lancados.push(id);
        }
        for id in lancados {
            esperar_ate(|| !crate::fios::vivo(id), 600).map_err(|_| "um ola nao saiu")?;
        }
        Ok(())
    })();
    SOLTAR.store(true, SeqCst);
    for id in fios {
        let _ = esperar_ate(|| !crate::fios::vivo(id), 600);
    }
    crate::autorizacao::carregar();
    crate::pessoas::esquecer_registradas();
    resultado
}

/// A cota com zumbis vale com tudo ao mesmo tempo: o colhedor bifurca e
/// colhe em rajadas — os filhos saem noutros núcleos, o coletor passa —,
/// e um lançador em cada núcleo secundário tenta lançar o `ola` como o
/// mesmo titular, `TENTATIVAS_POR_RAJADA` vezes a cada rajada, no
/// instante em que ela abre, junto com as bifurcações. Um vigia, noutro
/// núcleo, confere a cada volta, sob a trava do escalonador, quantas vagas
/// o titular ocupa — vivos, zumbis e mortos ainda não recolhidos —, e a
/// suíte confere também entre as rajadas: nunca mais que a cota. Em cada
/// olhada, a conta da cota tem de ser a da definição. No fim, o colhedor
/// encerrado, nenhum zumbi fica e nenhuma vaga sobra.
///
/// # Por que os lançadores andam com as rajadas
///
/// Soltos, eles lançavam enquanto a suíte não acabasse as rajadas — e cada
/// `ola` escreve três linhas, e o kernel mais duas, cada uma na serial e
/// na tela, com as interrupções mascaradas. O fio da suíte, fixo no
/// primeiro núcleo, esperava atrás dos processos lançados; quanto mais ele
/// esperava, mais `ola` nasciam: de 1 107 a 1 574 por rodada no x86, e de
/// 6 334 a 10 874 recusas, de cinquenta a setenta segundos do relógio do
/// kernel. Na CI 444, com a serial do runner escoando umas vinte linhas por
/// segundo, o caso passou dos dez minutos sem terminar, e o emulador foi
/// encerrado. Em rajadas, o trabalho tem teto — as rajadas, vezes um
/// lançador por núcleo secundário, vezes as tentativas de cada um —, e as
/// tentativas de uma rajada saem juntas: a corrida entre o gate e o
/// nascimento que a cota tem de fechar (a MZ7 a abre).
pub(super) fn zumbis_a_cota_vale_com_tudo_ao_mesmo_tempo() -> Resultado {
    const COTA: u32 = 4;
    const RAJADAS: usize = 24;
    /// Quantas vezes cada lançador tenta lançar o `ola` em cada rajada.
    const TENTATIVAS_POR_RAJADA: usize = 4;
    static AUTORIDADE: crate::trava::Mutex<Option<Autoridade>> = crate::trava::Mutex::new(None);
    static PARAR: AtomicBool = AtomicBool::new(false);
    /// A rajada aberta: os lançadores tentam quando ela muda.
    static RAJADA: AtomicUsize = AtomicUsize::new(0);
    static VIVOS: AtomicUsize = AtomicUsize::new(0);
    static LANCADOS: AtomicU64 = AtomicU64::new(0);
    static PELA_COTA: AtomicU64 = AtomicU64::new(0);
    static OUTRAS: AtomicU64 = AtomicU64::new(0);
    static MAIOR: AtomicUsize = AtomicUsize::new(0);
    static OLHADAS: AtomicU64 = AtomicU64::new(0);
    static DIVERGENCIAS: AtomicU64 = AtomicU64::new(0);

    fn autoridade() -> Option<Autoridade> {
        crate::arch::sem_interrupcoes(|| *AUTORIDADE.lock())
    }
    /// Uma olhada, sob a trava do escalonador: a ocupação pela definição —
    /// os vivos, os que nascem, os zumbis e os mortos ainda não recolhidos
    /// —, e a conta da cota conferida contra ela.
    fn olhar(a: Autoridade) {
        let (da_cota, da_definicao) = crate::fios::contas_da_cota_de_teste(a);
        MAIOR.fetch_max(da_definicao, SeqCst);
        if da_cota != da_definicao {
            DIVERGENCIAS.fetch_add(1, SeqCst);
        }
    }
    extern "C" fn lancador(_argumento: u64) -> ! {
        let ola = alloc::format!("{}/ola", crate::usuario::DIRETORIO_DOS_COMPILADOS);
        if let Some(a) = autoridade() {
            let mut vista = 0;
            while !PARAR.load(SeqCst) {
                // Cedendo, e não dormindo até o tique: as tentativas da
                // rajada saem juntas dos núcleos secundários.
                let rajada = RAJADA.load(SeqCst);
                if rajada == vista {
                    crate::fios::ceder();
                    continue;
                }
                vista = rajada;
                for _ in 0..TENTATIVAS_POR_RAJADA {
                    if PARAR.load(SeqCst) {
                        break;
                    }
                    match crate::usuario::lancar_como(Some(&ola), a) {
                        Ok(_) => LANCADOS.fetch_add(1, SeqCst),
                        Err(crate::fios::COTA_ESGOTADA) => PELA_COTA.fetch_add(1, SeqCst),
                        Err(_) => OUTRAS.fetch_add(1, SeqCst),
                    };
                    crate::fios::ceder();
                }
            }
        }
        VIVOS.fetch_sub(1, SeqCst);
        crate::fios::terminar()
    }
    extern "C" fn vigia(_argumento: u64) -> ! {
        if let Some(a) = autoridade() {
            while !PARAR.load(SeqCst) {
                olhar(a);
                OLHADAS.fetch_add(1, SeqCst);
                crate::fios::ceder();
            }
        }
        VIVOS.fetch_sub(1, SeqCst);
        crate::fios::terminar()
    }

    let secundarios: Vec<usize> = nucleos_secundarios().collect();
    if secundarios.is_empty() {
        crate::log_info!("teste", "um nucleo so: nada corre ao mesmo tempo");
        return Ok(());
    }
    if crate::fios::colheita().1 != 0 {
        return Err("a tabela ja tinha zumbi antes do caso comecar");
    }
    politica_com_a_cota(COTA)?;
    let titular = operador(0, "pessoa-da-corrida");
    crate::arch::sem_interrupcoes(|| *AUTORIDADE.lock() = Some(titular));
    for c in [&LANCADOS, &PELA_COTA, &OUTRAS, &OLHADAS, &DIVERGENCIAS] {
        c.store(0, SeqCst);
    }
    MAIOR.store(0, SeqCst);
    RAJADA.store(0, SeqCst);
    PARAR.store(false, SeqCst);
    // As vagas livres são as vazias: os mortos que os casos anteriores
    // deixaram saem antes da medida, ou a conta do fim os acharia a mais.
    super::sem_mortos_por_recolher();
    let livres_antes = crate::fios::vagas_livres_de_teste();
    let (bifurcacoes_antes, _, _) = crate::usuario::estatisticas_de_processo();
    let mut fio = None;
    let resultado = (|| -> Resultado {
        let c = Colhedor::lancar(titular)?;
        fio = Some(c.fio);
        VIVOS.store(0, SeqCst);
        for &nucleo in &secundarios {
            VIVOS.fetch_add(1, SeqCst);
            crate::fios::criar_no_nucleo("teste-lancador", lancador, 0, nucleo)?;
        }
        VIVOS.fetch_add(1, SeqCst);
        crate::fios::criar_no_nucleo("teste-vigia", vigia, 0, secundarios[0])?;
        for _ in 0..RAJADAS {
            // A rajada abre para os lançadores, e as bifurcações saem junto.
            RAJADA.fetch_add(1, SeqCst);
            // Três bifurcações e duas colheitas por rajada, sem esperar a
            // resposta de cada uma: sem a cota, sobra um zumbi a cada uma.
            for _ in 0..3 {
                Colhedor::publicar(tipo::ACAO, BIFURCAR)?;
            }
            for _ in 0..2 {
                Colhedor::publicar(tipo::ACAO, COLHER)?;
            }
            olhar(titular);
            let _ = esperar_ate(|| false, 3);
            olhar(titular);
        }
        PARAR.store(true, SeqCst);
        esperar_cedendo(|| VIVOS.load(SeqCst) == 0, 600)
            .map_err(|_| "os lancadores e o vigia nao terminaram")?;
        c.encerrar()?;
        esperar_ate(
            || crate::fios::ocupadas_de_teste(titular) == 0 && crate::fios::colheita().1 == 0,
            600,
        )
        .map_err(|_| "sobrou processo ou zumbi do titular depois do fim")?;
        let livres = esperar_ate(|| crate::fios::vagas_livres_de_teste() == livres_antes, 600);
        let (bifurcacoes, _, _) = crate::usuario::estatisticas_de_processo();
        crate::log_info!(
            "teste",
            "zumbis: cota {}; maior ocupacao {}; {} olhadas do vigia, {} com as contas \
             divergindo; {} bifurcacoes; ola: {} lancados, {} pela cota, {} por outro motivo; \
             vagas livres {} de {} antes",
            COTA,
            MAIOR.load(SeqCst),
            OLHADAS.load(SeqCst),
            DIVERGENCIAS.load(SeqCst),
            bifurcacoes - bifurcacoes_antes,
            LANCADOS.load(SeqCst),
            PELA_COTA.load(SeqCst),
            OUTRAS.load(SeqCst),
            crate::fios::vagas_livres_de_teste(),
            livres_antes
        );
        if MAIOR.load(SeqCst) > COTA as usize {
            return Err("o titular ocupou mais vagas que a cota com tudo ao mesmo tempo");
        }
        if DIVERGENCIAS.load(SeqCst) != 0 {
            return Err("a conta da cota divergiu da definicao com tudo ao mesmo tempo");
        }
        if OLHADAS.load(SeqCst) == 0 || bifurcacoes == bifurcacoes_antes {
            return Err("nada correu ao mesmo tempo: o caso nao conferiu nada");
        }
        if LANCADOS.load(SeqCst) == 0 || PELA_COTA.load(SeqCst) == 0 {
            return Err("os lancamentos nao disputaram a cota com as bifurcacoes");
        }
        livres.map_err(|_| "sobrou vaga ocupada depois do fim")
    })();
    PARAR.store(true, SeqCst);
    let _ = esperar_cedendo(|| VIVOS.load(SeqCst) == 0, 600);
    crate::arch::sem_interrupcoes(|| *AUTORIDADE.lock() = None);
    limpar(fio);
    resultado
}
