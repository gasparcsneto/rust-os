//! Os casos `vagas:` — a vaga de um processo morto só volta a um fio novo
//! depois de o coletor soltar a morte dele: a malha, os fluxos, os pedidos
//! ao enlace, as designações dos avisos e a janela de nonces.
//!
//! Antes, um fio que nascia podia ficar com a vaga de um morto ainda não
//! limpo — o filho que o pai acabou de colher, antes da passada do coletor
//! — e largava o morto sem a limpeza: o que ela soltaria ficava para
//! sempre. Foi o que a CI 445 e a 447 viram no caso `sdk: o programa de
//! fora do repositorio`: a variante seguinte ficou com a vaga do cliente do
//! modelo, e a designação do endpoint dele sobrou.
//!
//! A janela entre a morte, ou a colheita, e a passada do coletor dura no
//! máximo um tique; os casos a abrem de propósito, segurando o coletor
//! ([`ColetorSegurado`]), ou pausando-o no começo da limpeza de um processo
//! vigiado ([`PausaNaLimpeza`]). E tampam as vagas vazias de baixo
//! ([`Tampas`]): o próximo fio que nasce cai na vaga que o caso olha, se
//! ela puder ser escolhida — e na primeira vazia acima dela, se não.
//!
//! O kernel de teste de depuração do x86_64 mora perto do teto de 32 MiB
//! que o iniciador aceita, e cada fecho passado a uma função genérica vira
//! mais código e mais um nome na tabela de símbolos: estes casos esperam
//! por condições que são `fn` ([`ate`]), com uma instância só de
//! `esperar_ate`, e os do aviso passam por [`com_os_avisos`] com um `fn`.

use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::SeqCst};

use super::aviso::{Avisado, aberto, com_os_avisos, pessoa};
use super::fluxo::{BIFURCAR, COLHER, INTENCAO, Ponta, SAIDA, chamador_de, fim_gravado_com};
use super::{
    Resultado, TETO_DA_MALHA, chave_de_teste, com_mensagens, conectado, dito_na_malha,
    encerrar_na_malha, esperar_ate, fs_pedir, fs_texto, nome_de_teste, nucleos_secundarios,
    passo_na_malha, registros_depois, rodar_programa, sem_mortos_por_recolher,
};
use crate::fios::{RetratoDeTeste, retrato_de_teste};
use politica::mensagens::Canal;
use protocolo::usuario::evento::{Evento, tipo};

// ---------------------------------------------------------------------------
// As esperas, o coletor segurado, a limpeza pausada e as tampas
// ---------------------------------------------------------------------------

/// Espera `cond` até `teto` tiques; falha com `erro`. A única instância de
/// `esperar_ate` do módulo.
fn esperar(cond: &mut dyn FnMut() -> bool, teto: u64, erro: &'static str) -> Resultado {
    esperar_ate(cond, teto).map_err(|_| erro)
}

/// Espera `cond(x)` até o teto da malha; falha com `erro`.
fn ate(cond: fn(u64) -> bool, x: u64, erro: &'static str) -> Resultado {
    esperar(&mut || cond(x), TETO_DA_MALHA, erro)
}

/// Deixa passar `tiques`, atendendo os pedidos dos processos.
fn passar(tiques: u64) {
    let _ = esperar(&mut || false, tiques, "");
}

/// O fio `id` está na vaga `vaga`.
fn na_vaga(id: u64, vaga: usize) -> bool {
    matches!(retrato_de_teste(id), Some(r) if r.vaga == vaga)
}

/// O fio `id` terminou e largou o núcleo.
fn esta_parado(id: u64) -> bool {
    matches!(retrato_de_teste(id), Some(r) if r.parado)
}

/// O fio `id` saiu da tabela, e nenhum recolhimento está no meio — sem
/// marcador na tabela: o coletor tira o morto antes de soltar a morte dele,
/// e só tira o marcador depois. Sair da tabela, sozinho, não diz que a
/// limpeza acabou.
fn fora_da_tabela(id: u64) -> bool {
    retrato_de_teste(id).is_none() && crate::fios::marcadores_de_teste() == 0
}

/// A morte do primeiro vigiado foi solta uma vez.
fn limpo_uma_vez(_: u64) -> bool {
    crate::fios::limpezas_vigiadas() == 1
}

/// A morte do vigiado `id` foi solta uma vez.
fn limpo_uma_vez_o(id: u64) -> bool {
    crate::fios::limpezas_de(id) == Some(1)
}

/// Falha com `erro` se `ruim`.
fn conferir(ruim: bool, erro: &'static str) -> Resultado {
    if ruim { Err(erro) } else { Ok(()) }
}

/// O fio `id` na tabela.
fn retrato(id: u64) -> Result<RetratoDeTeste, &'static str> {
    retrato_de_teste(id).ok_or("o fio nao esta na tabela")
}

/// O fio `id` terminou e largou o núcleo.
fn parado(id: u64) -> Resultado {
    ate(esta_parado, id, "o processo nao largou o nucleo")
}

/// O coletor tirou o fio `id` da tabela, soltou a morte dele e devolveu a
/// vaga.
pub(in crate::testes) fn recolhido(id: u64) -> Resultado {
    ate(fora_da_tabela, id, "o coletor nao recolheu o morto")
}

/// O coletor segurado — nenhum morto sai da tabela, nem tem a morte solta
/// — enquanto isto vive. Solto ao sair de escopo: um caso que falha no meio
/// não deixa a suíte sem coletor.
pub(in crate::testes) struct ColetorSegurado;

impl ColetorSegurado {
    pub(in crate::testes) fn segurar() -> Self {
        crate::fios::segurar_o_coletor_de_teste();
        ColetorSegurado
    }
}

impl Drop for ColetorSegurado {
    fn drop(&mut self) {
        crate::fios::soltar_o_coletor_de_teste();
    }
}

/// A limpeza da morte do primeiro vigiado pausada no começo: o coletor que
/// chegar a ela gira até isto sair de escopo.
struct PausaNaLimpeza;

impl PausaNaLimpeza {
    fn armar() -> Self {
        crate::fios::PAUSAR_NA_LIMPEZA.store(crate::fios::PAUSA_ARMADA, SeqCst);
        PausaNaLimpeza
    }

    /// Espera um coletor tomar a pausa — ele está na limpeza do vigiado.
    fn tomada(&self) -> Resultado {
        fn tomada(_: u64) -> bool {
            crate::fios::PAUSAR_NA_LIMPEZA.load(SeqCst) == crate::fios::PAUSA_SEGURANDO
        }
        ate(tomada, 0, "o coletor nao chegou a limpeza do vigiado")
    }
}

impl Drop for PausaNaLimpeza {
    fn drop(&mut self) {
        crate::fios::PAUSAR_NA_LIMPEZA.store(0, SeqCst);
    }
}

/// Até que geração as tampas já foram soltas.
static TAMPAS_SOLTAS: AtomicU64 = AtomicU64::new(0);
/// A última geração de tampas dada.
static TAMPAS_DADAS: AtomicU64 = AtomicU64::new(0);

/// Uma tampa: segura a vaga até a geração dela ser solta, descansando — sem
/// tomar o núcleo de quem tem trabalho.
extern "C" fn tampa(geracao: u64) -> ! {
    while TAMPAS_SOLTAS.load(SeqCst) < geracao {
        crate::fios::descansar_ate_a_interrupcao();
    }
    crate::fios::terminar()
}

/// Fios do kernel que seguram vagas vazias, para o próximo fio que nasce
/// cair onde o caso olha. Soltos ao sair de escopo.
pub(in crate::testes) struct Tampas {
    geracao: u64,
}

impl Tampas {
    pub(in crate::testes) fn novas() -> Self {
        Tampas {
            geracao: TAMPAS_DADAS.fetch_add(1, SeqCst) + 1,
        }
    }

    /// Mais uma tampa: o fio e a vaga em que ele nasceu.
    fn mais_uma(&mut self) -> Result<(u64, usize), &'static str> {
        let id = crate::fios::criar("teste-tampa", tampa, self.geracao)?.numero();
        Ok((id, retrato(id)?.vaga))
    }

    /// Tampa as vagas que o próximo fio escolheria antes de `vaga`: ele vai
    /// para `vaga`, se ela puder ser escolhida, ou para uma acima dela.
    pub(in crate::testes) fn tapar_abaixo(&mut self, vaga: usize) -> Resultado {
        for _ in 0..crate::fios::MAX_FIOS {
            match crate::fios::primeira_vaga_vazia_de_teste() {
                Some(v) if v < vaga => {
                    self.mais_uma()?;
                }
                _ => return Ok(()),
            }
        }
        Err("as vagas de baixo nao se tamparam")
    }

    /// Tampa as vagas de baixo e faz nascer mais um fio: falha se ele
    /// nasceu em `vaga`.
    fn nao_nasce_em(&mut self, vaga: usize, erro: &'static str) -> Resultado {
        self.tapar_abaixo(vaga)?;
        let (_, nasceu) = self.mais_uma()?;
        conferir(nasceu == vaga, erro)
    }

    /// Faz nascer tampas até uma nascer em `vaga`: o fio que nasceu nela.
    /// Falha se a vaga não pode ser escolhida.
    fn nascer_em(&mut self, vaga: usize) -> Result<u64, &'static str> {
        for _ in 0..crate::fios::MAX_FIOS {
            match crate::fios::primeira_vaga_vazia_de_teste() {
                Some(v) if v <= vaga => {
                    let (id, nasceu) = self.mais_uma()?;
                    if nasceu == vaga {
                        return Ok(id);
                    }
                }
                _ => break,
            }
        }
        Err("a vaga do morto nao voltou depois da limpeza")
    }

    pub(in crate::testes) fn soltar(&self) {
        TAMPAS_SOLTAS.fetch_max(self.geracao, SeqCst);
    }
}

impl Drop for Tampas {
    fn drop(&mut self) {
        self.soltar();
    }
}

// ---------------------------------------------------------------------------
// O que a morte solta
// ---------------------------------------------------------------------------

/// O descritor do canal de eventos que o processo `fio` escuta — o do laço
/// dele.
fn canal_de_eventos_de(fio: u64) -> Option<u64> {
    for d in 0..64 {
        let alvo = crate::fios::com_descritores_de(fio, |t| t.alvo(d)).flatten();
        if let Some(crate::usuario::descritores::Alvo::Eventos { chave }) = alvo
            && crate::eventos::e_ouvinte(chave, fio)
        {
            return Some(d);
        }
    }
    None
}

/// Há registro de `metodo` sobre `recurso`, depois de `antes`, com o
/// detalhe que começa com `detalhe`.
fn gravado(antes: u64, metodo: &str, recurso: &str, detalhe: &str) -> bool {
    !registros_depois(antes, |e| {
        e.metodo == metodo && e.recurso == recurso && e.detalhe.starts_with(detalhe)
    })
    .is_empty()
}

/// O endpoint `endpoint` fechou com o fim de quem o abriu, depois de
/// `antes`.
fn endpoint_fechado(antes: u64, endpoint: &str) -> bool {
    gravado(
        antes,
        "fabric.withdraw",
        &format!("endpoint:{endpoint}"),
        "fechado: o processo que o abriu acabou",
    )
}

/// Espera o endpoint fechar com o fim de quem o abriu.
fn espera_o_endpoint_fechar(antes: u64, endpoint: &str) -> Resultado {
    esperar(
        &mut || endpoint_fechado(antes, endpoint),
        TETO_DA_MALHA,
        "o endpoint do morto nao fechou na limpeza",
    )
}

/// O processo `fio` ainda tem tudo o que a morte solta: designações (pelo
/// menos `designacoes`), o pedido ao enlace, e o endpoint aberto.
fn com_a_morte(fio: u64, designacoes: usize, antes: u64, endpoint: &str) -> Resultado {
    conferir(
        crate::aviso::designacoes_de_teste(fio) < designacoes
            || crate::enlace::pedidos_de_teste(Canal::Processo(fio)) != 1
            || endpoint_fechado(antes, endpoint),
        "o que a morte solta saiu sem o coletor",
    )
}

/// O processo `fio` não tem mais nada do que a morte solta: designação,
/// janela de nonces, pedido ao enlace.
fn nada_da_morte(fio: u64) -> Resultado {
    let canal = Canal::Processo(fio);
    conferir(
        crate::aviso::designacoes_de_teste(fio) != 0
            || crate::mensagens::tem_janela_de_teste(canal)
            || crate::enlace::pedidos_de_teste(canal) != 0,
        "o que a morte do processo devia soltar ficou",
    )
}

/// A morte do primeiro vigiado foi solta `n` vezes.
fn limpezas(n: u64, erro: &'static str) -> Resultado {
    let vistas = crate::fios::limpezas_vigiadas();
    if vistas != n {
        crate::log_error!("teste", "{} limpezas", vistas);
    }
    conferir(vistas != n, erro)
}

/// Os casos que mexem com a malha: os fluxos e as designações limpos antes,
/// e conferidos depois — uma instância de [`com_os_avisos`] para todos.
fn na_malha(caso: fn() -> Resultado) -> Resultado {
    let r = com_os_avisos(caso);
    crate::fios::vigiar_a_limpeza(u64::MAX);
    crate::enlace::esvaziar_de_teste();
    r
}

// ---------------------------------------------------------------------------
// vagas: o morto sem a limpeza guarda a vaga ate o coletor
// ---------------------------------------------------------------------------

/// Um processo sem pai — o de um `user.run` — com o que a morte solta: o
/// endpoint dele, oferecido com o aviso; um fluxo de outro processo até
/// ele, aceito com o aviso; e um pedido ao enlace. Com o coletor segurado,
/// ele morre: a vaga fica com ele, e tudo isso fica — um fio que nasce com
/// as vagas de baixo tampadas vai para cima dela. Solto o coletor, a morte
/// é solta uma vez — o endpoint fecha, o fluxo acaba com `o processo
/// acabou`, a designação e o pedido saem — e só então a vaga volta: o fio
/// seguinte nasce nela, sem nada do morto.
pub(super) fn vagas_o_morto_sem_a_limpeza_guarda_a_vaga() -> Resultado {
    na_malha(o_morto_sem_a_limpeza)
}

fn o_morto_sem_a_limpeza() -> Resultado {
    let (_, bia) = pessoa("bia-vagas", 331);
    let o = Avisado::lancar(bia)?;
    let r = Avisado::lancar(bia).and_then(|d| {
        let mut vivo = true;
        let r = o_morto_com(&o, &d, &mut vivo);
        let fim = if vivo { d.encerrar() } else { Ok(()) };
        r.and(fim)
    });
    let fim = o.encerrar();
    r.and(fim)
}

/// O caso, com `o` e `d` de pé; `vivo` diz se `d` ainda precisa sair.
fn o_morto_com(o: &Avisado, d: &Avisado, vivo: &mut bool) -> Resultado {
    {
        let fio = d.fio();
        let antes = crate::autorizacao::ultimo_registro();
        let (id, _) = aberto(o, d, true, true)?;
        crate::enlace::pedir_de_teste(Canal::Processo(fio)).ok_or("o pedido nao entrou")?;
        let vaga = retrato(fio)?.vaga;
        com_a_morte(fio, 2, antes, &d.endpoint)?;
        let segurado = ColetorSegurado::segurar();
        crate::fios::vigiar_a_limpeza(fio);
        d.encerrar()?;
        *vivo = false;
        parado(fio)?;

        // Morto e não limpo: a vaga é dele, e o que a morte solta, também.
        let mut tampas = Tampas::novas();
        tampas.nao_nasce_em(vaga, "um fio nasceu na vaga do morto antes da limpeza")?;
        conferir(!na_vaga(fio, vaga), "o morto saiu da vaga antes da limpeza")?;
        limpezas(0, "a morte foi solta com o coletor segurado")?;
        com_a_morte(fio, 2, antes, &d.endpoint)?;
        conferir(
            gravado(antes, "stream.end", &format!("fluxo:{id}"), ""),
            "o fluxo acabou sem o coletor",
        )?;

        // O coletor passa: a morte solta, uma vez, e a vaga de volta.
        drop(segurado);
        recolhido(fio)?;
        limpezas(1, "a morte nao foi solta uma vez")?;
        nada_da_morte(fio)?;
        espera_o_endpoint_fechar(antes, &d.endpoint)?;
        fim_gravado_com(antes, &id, "o processo acabou")?;
        let novo = tampas.nascer_em(vaga)?;
        nada_da_morte(novo)?;
        // E não de novo, nas passadas seguintes.
        passar(20);
        limpezas(1, "a morte foi solta de novo depois do recolhimento")
    }
}

// ---------------------------------------------------------------------------
// vagas: a colheita e a bifurcacao seguinte nao perdem a limpeza
// ---------------------------------------------------------------------------

/// O pai bifurca: o filho, já escutando o canal dele.
fn bifurcar(pai: &Ponta) -> Result<u64, &'static str> {
    let (desde, filho) = passo_na_malha(&pai.canal, BIFURCAR, 0, "fluxos: filho ")?;
    let filho: u64 = filho
        .trim()
        .parse()
        .map_err(|_| "o pai nao disse o filho")?;
    dito_na_malha(desde, &format!("fluxos: sou o filho {filho}"))?;
    dito_na_malha(desde, &format!("fluxos: pronto {}", pai.endpoint))?;
    Ok(filho)
}

/// Um filho com um endpoint designado no canal dele e um pedido ao
/// enlace, pronto para morrer. Devolve o filho e o endpoint.
fn filho_com_a_morte(pai: &Ponta) -> Result<(u64, alloc::string::String), &'static str> {
    let filho = bifurcar(pai)?;
    let do_filho = chamador_de(filho).ok_or("o filho nao esta vivo")?;
    let descritor = canal_de_eventos_de(filho).ok_or("o filho nao escuta canal nenhum")?;
    let r = fs_pedir(
        do_filho,
        "fabric.offer",
        &format!(r#"{{"intent":"{INTENCAO}","notify":{descritor}}}"#),
    );
    let endpoint = fs_texto(&r, "endpoint").ok_or("o filho nao ofereceu o endpoint dele")?;
    crate::enlace::pedir_de_teste(Canal::Processo(filho)).ok_or("o pedido nao entrou")?;
    Ok((filho, endpoint))
}

/// O filho sai, e espera ele largar o núcleo.
fn filho_sai(filho: u64) -> Resultado {
    encerrar_na_malha(&format!("teste-fluxos-{filho}"), SAIDA)?;
    parado(filho)
}

/// O pai colhe o filho, e o código é o dele.
fn colher(pai: &Ponta, filho: u64) -> Resultado {
    let (_, colhido) = passo_na_malha(&pai.canal, COLHER, filho as i64, "fluxos: colhi ")?;
    conferir(
        colhido != format!("{filho} {SAIDA}"),
        "o pai nao colheu o codigo de saida do filho",
    )
}

/// A corrida das CIs 445 e 447, aberta de propósito: o filho sai e fica
/// zumbi; com o coletor segurado, a morte dele não é solta; o pai o colhe —
/// ele deixa de ser zumbi, com a morte ainda devida — e bifurca de novo, com
/// as vagas de baixo tampadas. O filho novo não fica com a vaga do colhido:
/// ela é dele até o coletor passar. Solto o coletor, a morte do colhido é
/// solta uma vez, e o filho novo não tem nada do morto.
pub(super) fn vagas_a_colheita_e_a_bifurcacao_seguinte() -> Resultado {
    na_malha(a_colheita_e_a_bifurcacao)
}

fn a_colheita_e_a_bifurcacao() -> Resultado {
    let (_, bia) = pessoa("bia-vagas", 332);
    let pai = Ponta::lancar(bia)?;
    let r = (|| -> Resultado {
        let (filho, endpoint) = filho_com_a_morte(&pai)?;
        let vaga = retrato(filho)?.vaga;
        let antes = crate::autorizacao::ultimo_registro();
        let segurado = ColetorSegurado::segurar();
        crate::fios::vigiar_a_limpeza(filho);
        filho_sai(filho)?;
        conferir(
            !crate::fios::zumbi_de_teste(filho),
            "o filho que saiu nao ficou zumbi",
        )?;
        colher(&pai, filho)?;
        conferir(
            crate::fios::zumbi_de_teste(filho),
            "o colhido continuou zumbi",
        )?;
        limpezas(0, "a morte do colhido foi solta com o coletor segurado")?;
        com_a_morte(filho, 1, antes, &endpoint)?;

        // A bifurcação seguinte, com as vagas de baixo tampadas.
        let mut tampas = Tampas::novas();
        tampas.tapar_abaixo(vaga)?;
        let outro = bifurcar(&pai)?;
        conferir(
            na_vaga(outro, vaga) || !na_vaga(filho, vaga),
            "o filho seguinte ficou com a vaga do colhido antes da limpeza",
        )?;

        drop(segurado);
        recolhido(filho)?;
        limpezas(1, "a morte do colhido nao foi solta uma vez")?;
        nada_da_morte(filho)?;
        espera_o_endpoint_fechar(antes, &endpoint)?;
        nada_da_morte(outro)?;
        filho_sai(outro)?;
        colher(&pai, outro)
    })();
    let fim = pai.encerrar();
    r.and(fim)
}

// ---------------------------------------------------------------------------
// vagas: a vaga so volta depois de a limpeza terminar
// ---------------------------------------------------------------------------

/// Solta o fio de [`espera_e_sai`].
static SOLTAR_O_QUE_ESPERA: AtomicBool = AtomicBool::new(false);

/// Um fio do kernel que espera ser solto e sai.
extern "C" fn espera_e_sai(_argumento: u64) -> ! {
    while !SOLTAR_O_QUE_ESPERA.load(SeqCst) {
        crate::fios::descansar_ate_a_interrupcao();
    }
    crate::fios::terminar()
}

/// A limpeza pausada no começo, nos dois caminhos do coletor.
///
/// No recolhimento: o coletor tirou o morto da tabela, e a vaga fica com o
/// marcador até a limpeza acabar — um fio que nasce, com as vagas de baixo
/// tampadas, vai para cima dela. Solta a pausa, a vaga volta.
///
/// Na passada dos zumbis: o filho é zumbi e o coletor está soltando a
/// morte dele; o pai o colhe no meio — ele deixa de ser zumbi — e outro
/// coletor (a suíte) passa. Esse não o recolhe: a limpeza está em curso. A
/// vaga continua com ele, e a morte é solta uma vez só.
pub(super) fn vagas_a_vaga_so_volta_depois_da_limpeza() -> Resultado {
    SOLTAR_O_QUE_ESPERA.store(false, SeqCst);
    let x = crate::fios::criar("teste-vagas-espera", espera_e_sai, 0)?.numero();
    let r = (|| -> Resultado {
        let vaga = retrato(x)?.vaga;
        crate::fios::vigiar_a_limpeza(x);
        let pausa = PausaNaLimpeza::armar();
        SOLTAR_O_QUE_ESPERA.store(true, SeqCst);
        pausa.tomada()?;
        let mut tampas = Tampas::novas();
        tampas.nao_nasce_em(
            vaga,
            "a vaga voltou com a limpeza do morto pausada no recolhimento",
        )?;
        limpezas(0, "a limpeza pausada contou")?;
        drop(pausa);
        ate(limpo_uma_vez, 0, "a limpeza solta nao terminou")?;
        tampas.nascer_em(vaga).map(drop)
    })();
    SOLTAR_O_QUE_ESPERA.store(true, SeqCst);
    crate::fios::vigiar_a_limpeza(u64::MAX);
    r?;
    na_malha(a_limpeza_em_curso_na_passada_dos_zumbis)
}

fn a_limpeza_em_curso_na_passada_dos_zumbis() -> Resultado {
    let (_, bia) = pessoa("bia-vagas", 333);
    let pai = Ponta::lancar(bia)?;
    let r = (|| -> Resultado {
        let (filho, _) = filho_com_a_morte(&pai)?;
        let vaga = retrato(filho)?.vaga;
        crate::fios::vigiar_a_limpeza(filho);
        let pausa = PausaNaLimpeza::armar();
        filho_sai(filho)?;
        pausa.tomada()?;
        conferir(
            !crate::fios::zumbi_de_teste(filho) || !retrato(filho)?.limpeza_em_curso,
            "a passada dos zumbis nao estava limpando o filho",
        )?;
        colher(&pai, filho)?;
        // O outro coletor: a suíte.
        crate::fios::recolher_terminados();
        conferir(
            !na_vaga(filho, vaga),
            "outro coletor recolheu o filho com a limpeza dele em curso",
        )?;
        let mut tampas = Tampas::novas();
        tampas.nao_nasce_em(vaga, "a vaga voltou com a limpeza do zumbi em curso")?;
        limpezas(0, "a morte do zumbi foi solta duas vezes ao mesmo tempo")?;
        drop(pausa);
        recolhido(filho)?;
        // Mais passadas dos dois coletores: uma vez só.
        crate::fios::recolher_terminados();
        passar(10);
        limpezas(1, "a morte do zumbi nao foi solta uma vez")?;
        nada_da_morte(filho)?;
        tampas.nascer_em(vaga).map(drop)
    })();
    let fim = pai.encerrar();
    r.and(fim)
}

// ---------------------------------------------------------------------------
// vagas: a tabela cheia de mortos espera o coletor
// ---------------------------------------------------------------------------

/// Um fio do kernel que sai assim que roda.
extern "C" fn morre_na_hora(_argumento: u64) -> ! {
    crate::fios::terminar()
}

/// Um fio que sai na hora, vigiado: o motivo, se ele não nasceu.
fn mais_um_morto() -> Result<u64, &'static str> {
    let id = crate::fios::criar("teste-vagas-morto", morre_na_hora, 0)?.numero();
    conferir(
        !crate::fios::vigiar_tambem(id),
        "o vigia nao coube os mortos do caso",
    )?;
    Ok(id)
}

/// A recusa é a de não haver vaga.
fn sem_vaga(r: Result<u64, &'static str>) -> Resultado {
    match r {
        Ok(_) => Err("um fio nasceu na vaga de um morto antes do coletor"),
        Err(m) if m.contains("vaga") => Ok(()),
        Err(m) => {
            crate::log_error!("teste", "{}", m);
            Err("o nascimento foi recusado por outro motivo")
        }
    }
}

/// Cada vigiado: quantos tiveram a morte solta zero vezes, uma vez, e mais.
fn contar_as_limpezas() -> [usize; 3] {
    let mut contas = [0; 3];
    let mut i = 0;
    while let Some((_, n)) = crate::fios::vigiado_de_teste(i) {
        contas[n.min(2) as usize] += 1;
        i += 1;
    }
    contas
}

/// Com o coletor segurado, fios que saem na hora enchem a tabela: o
/// nascimento seguinte é recusado com o motivo de sempre — não há vaga —, e
/// continua recusado depois de todos estarem mortos. Solto o coletor, cada
/// morto tem a morte solta uma vez, as vagas voltam, e o nascimento passa.
pub(super) fn vagas_a_tabela_cheia_de_mortos_espera_o_coletor() -> Resultado {
    sem_mortos_por_recolher();
    let livres_antes = crate::fios::vagas_livres_de_teste();
    crate::fios::vigiar_a_limpeza(u64::MAX);
    let segurado = ColetorSegurado::segurar();
    let mut mortos = Vec::new();
    let mut r = Err("a tabela nao encheu: uma vaga de morto voltou antes do coletor");
    for _ in 0..2 * crate::fios::MAX_FIOS {
        match mais_um_morto() {
            Ok(id) => mortos.push(id),
            Err(m) => {
                r = sem_vaga(Err(m));
                break;
            }
        }
    }
    let r = r
        .and_then(|_| {
            for &m in &mortos {
                parado(m)?;
            }
            Ok(())
        })
        // Todos mortos, nenhum recolhido: continua sem vaga.
        .and_then(|_| sem_vaga(mais_um_morto()))
        .and_then(|_| {
            conferir(
                contar_as_limpezas()[0] != mortos.len(),
                "a morte foi solta com o coletor segurado",
            )
        });
    drop(segurado);
    crate::log_info!("teste", "vagas: {} mortos encheram a tabela", mortos.len());
    r?;
    for &m in &mortos {
        recolhido(m)?;
    }
    let contas = contar_as_limpezas();
    crate::fios::vigiar_a_limpeza(u64::MAX);
    if contas != [0, mortos.len(), 0] {
        crate::log_error!("teste", "limpezas: {:?}", contas);
        return Err("a morte de algum fio da tabela cheia nao foi solta uma vez");
    }
    crate::fios::criar("teste-vagas-morto", morre_na_hora, 0)?;
    ate(
        vagas_de_volta,
        livres_antes as u64,
        "as vagas nao voltaram todas depois do coletor",
    )
}

/// O coletor recolheu os mortos, e as vagas livres voltaram a `livres`.
fn vagas_de_volta(livres: u64) -> bool {
    sem_mortos_por_recolher();
    crate::fios::vagas_livres_de_teste() as u64 == livres
}

// ---------------------------------------------------------------------------
// vagas: o pai que morre sem colher e os zumbis seguem como antes
// ---------------------------------------------------------------------------

/// O que já era continua: a morte do zumbi sai na passada seguinte, com ele
/// ainda na vaga — o código de saída é do pai —; o pai que morre sem colher
/// solta o filho, e o coletor o recolhe sem soltar a morte de novo; e a do
/// pai, uma vez.
pub(super) fn vagas_o_pai_que_morre_sem_colher() -> Resultado {
    na_malha(o_pai_que_morre_sem_colher)
}

fn o_pai_que_morre_sem_colher() -> Resultado {
    let (_, bia) = pessoa("bia-vagas", 334);
    let pai = Ponta::lancar(bia)?;
    let do_pai = pai.fio();
    let mut pai_vivo = true;
    let r = (|| -> Resultado {
        let (filho, endpoint) = filho_com_a_morte(&pai)?;
        let antes = crate::autorizacao::ultimo_registro();
        crate::fios::vigiar_a_limpeza(filho);
        crate::fios::vigiar_tambem(do_pai);
        filho_sai(filho)?;
        ate(
            limpo_uma_vez_o,
            filho,
            "a morte do zumbi nao saiu antes da colheita",
        )?;
        conferir(
            !crate::fios::zumbi_de_teste(filho),
            "o filho deixou de ser zumbi sem colheita",
        )?;
        nada_da_morte(filho)?;
        espera_o_endpoint_fechar(antes, &endpoint)?;
        pai.encerrar()?;
        pai_vivo = false;
        recolhido(filho)?;
        recolhido(do_pai)?;
        passar(10);
        conferir(
            crate::fios::limpezas_de(filho) != Some(1)
                || crate::fios::limpezas_de(do_pai) != Some(1),
            "a morte do pai ou a do filho nao foi solta uma vez",
        )?;
        nada_da_morte(do_pai)
    })();
    let fim = if pai_vivo { pai.encerrar() } else { Ok(()) };
    r.and(fim)
}

// ---------------------------------------------------------------------------
// vagas: a janela de nonces do morto sai com a limpeza
// ---------------------------------------------------------------------------

/// O programa `nativo`, lançado com a autoridade de um agente, manda
/// mensagens com os nonces dele: a janela é do processo. Com o coletor
/// segurado, ele sai, e a janela fica com ele; solto o coletor, sai com a
/// morte, uma vez.
pub(super) fn vagas_a_janela_de_nonces_do_morto() -> Resultado {
    com_mensagens(a_janela_de_nonces_do_morto)
}

fn a_janela_de_nonces_do_morto() -> Resultado {
    let (_agente, _sessao) = conectado(1)?;
    crate::identidade::atribuir(&nome_de_teste(1), "operador")
        .map_err(|_| "a atribuicao falhou")?;
    let autoridade = crate::autorizacao::Autoridade::Sessao {
        sessao: 1,
        chave: Some(sigilo::publica_de(&chave_de_teste(1))),
    };
    let segurado = ColetorSegurado::segurar();
    let r = rodar_programa("nativo", Some(autoridade), 74).and_then(|fio| {
        crate::fios::vigiar_a_limpeza(fio);
        parado(fio)?;
        conferir(
            !crate::mensagens::tem_janela_de_teste(Canal::Processo(fio)),
            "o morto nao guardou a janela ate o coletor",
        )?;
        limpezas(0, "a morte foi solta com o coletor segurado")?;
        Ok(fio)
    });
    drop(segurado);
    let fio = r?;
    let r = recolhido(fio)
        .and_then(|_| limpezas(1, "a morte do programa nao foi solta uma vez"))
        .and_then(|_| nada_da_morte(fio));
    crate::fios::vigiar_a_limpeza(u64::MAX);
    r
}

// ---------------------------------------------------------------------------
// vagas: termino, colheita, coleta e nascimento ao mesmo tempo
// ---------------------------------------------------------------------------

/// O canal do `colhedor` e os passos dele (`programas/src/bin/colhedor.rs`).
const CANAL_DO_COLHEDOR: &str = "teste-colhedor";
const COLHEDOR_BIFURCA: i64 = 1;
const COLHEDOR_COLHE: i64 = 2;

/// Quantas vítimas cada lançador faz nascer, no máximo.
const VITIMAS_POR_LANCADOR: u64 = 120;

static PARAR: AtomicBool = AtomicBool::new(false);
static VIVOS: AtomicUsize = AtomicUsize::new(0);
static NASCIDAS: AtomicU64 = AtomicU64::new(0);
static SEM_VAGA: AtomicU64 = AtomicU64::new(0);
static OUTRAS_RECUSAS: AtomicU64 = AtomicU64::new(0);
static FORA_DO_VIGIA: AtomicU64 = AtomicU64::new(0);
static PASSADAS: AtomicU64 = AtomicU64::new(0);

/// Uma vítima: se vigia, pede ao enlace — o que a morte dela tem de soltar
/// — e sai.
extern "C" fn vitima(_argumento: u64) -> ! {
    let eu = crate::fios::id_atual();
    if crate::fios::vigiar_tambem(eu) {
        let _ = crate::enlace::pedir_de_teste(Canal::Processo(eu));
    } else {
        FORA_DO_VIGIA.fetch_add(1, SeqCst);
    }
    crate::fios::terminar()
}

/// Faz nascer vítimas até mandarem parar, ou até o teto dele.
extern "C" fn lancador(_argumento: u64) -> ! {
    let mut feitas = 0;
    while !PARAR.load(SeqCst) && feitas < VITIMAS_POR_LANCADOR {
        match crate::fios::criar("teste-vagas-vitima", vitima, 0) {
            Ok(_) => {
                NASCIDAS.fetch_add(1, SeqCst);
                feitas += 1;
            }
            Err(m) if m.contains("vaga") => {
                SEM_VAGA.fetch_add(1, SeqCst);
            }
            Err(_) => {
                OUTRAS_RECUSAS.fetch_add(1, SeqCst);
            }
        }
        crate::fios::ceder();
    }
    VIVOS.fetch_sub(1, SeqCst);
    crate::fios::terminar()
}

/// O segundo coletor: recolhe ao mesmo tempo que o do kernel.
extern "C" fn outro_coletor(_argumento: u64) -> ! {
    while !PARAR.load(SeqCst) {
        crate::fios::recolher_terminados();
        PASSADAS.fetch_add(1, SeqCst);
        crate::fios::descansar_ate_a_interrupcao();
    }
    VIVOS.fetch_sub(1, SeqCst);
    crate::fios::terminar()
}

/// Um passo ao `colhedor`, sem esperar o que ele diz — insistindo
/// enquanto a fila dele estiver cheia.
fn ao_colhedor(tipo: u32, a: i64) -> Resultado {
    let evento = Evento {
        tipo,
        a,
        ..Default::default()
    };
    esperar(
        &mut || crate::eventos::publicar(CANAL_DO_COLHEDOR, evento).is_ok(),
        TETO_DA_MALHA,
        "o canal do colhedor nao recebeu o passo",
    )
}

/// O colhedor disse que está pronto desde `desde`.
fn colhedor_pronto(desde: u64) -> bool {
    super::linhas_do_programa(desde, "colhedor: pronto") >= 1
}

/// Os lançadores e o outro coletor terminaram.
fn todos_parados(_: u64) -> bool {
    VIVOS.load(SeqCst) == 0
}

/// O fio `id` não vive mais.
fn morto(id: u64) -> bool {
    !crate::fios::vivo(id)
}

/// Nenhum zumbi na tabela.
fn sem_zumbis(_: u64) -> bool {
    crate::fios::colheita().1 == 0
}

/// Tudo ao mesmo tempo, em vários núcleos: lançadores fazem nascer vítimas
/// que pedem ao enlace e saem; o `colhedor` bifurca filhos que saem na hora
/// e colhe parte deles; o coletor do kernel e um segundo coletor recolhem.
/// No fim, cada vítima teve a morte solta uma vez — nenhuma perdida,
/// nenhuma em dobro —, nenhum pedido dela ficou, nenhum zumbi ficou, e as
/// vagas voltaram todas.
pub(super) fn vagas_tudo_ao_mesmo_tempo() -> Resultado {
    let secundarios: Vec<usize> = nucleos_secundarios().collect();
    if secundarios.is_empty() {
        crate::log_info!("teste", "um nucleo so: nada corre ao mesmo tempo");
        return Ok(());
    }
    conferir(
        crate::fios::colheita().1 != 0,
        "a tabela ja tinha zumbi antes do caso comecar",
    )?;
    sem_mortos_por_recolher();
    let livres_antes = crate::fios::vagas_livres_de_teste();
    crate::fios::vigiar_a_limpeza(u64::MAX);
    for c in [
        &NASCIDAS,
        &SEM_VAGA,
        &OUTRAS_RECUSAS,
        &FORA_DO_VIGIA,
        &PASSADAS,
    ] {
        c.store(0, SeqCst);
    }
    PARAR.store(false, SeqCst);
    VIVOS.store(0, SeqCst);
    let desde = crate::log::total_emitidos();
    let programa = format!("{}/colhedor", crate::usuario::DIRETORIO_DOS_COMPILADOS);
    let colhedor = crate::usuario::lancar(Some(&programa))?;
    let mut r = ate(colhedor_pronto, desde, "o colhedor nao ficou pronto");
    if r.is_ok() {
        for &nucleo in &secundarios {
            VIVOS.fetch_add(1, SeqCst);
            if crate::fios::criar_no_nucleo("teste-vagas-lancador", lancador, 0, nucleo).is_err() {
                VIVOS.fetch_sub(1, SeqCst);
            }
        }
        VIVOS.fetch_add(1, SeqCst);
        if crate::fios::criar_no_nucleo("teste-vagas-coletor", outro_coletor, 0, secundarios[0])
            .is_err()
        {
            VIVOS.fetch_sub(1, SeqCst);
        }
        for _ in 0..20 {
            for a in [
                COLHEDOR_BIFURCA,
                COLHEDOR_BIFURCA,
                COLHEDOR_BIFURCA,
                COLHEDOR_COLHE,
                COLHEDOR_COLHE,
            ] {
                r = r.and(ao_colhedor(tipo::ACAO, a));
            }
            passar(3);
        }
    }
    PARAR.store(true, SeqCst);
    r = r.and(ate(
        todos_parados,
        0,
        "os lancadores e o outro coletor nao terminaram",
    ));
    let encerrou = ao_colhedor(tipo::ENCERRAR, 0);
    r.and(encerrou)?;
    ate(morto, colhedor, "o colhedor nao saiu")?;
    ate(sem_zumbis, 0, "sobrou zumbi depois do fim")?;
    let (mut vigiadas, mut com_pedido) = (0usize, 0usize);
    while let Some((id, _)) = crate::fios::vigiado_de_teste(vigiadas) {
        recolhido(id)?;
        com_pedido += (crate::enlace::pedidos_de_teste(Canal::Processo(id)) != 0) as usize;
        vigiadas += 1;
    }
    let contas = contar_as_limpezas();
    crate::fios::vigiar_a_limpeza(u64::MAX);
    crate::enlace::esvaziar_de_teste();
    crate::log_info!(
        "teste",
        "vagas: {} vitimas, {} vigiadas, {} sem vaga; {} passadas do outro coletor; mortes \
         soltas 0/1/mais vezes: {:?}; {} com pedido",
        NASCIDAS.load(SeqCst),
        vigiadas,
        SEM_VAGA.load(SeqCst),
        PASSADAS.load(SeqCst),
        contas,
        com_pedido
    );
    conferir(
        contas[0] != 0,
        "a morte de uma vitima nao foi solta: a limpeza se perdeu",
    )?;
    conferir(
        contas[2] != 0,
        "a morte de uma vitima foi solta mais de uma vez",
    )?;
    conferir(
        com_pedido != 0,
        "um pedido de uma vitima ao enlace ficou depois da limpeza",
    )?;
    conferir(
        vigiadas == 0 || PASSADAS.load(SeqCst) == 0,
        "nada correu ao mesmo tempo: o caso nao conferiu nada",
    )?;
    conferir(
        OUTRAS_RECUSAS.load(SeqCst) + FORA_DO_VIGIA.load(SeqCst) != 0,
        "um nascimento foi recusado por outro motivo, ou uma vitima ficou fora do vigia",
    )?;
    ate(
        vagas_de_volta,
        livres_antes as u64,
        "sobrou vaga ocupada depois do fim",
    )
}
