//! A persistência: o journal na partição de estado, ancorado no TPM.
//!
//! # O que este módulo garante
//!
//! Que uma mudança no estado de autoridade — um agente registrado ou
//! revogado, um papel atribuído, a política escrita, uma pessoa registrada,
//! revogada ou com a credencial trocada, uma sessão encerrada, uma
//! credencial administrativa revogada por quórum — sobrevive a um boot, e
//! que um disco devolvido a uma cópia anterior não faz o sistema voltar a
//! antes dela. Em particular: uma credencial administrativa revogada não
//! reaparece válida depois de uma reinicialização. Ver
//! `docs/PERSISTENCIA.md`, requisitos R1 a R6.
//!
//! # As peças
//!
//! - O formato e as regras do journal são do pacote `diario`, testado no
//!   hospedeiro.
//! - O contador monotônico do TPM é do pacote `ancora`; o transporte até o
//!   chip é [`crate::tpm`].
//! - A escrita no disco é [`crate::virtio::blk`], restrita à janela da
//!   partição de estado — e este é o **único** módulo que a chama: a
//!   conferência de invariantes do `xtask` recusa qualquer outro.
//!
//! # Gravar antes de responder
//!
//! Uma operação que muda autoridade passa por aqui duas vezes: antes, para
//! saber se há persistência confiável (sem ela a operação é recusada, sem
//! exceção para o `sistema`); depois, para gravar o que ela mudou. A
//! gravação é: montar o registro, escrevê-lo, descarregar o disco, avançar
//! o contador do TPM. Só então a operação responde. Se a gravação falhar,
//! a mudança que concedia algo é desfeita; a que tirava algo fica — nunca
//! se fica mais fraco do que o pedido — e a persistência passa a
//! indisponível, o que bloqueia as próximas.
//!
//! # O boot
//!
//! [`abrir`] roda depois de o registro da imagem, a política e as pessoas
//! carregarem, e **antes** de as portas abrirem e de o primeiro desafio
//! administrativo existir. Ela lê o journal, julga contra o contador do
//! TPM, e reaplica cada registro autêntico — mesmo quando o julgamento
//! recusa o journal: o que ele diz é mais recente que a imagem, e uma
//! lápide lida é uma credencial a menos. Recusado, o journal deixa a
//! administração bloqueada até alguém resolver por fora.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use diario::estado::{self, tipo};
use diario::{Conteudo, Escritor, Meio, Relogio, Veredito};
use spin::Mutex;

/// O índice de NV do contador da âncora, na faixa que a especificação do
/// TCG reserva para o dono do TPM.
pub const INDICE_DA_ANCORA: u32 = 0x0180_D0E0;

/// O que a persistência é agora.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Estado {
    /// Ainda não aberta: o boot não chegou lá.
    Fechada,
    /// O journal é o atual, e uma gravação é possível.
    Disponivel,
    /// Não há como gravar com confiança: sem disco durável, sem TPM, sem a
    /// chave do Duke, ou uma gravação que falhou. As operações de
    /// autoridade ficam bloqueadas.
    Indisponivel(&'static str),
    /// O journal não confere com a âncora: o disco é anterior ao que o TPM
    /// já viu, ou o TPM não é o deste disco. As operações de autoridade
    /// ficam bloqueadas, e o que o journal disse foi reaplicado.
    Recusada(&'static str),
}

impl Estado {
    pub fn como_str(&self) -> &'static str {
        match self {
            Estado::Fechada => "closed",
            Estado::Disponivel => "available",
            Estado::Indisponivel(_) => "unavailable",
            Estado::Recusada(_) => "refused",
        }
    }

    pub fn motivo(&self) -> &'static str {
        match self {
            Estado::Fechada => "a persistencia ainda nao foi aberta",
            Estado::Disponivel => "",
            Estado::Indisponivel(m) | Estado::Recusada(m) => m,
        }
    }
}

/// O que a persistência guarda entre uma gravação e outra.
struct Aberta {
    escritor: Escritor,
    ancora: ancora::Ancora,
    chave: [u8; 32],
}

struct Persistencia {
    estado: Estado,
    aberta: Option<Aberta>,
    /// A geração administrativa: sobe a cada mudança de autoridade.
    geracao: u64,
    /// Quantos registros o journal tem.
    registros: u64,
    /// Quantos boots o journal contou, este incluído.
    boots: u64,
    relogio: Relogio,
}

static PERSISTENCIA: Mutex<Persistencia> = Mutex::new(Persistencia {
    estado: Estado::Fechada,
    aberta: None,
    geracao: 0,
    registros: 0,
    boots: 0,
    relogio: Relogio::novo(0),
});

/// Uma gravação de cada vez: o registro seguinte depende do anterior, e o
/// contador do TPM também. A tranca de [`PERSISTENCIA`] é mantida só
/// enquanto se lê e se troca o estado; esta é a que serializa uma gravação
/// inteira, com o disco e o TPM no meio.
static GRAVANDO: AtomicBool = AtomicBool::new(false);

/// Só na suíte: a próxima gravação falha antes de tocar o disco, como se o
/// disco ou o TPM tivessem recusado.
#[cfg(feature = "modo-teste")]
static FALHAR_A_PROXIMA: AtomicBool = AtomicBool::new(false);

fn com<R>(f: impl FnOnce(&mut Persistencia) -> R) -> R {
    crate::arch::sem_interrupcoes(|| f(&mut PERSISTENCIA.lock()))
}

/// O estado da persistência.
pub fn estado() -> Estado {
    com(|p| p.estado)
}

/// A geração administrativa em vigor.
pub fn geracao() -> u64 {
    com(|p| p.geracao)
}

/// O relatório para o `system.info`: estado, motivo, geração, âncora,
/// registros e boots.
pub fn relatorio() -> (Estado, u64, Option<u64>, u64, u64) {
    com(|p| {
        (
            p.estado,
            p.geracao,
            p.aberta.as_ref().map(|a| a.escritor.ancora()),
            p.registros,
            p.boots,
        )
    })
}

/// O tempo lógico: o RTC com o piso do journal — nunca volta.
pub fn agora() -> u64 {
    let rtc = crate::relogio::agora();
    com(|p| p.relogio.agora(rtc))
}

/// A partição de estado como meio do journal: setores relativos ao começo
/// dela, em pedidos que cabem numa ida ao disco.
struct Particao {
    primeiro: u64,
    setores: u64,
}

impl Meio for Particao {
    fn setores(&self) -> u64 {
        self.setores
    }

    fn ler(&mut self, setor: u64, destino: &mut [u8]) -> Result<(), &'static str> {
        let mut feito = 0;
        while feito < destino.len() {
            let n = (destino.len() - feito).min(crate::virtio::blk::MAIOR_LEITURA);
            let s = self.primeiro + setor + (feito / diario::TAM_SETOR) as u64;
            crate::virtio::blk::com_o_disco(|d| d.ler(s, &mut destino[feito..feito + n]))
                .ok_or("nao ha disco")??;
            feito += n;
        }
        Ok(())
    }

    fn escrever(&mut self, setor: u64, origem: &[u8]) -> Result<(), &'static str> {
        let mut feito = 0;
        while feito < origem.len() {
            let n = (origem.len() - feito).min(crate::virtio::blk::MAIOR_LEITURA);
            let s = self.primeiro + setor + (feito / diario::TAM_SETOR) as u64;
            crate::virtio::blk::com_o_disco(|d| d.gravar_setores(s, &origem[feito..feito + n]))
                .ok_or("nao ha disco")??;
            feito += n;
        }
        Ok(())
    }

    fn descarregar(&mut self) -> Result<(), &'static str> {
        crate::virtio::blk::com_o_disco(|d| d.descarregar_disco()).ok_or("nao ha disco")?
    }
}

/// A partição de estado: a janela de escrita que o boot fixou. Para ler
/// basta ela; para gravar, ver [`particao`].
fn janela() -> Result<Particao, &'static str> {
    let (primeiro, setores) =
        crate::virtio::blk::com_o_disco(|d| d.janela().unwrap_or((0, 0))).ok_or("nao ha disco")?;
    if setores == 0 {
        return Err("nao ha particao de estado");
    }
    Ok(Particao { primeiro, setores })
}

/// Se uma escrita no disco pode ser tornada durável.
fn duravel() -> Result<(), &'static str> {
    if crate::virtio::blk::com_o_disco(|d| d.duravel()).unwrap_or(false) {
        Ok(())
    } else {
        Err("o disco nao aceita descarga: nenhuma escrita seria duravel")
    }
}

/// A partição de estado, para gravar: a janela, num disco durável.
fn particao() -> Result<Particao, &'static str> {
    duravel()?;
    janela()
}

/// A chave do journal e a senha da âncora, derivadas da chave do Duke.
///
/// Duas derivações com rótulos diferentes: a chave que cifra o journal não
/// é a senha que vai pelo barramento até o TPM, e saber uma não dá a outra.
fn segredos() -> Option<([u8; 32], [u8; 32])> {
    crate::identidade::com_chave_do_duke(|k| {
        let sal = b"Duke persistencia v1";
        (
            sigilo::resumo::hkdf_rfc5869(sal, k, &[b"journal: cifra"]),
            sigilo::resumo::hkdf_rfc5869(sal, k, &[b"ancora: senha do contador"]),
        )
    })
}

/// Um nonce sorteado para um registro.
fn nonce() -> Result<[u8; diario::TAM_NONCE], &'static str> {
    let mut n = [0u8; diario::TAM_NONCE];
    crate::aleatorio::preencher(&mut n).map_err(|_| "sem entropia para o nonce")?;
    Ok(n)
}

/// Abre a persistência, no boot. Ver o cabeçalho do módulo.
pub fn abrir() {
    let estado = match abrir_de_fato() {
        Ok(e) => e,
        Err(motivo) => Estado::Indisponivel(motivo),
    };
    com(|p| p.estado = estado);
    match estado {
        Estado::Disponivel => {
            let (_, g, a, r, b) = relatorio();
            crate::log_info!(
                "persistencia",
                "journal aberto: {} registros, geracao {}, ancora {}, boot {}",
                r,
                g,
                a.unwrap_or(0),
                b
            );
        }
        outro => crate::log_error!(
            "persistencia",
            "{}: {} — as operacoes que mudam autoridade ficam bloqueadas",
            outro.como_str(),
            outro.motivo()
        ),
    }
}

fn abrir_de_fato() -> Result<Estado, &'static str> {
    let (chave, senha) = segredos().ok_or("sem a chave do Duke")?;
    let mut meio = janela()?;

    // O journal é lido e reaplicado antes de qualquer outra conferência, e
    // vale mesmo que a persistência acabe indisponível ou recusada: o que
    // ele diz é mais recente que a imagem, e uma lápide lida é uma
    // credencial a menos. Ler não precisa de descarga nem de TPM.
    let lido = diario::ler(&mut meio, &chave)?;
    if let diario::Parada::Ilegivel { setor, motivo } = lido.parada {
        crate::log_warn!(
            "persistencia",
            "a leitura parou no setor {} da particao: {}",
            setor,
            motivo
        );
    }
    for r in &lido.registros {
        if let Err(motivo) = reaplicar(r) {
            crate::log_error!(
                "persistencia",
                "o registro {} nao se reaplica: {}",
                r.sequencia,
                motivo
            );
            return Ok(Estado::Recusada(
                "um registro autentico do journal nao se reaplica",
            ));
        }
    }
    if let Some(ultimo) = lido.registros.last() {
        crate::autorizacao::fixar_versao_da_politica(ultimo.versao_da_politica);
        com(|p| {
            p.geracao = ultimo.geracao;
            p.relogio = Relogio::novo(ultimo.tempo);
        });
    }
    let boots = lido
        .registros
        .iter()
        .rev()
        .find(|r| r.tipo == tipo::BOOT)
        .and_then(|r| estado::exatamente::<1>(&r.conteudo).ok())
        .and_then(|[b]| b.try_into().ok().map(u64::from_le_bytes))
        .unwrap_or(0);
    com(|p| {
        p.registros = lido.registros.len() as u64;
        p.boots = boots;
    });

    // Agora, se dá para gravar: um disco durável e a âncora.
    duravel()?;
    if !crate::tpm::presente() {
        return Err("sem TPM: nao ha ancora contra um disco restaurado");
    }
    let aberta = crate::tpm::com_o_tpm(|t| ancora::Ancora::abrir(t, INDICE_DA_ANCORA, senha))
        .ok_or("sem TPM")?;
    let (ancora, valor) = match aberta {
        Ok(ancora::Aberta::Presente(a, v)) => (Some(a), Some(v)),
        Ok(ancora::Aberta::Ausente) => (None, None),
        Err(e) => return Ok(Estado::Recusada(e.motivo())),
    };

    let total = meio.setores();
    let (ancora, valor) = match diario::julgar(lido.ultima_ancora(), valor) {
        Veredito::Recusado(r) => return Ok(Estado::Recusada(r.motivo())),
        Veredito::Confere => (ancora.ok_or("ancora sumiu")?, valor.ok_or("ancora sumiu")?),
        Veredito::Completar => {
            let a = ancora.ok_or("ancora sumiu")?;
            let novo = crate::tpm::com_o_tpm(|t| a.avancar(t))
                .ok_or("sem TPM")?
                .map_err(|e| e.motivo())?;
            if Some(novo) != lido.ultima_ancora() {
                return Ok(Estado::Recusada(
                    "a ancora nao chegou ao ultimo registro ao completar o avanco",
                ));
            }
            crate::log_warn!(
                "persistencia",
                "o ultimo registro estava gravado e a ancora nao: avanco completado"
            );
            (a, novo)
        }
        Veredito::Novo => {
            let (a, v) =
                crate::tpm::com_o_tpm(|t| ancora::Ancora::criar(t, INDICE_DA_ANCORA, &[], senha))
                    .ok_or("sem TPM")?
                    .map_err(|e| e.motivo())?;
            crate::log_info!("persistencia", "ancora criada no TPM, em {}", v);
            (a, v)
        }
    };
    let escritor = Escritor::continuar(&lido, valor, total);
    let novo = escritor.ancora() == valor && lido.registros.is_empty();
    com(|p| {
        p.aberta = Some(Aberta {
            escritor,
            ancora,
            chave,
        });
        p.estado = Estado::Disponivel;
    });
    if novo {
        let mut instalacao = [0u8; 16];
        crate::aleatorio::preencher(&mut instalacao).map_err(|_| "sem entropia")?;
        gravar(tipo::ABERTURA, &estado::campos(&[&instalacao])?)?;
    }
    gravar(tipo::BOOT, &estado::campos(&[&(boots + 1).to_le_bytes()])?)?;
    com(|p| p.boots = boots + 1);
    Ok(Estado::Disponivel)
}

/// Grava um registro, pelo protocolo inteiro: montar, escrever,
/// descarregar, avançar o contador, confirmar. A geração que ele leva quem
/// dá é o journal, pelo tipo: um registro de operação sobe um.
///
/// Uma falha em qualquer passo deixa a persistência indisponível: o que
/// está no disco e o que o TPM diz podem ter ficado a um passo um do outro,
/// e só o próximo boot, pelo julgamento, sabe resolver isso com segurança.
fn gravar(tipo_do_registro: u16, dados: &[u8]) -> Result<(), &'static str> {
    if GRAVANDO.swap(true, Ordering::Acquire) {
        return Err("uma gravacao ja esta em curso");
    }
    let resultado = gravar_sozinho(tipo_do_registro, dados);
    GRAVANDO.store(false, Ordering::Release);
    if let Err(motivo) = resultado {
        com(|p| p.estado = Estado::Indisponivel("uma gravacao no journal falhou"));
        crate::log_error!("persistencia", "a gravacao falhou: {}", motivo);
    }
    resultado
}

fn gravar_sozinho(
    tipo_do_registro: u16,
    dados: &[u8],
) -> Result<(), &'static str> {
    let tempo = agora();
    let versao = crate::autorizacao::versao_da_politica();
    let n = nonce()?;
    let montado = com(|p| {
        if p.estado != Estado::Disponivel {
            return Err(p.estado.motivo());
        }
        let a = p.aberta.as_ref().ok_or("a persistencia nao esta aberta")?;
        a.escritor.montar(
            &a.chave,
            n,
            &Conteudo {
                tipo: tipo_do_registro,
                versao_da_politica: versao,
                tempo,
                dados,
            },
        )
    })?;
    #[cfg(feature = "modo-teste")]
    if FALHAR_A_PROXIMA.swap(false, Ordering::AcqRel) {
        return Err("falha de gravacao provocada pela suite");
    }
    let mut meio = particao()?;
    meio.escrever(montado.setor, &montado.bytes)?;
    meio.descarregar()?;
    // Só depois de descarregado o contador anda: um contador à frente do
    // disco seria um disco que parece velho no próximo boot.
    let avancado = crate::tpm::com_o_tpm(|t| {
        com(|p| p.aberta.as_ref().map(|a| a.ancora.avancar(t)))
            .ok_or(ancora::Erro::Transporte("a persistencia nao esta aberta"))?
    })
    .ok_or("sem TPM")?
    .map_err(|e| e.motivo())?;
    if avancado != montado.ancora {
        return Err("o contador do TPM nao foi para a ancora do registro");
    }
    com(|p| {
        if let Some(a) = p.aberta.as_mut() {
            a.escritor.confirmar(&montado);
        }
        p.geracao = montado.geracao;
        p.registros += 1;
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// As operações de autoridade
// ---------------------------------------------------------------------------

/// Uma operação de autoridade pode começar? Só com a persistência
/// disponível. Não há exceção: nem para o `sistema`, nem para a serial.
pub fn exigir() -> Result<(), &'static str> {
    match estado() {
        Estado::Disponivel => Ok(()),
        outro => Err(outro.motivo()),
    }
}

/// O estado de autoridade antes de uma operação: o que ela pode mudar, para
/// gravar a diferença — e desfazer, se a gravação falhar.
pub struct Foto {
    agentes: Vec<crate::identidade::Agente>,
    revogados: Vec<[u8; 32]>,
    politica: String,
    pessoas: Vec<sigilo::pessoas::Pessoa>,
}

impl Foto {
    pub fn tirar() -> Foto {
        Foto {
            agentes: crate::identidade::agentes(),
            revogados: crate::identidade::administradores_revogados(),
            politica: crate::autorizacao::com_politica(|p| p.texto()),
            pessoas: crate::pessoas::todas(),
        }
    }

    /// Volta o estado de autoridade ao da foto: o que a operação concedeu
    /// sai. Só para operações que concedem — ver [`concluir`]: numa que
    /// tira, a foto teria de volta o que foi tirado.
    fn restaurar_concessoes(&self) {
        crate::identidade::restaurar_agentes(&self.agentes);
        if let Ok(p) = politica::arquivo::Politica::ler(&self.politica) {
            crate::autorizacao::restaurar_politica(p);
        }
        crate::pessoas::restaurar(&self.pessoas);
    }
}

/// Grava o que uma operação de autoridade mudou, comparando com a foto de
/// antes dela. `nome` é a operação e `recurso` o que ela disse ter
/// alcançado — vão juntos, para o journal contar o que houve mesmo quando
/// a mudança não deixa rastro no estado (o encerramento de uma sessão).
///
/// Se a gravação falha, o que a operação **concedeu** é desfeito — um
/// agente registrado sai, a política volta — e o que ela **tirou** fica:
/// uma revogação que não ficou gravada continua valendo até o boot, e a
/// persistência indisponível impede que qualquer outra coisa mude até lá.
pub fn concluir(
    foto: &Foto,
    nome: &str,
    recurso: &str,
    desfazer: bool,
) -> Result<(), &'static str> {
    let entradas = diferenca(foto, nome, recurso)?;
    let conteudo = estado::campos(&entradas.iter().map(Vec::as_slice).collect::<Vec<_>>())?;
    match gravar(tipo::OPERACAO, &conteudo) {
        Ok(()) => Ok(()),
        Err(motivo) => {
            if desfazer {
                foto.restaurar_concessoes();
            }
            Err(motivo)
        }
    }
}

/// Uma entrada do registro de uma operação: o tipo e os campos.
fn entrada(t: u16, campos: &[&[u8]]) -> Result<Vec<u8>, &'static str> {
    let mut todos: Vec<&[u8]> = Vec::with_capacity(campos.len() + 1);
    let t = t.to_le_bytes();
    todos.push(&t);
    todos.extend_from_slice(campos);
    estado::campos(&todos)
}

/// O que mudou entre a foto e agora, como entradas do registro.
fn diferenca(foto: &Foto, nome: &str, recurso: &str) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut v = Vec::new();
    v.push(entrada(
        tipo::OPERACAO,
        &[nome.as_bytes(), recurso.as_bytes()],
    )?);

    let agora = crate::identidade::agentes();
    for a in &agora {
        match foto.agentes.iter().find(|b| b.chave == a.chave) {
            None => {
                let linha = sigilo::registro::linha(&a.chave, &a.nome, a.papel.as_deref());
                v.push(entrada(tipo::AGENTE_REGISTRADO, &[linha.as_bytes()])?);
            }
            Some(b) if b.papel != a.papel => {
                let papel = a.papel.as_deref().unwrap_or("");
                v.push(entrada(
                    tipo::PAPEL_ATRIBUIDO,
                    &[a.nome.as_bytes(), papel.as_bytes()],
                )?);
            }
            Some(_) => {}
        }
    }
    for b in &foto.agentes {
        if !agora.iter().any(|a| a.chave == b.chave) {
            v.push(entrada(tipo::AGENTE_REVOGADO, &[&b.chave])?);
        }
    }

    for chave in crate::identidade::administradores_revogados() {
        if !foto.revogados.contains(&chave) {
            let assinatura = crate::identidade::assinatura_do_administrador(&chave);
            v.push(entrada(
                tipo::LAPIDE,
                &[&chave, assinatura.as_ref().map_or(&[][..], |a| &a[..])],
            )?);
        }
    }

    let politica = crate::autorizacao::com_politica(|p| p.texto());
    if politica != foto.politica {
        v.push(entrada(tipo::POLITICA, &[politica.as_bytes()])?);
    }

    for p in crate::pessoas::todas() {
        match foto.pessoas.iter().find(|q| q.id == p.id) {
            None => {
                let linha = sigilo::pessoas::linha(&p);
                v.push(entrada(tipo::PESSOA_REGISTRADA, &[linha.as_bytes()])?);
            }
            Some(q) if q.estado != p.estado && p.estado == sigilo::pessoas::Estado::Revogada => {
                v.push(entrada(tipo::PESSOA_REVOGADA, &[&p.id.0])?);
            }
            Some(q) if q.credencial != p.credencial => {
                let linha = sigilo::pessoas::linha(&p);
                v.push(entrada(tipo::CREDENCIAL_ROTACIONADA, &[linha.as_bytes()])?);
            }
            Some(_) => {}
        }
    }
    Ok(v)
}

/// Reaplica um registro lido do journal, no boot.
fn reaplicar(r: &diario::Registro) -> Result<(), &'static str> {
    match r.tipo {
        tipo::ABERTURA | tipo::BOOT => Ok(()),
        tipo::OPERACAO => {
            for e in estado::ler_campos(&r.conteudo)? {
                reaplicar_entrada(e)?;
            }
            Ok(())
        }
        _ => Err("tipo de registro desconhecido"),
    }
}

fn texto(b: &[u8]) -> Result<&str, &'static str> {
    core::str::from_utf8(b).map_err(|_| "campo que nao e texto")
}

fn chave(b: &[u8]) -> Result<[u8; 32], &'static str> {
    b.try_into().map_err(|_| "chave que nao tem 32 bytes")
}

/// Reaplica uma entrada de um registro de operação.
pub(crate) fn reaplicar_entrada(e: &[u8]) -> Result<(), &'static str> {
    let campos = estado::ler_campos(e)?;
    let (t, resto) = campos.split_first().ok_or("entrada vazia")?;
    let t: [u8; 2] = (*t).try_into().map_err(|_| "tipo de entrada invalido")?;
    match (u16::from_le_bytes(t), resto) {
        (tipo::OPERACAO, [_nome, _recurso]) => Ok(()),
        (tipo::AGENTE_REGISTRADO, [linha]) => {
            let linha = texto(linha)?;
            let (k, nome, papel) = match sigilo::registro::ler_linha(linha) {
                Ok(Some(entrada)) => entrada,
                _ => return Err("linha de agente gravada que nao se le"),
            };
            crate::identidade::restaurar_agente(k, nome, papel);
            Ok(())
        }
        (tipo::AGENTE_REVOGADO, [k]) => {
            // Um agente que a imagem já não traz não é erro: a revogação
            // dele já vale.
            let _ = crate::identidade::revogar(&chave(k)?);
            Ok(())
        }
        (tipo::PAPEL_ATRIBUIDO, [nome, papel]) => {
            let _ = crate::identidade::atribuir(texto(nome)?, texto(papel)?);
            Ok(())
        }
        (tipo::POLITICA, [t]) => {
            let p = politica::arquivo::Politica::ler(texto(t)?)
                .map_err(|_| "a politica gravada nao vale")?;
            crate::autorizacao::restaurar_politica(p);
            Ok(())
        }
        (tipo::PESSOA_REGISTRADA | tipo::CREDENCIAL_ROTACIONADA, [linha]) => {
            let p = match sigilo::pessoas::ler_linha(texto(linha)?) {
                Ok(Some(p)) => p,
                _ => return Err("linha de pessoa gravada que nao se le"),
            };
            crate::pessoas::restaurar_pessoa(p);
            Ok(())
        }
        (tipo::PESSOA_REVOGADA, [id]) => {
            let id: [u8; 8] = (*id)
                .try_into()
                .map_err(|_| "identificador de pessoa invalido")?;
            let _ = crate::pessoas::revogar_pessoa(sigilo::pessoas::IdPessoa(id));
            Ok(())
        }
        (tipo::LAPIDE, [k, _assinatura]) => {
            crate::identidade::aplicar_lapide(&chave(k)?);
            Ok(())
        }
        _ => Err("entrada de registro desconhecida, ou com campos errados"),
    }
}

/// Só para a suíte: põe a persistência num estado, e devolve o anterior.
#[cfg(feature = "modo-teste")]
pub fn forcar_estado_de_teste(novo: Estado) -> Estado {
    com(|p| core::mem::replace(&mut p.estado, novo))
}

/// Só para a suíte: faz a próxima gravação falhar (com `true`), como se o
/// disco ou o TPM tivessem falhado no meio dela.
#[cfg(feature = "modo-teste")]
pub fn falhar_a_proxima_gravacao_de_teste(falhar: bool) {
    FALHAR_A_PROXIMA.store(falhar, Ordering::Release);
}

/// Só para a suíte: o valor do contador da âncora, lido do TPM agora.
#[cfg(feature = "modo-teste")]
pub fn ancora_no_tpm_de_teste() -> Result<u64, &'static str> {
    crate::tpm::com_o_tpm(|t| {
        com(|p| p.aberta.as_ref().map(|a| a.ancora.ler(t)))
            .ok_or("a persistencia nao esta aberta")?
            .map_err(|e| e.motivo())
    })
    .ok_or("sem TPM")?
}

/// Só para a suíte: uma entrada de registro de operação, como o journal a
/// grava.
#[cfg(feature = "modo-teste")]
pub fn entrada_de_teste(t: u16, campos: &[&[u8]]) -> Vec<u8> {
    entrada(t, campos).unwrap_or_default()
}

/// Só para a suíte: os registros do journal como estão no disco agora.
#[cfg(feature = "modo-teste")]
pub fn ler_de_teste() -> Result<Vec<diario::Registro>, &'static str> {
    let (chave, _) = segredos().ok_or("sem a chave do Duke")?;
    let mut meio = janela()?;
    Ok(diario::ler(&mut meio, &chave)?.registros)
}

/// Destrava as trancas da persistência à força, para uso exclusivo do
/// caminho de falha fatal.
///
/// # Safety
///
/// Só pode ser chamada quando o kernel já está em falha irrecuperável e não
/// há outro núcleo em execução. Ver [`crate::traps::fatal`].
pub unsafe fn destravar() {
    unsafe { PERSISTENCIA.force_unlock() };
    GRAVANDO.store(false, Ordering::Release);
}
