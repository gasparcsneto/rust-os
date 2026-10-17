//! O tempo, como a auditoria o conta: o estado do relógio civil e o que as
//! fontes de hora responderam, lidos dos registros de `time.sync` e
//! `time.confirm` — o NSF lê o tempo dos registros, nunca de um relógio.
//!
//! Só observa. Nenhuma regra de tempo está aqui ainda — elas vêm com os
//! consumidores do relógio —, e nada aqui pede ação: o NSF não ganha
//! autoridade sobre o relógio, não bloqueia fonte nenhuma, não cria
//! autorização. O serviço de hora, como titular, também não é alvo de
//! regra nem de resposta — ver `crate::motor`.
//!
//! # O que se lê
//!
//! O kernel grava, a cada `time.sync`, um registro de execução com o
//! veredito da resposta — o código diz a classe: `ALLOW` aceita,
//! `DENY_CREDENTIAL` assinatura ou delegação que a chave fixada não fecha,
//! `DENY_REPLAY` nonce ou pedido que não são deste, `INVALID_ARGUMENT`
//! forma, `ERROR` sem resposta ou vencida. Na última fonte da rodada, outro
//! com o recurso `civil <antes>><depois> logico <antes>><depois>
//! <estado>><estado> [pendente] [divergente] [adiantado]`. E o
//! `time.confirm` executado, com o recurso `salto <desvio> ...`.

use alloc::string::{String, ToString};

use politica::Codigo;

use crate::evento::{Evento, Tipo};

/// O tempo que a auditoria conta.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tempo {
    /// O estado do civil depois da última rodada que fechou: `rtc`,
    /// `sincronizado`, `holdover`, `vencido`.
    pub estado: Option<String>,
    /// As marcas da última rodada que fechou.
    pub pendente: bool,
    pub divergente: bool,
    pub adiantado: bool,
    /// Quantas rodadas fecharam, e o registro da última.
    pub rodadas: u64,
    pub ultima_rodada: Option<u64>,
    /// As respostas entregues, pela classe do veredito.
    pub aceitas: u64,
    pub assinatura_invalida: u64,
    pub repetidas: u64,
    pub malformadas: u64,
    pub sem_resposta: u64,
    /// Saltos pendentes que uma pessoa confirmou.
    pub saltos_confirmados: u64,
}

impl Tempo {
    /// Um registro, de qualquer titular: só os de tempo contam.
    pub fn observar(&mut self, e: &Evento) {
        match e.metodo.as_str() {
            "time.sync" if e.tipo == Tipo::Execucao => match e.recurso.strip_prefix("civil ") {
                Some(resto) => self.fechamento(e.seq, resto),
                None => self.veredito(e),
            },
            "time.confirm" if e.codigo == Codigo::Allow && e.recurso.starts_with("salto ") => {
                self.saltos_confirmados += 1;
            }
            _ => {}
        }
    }

    /// O desfecho de uma rodada: `X>Y logico A>B s1>s2 [marcas]`.
    fn fechamento(&mut self, seq: u64, resto: &str) {
        let mut partes = resto.split(' ');
        let (Some(_civil), Some("logico"), Some(_logico), Some(estados)) =
            (partes.next(), partes.next(), partes.next(), partes.next())
        else {
            return;
        };
        let Some((_, depois)) = estados.split_once('>') else {
            return;
        };
        self.estado = Some(depois.to_string());
        let (mut pendente, mut divergente, mut adiantado) = (false, false, false);
        for marca in partes {
            match marca {
                "pendente" => pendente = true,
                "divergente" => divergente = true,
                "adiantado" => adiantado = true,
                _ => {}
            }
        }
        self.pendente = pendente;
        self.divergente = divergente;
        self.adiantado = adiantado;
        self.rodadas += 1;
        self.ultima_rodada = Some(seq);
    }

    /// O veredito de uma entrega. O registro de uma entrega para um id
    /// que não existe (`id N`) e o de uma rodada descartada (`civil`) não
    /// são respostas de fonte nenhuma.
    fn veredito(&mut self, e: &Evento) {
        if e.recurso == "civil" || e.recurso.starts_with("id ") {
            return;
        }
        match e.codigo {
            Codigo::Allow => self.aceitas += 1,
            Codigo::DenyCredential => self.assinatura_invalida += 1,
            Codigo::DenyReplay => self.repetidas += 1,
            Codigo::InvalidArgument => self.malformadas += 1,
            Codigo::Error => self.sem_resposta += 1,
            _ => {}
        }
    }
}
