//! O eco da malha: um processo servindo vários fluxos ao mesmo tempo, com o
//! laço — o exemplo do SDK do servidor de vários clientes.
//!
//! O programa escuta um canal só dele ([`Laco::novo`]), oferece a intenção
//! [`INTENCAO`] com o aviso nesse canal e diz `eco-malha: pronto <endpoint>
//! <canal>`. Daí em diante ele só dorme no laço:
//!
//! - o aviso `PEDIDO` do endpoint: aceita, com o aviso, todos os pedidos da
//!   fila — cada fluxo aceito é um cliente, local ou de outro Duke;
//! - o aviso `ENTREGA`: lê as entregas — o eco não as usa, mas o aviso só se
//!   cala quando elas são lidas;
//! - o aviso de um fluxo: o cliente **anda** — escreve o que esperava
//!   espaço, lê o que chegou e junta ao que vai voltar, até não haver mais
//!   nada a fazer agora. Quando o outro lado termina e tudo foi ecoado,
//!   termina o sentido dele e diz `eco-malha: ecoei <fluxo> <bytes>`.
//!
//! Cada passo é um pedido ao gate, sem espera: o aviso só diz que vale a
//! pena pedir. O que não coube espera no [`EscritaPendente`] do cliente, e
//! o cliente não lê mais enquanto há o que voltar — a memória de cada um é
//! um buffer, e quem não lê o eco não faz o servidor crescer.
//!
//! O evento `ENCERRAR` no canal encerra o programa com [`CODIGO`].
//!
//! A intenção é uma das de exemplo da política padrão: um programa de
//! verdade usa a dele, que o administrador enumera na política.

#![no_std]
#![no_main]

extern crate alloc;

programas::manifesto!(
    "eco-malha",
    "fabric.offer",
    "fabric.stream",
    "fabric.remote"
);

use alloc::collections::BTreeMap;
use programas::escreverln;
use programas::fluxo::{self, EscritaPendente, Falha, Fluxo};
use programas::laco::{Acontecimento, Laco};
use programas::malha;
use protocolo::usuario::evento::{Evento, tipo};

/// A intenção que o eco oferece.
const INTENCAO: &str = "imagem.compartilhar";

/// O código de saída no fim pedido.
const CODIGO: i64 = 47;

/// Um cliente: o fluxo, o que espera para voltar e onde ele está.
struct Cliente {
    f: Fluxo,
    saida: EscritaPendente,
    /// O outro lado terminou o sentido dele, e o fim foi lido.
    fim_lido: bool,
    ecoados: u64,
}

/// O que um cliente fez numa volta.
enum Andou {
    /// Espera o próximo aviso.
    Espera,
    /// Tudo ecoado, e o sentido daqui terminado.
    Acabou,
}

impl Cliente {
    fn novo(f: Fluxo) -> Cliente {
        Cliente {
            f,
            saida: EscritaPendente::nova(),
            fim_lido: false,
            ecoados: 0,
        }
    }

    /// Faz o que dá para fazer agora, sem esperar: escreve o pendente; com
    /// ele vazio, lê; no fim lido e tudo escrito, termina.
    fn andar(&mut self) -> Result<Andou, Falha> {
        loop {
            if !self.saida.escoar(&self.f)? {
                // O buffer do outro lado encheu: o `GRAVAVEL` diz quando.
                return Ok(Andou::Espera);
            }
            if self.fim_lido {
                self.f.terminar()?;
                return Ok(Andou::Acabou);
            }
            let (bytes, fim) = self.f.ler_agora(fluxo::MAIOR_PEDACO)?;
            self.ecoados += bytes.len() as u64;
            self.saida.juntar(&bytes);
            self.fim_lido = fim;
            if bytes.is_empty() && !fim {
                // Nada mais agora: o `LEGIVEL` diz quando.
                return Ok(Andou::Espera);
            }
        }
    }
}

/// Aceita os pedidos que esperam no endpoint, cada um com o aviso.
fn aceitar_todos(endpoint: &str, laco: &Laco, clientes: &mut BTreeMap<u64, Cliente>) {
    loop {
        match fluxo::aceitar_avisando(endpoint, laco) {
            Ok(Some((f, origem))) => {
                let Some(n) = f.numero() else { continue };
                let _ = escreverln!("eco-malha: aceitei {} de {}", n, origem.descrever());
                let mut c = Cliente::novo(f);
                // Pode já haver dado: o aviso dele vem, mas andar agora não
                // custa nada.
                if let Ok(Andou::Acabou) = c.andar() {
                    let _ = escreverln!("eco-malha: ecoei {} {}", n, c.ecoados);
                } else {
                    clientes.insert(n, c);
                }
            }
            Ok(None) => return,
            Err(e) => {
                let _ = escreverln!("eco-malha: aceitar {} {}", e.codigo(), e.motivo());
                return;
            }
        }
    }
}

#[unsafe(no_mangle)]
fn principal() -> i64 {
    let mut laco = match Laco::novo() {
        Ok(l) => l,
        Err(e) => {
            let _ = escreverln!("eco-malha: escutar devolveu {}", e);
            return 1;
        }
    };
    let endpoint = match malha::oferecer_avisando(INTENCAO, &laco) {
        Ok(e) => e,
        Err(f) => {
            let _ = escreverln!("eco-malha: oferecer {}", f.codigo());
            return 2;
        }
    };
    let _ = escreverln!("eco-malha: pronto {} {}", endpoint, laco.nome());
    let mut clientes: BTreeMap<u64, Cliente> = BTreeMap::new();
    loop {
        let acontecimentos = match laco.esperar() {
            Ok(v) => v,
            Err(e) => {
                let _ = escreverln!("eco-malha: o laco falhou: {}", e);
                return 3;
            }
        };
        for a in acontecimentos {
            match a {
                Acontecimento::Endpoint { prontidao, .. } => {
                    if prontidao.fim() {
                        let _ = escreverln!("eco-malha: o endpoint fechou");
                        return 4;
                    }
                    if prontidao.entrega() {
                        let _ = malha::receber(&endpoint, None, 0);
                    }
                    aceitar_todos(&endpoint, &laco, &mut clientes);
                }
                Acontecimento::Fluxo { numero, .. } => {
                    let Some(c) = clientes.get_mut(&numero) else {
                        continue;
                    };
                    match c.andar() {
                        Ok(Andou::Espera) => {}
                        Ok(Andou::Acabou) => {
                            let _ = escreverln!("eco-malha: ecoei {} {}", numero, c.ecoados);
                            clientes.remove(&numero);
                        }
                        Err(e) => {
                            let _ = escreverln!("eco-malha: {} acabou: {}", numero, e.motivo());
                            clientes.remove(&numero);
                        }
                    }
                }
                Acontecimento::Evento(Evento {
                    tipo: tipo::ENCERRAR,
                    ..
                }) => {
                    let _ = escreverln!("eco-malha: encerrado");
                    return CODIGO;
                }
                Acontecimento::Evento(_) => {}
            }
        }
    }
}
