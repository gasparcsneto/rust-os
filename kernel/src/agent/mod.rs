//! O canal do agente: como o Claude opera este sistema operacional.
//!
//! # O que é
//!
//! Um servidor JSON-RPC 2.0 rodando dentro do kernel, falando por uma serial
//! própria — a COM2 no x86, a única PL011 no ARM. Um
//! objeto JSON por linha entra, um objeto JSON por linha sai. Do lado de fora,
//! o QEMU liga essa porta a um socket Unix, então o agente conversa com o OS
//! com um `connect()` comum — sem depurador, sem stub de GDB, sem instrumentar
//! o binário.
//!
//! # Por que serial, e não rede
//!
//! Porque funciona *agora*. Um canal sobre TCP exigiria driver de rede, pilha
//! IP e, para ser honesto sobre segurança, TLS — tudo isso é a fase 9 do
//! roteiro. A UART
//! já está de pé no primeiro milissegundo do boot, antes de haver paginação,
//! heap ou interrupções.
//!
//! E essa precocidade é justamente o que dá valor ao canal: ele existe para
//! nos ajudar a construir e depurar as camadas que vêm *depois* dele. Quando
//! a paginação quebrar, o canal do agente ainda vai estar respondendo.
//!
//! O transporte é um detalhe trocável: o conjunto de comandos em
//! [`commands::COMANDOS`] não sabe nada sobre serial. Quando houver rede,
//! expor o mesmo conjunto sobre TCP é trocar este módulo, não os comandos.
//!
//! # Os dois modos de atendimento
//!
//! - [`atender`] é o normal: uma tarefa assíncrona que espera bytes chegarem
//!   por interrupção e cede a CPU enquanto não há nada. É o que roda em
//!   operação.
//! - [`servir`] é o de emergência: um laço síncrono que não depende do heap
//!   nem do escalonador, usado no modo post-mortem depois de uma exceção
//!   fatal. Nessa hora, o heap e o escalonador podem ser exatamente o que
//!   quebrou, e o canal precisa responder mesmo assim.
//!
//! Os dois consomem a mesma fila de bytes e compartilham todo o resto:
//! enquadramento, decodificação e despacho.

// O canal do agente inteiro — enquadramento, parser, escritor e todos os
// comandos — é Rust seguro, e esta linha transforma esse fato num invariante
// verificado pelo compilador em vez de uma coincidência que o próximo commit
// desfaz sem ninguém notar.
//
// A escolha de módulo não é arbitrária. Este é o código que processa entrada
// vinda de fora da máquina: se algum dia houver um estouro de buffer no Duke,
// é aqui que ele teria mais valor para quem o explorasse. Também é o único
// subsistema grande que não fala com hardware — não há motivo legítimo para
// `unsafe` aqui, e portanto nada de legítimo é bloqueado.
//
// Se um dia for preciso mexer nisto, o caminho certo é isolar o `unsafe` num
// módulo de arquitetura e chamá-lo daqui, não relaxar a regra.
#![deny(unsafe_code)]

pub mod administracao;
pub mod commands;
pub mod json;
pub mod protocol;
pub mod registry;
pub mod seguro;
pub mod sessao;

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::autorizacao::{self, Chamador};
use json::JsonWriter;
use protocol::{Requisicao, RpcError};
use sessao::Canal;

/// Um comando pediu que o kernel falhasse de propósito.
///
/// A falha não pode acontecer dentro do handler: a serialização é em
/// streaming, e naquele ponto a resposta ainda está aberta no fio. Quem
/// dispara é [`processar`], depois que o quadro fechou.
static FALHA_AGENDADA: AtomicBool = AtomicBool::new(false);

/// O canal está no modo post-mortem — ver [`servir`]: sem heap confiável, a
/// resposta da serial vai direto no fio, enquanto o handler executa.
static DIRETO: AtomicBool = AtomicBool::new(false);

/// Marca que a próxima resposta deve ser seguida de uma falha fatal.
pub(crate) fn agendar_falha_fatal() {
    FALHA_AGENDADA.store(true, Ordering::SeqCst);
}

/// Quanto um quadro pode ficar parado antes de ser dado por abandonado.
///
/// Meio segundo a 100 Hz. Era de dois segundos, e a diferença tem uma medição
/// por trás.
///
/// # O que este teto protege
///
/// Um pedaço de requisição que ficou pendurado quando um cliente sumiu. O
/// kernel não enxerga a desconexão — não há linha de modem entre ele e o
/// socket —, então o fragmento cola na primeira requisição de quem conectar
/// depois. Medido, oito ciclos de oito: o cliente seguinte recebia `-32700`
/// e perdia o pedido dele.
///
/// Com dois segundos, quem reconectasse em menos disso herdava o fragmento —
/// e reconectar leva milissegundos. O teto cobria o caso tarde demais para
/// ser útil.
///
/// # Por que meio segundo, e não menos
///
/// Porque o custo de errar para baixo é partir um quadro legítimo ao meio. A
/// conta que limita: a maior requisição são 4096 bytes, que a 115200 bauds
/// levam 356 ms para atravessar uma serial de verdade. Meio segundo ainda
/// cobre — e a conta é de ociosidade, entre um byte e o seguinte —, e neste
/// canal — um socket no hospedeiro — é cinco ordens de
/// grandeza a mais do que uma requisição precisa.
///
/// A conta é sobre **ociosidade**, e não sobre a idade do quadro, então um
/// cliente lento porém constante nunca é penalizado: o relógio reinicia a
/// cada byte.
///
/// # O que ele não resolve
///
/// Quem reconectar dentro do meio segundo ainda herda o fragmento. Isso é
/// intrínseco a um fluxo de bytes sem fronteira de conexão, e a saída não é
/// um teto menor — é o cliente anunciar a fronteira que só ele conhece. Ver
/// [`LIMPAR_AO_CONECTAR`].
const TETO_DO_QUADRO_EM_TIQUES: u64 = 50;

/// O que um cliente deve enviar ao conectar: uma linha vazia.
///
/// # Por que isto existe
///
/// Porque o kernel não tem como saber que a conexão é nova. O cliente tem, e
/// é a única coisa que ele sabe e o kernel não — então é ele quem precisa
/// dizer.
///
/// Um `\n` solto fecha qualquer quadro que tenha ficado pela metade. Se não
/// havia nenhum, não custa nada: [`processar`] devolve sem responder a uma
/// linha vazia. Se havia, o cliente recebe **um** quadro de erro a mais, que
/// se refere ao lixo do cliente anterior e não ao pedido dele — e é por isso
/// que um cliente deste canal deve casar resposta por `id` e ignorar o que não
/// pediu, como o JSON-RPC já pressupõe.
///
/// A alternativa seria encurtar o teto de ociosidade até não sobrar janela, e
/// aí o preço seria partir requisições legítimas de clientes lentos. Um byte
/// enviado pelo cliente resolve sem cobrar nada de ninguém.
pub const LIMPAR_AO_CONECTAR: &[u8] = b"\n";

/// Tamanho máximo de uma requisição.
///
/// Fixo porque não há heap. Requisições maiores são rejeitadas com um erro
/// explícito em vez de silenciosamente truncadas — um agente precisa saber
/// que seu pedido não coube, e não receber uma resposta a uma pergunta que
/// não fez.
///
/// # Por que 4 KiB
///
/// A maior requisição legítima é um `admin.execute` com os parâmetros no
/// teto, [`administracao::MAIORES_PARAMETROS`] — 1 KiB —, que vão como
/// texto dentro do JSON e são escapados de novo. O pior escape que um
/// texto JSON válido pede é o de um caractere fora do ASCII escrito como
/// `\uXXXX`: seis bytes por dois de UTF-8, três vezes o tamanho. Três vezes
/// 1 KiB, mais o envelope — o desafio, o comando, a chave e a prova em hex
/// —, cabe em 4 KiB com folga. Com 2 KiB, um corpo de mensagem cheio de
/// aspas já não cabia, e o pedido era recusado por um limite de baixo,
/// e não pelo da prova. O preço é o buffer: um por canal, e o do modo
/// post-mortem na pilha.
pub(crate) const LINHA_MAX: usize = 4096;
const _: () = assert!(LINHA_MAX >= 3 * administracao::MAIORES_PARAMETROS + 512);

/// Monta linhas a partir de um fluxo de bytes.
///
/// Fica separado dos dois laços de atendimento porque o enquadramento é a
/// única parte com estado, e duplicá-lo seria duplicar exatamente a lógica
/// mais fácil de errar: o que fazer com uma linha longa demais.
struct Montador {
    /// De onde vêm os bytes, e para onde vai a resposta.
    canal: Canal,
    /// A geração do canal quando este quadro começou — ver
    /// [`Canal::geracao`]. Uma conexão nova recomeça o quadro.
    geracao: u64,
    buffer: [u8; LINHA_MAX],
    tam: usize,
    /// Quantos bytes o canal já tinha perdido quando este quadro começou.
    ///
    /// Bytes descartados por fila cheia não deixam marca no que sobra: o
    /// quadro remontado é indistinguível de um quadro íntegro, e se calhar de
    /// ser JSON válido o kernel o **executa** — uma requisição que ninguém
    /// enviou. Comparar o contador nas duas pontas é a única forma de saber.
    ///
    /// Medido, despejando vinte mil bytes de uma vez numa fila de quatro mil:
    /// no x86 o quadro vinha truncado e o erro saía; no ARM o `\n` final era
    /// descartado junto, o pedido seguinte era engolido pelo quadro quebrado,
    /// e o erro que voltava era atribuído a ele. Em nenhum dos dois havia como
    /// o agente saber que o que chegou não era o que ele mandou.
    perdas_ao_abrir: u64,
    /// Quando chegou o último byte deste quadro, em tiques.
    ///
    /// Um quadro parado tempo demais não é um cliente lento: é um cliente que
    /// morreu no meio de uma requisição. O kernel não enxerga a desconexão —
    /// não há linha de modem entre ele e o socket —, mas enxerga o relógio.
    ///
    /// Sem isto, o fragmento do cliente morto ficava pendurado e colava na
    /// primeira requisição de quem conectasse depois. Medido: um cliente
    /// enviou `{"jsonrpc":"2.0","id":2,"method":"agent.pi` e caiu; o cliente
    /// seguinte pediu um `agent.ping` com `id` 99 e recebeu
    ///
    ///     {"id":2,"error":{"code":-32601,"message":"metodo nao encontrado"}}
    ///
    /// — o pedido dele engolido, e uma resposta com o `id` de outra pessoa
    /// para um método que ele não chamou. Com um fragmento mais infeliz, o
    /// quadro colado vira uma requisição válida que ninguém fez, e o kernel a
    /// executa.
    ultimo_byte_em: u64,
    /// Este quadro já foi dado por perdido, e o cliente já foi avisado.
    ///
    /// Separado de `estourou` porque a causa é outra e o desfecho também: ali
    /// o kernel viu a requisição inteira e ela não coube; aqui ele não viu a
    /// requisição inteira. O que os dois compartilham é o que fazer a seguir —
    /// descartar até o próximo `\n` e recomeçar de um ponto conhecido.
    danificado: bool,
    /// Ligado quando a linha atual estourou o buffer: descartamos tudo até o
    /// próximo `\n` para voltar a um ponto de sincronia conhecido do stream.
    estourou: bool,
}

impl Montador {
    const fn novo(canal: Canal) -> Self {
        Self {
            canal,
            geracao: 0,
            buffer: [0; LINHA_MAX],
            tam: 0,
            perdas_ao_abrir: 0,
            ultimo_byte_em: 0,
            danificado: false,
            estourou: false,
        }
    }

    /// Consome um byte, processando a requisição quando a linha fecha.
    ///
    /// Devolve `true` quando este byte fechou uma linha — o chamador usa isso
    /// para saber que acabou de gastar um tempo indeterminado executando um
    /// comando, e que é uma boa hora de dar a vez a outra tarefa.
    fn alimentar(&mut self, byte: u8) -> bool {
        // Ociosidade primeiro: um quadro parado tempo demais é abandonado em
        // silêncio, e este byte passa a ser o primeiro de um quadro novo.
        //
        // Em silêncio de propósito. Quem deixou o fragmento não está mais
        // ouvindo, e mandar um erro só confundiria quem acabou de chegar — que
        // não fez nada de errado e cuja requisição precisa ser atendida
        // normalmente.
        // Uma conexão nova, num canal que as enxerga: o que estava pela
        // metade era de quem saiu, e fica com ele. Sem erro, pela mesma
        // razão da ociosidade logo abaixo.
        let geracao = self.canal.geracao();
        if geracao != self.geracao {
            self.geracao = geracao;
            self.tam = 0;
            self.estourou = false;
            self.danificado = false;
            self.abrir_quadro();
        }

        let agora = crate::tempo::ticks();
        if self.tam > 0 && agora.saturating_sub(self.ultimo_byte_em) > TETO_DO_QUADRO_EM_TIQUES {
            self.tam = 0;
            self.estourou = false;
            self.danificado = false;
            self.abrir_quadro();
        }
        self.ultimo_byte_em = agora;

        // A perda é conferida a cada byte, e não ao fechar o quadro, para que
        // o cliente saiba enquanto ainda está mandando. O quadro fecha de
        // qualquer forma — o handler repõe o delimitador que não coube, ver
        // [`crate::tarefas::entrada::coletar`] —, mas esperar por ele seria
        // responder só depois de o cliente terminar de despejar.
        if !self.danificado && self.canal.perdidos_no_texto() != self.perdas_ao_abrir {
            responder_erro(self.canal, None, RpcError::ENTRADA_PERDIDA, None);
            self.tam = 0;
            self.estourou = false;

            if byte == b'\n' {
                // Este byte **é** o fim do quadro danificado. Nada a descartar
                // depois dele: o que vier já é do quadro seguinte.
                //
                // A ordem aqui não é detalhe. Este byte saiu da fila antes de
                // tudo o que ainda está nela, então descartar a fila sem
                // olhá-lo primeiro jogaria fora o quadro **seguinte** e
                // deixaria o delimitador do danificado passar como se fosse
                // dele.
                self.abrir_quadro();
                return true;
            }

            // O resto deste quadro já está na fila e já é lixo conhecido.
            // Jogá-lo fora de uma vez, em vez de um byte por ida ao executor,
            // é o que devolve a fila ao pedido seguinte antes que ele chegue.
            // Sem isso, a requisição legítima que vem depois não cabe e se
            // perde junto — foi o que a CI pegou e a máquina daqui não.
            if self.canal.descartar_ate_nova_linha() {
                self.abrir_quadro();
                return true;
            }

            // A fila esvaziou sem o delimitador aparecer: ele ainda vem, e até
            // lá tudo que chegar é do quadro perdido.
            self.danificado = true;
            return false;
        }

        match byte {
            b'\n' => {
                // O aviso de dano já saiu quando a perda foi detectada; aqui
                // só se recomeça de um ponto conhecido do fluxo.
                if self.danificado {
                    // nada a responder
                } else if self.estourou {
                    responder_erro(self.canal, None, RpcError::LINHA_MUITO_LONGA, None);
                } else if self.tam > 0 {
                    processar(self.canal, &self.buffer[..self.tam]);
                }

                self.danificado = false;
                self.estourou = false;
                self.tam = 0;
                self.abrir_quadro();
                true
            }
            // Clientes que mandam CRLF não deveriam quebrar o parser.
            b'\r' => false,
            _ => {
                if self.estourou || self.danificado {
                    return false;
                }
                if self.tam < LINHA_MAX {
                    self.buffer[self.tam] = byte;
                    self.tam += 1;
                } else {
                    self.estourou = true;
                    self.tam = 0;
                }
                false
            }
        }
    }

    /// Marca o ponto de partida de um quadro novo.
    ///
    /// Chamado ao fechar o anterior, e não ao receber o primeiro byte: a perda
    /// que interessa a este quadro é toda a que acontecer entre o fim do
    /// quadro passado e o fim dele, inclusive a que acontecer antes de o
    /// primeiro byte dele chegar — que é justamente onde some um `\n`.
    fn abrir_quadro(&mut self) {
        self.perdas_ao_abrir = self.canal.perdidos_no_texto();
    }
}

/// A tarefa que atende o canal do agente. Nunca termina.
///
/// # O que o `.await` faz aqui
///
/// Cada `.await` é um ponto em que esta tarefa devolve o controle ao
/// executor. Enquanto não há byte na fila, ela não roda: seu waker fica
/// guardado, o handler da interrupção da serial o aciona quando um byte
/// chega, e só então o executor a traz de volta exatamente deste ponto.
///
/// Comparado ao laço antigo, a diferença prática é grande. Antes, o kernel
/// ou dormia até o próximo tique do timer (10 ms de latência por byte) ou
/// girava em espera ativa para evitá-la. Agora não faz nenhum dos dois: a
/// latência é a da interrupção, e o núcleo fica parado no resto do tempo.
///
/// O `async fn` não retorna `!` porque uma tarefa precisa produzir `()`. O
/// laço infinito por dentro dá no mesmo, com a vantagem de o executor poder
/// continuar rodando outras tarefas.
///
/// Em modo de teste esta função não tem chamador: a suíte roda no lugar do
/// atendimento, e uma tarefa que nunca termina não teria como devolver o
/// controle ao relatório.
///
/// Uma por canal: a serial, e cada porta do `virtio-console` — ver
/// [`sessao`].
#[cfg_attr(feature = "modo-teste", allow(dead_code))]
pub async fn atender(canal: Canal) {
    crate::log_info!(
        "agent",
        "sessao {} ({}) pronta, {} comandos registrados",
        canal.sessao(),
        canal.transporte(),
        commands::COMANDOS.len()
    );

    let mut montador = Montador::novo(canal);
    // A linha de partida do primeiro quadro é aqui, e não no `const fn`: o
    // contador de perdas não existe em tempo de compilação.
    montador.geracao = canal.geracao();
    montador.abrir_quadro();
    // Numa porta, os bytes passam antes pela sessão cifrada: o montador só
    // vê o texto que sobreviveu à decifração.
    let mut porta = match canal {
        Canal::Porta(p) => Some(seguro::Porta::nova(p)),
        Canal::Serial => None,
    };
    loop {
        let byte = canal.proximo_byte().await;
        let fechou = match porta.as_mut() {
            Some(porta) => {
                let mut fechou = false;
                porta.receber(byte, |b| fechou |= montador.alimentar(b));
                fechou
            }
            None => montador.alimentar(byte),
        };
        if fechou {
            // Acabamos de executar um comando, o que pode ter custado um
            // tempo arbitrário. Um cliente que envie várias requisições
            // emendadas manteria esta tarefa rodando sem parar, porque o
            // `.await` de cima encontraria a fila sempre cheia e nunca
            // cederia. Ceder aqui dá a vez às outras tarefas entre uma
            // requisição e a seguinte.
            crate::tarefas::ceder().await;
        }
    }
}

/// Atende o canal sem tarefas, sem heap e sem escalonador. Nunca retorna.
///
/// Este é o laço do modo post-mortem. Ele existe porque, depois de uma
/// exceção fatal, não dá para confiar em nada que o kernel construiu por
/// cima do básico — e o canal do agente é justamente o que precisa
/// sobreviver, para poder contar o que aconteceu.
///
/// Por isso ele bombeia a coleta da UART à mão em vez de esperar pela
/// interrupção: se a falha deixou as interrupções mascaradas, ou se o
/// controlador ficou num estado estranho, um laço que dependesse delas não
/// responderia nunca.
pub fn servir() -> ! {
    DIRETO.store(true, Ordering::SeqCst);
    crate::log_info!(
        "agent",
        "canal em modo direto, {} comandos registrados",
        commands::COMANDOS.len()
    );

    let mut montador = Montador::novo(Canal::Serial);
    // A linha de partida do primeiro quadro é aqui, e não no `const fn`: o
    // contador de perdas não existe em tempo de compilação.
    montador.abrir_quadro();

    loop {
        // A coleta é idempotente e barata quando não há nada: se as
        // interrupções ainda funcionarem, ela vai quase sempre encontrar a
        // fila já preenchida pelo handler, e não há conflito entre os dois —
        // ambos passam pela mesma fila.
        crate::tarefas::entrada::coletar();

        let mut atendeu = false;
        while let Some(byte) = crate::tarefas::entrada::retirar() {
            let _ = montador.alimentar(byte);
            atendeu = true;
        }

        if !atendeu {
            // Ocioso: dormimos até a próxima interrupção em vez de queimar o
            // núcleo. `esperar_interrupcao` é seguro mesmo com elas
            // mascaradas — cada arquitetura verifica e cai em espera ativa
            // nesse caso, porque dormir de verdade pararia o núcleo para
            // sempre.
            crate::arch::esperar_interrupcao();
        }
    }
}

/// Em modo de teste: uma sessão atendida à mão, sem o executor — a suíte
/// põe bytes na entrada do canal e manda atender, como a tarefa faria.
#[cfg(feature = "modo-teste")]
pub struct SessaoDeTeste {
    montador: Montador,
    porta: seguro::Porta,
}

#[cfg(feature = "modo-teste")]
impl SessaoDeTeste {
    /// Uma porta do `virtio-console`, de 1 a 4.
    pub fn porta(p: u8) -> SessaoDeTeste {
        let canal = Canal::Porta(p);
        let mut montador = Montador::novo(canal);
        montador.geracao = canal.geracao();
        montador.abrir_quadro();
        SessaoDeTeste {
            montador,
            porta: seguro::Porta::nova(p),
        }
    }

    /// Consome o que estiver na entrada da porta, respondendo cada quadro
    /// que fechar.
    pub fn atender(&mut self) {
        let Canal::Porta(p) = self.montador.canal else {
            return;
        };
        while let Some(byte) = crate::virtio::console::retirar(p) {
            let montador = &mut self.montador;
            self.porta.receber(byte, |b| {
                montador.alimentar(b);
            });
        }
    }
}

/// Remove ruído das bordas de um quadro.
///
/// Descarta bytes de controle e espaços no começo e no fim da linha. Isso
/// torna o canal tolerante a três coisas reais: terminadores CRLF, bytes
/// nulos que uma UART produz em transições de linha, e qualquer resíduo que
/// tenha escapado da drenagem feita na inicialização da porta.
///
/// É seguro: nenhum byte abaixo de 0x21 pode iniciar ou encerrar um valor
/// JSON, então nunca descartamos conteúdo significativo. E é preferível a
/// confiar só na drenagem — um único byte espúrio no momento errado não deve
/// custar ao agente uma requisição inteira.
pub(crate) fn limpar_quadro(linha: &[u8]) -> &[u8] {
    let inicio = linha.iter().position(|&b| b > 0x20);
    let Some(inicio) = inicio else {
        return &[];
    };
    let fim = linha
        .iter()
        .rposition(|&b| b > 0x20)
        .expect("se há um byte significativo no início, há um no fim");
    &linha[inicio..=fim]
}

/// Decodifica uma linha, despacha o comando como a sessão do canal, e
/// responde pelo mesmo canal.
fn processar(canal: Canal, linha: &[u8]) {
    let linha = limpar_quadro(linha);
    if linha.is_empty() {
        return;
    }

    // Quem pede, para a auditoria: até um pedido que não chega a ser
    // comando fica gravado, com o que se pôde ler dele.
    let chamador = Chamador::Sessao(canal.sessao());

    // O anexo que chegou antes desta linha é dela, e só dela: tirado agora,
    // reivindicado ou não, e zerado se o pedido não o leva. A serial não
    // tem quadros, nem anexo.
    let anexo = match canal {
        Canal::Porta(p) => crate::sessoes::tirar_anexo(p),
        Canal::Serial => Ok(crate::sessoes::AnexoDaPorta::nenhum()),
    };

    let requisicao = match Requisicao::parse(linha) {
        Ok(r) => r,
        Err((id, erro)) => {
            autorizacao::auditar_invalido(chamador, "", linha, erro.mensagem);
            return responder_erro(canal, id, erro, None);
        }
    };

    let Some(comando) = registry::encontrar(requisicao.metodo) else {
        autorizacao::auditar_invalido(
            chamador,
            requisicao.metodo,
            requisicao.params.0,
            "metodo nao encontrado",
        );
        return responder_erro(canal, requisicao.id, RpcError::METODO_NAO_ENCONTRADO, None);
    };

    // Validar antes de escrever qualquer coisa é obrigatório: a serialização
    // é em streaming, então depois de emitir `"result":` não há como voltar
    // atrás e transformar a resposta num erro.
    if let Err(campo) = registry::validar(comando, requisicao.params) {
        autorizacao::auditar_invalido(chamador, comando.nome, requisicao.params.0, campo);
        return responder_erro(
            canal,
            requisicao.id,
            RpcError::PARAMS_INVALIDOS,
            Some(campo),
        );
    }

    // O anexo confere com o que o pedido declara, byte a byte em número:
    // um anexo sem declaração, uma declaração sem anexo, ou um tamanho que
    // não confere é um pedido malformado — nada chega ao gate.
    let declarado = requisicao
        .params
        .member("attachment")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let anexo = match anexo {
        Ok(a) if a.len() as u64 == declarado => a,
        Ok(_) | Err(()) => {
            let motivo = "o anexo nao confere com attachment, ou passou do teto";
            autorizacao::auditar_invalido(chamador, comando.nome, requisicao.params.0, motivo);
            return responder_erro(
                canal,
                requisicao.id,
                RpcError::PARAMS_INVALIDOS,
                Some("attachment"),
            );
        }
    };

    // A decisão: identidade, sessão, papel, permissão. Só a licença que ela
    // devolve chama o handler — ver [`autorizacao`].
    let licenca = match autorizacao::autorizar(chamador, comando, requisicao.params) {
        Ok(l) => l,
        Err(codigo) => {
            return responder_erro(
                canal,
                requisicao.id,
                RpcError::da_recusa(codigo),
                Some(codigo.nome()),
            );
        }
    };

    com_saida(canal, |w| {
        protocol::envelope_ok(w, requisicao.id, |w| {
            licenca.executar_com_anexo(requisicao.params, anexo.entregar(), w)
        })
    });

    // Com a resposta inteira no fio, é seguro morrer. Daqui não se volta: o
    // handler da exceção entra em modo post-mortem, que reentra neste mesmo
    // módulo por [`servir`].
    if FALHA_AGENDADA.swap(false, Ordering::SeqCst) {
        crate::arch::disparar_falha_fatal();
    }
}

fn responder_erro(canal: Canal, id: Option<json::Json>, erro: RpcError, detalhe: Option<&str>) {
    com_saida(canal, |w| protocol::envelope_erro(w, id, erro, detalhe));
}

/// Emite uma resposta completa pelo canal, seguida do delimitador de quadro.
///
/// A resposta é montada inteira antes, com o handler rodando com as
/// interrupções ligadas, e só então vai ao canal: numa porta do
/// `virtio-console`, cifrada pela sessão da porta e entregue ao driver em
/// quadros; na serial, escrita no fio de uma vez, com a trava dela.
///
/// # Por que a serial não escreve enquanto o handler executa
///
/// A trava da serial é tomada com as interrupções mascaradas — o handler
/// da interrupção de recepção também a toma. Um handler que rodasse com ela
/// na mão rodaria mascarado, e um handler administrativo espera a ordem
/// das gravações do journal: com a ordem na mão de outro fio — o coletor,
/// no meio de uma compactação —, esperar mascarado com uma trava na mão é
/// a receita de um núcleo parado, e foi o que a bancada do 7.6 encontrou.
/// Só o modo post-mortem escreve direto, porque não pode contar com o heap.
fn com_saida(canal: Canal, f: impl FnOnce(&mut JsonWriter) -> fmt::Result) {
    let Canal::Porta(p) = canal else {
        if DIRETO.load(Ordering::SeqCst) {
            return com_saida_serial(f);
        }
        let mut texto = politica::sigiloso::Texto::novo();
        {
            let mut w = JsonWriter::new(&mut texto);
            let _ = f(&mut w);
        }
        texto.acrescentar(b"\n");
        return crate::arch::sem_interrupcoes(|| {
            if let Some(porta) = crate::serial::AGENT_LINK.lock().as_mut() {
                porta.write_bytes(texto.como_bytes());
            }
        });
    };
    // Num `Texto`, e não num `String`: a resposta pode levar o corpo de uma
    // mensagem, e o texto apaga cada bloco que larga — ao crescer e ao
    // sair, depois de cifrado. Ver `politica::sigiloso`.
    let mut texto = politica::sigiloso::Texto::novo();
    {
        let mut w = JsonWriter::new(&mut texto);
        let _ = f(&mut w);
    }
    texto.acrescentar(b"\n");
    // Sem sessão estabelecida não há a quem: a resposta é descartada. Não
    // acontece por um pedido — um pedido só chega decifrado —, mas acontece
    // quando a sessão cai entre o pedido e a resposta.
    seguro::enviar(p, texto.como_bytes());
}

/// Emite uma resposta completa na serial, direto no fio, enquanto `f`
/// executa — só no modo post-mortem.
fn com_saida_serial(f: impl FnOnce(&mut JsonWriter) -> fmt::Result) {
    crate::arch::sem_interrupcoes(|| {
        let mut guarda = crate::serial::AGENT_LINK.lock();
        let Some(porta) = guarda.as_mut() else {
            return;
        };

        // Escopo explícito: o `JsonWriter` empresta a porta mutavelmente, e
        // precisamos que esse empréstimo termine antes de escrever o `\n`.
        {
            let mut w = JsonWriter::new(&mut *porta);
            // Um erro de escrita aqui significa que a porta sumiu no meio da
            // resposta. Não há a quem reportar — o canal de reporte *é* a
            // porta —, então seguimos em frente.
            let _ = f(&mut w);
        }

        // NDJSON: um `\n` fecha o quadro. É o que permite ao cliente ler uma
        // resposta inteira sem contar chaves para achar onde o objeto termina.
        porta.write_bytes(b"\n");
    });
}
