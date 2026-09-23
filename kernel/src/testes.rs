//! Suíte de testes do kernel.
//!
//! # Por que não `cargo test`
//!
//! O harness de testes padrão do Rust depende da `std`, de threads e de um
//! sistema operacional que colete os resultados. Nada disso existe aqui — nós
//! *somos* o sistema operacional.
//!
//! A saída é o kernel ser seu próprio harness: compilado com a feature
//! `modo-teste`, ele roda esta suíte em vez de atender o agente, imprime o
//! relatório no console e encerra o emulador com um código de saída que o CI
//! entende. Os testes rodam no mesmo ambiente que o kernel de verdade — em
//! bare-metal, nas duas arquiteturas.
//!
//! # O que vale testar num kernel
//!
//! Priorizamos os lugares onde já encontramos bugs de verdade, porque bug
//! encontrado é evidência de que a área é escorregadia: o parser de JSON (que
//! precisa ignorar chaves dentro de strings), o enquadramento do canal (que
//! quebrava com um byte espúrio), o truncamento de mensagens de log em
//! fronteira de caractere, e agora o caminho de exceções e interrupções.

use core::fmt;

use crate::agent::json::{Json, JsonWriter};
use crate::agent::protocol::Requisicao;
use crate::agent::registry;
use crate::log::Level;

/// O que um teste devolve. A mensagem de erro é estática porque não há heap
/// para montar uma dinâmica; detalhes vão para o log antes do retorno.
type Resultado = Result<(), &'static str>;

struct Caso {
    nome: &'static str,
    f: fn() -> Resultado,
}

/// Buffer de escrita com capacidade fixa, para capturar a saída dos
/// serializadores sem precisar de heap.
struct Buffer {
    bytes: [u8; 1024],
    tam: usize,
}

impl Buffer {
    fn novo() -> Self {
        Self {
            bytes: [0; 1024],
            tam: 0,
        }
    }

    fn como_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.tam]).unwrap_or("<utf-8 invalido>")
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.tam]
    }
}

impl fmt::Write for Buffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let espaco = self.bytes.len() - self.tam;
        if s.len() > espaco {
            // Estourar em silêncio faria um teste passar com saída truncada,
            // que é pior que falhar.
            return Err(fmt::Error);
        }
        self.bytes[self.tam..self.tam + s.len()].copy_from_slice(s.as_bytes());
        self.tam += s.len();
        Ok(())
    }
}

/// Compara a saída capturada com o esperado, registrando a diferença no log.
fn conferir(buffer: &Buffer, esperado: &str) -> Resultado {
    if buffer.como_str() == esperado {
        Ok(())
    } else {
        crate::log_error!(
            "teste",
            "esperado `{}`, obtido `{}`",
            esperado,
            buffer.como_str()
        );
        Err("saida diferente do esperado")
    }
}

/// Atalho para converter erro de escrita em falha de teste.
fn escrita(r: fmt::Result) -> Resultado {
    r.map_err(|_| "falha ao escrever no buffer")
}

// ===========================================================================
// JSON — escrita
// ===========================================================================

fn json_objeto_simples() -> Resultado {
    let mut buffer = Buffer::novo();
    {
        let mut w = JsonWriter::new(&mut buffer);
        escrita(w.begin_object())?;
        escrita(w.field_u64("a", 1))?;
        escrita(w.field_str("b", "x"))?;
        escrita(w.end_object())?;
    }
    conferir(&buffer, r#"{"a":1,"b":"x"}"#)
}

/// O caso que exercita a lógica de vírgulas por nível de aninhamento.
///
/// É o ponto mais fácil de errar no serializador: uma vírgula a mais depois
/// de abrir um objeto, ou a menos entre dois irmãos, produz JSON inválido que
/// só aparece quando o cliente tenta parsear.
fn json_aninhado() -> Resultado {
    let mut buffer = Buffer::novo();
    {
        let mut w = JsonWriter::new(&mut buffer);
        escrita(w.begin_object())?;
        escrita(w.key("n"))?;
        escrita(w.begin_object())?;
        escrita(w.field_u64("a", 1))?;
        escrita(w.end_object())?;
        escrita(w.key("l"))?;
        escrita(w.begin_array())?;
        escrita(w.u64_value(1))?;
        escrita(w.u64_value(2))?;
        escrita(w.end_array())?;
        escrita(w.field_bool("z", true))?;
        escrita(w.end_object())?;
    }
    conferir(&buffer, r#"{"n":{"a":1},"l":[1,2],"z":true}"#)
}

fn json_escape_de_string() -> Resultado {
    let mut buffer = Buffer::novo();
    {
        let mut w = JsonWriter::new(&mut buffer);
        escrita(w.begin_object())?;
        escrita(w.field_str("s", "a\"b\\c\nd\te"))?;
        escrita(w.end_object())?;
    }
    conferir(&buffer, r#"{"s":"a\"b\\c\nd\te"}"#)
}

/// Caracteres de controle não podem aparecer crus dentro de uma string JSON.
fn json_escape_de_controle() -> Resultado {
    let mut buffer = Buffer::novo();
    {
        let mut w = JsonWriter::new(&mut buffer);
        escrita(w.begin_object())?;
        escrita(w.field_str("c", "\u{1}"))?;
        escrita(w.end_object())?;
    }
    conferir(&buffer, r#"{"c":"\u0001"}"#)
}

// ===========================================================================
// JSON — leitura
// ===========================================================================

fn json_busca_membro() -> Resultado {
    let j = Json(br#"{"a":1,"b":{"a":2},"c":"x"}"#);
    if j.member("a").and_then(|v| v.as_u64()) != Some(1) {
        return Err("nao encontrou a chave de primeiro nivel");
    }
    if j.member("z").is_some() {
        return Err("encontrou chave inexistente");
    }
    Ok(())
}

/// A busca só pode considerar chaves do nível imediato.
///
/// Sem pular objetos aninhados por inteiro, uma chave `method` dentro de
/// `params` seria confundida com a `method` do envelope — e o despachante
/// chamaria o comando errado.
fn json_ignora_chave_aninhada() -> Resultado {
    let j = Json(br#"{"externo":{"method":"errado"},"method":"certo"}"#);
    match j.member("method").and_then(|v| v.as_str()) {
        Some("certo") => Ok(()),
        outro => {
            crate::log_error!("teste", "obteve {:?}", outro);
            Err("confundiu chave aninhada com a de primeiro nivel")
        }
    }
}

/// Chaves e colchetes dentro de uma string não delimitam nada.
fn json_string_com_delimitadores() -> Resultado {
    let j = Json(br#"{"a":"}{[]","b":2}"#);
    if j.member("b").and_then(|v| v.as_u64()) != Some(2) {
        return Err("delimitadores dentro de string confundiram a varredura");
    }
    Ok(())
}

/// Uma aspa escapada não encerra a string.
fn json_string_com_aspa_escapada() -> Resultado {
    let j = Json(br#"{"a":"x\"y","b":3}"#);
    if j.member("b").and_then(|v| v.as_u64()) != Some(3) {
        return Err("aspa escapada encerrou a string cedo demais");
    }
    Ok(())
}

fn json_tipos_escalares() -> Resultado {
    let j = Json(br#"{"n":42,"t":true,"f":false,"s":"txt","z":null}"#);
    if j.member("n").and_then(|v| v.as_u64()) != Some(42) {
        return Err("numero");
    }
    if j.member("t").and_then(|v| v.as_bool()) != Some(true) {
        return Err("booleano verdadeiro");
    }
    if j.member("f").and_then(|v| v.as_bool()) != Some(false) {
        return Err("booleano falso");
    }
    if j.member("s").and_then(|v| v.as_str()) != Some("txt") {
        return Err("string");
    }
    if !j.member("z").map(|v| v.is_null()).unwrap_or(false) {
        return Err("nulo");
    }
    Ok(())
}

// ===========================================================================
// Protocolo JSON-RPC
// ===========================================================================

fn protocolo_decompoe_requisicao() -> Resultado {
    let linha = br#"{"jsonrpc":"2.0","id":7,"method":"system.info","params":{"a":1}}"#;
    let req = Requisicao::parse(linha).map_err(|_| "parse falhou numa requisicao valida")?;

    if req.metodo != "system.info" {
        return Err("metodo incorreto");
    }
    if req.id.and_then(|j| j.raw_str()) != Some("7") {
        return Err("id nao preservado");
    }
    if req.params.member("a").and_then(|v| v.as_u64()) != Some(1) {
        return Err("params nao acessiveis");
    }
    Ok(())
}

/// Um `id` que a varredura aceita mas que não é JSON tem de derrubar o
/// pedido — não ser ecoado cru numa resposta.
///
/// A varredura de `member` para no primeiro delimitador e devolve o que
/// houver antes, então `abc` e `1e` chegam com a mesma cara de um número. Como
/// o `id` é ecoado byte a byte na resposta, aceitá-los fazia o kernel emitir
/// JSON que nenhum cliente lê — e emitir *depois* de ter executado o comando.
fn protocolo_recusa_id_que_nao_e_json() -> Resultado {
    // Cada um destes foi visto saindo cru pela porta antes da correção.
    let recusaveis: &[&[u8]] = &[
        br#"{"jsonrpc":"2.0","id":abc,"method":"agent.ping"}"#,
        br#"{"jsonrpc":"2.0","id":@#$,"method":"agent.ping"}"#,
        br#"{"jsonrpc":"2.0","id":1e,"method":"agent.ping"}"#,
        br#"{"jsonrpc":"2.0","id":01,"method":"agent.ping"}"#,
        br#"{"jsonrpc":"2.0","id":1.,"method":"agent.ping"}"#,
        // Estruturados são JSON válido, mas a especificação (§4) só admite
        // String, Number ou Null como `id`.
        br#"{"jsonrpc":"2.0","id":[1,2],"method":"agent.ping"}"#,
        br#"{"jsonrpc":"2.0","id":{"a":1},"method":"agent.ping"}"#,
        br#"{"jsonrpc":"2.0","id":true,"method":"agent.ping"}"#,
        // Byte de controle cru dentro das aspas: o JSON proíbe, e ecoá-lo
        // quebrava a resposta do mesmo jeito.
        b"{\"jsonrpc\":\"2.0\",\"id\":\"a\x01b\",\"method\":\"agent.ping\"}",
    ];

    for linha in recusaveis {
        if Requisicao::parse(linha).is_ok() {
            return Err("um id que nao e JSON-RPC valido foi aceito");
        }
    }
    Ok(())
}

/// E a recusa não pode ter levado junto os `id` legítimos.
///
/// A metade que importa do caso acima: uma conferência estrita demais
/// silenciaria clientes corretos, e esse defeito seria mais caro que o que
/// ela conserta.
fn protocolo_aceita_id_legitimo() -> Resultado {
    let aceitaveis: &[(&[u8], &str)] = &[
        (br#"{"jsonrpc":"2.0","id":7,"method":"agent.ping"}"#, "7"),
        (br#"{"jsonrpc":"2.0","id":-3,"method":"agent.ping"}"#, "-3"),
        (br#"{"jsonrpc":"2.0","id":0,"method":"agent.ping"}"#, "0"),
        (
            br#"{"jsonrpc":"2.0","id":1.5e-3,"method":"agent.ping"}"#,
            "1.5e-3",
        ),
        (
            br#"{"jsonrpc":"2.0","id":"pedido-1","method":"agent.ping"}"#,
            "\"pedido-1\"",
        ),
        // Com escape: a aspa escapada não encerra a string, e o valor volta
        // com a grafia exata que chegou.
        (
            br#"{"jsonrpc":"2.0","id":"a\"b","method":"agent.ping"}"#,
            r#""a\"b""#,
        ),
    ];

    for (linha, esperado) in aceitaveis {
        let req = Requisicao::parse(linha).map_err(|_| "um id legitimo foi recusado")?;
        if req.id.and_then(|j| j.raw_str()) != Some(esperado) {
            return Err("o id legitimo nao voltou com a grafia que chegou");
        }
    }

    // `null` é legítimo e significa "sem id": some, e a resposta leva null.
    let req = Requisicao::parse(br#"{"jsonrpc":"2.0","id":null,"method":"agent.ping"}"#)
        .map_err(|_| "id null foi recusado")?;
    if req.id.is_some() {
        return Err("id null deveria virar ausencia de id");
    }
    Ok(())
}

/// Sem `params`, o padrão precisa ser um objeto vazio — é o que mantém os
/// handlers uniformes, sem cada um tratar o caso ausente.
fn protocolo_params_ausente_vira_objeto_vazio() -> Resultado {
    let req = Requisicao::parse(br#"{"jsonrpc":"2.0","id":1,"method":"agent.ping"}"#)
        .map_err(|_| "parse falhou")?;
    if req.params.member("qualquer").is_some() {
        return Err("params ausente deveria ser objeto vazio");
    }
    Ok(())
}

fn protocolo_rejeita_lixo() -> Resultado {
    if Requisicao::parse(b"isto nao e json").is_ok() {
        return Err("aceitou entrada que nao e json");
    }
    Ok(())
}

/// Numa requisição sem `method`, o `id` ainda precisa ser recuperado: a
/// especificação exige que a resposta de erro o ecoe, e um cliente com
/// várias requisições em voo precisa dele para saber qual falhou.
fn protocolo_preserva_id_no_erro() -> Resultado {
    match Requisicao::parse(br#"{"jsonrpc":"2.0","id":9}"#) {
        Ok(_) => Err("aceitou requisicao sem method"),
        Err((id, _)) => {
            if id.and_then(|j| j.raw_str()) == Some("9") {
                Ok(())
            } else {
                Err("id perdido na resposta de erro")
            }
        }
    }
}

// ===========================================================================
// Enquadramento do canal
// ===========================================================================

/// Regressão do bug em que um byte espúrio na FIFO da UART invalidava a
/// primeira requisição depois do boot.
fn enquadramento_descarta_ruido() -> Resultado {
    let limpo = crate::agent::limpar_quadro(b"\0\0  {\"a\":1}  \r\n");
    if limpo != br#"{"a":1}"# {
        return Err("nao removeu ruido das bordas");
    }
    if !crate::agent::limpar_quadro(b"\0\0\0").is_empty() {
        return Err("linha so de ruido deveria virar vazia");
    }
    if crate::agent::limpar_quadro(b"").is_empty() {
        Ok(())
    } else {
        Err("linha vazia deveria continuar vazia")
    }
}

// ===========================================================================
// Registro de comandos
// ===========================================================================

fn registro_encontra_comandos() -> Resultado {
    if registry::encontrar("system.info").is_none() {
        return Err("comando conhecido nao encontrado");
    }
    if registry::encontrar("nao.existe").is_some() {
        return Err("encontrou comando inexistente");
    }
    Ok(())
}

fn registro_valida_tipos_de_parametro() -> Resultado {
    let cmd = registry::encontrar("log.tail").ok_or("log.tail ausente")?;

    if registry::validar(cmd, Json(br#"{"count":5}"#)).is_err() {
        return Err("rejeitou parametro valido");
    }
    if registry::validar(cmd, Json(br#"{"count":"cinco"}"#)).is_ok() {
        return Err("aceitou parametro de tipo errado");
    }
    // Parâmetros opcionais ausentes são válidos.
    if registry::validar(cmd, Json(b"{}")).is_err() {
        return Err("rejeitou ausencia de parametro opcional");
    }
    Ok(())
}

/// Um parâmetro obrigatório ausente precisa ser recusado, e a recusa precisa
/// nomear o campo — senão o agente não tem como saber o que corrigir.
fn registro_exige_parametro_obrigatorio() -> Resultado {
    let cmd = registry::encontrar("debug.trigger").ok_or("debug.trigger ausente")?;
    match registry::validar(cmd, Json(b"{}")) {
        Ok(()) => Err("aceitou ausencia de parametro obrigatorio"),
        Err("kind") => Ok(()),
        Err(_) => Err("nomeou o campo errado"),
    }
}

/// Todo comando precisa estar descrito: `agent.describe` é como o agente
/// descobre o sistema, e uma entrada vazia ali é um comando invisível.
fn registro_esta_completamente_descrito() -> Resultado {
    for cmd in crate::agent::commands::COMANDOS {
        if cmd.nome.is_empty() || cmd.resumo.is_empty() {
            return Err("comando sem nome ou sem resumo");
        }
        for spec in cmd.params {
            if spec.nome.is_empty() || spec.descricao.is_empty() {
                crate::log_error!("teste", "comando {} tem parametro mal descrito", cmd.nome);
                return Err("parametro sem nome ou sem descricao");
            }
        }
    }
    Ok(())
}

/// Roda um handler de verdade e parseia a resposta com nosso próprio leitor.
///
/// É o teste mais próximo de ponta a ponta que cabe aqui: exercita o
/// serializador, o leitor e a introspecção da máquina de uma vez só.
fn comando_system_info_responde_arquitetura_correta() -> Resultado {
    let cmd = registry::encontrar("system.info").ok_or("system.info ausente")?;

    let mut buffer = Buffer::novo();
    {
        let mut w = JsonWriter::new(&mut buffer);
        escrita((cmd.handler)(Json(b"{}"), &mut w))?;
    }

    let resposta = Json(buffer.bytes());
    match resposta.member("arch").and_then(|v| v.as_str()) {
        Some(arch) if arch == crate::arch::nome() => Ok(()),
        _ => {
            crate::log_error!("teste", "resposta: {}", buffer.como_str());
            Err("system.info nao reporta a arquitetura correta")
        }
    }
}

// ===========================================================================
// Logging
// ===========================================================================

fn log_preserva_ordem() -> Resultado {
    crate::log_info!("teste", "marcador-um");
    crate::log_info!("teste", "marcador-dois");

    let mut viu_um = false;
    let mut viu_dois = false;
    let mut em_ordem = true;
    let mut seq_anterior: Option<u64> = None;

    crate::log::ultimos(2, Level::Trace, |registro| {
        match registro.mensagem() {
            "marcador-um" => viu_um = true,
            "marcador-dois" => viu_dois = true,
            _ => {}
        }
        if let Some(anterior) = seq_anterior
            && registro.seq <= anterior
        {
            em_ordem = false;
        }
        seq_anterior = Some(registro.seq);
    });

    if !viu_um || !viu_dois {
        return Err("registros recentes nao apareceram no tail");
    }
    if !em_ordem {
        return Err("tail devolveu registros fora de ordem");
    }
    Ok(())
}

fn log_filtra_por_nivel() -> Resultado {
    crate::log_error!("teste", "marcador-erro");
    crate::log_debug!("teste", "marcador-debug");

    let mut quantos = 0;
    crate::log::ultimos(2, Level::Warn, |_| quantos += 1);

    if quantos == 1 {
        Ok(())
    } else {
        crate::log_error!("teste", "filtro devolveu {} registros, esperado 1", quantos);
        Err("filtro de nivel nao funcionou")
    }
}

/// Mensagens longas são truncadas; o corte precisa cair numa fronteira de
/// caractere, senão a mensagem inteira vira UTF-8 inválido e fica ilegível.
fn log_trunca_em_fronteira_de_caractere() -> Resultado {
    // Acentos são multibyte, então o corte quase certamente cai no meio de um
    // deles se o truncamento for ingênuo.
    const PEDACO: &str = "áéíóúàâêôãõçüáéíóúàâêôãõçüáéíóúàâêôãõçü";
    crate::log_info!(
        "teste",
        "{}{}{}{}{}",
        PEDACO,
        PEDACO,
        PEDACO,
        PEDACO,
        PEDACO
    );

    let mut valido = false;
    crate::log::ultimos(1, Level::Trace, |registro| {
        let msg = registro.mensagem();
        valido = msg != "<utf-8 invalido>" && !msg.is_empty();
    });

    if valido {
        Ok(())
    } else {
        Err("truncamento produziu utf-8 invalido")
    }
}

// ===========================================================================
// Exceções
// ===========================================================================

/// Dispara um breakpoint de verdade e verifica que o handler rodou e devolveu
/// o controle. Se o caminho de exceções estivesse quebrado, o kernel morreria
/// aqui — e o CI veria um código de saída errado em vez de um teste falhando,
/// o que também é informativo.
fn excecao_breakpoint_e_retomada() -> Resultado {
    let antes = crate::traps::total();

    crate::arch::disparar_breakpoint();

    if crate::traps::total() != antes + 1 {
        return Err("breakpoint nao foi contabilizado");
    }
    match crate::traps::ultima() {
        Some(falha) if falha.nome == "breakpoint" => Ok(()),
        Some(falha) => {
            crate::log_error!("teste", "ultima falha foi {}", falha.nome);
            Err("ultima falha nao e o breakpoint")
        }
        None => Err("nenhuma falha registrada"),
    }
}

// ===========================================================================
// Tempo e interrupções
// ===========================================================================

fn timer_esta_configurado() -> Resultado {
    let hz = crate::tempo::frequencia_hz();
    if hz == 0 {
        return Err("timer sem frequencia registrada");
    }
    // Pedimos 100 Hz; o divisor inteiro pode desviar um pouco, mas não muito.
    if !(90..=110).contains(&hz) {
        crate::log_error!("teste", "frequencia efetiva: {} Hz", hz);
        return Err("frequencia do timer muito longe do pedido");
    }
    Ok(())
}

/// Verifica que as interrupções de timer realmente chegam.
///
/// É o teste que prova, de ponta a ponta, que o controlador de interrupções
/// foi configurado, que a linha está desmascarada, que o handler roda e que o
/// sinal de fim de interrupção está correto. Sem o EOI, por exemplo, o timer
/// dispararia exatamente uma vez — e este teste pegaria isso.
fn relogio_avanca() -> Resultado {
    let inicio = crate::tempo::ticks();

    // Espera ativa com teto. Um laço sem limite travaria o CI para sempre se
    // o timer estivesse mudo, o que é o pior modo de falhar.
    const TETO: u64 = 50_000_000;
    let mut giros = 0u64;
    while crate::tempo::ticks() == inicio && giros < TETO {
        core::hint::spin_loop();
        giros += 1;
    }

    if crate::tempo::ticks() > inicio {
        Ok(())
    } else {
        Err("nenhuma interrupcao de timer em 50M giros de espera")
    }
}

fn irq_do_timer_contabilizada() -> Resultado {
    let mut total_do_timer = 0u64;
    crate::irq::com_contadores(|_linha, nome, total| {
        if nome.starts_with("timer") {
            total_do_timer = total;
        }
    });

    if total_do_timer > 0 {
        Ok(())
    } else {
        Err("linha do timer sem contagem")
    }
}

/// Quantas linhas de timer o kernel pode ter, contando as que ele abandonou.
const MAX_TIMERS: usize = 4;

/// Exatamente uma linha de timer está avançando.
///
/// # A propriedade, e por que ela é a certa
///
/// No x86 o PIT sobe cedo e o APIC local o substitui assim que a paginação
/// permite. Entre programar o APIC e mascarar o PIT existe uma janela em que
/// **os dois** disparam, e os dois chamam `tempo::tick` — o relógio anda ao
/// dobro da velocidade. Fora dessa janela, exatamente um deve estar contando.
///
/// Os dois erros possíveis são simétricos e este caso pega os dois:
///
/// - mascarar o PIT sem que o APIC esteja contando para o relógio, e o
///   sistema para de preemptar sem nenhuma mensagem de erro;
/// - programar o APIC e esquecer de mascarar o PIT, e o uptime passa a andar
///   ao dobro — um erro que nenhum teste de "o relógio avança" pegaria,
///   porque ele avança mesmo, só que errado.
///
/// No ARM só existe um timer e o caso passa trivialmente. Ele vale mesmo
/// assim: a propriedade é do kernel, não da plataforma, e é o ARM que mostra
/// qual é o comportamento normal.
fn timer_exatamente_um_relogio_avanca() -> Resultado {
    /// Lê os contadores de todas as linhas cujo nome começa com "timer".
    fn amostrar(destino: &mut [(&'static str, u64); MAX_TIMERS]) -> usize {
        let mut quantos = 0;
        crate::irq::com_contadores(|_linha, nome, total| {
            if nome.starts_with("timer") && quantos < MAX_TIMERS {
                destino[quantos] = (nome, total);
                quantos += 1;
            }
        });
        quantos
    }

    let mut antes = [("", 0u64); MAX_TIMERS];
    let quantos = amostrar(&mut antes);
    if quantos == 0 {
        return Err("nenhuma linha de timer contabilizada");
    }

    // Esperar pelo relógio, e não por um número de voltas: o que interessa é
    // que tempo tenha passado, e o relógio é justamente o que está sob
    // exame. O teto de voltas existe só para que um relógio parado vire falha
    // em vez de travamento — e ele precisa ser folgado o bastante para que
    // esgotá-lo signifique mesmo isso. Ver [`VOLTAS_ESPERANDO_O_RELOGIO`].
    const TIQUES_NECESSARIOS: u64 = 3;

    let comeco = crate::tempo::ticks();
    let mut esgotou = true;
    for _ in 0..VOLTAS_ESPERANDO_O_RELOGIO {
        if crate::tempo::ticks() - comeco >= TIQUES_NECESSARIOS {
            esgotou = false;
            break;
        }
        core::hint::spin_loop();
    }

    // Distinguir as duas causas, porque confundi-las foi o que custou uma CI
    // vermelha: o relógio parado é defeito do kernel, o teto curto demais é
    // defeito deste caso, e a mensagem anterior chamava os dois de "o relogio
    // parou".
    if esgotou {
        crate::log_error!(
            "teste",
            "{} voltas sem completar {} tiques",
            VOLTAS_ESPERANDO_O_RELOGIO,
            TIQUES_NECESSARIOS
        );
        return Err("o teto de voltas acabou antes dos tiques: relogio parado ou teto curto");
    }

    let mut depois = [("", 0u64); MAX_TIMERS];
    let agora = amostrar(&mut depois);

    let mut avancaram = 0;
    for (nome, valor) in depois.iter().take(agora) {
        let anterior = antes
            .iter()
            .take(quantos)
            .find(|(n, _)| n == nome)
            .map(|(_, v)| *v)
            .unwrap_or(0);
        if *valor > anterior {
            avancaram += 1;
            crate::log_info!("teste", "{} avancou {} tiques", nome, valor - anterior);
        }
    }

    match avancaram {
        1 => Ok(()),
        0 => Err("nenhum timer avancou: o relogio parou"),
        _ => Err("mais de um timer avancando: o relogio anda rapido demais"),
    }
}

// ===========================================================================
// O leitor de device tree
// ===========================================================================

/// Monta um device tree mínimo, com as larguras de célula que se pedir.
///
/// # Por que um blob sintético
///
/// Porque o leitor de device tree interpreta o dado mais externo que este
/// kernel recebe — um blob que o firmware depositou na RAM — e até aqui ele
/// só tinha sido exercitado contra o blob que o QEMU produz. Um parser
/// testado só com entrada bem formada é um parser testado pela metade.
///
/// Montar o blob aqui é o que permite escrever a entrada **errada** de
/// propósito, que é a metade que faltava.
#[cfg(target_arch = "aarch64")]
fn montar_dtb(destino: &mut [u8; 256], address_cells: u32, size_cells: u32) -> usize {
    /// Os nomes das propriedades, num bloco só, referenciados por
    /// deslocamento — é assim que o formato os guarda.
    const STRINGS: &[u8] = b"#address-cells\0#size-cells\0reg\0";
    const OFF_ADDRESS_CELLS: u32 = 0;
    const OFF_SIZE_CELLS: u32 = 15;
    const OFF_REG: u32 = 27;

    const OFF_STRUCT: usize = 64;

    let mut n = OFF_STRUCT;
    let palavra = |destino: &mut [u8; 256], n: &mut usize, valor: u32| {
        destino[*n..*n + 4].copy_from_slice(&valor.to_be_bytes());
        *n += 4;
    };

    // A raiz, sem nome: um byte nulo preenchido até a fronteira de quatro.
    palavra(destino, &mut n, 1); // BEGIN_NODE
    palavra(destino, &mut n, 0); // nome vazio, já alinhado

    palavra(destino, &mut n, 3); // PROP
    palavra(destino, &mut n, 4); // tamanho
    palavra(destino, &mut n, OFF_ADDRESS_CELLS);
    palavra(destino, &mut n, address_cells);

    palavra(destino, &mut n, 3);
    palavra(destino, &mut n, 4);
    palavra(destino, &mut n, OFF_SIZE_CELLS);
    palavra(destino, &mut n, size_cells);

    // `memory@0`, filho direto da raiz.
    palavra(destino, &mut n, 1); // BEGIN_NODE
    destino[n..n + 12].copy_from_slice(b"memory@0\0\0\0\0");
    n += 12;

    // `reg` com doze bytes: dois de endereço e um de tamanho, que é o que um
    // blob com `#address-cells = 2` e `#size-cells = 1` declara.
    palavra(destino, &mut n, 3); // PROP
    palavra(destino, &mut n, 12);
    palavra(destino, &mut n, OFF_REG);
    palavra(destino, &mut n, 0x0000_0000); // endereço, palavra alta
    palavra(destino, &mut n, 0x4000_0000); // endereço, palavra baixa
    palavra(destino, &mut n, 0x0800_0000); // tamanho

    palavra(destino, &mut n, 2); // END_NODE de memory
    palavra(destino, &mut n, 2); // END_NODE da raiz
    palavra(destino, &mut n, 9); // END

    let tamanho_struct = n - OFF_STRUCT;
    let off_strings = n;
    destino[off_strings..off_strings + STRINGS.len()].copy_from_slice(STRINGS);
    let total = off_strings + STRINGS.len();

    // O cabeçalho, agora que os tamanhos são conhecidos.
    let mut cabecalho = 0usize;
    for valor in [
        0xd00d_feed,           // magic
        total as u32,          // tamanho total
        OFF_STRUCT as u32,     // onde o bloco de estrutura começa
        off_strings as u32,    // onde o bloco de strings começa
        0,                     // mapa de reservas: vazio
        17,                    // versão
        16,                    // última versão compatível
        0,                     // cpu de boot
        STRINGS.len() as u32,  // tamanho do bloco de strings
        tamanho_struct as u32, // tamanho do bloco de estrutura
    ] {
        destino[cabecalho..cabecalho + 4].copy_from_slice(&valor.to_be_bytes());
        cabecalho += 4;
    }

    total
}

/// Todo deslocamento do blob é conferido contra o tamanho que ele declara.
///
/// # O que estava solto
///
/// O percurso nunca lia o `totalsize` do cabeçalho — o único limite que um
/// device tree tem. Os deslocamentos que ele obedecia (`off_struct`,
/// `off_strings`, o `nameoff` de cada propriedade, o `len` de cada uma) vêm
/// todos de dentro do próprio blob, e eram seguidos sem conferência nenhuma.
///
/// Um `nameoff` corrompido mandava a busca do nome para um endereço arbitrário
/// e varria a memória de lá até encontrar um zero. Com um device tree assim, o
/// kernel pendurava no boot sem emitir um byte — antes de existir canal do
/// agente para contar o motivo.
///
/// Cada caso abaixo envenena **um** campo de trinta e dois bits de um blob que
/// de resto é válido, e exige duas coisas: que o leitor recuse, e que não
/// entregue região nenhuma ao alocador.
fn fdt_confere_deslocamentos_contra_o_tamanho_declarado() -> Resultado {
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::log_info!("teste", "o leitor de device tree so existe no aarch64");
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::fdt;

        // Deslocamentos do blob que `montar_dtb` produz: o cabeçalho é fixo
        // pelo formato, e a primeira propriedade é a primeira coisa que o
        // construtor escreve depois da raiz sem nome.
        const TOTALSIZE: usize = 4;
        const OFF_STRUCT: usize = 8;
        const OFF_STRINGS: usize = 12;
        const TAMANHO_DA_1A_PROP: usize = 76;
        const NAMEOFF_DA_1A_PROP: usize = 80;
        // O `reg` do nó `memory`: a única propriedade deste blob que um
        // consumidor de fato lê. É por ela que a conferência de faixa se
        // demonstra — as outras o percurso recusa sozinho ao seguir adiante,
        // mas quem lê `reg` nunca volta ao percurso para ser salvo por ele.
        const TAMANHO_DO_REG: usize = 124;

        const LONGE: u32 = 0xFFF0_0000;

        let envenenados: &[(&str, usize, u32)] = &[
            ("len do reg consumido alem do fim", TAMANHO_DO_REG, LONGE),
            ("nameoff apontando para fora", NAMEOFF_DA_1A_PROP, LONGE),
            ("len de propriedade alem do fim", TAMANHO_DA_1A_PROP, LONGE),
            ("bloco de estrutura fora do blob", OFF_STRUCT, LONGE),
            ("bloco de strings fora do blob", OFF_STRINGS, LONGE),
            ("totalsize menor que o cabecalho", TOTALSIZE, 8),
        ];

        for (o_que, onde, valor) in envenenados {
            let mut blob = [0u8; 256];
            montar_dtb(&mut blob, 2, 1);
            blob[*onde..*onde + 4].copy_from_slice(&valor.to_be_bytes());

            let mut entregues = 0;
            // SAFETY: o blob está neste quadro de pilha e traz a assinatura;
            // o que se afirma é justamente que o leitor não confia no resto.
            let r = unsafe { fdt::percorrer_memoria(blob.as_ptr(), |_, _| entregues += 1) };

            if r.is_ok() {
                crate::log_error!("teste", "aceitou: {}", o_que);
                return Err("o leitor aceitou um deslocamento fora do blob");
            }
            if entregues != 0 {
                crate::log_error!("teste", "inventou regiao com: {}", o_que);
                return Err("o leitor entregou regiao a partir de um blob corrompido");
            }
        }

        // E um blob sem `FDT_END`: trocando o token final por um `NOP`, o
        // percurso não tem mais onde parar por conta própria. O que o faz
        // parar é o teto — sem ele, a varredura seguia pela memória adiante.
        let mut sem_fim = [0u8; 256];
        montar_dtb(&mut sem_fim, 2, 1);
        let off_strings = u32::from_be_bytes([
            sem_fim[OFF_STRINGS],
            sem_fim[OFF_STRINGS + 1],
            sem_fim[OFF_STRINGS + 2],
            sem_fim[OFF_STRINGS + 3],
        ]) as usize;
        sem_fim[off_strings - 4..off_strings].copy_from_slice(&4u32.to_be_bytes());

        // SAFETY: mesma justificativa.
        let r = unsafe { fdt::percorrer_memoria(sem_fim.as_ptr(), |_, _| {}) };
        if r.is_ok() {
            return Err("o leitor chegou ao fim de um blob sem FDT_END sem reclamar");
        }

        Ok(())
    }
}

/// O leitor entende um blob bem formado e não morre com um malformado.
///
/// # O que o caso hostil exercita
///
/// As larguras de célula vêm **do blob**, e alimentam a aritmética que decide
/// quantos bytes cada entrada ocupa. Antes do teto em `MAX_CELULAS`, um blob
/// que declarasse `0xFFFF_FFFF` fazia `address_cells + size_cells`
/// transbordar a soma de 32 bits: pânico num build de depuração, e uma
/// largura pequena e falsa num de release — que levaria o leitor a
/// interpretar lixo como endereços de RAM e a entregá-los ao alocador.
fn fdt_le_o_normal_e_resiste_ao_hostil() -> Resultado {
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::log_info!("teste", "o leitor de device tree so existe no aarch64");
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::fdt;

        // O blob bem formado: uma região de 128 MiB em 0x4000_0000.
        let mut blob = [0u8; 256];
        montar_dtb(&mut blob, 2, 1);

        let mut achadas = 0;
        let mut regiao = (0u64, 0u64);
        // SAFETY: o blob acabou de ser montado neste quadro de pilha, com a
        // assinatura e os deslocamentos que o formato exige.
        let r = unsafe {
            fdt::percorrer_memoria(blob.as_ptr(), |inicio, tamanho| {
                achadas += 1;
                regiao = (inicio, tamanho);
            })
        };
        if r.is_err() {
            return Err("o leitor recusou um blob bem formado");
        }
        if achadas != 1 {
            return Err("o leitor nao achou a regiao de memoria do blob");
        }
        if regiao != (0x4000_0000, 0x0800_0000) {
            crate::log_error!("teste", "veio {:#x}+{:#x}", regiao.0, regiao.1);
            return Err("a regiao lida nao e a que o blob declara");
        }

        // E o hostil: larguras absurdas nas duas declarações. O que se afirma
        // é que o leitor volta — sem pânico e sem inventar região.
        let mut hostil = [0u8; 256];
        montar_dtb(&mut hostil, u32::MAX, u32::MAX);

        let mut inventadas = 0;
        // SAFETY: mesma justificativa.
        let _ = unsafe {
            fdt::percorrer_memoria(hostil.as_ptr(), |_, _| {
                inventadas += 1;
            })
        };
        if inventadas != 0 {
            return Err("o leitor inventou regiao a partir de larguras absurdas");
        }

        Ok(())
    }
}

// ===========================================================================
// A tela
// ===========================================================================

use crate::tela::{Cor, Formato, Tela};

/// Monta uma tela minúscula sobre `buffer` e chama `f` com ela.
///
/// A tela da suíte é de mentira de propósito: a aritmética de pixel não tem
/// nada de específico de arquitetura, e testá-la só onde há framebuffer de
/// verdade seria testá-la só no x86.
fn com_tela_falsa<R>(
    buffer: &mut [u8],
    largura: u32,
    altura: u32,
    stride: u32,
    bytes_por_pixel: u32,
    formato: Formato,
    f: impl FnOnce(&Tela) -> R,
) -> R {
    // SAFETY: o buffer é da pilha de quem chamou, vive durante toda a
    // chamada, e os casos abaixo o dimensionam para a geometria que passam.
    let tela = unsafe {
        Tela::sobre(
            buffer.as_mut_ptr() as u64,
            largura,
            altura,
            stride,
            bytes_por_pixel,
            formato,
        )
    };
    f(&tela)
}

/// O que é escrito volta igual, nos três formatos.
///
/// # O que este caso pega
///
/// A ordem dos bytes. `rgb` e `bgr` guardam as mesmas três componentes em
/// ordens opostas, e trocá-las não dá erro nenhum: dá uma tela em que o
/// vermelho aparece azul. Num kernel que desenha uma tela de falha vermelha,
/// o sintoma seria uma tela azul — e ninguém desconfia da ordem dos bytes ao
/// ver isso, desconfia da constante da cor.
fn tela_cada_formato_volta_como_foi_escrito() -> Resultado {
    const CORES: [Cor; 4] = [
        Cor::PRETO,
        Cor::BRANCO,
        Cor::nova(0xFF, 0x00, 0x00),
        Cor::nova(0x10, 0x18, 0x28),
    ];

    for (formato, bytes_por_pixel) in [
        (Formato::Rgb, 3),
        (Formato::Rgb, 4),
        (Formato::Bgr, 3),
        (Formato::Bgr, 4),
    ] {
        let mut buffer = [0u8; 4 * 4 * 4];
        let erro = com_tela_falsa(&mut buffer, 4, 4, 4, bytes_por_pixel, formato, |tela| {
            for (indice, cor) in CORES.iter().enumerate() {
                let x = indice as u32 % 4;
                let y = indice as u32 / 4;
                tela.retangulo(x, y, 1, 1, *cor);
                if tela.ler_pixel(x, y) != Some(*cor) {
                    return Some("uma cor nao voltou como foi escrita");
                }
            }
            None
        });
        if let Some(motivo) = erro {
            crate::log_error!(
                "teste",
                "formato {} com {} bytes por pixel",
                formato.como_str(),
                bytes_por_pixel
            );
            return Err(motivo);
        }
    }

    // Em tons de cinza a volta não é exata de propósito: a cor foi reduzida a
    // luminância na escrita. O que se afirma é que ela volta *cinza*, e que o
    // valor não é zero para uma cor que não é preta.
    let mut buffer = [0u8; 4 * 4];
    let erro = com_tela_falsa(&mut buffer, 4, 4, 4, 1, Formato::Cinza, |tela| {
        tela.retangulo(0, 0, 1, 1, Cor::BRANCO);
        if tela.ler_pixel(0, 0) != Some(Cor::BRANCO) {
            return Some("branco nao voltou branco em tons de cinza");
        }

        tela.retangulo(1, 0, 1, 1, Cor::nova(0x00, 0xFF, 0x00));
        match tela.ler_pixel(1, 0) {
            Some(Cor { r, g, b }) if r == g && g == b && r > 0 => None,
            _ => Some("o verde nao virou um cinza diferente de preto"),
        }
    });
    if let Some(motivo) = erro {
        return Err(motivo);
    }

    Ok(())
}

/// Uma linha começa a `stride` pixels da anterior, não a `largura`.
///
/// # Por que isto merece um caso próprio
///
/// Porque é o erro clássico deste tipo de código, e porque o sintoma dele é
/// uma imagem **inclinada** — cada linha deslocada um pouco mais que a
/// anterior. Num teste que só escrevesse e lesse o mesmo pixel, o erro
/// passaria: ele é consistente consigo mesmo.
///
/// O caso força a diferença: uma tela de 2 pixels de largura sobre um buffer
/// de 5 pixels por linha. Se a conta usasse a largura, o pixel de baixo cairia
/// dois pixels adiante em vez de cinco — e a posição exata é conferida byte a
/// byte.
fn tela_stride_nao_e_largura() -> Resultado {
    const LARGURA: u32 = 2;
    const STRIDE: u32 = 5;
    const BYTES: u32 = 3;

    let mut buffer = [0u8; (STRIDE * 2 * BYTES) as usize];

    com_tela_falsa(
        &mut buffer,
        LARGURA,
        2,
        STRIDE,
        BYTES,
        Formato::Rgb,
        |tela| {
            tela.retangulo(0, 1, 1, 1, Cor::nova(0xAB, 0xCD, 0xEF));
        },
    );

    // O pixel (0,1) tem de estar em `stride * bytes`, e não em
    // `largura * bytes`.
    let esperado = (STRIDE * BYTES) as usize;
    let errado = (LARGURA * BYTES) as usize;

    if buffer[esperado] != 0xAB || buffer[esperado + 1] != 0xCD || buffer[esperado + 2] != 0xEF {
        return Err("a segunda linha nao comecou em stride");
    }
    if buffer[errado] != 0 {
        return Err("a segunda linha comecou em largura, nao em stride");
    }

    Ok(())
}

/// Desenhar fora da tela não escreve fora do buffer.
///
/// Um retângulo maior que a tela é o caso normal, não o excepcional: é o que
/// acontece em toda borda. O que não pode acontecer é ele escrever no que vem
/// depois do framebuffer — e num kernel, o que vem depois é memória de outra
/// pessoa.
fn tela_recorta_na_borda() -> Resultado {
    const LARGURA: u32 = 3;
    const ALTURA: u32 = 3;
    const BYTES: u32 = 4;
    const UTEIS: usize = (LARGURA * ALTURA * BYTES) as usize;
    /// Bytes de sentinela depois da tela, que precisam continuar intactos.
    const SENTINELA: usize = 16;

    let mut buffer = [0u8; UTEIS + SENTINELA];

    com_tela_falsa(
        &mut buffer[..UTEIS],
        LARGURA,
        ALTURA,
        LARGURA,
        BYTES,
        Formato::Bgr,
        |tela| {
            // Bem maior que a tela, começando dentro dela.
            tela.retangulo(1, 1, 1000, 1000, Cor::BRANCO);
            // E um pixel solto muito além da borda.
            tela.retangulo(9999, 9999, 1, 1, Cor::BRANCO);
        },
    );

    if buffer[UTEIS..].iter().any(|&b| b != 0) {
        return Err("o desenho passou do fim da tela");
    }

    // E o que estava dentro foi pintado: um recorte que não pinta nada
    // passaria pela conferência acima sem fazer nada de útil.
    if buffer[..UTEIS].iter().all(|&b| b == 0) {
        return Err("o recorte descartou tambem o que estava dentro");
    }

    Ok(())
}

/// O que a ausência de framebuffer significa, que depende da arquitetura.
///
/// # Por que não é sempre tolerável
///
/// Porque a tolerância boa demais transformou este caso num que passava
/// justamente quando deveria falhar.
///
/// No ARM a `virt` do QEMU não expõe framebuffer nenhum, e a ausência é o
/// estado correto da máquina — uma lacuna que deve aparecer no relatório da
/// suíte até um driver de virtio-gpu fechá-la. No x86 é o contrário: o
/// bootloader entrega um framebuffer sempre, então "não há tela" não descreve
/// máquina nenhuma. Descreve um defeito — a geometria recusada, o registro
/// que não aconteceu, o endereço que não chegou.
///
/// Os dois casos eram tratados como um. Injetando um stride menor que a
/// largura, a tela foi corretamente recusada no boot e este caso continuou
/// dizendo `ok`: o único que olha para o framebuffer de verdade parou de
/// olhar, em silêncio, no exato cenário em que ele importa.
#[cfg(target_arch = "x86_64")]
fn sem_framebuffer() -> Resultado {
    Err("esta maquina deveria ter framebuffer e nao tem")
}

#[cfg(not(target_arch = "x86_64"))]
fn sem_framebuffer() -> Resultado {
    crate::log_info!("teste", "esta maquina nao tem framebuffer; nada a conferir");
    Ok(())
}

/// Uma imagem que o validador recusa não custa o espaço de quem chamou.
///
/// # O que este caso protege
///
/// `carregar` tem um ponto de não retorno — a troca do espaço de endereços —
/// e falha dos dois lados dele. Depois da troca não há para onde voltar, e
/// encerrar o processo é o desfecho certo. Antes, o processo que chamou está
/// inteiro: imagem mapeada, pilha no lugar.
///
/// Os dois casos eram tratados como um, com o tratamento do pior deles:
/// qualquer falha matava o processo. Uma imagem malformada e uma falta
/// momentânea de memória em `Espaco::novo`, as duas antes da troca e as duas
/// recuperáveis, custavam o processo inteiro.
///
/// A conferência do espaço é o que torna este caso mais que um teste de
/// classificação: se `carregar` tivesse trocado, a raiz teria mudado.
fn usuario_imagem_recusada_nao_custa_o_espaco() -> Resultado {
    use crate::usuario::programa::Falha;

    let antes = crate::arch::espaco_atual();

    // Oito bytes não são um cabeçalho ELF, e é a primeira conferência do
    // validador que os recusa — bem antes de qualquer mapeamento.
    let resultado = crate::usuario::programa::carregar(&[0u8; 8]);

    let depois = crate::arch::espaco_atual();
    if depois != antes {
        crate::log_error!("teste", "raiz {:#x} virou {:#x}", antes, depois);
        return Err("a carga recusada trocou o espaco de enderecos");
    }

    match resultado {
        Ok(_) => Err("oito bytes foram aceitos como um ELF"),
        Err(Falha::SemVolta(motivo)) => {
            crate::log_error!("teste", "classificada como sem volta: {}", motivo);
            Err("uma falha antes da troca foi classificada como sem volta")
        }
        Err(Falha::ProcessoIntacto(_)) => Ok(()),
    }
}

/// O banner do boot está desenhado no framebuffer da máquina.
///
/// # O que este caso acrescenta aos anteriores
///
/// Os três acima exercitam a aritmética de pixel sobre um buffer da pilha.
/// Eles passariam num kernel que nunca tocasse no framebuffer de verdade —
/// e o que pode dar errado ali é tudo que está entre a lógica e a tela: o
/// endereço que o bootloader entregou, a geometria que ele declarou, e a
/// escrita chegar mesmo à memória que o controlador de vídeo varre.
///
/// Numa máquina sem tela o caso não tem o que afirmar, e é [`sem_framebuffer`]
/// quem decide se essa ausência é legítima.
fn tela_banner_esta_na_tela_de_verdade() -> Resultado {
    let Some(tela) = crate::tela::tela() else {
        return sem_framebuffer();
    };

    // A faixa de acento ocupa as primeiras linhas; o fundo, o resto.
    let Some(topo) = tela.ler_pixel(0, 0) else {
        return Err("o canto da tela nao pode ser lido");
    };
    if topo != Cor::ACENTO {
        crate::log_error!(
            "teste",
            "o topo e {:02x}{:02x}{:02x}",
            topo.r,
            topo.g,
            topo.b
        );
        return Err("o topo da tela nao tem a faixa de acento");
    }

    // Bem abaixo da faixa, e no meio da tela, para não cair numa borda.
    let Some(fundo) = tela.ler_pixel(tela.largura / 2, tela.altura / 2) else {
        return Err("o centro da tela nao pode ser lido");
    };
    if fundo != Cor::FUNDO {
        crate::log_error!(
            "teste",
            "o centro e {:02x}{:02x}{:02x}",
            fundo.r,
            fundo.g,
            fundo.b
        );
        return Err("o centro da tela nao foi limpo");
    }

    Ok(())
}

// ===========================================================================
// Descrição da máquina
// ===========================================================================

fn regioes_de_memoria_sao_coerentes() -> Resultado {
    let mut invalida = false;
    crate::machine::com_regioes(|regiao| {
        if regiao.fim <= regiao.inicio {
            invalida = true;
        }
    });
    if invalida {
        return Err("regiao com fim menor ou igual ao inicio");
    }

    let mem = crate::machine::estatisticas();
    if mem.regioes == 0 {
        return Err("nenhuma regiao de memoria descoberta");
    }
    if mem.utilizavel == 0 {
        return Err("nenhuma memoria utilizavel");
    }
    // As duas partes que sabemos serem RAM cabem no que o firmware descreveu.
    // Não vale o contrário — o descrito inclui buracos de endereçamento que
    // não são memória nenhuma, e é por isso que ele não se chama "total".
    if mem.utilizavel + mem.bootloader > mem.descrito {
        return Err("a RAM conhecida excede o espaco descrito");
    }
    Ok(())
}

// ===========================================================================
// Alocador de frames
// ===========================================================================

fn frames_alocacao_alinhada_e_distinta() -> Resultado {
    const QUANTOS: usize = 8;
    let mut obtidos = [0u64; QUANTOS];

    for slot in obtidos.iter_mut() {
        match crate::frames::alocar() {
            Some(endereco) => *slot = endereco,
            None => return Err("alocador ficou sem frames"),
        }
    }

    let mut problema = None;
    for (i, &endereco) in obtidos.iter().enumerate() {
        if !endereco.is_multiple_of(crate::frames::TAMANHO_FRAME) {
            problema = Some("frame devolvido sem alinhamento");
        }
        // Entregar o mesmo frame duas vezes é a falha mais grave possível
        // neste módulo: dois donos escrevendo na mesma memória física.
        for &outro in obtidos.iter().skip(i + 1) {
            if endereco == outro {
                problema = Some("mesmo frame entregue duas vezes");
            }
        }
    }

    // Devolvemos tudo mesmo em caso de falha: um teste não deve vazar recursos
    // e distorcer os que vêm depois dele.
    for &endereco in &obtidos {
        crate::frames::liberar(endereco);
    }

    match problema {
        Some(motivo) => Err(motivo),
        None => Ok(()),
    }
}

fn frames_liberar_devolve_ao_contador() -> Resultado {
    let (antes, _) = crate::frames::estatisticas();

    let endereco = crate::frames::alocar().ok_or("alocador sem frames")?;
    let (durante, _) = crate::frames::estatisticas();
    if durante != antes - 1 {
        crate::frames::liberar(endereco);
        return Err("contador de livres nao caiu ao alocar");
    }
    if crate::frames::esta_livre(endereco) {
        crate::frames::liberar(endereco);
        return Err("frame alocado ainda consta como livre");
    }

    crate::frames::liberar(endereco);
    let (depois, _) = crate::frames::estatisticas();
    if depois != antes {
        return Err("contador de livres nao voltou ao liberar");
    }
    if !crate::frames::esta_livre(endereco) {
        return Err("frame liberado nao voltou a constar como livre");
    }
    Ok(())
}

/// Desreferenciar um ponteiro nulo precisa continuar falhando de forma
/// diagnosticável. Se o frame zero entrasse em circulação, uma escrita em
/// `null` corromperia dados legítimos em silêncio.
fn frames_frame_nulo_nunca_entregue() -> Resultado {
    if crate::frames::esta_livre(0) {
        return Err("frame do endereco zero esta em circulacao");
    }
    Ok(())
}

/// As faixas que cada arquitetura declara ocupadas — no ARM, a imagem do
/// kernel e o device tree — não podem estar livres.
///
/// No x86 não há faixas declaradas, porque o bootloader já as exclui do mapa;
/// lá este caso passa sem verificar nada, e isso é honesto: não há o que
/// verificar.
fn frames_faixas_reservadas_fora_de_circulacao() -> Resultado {
    let mut vazou = false;

    crate::arch::reservar_faixas(|inicio, fim| {
        let mut endereco = inicio & !(crate::frames::TAMANHO_FRAME - 1);
        while endereco < fim {
            if crate::frames::esta_livre(endereco) {
                vazou = true;
            }
            endereco += crate::frames::TAMANHO_FRAME;
        }
    });

    if vazou {
        Err("faixa reservada aparece como livre")
    } else {
        Ok(())
    }
}

fn frames_estatisticas_coerentes() -> Resultado {
    let (livres, rastreados) = crate::frames::estatisticas();
    if rastreados == 0 {
        return Err("nenhum frame rastreado");
    }
    if livres > rastreados {
        return Err("mais frames livres que rastreados");
    }
    if livres == 0 {
        return Err("nenhum frame livre apos o boot");
    }
    if !crate::frames::base().is_multiple_of(crate::frames::TAMANHO_FRAME) {
        return Err("base do alocador desalinhada");
    }
    Ok(())
}

// ===========================================================================
// Paginação
// ===========================================================================

/// Procura um endereço virtual sem tradução, para os testes de mapeamento.
///
/// Sondar em vez de fixar um endereço é o que mantém o teste válido nas duas
/// arquiteturas: no x86 o bootloader mapeia a memória física num deslocamento
/// que ele escolhe, e um endereço fixo poderia cair em cima dele.
fn endereco_virtual_livre() -> Option<u64> {
    // Abaixo de 512 GiB para caber nos 39 bits de endereço virtual que
    // configuramos no ARM, e alto o bastante para não colidir com o kernel.
    const BASE: u64 = 128 * 1024 * 1024 * 1024;

    (0..64).find_map(|i| {
        let candidato = BASE + i * crate::frames::TAMANHO_FRAME;
        crate::arch::traduzir(candidato)
            .is_none()
            .then_some(candidato)
    })
}

/// O código do kernel precisa estar mapeado — estamos executando nele.
fn paginacao_traduz_endereco_do_kernel() -> Resultado {
    let endereco = CASOS.as_ptr() as u64;
    match crate::arch::traduzir(endereco) {
        Some(_) => Ok(()),
        None => {
            crate::log_error!("teste", "endereco {:#x} sem traducao", endereco);
            Err("dados do kernel aparecem como nao mapeados")
        }
    }
}

/// O teste central da paginação: prova que o mapeamento roteia de verdade.
///
/// Escrevemos pelo endereço virtual recém-mapeado e lemos pelo caminho físico,
/// que é independente. Se os dois concordarem, a tradução levou a escrita
/// exatamente ao frame pretendido — não a um lugar qualquer que por acaso
/// aceitou a escrita.
fn paginacao_escreve_e_le_pelo_caminho_fisico() -> Resultado {
    const PADRAO: u64 = 0x5EED_1234_ABCD_9876;

    let virtual_ = endereco_virtual_livre().ok_or("nenhum endereco virtual livre")?;

    let frame = match crate::paginacao::mapear_novo(virtual_, crate::arch::Permissoes::DADOS) {
        Ok(frame) => frame,
        Err(motivo) => {
            crate::log_error!("teste", "mapear falhou: {}", motivo);
            return Err("mapeamento recusado");
        }
    };

    // SAFETY: acabamos de mapear esta página com permissão de escrita, e ela
    // não é usada por mais ninguém.
    unsafe { core::ptr::write_volatile(virtual_ as *mut u64, PADRAO) };

    // SAFETY: o frame está alocado a nós, e `acesso_fisico` devolve o endereço
    // virtual por onde o kernel enxerga memória física.
    let lido = unsafe { core::ptr::read_volatile(crate::arch::acesso_fisico(frame) as *const u64) };

    let desmapeou = crate::paginacao::desmapear_e_liberar(virtual_).is_ok();

    if !desmapeou {
        return Err("desmapear falhou");
    }
    if lido != PADRAO {
        crate::log_error!("teste", "esperado {:#x}, lido {:#x}", PADRAO, lido);
        return Err("escrita pela pagina nao chegou ao frame");
    }
    Ok(())
}

fn paginacao_desmapear_remove_traducao() -> Resultado {
    let virtual_ = endereco_virtual_livre().ok_or("nenhum endereco virtual livre")?;

    let mapeado = crate::paginacao::mapear_novo(virtual_, crate::arch::Permissoes::DADOS);
    let mapeou = mapeado.is_ok();
    let traduziu = mapeado.map(|frame| crate::arch::traduzir(virtual_) == Some(frame)) == Ok(true);
    let desmapeou = mapeou && crate::paginacao::desmapear_e_liberar(virtual_).is_ok();
    let sumiu = crate::arch::traduzir(virtual_).is_none();

    if !mapeou {
        return Err("mapeamento recusado");
    }
    if !traduziu {
        return Err("traducao nao aponta para o frame mapeado");
    }
    if !desmapeou {
        return Err("desmapear falhou");
    }
    if !sumiu {
        // Se a tradução sobrevive ao desmapeamento, a TLB não foi invalidada —
        // e memória liberada continuaria acessível, que é uma falha de
        // isolamento, não só um bug de contabilidade.
        return Err("traducao sobreviveu ao desmapeamento");
    }
    Ok(())
}

/// Mapear por cima de algo já mapeado precisa ser recusado, não silenciosamente
/// aceito: sobrescrever um descritor em uso deixa o frame anterior órfão e dá
/// ao novo dono acesso à memória do antigo.
fn paginacao_recusa_mapeamento_duplicado() -> Resultado {
    let virtual_ = endereco_virtual_livre().ok_or("nenhum endereco virtual livre")?;

    let primeiro = crate::paginacao::mapear_novo(virtual_, crate::arch::Permissoes::DADOS);
    let segundo = crate::paginacao::mapear_novo(virtual_, crate::arch::Permissoes::DADOS);

    let _ = crate::paginacao::desmapear_e_liberar(virtual_);

    if primeiro.is_err() {
        return Err("primeiro mapeamento recusado");
    }
    if segundo.is_ok() {
        return Err("mapeamento duplicado foi aceito");
    }
    Ok(())
}

/// Regressão do bug que derrubava o kernel pelo canal do agente.
///
/// O comando `paging.translate` aceita um inteiro arbitrário vindo de fora.
/// No x86, `VirtAddr::new` entra em pânico diante de um endereço não-canônico
/// — e um pânico no kernel é terminal. No ARM o sintoma era outro e mais
/// traiçoeiro: o cálculo de índices mascarava os bits altos, e um endereço
/// impossível "dobrava" para dentro do espaço válido, devolvendo uma tradução
/// falsa.
///
/// Chegar ao fim desta função já é metade do teste: antes da correção, a
/// primeira linha matava o sistema.
fn paginacao_endereco_impossivel_nao_derruba() -> Resultado {
    // Bit 63 ligado com os bits 62..48 zerados: não é extensão de sinal, logo
    // não é canônico no x86; e está muito além dos 39 bits do ARM.
    const IMPOSSIVEIS: [u64; 3] = [1 << 63, 0x0000_8000_0000_0000, 0xFFFF_FFFF_FFFF_F000];

    for endereco in IMPOSSIVEIS {
        if crate::arch::traduzir(endereco).is_some() {
            crate::log_error!("teste", "{:#x} reportado como mapeado", endereco);
            return Err("endereco impossivel reportado como mapeado");
        }
    }
    Ok(())
}

/// Endereços desalinhados precisam ser recusados, não arredondados.
///
/// As duas APIs de hardware arredondam para baixo em silêncio. Quem pedisse
/// para mapear `frame + 8` receberia um mapeamento para `frame` e passaria a
/// escrever oito bytes antes do pretendido — corrupção que só aparece muito
/// depois da causa.
fn paginacao_recusa_desalinhado() -> Resultado {
    let virtual_ = endereco_virtual_livre().ok_or("nenhum endereco virtual livre")?;
    let frame = crate::frames::alocar().ok_or("sem frames")?;

    // SAFETY: as três chamadas são rejeitadas pela validação antes de tocar em
    // qualquer tabela, então o contrato de "frame nao em uso" nunca chega a
    // ser exercido. Se alguma passasse, o teste falha e nós a desfazemos.
    let resultados = unsafe {
        [
            crate::arch::mapear_frame(virtual_ + 8, frame, crate::arch::Permissoes::DADOS),
            crate::arch::mapear_frame(virtual_, frame + 8, crate::arch::Permissoes::DADOS),
            crate::arch::mapear_frame(1 << 63, frame, crate::arch::Permissoes::DADOS),
        ]
    };

    let algum_passou = resultados.iter().any(|r| r.is_ok());
    if algum_passou {
        // Limpeza defensiva: se a validação falhou, não deixamos mapeamento
        // pendurado para confundir os testes seguintes.
        let _ = crate::arch::desmapear(virtual_ + 8);
        let _ = crate::arch::desmapear(virtual_);
    }
    crate::frames::liberar(frame);

    if algum_passou {
        return Err("endereco invalido foi aceito");
    }
    Ok(())
}

// ===========================================================================
// Heap
// ===========================================================================

/// O que `heap.stats` relata fecha com o que o alocador tem.
///
/// # Por que um invariante, e não um número esperado
///
/// Porque o número certo depende de tudo o que o kernel alocou até aqui, e um
/// teste que o fixasse quebraria a cada linha de código nova. O que não muda
/// é a soma: cada byte do heap ou está entregue a alguém ou está na lista
/// livre, e `alocado + livre` tem de dar exatamente `total`.
///
/// # O que ele pega
///
/// Contabilidade que escorrega. `dealloc` desconta com `saturating_sub`, que
/// é o certo a fazer num caminho onde não há a quem reclamar — e é também o
/// que **esconde** o descompasso, grudando em zero em vez de aparecer. Um
/// tamanho ajustado diferente entre alocar e liberar, um caminho de erro que
/// esquece de descontar, uma sobra que se perde numa divisão de bloco: todos
/// aparecem aqui, e em nenhum outro lugar.
///
/// A conferência acontece com uma alocação viva de propósito, para que o caso
/// não passe por trivialidade num heap intocado.
fn heap_relatorio_fecha() -> Resultado {
    fn conferir(quando: &str) -> Resultado {
        let e = crate::heap::estatisticas();
        if e.alocado + e.livre != e.total {
            crate::log_error!(
                "teste",
                "{}: alocado {} + livre {} != total {}",
                quando,
                e.alocado,
                e.livre,
                e.total
            );
            return Err("o relatorio do heap nao fecha com a lista livre");
        }
        if e.maior_bloco > e.livre {
            return Err("o maior bloco livre e maior que todo o espaco livre");
        }
        Ok(())
    }

    conferir("em repouso")?;

    {
        let _ocupa = alloc::vec![0u8; 4096];
        conferir("com uma alocacao viva")?;
    }

    conferir("depois de liberar")
}

fn heap_box_aloca_e_libera() -> Resultado {
    let antes = crate::heap::estatisticas();

    {
        let valor = alloc::boxed::Box::new(0xC0FFEEu64);
        if *valor != 0xC0FFEE {
            return Err("valor lido do heap esta corrompido");
        }
    }

    let depois = crate::heap::estatisticas();
    if depois.livre != antes.livre {
        crate::log_error!("teste", "livre {} -> {}", antes.livre, depois.livre);
        return Err("memoria nao voltou apos o drop");
    }
    Ok(())
}

fn heap_vec_cresce() -> Resultado {
    let mut numeros = alloc::vec::Vec::new();
    for i in 0..500u64 {
        numeros.push(i);
    }

    // Um `Vec` que cresce realoca várias vezes, então este caso exercita o
    // ciclo de alocar-copiar-liberar, e não só alocações isoladas.
    let soma: u64 = numeros.iter().sum();
    let esperado: u64 = (0..500u64).sum();
    if soma != esperado {
        return Err("conteudo do vetor nao sobreviveu as realocacoes");
    }
    Ok(())
}

fn heap_string_formata() -> Resultado {
    let texto = alloc::format!("arch={} paginas={}", crate::arch::nome(), 4);
    if !texto.starts_with("arch=") || !texto.contains("paginas=4") {
        crate::log_error!("teste", "obtido: {}", texto);
        return Err("formatacao com alocacao produziu texto errado");
    }
    Ok(())
}

/// O caso que separa um alocador de verdade de um *bump allocator*.
///
/// Um alocador que só avança um ponteiro consegue atender mil alocações
/// seguidas se cada uma for liberada antes da próxima — mas falha aqui,
/// porque o bloco de vida longa impede que o ponteiro volte. Só reaproveitando
/// memória liberada é possível passar.
fn heap_reaproveita_memoria_liberada() -> Resultado {
    let longevo = alloc::boxed::Box::new(0xABCDu64);

    for i in 0..1000u64 {
        let efemero = alloc::boxed::Box::new(i);
        if *efemero != i {
            return Err("valor corrompido durante o ciclo");
        }
    }

    if *longevo != 0xABCD {
        return Err("bloco de vida longa foi corrompido pelo ciclo");
    }
    Ok(())
}

/// Sem fusão de blocos adjacentes, o heap se estilhaça: sobra memória livre
/// mas nenhuma peça contígua grande o bastante. Este caso verifica que três
/// blocos vizinhos voltam a ser um só.
fn heap_funde_blocos_adjacentes() -> Resultado {
    let antes = crate::heap::estatisticas();

    {
        let a = alloc::boxed::Box::new([1u8; 512]);
        let b = alloc::boxed::Box::new([2u8; 512]);
        let c = alloc::boxed::Box::new([3u8; 512]);
        // Impede que o compilador descarte as alocações por não serem usadas.
        core::hint::black_box((&a, &b, &c));
    }

    let depois = crate::heap::estatisticas();

    if depois.livre != antes.livre {
        return Err("memoria nao voltou por completo");
    }
    if depois.maior_bloco != antes.maior_bloco {
        crate::log_error!(
            "teste",
            "maior bloco {} -> {} (livre {})",
            antes.maior_bloco,
            depois.maior_bloco,
            depois.livre
        );
        return Err("blocos adjacentes nao foram fundidos");
    }
    Ok(())
}

fn heap_respeita_alinhamento() -> Resultado {
    for expoente in 3..=9u32 {
        let alinhamento = 1usize << expoente;
        let layout =
            core::alloc::Layout::from_size_align(64, alinhamento).map_err(|_| "layout invalido")?;

        // Chamamos o alocador direto: por `alloc::alloc` o LLVM poderia
        // eliminar o par alocar/liberar e nos deixar testando o otimizador.
        let ponteiro = crate::heap::tentar_alocar(layout);
        if ponteiro.is_null() {
            return Err("alocacao alinhada falhou");
        }

        let alinhado = (ponteiro as usize).is_multiple_of(alinhamento);

        // SAFETY: devolvemos o mesmo ponteiro com o mesmo layout.
        unsafe { crate::heap::devolver(ponteiro, layout) };

        if !alinhado {
            crate::log_error!("teste", "alinhamento {} nao respeitado", alinhamento);
            return Err("ponteiro nao respeita o alinhamento pedido");
        }
    }
    Ok(())
}

/// O contrato do `GlobalAlloc` manda sinalizar falha com ponteiro nulo, nunca
/// com pânico — quem chama essas funções é o compilador, e um pânico ali seria
/// terminal.
///
/// Este caso precisa falar com o alocador diretamente. Por `alloc::alloc`, o
/// LLVM elimina um par alocar/liberar cujo resultado só é comparado com nulo e
/// assume que a alocação teve sucesso, o que fazia o teste passar em debug e
/// falhar em release — medindo o otimizador, não o alocador.
fn heap_falha_devolve_nulo() -> Resultado {
    let layout = core::alloc::Layout::from_size_align(crate::heap::HEAP_TAMANHO * 2, 8)
        .map_err(|_| "layout invalido")?;

    let ponteiro = crate::heap::tentar_alocar(layout);

    if ponteiro.is_null() {
        Ok(())
    } else {
        // SAFETY: mesmo ponteiro, mesmo layout.
        unsafe { crate::heap::devolver(ponteiro, layout) };
        Err("pedido maior que o heap foi atendido")
    }
}

fn heap_estatisticas_coerentes() -> Resultado {
    let e = crate::heap::estatisticas();
    if e.total == 0 {
        return Err("heap sem tamanho; init falhou?");
    }
    if e.livre > e.total {
        return Err("livre maior que o total");
    }
    if e.maior_bloco > e.livre {
        return Err("maior bloco maior que o total livre");
    }
    if e.liberacoes > e.alocacoes {
        return Err("mais liberacoes que alocacoes");
    }
    Ok(())
}

/// Mapear e desmapear não pode custar memória permanente.
///
/// Criar um mapeamento novo numa região virgem cria também as tabelas
/// intermediárias que levam até ele. Se elas não forem devolvidas quando
/// ficam vazias, cada região já visitada custa frames para sempre — um
/// vazamento que cresce com o uso e só aparece muito depois.
fn paginacao_nao_vaza_tabelas() -> Resultado {
    let virtual_ = endereco_virtual_livre().ok_or("nenhum endereco virtual livre")?;

    let (antes, _) = crate::frames::estatisticas();

    crate::paginacao::mapear_novo(virtual_, crate::arch::Permissoes::DADOS)
        .map_err(|_| "mapeamento recusado")?;
    crate::paginacao::desmapear_e_liberar(virtual_).map_err(|_| "desmapeamento falhou")?;

    let (depois, _) = crate::frames::estatisticas();

    if depois != antes {
        crate::log_error!(
            "teste",
            "frames livres {} -> {} ({} nao voltaram)",
            antes,
            depois,
            antes - depois
        );
        return Err("tabelas intermediarias nao foram recuperadas");
    }
    Ok(())
}

// ===========================================================================
// Estouro de pilha
// ===========================================================================

/// Recursão que consome pilha até estourá-la.
///
/// # Contra as otimizações do compilador
///
/// O inimigo deste teste é o próprio otimizador: se ele conseguir eliminar a
/// recursão, a função vira um laço que roda para sempre sem consumir pilha
/// nenhuma, e o teste espera pela eternidade por um estouro que nunca vem.
///
/// A primeira versão deste código tentava evitar isso usando o resultado
/// *depois* da chamada, com `consumir_pilha(n + 1) + n`. Não bastou, e a razão
/// é instrutiva: o LLVM reconhece esse formato exato — recursão cujo retorno
/// entra numa operação associativa — e o converte num laço com acumulador. Em
/// debug o teste passava; em release, pendurava.
///
/// A versão atual fecha as duas portas de uma vez. Cada quadro reserva um
/// bloco de pilha de verdade, e esse bloco é **escrito de forma volátil depois
/// da chamada recursiva**. Escrita volátil não pode ser eliminada nem
/// reordenada, e o bloco precisa continuar vivo do outro lado da chamada —
/// então o quadro tem de existir, e a chamada não está em posição de cauda
/// nem em forma de acumulador.
#[inline(never)]
#[allow(unconditional_recursion)]
fn consumir_pilha(profundidade: u64) -> u64 {
    // 128 bytes por quadro: acelera o estouro sem arriscar pular por cima da
    // guard page, que tem 4 KiB.
    let mut bloco = [0u64; 16];

    // SAFETY: escrita e leitura de uma variável local viva, deste quadro.
    unsafe {
        core::ptr::write_volatile(&mut bloco[0], profundidade);
        let eco = consumir_pilha(core::ptr::read_volatile(&bloco[0]) + 1);
        core::ptr::write_volatile(&mut bloco[15], eco);
        core::ptr::read_volatile(&bloco[15])
    }
}

/// O caso final: prova que um estouro de pilha é detectado.
///
/// Precisa ser o último, e por um motivo estrutural: não há como voltar dele.
/// A pilha que permitiria retornar é justamente a que estourou. O desfecho de
/// sucesso acontece *dentro* do handler de falha, que reconhece a falha
/// esperada e encerra o emulador — ver [`crate::traps::esperar`].
///
/// É também o único caso que testa as três peças de uma vez: a guard page
/// existe, a falha é entregue, e o handler tem uma pilha intacta para rodar.
/// Sem a terceira, o próprio handler faltaria ao empilhar o contexto.
fn estouro_de_pilha_e_detectado() -> ! {
    crate::serial_print!("  {:<42} ", "pilha: estouro e detectado");

    crate::traps::esperar(crate::arch::falha_de_estouro_de_pilha());
    let _ = consumir_pilha(0);

    // Inalcançável se a guard page funcionar.
    crate::serial_println!("FALHOU -- a recursao terminou sem estourar a pilha");
    crate::qemu::encerrar(crate::qemu::Resultado::Falha)
}

// ===========================================================================
// Registro e execução
// ===========================================================================

// ===========================================================================
// Tarefas — fila, executor e wakers
// ===========================================================================

fn fila_preserva_ordem() -> Resultado {
    let fila: crate::tarefas::fila::Fila<u8, 4> = crate::tarefas::fila::Fila::nova();

    for b in [1u8, 2, 3] {
        fila.enfileirar(b)
            .map_err(|_| "fila recusou item com espaco")?;
    }

    for esperado in [1u8, 2, 3] {
        match fila.desenfileirar() {
            Some(b) if b == esperado => {}
            Some(b) => {
                crate::log_error!("teste", "esperado {}, veio {}", esperado, b);
                return Err("fila entregou fora de ordem");
            }
            None => return Err("fila esvaziou cedo demais"),
        }
    }

    if fila.desenfileirar().is_some() {
        return Err("fila entregou item que nao foi enfileirado");
    }
    if !fila.vazia() {
        return Err("fila diz estar cheia depois de esvaziada");
    }
    Ok(())
}

/// O caso que garante que o excesso vira contador, e não corrupção.
///
/// Uma fila que sobrescreve em silêncio quando enche é pior que uma que
/// descarta: o cliente recebe bytes fora de ordem e a falha aparece longe da
/// causa.
fn fila_cheia_descarta_e_conta() -> Resultado {
    let fila: crate::tarefas::fila::Fila<u8, 2> = crate::tarefas::fila::Fila::nova();

    fila.enfileirar(10).map_err(|_| "recusou o primeiro")?;
    fila.enfileirar(20).map_err(|_| "recusou o segundo")?;

    if fila.enfileirar(30).is_ok() {
        return Err("fila aceitou item alem da capacidade");
    }
    if fila.descartados() != 1 {
        return Err("descarte nao foi contabilizado");
    }

    // O conteúdo precisa ter sobrevivido intacto ao descarte.
    if fila.desenfileirar() != Some(10) || fila.desenfileirar() != Some(20) {
        return Err("descarte corrompeu o conteudo da fila");
    }
    Ok(())
}

/// A fila é circular: depois de dar a volta, os índices precisam continuar
/// corretos. É onde um erro de aritmética modular se esconderia.
fn fila_da_a_volta() -> Resultado {
    let fila: crate::tarefas::fila::Fila<u8, 3> = crate::tarefas::fila::Fila::nova();

    for ciclo in 0..4u8 {
        for i in 0..3u8 {
            fila.enfileirar(ciclo * 10 + i)
                .map_err(|_| "fila recusou item com espaco")?;
        }
        for i in 0..3u8 {
            if fila.desenfileirar() != Some(ciclo * 10 + i) {
                return Err("fila perdeu a ordem ao dar a volta");
            }
        }
    }
    Ok(())
}

fn tarefa_roda_ate_o_fim() -> Resultado {
    static CONCLUIU: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    async fn corpo() {
        CONCLUIU.store(true, core::sync::atomic::Ordering::SeqCst);
    }

    CONCLUIU.store(false, core::sync::atomic::Ordering::SeqCst);

    let mut executor = crate::tarefas::executor::Executor::novo();
    executor.lancar(crate::tarefas::Tarefa::nova("teste-simples", corpo()));
    executor.rodar_ate_esvaziar(8)?;

    if !CONCLUIU.load(core::sync::atomic::Ordering::SeqCst) {
        return Err("a tarefa nao chegou a rodar");
    }
    if executor.vivas() != 0 {
        return Err("tarefa concluida nao foi removida do executor");
    }
    Ok(())
}

/// Duas tarefas cedendo mutuamente precisam se intercalar.
///
/// É a evidência direta de que há concorrência de verdade: se o executor
/// rodasse cada tarefa até o fim antes de olhar para a outra, a sequência
/// gravada seria `aabb` em vez de `abab`.
fn tarefas_se_intercalam() -> Resultado {
    static SEQUENCIA: spin::Mutex<[u8; 8]> = spin::Mutex::new([0; 8]);
    static ESCRITOS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

    fn anotar(marca: u8) {
        let i = ESCRITOS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        if i < 8 {
            SEQUENCIA.lock()[i] = marca;
        }
    }

    async fn corpo(marca: u8) {
        for _ in 0..2 {
            anotar(marca);
            crate::tarefas::ceder().await;
        }
    }

    ESCRITOS.store(0, core::sync::atomic::Ordering::SeqCst);
    *SEQUENCIA.lock() = [0; 8];

    let mut executor = crate::tarefas::executor::Executor::novo();
    executor.lancar(crate::tarefas::Tarefa::nova("teste-a", corpo(b'a')));
    executor.lancar(crate::tarefas::Tarefa::nova("teste-b", corpo(b'b')));
    executor.rodar_ate_esvaziar(16)?;

    let sequencia = *SEQUENCIA.lock();
    if &sequencia[..4] != b"abab" {
        crate::log_error!(
            "teste",
            "sequencia obtida: {}",
            core::str::from_utf8(&sequencia[..4]).unwrap_or("?")
        );
        return Err("tarefas nao se intercalaram nos pontos de cessao");
    }
    Ok(())
}

/// O caso central do artigo: uma tarefa dorme esperando um evento externo, e
/// só volta a rodar quando **alguém a acorda**.
///
/// A prova está em duas partes. Primeiro rodamos o executor com a fila de
/// entrada vazia e exigimos que ele *não* consiga terminar — se conseguisse, a
/// tarefa não estaria realmente esperando. Depois injetamos o byte e exigimos
/// que ela termine — o que só acontece se o waker registrado tiver funcionado.
fn waker_acorda_tarefa_bloqueada() -> Resultado {
    static RECEBIDO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

    async fn corpo() {
        let byte = crate::tarefas::entrada::proximo_byte().await;
        RECEBIDO.store(byte as u64 + 1, core::sync::atomic::Ordering::SeqCst);
    }

    // A fila é compartilhada com o hardware: qualquer resíduo faria a tarefa
    // completar sem nunca ter esperado, e o teste passaria sem testar nada.
    while crate::tarefas::entrada::retirar().is_some() {}
    RECEBIDO.store(0, core::sync::atomic::Ordering::SeqCst);

    let mut executor = crate::tarefas::executor::Executor::novo();
    executor.lancar(crate::tarefas::Tarefa::nova("teste-espera", corpo()));

    if executor.rodar_ate_esvaziar(2).is_ok() {
        return Err("a tarefa terminou sem que nenhum byte tivesse chegado");
    }
    if executor.vivas() != 1 {
        return Err("a tarefa sumiu sem concluir");
    }

    crate::tarefas::entrada::injetar(b'Z').map_err(|_| "fila de entrada cheia")?;
    executor.rodar_ate_esvaziar(8)?;

    if RECEBIDO.load(core::sync::atomic::Ordering::SeqCst) != b'Z' as u64 + 1 {
        return Err("a tarefa nao recebeu o byte injetado");
    }
    Ok(())
}

/// O mesmo mecanismo, agora acordado pelo hardware de verdade.
///
/// O waker é registrado pela tarefa e acionado de dentro do handler do timer.
/// Nada no caminho é simulado: é a interrupção física que traz a tarefa de
/// volta.
fn relogio_acorda_tarefa() -> Resultado {
    const ESPERA: u64 = 3;
    static ACORDOU_EM: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

    async fn corpo() {
        crate::tarefas::relogio::por_ticks(ESPERA).await;
        ACORDOU_EM.store(crate::tempo::ticks(), core::sync::atomic::Ordering::SeqCst);
    }

    ACORDOU_EM.store(0, core::sync::atomic::Ordering::SeqCst);
    let inicio = crate::tempo::ticks();

    let mut executor = crate::tarefas::executor::Executor::novo();
    executor.lancar(crate::tarefas::Tarefa::nova("teste-sono", corpo()));
    executor.rodar_ate_esvaziar(64)?;

    let acordou = ACORDOU_EM.load(core::sync::atomic::Ordering::SeqCst);
    if acordou < inicio + ESPERA {
        crate::log_error!(
            "teste",
            "acordou em {} tiques, esperado ao menos {}",
            acordou,
            inicio + ESPERA
        );
        return Err("a tarefa acordou antes do prazo");
    }
    Ok(())
}

/// Dormir precisa custar quase nada em repolagens.
///
/// Este é o caso que distingue um executor com wakers de um que só finge ter:
/// os dois passariam em todos os testes acima, mas o ingênuo repollaria a
/// tarefa adormecida milhares de vezes por segundo. Contamos os avanços e
/// exigimos que sejam poucos.
/// Encher a fila de prontas e o inventário aparece no relatório.
///
/// # O que este caso protege
///
/// Os dois tetos falhavam em silêncio durável. A fila de prontas cheia
/// descarta a entrada da tarefa, e a tarefa nunca roda — no lançamento ela não
/// roda nenhuma vez, num despertar ela para de rodar. A única prova era uma
/// linha de log, num anel de cento e vinte e oito registros que dá a volta: um
/// minuto depois não havia mais nada dizendo por que aquela tarefa estava
/// parada.
///
/// O inventário cheio é mais brando e igualmente mudo: a tarefa roda, mas a
/// linha dela não sai em `tasks.list`, e a lista fica mais curta que a verdade
/// sem dizer que ficou.
///
/// A fila de bytes do agente já tinha o contador dela exposto como
/// `input.dropped`, com um comentário explicando por que um valor diferente de
/// zero ali importa. Estes dois tinham a mesma necessidade e nenhum número.
///
/// # Por que os números exatos
///
/// Porque um caso que enchesse "com muitas tarefas" testaria o chute. Os dois
/// tetos vêm do módulo, e as contas saem deles: lançar `prontas + 1` tarefas
/// derruba exatamente uma na fila, e deixa `prontas + 1 - inventario` fora do
/// inventário, já que nenhuma delas terminou ainda.
fn tarefa_tetos_cheios_aparecem() -> Resultado {
    use crate::tarefas::executor;

    async fn nada() {}

    let prontas = executor::capacidade_da_fila_de_prontas();
    let inventario = executor::capacidade_do_inventario();
    let antes = executor::estatisticas();

    let mut e = executor::Executor::novo();
    for _ in 0..prontas + 1 {
        e.lancar(crate::tarefas::Tarefa::nova("teste-teto", nada()));
    }

    let depois = executor::estatisticas();

    let na_fila = depois.nunca_agendadas - antes.nunca_agendadas;
    if na_fila != 1 {
        crate::log_error!(
            "teste",
            "{} tarefas ficaram sem agendar, esperava 1",
            na_fila
        );
        return Err("a fila de prontas cheia nao foi contabilizada");
    }

    let fora = depois.fora_do_inventario - antes.fora_do_inventario;
    let esperado = (prontas + 1 - inventario) as u64;
    if fora != esperado {
        crate::log_error!(
            "teste",
            "{} tarefas fora do inventario, esperava {}",
            fora,
            esperado
        );
        return Err("o inventario cheio nao foi contabilizado");
    }

    // Drenar o que coube, para devolver as vagas do inventário aos casos
    // seguintes. O veredito é ignorado de propósito: o executor **não** tem
    // como esvaziar, e é isso que vem a seguir.
    let _ = e.rodar_ate_esvaziar(prontas * 2);

    // A prova do que a perda significa. A tarefa que não entrou na fila
    // continua registrada e viva, e não existe caminho que a faça rodar — não
    // há quem a enfileire, porque enfileirá-la era o passo que falhou. Uma
    // tarefa sobrando aqui é exatamente o que `never_scheduled` conta, vista
    // do outro lado.
    if e.vivas() != 1 {
        crate::log_error!("teste", "{} tarefas vivas, esperava 1", e.vivas());
        return Err("a tarefa que ficou fora da fila deveria continuar viva e parada");
    }

    Ok(())
}

fn tarefa_adormecida_nao_e_repollada() -> Resultado {
    const ESPERA: u64 = 5;
    // Uma repolagem para registrar o sono, uma para confirmar que venceu, e
    // folga para um despertar espúrio no limiar do tique.
    const TETO_DE_AVANCOS: u64 = 4;

    async fn corpo() {
        crate::tarefas::relogio::por_ticks(ESPERA).await;
    }

    let antes = crate::tarefas::executor::estatisticas().avancos;

    let mut executor = crate::tarefas::executor::Executor::novo();
    executor.lancar(crate::tarefas::Tarefa::nova("teste-ocioso", corpo()));
    executor.rodar_ate_esvaziar(64)?;

    let avancos = crate::tarefas::executor::estatisticas().avancos - antes;
    if avancos > TETO_DE_AVANCOS {
        crate::log_error!("teste", "{} avancos para dormir {} tiques", avancos, ESPERA);
        return Err("tarefa adormecida foi repollada demais");
    }
    Ok(())
}

/// Uma espera em milissegundos precisa ser convertida para tiques sem
/// arredondar *para baixo*.
///
/// Arredondar para baixo faria `por_ms` dormir menos que o pedido, e um pedido
/// menor que um tique inteiro viraria "não dorme nada" — transformando uma
/// espera curta num laço de espera ativa.
fn dormir_em_ms_arredonda_para_cima() -> Resultado {
    const PEDIDO_MS: u64 = 25;
    static ACORDOU_EM: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

    async fn corpo() {
        crate::tarefas::relogio::por_ms(PEDIDO_MS).await;
        ACORDOU_EM.store(crate::tempo::ticks(), core::sync::atomic::Ordering::SeqCst);
    }

    let hz = crate::tempo::frequencia_hz() as u64;
    if hz == 0 {
        return Err("sem timer configurado");
    }
    // A mesma conta que `por_ms` faz, derivada da frequência real do timer e
    // não de um 100 Hz presumido.
    let esperado = (PEDIDO_MS * hz).div_ceil(1000).max(1);

    ACORDOU_EM.store(0, core::sync::atomic::Ordering::SeqCst);
    let inicio = crate::tempo::ticks();

    let mut executor = crate::tarefas::executor::Executor::novo();
    executor.lancar(crate::tarefas::Tarefa::nova("teste-ms", corpo()));
    executor.rodar_ate_esvaziar(64)?;

    let decorridos = ACORDOU_EM.load(core::sync::atomic::Ordering::SeqCst) - inicio;
    if decorridos < esperado {
        crate::log_error!(
            "teste",
            "dormiu {} tiques, esperado ao menos {}",
            decorridos,
            esperado
        );
        return Err("por_ms dormiu menos que o pedido");
    }
    Ok(())
}

/// Uma tarefa encerrada precisa devolver sua vaga na tabela de dormentes.
///
/// Sem isso, a tabela se esgotaria depois de algumas dezenas de esperas e
/// todas as seguintes cairiam em espera ativa — uma degradação silenciosa,
/// que só apareceria como "o sistema fica lento com o tempo".
fn dormentes_devolvem_a_vaga() -> Resultado {
    async fn corpo() {
        crate::tarefas::relogio::por_ticks(1).await;
    }

    // Bem mais que o tamanho da tabela: se as vagas não fossem devolvidas,
    // as últimas rodadas não teriam onde registrar.
    for _ in 0..24 {
        let mut executor = crate::tarefas::executor::Executor::novo();
        executor.lancar(crate::tarefas::Tarefa::nova("teste-vaga", corpo()));
        executor.rodar_ate_esvaziar(32)?;
    }
    Ok(())
}

// ===========================================================================
// Robustez descoberta em revisão
// ===========================================================================

/// Uma região degenerada não pode entrar no mapa da máquina.
///
/// O caso existe porque uma região com `fim <= inicio` envenena tudo a
/// jusante: o alocador de frames calcula uma janela sem sentido, e a montagem
/// do mapa de identidade no ARM faz `fim - 1`, que numa região com `fim == 0`
/// entra em underflow — pânico em debug, e em release um índice gigante que
/// mapearia meio espaço de endereços como RAM.
fn machine_recusa_regiao_degenerada() -> Resultado {
    use crate::machine::{Regiao, TipoRegiao};

    let antes = crate::machine::estatisticas().regioes;
    let descartadas_antes = crate::machine::regioes_descartadas();

    // Tamanho zero.
    crate::machine::adicionar_regiao(Regiao {
        inicio: 0x1_0000,
        fim: 0x1_0000,
        tipo: TipoRegiao::Utilizavel,
    });
    // Invertida, como sairia de uma soma que transbordou na origem.
    crate::machine::adicionar_regiao(Regiao {
        inicio: 0x2_0000,
        fim: 0,
        tipo: TipoRegiao::Utilizavel,
    });

    let depois = crate::machine::estatisticas().regioes;
    if depois != antes {
        crate::log_error!("teste", "{} regioes -> {}", antes, depois);
        return Err("regiao degenerada entrou no mapa");
    }
    if crate::machine::regioes_descartadas() != descartadas_antes + 2 {
        return Err("descarte de regiao degenerada nao foi contabilizado");
    }
    Ok(())
}

/// Contabilizar uma falha não pode depender de conseguir a trava.
///
/// É o caminho que roda dentro de handlers de exceção. Uma exceção acontece em
/// qualquer instrução — inclusive numa que já segure a trava de `traps` —, e
/// mascarar interrupções não impede exceções síncronas. Se `registrar`
/// bloqueasse, o kernel travaria em silêncio exatamente quando deveria relatar
/// a falha.
///
/// Aqui seguramos a trava e chamamos `registrar` de dentro: se ela bloquear, o
/// teste pendura e o teto do xtask o mata — que é o sintoma que queremos
/// impedir de voltar.
fn traps_registrar_nao_bloqueia() -> Resultado {
    let total_antes = crate::traps::total();
    let perdidos_antes = crate::traps::detalhes_perdidos();

    // Simula a exceção acontecendo com a trava na mão de código interrompido.
    let seq = crate::traps::com_trava_ocupada(|| {
        crate::traps::registrar("teste_sintetico", 0xC0FFEE, Some(0x1234), 0)
    });

    if crate::traps::total() != total_antes + 1 {
        return Err("o total de falhas nao avancou");
    }
    if seq != total_antes {
        return Err("o numero de sequencia nao corresponde ao total anterior");
    }
    // O detalhamento tinha de ser pulado, e a perda contabilizada.
    if crate::traps::detalhes_perdidos() != perdidos_antes + 1 {
        return Err("a perda de detalhamento nao foi contabilizada");
    }
    Ok(())
}

/// Com a trava livre, o detalhamento precisa de fato ser gravado.
///
/// Sem este par, o caso acima passaria com uma `registrar` que nunca grava
/// nada.
fn traps_registrar_grava_detalhe() -> Resultado {
    let perdidos_antes = crate::traps::detalhes_perdidos();
    let seq = crate::traps::registrar("teste_detalhado", 0xBEEF, Some(0x99), 7);

    if crate::traps::detalhes_perdidos() != perdidos_antes {
        return Err("perdeu detalhamento com a trava livre");
    }
    match crate::traps::ultima() {
        Some(f) if f.nome == "teste_detalhado" && f.pc == 0xBEEF && f.seq == seq => Ok(()),
        Some(f) => {
            crate::log_error!(
                "teste",
                "ultima falha veio como `{}` pc={:#x}",
                f.nome,
                f.pc
            );
            Err("a ultima falha registrada nao confere")
        }
        None => Err("nenhuma falha registrada"),
    }
}

/// Dormir sem timer não pode ser dormir para sempre.
///
/// Sem relógio ninguém chama `tique`, então uma tarefa que peça um tique de
/// espera nunca mais seria acordada. O contrato é devolver um prazo já
/// vencido: a tarefa cede uma vez e segue.
fn relogio_sem_timer_nao_trava() -> Resultado {
    static CONCLUIU: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    async fn corpo() {
        // Zero tiques é o mesmo prazo já vencido que `por_ms` produz quando
        // não há timer; exercita o caminho sem precisar desligar o relógio.
        crate::tarefas::relogio::por_ticks(0).await;
        CONCLUIU.store(true, core::sync::atomic::Ordering::SeqCst);
    }

    CONCLUIU.store(false, core::sync::atomic::Ordering::SeqCst);

    let mut executor = crate::tarefas::executor::Executor::novo();
    executor.lancar(crate::tarefas::Tarefa::nova("teste-sem-timer", corpo()));

    // Teto de **uma** rodada, e o número importa. Um prazo já vencido resolve
    // na primeira polagem, sem depender de interrupção nenhuma. Um prazo de um
    // tique também terminaria — mas só depois de dormir até o timer disparar,
    // o que exige uma segunda rodada. Com teto 2 este caso passaria mesmo com
    // o bug de volta, porque o relógio *deste* teste funciona; é o teto 1 que
    // distingue "resolveu sozinho" de "precisou do timer".
    executor.rodar_ate_esvaziar(1)?;

    if !CONCLUIU.load(core::sync::atomic::Ordering::SeqCst) {
        return Err("a tarefa nao terminou com prazo ja vencido");
    }
    Ok(())
}

// ===========================================================================
// Fios de execução — multitarefa preemptiva
// ===========================================================================

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed, Ordering::SeqCst};

/// O caso que distingue preempção de cooperação.
///
/// Os dois fios rodam um laço apertado e **nunca cedem a vez**: não há
/// `.await`, não há `ceder`, não há chamada de sistema. Num escalonador
/// cooperativo — o que este kernel tinha até a fase anterior — o primeiro a
/// entrar rodaria para sempre e o segundo nunca sairia do lugar.
///
/// Exigir que os dois contadores avancem é, portanto, exigir que alguém os
/// tenha interrompido à força. É o timer, e é exatamente isso que "preemptivo"
/// significa.
fn fios_preemptam_sem_cooperacao() -> Resultado {
    static CONTADOR: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    static PARAR: AtomicBool = AtomicBool::new(false);
    static SAIRAM: AtomicU64 = AtomicU64::new(0);

    extern "C" fn girar(qual: u64) -> ! {
        let meu = &CONTADOR[qual as usize];
        while !PARAR.load(SeqCst) {
            meu.fetch_add(1, Relaxed);
            core::hint::spin_loop();
        }
        SAIRAM.fetch_add(1, SeqCst);
        crate::fios::terminar()
    }

    CONTADOR[0].store(0, SeqCst);
    CONTADOR[1].store(0, SeqCst);
    PARAR.store(false, SeqCst);
    SAIRAM.store(0, SeqCst);

    let trocas_antes = crate::fios::estatisticas().1;

    crate::fios::criar("teste-gira-a", girar, 0)?;
    crate::fios::criar("teste-gira-b", girar, 1)?;

    // Espera ativa de propósito: este fio também não cede: se ele avançar, foi
    // porque o timer o devolveu à CPU. Trinta tiques são seis quanta.
    esperar_ticks(30);
    PARAR.store(true, SeqCst);

    // Dá tempo de os dois notarem a parada e se encerrarem, para não deixarem
    // fios vivos disputando a CPU com os casos seguintes.
    esperar_ate(|| SAIRAM.load(SeqCst) == 2, 60)?;

    let a = CONTADOR[0].load(SeqCst);
    let b = CONTADOR[1].load(SeqCst);
    let trocas = crate::fios::estatisticas().1 - trocas_antes;

    crate::log_info!("teste", "fios avancaram {} e {} em {} trocas", a, b, trocas);

    if a == 0 || b == 0 {
        return Err("um dos fios nunca rodou; nao houve preempcao");
    }
    if trocas < 4 {
        return Err("houve poucas trocas de contexto para o tempo decorrido");
    }
    Ok(())
}

/// Um fio precisa retomar exatamente onde parou, com os registradores
/// intactos.
///
/// Preempção que perde estado é pior que preempção nenhuma: o fio continua,
/// mas com valores trocados, e a corrupção aparece longe da troca. Aqui cada
/// fio mantém uma soma numa variável local — que o compilador guarda em
/// registrador justamente por ser usada num laço — e confere o resultado no
/// fim. Se uma troca embaralhar registradores, a conta não fecha.
fn fios_preservam_contexto() -> Resultado {
    const VOLTAS: u64 = 200_000;
    static SOMA: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
    static PRONTOS: AtomicU64 = AtomicU64::new(0);

    extern "C" fn somar(qual: u64) -> ! {
        let mut acumulado = 0u64;
        let mut i = 0u64;
        while i < VOLTAS {
            acumulado = acumulado.wrapping_add(i ^ qual);
            i += 1;
        }
        SOMA[qual as usize].store(acumulado, SeqCst);
        PRONTOS.fetch_add(1, SeqCst);
        crate::fios::terminar()
    }

    /// A mesma conta, feita sem ninguém interromper.
    fn esperado(qual: u64) -> u64 {
        let mut acumulado = 0u64;
        let mut i = 0u64;
        while i < VOLTAS {
            acumulado = acumulado.wrapping_add(i ^ qual);
            i += 1;
        }
        acumulado
    }

    PRONTOS.store(0, SeqCst);
    crate::fios::criar("teste-soma-a", somar, 0)?;
    crate::fios::criar("teste-soma-b", somar, 1)?;

    esperar_ate(|| PRONTOS.load(SeqCst) == 2, 400)?;

    for qual in 0..2u64 {
        let obtido = SOMA[qual as usize].load(SeqCst);
        let alvo = esperado(qual);
        if obtido != alvo {
            crate::log_error!("teste", "fio {}: {} != {}", qual, obtido, alvo);
            return Err("um fio perdeu estado numa troca de contexto");
        }
    }
    Ok(())
}

/// Ceder a vez de propósito precisa funcionar sem depender do timer.
fn fios_cedem_voluntariamente() -> Resultado {
    static ORDEM: spin::Mutex<[u8; 6]> = spin::Mutex::new([0; 6]);
    static ESCRITOS: AtomicU64 = AtomicU64::new(0);
    static PRONTOS: AtomicU64 = AtomicU64::new(0);

    fn anotar(marca: u8) {
        let i = ESCRITOS.fetch_add(1, SeqCst) as usize;
        crate::arch::sem_interrupcoes(|| {
            if i < 6 {
                ORDEM.lock()[i] = marca;
            }
        });
    }

    extern "C" fn alternar(marca: u64) -> ! {
        for _ in 0..3 {
            anotar(marca as u8);
            crate::fios::ceder();
        }
        PRONTOS.fetch_add(1, SeqCst);
        crate::fios::terminar()
    }

    ESCRITOS.store(0, SeqCst);
    PRONTOS.store(0, SeqCst);
    crate::arch::sem_interrupcoes(|| *ORDEM.lock() = [0; 6]);

    crate::fios::criar("teste-cede-a", alternar, b'a' as u64)?;
    crate::fios::criar("teste-cede-b", alternar, b'b' as u64)?;

    esperar_ate(|| PRONTOS.load(SeqCst) == 2, 200)?;

    let ordem = crate::arch::sem_interrupcoes(|| *ORDEM.lock());
    // Não exigimos uma sequência exata: o timer também troca, e amarrar o
    // teste ao rodízio exato o tornaria frágil sem testar nada a mais. O que
    // precisa valer é que os dois escreveram três vezes cada.
    let a = ordem.iter().filter(|&&c| c == b'a').count();
    let b = ordem.iter().filter(|&&c| c == b'b').count();
    if a != 3 || b != 3 {
        crate::log_error!("teste", "a={} b={}", a, b);
        return Err("cessao voluntaria nao alternou entre os fios");
    }
    Ok(())
}

/// Duas criações concorrentes não podem escolher a mesma vaga.
///
/// `criar` escolhe a vaga sob a trava do escalonador e mapeia a pilha **fora**
/// dela — mapear toma as travas da paginação e dos frames, e aninhá-las seria
/// começo de deadlock. O intervalo entre as duas coisas é uma janela real: sem
/// marcar a vaga, duas criações simultâneas escolhem a mesma, e a segunda
/// falha ao tentar mapear por cima da primeira.
///
/// Aqui dois fios criam em rodízio, cedendo a vez entre uma criação e outra
/// para maximizar o entrelaçamento. Distinguimos os dois motivos de falha:
/// ficar sem vaga é legítimo, falhar no mapeamento é a colisão.
fn fios_criacao_concorrente_nao_colide() -> Resultado {
    const CADA: u64 = 3;
    static COLISOES: AtomicU64 = AtomicU64::new(0);
    static SEM_VAGA: AtomicU64 = AtomicU64::new(0);
    static CRIADOS: AtomicU64 = AtomicU64::new(0);
    static PRONTOS: AtomicU64 = AtomicU64::new(0);

    extern "C" fn efemero(_argumento: u64) -> ! {
        crate::fios::terminar()
    }

    extern "C" fn criador(_argumento: u64) -> ! {
        for _ in 0..CADA {
            match crate::fios::criar("teste-efemero", efemero, 0) {
                Ok(_) => {
                    CRIADOS.fetch_add(1, SeqCst);
                }
                Err(motivo) if motivo.contains("vaga") => {
                    SEM_VAGA.fetch_add(1, SeqCst);
                }
                Err(_) => {
                    COLISOES.fetch_add(1, SeqCst);
                }
            }
            crate::fios::ceder();
        }
        PRONTOS.fetch_add(1, SeqCst);
        crate::fios::terminar()
    }

    COLISOES.store(0, SeqCst);
    SEM_VAGA.store(0, SeqCst);
    CRIADOS.store(0, SeqCst);
    PRONTOS.store(0, SeqCst);

    // Abre a janela de propósito: cada criação cede a vez logo depois de
    // escolher a vaga, que é o ponto exato em que a corrida existe.
    crate::fios::CEDER_AO_ESCOLHER_VAGA.store(true, SeqCst);

    crate::fios::criar("teste-criador-a", criador, 0)?;
    crate::fios::criar("teste-criador-b", criador, 1)?;

    let desfecho = esperar_ate(|| PRONTOS.load(SeqCst) == 2, 200);
    crate::fios::CEDER_AO_ESCOLHER_VAGA.store(false, SeqCst);
    desfecho?;

    let colisoes = COLISOES.load(SeqCst);
    let criados = CRIADOS.load(SeqCst);
    crate::log_info!(
        "teste",
        "criacao concorrente: {} criados, {} sem vaga, {} colisoes",
        criados,
        SEM_VAGA.load(SeqCst),
        colisoes
    );

    if colisoes > 0 {
        return Err("duas criacoes concorrentes escolheram a mesma vaga");
    }
    if criados == 0 {
        return Err("nenhum fio foi criado; o teste nao exercitou nada");
    }
    Ok(())
}

// ===========================================================================
// Userspace — anel sem privilégio e chamadas de sistema
// ===========================================================================

/// A travessia completa, do kernel ao anel sem privilégio e de volta — agora
/// com o processo se duplicando e trocando de imagem no meio do caminho.
///
/// # O que cada elo prova
///
/// O programa de exemplo escreve nos dois descritores, confere a própria
/// `.bss`, chama `bifurcar` e aí os dois lados seguem caminhos diferentes: o
/// pai sai com um código improvável, e o filho chama `executar` para virar
/// outro programa, que escreve a própria linha e sai com outro código.
///
/// Encontrar os **dois** códigos do outro lado prova a cadeia inteira: as
/// páginas foram mapeadas a partir do ELF com permissão de usuário, o
/// processador desceu de privilégio, a chamada de sistema levou o controle de
/// volta com a pilha certa, o espaço do pai foi copiado para o filho, o filho
/// acordou retornando `0` de uma chamada que nunca fez, e a troca de imagem
/// pôs outro programa no lugar sem derrubar nada.
///
/// # Por que o log, e não só o código de saída
///
/// Porque agora há dois processos e um só campo de "última saída". Os códigos
/// são lidos do log, que guarda todos — e de quebra a leitura confere que cada
/// escrita saiu no nível certo, o que o código de saída não diria.
fn usuario_executa_bifurca_e_troca_de_imagem() -> Resultado {
    use alloc::format;

    static COMECOU: AtomicBool = AtomicBool::new(false);

    extern "C" fn hospedar(_argumento: u64) -> ! {
        COMECOU.store(true, SeqCst);
        match crate::usuario::programa::executar(crate::usuario::exemplo::bytes()) {
            Ok(_) => unreachable!("executar nao retorna em caso de sucesso"),
            Err(falha) => {
                crate::log_error!(
                    "teste",
                    "nao foi possivel entrar em userspace: {}",
                    falha.motivo()
                );
                crate::fios::terminar()
            }
        }
    }

    crate::usuario::limpar_ultima_saida();
    COMECOU.store(false, SeqCst);
    let (bifurcacoes_antes, trocas_antes, saidas_antes) =
        crate::usuario::estatisticas_de_processo();
    let chamadas_antes = crate::usuario::estatisticas().0;

    crate::fios::criar("teste-usuario", hospedar, 0)?;

    // Duas saídas: a do pai e a do filho já trocado de imagem.
    esperar_ate(
        || crate::usuario::estatisticas_de_processo().2 >= saidas_antes + 2,
        600,
    )?;

    if !COMECOU.load(SeqCst) {
        return Err("o fio hospedeiro nunca rodou");
    }

    let (bifurcacoes, trocas, _) = crate::usuario::estatisticas_de_processo();
    if bifurcacoes != bifurcacoes_antes + 1 {
        return Err("o processo nao se bifurcou exatamente uma vez");
    }
    if trocas != trocas_antes + 1 {
        return Err("nao houve exatamente uma troca de imagem");
    }

    // Cinco chamadas do pai (duas escritas, bifurcar, sair... e a do filho),
    // conferidas de forma frouxa de propósito: o que importa aqui é que
    // nenhuma delas tenha sumido, e o número exato já é conferido acima pelos
    // contadores de bifurcação e troca.
    let chamadas = crate::usuario::estatisticas().0 - chamadas_antes;
    if chamadas < 6 {
        crate::log_error!("teste", "apenas {} chamadas de sistema", chamadas);
        return Err("o processo nao fez todas as chamadas esperadas");
    }

    let saida_do_pai = format!(
        "processo encerrou com codigo {}",
        crate::usuario::exemplo::CODIGO_DE_SAIDA
    );
    let saida_do_filho = format!(
        "processo encerrou com codigo {}",
        crate::usuario::exemplo::CODIGO_DO_FILHO
    );
    let sujo = format!(
        "processo encerrou com codigo {}",
        crate::usuario::exemplo::CODIGO_DE_BSS_SUJA
    );

    let (mut viu_pai, mut viu_filho, mut viu_sujo) = (false, false, false);
    let (mut viu_mensagem, mut viu_diagnostico, mut viu_filho_escrevendo) = (false, false, false);
    crate::log::ultimos(64, crate::log::Level::Trace, |r| {
        if r.subsistema != "usuario" {
            return;
        }
        let m = r.mensagem();
        viu_pai |= m == saida_do_pai;
        viu_filho |= m == saida_do_filho;
        viu_sujo |= m == sujo;
        viu_filho_escrevendo |= m == crate::usuario::exemplo::MENSAGEM_DO_FILHO;
        viu_mensagem |= r.level == crate::log::Level::Info && m.starts_with("ola do ");
        viu_diagnostico |=
            r.level == crate::log::Level::Error && m == crate::usuario::exemplo::DIAGNOSTICO;
    });

    // O programa sai com este código quando a `.bss` chegou suja **ou** quando
    // `executar` voltou. As duas são falhas do kernel, não do programa.
    if viu_sujo {
        return Err("o processo relatou .bss suja ou executar que voltou");
    }
    if !viu_mensagem {
        return Err("a escrita no descritor de saida nao saiu em nivel info");
    }
    if !viu_diagnostico {
        return Err("a escrita no descritor de erro nao saiu em nivel error");
    }
    if !viu_pai {
        return Err("o pai nao saiu com o codigo dele");
    }
    if !viu_filho_escrevendo {
        return Err("o programa carregado por executar nao chegou a escrever");
    }
    if !viu_filho {
        return Err("o filho nao saiu com o codigo do programa novo");
    }
    Ok(())
}

/// A tabela de descritores é consultada de verdade, e um número inventado não
/// derruba nada.
///
/// # O que cada caso separa
///
/// O descritor é conferido **antes** do ponteiro, e isso é proposital: se a
/// ordem fosse a inversa, um processo poderia varrer endereços com um
/// descritor inválido e distinguir "mapeado" de "não mapeado" pela resposta
/// que recebesse. Os casos abaixo fixam essa ordem — todos usam um ponteiro
/// que o kernel jamais aceitaria, e mesmo assim os descritores abertos chegam
/// a reclamar *do ponteiro*, enquanto os fechados param antes.
fn usuario_descritor_e_conferido() -> Resultado {
    use crate::usuario::{descritor, despachar, erro, numero};

    // Um endereço do kernel: reprovado em qualquer caso que chegue a olhá-lo.
    let no_kernel = &raw const CASOS as *const _ as u64;
    // SAFETY: nenhuma das chamadas abaixo é `bifurcar` ou `executar`, que são
    // as únicas que tocam o quadro. `escrever` nem o olha.
    let escrever =
        |fd: u64| unsafe { despachar(numero::ESCREVER, fd, no_kernel, 8, core::ptr::null_mut()) };

    // Fechados para escrita: param no descritor, sem olhar o ponteiro.
    if escrever(descritor::ENTRADA) != erro::DESCRITOR_INVALIDO {
        return Err("aceitou escrita no descritor de entrada");
    }
    if escrever(3) != erro::DESCRITOR_INVALIDO {
        return Err("aceitou um descritor fora da tabela");
    }
    // Um número absurdo não pode indexar a tabela nem entrar em pânico: um
    // processo não deve conseguir matar o kernel com um inteiro grande.
    if escrever(u64::MAX) != erro::DESCRITOR_INVALIDO {
        return Err("um descritor absurdo nao foi recusado");
    }

    // Abertos: passam do descritor e reprovam no ponteiro. É o que prova que
    // a recusa acima veio da tabela, e não de um `escrever` que recusa tudo.
    if escrever(descritor::SAIDA) != erro::ENDERECO_INVALIDO {
        return Err("o descritor de saida nao chegou a validar o ponteiro");
    }
    if escrever(descritor::ERRO) != erro::ENDERECO_INVALIDO {
        return Err("o descritor de erro nao chegou a validar o ponteiro");
    }
    Ok(())
}

/// Um ponteiro que o usuário inventa não pode ser desreferenciado.
///
/// Este é o caso que separa um sistema operacional de uma biblioteca com
/// etapas extras. Todo argumento de chamada de sistema vem de código sem
/// privilégio; aceitar um ponteiro pelo valor de face daria ao processo um
/// jeito de fazer o kernel ler qualquer endereço em nome dele.
///
/// Testamos direto o validador, sem passar por userspace, porque é ele que
/// carrega a regra — e porque um processo mal-intencionado é exatamente o que
/// não queremos precisar escrever para descobrir que a regra falhou.
fn usuario_recusa_ponteiro_de_fora() -> Resultado {
    use crate::usuario::{BASE, TETO, erro, validar_faixa};

    // Dentro do kernel: o alvo óbvio de quem quer ler o que não deve.
    let no_kernel = &raw const CASOS as *const _ as u64;
    if validar_faixa(no_kernel, 8) != Err(erro::ENDERECO_INVALIDO) {
        return Err("aceitou um ponteiro para dentro do kernel");
    }

    // Logo abaixo e logo acima da faixa: os erros de um caractere.
    if validar_faixa(BASE - 8, 8) != Err(erro::ENDERECO_INVALIDO) {
        return Err("aceitou uma faixa que comeca antes do espaco do usuario");
    }
    if validar_faixa(TETO - 4, 8) != Err(erro::ENDERECO_INVALIDO) {
        return Err("aceitou uma faixa que termina depois do espaco do usuario");
    }

    // Transbordo: `inicio + tamanho` dá a volta e produziria uma faixa que
    // *parece* pequena e válida.
    if validar_faixa(u64::MAX - 4, 16) == Ok(()) {
        return Err("aceitou uma faixa cuja soma transborda");
    }

    // Tamanho absurdo: sem teto, uma chamada gastaria tempo ilimitado.
    if validar_faixa(BASE, u64::MAX) != Err(erro::TAMANHO_INVALIDO) {
        return Err("aceitou um tamanho sem teto");
    }

    // Dentro da faixa mas **não mapeado**: estar no intervalo certo não basta.
    let meio_nao_mapeado = BASE + 0x0080_0000;
    if validar_faixa(meio_nao_mapeado, 8) != Err(erro::ENDERECO_INVALIDO) {
        return Err("aceitou um endereco da faixa do usuario que nao esta mapeado");
    }

    // Tamanho zero é legítimo e não desreferencia nada.
    if validar_faixa(no_kernel, 0) != Ok(()) {
        return Err("recusou uma faixa vazia");
    }
    Ok(())
}

/// Dois espaços de endereços traduzem o **mesmo** endereço virtual para
/// memórias físicas diferentes.
///
/// # O que isto prova, e por que é o teste que importa
///
/// É a definição prática de isolamento entre processos. Até aqui havia uma
/// tabela de tradução só, e por isso dois processos teriam de ocupar faixas
/// diferentes do mesmo mapa — o que não é isolamento, é combinado. Com uma
/// tabela por espaço, `0x1_0000_0000` pode ser de um processo num instante e
/// de outro no seguinte, sem que nenhum dos dois saiba.
///
/// A sequência confere as três coisas que podem dar errado em separado:
///
/// 1. um endereço mapeado num espaço **não existe** no outro;
/// 2. o mesmo endereço, mapeado nos dois, guarda conteúdos distintos;
/// 3. voltar ao espaço do kernel devolve o mapa de antes, intacto.
///
/// Tudo com interrupções mascaradas: uma troca de fio no meio deixaria outro
/// fio rodando num espaço de endereços que não é o esperado, e embora isso
/// seja inofensivo (o kernel está mapeado em todos), tornaria o teste
/// dependente do instante em que o timer dispara.
fn memoria_espacos_isolam_o_mesmo_endereco() -> Resultado {
    use crate::arch::{self, Permissoes};

    const ALVO: u64 = crate::usuario::BASE;
    const MARCA_A: u64 = 0xAAAA_AAAA_AAAA_AAAA;
    const MARCA_B: u64 = 0xBBBB_BBBB_BBBB_BBBB;

    let privada = arch::entrada_de_topo(ALVO) as usize;
    let kernel = arch::espaco_do_kernel();
    if kernel == u64::MAX {
        return Err("a raiz do espaco do kernel nao foi registrada no boot");
    }
    if arch::espaco_atual() != kernel {
        return Err("o teste nao comecou no espaco do kernel");
    }

    arch::sem_interrupcoes(|| {
        let a = arch::criar_espaco(privada)?;
        let b = arch::criar_espaco(privada)?;

        // SAFETY: `a` e `b` vieram de `criar_espaco` e carregam as entradas de
        // topo do kernel, então o código e a pilha deste fio seguem mapeados
        // em qualquer um dos dois. Nenhum dos dois é destruído enquanto ativo.
        let resultado = unsafe {
            arch::trocar_espaco(a);
            crate::paginacao::mapear_novo(ALVO, Permissoes::DADOS)?;
            core::ptr::write_volatile(ALVO as *mut u64, MARCA_A);

            arch::trocar_espaco(b);
            if arch::traduzir(ALVO).is_some() {
                arch::trocar_espaco(kernel);
                return Err("o endereco do espaco A apareceu no espaco B");
            }
            crate::paginacao::mapear_novo(ALVO, Permissoes::DADOS)?;
            core::ptr::write_volatile(ALVO as *mut u64, MARCA_B);

            // O mesmo endereço, os dois espaços, conteúdos diferentes.
            let lido_em_b = core::ptr::read_volatile(ALVO as *const u64);
            arch::trocar_espaco(a);
            let lido_em_a = core::ptr::read_volatile(ALVO as *const u64);

            arch::trocar_espaco(kernel);
            (lido_em_a, lido_em_b)
        };

        // SAFETY: nenhum dos dois está ativo — voltamos ao espaço do kernel
        // acima —, e tudo abaixo deles saiu do alocador de frames.
        unsafe {
            arch::destruir_espaco(a, privada);
            arch::destruir_espaco(b, privada);
        }

        if resultado.0 != MARCA_A || resultado.1 != MARCA_B {
            crate::log_error!(
                "teste",
                "espaco A leu {:#x}, espaco B leu {:#x}",
                resultado.0,
                resultado.1
            );
            return Err("os dois espacos compartilharam a mesma memoria fisica");
        }

        // O espaço do kernel nunca teve este endereço, e continua sem ele.
        if arch::traduzir(ALVO).is_some() {
            return Err("o mapeamento do processo vazou para o espaco do kernel");
        }
        Ok(())
    })
}

/// O leitor de ELF aceita a imagem de exemplo e descreve o que ela pede.
fn elf_aceita_a_imagem_de_exemplo() -> Resultado {
    let imagem = crate::usuario::exemplo::bytes();
    let elf = crate::usuario::elf::validar(imagem)?;

    if elf.entrada() != crate::usuario::BASE {
        return Err("o ponto de entrada nao e o inicio do espaco do usuario");
    }

    let segmentos = elf.segmentos();
    if segmentos.len() != 2 {
        return Err("a imagem de exemplo deveria ter dois segmentos carregaveis");
    }

    let codigo = &segmentos[0];
    if !codigo.executavel || codigo.escrita {
        return Err("o segmento de codigo nao e executavel-e-somente-leitura");
    }

    let dados = &segmentos[1];
    if !dados.escrita || dados.executavel {
        return Err("o segmento de dados nao e gravavel-e-nao-executavel");
    }

    // O que prova que a `.bss` existe como conceito nesta imagem: o segmento
    // pede mais memória do que traz do arquivo.
    if dados.bytes_na_memoria <= dados.bytes_no_arquivo {
        return Err("o segmento de dados nao pede nenhuma .bss");
    }
    Ok(())
}

/// Um ELF malformado vira erro, nunca pânico.
///
/// # Por que a lista é longa
///
/// Cada caso corresponde a um campo que o arquivo controla e que o kernel usa
/// para decidir onde escrever ou quanto copiar. Um `e_phnum` grande demais faz
/// o kernel percorrer uma tabela que não existe; um `p_vaddr` fora da faixa
/// faz ele escrever onde não deve; uma soma que transborda transforma um
/// segmento enorme num que *parece* pequeno.
///
/// Hoje a imagem vem de dentro do próprio kernel e nenhum desses casos
/// aconteceria por acaso. Mas o ponto de um carregador é aceitar programas de
/// fora, e a hora de acertar isso é antes de existir quem os mande.
fn elf_recusa_imagens_invalidas() -> Resultado {
    use alloc::vec::Vec;

    let valida = crate::usuario::exemplo::bytes();
    if crate::usuario::elf::validar(valida).is_err() {
        return Err("a imagem de exemplo deveria ser valida");
    }

    /// Uma avaria a aplicar sobre uma cópia da imagem válida, e o motivo pelo
    /// qual o leitor precisa recusá-la.
    type Avaria<'a> = (&'a dyn Fn(&mut Vec<u8>), &'a str);

    let casos: &[Avaria] = &[
        (&|v: &mut Vec<u8>| v.truncate(8), "cabecalho truncado"),
        (&|v: &mut Vec<u8>| v[1] = b'X', "assinatura errada"),
        (&|v: &mut Vec<u8>| v[4] = 1, "classe 32 bits"),
        (&|v: &mut Vec<u8>| v[16] = 3, "ET_DYN em vez de ET_EXEC"),
        (&|v: &mut Vec<u8>| v[18] ^= 0xFF, "outra arquitetura"),
        (
            &|v: &mut Vec<u8>| v[24..32].copy_from_slice(&0u64.to_le_bytes()),
            "entrada fora do espaco do usuario",
        ),
        (
            &|v: &mut Vec<u8>| v[54..56].copy_from_slice(&32u16.to_le_bytes()),
            "p_entsize inesperado",
        ),
        (
            &|v: &mut Vec<u8>| v[56..58].copy_from_slice(&4096u16.to_le_bytes()),
            "e_phnum maior que a imagem",
        ),
        (
            &|v: &mut Vec<u8>| v[56..58].copy_from_slice(&0u16.to_le_bytes()),
            "nenhum segmento carregavel",
        ),
        (
            &|v: &mut Vec<u8>| v[68..72].copy_from_slice(&7u32.to_le_bytes()),
            "segmento pedindo escrita e execucao",
        ),
        (
            &|v: &mut Vec<u8>| v[80..88].copy_from_slice(&0u64.to_le_bytes()),
            "p_vaddr fora do espaco do usuario",
        ),
        (
            &|v: &mut Vec<u8>| v[96..104].copy_from_slice(&u64::MAX.to_le_bytes()),
            "p_filesz que transborda",
        ),
        (
            &|v: &mut Vec<u8>| v[104..112].copy_from_slice(&0u64.to_le_bytes()),
            "p_memsz menor que p_filesz",
        ),
        (
            &|v: &mut Vec<u8>| v[72..80].copy_from_slice(&(1u64 << 40).to_le_bytes()),
            "p_offset alem do fim da imagem",
        ),
    ];

    for (estragar, motivo) in casos {
        let mut copia: Vec<u8> = valida.to_vec();
        estragar(&mut copia);
        if crate::usuario::elf::validar(&copia).is_ok() {
            crate::log_error!("teste", "aceitou um ELF com {}", motivo);
            return Err("o leitor de ELF aceitou uma imagem invalida");
        }
    }
    Ok(())
}

/// Desmapear uma página do kernel não pode soltar uma tabela que outros
/// espaços referenciam.
///
/// # O defeito que este caso persegue
///
/// Os espaços de processo recebem uma **cópia das entradas de topo** do
/// kernel. Cópia da entrada, não da árvore abaixo dela: todos os espaços
/// apontam para as mesmas tabelas de nível inferior, e é isso que faz um
/// mapeamento do kernel valer em todos de uma vez.
///
/// A consequência é que liberar uma dessas tabelas é diferente de liberar uma
/// tabela do usuário. Quem desmapeia enxerga só a raiz **ativa**: zerar a
/// entrada de topo ali não alcança as cópias que os outros espaços guardam, e
/// elas ficam apontando para um frame que voltou ao alocador. O sintoma
/// aparece muito depois, quando esse frame for reaproveitado — memória do
/// kernel corrompida através de uma referência de tabela que já não valia.
///
/// # Como o caso detecta isso sem corromper nada
///
/// Só desmapear não basta, e a primeira versão deste teste passava por isso:
/// a limpeza zera cada nível **antes** de liberá-lo, então uma travessia pela
/// referência pendurada encontra tabelas vazias e responde "não mapeado" — a
/// mesma resposta de um kernel correto. O defeito fica escondido até o frame
/// liberado ser reaproveitado.
///
/// O que o denuncia de forma determinística é mapear de novo. Aí a raiz do
/// kernel passa a apontar para uma árvore **nova**, enquanto a cópia guardada
/// pelo espaço do processo segue apontando para a antiga. Um mapeamento do
/// kernel tem de valer identicamente em todo espaço; basta então comparar as
/// duas traduções, e não confiar em nenhuma delas isoladamente.
///
/// O endereço de sonda fica na entrada de topo seguinte à do heap, que nenhuma
/// região usa. Ela precisa ficar **vazia** depois da remoção: é o caso em que
/// a limpeza sobe até o topo, e o único em que o defeito se manifesta.
fn memoria_desmapear_do_kernel_vale_em_todo_espaco() -> Resultado {
    use crate::arch::{self, Permissoes};

    let sonda = arch::BASE_DO_HEAP + arch::COBERTURA_DA_ENTRADA_DE_TOPO;
    let privada = arch::entrada_de_topo(crate::usuario::BASE) as usize;
    let kernel = arch::espaco_do_kernel();

    if arch::entrada_de_topo(sonda) == arch::entrada_de_topo(arch::BASE_DO_HEAP) {
        return Err("a sonda caiu na mesma entrada de topo do heap");
    }

    arch::sem_interrupcoes(|| {
        // A página existe **antes** do espaço nascer, para que a entrada de
        // topo que ele copia já aponte para a árvore que vai ser removida.
        crate::paginacao::mapear_novo(sonda, Permissoes::DADOS)?;

        let espaco = crate::paginacao::Espaco::novo(privada)?;
        let raiz = espaco.raiz();

        crate::paginacao::desmapear_e_liberar(sonda)?;

        if arch::traduzir(sonda).is_some() {
            return Err("a sonda continuou mapeada no espaco do kernel");
        }

        // Os chamarizes existem para desfazer uma coincidência. O alocador é
        // um bitmap: sem eles, remontar a árvore recebe de volta exatamente os
        // mesmos frames na mesma ordem, a cópia presa pelo processo volta a
        // apontar para a tabela certa por acidente, e o teste passa sem provar
        // nada. Foi o que aconteceu na primeira versão deste caso.
        let chamarizes = [
            crate::frames::alocar().ok_or("memoria fisica esgotada")?,
            crate::frames::alocar().ok_or("memoria fisica esgotada")?,
        ];

        // O passo que denuncia: a raiz do kernel ganha uma árvore nova para
        // este endereço. Se a entrada de topo tiver sido zerada, a cópia do
        // processo ficou presa à árvore antiga.
        crate::paginacao::mapear_novo(sonda, Permissoes::DADOS)?;
        let no_kernel = arch::traduzir(sonda);

        // SAFETY: a raiz saiu de `Espaco::novo` e carrega as entradas de topo
        // do kernel, então o código e a pilha deste fio seguem mapeados.
        // Voltamos ao espaço do kernel antes de largar o espaço.
        let no_processo = unsafe {
            arch::trocar_espaco(raiz);
            let visto = arch::traduzir(sonda);
            arch::trocar_espaco(kernel);
            visto
        };
        drop(espaco);
        crate::paginacao::desmapear_e_liberar(sonda)?;
        for frame in chamarizes {
            crate::frames::liberar(frame);
        }

        if no_processo != no_kernel {
            crate::log_error!(
                "teste",
                "kernel traduz {:?}, processo traduz {:?}",
                no_kernel,
                no_processo
            );
            return Err("os dois espacos discordam sobre um mapeamento do kernel");
        }
        Ok(())
    })
}

/// A varredura do barramento encontra dispositivos coerentes.
///
/// # O que dá para afirmar sem saber que máquina é esta
///
/// Pouco, e é por isso que o caso é escrito como é. O conjunto de dispositivos
/// depende da placa, da versão do QEMU e dos argumentos de linha de comando —
/// fixar "deve haver uma placa de rede" seria testar o emulador, não o kernel.
///
/// O que vale nas duas arquiteturas e em qualquer configuração:
///
/// 1. **A varredura roda e acha alguma coisa.** As duas máquinas têm ao menos
///    uma ponte hospedeira, que é o dispositivo que *é* o barramento. Zero
///    significa que o acesso à configuração não funcionou.
/// 2. **Ninguém é `0xFFFF`.** Esse é o valor que o barramento devolve quando
///    não há ninguém no endereço; um dispositivo guardado com ele seria a
///    varredura confundindo ausência com presença.
/// 3. **A função zero existe para todo dispositivo listado.** As funções de 1
///    a 7 só são procuradas quando a zero diz que existem; encontrar uma
///    função alta sem a zero significaria ter lido o bit errado.
/// 4. **Não há endereços repetidos.** Dois registros para o mesmo
///    `(barramento, dispositivo, função)` seriam a varredura contando duas
///    vezes.
fn pci_varredura_coerente() -> Resultado {
    let total = crate::pci::total();
    if total == 0 {
        return Err("a varredura nao encontrou nenhum dispositivo");
    }

    let mut vistos = [(0u8, 0u8, 0u8); crate::pci::MAX_DISPOSITIVOS];
    let mut quantos = 0usize;
    let mut com_funcao_zero = [(0u8, 0u8); crate::pci::MAX_DISPOSITIVOS];
    let mut zeros = 0usize;
    let mut falha: Option<&'static str> = None;

    crate::pci::com_dispositivos(|d| {
        if d.fabricante == 0xFFFF {
            falha = Some("um dispositivo foi guardado com fabricante 0xFFFF");
        }
        if d.funcao >= 8 {
            falha = Some("numero de funcao fora da faixa");
        }

        let chave = (d.barramento, d.dispositivo, d.funcao);
        if vistos[..quantos].contains(&chave) {
            falha = Some("o mesmo endereco apareceu duas vezes");
        }
        if quantos < vistos.len() {
            vistos[quantos] = chave;
            quantos += 1;
        }

        if d.funcao == 0 && zeros < com_funcao_zero.len() {
            com_funcao_zero[zeros] = (d.barramento, d.dispositivo);
            zeros += 1;
        }
    });

    if let Some(motivo) = falha {
        return Err(motivo);
    }

    for (barramento, dispositivo, funcao) in &vistos[..quantos] {
        if *funcao != 0 && !com_funcao_zero[..zeros].contains(&(*barramento, *dispositivo)) {
            crate::log_error!(
                "teste",
                "funcao {} de {:02x}:{:02x} sem a funcao zero",
                funcao,
                barramento,
                dispositivo
            );
            return Err("uma funcao alta apareceu sem a funcao zero do mesmo dispositivo");
        }
    }

    crate::log_info!("teste", "{} dispositivos PCI coerentes", total);
    Ok(())
}

/// Traduzir permissões para bits de descritor e de volta devolve o original.
///
/// # Por que um caso só para isto
///
/// Porque `fork` transformou um caminho de mão única em ida e volta. Até ele,
/// permissões só eram **escritas** em descritores; duplicar um espaço obriga a
/// lê-las de volta, para que o `W^X` do pai chegue intacto ao filho.
///
/// Um par de inversas é a espécie de coisa que deixa de ser sem que nada
/// quebre: quem mexe numa delas raramente reabre a outra, e o erro só aparece
/// muito depois, como uma página com permissão errada. As dezesseis
/// combinações são poucas o bastante para conferir todas.
///
/// Este caso encontrou um erro assim. A primeira versão do lado ARM lia `UXN`
/// para saber se a página era executável, o que vale para página de usuário —
/// o único caminho que existia — mas não para página do kernel, onde a
/// resposta mora em `PXN`.
fn memoria_permissoes_sobrevivem_a_ida_e_volta() -> Resultado {
    use crate::arch::{self, Permissoes};

    for combinacao in 0..16u8 {
        let original = Permissoes {
            escrita: combinacao & 1 != 0,
            executavel: combinacao & 2 != 0,
            // Memória de dispositivo não convive com permissão de usuário em
            // nenhum lugar deste kernel, mas a combinação é conferida mesmo
            // assim: o par de conversões não sabe disso, e não deveria mentir
            // sobre uma entrada que aceita.
            dispositivo: combinacao & 4 != 0,
            usuario: combinacao & 8 != 0,
        };

        let voltou = arch::permissoes_ida_e_volta(original);
        if voltou != original {
            crate::log_error!("teste", "{:?} voltou como {:?}", original, voltou);
            return Err("permissoes nao sobreviveram a conversao de ida e volta");
        }
    }
    Ok(())
}

/// Clonar um espaço copia o conteúdo, e não a página.
///
/// # O que separa uma cópia de um compartilhamento
///
/// Depois de um `fork`, pai e filho enxergam o mesmo endereço com o mesmo
/// conteúdo — e é fácil obter isso do jeito errado, apontando as duas tabelas
/// para o **mesmo** frame. Nos primeiros instantes os dois comportamentos são
/// indistinguíveis: o conteúdo confere dos dois lados.
///
/// A diferença aparece na primeira escrita. Este caso a provoca: escreve uma
/// marca no original, clona, escreve outra no clone e volta a olhar o
/// original. Se as duas tabelas apontarem para o mesmo frame, a segunda
/// escrita apaga a primeira.
///
/// Também confere o que um `fork` ingênuo perderia: as permissões. Uma página
/// somente leitura no original não pode chegar gravável no clone — seria o
/// `W^X` do processo desaparecendo no instante em que ele tem um filho.
fn memoria_clonar_copia_o_conteudo() -> Resultado {
    use crate::arch::{self, Permissoes};

    const ALVO: u64 = crate::usuario::BASE;
    const SO_LEITURA: u64 = crate::usuario::BASE + crate::arch::TAMANHO_PAGINA;
    const MARCA_ORIGINAL: u64 = 0x0819_0819_0819_0819;
    const MARCA_DO_CLONE: u64 = 0xC10E_C10E_C10E_C10E;

    let privada = arch::ENTRADA_PRIVADA as usize;
    let kernel = arch::espaco_do_kernel();

    arch::sem_interrupcoes(|| {
        let original = crate::paginacao::Espaco::novo(privada)?;

        // SAFETY: as raízes vêm de `Espaco::novo` e carregam as entradas de
        // topo do kernel; voltamos ao espaço do kernel antes de largar
        // qualquer uma delas.
        let (lido_no_original, lido_no_clone, gravavel_no_clone) = unsafe {
            arch::trocar_espaco(original.raiz());
            crate::paginacao::mapear_novo(ALVO, Permissoes::DADOS_USUARIO)?;
            core::ptr::write_volatile(ALVO as *mut u64, MARCA_ORIGINAL);

            // Uma página somente leitura, para conferir que a permissão
            // atravessa o clone.
            let frame = crate::paginacao::mapear_novo(SO_LEITURA, Permissoes::DADOS_USUARIO)?;
            arch::desmapear(SO_LEITURA)?;
            arch::mapear_frame(
                SO_LEITURA,
                frame,
                Permissoes {
                    escrita: false,
                    executavel: false,
                    dispositivo: false,
                    usuario: true,
                },
            )?;

            let clone = crate::paginacao::Espaco::clonar_o_ativo(privada)?;

            arch::trocar_espaco(clone.raiz());
            let lido_no_clone = core::ptr::read_volatile(ALVO as *const u64);
            core::ptr::write_volatile(ALVO as *mut u64, MARCA_DO_CLONE);
            let gravavel = crate::paginacao::mapear_novo(SO_LEITURA, Permissoes::DADOS).is_ok();

            arch::trocar_espaco(original.raiz());
            let lido_no_original = core::ptr::read_volatile(ALVO as *const u64);

            arch::trocar_espaco(kernel);
            drop(clone);
            (lido_no_original, lido_no_clone, gravavel)
        };
        drop(original);

        if lido_no_clone != MARCA_ORIGINAL {
            return Err("o clone nao recebeu o conteudo do original");
        }
        if lido_no_original != MARCA_ORIGINAL {
            crate::log_error!("teste", "o original passou a ler {:#x}", lido_no_original);
            return Err("escrever no clone alterou o original: os dois dividem o frame");
        }
        if gravavel_no_clone {
            return Err("a pagina somente leitura do original ficou livre no clone");
        }
        Ok(())
    })
}

/// Destruir um espaço devolve **tudo**: tabelas, páginas e a própria raiz.
///
/// # Por que isto merece um caso próprio
///
/// Um vazamento aqui não produz sintoma nenhum — nem falha, nem log, nem
/// resposta errada. Ele só aparece muito depois, como memória física que
/// acabou sem ninguém ter pedido nada de grande. E a contagem não é óbvia:
/// além das páginas do processo há as tabelas intermediárias, que nascem sob
/// demanda no meio de um mapeamento e não têm dono visível.
///
/// Comparar o alocador antes e depois é a única forma honesta de conferir, e
/// dez voltas em vez de uma transformam um vazamento de um frame por processo
/// — o tamanho típico de um esquecimento — em dez, bem acima de qualquer
/// ruído.
fn memoria_espaco_destruido_devolve_tudo() -> Resultado {
    use crate::arch::{self, Permissoes};

    const ALVO: u64 = crate::usuario::BASE;
    const VOLTAS: usize = 10;

    let privada = arch::entrada_de_topo(ALVO) as usize;
    let kernel = arch::espaco_do_kernel();

    arch::sem_interrupcoes(|| {
        let (livres_antes, _) = crate::frames::estatisticas();

        for _ in 0..VOLTAS {
            let espaco = crate::paginacao::Espaco::novo(privada)?;
            let raiz = espaco.raiz();

            // SAFETY: a raiz saiu de `Espaco::novo` e carrega as entradas de
            // topo do kernel, então o código e a pilha deste fio seguem
            // mapeados. Voltamos ao espaço do kernel antes de largar o espaço.
            unsafe {
                arch::trocar_espaco(raiz);

                // Duas páginas distantes uma da outra de propósito: forçam a
                // criação de tabelas intermediárias diferentes, que são
                // exatamente as que um `destruir` incompleto esqueceria.
                crate::paginacao::mapear_novo(ALVO, Permissoes::DADOS)?;
                crate::paginacao::mapear_novo(ALVO + 0x20_0000, Permissoes::DADOS)?;

                arch::trocar_espaco(kernel);
            }

            drop(espaco);
        }

        let (livres_depois, _) = crate::frames::estatisticas();
        if livres_depois != livres_antes {
            crate::log_error!(
                "teste",
                "{} frames livres antes, {} depois de {} espacos",
                livres_antes,
                livres_depois,
                VOLTAS
            );
            return Err("destruir um espaco nao devolveu tudo que ele ocupava");
        }
        Ok(())
    })
}

/// Nenhuma página de um processo carregado é gravável **e** executável.
///
/// # Por que afirmar isto, e não presumir
///
/// O `W^X` é mantido por uma sequência de três passos numa ordem específica —
/// mapear gravável, preencher, repermissionar. Até aqui nada o conferia: os
/// testes provavam que o programa *roda*, e um programa roda igualmente bem
/// num espaço onde tudo ficou gravável. A falha seria invisível exatamente
/// onde mais importa.
///
/// O percorredor de páginas que o `fork` trouxe tornou a afirmação possível:
/// dá para olhar cada descritor do espaço do processo e perguntar.
///
/// O caso também conta quantas páginas executáveis encontrou. Sem isso, um
/// percurso que não achasse nada passaria — e passaria em silêncio, que é o
/// modo de falhar mais caro que um teste tem.
fn usuario_nenhuma_pagina_gravavel_e_executavel() -> Resultado {
    static PRONTO: AtomicBool = AtomicBool::new(false);
    static EXECUTAVEIS: AtomicU64 = AtomicU64::new(0);
    static GRAVAVEIS: AtomicU64 = AtomicU64::new(0);
    static AMBOS: AtomicU64 = AtomicU64::new(0);

    extern "C" fn inspetor(_argumento: u64) -> ! {
        if crate::usuario::programa::carregar(crate::usuario::exemplo::bytes()).is_err() {
            crate::fios::terminar()
        }

        crate::arch::sem_interrupcoes(|| {
            // SAFETY: o espaço ativo é o deste fio, acabado de montar, e as
            // interrupções mascaradas garantem que ninguém o altera durante o
            // percurso.
            unsafe {
                crate::arch::percorrer_paginas_do_usuario(
                    crate::arch::espaco_atual(),
                    crate::usuario::programa::ENTRADA_PRIVADA,
                    &mut |_virtual, _fisico, permissoes| {
                        if permissoes.executavel {
                            EXECUTAVEIS.fetch_add(1, SeqCst);
                        }
                        if permissoes.escrita {
                            GRAVAVEIS.fetch_add(1, SeqCst);
                        }
                        if permissoes.escrita && permissoes.executavel {
                            AMBOS.fetch_add(1, SeqCst);
                        }
                    },
                );
            }
        });

        PRONTO.store(true, SeqCst);
        crate::fios::terminar()
    }

    PRONTO.store(false, SeqCst);
    EXECUTAVEIS.store(0, SeqCst);
    GRAVAVEIS.store(0, SeqCst);
    AMBOS.store(0, SeqCst);

    // Num fio próprio: `carregar` instala um espaço no fio corrente, e o fio
    // do teste não morre — se ele adotasse um, os casos seguintes o herdariam.
    crate::fios::criar("teste-wx", inspetor, 0)?;
    esperar_ate(|| PRONTO.load(SeqCst), 300)?;

    let (executaveis, gravaveis, ambos) = (
        EXECUTAVEIS.load(SeqCst),
        GRAVAVEIS.load(SeqCst),
        AMBOS.load(SeqCst),
    );

    if executaveis == 0 {
        return Err("o percurso nao encontrou nenhuma pagina executavel");
    }
    if gravaveis == 0 {
        return Err("o percurso nao encontrou nenhuma pagina gravavel");
    }
    if ambos != 0 {
        crate::log_error!(
            "teste",
            "{} paginas gravaveis e executaveis ao mesmo tempo",
            ambos
        );
        return Err("o processo tem pagina gravavel e executavel: W^X quebrado");
    }
    Ok(())
}

/// Dois processos coexistem, cada um no seu espaço, nos mesmos endereços.
///
/// # Por que este caso substituiu "um processo por vez"
///
/// Enquanto havia uma tabela de tradução só, carregar um programa começava
/// desmapeando o que estivesse no espaço do usuário — e por isso dois
/// hospedeiros concorrentes arrancavam o chão um do outro. O caso anterior
/// existia para impor a serialização que faltava.
///
/// Com um espaço por processo, a serialização deixou de ser necessária: o que
/// precisa ser demonstrado agora é o contrário dela.
///
/// # A coreografia, e por que ela não depende do relógio
///
/// Os dois fios se alternam por sinalizações explícitas, não por sorte de
/// escalonamento. O fio A carrega, escreve a marca dele e **espera**; só então
/// B carrega no mesmo endereço e escreve a marca dele. Se os dois
/// compartilhassem memória, a escrita de B apagaria a de A — e A, ao acordar,
/// leria a marca errada.
///
/// A leitura de volta acontece depois que ambos escreveram, que é o instante
/// em que um espaço compartilhado se denunciaria.
fn usuario_dois_processos_coexistem() -> Resultado {
    const MARCA_A: u64 = 0xA1A1_A1A1_A1A1_A1A1;
    const MARCA_B: u64 = 0xB2B2_B2B2_B2B2_B2B2;

    static CARREGOU_A: AtomicBool = AtomicBool::new(false);
    static ESCREVEU_B: AtomicBool = AtomicBool::new(false);
    static LIDO_A: AtomicU64 = AtomicU64::new(0);
    static LIDO_B: AtomicU64 = AtomicU64::new(0);
    static FALHA: AtomicBool = AtomicBool::new(false);

    /// Carrega, escreve `marca` no topo da própria pilha e devolve o que ler
    /// de volta depois que o outro fio também escreveu.
    ///
    /// # Safety
    /// Só pode rodar num fio criado por `fios::criar`, porque `carregar`
    /// instala um espaço de endereços no fio corrente.
    unsafe fn marcar(marca: u64) -> Result<(), &'static str> {
        let programa = crate::usuario::programa::carregar(crate::usuario::exemplo::bytes())
            .map_err(|falha| falha.motivo())?;

        // O topo da pilha do processo: mapeado por `carregar`, e no mesmo
        // endereço virtual para os dois — que é o ponto do teste.
        let alvo = (programa.topo_da_pilha() - 16) as *mut u64;

        // SAFETY: `alvo` está dentro da página de pilha que `carregar` acabou
        // de mapear no espaço deste fio, com permissão de escrita.
        unsafe { core::ptr::write_volatile(alvo, marca) };
        Ok(())
    }

    extern "C" fn fio_a(_argumento: u64) -> ! {
        // SAFETY: estamos num fio criado por `fios::criar`.
        if unsafe { marcar(MARCA_A) }.is_err() {
            FALHA.store(true, SeqCst);
            crate::fios::terminar()
        }
        let alvo = (crate::usuario::TETO - 16) as *const u64;
        CARREGOU_A.store(true, SeqCst);

        // Espera B escrever no mesmo endereço, no espaço dele.
        while !ESCREVEU_B.load(SeqCst) {
            crate::fios::ceder();
        }

        // SAFETY: a página segue mapeada no espaço deste fio, que o
        // escalonador reinstalou ao devolver a CPU.
        LIDO_A.store(unsafe { core::ptr::read_volatile(alvo) }, SeqCst);
        crate::fios::terminar()
    }

    extern "C" fn fio_b(_argumento: u64) -> ! {
        while !CARREGOU_A.load(SeqCst) {
            crate::fios::ceder();
        }
        // SAFETY: estamos num fio criado por `fios::criar`.
        if unsafe { marcar(MARCA_B) }.is_err() {
            FALHA.store(true, SeqCst);
            ESCREVEU_B.store(true, SeqCst);
            crate::fios::terminar()
        }
        let alvo = (crate::usuario::TETO - 16) as *const u64;

        // SAFETY: mesma justificativa do fio A.
        LIDO_B.store(unsafe { core::ptr::read_volatile(alvo) }, SeqCst);
        ESCREVEU_B.store(true, SeqCst);
        crate::fios::terminar()
    }

    CARREGOU_A.store(false, SeqCst);
    ESCREVEU_B.store(false, SeqCst);
    LIDO_A.store(0, SeqCst);
    LIDO_B.store(0, SeqCst);
    FALHA.store(false, SeqCst);

    crate::fios::criar("teste-proc-a", fio_a, 0)?;
    crate::fios::criar("teste-proc-b", fio_b, 0)?;

    esperar_ate(|| LIDO_A.load(SeqCst) != 0 && LIDO_B.load(SeqCst) != 0, 600)?;

    if FALHA.load(SeqCst) {
        return Err("um dos fios nao conseguiu carregar o programa");
    }
    let (a, b) = (LIDO_A.load(SeqCst), LIDO_B.load(SeqCst));
    if a != MARCA_A || b != MARCA_B {
        crate::log_error!("teste", "fio A leu {:#x}, fio B leu {:#x}", a, b);
        return Err("os dois processos compartilharam a mesma memoria");
    }
    Ok(())
}

/// Um processo não alcança a memória do kernel, e tentar mata só o processo.
///
/// É o teste que dá sentido a todos os outros deste grupo. Entrar em ring 3
/// sem que ele proteja nada seria uma troca de contexto cara e mais nada; o
/// que precisa ser demonstrado são duas coisas ao mesmo tempo:
///
/// 1. o processo **não consegue** ler o que não é dele — se conseguisse,
///    seguiria em frente e sairia com o código do invasor;
/// 2. a tentativa mata **só o processo** — o kernel continua vivo, e a prova
///    disso é que este próprio teste chega ao fim e reporta.
fn usuario_nao_alcanca_o_kernel() -> Resultado {
    static COMECOU: AtomicBool = AtomicBool::new(false);

    extern "C" fn hospedar(_argumento: u64) -> ! {
        COMECOU.store(true, SeqCst);
        match crate::usuario::programa::executar(crate::usuario::exemplo::bytes_invasores()) {
            Ok(_) => unreachable!("executar nao retorna em caso de sucesso"),
            Err(falha) => {
                crate::log_error!(
                    "teste",
                    "nao foi possivel entrar em userspace: {}",
                    falha.motivo()
                );
                crate::fios::terminar()
            }
        }
    }

    crate::usuario::limpar_ultima_saida();
    COMECOU.store(false, SeqCst);
    let falhas_antes = crate::traps::total();
    let vivos_antes = crate::fios::estatisticas().0;

    crate::fios::criar("teste-invasor", hospedar, 0)?;

    // Esperamos a falha aparecer na contabilidade de exceções.
    esperar_ate(|| crate::traps::total() > falhas_antes, 300)?;

    if !COMECOU.load(SeqCst) {
        return Err("o fio hospedeiro nunca rodou");
    }

    // Se o invasor tivesse conseguido ler, teria saído com o código dele.
    if crate::usuario::ultima_saida() == Some(crate::usuario::exemplo::CODIGO_DO_INVASOR) {
        return Err("o processo leu memoria do kernel e sobreviveu");
    }

    // O fio do invasor precisa ter sumido — e o kernel, não.
    esperar_ate(|| crate::fios::estatisticas().0 <= vivos_antes, 200)?;

    // Chegar aqui já é metade da prova: o kernel seguiu executando. A outra
    // metade é que ele ainda funciona, então exercitamos um caminho que toca
    // heap, paginação e log.
    let (livres, _) = crate::frames::estatisticas();
    if livres == 0 {
        return Err("o alocador de frames nao sobreviveu");
    }
    crate::log_info!("teste", "kernel vivo depois de matar o invasor");
    Ok(())
}

/// Espera `quantos` tiques do timer passarem.
fn esperar_ticks(quantos: u64) {
    let ate = crate::tempo::ticks().saturating_add(quantos);
    while crate::tempo::ticks() < ate {
        core::hint::spin_loop();
    }
}

/// Espera uma condição, com teto em tiques para não pendurar o CI.
fn esperar_ate(mut condicao: impl FnMut() -> bool, teto_em_ticks: u64) -> Resultado {
    let limite = crate::tempo::ticks().saturating_add(teto_em_ticks);
    while crate::tempo::ticks() < limite {
        if condicao() {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err("a condicao nao se cumpriu dentro do teto de tempo")
}

static CASOS: &[Caso] = &[
    Caso {
        nome: "json: objeto simples",
        f: json_objeto_simples,
    },
    Caso {
        nome: "json: aninhamento e virgulas",
        f: json_aninhado,
    },
    Caso {
        nome: "json: escape de string",
        f: json_escape_de_string,
    },
    Caso {
        nome: "json: escape de controle",
        f: json_escape_de_controle,
    },
    Caso {
        nome: "json: busca de membro",
        f: json_busca_membro,
    },
    Caso {
        nome: "json: ignora chave aninhada",
        f: json_ignora_chave_aninhada,
    },
    Caso {
        nome: "json: delimitador dentro de string",
        f: json_string_com_delimitadores,
    },
    Caso {
        nome: "json: aspa escapada",
        f: json_string_com_aspa_escapada,
    },
    Caso {
        nome: "json: tipos escalares",
        f: json_tipos_escalares,
    },
    Caso {
        nome: "rpc: decompoe requisicao",
        f: protocolo_decompoe_requisicao,
    },
    Caso {
        nome: "rpc: recusa id que nao e JSON",
        f: protocolo_recusa_id_que_nao_e_json,
    },
    Caso {
        nome: "rpc: aceita id legitimo",
        f: protocolo_aceita_id_legitimo,
    },
    Caso {
        nome: "rpc: params ausente vira {}",
        f: protocolo_params_ausente_vira_objeto_vazio,
    },
    Caso {
        nome: "rpc: rejeita lixo",
        f: protocolo_rejeita_lixo,
    },
    Caso {
        nome: "rpc: preserva id no erro",
        f: protocolo_preserva_id_no_erro,
    },
    Caso {
        nome: "canal: descarta ruido das bordas",
        f: enquadramento_descarta_ruido,
    },
    Caso {
        nome: "registro: encontra comandos",
        f: registro_encontra_comandos,
    },
    Caso {
        nome: "registro: valida tipos",
        f: registro_valida_tipos_de_parametro,
    },
    Caso {
        nome: "registro: exige obrigatorios",
        f: registro_exige_parametro_obrigatorio,
    },
    Caso {
        nome: "registro: tudo descrito",
        f: registro_esta_completamente_descrito,
    },
    Caso {
        nome: "comando: system.info fim a fim",
        f: comando_system_info_responde_arquitetura_correta,
    },
    Caso {
        nome: "log: preserva ordem",
        f: log_preserva_ordem,
    },
    Caso {
        nome: "log: filtra por nivel",
        f: log_filtra_por_nivel,
    },
    Caso {
        nome: "log: trunca em fronteira utf-8",
        f: log_trunca_em_fronteira_de_caractere,
    },
    Caso {
        nome: "excecao: breakpoint retomado",
        f: excecao_breakpoint_e_retomada,
    },
    Caso {
        nome: "timer: configurado",
        f: timer_esta_configurado,
    },
    Caso {
        nome: "timer: relogio avanca",
        f: relogio_avanca,
    },
    Caso {
        nome: "irq: timer contabilizado",
        f: irq_do_timer_contabilizada,
    },
    Caso {
        nome: "timer: exatamente um relogio avanca",
        f: timer_exatamente_um_relogio_avanca,
    },
    Caso {
        nome: "fdt: le o blob normal e resiste ao hostil",
        f: fdt_le_o_normal_e_resiste_ao_hostil,
    },
    Caso {
        nome: "fdt: confere deslocamentos contra o tamanho declarado",
        f: fdt_confere_deslocamentos_contra_o_tamanho_declarado,
    },
    Caso {
        nome: "tela: cada formato volta como foi escrito",
        f: tela_cada_formato_volta_como_foi_escrito,
    },
    Caso {
        nome: "tela: stride nao e largura",
        f: tela_stride_nao_e_largura,
    },
    Caso {
        nome: "tela: recorta na borda",
        f: tela_recorta_na_borda,
    },
    Caso {
        nome: "tela: o banner esta na tela de verdade",
        f: tela_banner_esta_na_tela_de_verdade,
    },
    Caso {
        nome: "memoria: regioes coerentes",
        f: regioes_de_memoria_sao_coerentes,
    },
    Caso {
        nome: "frames: alinhados e distintos",
        f: frames_alocacao_alinhada_e_distinta,
    },
    Caso {
        nome: "frames: liberar devolve ao pool",
        f: frames_liberar_devolve_ao_contador,
    },
    Caso {
        nome: "frames: frame nulo reservado",
        f: frames_frame_nulo_nunca_entregue,
    },
    Caso {
        nome: "frames: faixas reservadas fora",
        f: frames_faixas_reservadas_fora_de_circulacao,
    },
    Caso {
        nome: "frames: estatisticas coerentes",
        f: frames_estatisticas_coerentes,
    },
    Caso {
        nome: "paginacao: kernel esta mapeado",
        f: paginacao_traduz_endereco_do_kernel,
    },
    Caso {
        nome: "paginacao: escrita chega ao frame",
        f: paginacao_escreve_e_le_pelo_caminho_fisico,
    },
    Caso {
        nome: "paginacao: desmapear remove traducao",
        f: paginacao_desmapear_remove_traducao,
    },
    Caso {
        nome: "paginacao: recusa duplicado",
        f: paginacao_recusa_mapeamento_duplicado,
    },
    Caso {
        nome: "paginacao: endereco impossivel e seguro",
        f: paginacao_endereco_impossivel_nao_derruba,
    },
    Caso {
        nome: "paginacao: recusa desalinhado",
        f: paginacao_recusa_desalinhado,
    },
    Caso {
        nome: "paginacao: nao vaza tabelas",
        f: paginacao_nao_vaza_tabelas,
    },
    Caso {
        nome: "heap: box aloca e libera",
        f: heap_box_aloca_e_libera,
    },
    Caso {
        nome: "heap: vec cresce e realoca",
        f: heap_vec_cresce,
    },
    Caso {
        nome: "heap: formatacao com alocacao",
        f: heap_string_formata,
    },
    Caso {
        nome: "heap: reaproveita memoria liberada",
        f: heap_reaproveita_memoria_liberada,
    },
    Caso {
        nome: "heap: o relatorio fecha com a lista livre",
        f: heap_relatorio_fecha,
    },
    Caso {
        nome: "heap: funde blocos adjacentes",
        f: heap_funde_blocos_adjacentes,
    },
    Caso {
        nome: "heap: respeita alinhamento",
        f: heap_respeita_alinhamento,
    },
    Caso {
        nome: "heap: falha devolve nulo",
        f: heap_falha_devolve_nulo,
    },
    Caso {
        nome: "heap: estatisticas coerentes",
        f: heap_estatisticas_coerentes,
    },
    Caso {
        nome: "fila: preserva ordem",
        f: fila_preserva_ordem,
    },
    Caso {
        nome: "fila: cheia descarta e conta",
        f: fila_cheia_descarta_e_conta,
    },
    Caso {
        nome: "fila: indices dao a volta",
        f: fila_da_a_volta,
    },
    Caso {
        nome: "tarefa: roda ate o fim",
        f: tarefa_roda_ate_o_fim,
    },
    Caso {
        nome: "tarefa: duas se intercalam",
        f: tarefas_se_intercalam,
    },
    Caso {
        nome: "tarefa: waker acorda bloqueada",
        f: waker_acorda_tarefa_bloqueada,
    },
    Caso {
        nome: "tarefa: relogio acorda tarefa",
        f: relogio_acorda_tarefa,
    },
    Caso {
        nome: "tarefa: os tetos cheios aparecem no relatorio",
        f: tarefa_tetos_cheios_aparecem,
    },
    Caso {
        nome: "tarefa: adormecida nao gira",
        f: tarefa_adormecida_nao_e_repollada,
    },
    Caso {
        nome: "tarefa: dormir em ms arredonda",
        f: dormir_em_ms_arredonda_para_cima,
    },
    Caso {
        nome: "tarefa: dormentes devolvem vaga",
        f: dormentes_devolvem_a_vaga,
    },
    Caso {
        nome: "tarefa: sem timer nao trava",
        f: relogio_sem_timer_nao_trava,
    },
    Caso {
        nome: "machine: recusa regiao degenerada",
        f: machine_recusa_regiao_degenerada,
    },
    Caso {
        nome: "traps: registrar nao bloqueia",
        f: traps_registrar_nao_bloqueia,
    },
    Caso {
        nome: "traps: registrar grava detalhe",
        f: traps_registrar_grava_detalhe,
    },
    Caso {
        nome: "fios: cedem voluntariamente",
        f: fios_cedem_voluntariamente,
    },
    Caso {
        nome: "fios: preemptam sem cooperar",
        f: fios_preemptam_sem_cooperacao,
    },
    Caso {
        nome: "fios: preservam contexto",
        f: fios_preservam_contexto,
    },
    Caso {
        nome: "fios: criacao concorrente",
        f: fios_criacao_concorrente_nao_colide,
    },
    Caso {
        nome: "memoria: espacos isolam o mesmo endereco",
        f: memoria_espacos_isolam_o_mesmo_endereco,
    },
    Caso {
        nome: "usuario: recusa ponteiro de fora",
        f: usuario_recusa_ponteiro_de_fora,
    },
    Caso {
        nome: "usuario: descritor e conferido",
        f: usuario_descritor_e_conferido,
    },
    Caso {
        nome: "elf: aceita a imagem de exemplo",
        f: elf_aceita_a_imagem_de_exemplo,
    },
    Caso {
        nome: "elf: recusa imagens invalidas",
        f: elf_recusa_imagens_invalidas,
    },
    Caso {
        nome: "memoria: desmapear do kernel vale em todo espaco",
        f: memoria_desmapear_do_kernel_vale_em_todo_espaco,
    },
    Caso {
        nome: "pci: varredura coerente",
        f: pci_varredura_coerente,
    },
    Caso {
        nome: "memoria: permissoes sobrevivem a ida e volta",
        f: memoria_permissoes_sobrevivem_a_ida_e_volta,
    },
    Caso {
        nome: "memoria: clonar copia o conteudo",
        f: memoria_clonar_copia_o_conteudo,
    },
    Caso {
        nome: "memoria: espaco destruido devolve tudo",
        f: memoria_espaco_destruido_devolve_tudo,
    },
    Caso {
        nome: "usuario: nenhuma pagina gravavel e executavel",
        f: usuario_nenhuma_pagina_gravavel_e_executavel,
    },
    Caso {
        nome: "usuario: dois processos coexistem",
        f: usuario_dois_processos_coexistem,
    },
    Caso {
        nome: "usuario: executa, bifurca e troca de imagem",
        f: usuario_executa_bifurca_e_troca_de_imagem,
    },
    Caso {
        nome: "pci: regioes atribuidas nao se sobrepoem",
        f: pci_regioes_atribuidas_nao_se_sobrepoem,
    },
    Caso {
        nome: "disco: le a assinatura do setor zero",
        f: disco_le_a_assinatura_do_setor_zero,
    },
    Caso {
        nome: "disco: cada setor devolve o seu padrao",
        f: disco_cada_setor_devolve_o_seu_padrao,
    },
    Caso {
        nome: "disco: recusa setor fora da capacidade",
        f: disco_recusa_setor_fora_da_capacidade,
    },
    Caso {
        nome: "rede: publica um endereco valido",
        f: rede_publica_um_endereco_valido,
    },
    Caso {
        nome: "rede: ARP vai e volta",
        f: rede_arp_vai_e_volta,
    },
    Caso {
        nome: "rede: contadores acompanham o trafego",
        f: rede_contadores_acompanham_o_trafego,
    },
    Caso {
        nome: "rede: cadeia desconhecida desliga a placa",
        f: rede_cadeia_desconhecida_desliga_a_placa,
    },
    Caso {
        nome: "rede: um descritor por buffer, e so um",
        f: rede_um_descritor_por_buffer,
    },
    Caso {
        nome: "irq: o virtio interrompe de verdade",
        f: irq_o_virtio_interrompe_de_verdade,
    },
    Caso {
        nome: "irq: a linha compartilhada nao confunde os donos",
        f: irq_linha_compartilhada_nao_confunde,
    },
    Caso {
        nome: "usuario: nao alcanca o kernel",
        f: usuario_nao_alcanca_o_kernel,
    },
    Caso {
        nome: "usuario: imagem recusada nao custa o espaco",
        f: usuario_imagem_recusada_nao_custa_o_espaco,
    },
];

// ---------------------------------------------------------------------------
// O disco
// ---------------------------------------------------------------------------

/// A assinatura que o `xtask` grava no começo do disco de testes.
///
/// Ela e a regra de preenchimento abaixo são metade de um contrato cujo outro
/// lado está em `xtask/src/main.rs`. Duplicá-las é o preço de o disco ser
/// gerado por um programa que roda no hospedeiro e lido por outro que roda no
/// hóspede — não há lugar comum onde as duas metades caibam. O que impede a
/// divergência é este teste: se o `xtask` mudar a regra e não mudar esta, o
/// caso falha.
const ASSINATURA_DO_DISCO: &[u8] = b"DUKE-DISCO-v1";

/// O byte com que o setor `numero` é preenchido.
///
/// Deriva do número do setor de propósito. Zeros pareceriam plausíveis em
/// qualquer lugar, e um erro de deslocamento — ler o setor 3 quando se pediu o
/// 4 — passaria despercebido. Com um padrão que muda a cada setor, ler o setor
/// errado é indistinguível de não ler nada.
fn marca_do_setor(numero: u64) -> u8 {
    (numero as u8).wrapping_mul(7).wrapping_add(1)
}

/// Nenhum dispositivo recebeu uma faixa de memória que invada a de outro.
///
/// É a invariante do distribuidor de BARs, e a única que uma inspeção do
/// `pci.list` não pegaria: dois dispositivos com endereços diferentes ainda
/// podem se sobrepor se o tamanho de um alcançar o começo do outro. Foi
/// exatamente o que o alinhamento ao tamanho do BAR existe para impedir.
fn pci_regioes_atribuidas_nao_se_sobrepoem() -> Resultado {
    // Cada dispositivo pode ter até seis regiões, e o inventário tem teto.
    let mut faixas = [(0u64, 0u64); crate::pci::MAX_DISPOSITIVOS * crate::pci::BARS];
    let mut quantas = 0usize;
    let mut falha: Option<&'static str> = None;

    crate::pci::com_dispositivos(|d| {
        for regiao in d.regioes.iter().flatten() {
            if regiao.tamanho == 0 {
                falha = Some("uma regiao foi registrada com tamanho zero");
                continue;
            }
            // O alinhamento não é cosmético: os bits baixos de um BAR são
            // fixos em zero, então um endereço desalinhado não é o endereço
            // que o dispositivo passou a decodificar.
            if !regiao.tamanho.is_power_of_two() || regiao.base % regiao.tamanho != 0 {
                falha = Some("uma regiao nao esta alinhada ao proprio tamanho");
            }
            if quantas < faixas.len() {
                faixas[quantas] = (regiao.base, regiao.tamanho);
                quantas += 1;
            }
        }
    });

    if let Some(motivo) = falha {
        return Err(motivo);
    }
    if quantas == 0 {
        return Err("nenhum dispositivo tem regiao de memoria");
    }

    for i in 0..quantas {
        let (base_a, tamanho_a) = faixas[i];
        for &(base_b, tamanho_b) in faixas.iter().take(quantas).skip(i + 1) {
            if base_a < base_b + tamanho_b && base_b < base_a + tamanho_a {
                crate::log_error!(
                    "teste",
                    "regioes sobrepostas: {:#x}+{:#x} e {:#x}+{:#x}",
                    base_a,
                    tamanho_a,
                    base_b,
                    tamanho_b
                );
                return Err("duas regioes de memoria se sobrepoem");
            }
        }
    }

    Ok(())
}

/// O primeiro setor traz a assinatura que o `xtask` gravou.
///
/// É o teste que separa "a leitura retornou" de "a leitura funcionou". Um
/// caminho de DMA quebrado devolve um buffer intacto — e um buffer intacto é
/// de zeros, que passariam por qualquer verificação frouxa.
fn disco_le_a_assinatura_do_setor_zero() -> Resultado {
    let mut setor = [0u8; crate::virtio::blk::TAMANHO_DO_SETOR];
    let Some(resultado) = crate::virtio::blk::com_o_disco(|d| d.ler_setor(0, &mut setor)) else {
        return Err("nao ha disco nesta maquina");
    };
    resultado?;

    if &setor[..ASSINATURA_DO_DISCO.len()] != ASSINATURA_DO_DISCO {
        crate::log_error!(
            "teste",
            "o setor zero comeca com {:#04x} {:#04x} {:#04x} {:#04x}",
            setor[0],
            setor[1],
            setor[2],
            setor[3]
        );
        return Err("o setor zero nao traz a assinatura do disco");
    }

    // O resto do setor zero segue a mesma regra dos outros. Conferi-lo aqui é
    // o que prova que a leitura trouxe o setor **inteiro**, e não só os
    // primeiros bytes.
    let marca = marca_do_setor(0);
    if setor[ASSINATURA_DO_DISCO.len()..]
        .iter()
        .any(|&b| b != marca)
    {
        return Err("o resto do setor zero nao segue o padrao");
    }

    Ok(())
}

/// Setores diferentes devolvem conteúdos diferentes, e o certo para cada um.
///
/// Ler o setor zero corretamente ainda seria compatível com um driver que
/// ignora o número do setor e devolve sempre o primeiro. Esta é a verificação
/// que fecha essa porta.
fn disco_cada_setor_devolve_o_seu_padrao() -> Resultado {
    // Os escolhidos não são consecutivos de propósito: um erro de um setor
    // para cima ou para baixo é o mais provável, e saltos o tornam visível.
    const ALVOS: [u64; 5] = [1, 2, 7, 64, 255];

    let mut setor = [0u8; crate::virtio::blk::TAMANHO_DO_SETOR];

    for numero in ALVOS {
        let Some(resultado) = crate::virtio::blk::com_o_disco(|d| d.ler_setor(numero, &mut setor))
        else {
            return Err("nao ha disco nesta maquina");
        };
        resultado?;

        let esperado = marca_do_setor(numero);
        if let Some(posicao) = setor.iter().position(|&b| b != esperado) {
            crate::log_error!(
                "teste",
                "setor {}: byte {} e {:#04x}, esperava {:#04x}",
                numero,
                posicao,
                setor[posicao],
                esperado
            );
            return Err("um setor veio com o conteudo de outro");
        }
    }

    Ok(())
}

/// Pedir um setor além do fim do disco é erro, e não uma leitura de lixo.
///
/// O limite é conferido do nosso lado antes de o pedido chegar ao
/// dispositivo. Poderia não ser — o dispositivo também recusaria —, mas então
/// o erro voltaria como "o dispositivo recusou", que não diz por quê.
fn disco_recusa_setor_fora_da_capacidade() -> Resultado {
    let Some(capacidade) = crate::virtio::blk::com_o_disco(|d| d.capacidade()) else {
        return Err("nao ha disco nesta maquina");
    };
    if capacidade == 0 {
        return Err("o disco diz ter zero setores");
    }

    let mut setor = [0u8; crate::virtio::blk::TAMANHO_DO_SETOR];
    let resultado = crate::virtio::blk::com_o_disco(|d| d.ler_setor(capacidade, &mut setor));

    match resultado {
        Some(Err(_)) => Ok(()),
        Some(Ok(())) => Err("o disco aceitou ler um setor que nao existe"),
        None => Err("nao ha disco nesta maquina"),
    }
}

// ---------------------------------------------------------------------------
// A rede
// ---------------------------------------------------------------------------

/// O endereço que a rede em modo usuário do QEMU dá ao hóspede.
const NOSSO_IP: [u8; 4] = [10, 0, 2, 15];
/// O roteador dessa rede, que é quem responde ao ARP.
const IP_DO_ROTEADOR: [u8; 4] = [10, 0, 2, 2];

/// A placa publica um endereço, e ele não é um dos inválidos.
///
/// Um endereço todo zeros é o que se lê de um registrador que não responde;
/// um todo `0xFF` é o que o barramento devolve quando ninguém atende. Os dois
/// pareceriam um MAC para quem só conferisse o tamanho.
fn rede_publica_um_endereco_valido() -> Resultado {
    let Some(mac) = crate::virtio::net::com_a_placa(|placa| placa.mac()) else {
        return Err("nao ha placa de rede nesta maquina");
    };
    let Some(mac) = mac else {
        return Err("a placa nao publicou endereco");
    };

    if mac.iter().all(|&b| b == 0) {
        return Err("o endereco e todo zeros");
    }
    if mac.iter().all(|&b| b == 0xFF) {
        return Err("o endereco e todo uns");
    }
    // O bit de multicast no primeiro byte não pode estar aceso num endereço
    // de placa: seria um endereço de grupo, e nenhuma placa se chama assim.
    if mac[0] & 1 != 0 {
        return Err("o endereco tem o bit de grupo aceso");
    }

    Ok(())
}

/// Um pedido ARP sai e a resposta volta.
///
/// É o teste que exercita as duas filas de uma vez, e prova algo que nenhum
/// exame interno provaria: que os bytes saíram do kernel, foram interpretados
/// por outro software e voltaram. Um driver que transmitisse para o nada e
/// recebesse lixo passaria por qualquer verificação que só olhasse para os
/// contadores.
///
/// Toda a conferência da resposta está em [`crate::rede::resolver`], que é
/// quem o canal do agente também chama — de propósito. Um teste que validasse
/// por um caminho próprio deixaria o caminho de produção sem teste.
fn rede_arp_vai_e_volta() -> Resultado {
    let dono = crate::rede::resolver(&IP_DO_ROTEADOR, &NOSSO_IP)?;

    crate::log_info!(
        "teste",
        "{}.{}.{}.{} responde de {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        IP_DO_ROTEADOR[0],
        IP_DO_ROTEADOR[1],
        IP_DO_ROTEADOR[2],
        IP_DO_ROTEADOR[3],
        dono[0],
        dono[1],
        dono[2],
        dono[3],
        dono[4],
        dono[5]
    );

    Ok(())
}

/// Os contadores da placa acompanham o que passou por ela.
///
/// Um driver pode acertar o diálogo e mentir no relatório, e é o relatório
/// que o agente lê. Este caso confere que os dois concordam: depois de um ARP
/// que deu certo, ao menos um quadro saiu e ao menos um entrou.
fn rede_contadores_acompanham_o_trafego() -> Resultado {
    let Some((transmitidos, recebidos)) =
        crate::virtio::net::com_a_placa(|placa| placa.contadores())
    else {
        return Err("nao ha placa de rede nesta maquina");
    };

    if transmitidos == 0 {
        return Err("a placa diz nao ter transmitido nada");
    }
    if recebidos == 0 {
        return Err("a placa diz nao ter recebido nada");
    }

    Ok(())
}

/// Uma cadeia colhida que não é de nenhum buffer desliga a placa.
///
/// # O que este caso protege
///
/// A colheita devolve o índice do descritor que encabeça a cadeia, e o driver
/// descobre por ele de qual buffer o pacote veio. Quando esse índice não
/// corresponde a buffer nenhum, o anel deixou de descrever a realidade.
///
/// A primeira versão deste driver respondia a isso caindo no buffer zero.
/// Duas coisas ruins saíam dali: um quadro que nunca chegou era entregue e
/// contado como recebido — um valor plausível e errado —, e a leitura caía
/// num buffer que continuava pendurado, isto é, que o dispositivo podia estar
/// escrevendo naquele instante. É a mesma corrida de DMA que o disco e a
/// transmissão já tratavam como fatal; só a recepção não tratava.
///
/// # Por que a falha é injetada
///
/// Porque o dispositivo do QEMU não comete esse erro, e um defeito que só
/// aparece com hardware quebrado ficaria sem teste para sempre. A injeção
/// atinge exatamente a comparação que decide o índice, trocando os endereços
/// que o driver guarda — o dispositivo segue com os buffers de verdade.
fn rede_cadeia_desconhecida_desliga_a_placa() -> Resultado {
    let Some(vivo) = crate::virtio::net::com_a_placa(|placa| placa.vivo()) else {
        return Err("nao ha placa de rede nesta maquina");
    };
    if !vivo {
        return Err("a placa ja estava desligada antes do caso");
    }

    let Some(verdadeiros) = crate::virtio::net::com_a_placa(|placa| placa.desfigurar_buffers())
    else {
        return Err("nao ha placa de rede nesta maquina");
    };

    // Um ARP para provocar a resposta que será colhida. O resultado dele não
    // interessa: o que interessa é o que a colheita fez com a placa.
    let resposta = crate::rede::resolver(&IP_DO_ROTEADOR, &NOSSO_IP);

    let Some(vivo) = crate::virtio::net::com_a_placa(|placa| placa.vivo()) else {
        return Err("nao ha placa de rede nesta maquina");
    };

    crate::virtio::net::com_a_placa(|placa| placa.restaurar_buffers(verdadeiros));

    if vivo {
        return Err("a placa continuou no ar depois de colher uma cadeia que nao reconhece");
    }
    if resposta.is_ok() {
        return Err("o ARP foi respondido por uma placa que nao reconhecia os buffers");
    }

    // A reparação precisa valer: uma placa que não voltasse daqui deixaria os
    // casos seguintes falhando por culpa deste.
    crate::rede::resolver(&IP_DO_ROTEADOR, &NOSSO_IP)?;

    crate::log_info!(
        "teste",
        "placa desligada por cadeia desconhecida e recolocada no ar"
    );

    Ok(())
}

/// Cada buffer de recepção está pendurado uma vez só.
///
/// # O defeito que este caso pega
///
/// `pendurar_buffers` percorria os quatro buffers e entregava cada um
/// enquanto houvesse descritor livre, sem ter como saber quais já estavam com
/// o dispositivo. Depois de cada colheita ela entregava de novo os três que
/// nunca tinham voltado.
///
/// O mesmo buffer entregue duas vezes é o dispositivo escrevendo dois pacotes
/// na mesma memória: um sobrescreve o outro, e as duas colheitas devolvem o
/// mesmo conteúdo. Um pacote perdido e um duplicado, sem uma linha de log.
///
/// Nada disso aparece num teste que só confira se o ARP volta — e não
/// aparecia: a suíte inteira passava. O que aparece é a contagem de
/// descritores, que é o mesmo defeito visto pelo outro lado. Ela caía de
/// quatro livres para um depois do primeiro pacote e para zero depois do
/// segundo.
///
/// Este caso roda depois de todo o tráfego dos anteriores, inclusive da placa
/// que foi desligada e recolocada no ar — então ele também confere que aquela
/// reparação devolveu o estado certo, e não um aproximado.
fn rede_um_descritor_por_buffer() -> Resultado {
    let Some(em_uso) =
        crate::virtio::net::com_a_placa(|placa| placa.descritores_de_recepcao_em_uso())
    else {
        return Err("nao ha placa de rede nesta maquina");
    };

    if em_uso != crate::virtio::net::BUFFERS_DE_RECEPCAO {
        crate::log_error!(
            "teste",
            "{} descritores em uso para {} buffers",
            em_uso,
            crate::virtio::net::BUFFERS_DE_RECEPCAO
        );
        return Err("a fila de recepcao nao tem um descritor por buffer");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Roteamento de interrupção
// ---------------------------------------------------------------------------

/// Quantas voltas esperar a interrupção chegar depois de gerar o trabalho.
///
/// A entrega não é instantânea: o acesso ao disco roda com interrupções
/// mascaradas, então o sinal fica pendente no controlador e só é entregue
/// depois que a tranca do driver é solta. O laço aqui existe justamente para
/// dar essa janela.
const VOLTAS_ESPERANDO_INTERRUPCAO: u32 = 2_000_000;

/// Quantas voltas esperar o **relógio** andar os tiques de que um caso precisa.
///
/// # Por que não serve o teto acima
///
/// Porque os dois medem coisas diferentes. Lá a interrupção já está pendente
/// no controlador e chega em microssegundos assim que a tranca é solta; aqui é
/// preciso esperar **tempo de parede** — três tiques a 100 Hz são trinta
/// milissegundos.
///
/// Um teto de voltas é um substituto ruim para uma duração, e o erro de
/// calibração não aparece onde se testa. Medido, contando as voltas até o
/// terceiro tique no ARM:
///
///   debug:    104 372 voltas
///   release:  2 000 000 voltas — o teto inteiro, sem nunca completar os três
///
/// Ou seja: em release o caso já rodava exatamente no limite nesta máquina, e
/// passava porque um tique ainda cabia. Num runner da CI, mais rápido, nem
/// esse coube, e o caso acusou "o relogio parou" num kernel cujo relógio
/// estava perfeito.
///
/// Dois bilhões cobrem os trinta milissegundos com duas ordens de grandeza de
/// folga mesmo a um nanossegundo por volta. O preço é que um relógio de fato
/// parado leva alguns segundos para ser declarado morto — a troca certa, já
/// que o outro lado custa uma CI vermelha sem defeito nenhum.
const VOLTAS_ESPERANDO_O_RELOGIO: u64 = 2_000_000_000;

/// O dispositivo interrompe, e a interrupção chega.
///
/// # Por que este caso não é redundante com os outros
///
/// Porque disco e rede funcionam **sem** interrupção nenhuma. Os dois esperam
/// em laço lendo o anel de usados, que o dispositivo preenche por DMA — todos
/// os outros casos passariam com o roteamento completamente quebrado.
///
/// Descobrir a linha também não prova nada: um número lido do device tree ou
/// de um registrador de configuração é só um número. O que prova é o
/// contador subir, e ele só sobe se a linha certa foi encontrada, se ela foi
/// liberada nos dois controladores certos, se o vetor existia na tabela, e se
/// o dispositivo não foi instruído a ficar calado.
///
/// São cinco coisas, e este é o único caso que falha se qualquer uma delas
/// estiver errada.
fn irq_o_virtio_interrompe_de_verdade() -> Resultado {
    let antes = crate::virtio::total_de_avisos();

    // Gerar trabalho: uma leitura de disco basta, e é a mais barata.
    let mut setor = [0u8; crate::virtio::blk::TAMANHO_DO_SETOR];
    let Some(resultado) = crate::virtio::blk::com_o_disco(|d| d.ler_setor(1, &mut setor)) else {
        return Err("nao ha disco nesta maquina");
    };
    resultado?;

    for _ in 0..VOLTAS_ESPERANDO_INTERRUPCAO {
        if crate::virtio::total_de_avisos() > antes {
            return Ok(());
        }
        core::hint::spin_loop();
    }

    Err("o dispositivo trabalhou mas nenhuma interrupcao chegou")
}

/// Numa linha compartilhada, quem trabalhou é quem conta.
///
/// # O caso que este teste existe para pegar
///
/// No x86 o disco e a rede caem os dois na IRQ 11. Uma entrega dessa linha
/// não diz qual dos dois a levantou, e a primeira versão deste kernel contava
/// uma para cada — um número plausível, que não respondia a pergunta que o
/// nome dele fazia.
///
/// A resposta está no registrador de estado de cada dispositivo: quem não
/// interrompeu lê zero. O teste força tráfego de **um** deles e confere que o
/// outro não foi creditado.
///
/// No ARM as linhas são separadas e o caso passa trivialmente. Ele vale
/// mesmo assim: a atribuição é do código comum, e um dia o ARM também terá
/// dois dispositivos no mesmo pino.
fn irq_linha_compartilhada_nao_confunde() -> Resultado {
    let Some(rede_antes) = crate::virtio::avisos_de("rede") else {
        return Err("a rede nao registrou interrupcao");
    };
    let Some(disco_antes) = crate::virtio::avisos_de("disco") else {
        return Err("o disco nao registrou interrupcao");
    };

    let mut setor = [0u8; crate::virtio::blk::TAMANHO_DO_SETOR];
    let Some(resultado) = crate::virtio::blk::com_o_disco(|d| d.ler_setor(2, &mut setor)) else {
        return Err("nao ha disco nesta maquina");
    };
    resultado?;

    let mut subiu = false;
    for _ in 0..VOLTAS_ESPERANDO_INTERRUPCAO {
        if crate::virtio::avisos_de("disco").unwrap_or(0) > disco_antes {
            subiu = true;
            break;
        }
        core::hint::spin_loop();
    }

    if !subiu {
        return Err("o disco trabalhou mas nao foi creditado");
    }

    // A rede não transmitiu nada nesse intervalo. Se o contador dela subiu, o
    // crédito foi dado pela linha e não pelo dispositivo.
    let rede_depois = crate::virtio::avisos_de("rede").unwrap_or(0);
    if rede_depois != rede_antes {
        crate::log_error!(
            "teste",
            "a rede foi de {} para {} sem transmitir nada",
            rede_antes,
            rede_depois
        );
        return Err("a interrupcao do disco foi creditada tambem a rede");
    }

    Ok(())
}

/// Roda todos os casos e encerra o emulador com o veredito.
pub fn executar_todos() -> ! {
    crate::serial_println!();
    crate::serial_println!("=====================================================");
    crate::serial_println!(
        "  suite de testes :: {} :: {} casos",
        crate::arch::nome(),
        CASOS.len()
    );
    crate::serial_println!("=====================================================");

    let mut falhas = 0usize;

    for caso in CASOS {
        // O resultado é impresso *depois* de rodar, e não antes, porque um
        // teste que emite log jogaria essas linhas no meio de uma linha de
        // relatório pela metade. Assim cada linha do relatório fica íntegra e
        // os logs do teste aparecem logo acima dela, que é onde ajudam.
        let resultado = (caso.f)();
        match resultado {
            Ok(()) => crate::serial_println!("  {:<42} ok", caso.nome),
            Err(motivo) => {
                falhas += 1;
                crate::serial_println!("  {:<42} FALHOU -- {}", caso.nome, motivo);
            }
        }
    }

    crate::serial_println!("-----------------------------------------------------");
    crate::serial_println!("  {} de {} passaram", CASOS.len() - falhas, CASOS.len());

    if falhas > 0 {
        crate::serial_println!("=====================================================");
        crate::serial_println!();
        crate::qemu::encerrar(crate::qemu::Resultado::Falha);
    }

    // O caso final fica fora da tabela porque não devolve o controle: ele
    // encerra o emulador de dentro do handler de falha.
    estouro_de_pilha_e_detectado()
}
