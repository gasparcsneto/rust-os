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

    let (utilizavel, total, quantas) = crate::machine::estatisticas();
    if quantas == 0 {
        return Err("nenhuma regiao de memoria descoberta");
    }
    if utilizavel > total {
        return Err("memoria utilizavel maior que o total");
    }
    if utilizavel == 0 {
        return Err("nenhuma memoria utilizavel");
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
fn tarefa_adormecida_nao_e_repollada() -> Resultado {
    const ESPERA: u64 = 5;
    // Uma repolagem para registrar o sono, uma para confirmar que venceu, e
    // folga para um despertar espúrio no limiar do tique.
    const TETO_DE_AVANCOS: u64 = 4;

    async fn corpo() {
        crate::tarefas::relogio::por_ticks(ESPERA).await;
    }

    let antes = crate::tarefas::executor::estatisticas().2;

    let mut executor = crate::tarefas::executor::Executor::novo();
    executor.lancar(crate::tarefas::Tarefa::nova("teste-ocioso", corpo()));
    executor.rodar_ate_esvaziar(64)?;

    let avancos = crate::tarefas::executor::estatisticas().2 - antes;
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

    let (_, _, antes) = crate::machine::estatisticas();
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

    let (_, _, depois) = crate::machine::estatisticas();
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
];

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
