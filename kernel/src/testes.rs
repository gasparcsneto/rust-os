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
