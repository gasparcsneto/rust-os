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

/// Um parâmetro que o comando não declara derruba a chamada.
///
/// # Por que recusar, e não ignorar
///
/// Porque ignorar produz a pior resposta possível: sucesso por um pedido que
/// o kernel não honrou. Medido contra um kernel de pé, antes:
///
///     -> {"method":"user.run","params":{"name":"nao_existe"}}
///     <- {"result":{"launched":true,"thread_id":2}}
///
/// `user.run` não declara parâmetro nenhum. O `name` foi jogado fora, o
/// programa embutido de sempre rodou, e o agente recebeu `launched: true`.
///
/// Num sistema em que o cliente descobre a interface em tempo de execução, e
/// portanto às vezes chuta, um erro que aponta o campo é o que o manda ler
/// `agent.describe` em vez de acreditar num sucesso que não houve.
fn protocolo_recusa_parametro_nao_declarado() -> Resultado {
    let Some(cmd) = registry::encontrar("log.tail") else {
        return Err("log.tail sumiu do registro");
    };

    // Um campo inventado, sozinho e acompanhado de um legítimo.
    for bruto in [
        br#"{"inventado":1}"#.as_slice(),
        br#"{"count":3,"inventado":"x"}"#.as_slice(),
        br#"{"Count":3}"#.as_slice(), // caixa diferente é outro nome
    ] {
        match registry::validar(cmd, Json(bruto)) {
            Err(campo) if campo == "inventado" || campo == "Count" => {}
            Err(outro) => {
                crate::log_error!("teste", "recusou o campo errado: {}", outro);
                return Err("a recusa apontou um campo que nao e o desconhecido");
            }
            Ok(()) => return Err("um parametro nao declarado foi aceito"),
        }
    }

    // E a metade que impede um conserto estrito demais: o que é declarado
    // continua passando, sozinho, junto e ausente.
    for bruto in [
        br#"{}"#.as_slice(),
        br#"{"count":3}"#.as_slice(),
        br#"{"count":3,"min_level":"info"}"#.as_slice(),
    ] {
        if registry::validar(cmd, Json(bruto)).is_err() {
            return Err("um parametro legitimo foi recusado");
        }
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
// Pilha gráfica
// ===========================================================================

/// O recorte do dano mantém todo retângulo dentro da área, para qualquer
/// entrada — inclusive a que o original do Redox deixa escapar.
fn grafico_dano_recorta_nas_bordas() -> Resultado {
    use crate::grafico::Dano;

    let casos: [(Dano, Dano, &str); 6] = [
        (Dano::novo(2, 3, 4, 5), Dano::novo(2, 3, 4, 5), "dentro"),
        (
            Dano::novo(10, 0, 20, 1),
            Dano::novo(10, 0, 6, 1),
            "cruza a direita",
        ),
        (
            Dano::novo(0, 6, 1, 20),
            Dano::novo(0, 6, 1, 2),
            "cruza embaixo",
        ),
        (
            Dano::novo(40, 40, 5, 5),
            Dano::novo(16, 8, 0, 0),
            "todo fora",
        ),
        (
            Dano::novo(0, 0, 16, 8),
            Dano::novo(0, 0, 16, 8),
            "a area inteira",
        ),
        // O que o `Damage::clip` do Redox devolve como x=16, largura=10:
        // dez colunas fora da área. Aqui, nada.
        (
            Dano::novo(u32::MAX - 1, 0, 10, 1),
            Dano::novo(16, 0, 0, 1),
            "x no fim do u32",
        ),
    ];

    for (entrada, esperado, nome) in casos {
        let saida = entrada.recortar(16, 8);
        if saida != esperado {
            crate::log_error!(
                "teste",
                "{}: {:?} recortou para {:?}, esperado {:?}",
                nome,
                entrada,
                saida,
                esperado
            );
            return Err("o recorte do dano devolveu outro retangulo");
        }
        // A propriedade que importa, conferida à parte do valor exato: nada
        // passa da borda.
        if saida.x as u64 + saida.largura as u64 > 16 || saida.y as u64 + saida.altura as u64 > 8 {
            return Err("o recorte deixou o retangulo passar da borda");
        }
    }
    Ok(())
}

/// Unir dois danos dá o menor retângulo que cobre os dois, e unir com um
/// vazio não muda nada.
fn grafico_dano_une() -> Resultado {
    use crate::grafico::Dano;

    if Dano::novo(1, 2, 3, 4).unir(Dano::novo(10, 1, 2, 2)) != Dano::novo(1, 1, 11, 5) {
        return Err("a uniao de dois danos nao cobre os dois");
    }
    if Dano::novo(1, 2, 3, 4).unir(Dano::novo(0, 0, 0, 0)) != Dano::novo(1, 2, 3, 4) {
        return Err("unir com um dano vazio mudou o retangulo");
    }
    if Dano::novo(0, 0, 0, 5).unir(Dano::novo(1, 2, 3, 4)) != Dano::novo(1, 2, 3, 4) {
        return Err("um dano vazio expandiu a uniao");
    }
    Ok(())
}

/// Uma tela sintética sobre memória própria, cheia de um byte sentinela.
///
/// O sentinela é o que permite ver a escrita que **não** deveria ter
/// acontecido: o preenchimento entre a largura e o stride de cada linha não é
/// tela, e nada pode tocar nele.
fn tela_sintetica(
    largura: u32,
    altura: u32,
    stride: u32,
    bytes_por_pixel: u32,
    formato: crate::tela::Formato,
) -> Result<(crate::grafico::memoria::Memoria, crate::tela::Tela), &'static str> {
    const SENTINELA: u8 = 0x5A;
    let bytes = stride as u64 * altura as u64 * bytes_por_pixel as u64;
    let memoria = crate::grafico::memoria::Memoria::nova(bytes)?;
    // SAFETY: a memória é nossa, mapeada e gravável, com `bytes` de extensão.
    unsafe { core::ptr::write_bytes(memoria.inicio() as *mut u8, SENTINELA, bytes as usize) };
    // SAFETY: a mesma memória, que vive enquanto a `Memoria` devolvida viver.
    let tela = unsafe {
        crate::tela::sintetica(
            memoria.inicio(),
            largura,
            altura,
            stride,
            bytes_por_pixel,
            formato,
        )
    }
    .ok_or("a tela sintetica foi recusada")?;
    Ok((memoria, tela))
}

/// Atualizar leva à tela o retângulo do dano, e só ele — nos quatro
/// formatos, e sem tocar no preenchimento entre a largura e o stride.
///
/// # Por que quatro formatos numa máquina que tem um
///
/// As duas máquinas da suíte são BGR de quatro bytes por pixel. Um adaptador
/// que trocasse vermelho e azul, ou que escrevesse quatro bytes onde a placa
/// tem três, passaria em toda rodada — e erraria na primeira máquina real com
/// outra placa. O `vesad`, de onde este adaptador vem, só sabe o formato das
/// duas máquinas.
fn grafico_atualizar_leva_so_o_dano() -> Resultado {
    use crate::grafico::linear::AdaptadorLinear;
    use crate::grafico::{AdaptadorGrafico, Dano, Superficie};
    use crate::tela::{Cor, Formato};

    const LARGURA: u32 = 16;
    const ALTURA: u32 = 8;
    // Maior que a largura, de propósito: um adaptador que confundisse os
    // dois desenharia inclinado, e escreveria no preenchimento.
    const STRIDE: u32 = 20;
    // Três canais distintos: uma troca de vermelho com azul muda o valor.
    const ANTES: Cor = Cor::nova(0x11, 0x22, 0x33);
    const DEPOIS: Cor = Cor::nova(0xAA, 0xBB, 0xCC);
    let dano = Dano::novo(3, 2, 5, 3);

    for (formato, bytes_por_pixel) in [
        (Formato::Bgr, 4),
        (Formato::Rgb, 4),
        (Formato::Bgr, 3),
        (Formato::Rgb, 3),
    ] {
        let (memoria, tela) = tela_sintetica(LARGURA, ALTURA, STRIDE, bytes_por_pixel, formato)?;
        let mut adaptador = AdaptadorLinear::novo(tela);
        let mut superficie = adaptador.criar_superficie(LARGURA, ALTURA)?;

        superficie.pixels_mut().fill(ANTES.para_u32());
        adaptador.atualizar(0, &superficie, Dano::inteiro(LARGURA, ALTURA))?;

        superficie.pixels_mut().fill(DEPOIS.para_u32());
        let levado = adaptador.atualizar(0, &superficie, dano)?;
        if levado != dano {
            return Err("atualizar nao devolveu o dano que levou");
        }

        for y in 0..ALTURA {
            for x in 0..LARGURA {
                let dentro = x >= dano.x
                    && x < dano.x + dano.largura
                    && y >= dano.y
                    && y < dano.y + dano.altura;
                let esperada = if dentro { DEPOIS } else { ANTES };
                if tela.ler_pixel(x, y) != Some(esperada) {
                    crate::log_error!(
                        "teste",
                        "{} {} bytes/pixel: ({}, {}) = {:?}, esperada {:?}",
                        formato.como_str(),
                        bytes_por_pixel,
                        x,
                        y,
                        tela.ler_pixel(x, y),
                        esperada
                    );
                    return Err("o pixel na tela nao e o que o dano devia deixar");
                }
            }
        }

        // O preenchimento de cada linha segue intacto.
        let bytes = memoria.inicio() as *const u8;
        for y in 0..ALTURA {
            for x in LARGURA..STRIDE {
                for b in 0..bytes_por_pixel {
                    let em = (y * STRIDE + x) * bytes_por_pixel + b;
                    // SAFETY: `em` está dentro da memória da tela sintética.
                    if unsafe { core::ptr::read_volatile(bytes.add(em as usize)) } != 0x5A {
                        crate::log_error!(
                            "teste",
                            "{} {} bytes/pixel: preenchimento tocado na linha {}, coluna {}",
                            formato.como_str(),
                            bytes_por_pixel,
                            y,
                            x
                        );
                        return Err("o adaptador escreveu entre a largura e o stride");
                    }
                }
            }
        }
    }
    Ok(())
}

/// O dano que escapa do recorte do Redox não escreve nada aqui.
///
/// É o caso integrado do que `grafico_dano_recorta_nas_bordas` confere na
/// aritmética: o mesmo retângulo, agora passando pelo adaptador até a
/// memória. Com a soma do original, e `overflow-checks` ligado em release,
/// isto seria pânico do kernel; com a soma que dá a volta, dez colunas além
/// de cada linha.
fn grafico_dano_hostil_nao_escreve() -> Resultado {
    use crate::grafico::linear::AdaptadorLinear;
    use crate::grafico::{AdaptadorGrafico, Dano, Superficie};

    let (memoria, tela) = tela_sintetica(16, 8, 20, 4, crate::tela::Formato::Bgr)?;
    let mut adaptador = AdaptadorLinear::novo(tela);
    let mut superficie = adaptador.criar_superficie(16, 8)?;
    superficie.pixels_mut().fill(0x00FF_FFFF);

    let levado = adaptador.atualizar(0, &superficie, Dano::novo(u32::MAX - 1, 0, 10, 8))?;
    if !levado.vazio() {
        return Err("um dano inteiro fora da tela levou alguma coisa");
    }

    let bytes = memoria.inicio() as *const u8;
    for i in 0..(20 * 8 * 4) {
        // SAFETY: dentro da memória da tela sintética.
        if unsafe { core::ptr::read_volatile(bytes.add(i)) } != 0x5A {
            return Err("um dano inteiro fora da tela escreveu na memoria");
        }
    }
    Ok(())
}

/// Uma superfície devolve ao alocador cada frame que tomou.
fn grafico_superficie_devolve_os_frames() -> Resultado {
    use crate::grafico::linear::AdaptadorLinear;
    use crate::grafico::{AdaptadorGrafico, Superficie};

    let (_memoria, tela) = tela_sintetica(16, 8, 16, 4, crate::tela::Formato::Bgr)?;
    let mut adaptador = AdaptadorLinear::novo(tela);

    // 64x64 a quatro bytes são quatro páginas, exatas.
    const PAGINAS: u64 = 4;
    let (vivas_antes, bytes_antes) = crate::grafico::memoria::vivas();

    let superficie = adaptador.criar_superficie(64, 64)?;
    if superficie.bytes() != PAGINAS * crate::arch::TAMANHO_PAGINA {
        return Err("a superficie nao segura as paginas que devia");
    }
    let (vivas_com, bytes_com) = crate::grafico::memoria::vivas();
    if vivas_com != vivas_antes + 1 || bytes_com != bytes_antes + superficie.bytes() {
        return Err("o relatorio nao contou a superficie nova");
    }

    // Medido entre criar e largar, e não desde antes de criar: criar pode
    // montar tabelas de tradução que ficam — elas são do kernel, e não da
    // superfície. O que a superfície tomou para si, ela devolve inteiro.
    // Mascarado, pela mesma razão do caso do `mmio`: o coletor de fios
    // mortos devolve frames em outro fio, e cairia dentro da conta.
    let (livres_com, livres_depois) = crate::arch::sem_interrupcoes(|| {
        let (livres_com, _) = crate::frames::estatisticas();
        drop(superficie);
        let (livres_depois, _) = crate::frames::estatisticas();
        (livres_com, livres_depois)
    });
    if livres_depois as u64 != livres_com as u64 + PAGINAS {
        crate::log_error!(
            "teste",
            "livres: {} com a superficie, {} depois de largar",
            livres_com,
            livres_depois
        );
        return Err("largar a superficie nao devolveu os frames dela");
    }
    if crate::grafico::memoria::vivas() != (vivas_antes, bytes_antes) {
        return Err("o relatorio seguiu contando a superficie largada");
    }
    Ok(())
}

/// Uma superfície que falha no meio não deixa página mapeada para trás.
///
/// # A armadilha que este caso contorna
///
/// Uma falha na **primeira** alocação não prova nada: o desfazer roda com
/// nada a desfazer. A falha precisa cair depois de ao menos uma página ter
/// sido mapeada — e para isso as tabelas de tradução da região precisam já
/// existir, ou a segunda alocação seria uma tabela da página zero, e não o
/// frame da página um.
fn grafico_superficie_que_falha_no_meio_desfaz() -> Resultado {
    use crate::grafico::memoria::{Memoria, onde_cairia, vivas};

    const PAGINA: u64 = crate::arch::TAMANHO_PAGINA;

    if crate::frames::falhas_pendentes() != 0 {
        return Err("um caso anterior deixou falhas encomendadas pendentes");
    }

    // O aquecimento: duas páginas, do tamanho do caso, que montam as tabelas
    // de onde elas caem e são largadas. Largadas, o endereço volta à faixa —
    // e a reserva seguinte do mesmo tamanho o recebe de volta, porque o
    // trecho que ele deixa é o primeiro em que ela cabe.
    let aquecimento = Memoria::nova(2 * PAGINA)?;
    let aquecido = aquecimento.inicio();
    drop(aquecimento);
    let inicio = onde_cairia(2 * PAGINA).ok_or("a faixa das superficies se esgotou")?;
    if inicio != aquecido {
        crate::log_error!(
            "teste",
            "o aquecimento caiu em {:#x}, e a proxima em {:#x}",
            aquecido,
            inicio
        );
        return Err("o endereco devolvido nao e o que a proxima reserva recebe");
    }
    let antes = vivas();

    // A primeira alocação — o frame da página zero — passa. A segunda — o
    // da página um — falha.
    //
    // Mascarado: a contagem "deixe uma passar" é de alocações do sistema
    // inteiro, e um handler que alocasse no meio levaria a que era da página
    // zero.
    let (resultado, pendentes) = crate::arch::sem_interrupcoes(|| {
        crate::frames::encomendar_falhas_depois(1, 1);
        let resultado = Memoria::nova(2 * PAGINA);
        let pendentes = crate::frames::falhas_pendentes();
        crate::frames::encomendar_falhas(0);
        (resultado, pendentes)
    });

    if resultado.is_ok() {
        return Err("a superficie foi criada apesar da falha encomendada");
    }
    if pendentes != 0 {
        return Err("a falha encomendada nao chegou ao alocador");
    }
    for pagina in [inicio, inicio + PAGINA] {
        if let Some(fisico) = crate::arch::traduzir(pagina) {
            crate::log_error!(
                "teste",
                "a pagina {:#x} da superficie que falhou ainda traduz para {:#x}",
                pagina,
                fisico
            );
            return Err("o desfazer deixou pagina mapeada");
        }
    }
    if vivas() != antes {
        return Err("uma superficie que falhou foi contada como viva");
    }
    // E o endereço voltou à faixa: sem isso, cada criação que falha gastaria
    // espaço virtual para sempre.
    if onde_cairia(2 * PAGINA) != Some(inicio) {
        return Err("a superficie que falhou nao devolveu o endereco");
    }
    Ok(())
}

/// A aritmética da faixa das superfícies, sobre uma faixa de mentira.
///
/// Reaproveitar, partir, fundir dos dois lados, descer o topo e recusar
/// quando não cabe. Uma faixa de mentira porque nenhum destes precisa de
/// página mapeada, e porque a de verdade tem superfícies vivas de outros
/// casos no meio — a conta não seria reproduzível.
fn grafico_a_faixa_reaproveita_e_funde() -> Resultado {
    use crate::grafico::memoria::{Faixa, MAX_TRECHOS};

    const P: u64 = crate::arch::TAMANHO_PAGINA;
    const BASE: u64 = 0x1000_0000;
    // A faixa inteira de mentira mora em `static`: são 4 KiB de trechos, e a
    // pilha de um fio não é lugar para eles.
    static FAIXA: spin::Mutex<Faixa> = spin::Mutex::new(Faixa::nova(0, 0));

    let mut f = FAIXA.lock();
    *f = Faixa::nova(BASE, BASE + 16 * P);

    let a = f.reservar(P).ok_or("a primeira reserva falhou")?;
    let b = f.reservar(2 * P).ok_or("a segunda reserva falhou")?;
    let c = f.reservar(P).ok_or("a terceira reserva falhou")?;
    if (a, b, c, f.topo()) != (BASE, BASE + P, BASE + 3 * P, BASE + 4 * P) {
        return Err("reservas numa faixa vazia nao sairam em sequencia");
    }

    // Reaproveitar: o buraco do meio volta para quem cabe nele.
    f.devolver(b, 2 * P);
    if f.trechos() != 1 || f.reservar(2 * P) != Some(b) || f.trechos() != 0 {
        return Err("o trecho devolvido nao foi reaproveitado inteiro");
    }

    // Partir: um pedido menor que o trecho leva o começo dele.
    f.devolver(b, 2 * P);
    if f.reservar(P) != Some(b) || f.reservar(P) != Some(b + P) || f.trechos() != 0 {
        return Err("um pedido menor nao partiu o trecho pelo comeco");
    }

    // Fundir dos dois lados: dois trechos separados, e o do meio os junta.
    f.devolver(a, P);
    f.devolver(b + P, P);
    if f.trechos() != 2 {
        return Err("dois trechos separados viraram um");
    }
    f.devolver(b, P);
    if f.trechos() != 1 || f.onde_cairia(3 * P) != Some(a) {
        return Err("o trecho do meio nao fundiu os dois lados");
    }

    // O topo desce, e leva junto o trecho livre que encosta nele.
    f.devolver(c, P);
    if f.topo() != BASE || f.trechos() != 0 {
        return Err("devolver o ultimo nao desceu o topo ate o trecho livre");
    }

    // Recusar o que não cabe, e caber de novo depois de devolver.
    let tudo = f.reservar(16 * P).ok_or("a faixa inteira nao coube")?;
    if f.reservar(P).is_some() {
        return Err("a faixa cheia aceitou mais uma reserva");
    }
    f.devolver(tudo, 16 * P);
    if f.reservar(u64::MAX).is_some() || f.reservar(0).is_some() {
        return Err("uma reserva impossivel foi aceita");
    }

    // Fundir só com o vizinho de cima.
    let x = f.reservar(P).ok_or("reserva depois de esvaziar falhou")?;
    let y = f.reservar(P).ok_or("reserva depois de esvaziar falhou")?;
    let _z = f.reservar(P).ok_or("reserva depois de esvaziar falhou")?;
    f.devolver(y, P);
    f.devolver(x, P);
    if f.trechos() != 1 || f.onde_cairia(2 * P) != Some(x) {
        return Err("um trecho nao fundiu com o vizinho de cima");
    }

    // A tabela cheia: um trecho a mais não cabe, e quem devolve fica sabendo.
    *f = Faixa::nova(BASE, BASE + (2 * MAX_TRECHOS as u64 + 4) * P);
    let mut enderecos = [0u64; 2 * MAX_TRECHOS + 3];
    for e in enderecos.iter_mut() {
        *e = f
            .reservar(P)
            .ok_or("a faixa grande se esgotou antes do previsto")?;
    }
    // Um sim, um não, para nenhum fundir com o vizinho, e longe do topo.
    for i in 0..MAX_TRECHOS {
        if !f.devolver(enderecos[2 * i], P) {
            return Err("a tabela recusou um trecho antes de encher");
        }
    }
    if f.trechos() != MAX_TRECHOS {
        return Err("a tabela nao guardou um trecho por devolucao");
    }
    if f.devolver(enderecos[2 * MAX_TRECHOS], P) {
        return Err("a tabela cheia aceitou mais um trecho sem dizer que perdeu");
    }
    // Mas um que funde não precisa de vaga.
    if !f.devolver(enderecos[1], P) || f.trechos() != MAX_TRECHOS - 1 {
        return Err("um trecho que funde foi recusado com a tabela cheia");
    }
    Ok(())
}

/// Criar e soltar superfícies não gasta a faixa.
///
/// Era o defeito que impedia o compositor: a reserva só subia, e no ARM
/// umas duzentas e cinquenta telas a esgotavam com a memória sobrando. Aqui
/// três superfícies nascem e morrem fora de ordem, e a faixa tem de voltar ao
/// que era — topo e trechos. Voltando, um laço infinito de criações não a
/// esgota.
fn grafico_soltar_superficies_devolve_a_faixa() -> Resultado {
    use crate::grafico::memoria::{Memoria, onde_cairia, perdidos, topo};

    const KIB_64: u64 = 64 * 1024;
    let topo_antes = topo();
    let perdidos_antes = perdidos();

    let a = Memoria::nova(KIB_64)?;
    let b = Memoria::nova(2 * KIB_64)?;
    let c = Memoria::nova(KIB_64)?;
    let em_b = b.inicio();
    drop(b);
    // O buraco de `b` é o primeiro lugar em que uma superfície do tamanho
    // dele cabe — a menos que já houvesse um trecho livre mais baixo.
    if onde_cairia(2 * KIB_64).is_none_or(|e| e > em_b) {
        return Err("o endereco da superficie solta nao voltou a faixa");
    }
    drop(a);
    drop(c);
    if topo() != topo_antes {
        crate::log_error!("teste", "topo foi de {:#x} para {:#x}", topo_antes, topo());
        return Err("soltar as superficies nao devolveu a faixa");
    }
    if perdidos() != perdidos_antes {
        return Err("a faixa perdeu endereco com tres superficies");
    }
    Ok(())
}

// ===========================================================================
// O compositor
// ===========================================================================

/// O pixel que o monitor mostra em `(x, y)`.
fn pixel_na_tela(x: u32, y: u32) -> Result<crate::tela::Cor, &'static str> {
    crate::tela::tela_fisica()
        .and_then(|t| t.ler_pixel(x, y))
        .ok_or("ponto fora da tela fisica")
}

/// O pixel da camada do console em `(x, y)`.
fn pixel_no_console(x: u32, y: u32) -> Result<crate::tela::Cor, &'static str> {
    crate::tela::tela()
        .and_then(|t| t.ler_pixel(x, y))
        .ok_or("ponto fora da camada do console")
}

/// Confere que a tela mostra o console, e não outra coisa, em cada ponto.
fn mostra_o_console(pontos: &[(u32, u32)]) -> Resultado {
    for &(x, y) in pontos {
        if pixel_na_tela(x, y)? != pixel_no_console(x, y)? {
            crate::log_error!("teste", "em ({}, {}) a tela nao mostra o console", x, y);
            return Err("a tela nao mostra o console onde nenhuma camada o cobre");
        }
    }
    Ok(())
}

/// Confere que a tela mostra `cor` em cada ponto.
fn mostra_a_cor(cor: crate::tela::Cor, pontos: &[(u32, u32)]) -> Resultado {
    for &(x, y) in pontos {
        let lido = pixel_na_tela(x, y)?;
        if lido != cor {
            crate::log_error!("teste", "em ({}, {}): {:?}, esperado {:?}", x, y, lido, cor);
            return Err("a tela nao mostra a camada que esta por cima");
        }
    }
    Ok(())
}

/// Uma camada pintada inteira de uma cor.
fn camada_de_cor(
    nome: &'static str,
    x: i32,
    y: i32,
    largura: u32,
    altura: u32,
    cor: crate::tela::Cor,
) -> Result<crate::grafico::compositor::Camada, &'static str> {
    let camada = crate::grafico::compositor::Camada::nova(nome, x, y, largura, altura)?;
    camada.pintar(|pixels, _, _| pixels.fill(cor.para_u32()))?;
    Ok(camada)
}

const VERDE: crate::tela::Cor = crate::tela::Cor::nova(0x20, 0xC0, 0x40);
const VERMELHO: crate::tela::Cor = crate::tela::Cor::nova(0xD0, 0x30, 0x30);

/// O console é a camada de baixo, e a tela física é outra memória.
///
/// Sem isto, todos os casos de console continuariam passando com o
/// compositor desligado: eles leem a tela onde o console desenha, e sem
/// compositor ela é a física.
fn compositor_o_console_e_a_camada_de_baixo() -> Resultado {
    let (Some(console), Some(fisica)) = (crate::tela::tela(), crate::tela::tela_fisica()) else {
        return sem_framebuffer();
    };
    if !crate::tela::console_desviado() {
        return Err("com tela, o console nao foi para uma camada do compositor");
    }
    if console.faixa().0 == fisica.faixa().0 {
        return Err("o console desviado ainda desenha na tela fisica");
    }
    // A camada adotou o que o boot desenhou: a faixa de acento do banner,
    // pintada antes de o compositor existir, está nela. Sem a adoção ela
    // começaria preta, e cada composição apagaria um pedaço do boot.
    if console.ler_pixel(0, 0) != Some(crate::tela::Cor::ACENTO) {
        return Err("a camada do console nao adotou o que estava na tela");
    }
    let mut primeira = None;
    crate::grafico::camadas(|c| {
        primeira.get_or_insert(c);
    });
    match primeira {
        Some(c)
            if c.id == crate::grafico::compositor::CAMADA_DO_CONSOLE
                && (c.largura, c.altura) == (fisica.largura, fisica.altura) =>
        {
            Ok(())
        }
        _ => Err("a camada de baixo nao e o console do tamanho da tela"),
    }
}

/// A camada de cima vence, e soltá-la revela o console.
fn compositor_a_camada_de_cima_vence() -> Resultado {
    if crate::tela::tela_fisica().is_none() {
        return sem_framebuffer();
    }
    sem_intrusos(|| {
        let dentro = [(100, 120), (147, 151), (120, 130)];
        let fora = [(99, 120), (148, 120), (100, 152)];
        let camada = camada_de_cor("teste", 100, 120, 48, 32, VERDE)?;
        mostra_a_cor(VERDE, &dentro)?;
        mostra_o_console(&fora)?;
        drop(camada);
        mostra_o_console(&dentro)
    })
}

/// Mover recompõe onde a camada estava e onde ela está.
fn compositor_mover_nao_deixa_rastro() -> Resultado {
    if crate::tela::tela_fisica().is_none() {
        return sem_framebuffer();
    }
    sem_intrusos(|| {
        let camada = camada_de_cor("teste", 200, 200, 40, 40, VERMELHO)?;
        camada.mover(260, 200)?;
        mostra_o_console(&[(205, 205), (239, 239)])?;
        mostra_a_cor(VERMELHO, &[(265, 205), (299, 239)])
    })
}

/// A ordem de empilhamento decide quem aparece onde duas se cruzam.
fn compositor_ordem_de_empilhamento() -> Resultado {
    if crate::tela::tela_fisica().is_none() {
        return sem_framebuffer();
    }
    sem_intrusos(|| {
        let baixo = camada_de_cor("baixo", 300, 300, 40, 40, VERDE)?;
        let _cima = camada_de_cor("cima", 320, 300, 40, 40, VERMELHO)?;
        mostra_a_cor(VERDE, &[(305, 305)])?;
        mostra_a_cor(VERMELHO, &[(325, 305), (345, 305)])?;
        baixo.trazer_para_frente()?;
        mostra_a_cor(VERDE, &[(305, 305), (325, 305), (339, 339)])?;
        mostra_a_cor(VERMELHO, &[(345, 305)])
    })
}

/// O que o console escreve debaixo de uma camada não aparece por cima dela,
/// e aparece quando ela sai.
///
/// É o defeito que a opção de desenhar o console direto na tela teria: cada
/// letra escrita sob uma janela apareceria por cima dela até a janela ser
/// redesenhada.
fn compositor_escrever_debaixo_nao_vaza() -> Resultado {
    let Some(g) = crate::tela::console::geometria() else {
        return sem_framebuffer();
    };
    sem_intrusos(|| {
        crate::serial_println!();
        let (x, y) = crate::tela::console::cursor();
        let camada = camada_de_cor(
            "cobre",
            0,
            y as i32,
            x + 8 * g.largura_da_celula,
            g.altura_da_celula,
            VERDE,
        )?;
        crate::serial_print!("W");
        let resultado = (|| {
            crate::tela::console::conferir_glifo('W', x, y)?;
            for dy in 0..g.altura_da_celula {
                for dx in 0..g.largura_da_celula {
                    if pixel_na_tela(x + dx, y + dy)? != VERDE {
                        return Err("a letra escrita sob a camada apareceu por cima dela");
                    }
                }
            }
            drop(camada);
            let fisica = crate::tela::tela_fisica().ok_or("a tela fisica sumiu")?;
            crate::tela::console::conferir_glifo_em(&fisica, 'W', x, y)
        })();
        crate::serial_println!();
        resultado
    })
}

/// Uma camada que passa da borda é composta só no que cai dentro, e uma
/// fora da tela não quebra nada.
fn compositor_camada_na_borda() -> Resultado {
    let Some(fisica) = crate::tela::tela_fisica() else {
        return sem_framebuffer();
    };
    sem_intrusos(|| {
        // No canto de baixo, que é do console: o de cima é da barra.
        //
        // Cada pixel do canto diz de onde veio na camada: verde é a coluna,
        // azul é a linha. Uma cor só esconderia um deslocamento errado — todo
        // pixel da camada seria igual a qualquer outro.
        let h = fisica.altura;
        let canto = crate::grafico::compositor::Camada::nova("canto", -20, h as i32 - 20, 40, 30)?;
        canto.pintar(|pixels, largura, _| {
            for (i, p) in pixels.iter_mut().enumerate() {
                let (x, y) = (i as u32 % largura, i as u32 / largura);
                *p = crate::tela::Cor::nova(0x80, x as u8, y as u8).para_u32();
            }
        })?;
        mostra_a_cor(crate::tela::Cor::nova(0x80, 20, 0), &[(0, h - 20)])?;
        mostra_a_cor(crate::tela::Cor::nova(0x80, 39, 19), &[(19, h - 1)])?;
        mostra_o_console(&[(20, h - 1), (0, h - 21)])?;
        let longe = camada_de_cor("longe", fisica.largura as i32 + 10, 0, 16, 16, VERDE)?;
        drop(longe);
        let direita = camada_de_cor(
            "direita",
            fisica.largura as i32 - 8,
            fisica.altura as i32 - 8,
            32,
            32,
            VERDE,
        )?;
        mostra_a_cor(VERDE, &[(fisica.largura - 1, fisica.altura - 1)])?;
        drop(direita);
        drop(canto);
        mostra_o_console(&[
            (0, h - 20),
            (19, h - 1),
            (fisica.largura - 1, fisica.altura - 1),
        ])
    })
}

/// O agente vê as camadas: `display.info` as lista, e a árvore mostra as de
/// cima como janelas, que deixam de existir quando saem.
fn agente_ve_as_camadas() -> Resultado {
    if crate::tela::tela_fisica().is_none() {
        return sem_framebuffer();
    }
    let camada = camada_de_cor("vista-pelo-agente", 40, 60, 24, 16, VERDE)?;
    let id = crate::ui::id_da_camada(camada.id());

    let info = chamar("display.info", "{}")?;
    let camadas = Json(info.as_bytes())
        .member("layers")
        .ok_or("display.info nao lista as camadas")?;
    if camadas
        .item(0)
        .and_then(|c| c.member("name"))
        .and_then(|v| v.as_str())
        != Some("console")
    {
        return Err("a primeira camada listada nao e o console");
    }
    let achada = (0..64)
        .filter_map(|i| camadas.item(i))
        .find(|c| c.member("name").and_then(|v| v.as_str()) == Some("vista-pelo-agente"))
        .ok_or("display.info nao lista a camada criada")?;
    if achada.member("x").and_then(|v| v.as_u64()) != Some(40)
        || achada.member("width").and_then(|v| v.as_u64()) != Some(24)
        || achada.member("blend").and_then(|v| v.as_str()) != Some("opaque")
        || achada.member("opacity").and_then(|v| v.as_u64()) != Some(255)
    {
        return Err("display.info descreve a camada com outra geometria");
    }

    let arvore = chamar("ui.tree", "{}")?;
    let marca = alloc::format!("\"id\":{},\"role\":\"window\"", id);
    if !arvore.contains(&marca) {
        crate::log_error!("teste", "arvore: {}", arvore);
        return Err("a arvore nao mostra a camada como janela");
    }
    if !crate::ui::existe(id) {
        return Err("a janela da arvore nao existe para ui.act");
    }
    drop(camada);
    if crate::ui::existe(id) {
        return Err("a janela continuou existindo depois de a camada sair");
    }
    if chamar("ui.tree", "{}")?.contains(&marca) {
        return Err("a arvore seguiu mostrando uma camada que saiu");
    }
    Ok(())
}

// ===========================================================================
// A barra superior
// ===========================================================================

/// A barra está no topo da tela, e o console começa abaixo dela.
fn barra_esta_no_topo() -> Resultado {
    let Some(fisica) = crate::tela::tela_fisica() else {
        return sem_framebuffer();
    };
    if !crate::barra::ativa() {
        return Err("com compositor, a barra superior nao subiu");
    }
    let altura = crate::tela::ALTURA_DA_BARRA;
    // O fundo dela, a linha de acento embaixo, e tinta onde está o nome.
    mostra_a_cor(crate::barra::FUNDO, &[(fisica.largura / 2, 1)])?;
    mostra_a_cor(
        crate::tela::Cor::ACENTO,
        &[(0, altura - 1), (fisica.largura - 1, altura - 2)],
    )?;
    let nome = crate::barra::moldura_do_nome().ok_or("a barra nao tem o nome")?;
    let mut tinta = false;
    for y in nome.y..nome.y + nome.altura {
        for x in nome.x..nome.x + nome.largura {
            tinta |= pixel_na_tela(x, y)? != crate::barra::FUNDO;
        }
    }
    if !tinta {
        return Err("o nome na barra nao foi desenhado");
    }
    // O console, abaixo dela.
    let g = crate::tela::console::geometria().ok_or("sem geometria")?;
    if g.margem_y < altura {
        return Err("o console comeca debaixo da barra");
    }
    Ok(())
}

/// O relógio da barra anda, e a árvore publica o que ele mostra.
fn barra_o_relogio_anda() -> Resultado {
    if !crate::barra::ativa() {
        return sem_framebuffer();
    }
    if crate::barra::texto_do_relogio(3723) != "ligado 1:02:03" {
        return Err("o relogio nao formata horas, minutos e segundos");
    }
    // Espera o segundo virar, e o relógio tem de ser redesenhado.
    let agora = crate::tempo::uptime_ms() / 1000;
    let limite = crate::tempo::uptime_ms() + 2_500;
    while crate::tempo::uptime_ms() / 1000 == agora {
        if crate::tempo::uptime_ms() > limite {
            return Err("o tempo nao andou");
        }
        core::hint::spin_loop();
    }
    if !crate::barra::atualizar_relogio() {
        return Err("o segundo virou e o relogio nao foi redesenhado");
    }
    let (moldura, texto) = crate::barra::relogio_na_tela().ok_or("a barra nao tem relogio")?;
    let esperado = crate::barra::texto_do_relogio(crate::tempo::uptime_ms() / 1000);
    let anterior = crate::barra::texto_do_relogio(crate::tempo::uptime_ms() / 1000 - 1);
    if texto != esperado && texto != anterior {
        crate::log_error!("teste", "relogio: {:?}, esperado {:?}", texto, esperado);
        return Err("o relogio na tela nao e o tempo ligado");
    }
    // E o que a árvore diz é o que está desenhado: o texto, pela mesma fonte,
    // pixel a pixel na moldura. Sem isto a árvore poderia publicar uma hora
    // que a tela não mostra — medido, um relógio que não redesenhava passava.
    let mut esperado_px =
        alloc::vec![crate::barra::FUNDO.para_u32(); (moldura.largura * moldura.altura) as usize];
    crate::tela::console::desenhar_texto_em(
        &mut esperado_px,
        moldura.largura,
        0,
        0,
        &texto,
        crate::barra::TEXTO,
        crate::barra::FUNDO,
    );
    for y in 0..moldura.altura {
        for x in 0..moldura.largura {
            let esperado =
                crate::tela::Cor::de_u32(esperado_px[(y * moldura.largura + x) as usize]);
            if pixel_na_tela(moldura.x + x, moldura.y + y)? != esperado {
                return Err("o relogio desenhado nao e o que a arvore publica");
            }
        }
    }
    let arvore = chamar("ui.tree", "{}")?;
    if !arvore.contains(&alloc::format!("\"value\":\"{}\"", texto)) {
        return Err("a arvore nao publica o relogio que esta desenhado");
    }
    Ok(())
}

/// O agente pressiona o botão: o console é limpo, e o log diz que foi ele.
fn barra_press_do_agente_limpa() -> Resultado {
    if !crate::barra::ativa() {
        return sem_framebuffer();
    }
    const MARCA: &str = "marca-antes-de-limpar";
    crate::serial_println!("{}", MARCA);
    let antes = crate::barra::pressionado();

    let arvore = chamar("ui.tree", "{}")?;
    let botao = alloc::format!(
        "\"id\":{},\"role\":\"button\",\"label\":\"Limpar\"",
        crate::ui::ID_DO_BOTAO_LIMPAR
    );
    if !arvore.contains(&botao) || !arvore.contains("\"actions\":[\"press\"]") {
        crate::log_error!("teste", "arvore: {}", arvore);
        return Err("a arvore nao mostra o botao Limpar aceitando press");
    }

    let r = chamar(
        "ui.act",
        &alloc::format!(
            r#"{{"id":{},"action":"press"}}"#,
            crate::ui::ID_DO_BOTAO_LIMPAR
        ),
    )?;
    if Json(r.as_bytes()).member("ok").and_then(|v| v.as_bool()) != Some(true) {
        crate::log_error!("teste", "resposta: {}", r);
        return Err("o press do agente foi recusado");
    }
    if crate::barra::pressionado() != antes + 1 {
        return Err("o press nao chegou ao botao");
    }
    let arvore = chamar("ui.tree", "{}")?;
    let (console, _) = console_da_arvore(&arvore)?;
    if texto_do_console(&console)?.contains(MARCA) {
        return Err("o console nao foi limpo");
    }
    if !log_tem(&alloc::format!(
        "agente: press no elemento {}",
        crate::ui::ID_DO_BOTAO_LIMPAR
    )) {
        return Err("o log nao registrou o press com a origem do agente");
    }
    Ok(())
}

/// F1 da pessoa passa pelo mesmo caminho do press do agente.
///
/// Do evento de tecla — o mesmo que os três drivers de teclado entregam —
/// até a ação, pela fila e pelo interpretador. Só o laço que espera a tecla
/// fica de fora: em modo de teste não há executor.
fn barra_f1_da_pessoa_pressiona() -> Resultado {
    if !crate::barra::ativa() {
        return sem_framebuffer();
    }
    crate::teclado::esvaziar();
    while crate::teclado::observar().is_some() {}
    let antes = crate::barra::pressionado();

    crate::teclado::evento(59, true);
    crate::teclado::evento(59, false);
    let tecla = crate::teclado::ler().ok_or("F1 nao chegou a fila do interpretador")?;
    if tecla != crate::teclado::F1 {
        return Err("F1 chegou como outra tecla");
    }
    if crate::teclado::observar().is_some() {
        return Err("F1 entrou no historico do que foi digitado");
    }
    crate::interpretador::tratar_tecla(tecla);

    if crate::barra::pressionado() != antes + 1 {
        return Err("F1 nao pressionou o botao");
    }
    if !log_tem(&alloc::format!(
        "pessoa: press no elemento {}",
        crate::ui::ID_DO_BOTAO_LIMPAR
    )) {
        return Err("o log nao registrou o press com a origem da pessoa");
    }
    // E o USB traduz F1 e F12 para os mesmos códigos.
    if crate::usb::hid::traduzir(0x3A) != Some(59) || crate::usb::hid::traduzir(0x45) != Some(88) {
        return Err("o teclado USB nao traduz as teclas de funcao");
    }
    Ok(())
}

/// Limpar não perde o que estava sendo digitado.
fn barra_limpar_guarda_a_linha() -> Resultado {
    if !crate::barra::ativa() {
        return sem_framebuffer();
    }
    crate::interpretador::ativar_para_teste();
    let resultado = (|| {
        crate::interpretador::definir("limpo")?;
        // Direto, e não pelo botão: o botão registra no log, e o registro
        // redesenha o prompt por conta própria — medido, um `limpar` que não
        // o redesenhasse passaria por aqui se o caso fosse pelo botão.
        crate::interpretador::limpar();
        let arvore = chamar("ui.tree", "{}")?;
        let (console, linha) = console_da_arvore(&arvore)?;
        let texto = texto_do_console(&console)?;
        if texto.rsplit('\n').next() != Some("duke> limpo") {
            crate::log_error!("teste", "console: {:?}", texto);
            return Err("depois de limpar, a linha digitada nao esta no prompt");
        }
        let mut buffer = [0u8; 64];
        let valor = linha
            .and_then(|l| l.member("value"))
            .and_then(|v| v.desescapar_em(&mut buffer));
        if valor != Some("limpo") {
            return Err("depois de limpar, a linha de comando perdeu o valor");
        }
        Ok(())
    })();
    crate::interpretador::desativar_para_teste();
    // Sem deixar prompt para trás: os casos da árvore que vêm depois contam
    // quantas vezes uma linha aparece no console.
    crate::interpretador::limpar();
    resultado
}

/// Uma camada transparente mistura cada pixel com o que está embaixo, pela
/// opacidade dele; e a opacidade da camada inteira multiplica a dos pixels.
///
/// As contas são as da mistura com arredondamento: alfa 0 é o de baixo, 255
/// é o de cima, e o meio é a fórmula — escrita aqui de novo, para o caso não
/// conferir o compositor contra ele mesmo.
fn compositor_transparencia() -> Resultado {
    use crate::grafico::compositor::{Camada, Mistura};
    use crate::tela::Cor;

    if crate::tela::tela_fisica().is_none() {
        return sem_framebuffer();
    }
    let esperado = |fundo: Cor, frente: Cor, alfa: u32| {
        let c = |f: u8, b: u8| ((f as u32 * alfa + b as u32 * (255 - alfa) + 127) / 255) as u8;
        Cor::nova(
            c(frente.r, fundo.r),
            c(frente.g, fundo.g),
            c(frente.b, fundo.b),
        )
    };
    let vermelho = Cor::nova(0xFF, 0, 0);
    let verde = Cor::nova(0, 0xFF, 0);

    sem_intrusos(|| {
        // Embaixo, uma camada opaca vermelha; em cima, uma transparente com
        // três faixas de alfa: 0, 128 e 255.
        let fundo = camada_de_cor("fundo", 400, 400, 60, 20, vermelho)?;
        let cima = Camada::nova("cima", 400, 400, 60, 20)?;
        cima.definir_mistura(Mistura::Alfa)?;
        cima.pintar(|pixels, largura, _| {
            for (i, p) in pixels.iter_mut().enumerate() {
                let alfa: u32 = match i as u32 % largura / 20 {
                    0 => 0,
                    1 => 128,
                    _ => 255,
                };
                *p = alfa << 24 | verde.para_u32();
            }
        })?;
        mostra_a_cor(vermelho, &[(405, 405)])?;
        mostra_a_cor(esperado(vermelho, verde, 128), &[(425, 405)])?;
        mostra_a_cor(verde, &[(445, 405)])?;

        // A opacidade da camada multiplica a do pixel: 255 vira 128.
        cima.definir_opacidade(128)?;
        mostra_a_cor(esperado(vermelho, verde, 128), &[(445, 405)])?;
        mostra_a_cor(esperado(vermelho, verde, 64), &[(425, 405)])?;
        // E zero some com a camada.
        cima.definir_opacidade(0)?;
        mostra_a_cor(vermelho, &[(425, 405), (445, 405)])?;

        // Uma camada opaca ignora o byte alto: o que já desenhava com
        // `0x00RRGGBB`, ou com lixo ali, continua opaco.
        cima.definir_opacidade(255)?;
        cima.definir_mistura(Mistura::Opaca)?;
        mostra_a_cor(verde, &[(405, 405), (425, 405)])?;

        // Opaca com opacidade de camada: meio a meio, também.
        cima.definir_opacidade(128)?;
        mostra_a_cor(esperado(vermelho, verde, 128), &[(405, 405)])?;

        drop(cima);
        drop(fundo);
        mostra_o_console(&[(405, 405), (445, 405)])
    })
}

// ===========================================================================
// O ponteiro
// ===========================================================================
//
// No fim da lista de propósito: o cursor, depois que aparece, fica fixo no
// topo da tela, e um caso de pixels que viesse depois poderia esbarrar nele.

/// Um tablet e um mouse levam o ponteiro ao mesmo lugar da tela, pela
/// escala de cada um, e o ponteiro não sai dela.
fn ponteiro_absoluto_e_relativo() -> Resultado {
    let Some(tela) = crate::tela::tela_fisica() else {
        return sem_framebuffer();
    };
    sem_intrusos(|| {
        // O meio da escala de um tablet é o meio da tela.
        crate::ponteiro::absoluto(16384, 16384, 32767, 32767);
        let (x, y) = crate::ponteiro::posicao();
        if x.abs_diff(tela.largura / 2) > 1 || y.abs_diff(tela.altura / 2) > 1 {
            crate::log_error!("teste", "meio do tablet em ({}, {})", x, y);
            return Err("a escala do tablet nao leva o meio ao meio da tela");
        }
        // Um mouse anda a partir de onde está.
        crate::ponteiro::relativo(-10, 5);
        if crate::ponteiro::posicao() != (x - 10, y + 5) {
            return Err("o deslocamento do mouse nao andou o que disse");
        }
        // E a borda prende.
        crate::ponteiro::relativo(-100_000, 100_000);
        if crate::ponteiro::posicao() != (0, tela.altura - 1) {
            return Err("o ponteiro saiu da tela");
        }
        crate::ponteiro::absoluto(40_000, 40_000, 32767, 32767);
        if crate::ponteiro::posicao() != (tela.largura - 1, tela.altura - 1) {
            return Err("um tablet alem da escala tirou o ponteiro da tela");
        }
        Ok(())
    })
}

/// O cursor aparece no primeiro movimento e segue o ponteiro: a seta onde
/// ele está, transparente em volta, e nada onde ele estava.
fn ponteiro_o_cursor_segue() -> Resultado {
    if crate::tela::tela_fisica().is_none() {
        return sem_framebuffer();
    }
    sem_intrusos(|| {
        crate::ponteiro::absoluto(0, 0, 32767, 32767);
        crate::ponteiro::relativo(300, 300);
        crate::ponteiro::sincronizar();
        let mut cursor = None;
        crate::grafico::camadas(|c| {
            if c.nome == "cursor" {
                cursor = Some(c);
            }
        });
        let cursor = cursor.ok_or("o cursor nao apareceu nas camadas")?;
        if cursor.mistura != crate::grafico::compositor::Mistura::Alfa {
            return Err("o cursor nao e uma camada transparente");
        }
        // A ponta da seta é contorno; à direita dela, na primeira linha, é
        // transparente — o console aparece.
        mostra_a_cor(
            crate::tela::Cor::de_u32(crate::ponteiro::CONTORNO),
            &[(300, 300)],
        )?;
        mostra_o_console(&[(310, 300)])?;
        // E anda: onde estava volta a ser o console.
        crate::ponteiro::relativo(40, 0);
        crate::ponteiro::sincronizar();
        mostra_a_cor(
            crate::tela::Cor::de_u32(crate::ponteiro::CONTORNO),
            &[(340, 300)],
        )?;
        mostra_o_console(&[(300, 300)])?;
        // E fica por cima de uma camada criada depois dele: o cursor é fixo
        // no topo, e uma janela nova entra abaixo.
        let janela = camada_de_cor("janela", 320, 290, 60, 40, VERDE)?;
        mostra_a_cor(
            crate::tela::Cor::de_u32(crate::ponteiro::CONTORNO),
            &[(340, 300)],
        )?;
        mostra_a_cor(VERDE, &[(360, 320)])?;
        janela.trazer_para_frente()?;
        mostra_a_cor(
            crate::tela::Cor::de_u32(crate::ponteiro::CONTORNO),
            &[(340, 300)],
        )
    })
}

/// Um clique no botão da barra o pressiona pelo caminho da pessoa — o
/// mesmo da F1 —, e um clique fora dele não aciona nada.
fn ponteiro_clique_no_botao() -> Resultado {
    let Some(tela) = crate::tela::tela_fisica() else {
        return sem_framebuffer();
    };
    let botao = crate::barra::moldura_do_botao().ok_or("a barra nao tem o botao")?;
    crate::teclado::esvaziar();
    let antes = crate::barra::pressionado();

    // Pelo tablet, até o meio do botão.
    let escala = |v: u32, lado: u32| v * 32767 / (lado - 1);
    let (cx, cy) = (botao.x + botao.largura / 2, botao.y + botao.altura / 2);
    crate::ponteiro::absoluto(
        escala(cx, tela.largura),
        escala(cy, tela.altura),
        32767,
        32767,
    );
    crate::ponteiro::sincronizar();
    // O clique é o apertar: chega à fila antes de o botão ser solto.
    crate::ponteiro::botao(true);
    let tecla = crate::teclado::ler().ok_or("o clique nao chegou a fila ao apertar o botao")?;
    crate::ponteiro::botao(false);
    if crate::teclado::ler().is_some() {
        return Err("soltar o botao contou outro clique");
    }
    if tecla != crate::teclado::CLIQUE {
        return Err("o clique chegou como outra tecla");
    }
    crate::interpretador::tratar_tecla(tecla);
    if crate::barra::pressionado() != antes + 1 {
        return Err("o clique no botao nao o pressionou");
    }
    if !log_tem(&alloc::format!(
        "pessoa: press no elemento {}",
        crate::ui::ID_DO_BOTAO_LIMPAR
    )) {
        return Err("o log nao registrou o clique com a origem da pessoa");
    }

    // Fora do botão: nada.
    crate::ponteiro::absoluto(
        escala(cx, tela.largura),
        escala(tela.altura / 2, tela.altura),
        32767,
        32767,
    );
    crate::ponteiro::botao(true);
    crate::ponteiro::botao(false);
    let tecla = crate::teclado::ler().ok_or("o segundo clique nao chegou")?;
    crate::interpretador::tratar_tecla(tecla);
    if crate::barra::pressionado() != antes + 1 {
        return Err("um clique fora do botao pressionou o botao");
    }
    // E segurar não é clicar de novo.
    crate::ponteiro::botao(true);
    crate::ponteiro::botao(true);
    crate::ponteiro::botao(false);
    let mut cliques = 0;
    while crate::teclado::ler().is_some() {
        cliques += 1;
    }
    if cliques != 1 {
        return Err("segurar o botao contou mais de um clique");
    }
    Ok(())
}

/// Os eventos do virtio chegam ao ponteiro: eixos absolutos na escala que o
/// dispositivo declarou, o botão esquerdo, e o sincronismo que move o
/// cursor. Montados à mão, com a função que o driver usa.
fn ponteiro_eventos_do_virtio() -> Resultado {
    use crate::virtio::teclado::{evento, traduzir};
    let Some(tela) = crate::tela::tela_fisica() else {
        return sem_framebuffer();
    };
    const EV_SYN: u16 = 0;
    const EV_KEY: u16 = 1;
    const EV_ABS: u16 = 3;
    const BTN_LEFT: u16 = 0x110;
    let maximo = (1000, 1000);
    let mut posicao = (0, 0);
    let (cliques, movimentos) = crate::ponteiro::contadores();
    crate::teclado::esvaziar();

    traduzir(&mut posicao, maximo, evento(EV_ABS, 0, 500));
    traduzir(&mut posicao, maximo, evento(EV_ABS, 1, 1000));
    traduzir(&mut posicao, maximo, evento(EV_SYN, 0, 0));
    if crate::ponteiro::posicao() != ((tela.largura - 1) / 2, tela.altura - 1) {
        return Err("os eixos do tablet nao levaram o ponteiro ao lugar");
    }
    if crate::ponteiro::contadores().1 != movimentos + 1 {
        return Err("o sincronismo nao moveu o cursor");
    }
    traduzir(&mut posicao, maximo, evento(EV_KEY, BTN_LEFT, 1));
    traduzir(&mut posicao, maximo, evento(EV_KEY, BTN_LEFT, 0));
    if crate::ponteiro::contadores().0 != cliques + 1 {
        return Err("o botao do tablet nao clicou");
    }
    // O clique entra na fila, e sai dela — sem acionar nada no meio da tela.
    if crate::teclado::ler() != Some(crate::teclado::CLIQUE) {
        return Err("o clique do tablet nao chegou a fila");
    }
    Ok(())
}

/// O pacote do mouse PS/2: três bytes, o primeiro com o bit 3 ligado; um
/// byte fora de fase é descartado até achar o começo de novo.
#[cfg(target_arch = "x86_64")]
fn ponteiro_pacote_ps2() -> Resultado {
    use crate::arch::atual::mouse::{byte, esquecer};
    crate::teclado::esvaziar();
    // Nada pendurado: a IRQ 12 que o PIC guarda da inicialização não pode
    // ter virado byte — ver `mouse::atender`.
    let pendentes = esquecer();
    if pendentes != 0 {
        crate::log_error!(
            "teste",
            "{} byte(s) de um pacote PS/2 pela metade",
            pendentes
        );
        return Err("sobrou um pedaco de pacote PS/2 de antes do primeiro movimento");
    }
    crate::ponteiro::relativo(-100_000, -100_000);
    let (cliques, _) = crate::ponteiro::contadores();
    // Um byte sem o bit 3: não é começo de pacote, e não conta.
    byte(0x00);
    // Botão esquerdo, x +10, y -5 (para cima no PS/2 é para baixo na tela):
    // estado 0x08 | 0x01 | sinal de y (0x20), dx 10, dy 0xFB (-5).
    byte(0x29);
    byte(10);
    byte(0xFB);
    if crate::ponteiro::posicao() != (10, 5) {
        crate::log_error!(
            "teste",
            "posicao depois do pacote: {:?}",
            crate::ponteiro::posicao()
        );
        return Err("o pacote PS/2 nao moveu o ponteiro o que dizia");
    }
    if crate::ponteiro::contadores().0 != cliques + 1 {
        return Err("o botao do pacote PS/2 nao clicou");
    }
    // Soltar, sem mover.
    byte(0x08);
    byte(0);
    byte(0);
    crate::teclado::esvaziar();
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn ponteiro_pacote_ps2() -> Resultado {
    // O ARM não tem 8042; o ponteiro dele chega pelo virtio, conferido no
    // caso anterior.
    Ok(())
}

/// O relatório de um mouse USB no protocolo de boot: botões, x e y com
/// sinal — y positivo para baixo, ao contrário do PS/2 —, e o que vem depois
/// ignorado. Um relatório curto demais não é lido.
fn ponteiro_relatorio_usb() -> Resultado {
    use crate::usb::hid::{processar_mouse, relatorios_do_mouse};
    if crate::tela::tela_fisica().is_none() {
        return sem_framebuffer();
    }
    crate::teclado::esvaziar();
    crate::ponteiro::relativo(-100_000, -100_000);
    let (cliques, movimentos) = crate::ponteiro::contadores();
    let antes = relatorios_do_mouse();

    // Botão esquerdo, x +12, y +7, e uma roda de -1 que não é da conta do
    // ponteiro.
    processar_mouse(&[0x01, 12, 7, 0xFF]);
    if crate::ponteiro::posicao() != (12, 7) {
        crate::log_error!(
            "teste",
            "posicao depois do relatorio: {:?}",
            crate::ponteiro::posicao()
        );
        return Err("o relatorio do mouse USB nao moveu o ponteiro o que dizia");
    }
    if crate::ponteiro::contadores() != (cliques + 1, movimentos + 1) {
        return Err("o relatorio do mouse USB nao clicou nem moveu o cursor");
    }
    if crate::teclado::ler() != Some(crate::teclado::CLIQUE) {
        return Err("o clique do mouse USB nao chegou a fila");
    }
    // Soltar e voltar: -2 e -3 em complemento de dois.
    processar_mouse(&[0x00, 0xFE, 0xFD]);
    if crate::ponteiro::posicao() != (10, 4) {
        return Err("o mouse USB nao leu o deslocamento negativo");
    }
    // Curto demais: nem move, nem conta.
    processar_mouse(&[0x01, 50]);
    if crate::ponteiro::posicao() != (10, 4) || crate::teclado::ler().is_some() {
        return Err("um relatorio de dois bytes foi lido como mouse");
    }
    if relatorios_do_mouse() != antes + 2 {
        return Err("o mouse USB nao contou os relatorios que leu");
    }
    Ok(())
}

/// O agente vê a pilha gráfica pelo registro, com o adaptador e a tela certos.
fn agente_display_info_descreve_a_pilha() -> Resultado {
    let cmd = registry::encontrar("display.info").ok_or("display.info ausente")?;

    let mut buffer = Buffer::novo();
    {
        let mut w = JsonWriter::new(&mut buffer);
        escrita((cmd.handler)(Json(b"{}"), &mut w))?;
    }
    let resposta = Json(buffer.bytes());

    let Some(tela) = crate::tela::tela() else {
        return match resposta.member("present").and_then(|v| v.as_bool()) {
            Some(false) => Ok(()),
            _ => Err("sem tela, display.info nao disse que nao ha pilha"),
        };
    };

    // O adaptador é o de quem mostra a tela: o linear num framebuffer que o
    // dispositivo varre sozinho, o virtio-gpu quando a tela mora sobre ele.
    let sobre_virtio = crate::virtio::gpu::tem_a_tela();
    let esperado = if sobre_virtio { "virtio-gpu" } else { "linear" };
    if resposta.member("adapter").and_then(|v| v.as_str()) != Some(esperado) {
        crate::log_error!("teste", "resposta: {}", buffer.como_str());
        return Err("display.info nao nomeou o adaptador de quem mostra a tela");
    }
    // E os números do dispositivo existem só onde há o que mandar a ele.
    let descargas = resposta
        .member("device")
        .and_then(|d| d.member("flushes"))
        .and_then(|v| v.as_u64());
    match (sobre_virtio, descargas) {
        (true, Some(n)) if n > 0 => {}
        (false, None) => {}
        _ => {
            crate::log_error!("teste", "resposta: {}", buffer.como_str());
            return Err("display.info nao descreveu o dispositivo como ele e");
        }
    }
    let Some(tela0) = resposta.member("displays").and_then(|d| d.item(0)) else {
        return Err("display.info nao listou a tela");
    };
    let largura = tela0.member("width").and_then(|v| v.as_u64());
    let altura = tela0.member("height").and_then(|v| v.as_u64());
    if largura != Some(tela.largura as u64) || altura != Some(tela.altura as u64) {
        crate::log_error!("teste", "resposta: {}", buffer.como_str());
        return Err("display.info descreveu outra geometria");
    }

    // E a pergunta que um agente faz depois de mandar desenhar — "o que
    // mudou?" — tem de responder o último retângulo que chegou à tela. Os
    // contadores são os da máquina, e é a suíte registrando um retângulo
    // conhecido: é o caminho inteiro, do registro até o JSON.
    let atualizacoes_antes = resposta
        .member("updates")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    crate::grafico::registrar_atualizacao(crate::grafico::Dano::novo(7, 11, 13, 17));

    let mut buffer = Buffer::novo();
    {
        let mut w = JsonWriter::new(&mut buffer);
        escrita((cmd.handler)(Json(b"{}"), &mut w))?;
    }
    let resposta = Json(buffer.bytes());
    if resposta.member("updates").and_then(|v| v.as_u64()) != Some(atualizacoes_antes + 1) {
        return Err("display.info nao contou a atualizacao");
    }
    let Some(dano) = resposta.member("last_damage") else {
        return Err("display.info nao trouxe o ultimo dano");
    };
    let campo = |nome| dano.member(nome).and_then(|v| v.as_u64());
    if (campo("x"), campo("y"), campo("width"), campo("height"))
        != (Some(7), Some(11), Some(13), Some(17))
    {
        crate::log_error!("teste", "resposta: {}", buffer.como_str());
        return Err("display.info devolveu outro retangulo como ultimo dano");
    }
    Ok(())
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
/// Uma propriedade menor que uma célula é ignorada, não lida pela metade.
///
/// `#address-cells` diz quantas palavras de 32 bits cada endereço ocupa, e é
/// o número que decide como o resto do blob é interpretado. `be32` lê quatro
/// bytes; numa propriedade de dois, os outros dois vêm do token seguinte —
/// uma largura inventada a partir de bytes que não são dela.
///
/// O caso declara `#address-cells` com dois bytes e deixa, logo depois deles,
/// bytes que fariam a leitura de quatro devolver `1`. Com a conferência, a
/// declaração é descartada e vale o padrão da especificação, que é `2`; sem
/// ela, o leitor passa a interpretar o `reg` do nó de memória com a largura
/// errada e devolve uma região que o blob não declara.
///
/// Medido: sem a conferência, a suíte inteira passava.
fn fdt_ignora_propriedade_menor_que_uma_celula() -> Resultado {
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::log_info!("teste", "o leitor de device tree so existe no aarch64");
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::fdt;

        // Deslocamentos do blob que `montar_dtb` produz.
        const TAMANHO_DA_1A_PROP: usize = 76;
        const VALOR_DA_1A_PROP: usize = 84;

        let mut blob = [0u8; 256];
        montar_dtb(&mut blob, 2, 1);

        // A propriedade passa a ter dois bytes...
        blob[TAMANHO_DA_1A_PROP..TAMANHO_DA_1A_PROP + 4].copy_from_slice(&2u32.to_be_bytes());
        // ...e os quatro bytes naquele ponto passam a valer 1, que é uma
        // largura plausível e diferente do padrão. Ler além do tamanho
        // declarado deixa de ser inofensivo e vira uma largura errada.
        blob[VALOR_DA_1A_PROP..VALOR_DA_1A_PROP + 4].copy_from_slice(&1u32.to_be_bytes());

        let mut achadas = 0;
        let mut regiao = (0u64, 0u64);
        // SAFETY: o blob está neste quadro de pilha e traz a assinatura; o que
        // se afirma é como o leitor trata uma propriedade curta demais.
        let r = unsafe {
            fdt::percorrer_memoria(blob.as_ptr(), |inicio, tamanho| {
                achadas += 1;
                regiao = (inicio, tamanho);
            })
        };
        if r.is_err() {
            return Err("o leitor recusou um blob cuja unica anomalia e uma propriedade curta");
        }
        if achadas != 1 || regiao != (0x4000_0000, 0x0800_0000) {
            crate::log_error!(
                "teste",
                "{} regiao(oes), a primeira {:#x}+{:#x}",
                achadas,
                regiao.0,
                regiao.1
            );
            return Err("uma propriedade curta demais mudou a largura de celula");
        }
        Ok(())
    }
}

/// Ninguém gira mascarado esperando uma interrupção.
///
/// # A frase que este caso substitui
///
/// `esperar_interrupcao` tem dois ramos: dorme se as interrupções estiverem
/// ligadas, gira se não estiverem. O giro é o ramo ruim — ele só termina se
/// **outro** fio religar as interrupções, e para quem chamou sem ter para
/// onde voltar ele não termina nunca.
///
/// O que autorizava os dois chamadores de hoje — o laço do agente e o
/// descanso do coletor — a usarem essa função em vez de `dormir_parado` era
/// uma medida escrita num comentário: o ramo mascarado foi tomado zero vezes
/// na suíte inteira. Uma medida escrita vale até o próximo chamador; esta
/// vale a cada rodada.
///
/// # O que ele não cobre
///
/// O que rodar **depois** dele. O caso mora perto do fim da tabela por isso,
/// e mesmo assim a garantia é "até aqui" — o preço de perguntar de dentro da
/// própria suíte.
#[cfg(target_arch = "x86_64")]
fn x86_ninguem_gira_mascarado_esperando_interrupcao() -> Resultado {
    let giros = crate::arch::atual::giros_mascarados();
    if giros != 0 {
        crate::log_error!(
            "teste",
            "esperar_interrupcao girou mascarada {} vez(es)",
            giros
        );
        return Err("alguem esperou interrupcao com as interrupcoes mascaradas");
    }
    Ok(())
}

/// O custo de desenhar, medido a cada rodada em vez de escrito num comentário.
///
/// # O que estava escrito antes, e por que era pior que nada
///
/// O doc de [`crate::tela::Tela::retangulo`] dizia "450 ms antes, 250 ms
/// depois", e o de `tela::console` pendurava uma decisão de projeto nisso: o
/// console não rola porque rolar custaria meio segundo por linha.
///
/// Nenhum dos dois dizia **em que perfil**, e essa omissão é o defeito
/// inteiro. Era debug. Medido hoje, o mesmo preenchimento leva cerca de 7 ms
/// em release e 640 ms em debug — o comentário errava por oitenta e cinco
/// vezes para menos num caso e por duas vezes e meia para mais no outro, ao
/// mesmo tempo. Uma medida sem a configuração dela não é uma medida.
///
/// # Por que um teto, e não um número
///
/// Porque o número depende da máquina que roda a suíte, e uma asserção sobre
/// ele seria falsa na primeira máquina diferente. O teto vale por outro
/// motivo: o que ele recusa não é variação, é ordem de grandeza — alguém
/// voltando a desenhar pixel a pixel por uma chamada de função, ou mapeando o
/// framebuffer como memória de dispositivo em vez de RAM. As duas coisas já
/// aconteceram neste arquivo, e as duas passariam despercebidas sem isto.
fn tela_desenhar_nao_regrediu_em_ordem_de_grandeza() -> Resultado {
    let Some(tela) = crate::tela::tela() else {
        // Sem tela não há o que medir, e isso não é falha: a máquina pode
        // legitimamente não ter uma.
        return Ok(());
    };

    const VOLTAS: u64 = 20;
    let preto = crate::tela::Cor { r: 0, g: 0, b: 0 };
    let branco = crate::tela::Cor {
        r: 255,
        g: 255,
        b: 255,
    };

    // Uma passada fora da conta: a primeira paga o que as seguintes não pagam.
    tela.preencher(branco);

    let antes = crate::tempo::uptime_ms();
    for volta in 0..VOLTAS {
        tela.preencher(if volta % 2 == 0 { branco } else { preto });
    }
    let total = crate::tempo::uptime_ms() - antes;
    let por_tela = total * 1000 / VOLTAS;

    crate::log_info!(
        "tela",
        "{}x{} com {} bytes/pixel: {} us por preenchimento",
        tela.largura,
        tela.altura,
        tela.bytes_por_pixel,
        por_tela
    );

    // O teto só vale em release, e o motivo está medido.
    //
    // A regressão que este caso existe para recusar é voltar a desenhar por
    // chamada de função em vez de por laço. Semeada, ela move os números
    // assim:
    //
    // | | limpo | com a regressão | razão |
    // |---|---|---|---|
    // | release | 6–8 ms | 59 ms | ~9x |
    // | debug | 637 ms | 755 ms | 1,19x |
    //
    // Em debug o custo por pixel já é dominado pela falta de inline e pelas
    // conferências de limite, e a chamada a mais quase não aparece. Um teto
    // que pegasse 755 ms teria de ficar abaixo de 700, que é dentro do ruído
    // de uma rodada limpa — reprovaria máquina lenta e não reprovaria a
    // regressão. Seria decoração, e este caso já teve uma: o primeiro teto
    // que escrevi aqui era de 100 ms em release, e a mutação passou por baixo
    // dele.
    //
    // Então em debug o número é registrado e não julgado. Uma asserção que
    // não pode falhar pelo motivo que a justifica não é uma asserção.
    if !cfg!(debug_assertions) {
        // Quatro vezes o pior medido em release nas duas arquiteturas: absorve
        // uma máquina bem mais lenta que esta e ainda reprova a chamada por
        // pixel, que chega a 59 ms.
        const TETO_US: u64 = 30_000;
        if por_tela > TETO_US {
            crate::log_error!(
                "teste",
                "preenchimento a {} us, teto {} us",
                por_tela,
                TETO_US
            );
            return Err("desenhar na tela ficou uma ordem de grandeza mais lento");
        }
    }

    // E o desenho escreve de verdade — senão o laço acima mediu nada.
    //
    // # As duas versões erradas desta conferência
    //
    // A primeira lia o centro da tela depois do laço, que terminava em preto,
    // com o aquecimento também em preto: um `retangulo` que não desenhasse
    // nada deixava a tela preta e passava. A segunda trocou o aquecimento por
    // branco — e ganhou uma corrida com o console. Entre o último
    // preenchimento e a leitura havia uma linha de log, o console desenha
    // log na mesma tela, e com mais casos logando antes deste o cursor dele
    // caiu no centro da tela de 720 linhas do ARM. Medido: o pixel lido era
    // `(16, 24, 40)`, o fundo do console.
    //
    // Aqui a escrita e a leitura acontecem com as interrupções mascaradas, e
    // num único núcleo isso quer dizer que nada mais roda entre as duas. Num
    // retângulo pequeno, e não na tela inteira: em debug um preenchimento
    // leva 600 ms, e mascarar por isso pararia o relógio do resto da suíte.
    // Duas cores, e as duas lidas de volta: uma escrita que não acontece
    // deixa a primeira leitura com a cor de antes.
    let (claro, escuro) = crate::arch::sem_interrupcoes(|| {
        let (x, y) = (tela.largura / 2, tela.altura / 2);
        tela.retangulo(x - 1, y - 1, 3, 3, branco);
        let claro = tela.ler_pixel(x, y);
        tela.retangulo(x - 1, y - 1, 3, 3, preto);
        (claro, tela.ler_pixel(x, y))
    });
    if claro != Some(branco) || escuro != Some(preto) {
        crate::log_error!("teste", "lido {:?} e {:?}", claro, escuro);
        return Err("desenhar na tela nao deixou a cor que pintou");
    }
    Ok(())
}

/// Um cabeçalho de GPT absurdo vira recusa, e não pânico nem laço eterno.
///
/// # Por que este caso existe
///
/// Porque a regra estava escrita de um lado só. Dos três campos do cabeçalho
/// que a varredura usa para calcular endereços, um era conferido — o tamanho
/// da entrada, com comentário e tudo — e os outros dois não, apesar de serem
/// lidos na mesma função e usados na mesma conta.
///
/// O cabeçalho do módulo promete que uma tabela corrompida dá no mesmo que
/// uma tabela ausente: um kernel que não monta nada. Com `entradas_em` perto
/// do fim do `u64`, o que ela dava era outra coisa — a soma que escolhe o
/// setor voltava ao começo, em silêncio antes de `overflow-checks` entrar no
/// perfil de release e em pânico do kernel depois dele.
///
/// O disco desta máquina nunca vai produzir nenhum destes números, e é por
/// isso que só um caso os produz.
fn gpt_cabecalho_absurdo_e_recusado() -> Resultado {
    use crate::particoes::planejar;
    const SETOR: usize = crate::virtio::blk::TAMANHO_DO_SETOR;

    // O que o disco desta máquina traz, e que tem de continuar passando: 128
    // entradas de 128 bytes, o vetor começando no setor 2.
    if planejar(2, 128, 128).is_err() {
        return Err("a gpt normal do disco foi recusada");
    }

    // Tamanho da entrada: a conferência que já existia.
    if planejar(2, 128, 0).is_ok() {
        return Err("uma entrada de zero byte foi aceita");
    }
    if planejar(2, 128, SETOR + 1).is_ok() {
        return Err("uma entrada maior que o setor foi aceita");
    }

    // Quantidade: quatro bilhões de entradas são quatro bilhões de leituras
    // de setor, ou seja, um kernel que não termina de subir.
    if planejar(2, u32::MAX, 128).is_ok() {
        return Err("uma gpt de quatro bilhoes de entradas foi aceita");
    }

    // Começo do vetor: a soma que escolhe o setor daria a volta.
    if planejar(u64::MAX, 128, 128).is_ok() {
        return Err("um vetor de entradas no fim do u64 foi aceito");
    }

    // E a fronteira exata, que é onde uma conferência frouxa se revela. Com
    // 128 entradas de 128 bytes cabem quatro por setor, então a última mora
    // trinta e um setores adiante do começo.
    let maior = u64::MAX - 31;
    if planejar(maior, 128, 128).is_err() {
        return Err("o maior comeco que ainda cabe foi recusado");
    }
    if planejar(maior + 1, 128, 128).is_ok() {
        return Err("um comeco um setor acima do que cabe foi aceito");
    }

    Ok(())
}

/// Um mapeamento de MMIO que falha no meio não deixa meia região traduzindo.
///
/// # O caminho que nenhum caso alcançava
///
/// `mmio::mapear` mapeia página por página, e se uma falhar ele desfaz as
/// anteriores. Esse desfazer existe desde que o módulo existe e **nunca
/// rodou**: para chegar até ele, o alocador de frames tem de dar certo numa
/// página e falhar na seguinte, o que não acontece numa máquina com 128 MiB
/// livres.
///
/// Era um caminho de limpeza lido e considerado correto — que é o mesmo grau
/// de garantia que um comentário. `frames::encomendar_falhas` existe para
/// isto: faz a próxima alocação falhar, no ponto que o caso escolher.
///
/// # O que se afirma
///
/// Que os frames voltam. Um desfazer que esquecesse uma página deixaria o
/// contador de livres mais baixo do que começou, e a faixa seguinte a pedir
/// aqueles endereços falharia por um motivo que não é o dela.
fn mmio_mapeamento_que_falha_no_meio_desfaz_tudo() -> Resultado {
    const PAGINA: u64 = 4096;
    /// Páginas de 4 KiB cobertas por uma tabela de último nível.
    const POR_TABELA: u64 = 512;
    const REGIAO: u64 = PAGINA * POR_TABELA;

    if crate::frames::falhas_pendentes() != 0 {
        return Err("um caso anterior deixou falhas encomendadas pendentes");
    }

    // Cada mapeamento leva uma faixa física própria: `mapear_frame` exige que
    // o físico não esteja em uso por outro mapeamento, e um caso não pode
    // violar o contrato que está medindo. Os endereços são altos e de
    // dispositivo nenhum — nada aqui desreferencia o que mapeia.
    let mut fisico = 0x0000_0000_E000_0000u64;
    let mut reservar = |bytes: u64| -> Result<u64, &'static str> {
        let f = fisico;
        fisico += bytes;
        crate::mmio::mapear(f, bytes)
    };

    // Onde o cursor virtual está. `mapear` devolve o endereço que entregou, e
    // a faixa de MMIO é um incremento: o próximo mapeamento começa logo
    // depois deste.
    let sonda = reservar(PAGINA)?;
    let cursor = sonda + PAGINA;

    // Empurrar o cursor até uma fronteira de região. Daqui em diante a
    // geometria é conhecida, que é o que separa este caso de um palpite:
    // sem isso, a falha encomendada poderia cair na **primeira** página do
    // mapeamento — e aí o desfazer não teria nada a desfazer, e o caso
    // passaria sem exercitar a linha que veio medir.
    let resto = cursor % REGIAO;
    let fronteira = if resto == 0 {
        cursor
    } else {
        let base = reservar(REGIAO - resto)?;
        if base != cursor {
            return Err("a faixa de MMIO nao entregou o endereco seguinte");
        }
        cursor + (REGIAO - resto)
    };

    // A âncora paga a tabela de último nível da região nova, sem falha
    // encomendada. É o que garante que o mapeamento seguinte comece numa
    // região cuja tabela já existe.
    let ancora = reservar(PAGINA)?;
    if ancora != fronteira {
        return Err("a ancora nao caiu na fronteira");
    }

    // E agora 512 páginas a partir de `fronteira + PAGINA`: as 511 primeiras
    // caem na região da âncora e não pedem frame nenhum; a última cai na
    // região seguinte, que precisa de tabela nova. É ali, e só ali, que este
    // mapeamento chama o alocador — com 511 páginas já mapeadas atrás dele.
    let inicio = fronteira + PAGINA;

    // A contagem de livres e o mapeamento com as interrupções mascaradas, e
    // pelos dois motivos que o caso de custo do `fork` já seguia. O coletor
    // de fios mortos devolve frames de processos encerrados em outro fio, a
    // qualquer momento: medido, em debug no x86 ele caiu dentro desta janela
    // e os livres **subiram** 44 durante um mapeamento que não devolve
    // nada. E um handler que alocasse um frame no meio consumiria a falha
    // encomendada no lugar do mapeamento.
    let (livres_antes, falho, sobraram, livres_depois) = crate::arch::sem_interrupcoes(|| {
        let (livres_antes, _) = crate::frames::estatisticas();
        crate::frames::encomendar_falhas(1);
        let falho = reservar(REGIAO);
        let sobraram = crate::frames::encomendar_falhas(0);
        let (livres_depois, _) = crate::frames::estatisticas();
        (livres_antes, falho, sobraram, livres_depois)
    });

    if falho.is_ok() {
        return Err("o mapeamento passou apesar da falha encomendada");
    }
    if sobraram != 0 {
        return Err("a falha encomendada nao chegou ao alocador");
    }

    // O que o desfazer existe para garantir: nenhuma página da faixa que
    // falhou traduz. Meia região traduzindo é o defeito — uma escrita nela
    // chegaria ao dispositivo pela metade, e a próxima tentativa de mapear a
    // mesma faixa falharia por um motivo que não é o dela.
    for i in 0..POR_TABELA {
        let pagina = inicio + i * PAGINA;
        if let Some(f) = crate::arch::traduzir(pagina) {
            crate::log_error!(
                "teste",
                "a pagina {:#x} do mapeamento que falhou ainda traduz para {:#x}",
                pagina,
                f
            );
            return Err("o desfazer deixou paginas do mapeamento que falhou");
        }
    }

    // E a âncora, que é de outra chamada, continua onde estava: o desfazer
    // desfaz o que a chamada fez, não o que ela encontrou.
    if crate::arch::traduzir(ancora).is_none() {
        return Err("o desfazer levou junto o mapeamento vizinho");
    }

    // Nenhum frame ficou pelo caminho. A alocação que falhou não chegou a
    // tirar nada, e o desfazer não devolve físico de dispositivo ao alocador
    // — se este número andar, uma das duas coisas deixou de ser verdade.
    //
    // Esta conferência foi decoração do dia em que o caso nasceu até o dia
    // seguinte: lia `estatisticas().1`, que é o total **rastreado** — uma
    // constante —, e comparava a constante com ela mesma. Passava sempre, em
    // silêncio. Quem a denunciou foi o caso da superfície gráfica, que leu o
    // mesmo campo esperando uma **diferença**, e falhou alto. Uma igualdade
    // contra uma constante não tem como reprovar; uma diferença tem.
    //
    // As duas leituras foram feitas lá em cima, dentro da janela mascarada.
    if livres_depois != livres_antes {
        crate::log_error!(
            "teste",
            "livres: {} antes, {} depois do mapeamento que falhou",
            livres_antes,
            livres_depois
        );
        return Err("o desfazer do mapeamento nao devolveu todos os frames");
    }

    Ok(())
}

/// O embrulho que relata um percurso interrompido diz **para quê** era a
/// busca.
///
/// # Por que este caso existe ao lado do de ponta a ponta
///
/// Porque o de ponta a ponta alcança **uma** das cinco buscas. A do host
/// bridge roda primeiro, e as outras quatro só chegam a percorrer o blob
/// depois que ela acha alguma coisa — o que um blob truncado justamente
/// impede. Mutando o relato de qualquer uma das quatro, aquele caso passa.
///
/// Este exercita o embrulho que as cinco compartilham: o `Result` conferido,
/// a linha emitida, e o `para_que` dentro dela. O que fica sem conferência é
/// a string que cada chamada passa — e essa é uma linha que se lê.
fn fdt_o_relato_do_percurso_diz_para_que_era() -> Resultado {
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::log_info!("teste", "o leitor de device tree so existe no aarch64");
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::fdt;

        // Um blob que não é um device tree: a assinatura é a primeira coisa
        // que `percorrer` confere, e recusar ali é o caminho mais curto até
        // o `Err` que o embrulho tem de relatar.
        let blob = [0u8; 64];
        let para_que = "uma busca que este caso inventou";
        let antes = contar_no_log("fdt", para_que);

        // SAFETY: o ponteiro é de um array neste quadro de pilha, e
        // `percorrer` confere a assinatura antes de ler qualquer outra coisa
        // — que é exatamente o caminho que este caso exercita.
        unsafe { fdt::percorrer_relatando(blob.as_ptr(), |_| {}, para_que) };

        if contar_no_log("fdt", para_que) == antes {
            return Err("o percurso falhou e o embrulho nao disse para que era");
        }

        // E a linha traz o motivo, não só o rótulo: sem ele, quem lê o log
        // sabe que algo parou e não sabe o quê.
        if contar_no_log("fdt", "assinatura de device tree invalida") == 0 {
            return Err("o relato nao trouxe o motivo da parada");
        }
        Ok(())
    }
}

/// Uma busca no device tree que para no meio **diz** que parou.
///
/// # O que este caso protege
///
/// Que "esta placa não tem PCI" e "o blob acabou antes de eu achar o PCI"
/// não sejam a mesma resposta. As buscas por barramento, por controlador de
/// interrupção e por larguras devolvem `Option`, e `None` já significa
/// ausência — então um percurso que aborta no meio produz exatamente a
/// resposta que significa outra coisa.
///
/// Cinco chamadas descartavam o `Result` do percurso com `let _ =`. O erro
/// existia, era específico ("deslocamento fora do blob", "assinatura
/// invalida") e ia para o chão. O kernel seguia o boot inteiro convencido de
/// que a máquina não tinha o que ele não conseguiu ler.
///
/// O caso corta o `totalsize` do blob para dentro da região de estrutura,
/// que é o que um firmware truncado produz, e exige a linha de aviso. A
/// busca continua devolvendo `None` — interromper o boot por um `ranges`
/// truncado seria pior —, mas agora com rastro.
fn fdt_busca_que_para_no_meio_avisa() -> Resultado {
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::log_info!("teste", "o leitor de device tree so existe no aarch64");
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::fdt;

        const TOTALSIZE: usize = 4;

        let mut blob = [0u8; 256];
        let usado = montar_dtb(&mut blob, 2, 1);

        // O blob declara-se menor do que é, cortando no meio da estrutura.
        // O percurso obedece ao `totalsize` — é o único limite que ele tem —
        // e para ali.
        let cortado = (usado / 2) as u32;
        blob[TOTALSIZE..TOTALSIZE + 4].copy_from_slice(&cortado.to_be_bytes());

        // A frase **inteira**, e não só "parou antes do fim".
        //
        // A primeira versão deste caso casava com o trecho curto, e passou
        // numa mutação que tirou o relato de `encontrar_barramento_pci`: a
        // linha que ela via vinha de `no_do_host_bridge`, que roda antes e
        // relata por conta. Uma afirmação que casa com qualquer aviso do
        // subsistema não afirma nada sobre o aviso que se queria.
        //
        // E é `no_do_host_bridge` mesmo que este caso alcança: a busca do
        // barramento começa por ela e devolve `None` com `?` quando ela não
        // acha nada, sem chegar ao percurso próprio.
        let marca = "a busca por o host bridge do PCI parou antes do fim";
        let antes = contar_no_log("fdt", marca);

        // SAFETY: o blob está neste quadro de pilha e traz a assinatura; o
        // que se afirma é o que o leitor faz quando o `totalsize` mente.
        let achou = unsafe { fdt::encontrar_barramento_pci(blob.as_ptr()) };
        if achou.is_some() {
            return Err("um blob cortado ao meio produziu um barramento PCI");
        }

        if contar_no_log("fdt", marca) == antes {
            return Err("a busca parou no meio e nao disse nada");
        }
        Ok(())
    }
}

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

/// O texto que uma pessoa lê precisa estar mesmo no framebuffer.
///
/// # O que este caso protege
///
/// Tudo que está entre a fonte e a tela: o endereço para onde o glifo foi, a
/// ordem dos bytes de cada pixel, o stride que separa uma linha da seguinte e
/// a mistura da cobertura parcial com o fundo. Nenhuma dessas quatro coisas
/// falha de forma visível para o kernel — falham produzindo uma tela que só
/// uma pessoa olhando saberia dizer que está errada, e no ARM não havia
/// pessoa nenhuma olhando até agora.
///
/// A conferência é pixel a pixel contra a própria fonte, e mora em
/// [`crate::tela::console::conferir_glifo`] para não haver duas cópias da
/// resposta — uma no desenho e outra no teste, livres para errarem juntas.
fn console_texto_chega_ao_framebuffer() -> Resultado {
    if crate::tela::tela().is_none() {
        return sem_framebuffer();
    }

    // O banner limpa a tela e devolve o cursor ao começo. Sem isso o glifo
    // sairia sobre o que as linhas de log já escreveram, e o que se conferiria
    // seria a soma dos dois.
    sem_intrusos(|| {
        crate::tela::banner();
        let (x, y) = crate::tela::console::cursor();

        if !crate::tela::console::escrever("A") {
            return Err("o console recusou escrever com a tela de pe");
        }
        crate::tela::console::conferir_glifo('A', x, y)?;

        // E o cursor andou exatamente a largura de um glifo. Uma fonte
        // monoespaçada é o que torna isso uma igualdade em vez de um
        // intervalo.
        let (largura, _) = crate::tela::console::tamanho_do_glifo();
        let (depois, _) = crate::tela::console::cursor();
        if depois != x + largura {
            crate::log_error!("teste", "o cursor foi de {} para {}", x, depois);
            return Err("o cursor nao andou uma largura de glifo");
        }

        Ok(())
    })
}

/// O texto que o kernel manda ao console humano aparece na tela.
///
/// # Por que não basta o caso anterior
///
/// Porque ele chama [`crate::tela::console::escrever`] diretamente, e isso
/// prova que o desenho funciona — não que alguém o use. Entre o log e a tela
/// há uma ligação, uma linha em [`crate::serial::_print`], e removê-la
/// deixaria a tela em branco com a suíte inteira verde: os dois casos de
/// console continuariam desenhando por conta própria.
///
/// Este caso passa pelo funil de verdade. É o mesmo `serial_print!` que toda
/// linha de log atravessa.
fn console_log_humano_chega_a_tela() -> Resultado {
    if crate::tela::tela().is_none() {
        return sem_framebuffer();
    }

    sem_intrusos(|| {
        crate::tela::banner();
        let (x, y) = crate::tela::console::cursor();

        crate::serial_print!("X");

        crate::tela::console::conferir_glifo('X', x, y)?;

        // E na tela física. Com o compositor, o console desenha numa camada,
        // e a conferência de cima só prova que a camada tem a letra — um
        // compositor que não levasse nada à tela passaria nela. Esta prova que
        // a letra chegou ao que o monitor mostra.
        let fisica = crate::tela::tela_fisica().ok_or("a tela fisica sumiu")?;
        crate::tela::console::conferir_glifo_em(&fisica, 'X', x, y)
    })
}

/// A linha quebra na borda direita, e o texto rola quando chega ao pé.
///
/// # Por que os dois no mesmo caso
///
/// Porque são a mesma decisão vista de dois lados: o que fazer quando não
/// cabe mais. Errar o primeiro corta letras na borda; errar o segundo escreve
/// fora da tela — e é [`crate::tela::Tela::retangulo`] que recorta, o que
/// significa que o erro não apareceria como falha, e sim como texto que some.
///
/// O caso é escrito com espaços de propósito. Um espaço tem glifo, ocupa
/// largura e move o cursor como qualquer outro, mas sua cobertura é toda
/// zero — e o desenho pula pixel de cobertura zero. Encher a tela com letras
/// de verdade custaria centenas de milhares de escritas em memória de
/// dispositivo; com espaços, custa a mesma lógica e quase nenhum pixel.
fn console_quebra_na_borda_e_rola() -> Resultado {
    let Some(tela) = crate::tela::tela() else {
        return sem_framebuffer();
    };
    sem_intrusos(|| quebra_na_borda_e_rola(&tela))
}

fn quebra_na_borda_e_rola(tela: &crate::tela::Tela) -> Resultado {
    crate::tela::banner();
    let (largura_do_glifo, altura_do_glifo) = crate::tela::console::tamanho_do_glifo();
    let (x_topo, y_topo) = crate::tela::console::cursor();

    // Uma letra na segunda linha, para ver o texto subir.
    crate::tela::console::escrever("\nR\n");

    let (x_inicial, y_inicial) = crate::tela::console::cursor();

    // Espaços suficientes para passar da borda direita com folga.
    let cabem = tela.largura / largura_do_glifo;
    for _ in 0..=cabem {
        crate::tela::console::escrever(" ");
    }

    let (x, y) = crate::tela::console::cursor();
    if x >= x_inicial + cabem * largura_do_glifo {
        return Err("a linha nao quebrou na borda direita");
    }
    if y != y_inicial + altura_do_glifo {
        crate::log_error!("teste", "a linha foi de {} para {}", y_inicial, y);
        return Err("a quebra nao desceu exatamente uma linha");
    }

    // E agora o pé da tela. Uma quebra de linha por vez, parando na primeira
    // em que o cursor **não desce** — que é a rolagem acontecendo: o texto
    // sobe, e o cursor fica na última linha.
    //
    // Parar na primeira, e não contar quantas linhas cabem e conferir no
    // fim, porque a segunda forma exige acertar o número exato — foi assim
    // que a versão deste caso para o recomeço do topo reprovou na primeira
    // escrita.
    let linhas = tela.altura / altura_do_glifo;
    let rolagens_antes = crate::tela::console::rolagens();
    let mut rolou = false;
    for _ in 0..=linhas {
        let (_, antes) = crate::tela::console::cursor();
        crate::tela::console::escrever("\n");
        let (_, agora) = crate::tela::console::cursor();
        if agora == antes {
            rolou = true;
            break;
        }
        if agora < antes {
            return Err("o console recomecou do topo em vez de rolar");
        }
    }
    if !rolou {
        return Err("o console nunca rolou, mesmo passando do pe");
    }
    if crate::tela::console::rolagens() != rolagens_antes + 1 {
        return Err("rolar uma linha nao contou uma rolagem");
    }

    // A letra subiu uma linha: estava na segunda, está na primeira — na grade
    // e nos pixels.
    if crate::tela::console::caractere(0, 0) != Some('R') {
        return Err("a grade nao subiu junto com a tela");
    }
    crate::tela::console::conferir_glifo('R', x_topo, y_topo)?;
    // E na tela física, depois que o compositor levar: uma rolagem que não
    // marcasse a região como suja ficaria na camada, e o monitor mostraria o
    // texto no lugar antigo.
    crate::tela::descarregar();
    let fisica = crate::tela::tela_fisica().ok_or("a tela fisica sumiu")?;
    crate::tela::console::conferir_glifo_em(&fisica, 'R', x_topo, y_topo)?;
    // E a linha de baixo subiu também: a segunda linha tem agora o que a
    // terceira tinha — os espaços da quebra na borda.
    if crate::tela::console::caractere(0, 1) != Some(' ') {
        return Err("a linha de baixo nao subiu junto com a da letra");
    }

    // E a faixa de cima da região do console não foi tocada.
    match tela.ler_pixel(0, 0) {
        Some(topo) if topo == Cor::ACENTO => Ok(()),
        Some(_) => Err("a rolagem do console subiu por cima da faixa de cima"),
        None => Err("o canto da tela nao pode ser lido"),
    }
}

/// A linha de comando continua descrita onde está quando a tela rola com
/// ela aberta: qualquer impressão do kernel no pé da tela faz subir, e o
/// campo sobe junto — na árvore e na grade.
fn console_rolar_leva_a_linha_de_comando() -> Resultado {
    let Some(g) = crate::tela::console::geometria() else {
        return sem_framebuffer();
    };
    sem_intrusos(|| {
        // Até o pé da tela, com o interpretador desligado.
        crate::tela::banner();
        for _ in 0..g.linhas {
            crate::tela::console::escrever("\n");
        }
        crate::interpretador::ativar_para_teste();
        let resultado = (|| {
            let (_, linha_do_prompt) =
                crate::interpretador::inicio_do_campo().ok_or("a linha de comando nao abriu")?;
            crate::interpretador::definir("abc")?;
            // Uma impressão comum, que não passa pelo log nem redesenha o
            // prompt: a tela sobe por baixo do campo.
            let rolagens = crate::tela::console::rolagens();
            crate::serial_println!();
            if crate::tela::console::rolagens() == rolagens {
                return Err("imprimir no pe da tela nao rolou");
            }
            let (_, linha) =
                crate::interpretador::inicio_do_campo().ok_or("a linha de comando sumiu")?;
            if linha + 1 != linha_do_prompt {
                crate::log_error!(
                    "teste",
                    "o campo estava na {} e ficou na {}",
                    linha_do_prompt,
                    linha
                );
                return Err("o campo nao subiu junto com a tela");
            }
            if crate::tela::console::caractere(0, linha) != Some('d') {
                return Err("onde a arvore diz que o campo comeca nao esta o prompt");
            }
            Ok(())
        })();
        crate::interpretador::desativar_para_teste();
        crate::interpretador::limpar();
        resultado
    })
}

/// Os códigos comuns ao PS/2 e ao virtio-input produzem o caractere certo.
///
/// # O que este caso protege
///
/// As duas tabelas de [`crate::teclado`], que são escritas contando
/// caracteres à mão. Um trecho com um caractere a mais desloca tudo o que vem
/// depois, e o sintoma é uma tecla digitando a letra da vizinha — nada que
/// quebre, nada que apareça em teste que não digite.
///
/// As asserções de compilação já ancoram os índices que importam. Este caso
/// cobre o resto do caminho: o evento, a fila e a leitura.
///
/// Ele é a única parte do teclado que a suíte alcança. Os dois drivers —
/// o scancode do 8042 e o evento do virtio — dependem de hardware que a
/// suíte não tem como acionar, e quem os exercita é a sonda de fumaça, que
/// manda teclas pelo monitor do emulador.
fn teclado_codigo_vira_caractere() -> Resultado {
    crate::teclado::esvaziar();

    // `a`, `z`, `1` e espaço: um de cada trecho da tabela, que é onde um
    // desalinhamento apareceria.
    for (codigo, esperado) in [(30u8, 'a'), (44, 'z'), (2, '1'), (57, ' ')] {
        crate::teclado::evento(codigo, true);
        match crate::teclado::ler() {
            Some(c) if c == esperado => {}
            Some(c) => {
                crate::log_error!(
                    "teste",
                    "o codigo {} deu {:?}, esperado {:?}",
                    codigo,
                    c,
                    esperado
                );
                return Err("o codigo produziu outro caractere");
            }
            None => return Err("o codigo nao produziu caractere nenhum"),
        }
    }

    // E um código que não é texto não enfileira nada.
    crate::teclado::evento(29, true); // control
    if crate::teclado::ler().is_some() {
        return Err("uma tecla sem caractere enfileirou alguma coisa");
    }

    Ok(())
}

/// O shift muda a letra, e soltá-lo a muda de volta.
///
/// # Por que a segunda metade é a que importa
///
/// Porque o pressionar é fácil de acertar e o soltar é fácil de esquecer —
/// e esquecê-lo não produz erro nenhum: produz um teclado que digita em
/// maiúsculas para sempre depois do primeiro shift. Um caso que só
/// conferisse a letra maiúscula passaria nesse kernel.
fn teclado_shift_muda_e_solta() -> Resultado {
    crate::teclado::esvaziar();

    crate::teclado::evento(42, true); // shift esquerdo
    if crate::teclado::ler().is_some() {
        return Err("o shift enfileirou um caractere");
    }

    crate::teclado::evento(30, true);
    if crate::teclado::ler() != Some('A') {
        return Err("com shift, a tecla nao deu maiuscula");
    }

    crate::teclado::evento(42, false); // e solta

    crate::teclado::evento(30, true);
    if crate::teclado::ler() != Some('a') {
        return Err("o shift ficou preso depois de solto");
    }

    // E o shift da direita faz a mesma coisa. São dois códigos diferentes
    // para a mesma tecla, e tratar só um é o tipo de metade que passa
    // despercebida.
    crate::teclado::evento(54, true);
    crate::teclado::evento(30, true);
    let com_o_direito = crate::teclado::ler();
    crate::teclado::evento(54, false);
    if com_o_direito != Some('A') {
        return Err("o shift da direita nao muda a letra");
    }

    Ok(())
}

/// Soltar uma tecla não digita a letra outra vez.
///
/// Cada tecla chega duas vezes — pressionar e soltar —, e tratar as duas
/// igual dobra tudo o que se digita. É o defeito mais provável deste módulo,
/// e o mais fácil de não ver: o texto sai, só sai errado.
fn teclado_soltar_nao_digita() -> Resultado {
    crate::teclado::esvaziar();

    crate::teclado::evento(30, true);
    crate::teclado::evento(30, false);

    if crate::teclado::ler() != Some('a') {
        return Err("a tecla nao produziu a letra");
    }
    if let Some(c) = crate::teclado::ler() {
        crate::log_error!("teste", "soltar tambem digitou {:?}", c);
        return Err("soltar a tecla digitou de novo");
    }

    Ok(())
}

/// O relatório de um teclado USB vira as teclas certas.
///
/// # O que este caso protege
///
/// Três coisas que falham em silêncio. A tabela do HID para o AT, que é
/// escrita à mão e cuja numeração **não** coincide com a dos outros dois
/// barramentos — no HID as letras estão em ordem alfabética, no AT na ordem
/// do teclado. A dedução de eventos a partir do estado, que é o que impede
/// uma tecla segurada de digitar a cada relatório. E a ordem entre o
/// modificador e a letra dentro do mesmo relatório: o shift precisa valer
/// antes de a letra ser traduzida, ou a maiúscula sai minúscula.
///
/// E uma quarta, desde que o controlador atende mais de um dispositivo: a
/// memória do relatório anterior é de cada teclado, e não do módulo.
///
/// É, com o relatório do mouse, o pedaço do caminho USB que a suíte alcança.
/// O controlador xHCI depende de hardware que ela não tem como acionar, e
/// quem o exercita é a fumaça com `--teclado usb`.
fn usb_relatorio_hid_vira_teclas() -> Resultado {
    use crate::usb::hid::processar;
    crate::teclado::esvaziar();
    let mut anterior = [0u8; 8];

    // `a` é 0x04 no HID e 30 no AT — os dois números mais distantes que esta
    // tabela precisa ligar.
    processar(&mut anterior, [0, 0, 0x04, 0, 0, 0, 0, 0]);
    if crate::teclado::ler() != Some('a') {
        return Err("o relatorio com `a` nao produziu a letra");
    }

    // O mesmo relatório outra vez é a tecla **continuando** pressionada.
    processar(&mut anterior, [0, 0, 0x04, 0, 0, 0, 0, 0]);
    if let Some(c) = crate::teclado::ler() {
        crate::log_error!("teste", "segurar a tecla digitou {:?} de novo", c);
        return Err("segurar a tecla repetiu a letra");
    }

    // Outro teclado, com a memória dele: o `a` que o primeiro segura é, para
    // este, uma tecla nova.
    let mut outro = [0u8; 8];
    processar(&mut outro, [0, 0, 0x04, 0, 0, 0, 0, 0]);
    if crate::teclado::ler() != Some('a') {
        return Err("um segundo teclado herdou o que o primeiro segurava");
    }

    // Solta tudo, e então shift com `b` no mesmo relatório.
    processar(&mut anterior, [0, 0, 0, 0, 0, 0, 0, 0]);
    processar(&mut anterior, [0x02, 0, 0x05, 0, 0, 0, 0, 0]);
    if crate::teclado::ler() != Some('B') {
        return Err("shift e `b` no mesmo relatorio nao deram maiuscula");
    }

    // E um usage que não é texto não vira nada.
    if crate::usb::hid::traduzir(0x32).is_some() {
        return Err("um usage sem equivalente virou codigo");
    }

    Ok(())
}

/// Os programas compilados à parte rodam: saem com o código deles e dizem o
/// que deviam dizer, lidos do disco.
///
/// # O que este caso protege
///
/// A cadeia inteira, que nenhum outro caso atravessa: o pacote `programas`
/// compilado pelo `xtask`, posto no disco, lido pelo VFS, validado pelo
/// carregador de ELF e executado. O `ola` usa o monte, a formatação e 40 KiB
/// de pilha; o `memoria` confere as recusas de `mapear` do lado de quem
/// pede, e que o monte reaproveita o que libera. Os dois dizem o que deu
/// errado pelo código de saída — ver cada um em `programas/src/bin`.
///
/// E um vazamento: lançar do disco guardava a imagem num `Vec` do heap do
/// kernel que ninguém largava, porque `executar` não volta. Cinco
/// lançamentos seguidos custariam cinco imagens; o caso confere que custam
/// menos que uma.
fn usuario_programas_compilados_rodam() -> Resultado {
    use crate::usuario::DIRETORIO_DOS_COMPILADOS;
    use alloc::format;

    if !DIRETORIO_DOS_COMPILADOS.ends_with(crate::arch::nome()) {
        return Err("o diretorio dos programas compilados nao e o desta arquitetura");
    }

    // Espera o processo sair com o código dele — ou morrer. Pela linha do
    // log a partir do lançamento, e não por um contador de saídas: um
    // programa que bifurca tem duas, e a primeira pode ser a do filho. E um
    // processo morto por falha não sai; esperar só pela saída transformava
    // a morte num estouro de tempo sem motivo — medido, com a pilha de volta
    // a uma página, o caso dizia "a condicao nao se cumpriu" em vez de dizer
    // que o programa morreu.
    let rodar = |nome: &str, codigo: i64| -> Resultado {
        let caminho = format!("{DIRETORIO_DOS_COMPILADOS}/{nome}");
        let desde = crate::log::total_emitidos();
        let saida = format!("processo encerrou com codigo {codigo}");
        let visto = |procurada: &str| {
            let mut achou = false;
            crate::log::ultimos(24, crate::log::Level::Trace, |r| {
                achou |= r.seq >= desde
                    && r.subsistema == "usuario"
                    && r.mensagem().starts_with(procurada);
            });
            achou
        };
        crate::usuario::lancar(Some(&caminho))?;
        let _ = esperar_ate(|| visto(&saida) || visto("processo morto por"), 600);
        if visto("processo morto por") {
            crate::log_error!("teste", "{} morreu por uma falha", nome);
            return Err("um programa compilado morreu por uma falha");
        }
        if !visto(&saida) {
            crate::log_error!("teste", "{} nao saiu com {}", nome, codigo);
            return Err("um programa compilado nao saiu com o codigo dele");
        }
        Ok(())
    };

    // Os frames livres antes: o `memoria` esgota a memória de propósito, e
    // o que ele segurava tem de voltar quando ele sair.
    let livres_antes = crate::frames::estatisticas().0;

    // O quarto campo diz se o programa usa o monte — e, portanto, se tem de
    // ter pedido memória ao kernel.
    for (nome, codigo, marca, usa_o_monte) in [
        ("ola", 61, "ola do Rust, no anel sem privilegio", true),
        ("memoria", 62, "memoria conferida:", true),
        ("ponteiros", 64, "ponteiros conferidos:", false),
    ] {
        let mapeamentos = crate::usuario::estatisticas_de_memoria().0;
        rodar(nome, codigo)?;
        let mut disse = false;
        crate::log::ultimos(32, crate::log::Level::Trace, |r| {
            disse |= r.subsistema == "usuario" && r.mensagem().starts_with(marca);
        });
        if !disse {
            return Err("um programa compilado nao disse o que devia");
        }
        // O monte vem de `mapear`.
        if usa_o_monte && crate::usuario::estatisticas_de_memoria().0 == mapeamentos {
            return Err("um programa compilado rodou sem pedir memoria ao kernel");
        }
    }

    // A linha longa do `ola`: cortada no tamanho de um registro, e marcada
    // com a reticência — uma linha truncada que parecesse inteira mentiria
    // para quem lê o log.
    let mut cortada = false;
    crate::log::ultimos(32, crate::log::Level::Trace, |r| {
        let m = r.mensagem();
        cortada |= r.subsistema == "usuario" && m.starts_with("longa longa") && m.ends_with('…');
    });
    if !cortada {
        return Err("a linha longa do ola nao chegou cortada e marcada");
    }

    // O vazamento: cinco lançamentos, e o heap do kernel no fim cresce menos
    // que uma imagem. O coletor precisa passar para largar os fios mortos, e
    // é por isso que a medida é tomada depois de uma espera.
    let imagem = crate::vfs::ler_tudo(&format!("{DIRETORIO_DOS_COMPILADOS}/ola"))
        .map_err(|_| "o ola nao esta no disco")?
        .len();
    let esperar_o_coletor = || {
        let _ = esperar_ate(|| false, 30);
    };
    esperar_o_coletor();
    let antes = crate::heap::estatisticas().alocado;
    for _ in 0..5 {
        rodar("ola", 61)?;
    }
    esperar_o_coletor();
    let depois = crate::heap::estatisticas().alocado;

    // E o `memoria` esgotou a memória e deixou a máquina inteira: os frames
    // que ele segurava voltaram quando ele saiu e o coletor passou. A folga
    // é de um punhado de frames — tabelas de página que o kernel guarda para
    // o próximo processo, e não um espaço de endereços retido.
    let livres_depois = crate::frames::estatisticas().0;
    if livres_depois + 64 < livres_antes {
        crate::log_error!(
            "teste",
            "frames livres: {} antes dos programas, {} depois",
            livres_antes,
            livres_depois
        );
        return Err("a memoria que o programa esgotou nao voltou quando ele saiu");
    }

    if depois > antes + imagem {
        crate::log_error!(
            "teste",
            "o heap do kernel cresceu {} bytes em cinco lancamentos de {} bytes",
            depois - antes,
            imagem
        );
        return Err("lancar do disco vaza a imagem no heap do kernel");
    }
    Ok(())
}

/// Um canal de eventos: o ouvinte dorme com a fila vazia, recebe em ordem o
/// que o kernel publica, e o que não cabe é recusado e contado.
///
/// # O que este caso protege
///
/// O mecanismo por onde o servidor de janelas vai saber do mundo. Quatro
/// coisas, e cada uma falha em silêncio:
///
/// - **dormir de verdade.** Um ouvinte que girasse perguntando também
///   receberia tudo, e o caso só passaria a ver a diferença na conta das
///   chamadas de sistema: com a fila vazia, ela não pode andar;
/// - **a ordem.** Uma fila circular com o índice errado entrega tudo, fora
///   de ordem;
/// - **o que não cabe.** Setenta eventos numa fila de sessenta e quatro, com
///   o ouvinte impedido de rodar no meio: seis recusados, contados, e os
///   sessenta e quatro entregues — a soma no fim confere quais;
/// - **o ouvinte que morre.** Ele não fecha o descritor; o canal volta a
///   ser de ninguém quando alguém o procura, e o nome fica livre.
fn eventos_canal_dorme_entrega_e_recusa() -> Resultado {
    use crate::eventos::{self, CAPACIDADE, NaoPublicado};
    use crate::usuario::DIRETORIO_DOS_COMPILADOS;
    use alloc::format;
    use protocolo::usuario::evento::{Evento, tipo};

    const CANAL: &str = "teste-eco";
    let teste = |a: i64| Evento {
        tipo: tipo::TESTE,
        a,
        b: 0,
        c: 0,
    };
    let desde = crate::log::total_emitidos();
    let visto = |procurada: &str| {
        let mut achou = false;
        crate::log::ultimos(24, crate::log::Level::Trace, |r| {
            achou |= r.seq >= desde && r.subsistema == "usuario" && r.mensagem() == procurada;
        });
        achou
    };

    // Ninguém escuta ainda.
    if eventos::publicar(CANAL, teste(1)) != Err(NaoPublicado::SemOuvinte) {
        return Err("publicar num canal sem ouvinte nao foi recusado");
    }

    crate::usuario::lancar(Some(&format!("{DIRETORIO_DOS_COMPILADOS}/eco")))?;
    esperar_ate(|| visto("eco: escutando"), 600)?;

    // Dormindo: o canal sabe que o ouvinte espera, e a conta de chamadas de
    // sistema para enquanto a fila está vazia.
    esperar_ate(|| eventos::estado(CANAL).is_some_and(|e| e.esperando), 200)?;
    let chamadas = crate::usuario::estatisticas().0;
    let _ = esperar_ate(|| false, 20);
    if crate::usuario::estatisticas().0 != chamadas {
        return Err("o ouvinte fez chamadas de sistema com a fila vazia, em vez de dormir");
    }

    // Cinco eventos, e as linhas na ordem em que foram publicados.
    for n in 1..=5 {
        eventos::publicar(CANAL, teste(n))
            .map_err(|_| "o canal recusou um evento com a fila vazia")?;
    }
    esperar_ate(|| visto("eco 5"), 600)?;
    let mut ordem = alloc::vec::Vec::new();
    crate::log::ultimos(24, crate::log::Level::Trace, |r| {
        if r.seq >= desde
            && let Some(n) = r.mensagem().strip_prefix("eco ")
            && let Ok(n) = n.parse::<i64>()
        {
            ordem.push(n);
        }
    });
    if ordem != [1, 2, 3, 4, 5] {
        crate::log_error!("teste", "o ouvinte disse {:?}", ordem);
        return Err("os eventos nao chegaram na ordem em que foram publicados");
    }

    // A rajada, com as interrupções mascaradas: o ouvinte não roda no meio,
    // e a fila enche.
    let rajada = 70;
    let recusados = crate::arch::sem_interrupcoes(|| {
        (100..100 + rajada)
            .filter(|&n| eventos::publicar(CANAL, teste(n)) == Err(NaoPublicado::Cheio))
            .count()
    });
    if recusados != rajada as usize - CAPACIDADE {
        crate::log_error!("teste", "{} de {} recusados", recusados, rajada);
        return Err("a fila cheia nao recusou exatamente o que nao cabia");
    }
    esperar_ate(
        || eventos::estado(CANAL).is_some_and(|e| e.entregues == 5 + CAPACIDADE as u64),
        600,
    )?;
    if eventos::estado(CANAL).map(|e| e.recusados) != Some(recusados as u64) {
        return Err("o canal nao contou os recusados");
    }

    // O fim: a contagem e a soma dizem que chegaram os cinco e os sessenta
    // e quatro **primeiros** da rajada — de 100 a 163.
    eventos::publicar(CANAL, teste(0)).map_err(|_| "o canal recusou o fim")?;
    let soma = 15 + (100..100 + CAPACIDADE as i64).sum::<i64>();
    let fim = format!("eco: fim, {} eventos, soma {}", 5 + CAPACIDADE, soma);
    esperar_ate(|| visto(&fim), 600).map_err(|_| "o ouvinte nao disse o fim esperado")?;
    esperar_ate(|| visto("processo encerrou com codigo 63"), 600)?;

    // O ouvinte saiu sem fechar o descritor: o canal volta a ser de ninguém
    // na primeira vez que alguém o procura.
    let recuperados = eventos::recuperados();
    if eventos::publicar(CANAL, teste(1)) != Err(NaoPublicado::SemOuvinte) {
        return Err("o canal de um ouvinte morto continuou aceitando eventos");
    }
    if eventos::recuperados() != recuperados + 1 || eventos::estado(CANAL).is_some() {
        return Err("o canal do ouvinte morto nao foi recuperado");
    }
    Ok(())
}

/// Uma linha digitada se separa em nome de comando e parâmetros.
///
/// # O que este caso protege
///
/// A única lógica do interpretador que não depende de hardware, e a que erra
/// em silêncio: um nome com espaço sobrando não é encontrado no registro, e o
/// que a pessoa vê é "comando desconhecido" para um comando que existe.
///
/// Os parâmetros ausentes viram `{}`, e não string vazia. A diferença importa
/// porque é o que o registro recebe: um `Json` sobre bytes vazios não é um
/// objeto, e todo handler que consulta um parâmetro opcional passaria a ver
/// ausência onde deveria ver um objeto sem campos.
fn console_linha_vira_nome_e_parametros() -> Resultado {
    use crate::interpretador::separar;

    if separar("agent.ping") != ("agent.ping", "{}") {
        return Err("um comando sem parametros nao virou nome mais objeto vazio");
    }

    // Espaços dos dois lados, e mais de um no meio: é o que uma pessoa digita.
    if separar("  log.tail   {\"count\":3}  ") != ("log.tail", "{\"count\":3}") {
        return Err("os espacos em volta entraram no nome ou nos parametros");
    }

    if separar("") != ("", "{}") {
        return Err("a linha vazia nao virou nome vazio");
    }

    Ok(())
}

/// Um caminho absoluto chega ao conteúdo do arquivo.
///
/// # Por que conferir o conteúdo, e não só que resolveu
///
/// Porque resolver prova que a árvore foi percorrida, e não que o que voltou
/// é o arquivo certo. O que sai de `/bin` é um ELF, e os quatro primeiros
/// bytes de um ELF são conhecidos — é a diferença entre "leu alguma coisa" e
/// "leu aquilo".
fn vfs_caminho_chega_ao_conteudo() -> Resultado {
    let imagem = crate::vfs::ler_tudo("/bin/exemplo").map_err(|e| e.motivo())?;

    if imagem.len() < 4 || &imagem[..4] != b"\x7fELF" {
        crate::log_error!(
            "teste",
            "vieram {} bytes, comecando diferente",
            imagem.len()
        );
        return Err("o que veio de /bin/exemplo nao e um ELF");
    }

    // E o tamanho que a resolução anunciou bate com o que a leitura trouxe. As
    // duas informações vêm do mesmo sistema de arquivos por caminhos
    // diferentes, e divergirem é o sintoma de uma leitura que parou cedo.
    let vnode = crate::vfs::resolver("/bin/exemplo").map_err(|e| e.motivo())?;
    if vnode.no.tamanho as usize != imagem.len() {
        crate::log_error!(
            "teste",
            "o no diz {} bytes e a leitura trouxe {}",
            vnode.no.tamanho,
            imagem.len()
        );
        return Err("o tamanho do no nao bate com o que foi lido");
    }

    Ok(())
}

/// Cada jeito de um caminho não dar certo devolve o motivo certo.
///
/// # O que este caso protege
///
/// A distinção entre os motivos. Um VFS que devolvesse "não encontrado" para
/// tudo compilaria e passaria em qualquer teste que só olhasse `is_err` — e
/// quem estivesse depurando não saberia se errou o caminho, se esqueceu de
/// montar, ou se pediu para entrar dentro de um arquivo.
fn vfs_recusa_o_que_nao_resolve() -> Resultado {
    use crate::vfs::Erro;

    // Relativo: não há diretório de trabalho neste kernel.
    if crate::vfs::resolver("bin/exemplo").err() != Some(Erro::CaminhoInvalido) {
        return Err("um caminho relativo nao foi recusado como invalido");
    }

    // `SemMontagem` não é exercitado aqui, e a razão é o que mudou: com a raiz
    // do disco montada em `/`, **todo** caminho absoluto tem dona. O motivo
    // continua existindo para a janela entre o boot e a montagem da raiz, que
    // é quando um caminho não tem quem responda por ele — e essa janela a
    // suíte não alcança, porque ela roda com tudo já montado.
    //
    // Antes deste commit o caso conferia `/nada/aqui`, e ele passou a resolver
    // pela raiz. Um caso que afirma algo que deixou de ser verdade é pior que
    // um que não afirma nada.

    // Dentro da montagem, e o nome não existe.
    if crate::vfs::resolver("/bin/nao-existe").err() != Some(Erro::NaoEncontrado) {
        return Err("um nome ausente devolveu outro motivo");
    }

    // E entrar dentro de um arquivo.
    if crate::vfs::resolver("/bin/exemplo/mais").err() != Some(Erro::NaoEhDiretorio) {
        return Err("entrar dentro de um arquivo devolveu outro motivo");
    }

    Ok(())
}

/// Com duas montagens encaixadas, a mais específica é a dona.
///
/// # Por que esta regra precisa de teste
///
/// Porque a versão errada funciona até o dia em que houver duas montagens.
/// Escolhendo a primeira que casa, `/bin/exemplo` passaria a ser procurado na
/// raiz assim que a raiz existisse — e o que se veria é `executar` parando de
/// achar os programas no dia em que o disco fosse montado, sem nada
/// apontando para a causa.
///
/// É exatamente o dia que vem a seguir: o Btrfs entra em `/`.
fn vfs_montagem_mais_longa_ganha() -> Resultado {
    // Pontos de montagem próprios, que não existem em produção.
    //
    // A primeira versão deste caso mexia em `/bin`: desmontava, remontava em
    // outra ordem e devolvia. Funcionou até a raiz do disco ser montada — aí
    // o `montar("/")` passou a falhar com "ja ha algo montado", e o `?` saiu
    // da função **depois** de desmontar `/bin` e antes de o repor. Todos os
    // casos seguintes rodaram sem `/bin`, e o de `executar` reprovou por um
    // motivo que não tinha nada a ver com ele.
    //
    // Um caso que mexe no estado global de produção é um caso que pode
    // derrubar os outros. Este mexe só no que ele mesmo criou.
    const FUNDO: &str = "/teste-de-montagem";
    const DENTRO: &str = "/teste-de-montagem/dentro";

    // A ordem é o ponto: o mais curto entra primeiro, então a regra errada —
    // "a primeira da lista que casar" — escolheria ele.
    crate::vfs::montar(
        "programas",
        FUNDO,
        alloc::boxed::Box::new(crate::vfs::programas::Programas),
    )
    .map_err(|e| e.motivo())?;

    let segunda = crate::vfs::montar(
        "programas",
        DENTRO,
        alloc::boxed::Box::new(crate::vfs::programas::Programas),
    );

    // Daqui para baixo nada sai sem desmontar: as duas montagens são deste
    // caso, e deixá-las penduradas estraga quem vier depois.
    let pelo_dentro = crate::vfs::resolver("/teste-de-montagem/dentro/exemplo");
    let pelo_fundo = crate::vfs::resolver("/teste-de-montagem/exemplo");

    let _ = crate::vfs::desmontar(DENTRO);
    let _ = crate::vfs::desmontar(FUNDO);

    segunda.map_err(|e| e.motivo())?;
    if pelo_dentro.is_err() {
        return Err("o caminho foi procurado na montagem curta em vez da longa");
    }
    if pelo_fundo.is_err() {
        return Err("o que esta na montagem curta deixou de ser alcancavel");
    }

    Ok(())
}

/// Uma leitura de vários setores devolve os mesmos bytes que várias de um.
///
/// # O que este caso protege
///
/// A montagem da cadeia de descritores. Um pedido de dezesseis kilobytes não
/// cabe numa página, então ele vira uma entrada por página — e a ordem delas
/// é o que decide onde cada setor aterrissa. Trocar duas páginas, ou copiar
/// de volta na ordem errada, produz um buffer que tem todos os bytes certos
/// nos lugares errados: nada falha, nada avisa, e quem lê um sistema de
/// arquivos em cima disso vê estruturas embaralhadas.
///
/// A conferência é contra a leitura setor a setor, que é o caminho que já
/// estava exercitado. As duas precisam concordar byte a byte.
///
/// O tamanho não-alinhado está aqui de propósito: doze setores são uma página
/// e meia, e é onde um laço que assume páginas cheias se perde.
fn disco_leitura_multipla_atravessa_paginas() -> Resultado {
    const PRIMEIRO: u64 = PADRAO_DE;
    let maximo = crate::virtio::blk::MAIOR_LEITURA / crate::virtio::blk::TAMANHO_DO_SETOR;

    for quantos in [1usize, 12, maximo] {
        let mut juntos = [0u8; crate::virtio::blk::MAIOR_LEITURA];
        let bytes = quantos * crate::virtio::blk::TAMANHO_DO_SETOR;
        let Some(resultado) =
            crate::virtio::blk::com_o_disco(|d| d.ler(PRIMEIRO, &mut juntos[..bytes]))
        else {
            return Err("nao ha disco nesta maquina");
        };
        resultado?;

        for i in 0..quantos {
            let esperado = marca_do_setor(PRIMEIRO + i as u64);
            let fatia = &juntos[i * crate::virtio::blk::TAMANHO_DO_SETOR..]
                [..crate::virtio::blk::TAMANHO_DO_SETOR];
            if let Some(posicao) = fatia.iter().position(|&b| b != esperado) {
                crate::log_error!(
                    "teste",
                    "lendo {} setores: o setor {} traz {:#04x} no byte {}, esperava {:#04x}",
                    quantos,
                    PRIMEIRO + i as u64,
                    fatia[posicao],
                    posicao,
                    esperado
                );
                return Err("a leitura multipla trouxe os setores fora de ordem");
            }
        }
    }

    // E os pedidos que o driver precisa recusar. Um destino que não é
    // múltiplo de setor faria o dispositivo escrever menos do que a cadeia
    // anuncia; um maior que a cadeia comporta não caberia nos descritores.
    let mut qualquer = [0u8; crate::virtio::blk::MAIOR_LEITURA];
    let recusas = crate::virtio::blk::com_o_disco(|d| {
        [
            d.ler(PRIMEIRO, &mut []).is_err(),
            d.ler(PRIMEIRO, &mut qualquer[..100]).is_err(),
            d.ler(
                PRIMEIRO,
                &mut qualquer[..crate::virtio::blk::TAMANHO_DO_SETOR + 1],
            )
            .is_err(),
        ]
    });
    let Some(recusas) = recusas else {
        return Err("nao ha disco nesta maquina");
    };
    if !recusas.iter().all(|r| *r) {
        return Err("o driver aceitou um destino que nao e multiplo de setor");
    }

    Ok(())
}

/// A tabela de partições lida do disco descreve o disco que o `xtask` montou.
///
/// # O que este caso protege
///
/// A aritmética da GPT: o vetor de entradas fica num LBA que o cabeçalho
/// indica, cada entrada tem um tamanho que o cabeçalho indica, e o último
/// setor é **inclusive**. Errar o inclusive dá uma partição um setor menor;
/// errar o tamanho da entrada dá partições que não existem, montadas a partir
/// de bytes no meio de outra.
///
/// Os números vêm do `xtask`, que é quem manda montar o disco — e é o mesmo
/// contrato duplicado que o padrão por setor já tem, pela mesma razão: os
/// dois lados rodam em máquinas diferentes.
fn particoes_tabela_do_disco() -> Resultado {
    let tabela = crate::particoes::varrer()?;
    let mut vistas = 0;

    for particao in tabela.iter() {
        vistas += 1;
        let esperado = match particao.tipo {
            crate::particoes::Tipo::Esp => (2048u64, 98304u64),
            crate::particoes::Tipo::Dados => (100352, 262144),
            crate::particoes::Tipo::Outro => {
                return Err("apareceu uma particao de tipo inesperado");
            }
        };
        if (particao.primeiro, particao.setores) != esperado {
            crate::log_error!(
                "teste",
                "particao {}: comeca em {} com {} setores",
                particao.tipo.como_str(),
                particao.primeiro,
                particao.setores
            );
            return Err("uma particao nao tem o lugar nem o tamanho que o disco declara");
        }
    }

    if vistas != 2 {
        crate::log_error!("teste", "a tabela trouxe {} particoes", vistas);
        return Err("o disco tem duas particoes e a tabela disse outra coisa");
    }

    Ok(())
}

/// O superbloco lido do disco é o que o `mkfs.btrfs` escreveu.
///
/// # Por que estes campos
///
/// Porque cada um deles vem de um deslocamento diferente, e um erro de
/// deslocamento produz números plausíveis — um endereço que existe, um
/// tamanho que cabe. Conferir vários espalhados pelo bloco é o que
/// transforma "leu alguma coisa" em "leu o campo certo".
///
/// O `nodesize` tem um papel a mais: ele é 16 KiB, que é exatamente o que
/// [`crate::virtio::blk::MAIOR_LEITURA`] traz numa ida ao disco. Os dois
/// números coincidirem não é sorte — o driver foi dimensionado para isto — e
/// o caso falha se alguém mudar um sem o outro.
fn btrfs_superbloco_confere() -> Resultado {
    let tabela = crate::particoes::varrer()?;
    let particao = tabela
        .primeira(crate::particoes::Tipo::Dados)
        .ok_or("nao ha particao de dados")?;

    let mut bloco = alloc::vec![0u8; 4096];
    let sb = crate::vfs::btrfs::do_disco(particao.primeiro, &mut bloco)?;

    if crate::vfs::btrfs::rotulo(&bloco) != "duke-raiz" {
        return Err("o rotulo do sistema de arquivos nao e o esperado");
    }
    // O tamanho de nó da imagem é escolhido pelo `xtask`, e é menor que o
    // padrão do `mkfs.btrfs` de propósito: é o que faz a árvore de arquivos
    // ganhar níveis com poucos arquivos. Ver `disco::TAMANHO_DE_NO`.
    //
    // O que este caso afirma é que o leitor **lê** o campo em vez de
    // presumir um valor: um nó diferente do padrão, e diferente do tamanho
    // de uma ida ao disco, é o que separa as duas coisas. O teto continua
    // valendo — um nó maior que uma ida exigiria remontar a leitura.
    const TAMANHO_DE_NO: u32 = 4096;
    if sb.tamanho_de_no != TAMANHO_DE_NO {
        crate::log_error!(
            "teste",
            "o no tem {} bytes e a imagem foi formatada com {}",
            sb.tamanho_de_no,
            TAMANHO_DE_NO
        );
        return Err("o tamanho de no nao e o que o xtask formatou");
    }
    if sb.tamanho_de_no as usize > crate::virtio::blk::MAIOR_LEITURA {
        return Err("o no nao cabe numa ida ao disco");
    }
    if sb.tamanho_de_setor != 4096 {
        return Err("o tamanho de setor do sistema de arquivos mudou");
    }
    if sb.total != 128 * 1024 * 1024 {
        return Err("o sistema de arquivos nao tem o tamanho da particao");
    }
    // Os dois endereços de raiz são lógicos, e o que se pode afirmar sem
    // traduzi-los é que existem e não coincidem: são árvores diferentes.
    if sb.raiz == 0 || sb.raiz_dos_pedacos == 0 || sb.raiz == sb.raiz_dos_pedacos {
        return Err("as raizes do superbloco nao sao dois enderecos distintos");
    }

    Ok(())
}

/// Um superbloco com qualquer byte trocado é recusado.
///
/// # Por que este é o caso que importa
///
/// Porque calcular a soma e **conferi-la** são coisas diferentes, e a
/// diferença não aparece em nenhum caminho feliz. Um leitor que calculasse e
/// ignorasse o resultado passaria no caso anterior inteiro — e o primeiro
/// disco com um bit trocado viraria um sistema de arquivos com estruturas
/// inventadas, que é o pior desfecho possível para um erro de mídia.
///
/// Também confere que a magia é conferida antes: sem ela, um bloco de zeros
/// seria lido como um sistema de arquivos com todos os campos zerados.
fn btrfs_recusa_superbloco_adulterado() -> Resultado {
    let tabela = crate::particoes::varrer()?;
    let particao = tabela
        .primeira(crate::particoes::Tipo::Dados)
        .ok_or("nao ha particao de dados")?;

    let mut bloco = alloc::vec![0u8; 4096];
    crate::vfs::btrfs::do_disco(particao.primeiro, &mut bloco)?;

    // Um bit trocado bem no fim do bloco, longe de qualquer campo que o
    // leitor consulte: só a soma pode perceber.
    let ultimo = bloco.len() - 1;
    bloco[ultimo] ^= 1;
    if crate::vfs::btrfs::ler_superbloco(&bloco).is_ok() {
        return Err("um byte trocado no fim do bloco passou pela soma");
    }
    bloco[ultimo] ^= 1;

    // E com o bloco de volta ao que era, ele volta a ser aceito. Sem esta
    // metade, um leitor que recusasse tudo passaria na primeira.
    crate::vfs::btrfs::ler_superbloco(&bloco)?;

    // A magia vem antes da soma: um bloco de zeros não é um superbloco.
    let zeros = alloc::vec![0u8; 4096];
    if crate::vfs::btrfs::ler_superbloco(&zeros).is_ok() {
        return Err("um bloco de zeros passou por superbloco");
    }

    Ok(())
}

/// A tradução de endereço lógico para deslocamento no disco.
///
/// # Por que este caso não pode ser feito contra o disco
///
/// Porque na imagem que o `xtask` monta o deslocamento da primeira faixa de
/// cada pedaço é **igual** ao endereço lógico dele — não é regra do formato,
/// é como o `mkfs.btrfs` dispôs um disco recém-criado. Uma tradução que
/// devolvesse o endereço sem traduzir funcionaria em tudo que o kernel lê
/// hoje, e passaria em qualquer caso que só lesse o disco.
///
/// Então os pedaços daqui são montados à mão, em endereços que não
/// coincidem, e com uma lacuna entre eles: é onde a busca precisa dizer que
/// não sabe, em vez de casar com o vizinho.
fn btrfs_traduz_endereco_logico() -> Resultado {
    use crate::vfs::btrfs::pedacos::{Mapa, Pedaco};

    let mut mapa = Mapa::vazio();
    mapa.acrescentar(Pedaco {
        logico: 0x1000_0000,
        tamanho: 0x10_0000,
        fisico: 0x400_0000,
        tipo: 0,
        faixas: 1,
    })?;
    // O segundo começa bem depois do fim do primeiro: entre os dois há uma
    // faixa de endereços que não pertence a pedaço nenhum.
    mapa.acrescentar(Pedaco {
        logico: 0x3000_0000,
        tamanho: 0x2_0000,
        fisico: 0x100_0000,
        tipo: 0,
        faixas: 2,
    })?;

    // O primeiro byte, um do meio e o último de cada pedaço.
    let esperados = [
        (0x1000_0000u64, 0x400_0000u64),
        (0x1000_0001, 0x400_0001),
        (0x1008_0000, 0x408_0000),
        (0x100F_FFFF, 0x40F_FFFF),
        (0x3000_0000, 0x100_0000),
        (0x3001_FFFF, 0x101_FFFF),
    ];
    for (logico, fisico) in esperados {
        match mapa.traduzir(logico) {
            Some(achado) if achado == fisico => {}
            Some(achado) => {
                crate::log_error!("teste", "{:#x} traduziu para {:#x}", logico, achado);
                return Err("a traducao levou ao deslocamento errado");
            }
            None => return Err("um endereco dentro de um pedaco nao traduziu"),
        }
    }

    // E o que está fora: antes do primeiro, na lacuna, e um byte depois do
    // fim de cada um. O último é o que um `<=` no lugar de `<` deixaria
    // passar, traduzindo para o byte seguinte ao pedaço.
    for fora in [
        0x0FFF_FFFFu64,
        0x1010_0000,
        0x2000_0000,
        0x3002_0000,
        u64::MAX,
    ] {
        if let Some(achado) = mapa.traduzir(fora) {
            crate::log_error!("teste", "{:#x} traduziu para {:#x}", fora, achado);
            return Err("um endereco fora de qualquer pedaco traduziu");
        }
    }

    Ok(())
}

/// Um pedaço com perfil de paridade ou intercalado é recusado por nome.
///
/// # O que este caso protege
///
/// A honestidade do leitor sobre o que ele sabe fazer. Num `RAID0` ou num
/// `RAID10` cada faixa guarda um **pedaço diferente** do dado, e montar o
/// bloco exige intercalar; ler a primeira faixa como se fosse tudo devolve
/// bytes reais, de lugares errados. A soma de verificação acusaria, e a
/// mensagem seria "corrompido" para um disco íntegro que este leitor apenas
/// não sabe ler.
fn btrfs_recusa_perfil_desconhecido() -> Resultado {
    // Um item de pedaço com uma faixa: 48 bytes de cabeçalho e 32 de faixa.
    fn item(tipo: u64) -> [u8; 80] {
        let mut bytes = [0u8; 80];
        bytes[0..8].copy_from_slice(&0x10_0000u64.to_le_bytes()); // tamanho
        bytes[24..32].copy_from_slice(&tipo.to_le_bytes());
        bytes[44..46].copy_from_slice(&1u16.to_le_bytes()); // uma faixa
        bytes[56..64].copy_from_slice(&0x20_0000u64.to_le_bytes()); // deslocamento
        bytes
    }

    // `single` e `DUP` passam: as faixas são cópias inteiras.
    for tipo in [0x1u64, 0x2 | 0x20, 0x4 | 0x10] {
        if crate::vfs::btrfs::pedacos::ler_item(0x1000, &item(tipo)).is_err() {
            crate::log_error!("teste", "o perfil {:#x} foi recusado", tipo);
            return Err("um perfil de copia inteira foi recusado");
        }
    }

    // RAID0, RAID10, RAID5 e RAID6 não.
    for tipo in [0x1u64 | 0x8, 0x4 | 0x40, 0x1 | 0x80, 0x1 | 0x100] {
        if crate::vfs::btrfs::pedacos::ler_item(0x1000, &item(tipo)).is_ok() {
            crate::log_error!("teste", "o perfil {:#x} passou", tipo);
            return Err("um perfil que o leitor nao sabe montar foi aceito");
        }
    }

    // E um pedaço sem faixa nenhuma, que faria a leitura do deslocamento
    // apontar para o nada.
    let mut sem_faixa = item(0x1);
    sem_faixa[44..46].copy_from_slice(&0u16.to_le_bytes());
    if crate::vfs::btrfs::pedacos::ler_item(0x1000, &sem_faixa).is_ok() {
        return Err("um pedaco sem faixas foi aceito");
    }

    Ok(())
}

/// A raiz da árvore de pedaços é alcançada pelo endereço lógico dela.
///
/// # O que este caso fecha
///
/// A circularidade do formato. O endereço da árvore que traduz endereços vem
/// do superbloco em forma lógica; o que permite lê-lo é o vetor de pedaços
/// que o próprio superbloco carrega. Um nó que volta com a soma certa **e**
/// afirmando o endereço que pedimos é as duas coisas funcionando.
///
/// O endereço errado no fim é o que separa "a soma confere" de "é o nó
/// certo": um nó lido de outro lugar tem soma válida, porque é um nó de
/// verdade — só que outro.
fn btrfs_le_a_raiz_dos_pedacos() -> Resultado {
    let tabela = crate::particoes::varrer()?;
    let particao = tabela
        .primeira(crate::particoes::Tipo::Dados)
        .ok_or("nao ha particao de dados")?;
    let volume = crate::vfs::btrfs::Volume::abrir(particao.primeiro)?;

    if volume.mapa.quantos() == 0 {
        return Err("o vetor do superbloco nao deu pedaco nenhum");
    }

    let mut bloco = alloc::vec![0u8; volume.superbloco.tamanho_de_no as usize];
    let cabecalho = volume.ler_no(volume.superbloco.raiz_dos_pedacos, &mut bloco)?;

    if cabecalho.endereco != volume.superbloco.raiz_dos_pedacos {
        return Err("o no lido nao e o endereco pedido");
    }
    // Dono 3 é a árvore de pedaços. Ler a árvore certa e não outra é o que
    // este número diz.
    if cabecalho.dono != 3 {
        crate::log_error!("teste", "o no pertence a arvore {}", cabecalho.dono);
        return Err("a raiz dos pedacos pertence a outra arvore");
    }
    if cabecalho.itens == 0 {
        return Err("a raiz dos pedacos veio sem itens");
    }

    // Um endereço um nó adiante: traduzível, e não é um nó. A soma recusa.
    let adiante = volume.superbloco.raiz_dos_pedacos + u64::from(volume.superbloco.tamanho_de_no);
    if volume.ler_no(adiante, &mut bloco).is_ok() {
        return Err("um endereco que nao e o do no foi aceito");
    }

    // E o caso que a soma **não** pega: um mapa que traduz um endereço
    // lógico qualquer para o lugar onde um nó de verdade mora. O bloco que
    // volta tem soma correta, porque é um nó; o que não bate é o endereço que
    // ele afirma ocupar.
    //
    // Esta metade existe porque a primeira não estava exercitando nada:
    // desligando a conferência de endereço, o caso continuava passando, já
    // que o `adiante` era recusado pela soma de qualquer forma.
    //
    // É a diferença entre "li um nó" e "li o nó certo", e ela é o que pega
    // uma tradução errada — que é justamente o defeito silencioso deste
    // formato, onde todo endereço é indireto.
    const LOGICO_INVENTADO: u64 = 0x9000_0000;
    let mut enganoso = crate::vfs::btrfs::pedacos::Mapa::vazio();
    enganoso.acrescentar(crate::vfs::btrfs::pedacos::Pedaco {
        logico: LOGICO_INVENTADO,
        tamanho: 0x10_0000,
        fisico: volume.superbloco.raiz_dos_pedacos,
        tipo: 0,
        faixas: 1,
    })?;

    let mut volume = volume;
    volume.mapa = enganoso;
    match volume.ler_no(LOGICO_INVENTADO, &mut bloco) {
        Ok(cabecalho) => {
            crate::log_error!(
                "teste",
                "o no em {:#x} foi aceito como sendo de {:#x}",
                cabecalho.endereco,
                LOGICO_INVENTADO
            );
            Err("um no valido foi aceito para o endereco errado")
        }
        Err(_) => Ok(()),
    }
}

/// Os itens de uma folha são lidos com a chave e os dados certos.
///
/// # O que este caso protege
///
/// A aritmética de deslocamento dentro do nó. Os dados de um item começam a
/// partir do **fim do cabeçalho**, e não do começo do nó — somar errado dá um
/// item que existe, do tamanho certo, com bytes de outro. Nada falha, e o que
/// se lê depois é um pedaço, uma raiz ou um nome montado a partir de lixo.
///
/// A folha usada é a da árvore de pedaços, cujos quatro itens têm chave e
/// tamanho conhecidos do lado de fora: o `dump-tree` imprime `itemoff` e
/// `itemsize` de cada um.
fn btrfs_percorre_itens_da_folha() -> Resultado {
    let tabela = crate::particoes::varrer()?;
    let particao = tabela
        .primeira(crate::particoes::Tipo::Dados)
        .ok_or("nao ha particao de dados")?;
    let volume = crate::vfs::btrfs::Volume::abrir(particao.primeiro)?;

    let mut bloco = alloc::vec![0u8; volume.superbloco.tamanho_de_no as usize];
    volume.ler_no(volume.superbloco.raiz_dos_pedacos, &mut bloco)?;

    let mut quantos = 0;
    let mut pedacos = 0;
    for item in crate::vfs::btrfs::folha::itens(&bloco)? {
        let item = item?;
        quantos += 1;

        // Todo item precisa ter vindo de dentro do nó. A iteração já recusa o
        // que aponta para fora; isto confere que ela não devolveu uma fatia
        // vazia no lugar.
        if item.dados.is_empty() {
            return Err("um item veio sem dados");
        }
        if item.chave.tipo == crate::vfs::btrfs::folha::tipo::PEDACO {
            pedacos += 1;
            // O `offset` da chave de um pedaço é o endereço lógico dele, e
            // todos os três precisam estar no mapa depois da abertura.
            if volume.mapa.traduzir(item.chave.offset).is_none() {
                crate::log_error!(
                    "teste",
                    "o pedaco em {:#x} nao esta no mapa",
                    item.chave.offset
                );
                return Err("um pedaco da arvore nao entrou no mapa");
            }
        }
    }

    if quantos != 4 {
        crate::log_error!("teste", "a folha deu {} itens", quantos);
        return Err("a folha de pedacos nao tem os quatro itens que o disco traz");
    }
    if pedacos != 3 {
        return Err("a folha de pedacos nao trouxe os tres pedacos");
    }

    // E um nó interno não é folha. Forjar o nível no bloco já lido é o
    // caminho mais curto para o caso: os descritores de um nó interno têm
    // outro tamanho, e lê-los como itens daria fatias montadas a partir de
    // ponteiros.
    bloco[100] = 1;
    if crate::vfs::btrfs::folha::itens(&bloco).is_ok() {
        return Err("um no interno foi percorrido como folha");
    }
    bloco[100] = 0;

    // Um item que aponta para fora do nó precisa ser recusado na hora, e não
    // devolver bytes de memória vizinha.
    const PRIMEIRO_DESCRITOR: usize = 101;
    bloco[PRIMEIRO_DESCRITOR + 17..PRIMEIRO_DESCRITOR + 21]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    let recusou = crate::vfs::btrfs::folha::itens(&bloco)?.any(|i| i.is_err());
    if !recusou {
        return Err("um item apontando para fora do no foi aceito");
    }

    Ok(())
}

/// A árvore de arquivos tem mais de um nível, e a descida chega a todas as
/// folhas.
///
/// # Por que a primeira metade é a mais importante
///
/// Porque todos os outros casos do Btrfs continuariam passando se a árvore
/// voltasse a caber numa folha — e passariam **sem exercitar nada** do
/// código de descida. A imagem é montada de propósito com nós de quatro
/// kilobytes e arquivos de enchimento para que ela tenha níveis; se um dia
/// alguém mudar isso, é aqui que aparece, e com uma mensagem que diz o que
/// mudar de volta.
///
/// # O que a segunda metade prova
///
/// Que o percurso atravessa folhas, e ele conta **folhas**, não itens.
/// Contar itens não serviria: quantos cabem numa folha depende do tamanho
/// de cada um, e o teto teórico — cento e cinquenta e nove, num nó de
/// quatro kilobytes com descritores de vinte e cinco bytes e nenhum dado —
/// é folgado o bastante para que um percurso parado na primeira folha
/// passasse.
///
/// As chaves também precisam sair em ordem estritamente crescente. É o que
/// pega os dois erros de travessia que não dão erro nenhum: repetir uma
/// folha — que o percurso faria se a chave procurada não avançasse — e
/// pular para trás.
fn btrfs_desce_pela_arvore_de_arquivos() -> Resultado {
    let tabela = crate::particoes::varrer()?;
    let particao = tabela
        .primeira(crate::particoes::Tipo::Dados)
        .ok_or("nao ha particao de dados")?;
    let volume = crate::vfs::btrfs::Volume::abrir(particao.primeiro)?;
    let (raiz, _) = volume.raiz_dos_arquivos()?;

    let nivel = volume.nivel_da_arvore(raiz)?;
    if nivel == 0 {
        return Err("a arvore de arquivos cabe numa folha; a descida nao e exercitada");
    }

    let mut quantos = 0usize;
    let mut anterior: Option<crate::vfs::btrfs::folha::Chave> = None;
    let mut fora_de_ordem = 0usize;

    let folhas = volume.percorrer(
        raiz,
        crate::vfs::btrfs::folha::Chave {
            objeto: 0,
            tipo: 0,
            offset: 0,
        },
        |item| {
            if let Some(anterior) = anterior
                && item.chave <= anterior
            {
                fora_de_ordem += 1;
            }
            anterior = Some(item.chave);
            quantos += 1;
            crate::vfs::btrfs::Passo::Segue
        },
    )?;

    crate::log_info!(
        "teste",
        "arvore de arquivos: nivel {}, {} folhas, {} itens",
        nivel,
        folhas,
        quantos
    );

    if fora_de_ordem > 0 {
        return Err("o percurso devolveu chaves fora de ordem: folha repetida ou pulada");
    }
    if folhas < 2 {
        return Err("o percurso parou na primeira folha");
    }

    // E o percurso precisa ter visto a árvore inteira, e não só as duas
    // primeiras folhas: o número de itens é o que o `btrfs inspect-internal
    // dump-tree` conta do lado de fora, somado sobre todas as folhas.
    if quantos < 60 {
        crate::log_error!("teste", "{} itens em {} folhas", quantos, folhas);
        return Err("o percurso trouxe itens de menos para esta imagem");
    }
    Ok(())
}

/// A descida acha um inode que **não** está na primeira folha.
///
/// # O caso que o leitor de uma folha só reprovava
///
/// Abrir um arquivo exige dois itens: o `DIR_ITEM` que liga o nome ao número
/// do inode, e o `INODE_ITEM` daquele número. Eles são ordenados por coisas
/// diferentes — o primeiro pelo resumo do nome, o segundo pelo número — e
/// numa árvore com níveis eles caem em folhas diferentes.
///
/// Este caso escolhe o arquivo pelo caminho mais direto possível: pergunta
/// ao VFS, que é quem o userspace usa. O que ele confere a mais é **onde** o
/// inode mora: se ele estiver na mesma folha que a raiz da árvore, o caso
/// não estaria provando a travessia, e diz isso em vez de passar.
fn btrfs_acha_inode_fora_da_primeira_folha() -> Resultado {
    let tabela = crate::particoes::varrer()?;
    let particao = tabela
        .primeira(crate::particoes::Tipo::Dados)
        .ok_or("nao ha particao de dados")?;
    let volume = crate::vfs::btrfs::Volume::abrir(particao.primeiro)?;
    let (raiz, diretorio) = volume.raiz_dos_arquivos()?;

    let achada = crate::vfs::btrfs::arvore::procurar(&volume, raiz, diretorio, "grande.txt")?
        .ok_or("grande.txt nao foi achado na raiz")?;

    // A primeira folha da árvore é onde uma leitura sem descida pararia.
    let mut primeira = alloc::vec![0u8; volume.superbloco.tamanho_de_no as usize];
    volume.ler_no(raiz, &mut primeira)?;
    let na_primeira = crate::vfs::btrfs::folha::itens(&primeira)
        .map(|itens| {
            itens.flatten().any(|i| {
                i.chave.objeto == achada.objeto
                    && i.chave.tipo == crate::vfs::btrfs::arvore::tipo::INODE
            })
        })
        .unwrap_or(false);
    if na_primeira {
        return Err("o inode esta no no de topo; o caso nao prova a travessia");
    }

    let item = volume
        .achar(raiz, achada.objeto, crate::vfs::btrfs::arvore::tipo::INODE)?
        .ok_or("o inode de grande.txt nao foi achado")?;
    let inode = crate::vfs::btrfs::arvore::ler_inode(&item).ok_or("inode truncado")?;

    if inode.especie != crate::vfs::btrfs::arvore::Especie::Arquivo {
        return Err("o inode achado nao e de um arquivo");
    }
    if inode.tamanho != TAMANHO_DO_GRANDE as u64 {
        crate::log_error!("teste", "o inode diz {} bytes", inode.tamanho);
        return Err("o inode achado nao e o de grande.txt");
    }
    Ok(())
}

/// A escolha do filho, num nó interno, é a última chave menor ou igual.
///
/// # Por que um nó forjado, e não o do disco
///
/// Porque o erro que este caso existe para pegar é de **um índice**, e ele
/// não aparece com dados reais: escolher o filho seguinte devolve uma folha
/// cujas chaves começam depois do alvo, e o sintoma é "este arquivo não
/// existe" — indistinguível de um arquivo que realmente não existe.
///
/// Com um nó montado à mão, a resposta certa de cada pergunta é sabida, e
/// as três que importam são as bordas: antes da primeira chave, exatamente
/// numa chave, e depois da última.
fn btrfs_descida_escolhe_o_filho_certo() -> Resultado {
    use crate::vfs::btrfs::folha::Chave;
    use crate::vfs::btrfs::interno::descer_para;

    const CABECALHO: usize = 101;
    const PONTEIRO: usize = 33;

    // Um nó interno de nível 1 com três ponteiros, nas chaves 10, 20 e 30.
    let mut no = alloc::vec![0u8; 4096];
    no[100] = 1;
    no[96..100].copy_from_slice(&3u32.to_le_bytes());
    for (i, (objeto, bloco)) in [(10u64, 0xAAAAu64), (20, 0xBBBB), (30, 0xCCCC)]
        .into_iter()
        .enumerate()
    {
        let base = CABECALHO + i * PONTEIRO;
        no[base..base + 8].copy_from_slice(&objeto.to_le_bytes());
        no[base + 17..base + 25].copy_from_slice(&bloco.to_le_bytes());
    }

    let alvo = |objeto: u64| Chave {
        objeto,
        tipo: 0,
        offset: 0,
    };

    for (objeto, esperado, porque) in [
        // Antes de tudo: desce pelo primeiro, que é onde as menores chaves
        // moram. Descer pelo último devolveria a folha errada e "não existe".
        (5u64, 0xAAAAu64, "antes da primeira chave"),
        (10, 0xAAAA, "exatamente na primeira"),
        // No meio de duas: vai para a de baixo. Ir para a de cima é o erro
        // de um índice, e é o que este caso existe para pegar.
        (15, 0xAAAA, "entre a primeira e a segunda"),
        (20, 0xBBBB, "exatamente na segunda"),
        (29, 0xBBBB, "logo antes da terceira"),
        (30, 0xCCCC, "exatamente na terceira"),
        (u64::MAX, 0xCCCC, "depois de todas"),
    ] {
        let escolhido = descer_para(&no, alvo(objeto))?;
        if escolhido != esperado {
            crate::log_error!(
                "teste",
                "{}: alvo {} desceu por {:#x}, esperava {:#x}",
                porque,
                objeto,
                escolhido,
                esperado
            );
            return Err("a descida escolheu o filho errado");
        }
    }

    // Uma folha não tem por onde descer, e tratá-la como nó interno leria
    // descritores de 25 bytes como ponteiros de 33.
    no[100] = 0;
    if descer_para(&no, alvo(15)).is_ok() {
        return Err("uma folha foi tratada como no interno");
    }

    // E um nó que diz ter mais ponteiros do que cabem nele precisa ser
    // recusado **antes** da busca: no meio de uma busca binária o índice
    // lido nem é previsível.
    no[100] = 1;
    no[96..100].copy_from_slice(&u32::MAX.to_le_bytes());
    if descer_para(&no, alvo(15)).is_ok() {
        return Err("um no com ponteiros demais foi aceito");
    }
    Ok(())
}

/// Um percurso que começa numa chave que não existe entrega a primeira que
/// existe depois dela — inclusive quando ela está na folha seguinte.
///
/// # O defeito que este caso pega
///
/// A descida procura "o último ponteiro cuja chave é menor ou igual ao
/// alvo". Quando o alvo cai no vão **entre** duas folhas, isso aterrissa na
/// da esquerda, cujas chaves são todas menores que ele. O percurso lia a
/// última chave da folha, via que ela não alcançava o alvo, e concluía que
/// a árvore tinha acabado — sem visitar a folha da direita, onde estava tudo
/// o que vinha depois.
///
/// Ficou escondido enquanto nenhum percurso começou num vão entre folhas.
/// Apareceu com o terceiro programa compilado no disco: os itens de
/// `/programas/x86_64` passaram a atravessar uma fronteira de folha, e o
/// diretório listava um arquivo só dos três — `/programas/x86_64/ola` dava
/// "não encontrado", com o arquivo lá.
///
/// # Por que todos os vãos, e não o do diretório
///
/// Porque onde as folhas se dividem depende de tudo que está no disco, e um
/// caso preso a um diretório passaria no dia em que o diretório mudasse de
/// folha. Aqui a árvore de arquivos inteira é lida em ordem, e para cada par
/// de chaves consecutivas com um vão entre elas o percurso recomeça dentro
/// do vão e tem de entregar a segunda. Os vãos entre folhas estão entre eles
/// sempre que a árvore tiver mais de uma folha — e ela tem, por causa do
/// enchimento da raiz.
fn btrfs_percurso_atravessa_o_vao_entre_folhas() -> Resultado {
    use crate::vfs::btrfs::Passo;
    use crate::vfs::btrfs::folha::Chave;

    let tabela = crate::particoes::varrer()?;
    let particao = tabela
        .primeira(crate::particoes::Tipo::Dados)
        .ok_or("nao ha particao de dados")?;
    let volume = crate::vfs::btrfs::Volume::abrir(particao.primeiro)?;
    let (raiz, _) = volume.raiz_dos_arquivos()?;

    // A referência: todas as chaves, lidas pela **estrutura** — nó a nó,
    // filho a filho, da esquerda para a direita —, sem passar pela descida
    // nem pelo percurso. A primeira versão deste caso tomava a referência do
    // próprio percurso, começado da chave zero; com o defeito, esse percurso
    // também parava na primeira fronteira com vão, a referência saía com 71
    // das chaves, e o caso passava conferindo só o pedaço que o defeito
    // deixava ver.
    let mut chaves: alloc::vec::Vec<Chave> = alloc::vec::Vec::new();
    let mut folhas = 0usize;
    let mut pendentes: alloc::vec::Vec<u64> = alloc::vec![raiz];
    let mut no = alloc::vec![0u8; volume.superbloco.tamanho_de_no as usize];
    while let Some(endereco) = pendentes.pop() {
        let cabecalho = volume.ler_no(endereco, &mut no)?;
        if cabecalho.nivel == 0 {
            folhas += 1;
            for item in crate::vfs::btrfs::folha::itens(&no)? {
                chaves.push(item?.chave);
            }
        } else {
            // Empilhados ao contrário, para o da esquerda sair primeiro.
            let filhos = crate::vfs::btrfs::interno::ponteiros(&no)?;
            pendentes.extend(filhos.iter().rev().map(|&(_, filho)| filho));
        }
    }
    if folhas < 2 {
        return Err("a arvore de arquivos tem uma folha so; nao ha vao entre folhas para conferir");
    }
    if chaves.windows(2).any(|par| par[0] >= par[1]) {
        return Err("as folhas lidas pela estrutura nao estao em ordem estrita");
    }

    // O percurso completo, da chave zero, tem de entregar exatamente as
    // mesmas.
    let mut percorridas: alloc::vec::Vec<Chave> = alloc::vec::Vec::new();
    volume.percorrer(
        raiz,
        Chave {
            objeto: 0,
            tipo: 0,
            offset: 0,
        },
        |item| {
            percorridas.push(item.chave);
            Passo::Segue
        },
    )?;
    if percorridas != chaves {
        crate::log_error!(
            "teste",
            "o percurso entregou {} chaves; a arvore tem {}",
            percorridas.len(),
            chaves.len()
        );
        return Err("o percurso completo nao entregou todas as chaves da arvore");
    }

    let mut vaos = 0;
    for par in chaves.windows(2) {
        let Some(no_vao) = par[0].sucessora() else {
            continue;
        };
        if no_vao == par[1] {
            continue;
        }
        vaos += 1;
        let mut primeira = None;
        volume.percorrer(raiz, no_vao, |item| {
            primeira = Some(item.chave);
            Passo::Para
        })?;
        if primeira != Some(par[1]) {
            crate::log_error!(
                "teste",
                "do vao depois de {:?}, o percurso deu {:?}, e nao {:?}",
                par[0],
                primeira,
                par[1]
            );
            return Err("um percurso comecado num vao nao entregou a chave seguinte");
        }
    }
    crate::log_info!(
        "teste",
        "{} chaves em {} folhas, {} vaos conferidos",
        chaves.len(),
        folhas,
        vaos
    );
    Ok(())
}

/// A sucessora de uma chave é a menor estritamente maior que ela.
///
/// # Por que isto não é aritmética óbvia
///
/// Porque a chave tem três campos com pesos diferentes, e somar um ao último
/// funciona em todo caso menos nos dois que importam: quando ele satura. É
/// exatamente nesses dois que um percurso pararia cedo, deixando de fora
/// itens que existem — sem erro, sem log, com um diretório que perdeu
/// entradas.
fn btrfs_sucessora_de_chave() -> Resultado {
    use crate::vfs::btrfs::folha::Chave;

    let casos = [
        (
            Chave {
                objeto: 7,
                tipo: 3,
                offset: 1,
            },
            Some(Chave {
                objeto: 7,
                tipo: 3,
                offset: 2,
            }),
        ),
        // O deslocamento satura: sobe para o tipo seguinte, e o deslocamento
        // volta a zero. Somar um e deixar transbordar daria (7, 3, 0), que é
        // **menor** que a chave de partida — o percurso voltaria ao começo.
        (
            Chave {
                objeto: 7,
                tipo: 3,
                offset: u64::MAX,
            },
            Some(Chave {
                objeto: 7,
                tipo: 4,
                offset: 0,
            }),
        ),
        // O tipo também satura: sobe para o objeto seguinte.
        (
            Chave {
                objeto: 7,
                tipo: u8::MAX,
                offset: u64::MAX,
            },
            Some(Chave {
                objeto: 8,
                tipo: 0,
                offset: 0,
            }),
        ),
        // E no topo absoluto não há sucessora. Dar a volta para zero faria o
        // percurso recomeçar do começo e nunca terminar.
        (
            Chave {
                objeto: u64::MAX,
                tipo: u8::MAX,
                offset: u64::MAX,
            },
            None,
        ),
    ];

    for (chave, esperada) in casos {
        let obtida = chave.sucessora();
        if obtida != esperada {
            crate::log_error!(
                "teste",
                "{:?} -> {:?}, esperava {:?}",
                chave,
                obtida,
                esperada
            );
            return Err("a sucessora de uma chave saiu errada");
        }
        if let Some(obtida) = obtida
            && obtida <= chave
        {
            return Err("a sucessora nao e maior que a chave");
        }
    }
    Ok(())
}

/// Depois de aberto, o volume traduz endereços de metadados.
///
/// # Por que isto vale mais que o caso anterior de tradução
///
/// Porque aqui a tradução **não** é identidade. No vetor que o superbloco
/// carrega, o pedaço de sistema começa no mesmo endereço lógico e físico — e
/// foi por isso que o caso da etapa anterior precisou de pedaços sintéticos
/// para provar alguma coisa.
///
/// O pedaço de metadados, que só aparece depois de a árvore de pedaços ser
/// lida, é lógico 30408704 e físico 38797312. Como as outras árvores moram
/// nele, ler qualquer uma passa a exigir a aritmética de verdade — e uma
/// tradução por identidade devolve um bloco que não é nó nenhum.
fn btrfs_mapa_completo_alcanca_metadados() -> Resultado {
    let tabela = crate::particoes::varrer()?;
    let particao = tabela
        .primeira(crate::particoes::Tipo::Dados)
        .ok_or("nao ha particao de dados")?;
    let volume = crate::vfs::btrfs::Volume::abrir(particao.primeiro)?;

    if volume.mapa.quantos() != 3 {
        crate::log_error!(
            "teste",
            "o mapa ficou com {} pedacos",
            volume.mapa.quantos()
        );
        return Err("o mapa completo nao tem os tres pedacos do disco");
    }

    let mut bloco = alloc::vec![0u8; volume.superbloco.tamanho_de_no as usize];
    let cabecalho = volume.ler_no(volume.superbloco.raiz, &mut bloco)?;

    // Dono 1 é a árvore de raízes. É o número que distingue "li um nó" de
    // "li a árvore que o superbloco apontou".
    if cabecalho.dono != 1 {
        crate::log_error!("teste", "o no pertence a arvore {}", cabecalho.dono);
        return Err("a raiz do superbloco nao e a arvore de raizes");
    }
    if cabecalho.itens == 0 {
        return Err("a arvore de raizes veio sem itens");
    }

    // E ela traz raízes de outras árvores, cada uma com um endereço que o
    // mapa sabe traduzir.
    let mut raizes = 0;
    for item in crate::vfs::btrfs::folha::itens(&bloco)? {
        let item = item?;
        if item.chave.tipo != crate::vfs::btrfs::folha::tipo::RAIZ {
            continue;
        }
        let endereco =
            crate::vfs::btrfs::raiz_da_arvore(item.dados).ok_or("item de raiz truncado")?;
        if endereco == 0 {
            return Err("uma raiz aponta para o endereco zero");
        }
        if volume.mapa.traduzir(endereco).is_none() {
            return Err("uma raiz aponta para fora de qualquer pedaco");
        }
        raizes += 1;
    }

    if raizes == 0 {
        return Err("a arvore de raizes nao trouxe raiz nenhuma");
    }

    Ok(())
}

/// O que o `xtask` escreveu nos arquivos do disco.
///
/// Metade de um contrato cujo outro lado está em `xtask/src/main.rs`, como o
/// padrão por setor — e pela mesma razão: os dois lados rodam em máquinas
/// diferentes e não há lugar comum onde caibam. O que impede a divergência
/// são estes casos.
const NO_SAUDACAO: &str = "ola do btrfs, lido pelo duke\n";
const NO_SUBDIRETORIO: &str = "uma nota num subdiretorio\n";
const TAMANHO_DO_GRANDE: usize = 48 * 1024;

/// O byte que deve estar na posição `i` do arquivo grande.
///
/// A outra metade desta regra está no `xtask`, e o comentário de lá explica
/// por que ela não é uma palavra repetida: com `duke` repetido, um pedaço
/// lido do lugar errado vinha **idêntico** ao certo, e a conferência byte a
/// byte aprovava uma leitura que tinha ido buscar em 0 o que estava em 16 Ki.
fn marca_do_grande(i: usize) -> u8 {
    ((i / 256) as u8).wrapping_add((i as u8).wrapping_mul(7))
}

/// A raiz do disco está montada, e listá-la traz o que o disco tem.
///
/// # O que este caso protege
///
/// A composição inteira, do setor ao nome: a GPT achou a partição, o
/// superbloco passou na soma, o mapa traduziu, a folha foi percorrida, os
/// itens de diretório foram lidos e o VFS montou. Qualquer uma dessas
/// falhando dá a mesma lista vazia.
///
/// E a precedência das montagens, em produção: `/bin` continua vindo dos
/// programas embutidos mesmo com a raiz montada por cima, porque a montagem
/// mais longa ganha. É a regra que o caso sintético do VFS prova em
/// isolamento, aqui exercitada no arranjo de verdade.
fn btrfs_raiz_montada() -> Resultado {
    use crate::vfs::Tipo;

    /// Lista um diretório e devolve os nomes com os tipos, em ordem de
    /// chegada.
    fn conteudo(
        caminho: &str,
    ) -> Result<alloc::vec::Vec<(alloc::string::String, Tipo)>, &'static str> {
        let mut visto = alloc::vec::Vec::new();
        crate::vfs::listar(caminho, |entrada| {
            visto.push((entrada.nome.clone(), entrada.tipo));
        })
        .map_err(|e| e.motivo())?;
        visto.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(visto)
    }

    // A lista é conferida **inteira**, e não por presença. A primeira versão
    // deste caso perguntava "veio `saudacao.txt`?" e três perguntas iguais,
    // e passava com uma listagem que trouxesse também o que mora em outro
    // diretório: apagar o filtro por diretório do `arvore::listar` fazia a
    // raiz mostrar `nota.txt`, que está dentro de `dados`, e nenhuma das
    // perguntas reclamava. Um diretório é o conjunto do que está nele.
    // Os arquivos de enchimento entram na conta: eles existem para dar
    // níveis à árvore, e a raiz é justamente onde eles estão. Conferir a
    // lista inteira **com** eles é o que mantém o caso sendo sobre o
    // conjunto, e não sobre uma amostra — e o que faz a listagem provar que
    // a travessia de folhas traz tudo, porque as entradas da raiz já não
    // cabem onde cabiam.
    const ENCHIMENTO: usize = 24;

    let raiz = conteudo("/")?;
    let nomeados: &[(&str, Tipo)] = &[
        ("dados", Tipo::Diretorio),
        ("grande.txt", Tipo::Arquivo),
        // Os programas compilados à parte, um diretório por arquitetura —
        // ver `usuario::DIRETORIO_DOS_COMPILADOS`.
        ("programas", Tipo::Diretorio),
        ("saudacao.txt", Tipo::Arquivo),
    ];

    let mut esperado: alloc::vec::Vec<(alloc::string::String, Tipo)> = nomeados
        .iter()
        .map(|(nome, tipo)| ((*nome).into(), *tipo))
        .collect();
    for i in 1..=ENCHIMENTO {
        esperado.push((alloc::format!("enche-{i}.txt"), Tipo::Arquivo));
    }
    esperado.sort_by(|a, b| a.0.cmp(&b.0));

    if raiz != esperado {
        crate::log_error!("teste", "a raiz listou {} entradas: {:?}", raiz.len(), raiz);
        return Err("a raiz montada nao lista exatamente o que o xtask pos nela");
    }

    // E o subdiretório tem o que é dele, e só.
    let dados = conteudo("/dados")?;
    if dados.len() != 1 || dados[0].0 != "nota.txt" || dados[0].1 != Tipo::Arquivo {
        crate::log_error!("teste", "/dados listou {:?}", dados);
        return Err("o subdiretorio nao lista exatamente o que esta dentro dele");
    }

    // E `/programas` tem uma arquitetura por diretório, as duas, e nada mais:
    // o disco é o mesmo para as duas máquinas.
    let arquiteturas = conteudo("/programas")?;
    if arquiteturas.len() != 2
        || arquiteturas[0] != ("aarch64".into(), Tipo::Diretorio)
        || arquiteturas[1] != ("x86_64".into(), Tipo::Diretorio)
    {
        crate::log_error!("teste", "/programas listou {:?}", arquiteturas);
        return Err("/programas nao tem um diretorio por arquitetura");
    }

    // A busca por nome também respeita o diretório: o que está na raiz não é
    // alcançável de dentro de `dados`, nem o contrário. Sem isto, um leitor
    // que procurasse o nome na folha inteira acertaria todos os caminhos
    // certos e também os errados.
    if crate::vfs::resolver("/dados/saudacao.txt").is_ok() {
        return Err("um arquivo da raiz foi achado dentro do subdiretorio");
    }
    if crate::vfs::resolver("/nota.txt").is_ok() {
        return Err("um arquivo do subdiretorio foi achado na raiz");
    }

    // E `/bin` continua sendo dos programas embutidos.
    let mut programas = 0;
    crate::vfs::listar("/bin", |_| programas += 1).map_err(|e| e.motivo())?;
    if programas != crate::usuario::programa::quantos_embutidos() {
        crate::log_error!("teste", "/bin listou {} entradas", programas);
        return Err("a raiz montada por cima roubou /bin dos programas embutidos");
    }

    Ok(())
}

/// Os dois jeitos de um arquivo guardar conteúdo são lidos corretamente.
///
/// # Por que os dois no mesmo caso
///
/// Porque são caminhos de código inteiramente diferentes e é fácil ter só um.
/// Um arquivo pequeno mora **dentro** do item de extensão, e lê-lo é copiar
/// bytes que já vieram com a folha. Um grande mora num endereço lógico, e
/// lê-lo exige traduzir esse endereço e ir ao disco outra vez.
///
/// A imagem tinha só arquivos pequenos quando esta etapa começou — todos
/// embutidos. O `grande.txt` foi posto lá justamente para que o segundo
/// caminho existisse para ser exercitado, em vez de ficar escrito e nunca
/// percorrido.
fn btrfs_le_os_dois_tipos_de_arquivo() -> Resultado {
    // Embutido: vinte e nove bytes que vieram junto com a folha.
    let embutido = crate::vfs::ler_tudo("/saudacao.txt").map_err(|e| e.motivo())?;
    if embutido != NO_SAUDACAO.as_bytes() {
        crate::log_error!(
            "teste",
            "vieram {} bytes do arquivo embutido",
            embutido.len()
        );
        return Err("o arquivo embutido nao tem o conteudo que o xtask escreveu");
    }

    // Num subdiretório, que exige uma busca de nome dentro de outro
    // diretório em vez de na raiz.
    let no_subdiretorio = crate::vfs::ler_tudo("/dados/nota.txt").map_err(|e| e.motivo())?;
    if no_subdiretorio != NO_SUBDIRETORIO.as_bytes() {
        return Err("o arquivo do subdiretorio nao tem o conteudo esperado");
    }

    // Com extensão normal: quarenta e oito kilobytes, que exigem seguir um
    // endereço lógico, traduzi-lo e ir ao disco — três vezes, porque o driver
    // monta dezesseis kilobytes por ida e o `ler_tudo` chama em laço.
    let grande = crate::vfs::ler_tudo("/grande.txt").map_err(|e| e.motivo())?;
    if grande.len() != TAMANHO_DO_GRANDE {
        crate::log_error!("teste", "o arquivo grande veio com {} bytes", grande.len());
        return Err("o arquivo com extensao nao veio inteiro");
    }
    // O conteúdo é uma regra, e não uma tabela. Conferir todos os bytes é o
    // que pega uma volta do laço que trouxe o pedaço certo do lugar errado.
    if let Some(posicao) = (0..grande.len()).find(|i| grande[*i] != marca_do_grande(*i)) {
        crate::log_error!(
            "teste",
            "o byte {} e {:#04x}, esperava {:#04x}",
            posicao,
            grande[posicao],
            marca_do_grande(posicao)
        );
        return Err("o arquivo com extensao veio com bytes de outro lugar");
    }

    Ok(())
}

/// Cada forma de extensão é classificada pelo que ela é, e as duas que este
/// leitor não sabe ler são recusadas.
///
/// # Por que sintético
///
/// Porque a imagem só tem o que o `mkfs.btrfs` produz, e ele produz dois dos
/// cinco casos: embutida e normal. Esses dois o caso anterior já cobre lendo
/// o disco de verdade. Os outros três — buraco, comprimida e pré-alocada —
/// não aparecem em imagem nenhuma que este `xtask` saiba gerar, e o que está
/// escrito no código para eles seria texto: dava para apagar os três braços
/// e a suíte inteira continuava verde.
///
/// Um buraco é o mais perigoso dos três. O campo do endereço vem zero, e um
/// leitor que não notasse iria traduzir o endereço lógico zero e entregar os
/// bytes que morassem lá — o começo do próprio sistema de arquivos — como se
/// fossem o conteúdo do arquivo. Não é um erro que apareça: é conteúdo
/// plausível, de outro lugar.
///
/// Os deslocamentos abaixo são escritos à mão, e não vêm das constantes do
/// módulo, de propósito. Um teste que peça ao código onde os campos estão
/// concorda com qualquer resposta que o código der.
fn btrfs_classifica_cada_extensao() -> Resultado {
    use crate::vfs::btrfs::arvore::{Conteudo, ler_extensao};

    /// Um `btrfs_file_extent_item`: 21 bytes de cabeçalho e, depois deles, ou
    /// o conteúdo embutido ou os quatro campos de uma extensão normal.
    fn item(compressao: u8, tipo: u8) -> [u8; 53] {
        let mut bytes = [0u8; 53];
        bytes[8..16].copy_from_slice(&0x2000u64.to_le_bytes()); // ram_bytes
        bytes[16] = compressao;
        bytes[20] = tipo;
        bytes
    }

    // Embutida: o conteúdo começa logo depois do cabeçalho, e vai até o fim
    // do item. Um item de 53 bytes tem 32 de conteúdo.
    let embutida = item(0, 0);
    match ler_extensao(&embutida) {
        Ok(Conteudo::Embutido { em, quantos }) if em == 21 && quantos == 32 => {}
        outro => {
            crate::log_error!("teste", "a embutida saiu como {:?}", outro);
            return Err("uma extensao embutida nao foi lida como embutida");
        }
    }

    // Normal: o endereço do bloco mais o deslocamento dentro dele.
    let mut normal = item(0, 1);
    normal[21..29].copy_from_slice(&0x30_0000u64.to_le_bytes()); // disk_bytenr
    normal[37..45].copy_from_slice(&0x1000u64.to_le_bytes()); // offset
    normal[45..53].copy_from_slice(&0x2000u64.to_le_bytes()); // num_bytes
    match ler_extensao(&normal) {
        Ok(Conteudo::Normal { endereco, quantos })
            if endereco == 0x30_0000 + 0x1000 && quantos == 0x2000 => {}
        outro => {
            crate::log_error!("teste", "a normal saiu como {:?}", outro);
            return Err("uma extensao normal nao foi lida como normal");
        }
    }

    // Buraco: o mesmo item, com o endereço zerado.
    let mut buraco = normal;
    buraco[21..29].copy_from_slice(&0u64.to_le_bytes());
    match ler_extensao(&buraco) {
        Ok(Conteudo::Buraco { quantos: 0x2000 }) => {}
        outro => {
            crate::log_error!("teste", "o buraco saiu como {:?}", outro);
            return Err("um buraco foi lido como um endereco de verdade");
        }
    }

    // Comprimida: entregar os bytes comprimidos seria pior que recusar.
    for metodo in [1u8, 2, 3] {
        if ler_extensao(&item(metodo, 1)).is_ok() {
            crate::log_error!("teste", "a compressao {} passou", metodo);
            return Err("uma extensao comprimida foi aceita");
        }
    }

    // Pré-alocada: tem endereço e não tem conteúdo escrito ainda.
    if ler_extensao(&item(0, 2)).is_ok() {
        return Err("uma extensao pre-alocada foi aceita");
    }

    // E um item que acaba antes do campo do tipo.
    if ler_extensao(&item(0, 1)[..18]).is_ok() {
        return Err("uma extensao truncada foi aceita");
    }

    Ok(())
}

/// A leitura por deslocamento continua de onde a anterior parou.
///
/// # Por que este caso existe separado do `ler_tudo`
///
/// Porque `ler_tudo` chama o sistema de arquivos com um deslocamento que ele
/// mesmo calcula, e o [`crate::vfs::ler_em`] recebe o deslocamento de fora —
/// de um descritor aberto, que é quem guarda a posição. Era falsificável em
/// nenhum caso: apagar o deslocamento na passagem para o sistema de arquivos
/// não reprovava nada, porque o único leitor por descritor lia do começo uma
/// vez só.
///
/// Este caso lê o mesmo arquivo em pedaços e exige que eles se emendem.
fn vfs_le_a_partir_de_um_deslocamento() -> Resultado {
    let vnode = crate::vfs::resolver("/saudacao.txt").map_err(|e| e.motivo())?;
    let esperado = NO_SAUDACAO.as_bytes();

    // Em pedaços de oito, do começo ao fim, emendando.
    const PEDACO: usize = 8;
    let mut juntado = alloc::vec::Vec::new();
    let mut de = 0u64;
    loop {
        let mut buffer = [0u8; PEDACO];
        let veio = crate::vfs::ler_em(&vnode, de, &mut buffer).map_err(|e| e.motivo())?;
        if veio == 0 {
            break;
        }
        juntado.extend_from_slice(&buffer[..veio]);
        de += veio as u64;
        if juntado.len() > esperado.len() {
            return Err("a leitura em pedacos trouxe mais que o arquivo tem");
        }
    }
    if juntado != esperado {
        crate::log_error!("teste", "vieram {} bytes emendados", juntado.len());
        return Err("os pedacos nao remontam o arquivo: o deslocamento foi ignorado");
    }

    // Um deslocamento no meio traz o que está no meio, e não o começo.
    let mut buffer = [0u8; PEDACO];
    let veio = crate::vfs::ler_em(&vnode, 4, &mut buffer).map_err(|e| e.motivo())?;
    if buffer[..veio] != esperado[4..4 + veio] {
        return Err("a leitura no meio trouxe bytes de outro lugar");
    }

    // Além do fim não é erro: é zero bytes, que é o que uma leitura
    // sequencial encontra ao chegar ao fim.
    if crate::vfs::ler_em(&vnode, esperado.len() as u64, &mut buffer).map_err(|e| e.motivo())? != 0
    {
        return Err("uma leitura alem do fim trouxe bytes");
    }

    // E um diretório não se lê.
    let dir = crate::vfs::resolver("/dados").map_err(|e| e.motivo())?;
    if crate::vfs::ler_em(&dir, 0, &mut buffer).is_ok() {
        return Err("um diretorio foi lido como arquivo");
    }

    Ok(())
}

/// A identidade que o iniciador deixou foi largada.
///
/// # O que ela era, e por que ela não pode ficar
///
/// O iniciador mapeia a RAM duas vezes: no deslocamento do kernel, que é por
/// onde o kernel a alcança, e por identidade — virtual igual a físico. A
/// segunda existe para um instante só, o do `mov cr3`: a instrução seguinte é
/// buscada no código do iniciador, que mora num endereço baixo.
///
/// Passado esse instante ela é um peso. Ela ocupa a entrada de topo do
/// **espaço do usuário**, e faz o endereço zero ser memória legível —
/// desreferenciar um ponteiro nulo dentro do kernel deixaria de ser uma falha
/// de página e passaria a ler o primeiro frame da máquina.
///
/// # Por que este caso existe
///
/// Porque largar a identidade não tem efeito visível: o kernel boota igual
/// com ela e sem ela. Medido por mutação — desligar o `largar_a_identidade`
/// não reprovava caso nenhum, e o defeito ficaria esperando o primeiro
/// ponteiro nulo do kernel para aparecer como uma leitura silenciosa.
fn mmu_identidade_largada() -> Resultado {
    #[cfg(not(target_arch = "x86_64"))]
    {
        crate::log_info!("teste", "so o x86 boota por um iniciador com identidade");
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    {
        // Endereços baixos que a identidade cobria e que nada mais mapeia: o
        // primeiro frame da máquina, e um no meio da faixa onde o iniciador
        // e as tabelas dele moram.
        for endereco in [0x1000u64, 0x10_0000, 0x400_0000] {
            if let Some(fisico) = crate::arch::traduzir(endereco) {
                crate::log_error!("teste", "{:#x} traduz para {:#x}", endereco, fisico);
                return Err("um endereco baixo ainda traduz: a identidade ficou");
            }
        }

        // E o que substituiu a identidade continua de pé: a memória física
        // pelo deslocamento do kernel. Sem esta metade, o caso passaria com
        // um kernel que tivesse largado a tabela inteira.
        if crate::arch::traduzir(protocolo::mapa::BASE_DA_MEMORIA_FISICA + 0x1000) != Some(0x1000) {
            return Err("o mapa da memoria fisica saiu junto com a identidade");
        }

        Ok(())
    }
}

/// A tabela de descritores faz o que uma tabela de descritores faz.
///
/// # Por que um caso de unidade, se há um programa que a usa
///
/// Porque o programa exercita **um** caminho: abrir uma vez, ler, fechar. Ele
/// não tem como encher a tabela, nem como conferir que a vaga fechada volta
/// para o mesmo número — são coisas que exigem contar até dezesseis e olhar o
/// resultado, e um programa em assembly que fizesse isso testaria mais o
/// assembly que o kernel.
///
/// Este caso confere as regras; o programa confere que elas valem do outro
/// lado da chamada de sistema. Nenhum dos dois substitui o outro.
fn descritores_a_tabela_do_processo() -> Resultado {
    use crate::usuario::descritores::{Alvo, MAX, PRIMEIRO_LIVRE, Tabela, padrao};

    let vnode = crate::vfs::resolver("/saudacao.txt").map_err(|e| e.motivo())?;
    let mut tabela = Tabela::nova();

    // Ela nasce com os três de sempre, e a entrada padrão vazia.
    if tabela.alvo(padrao::ENTRADA).is_some() {
        return Err("a entrada padrao nasceu apontando para algum lugar");
    }
    if !matches!(tabela.alvo(padrao::SAIDA), Some(Alvo::Registro)) {
        return Err("a saida padrao nao nasceu apontando para o registro");
    }
    if !matches!(tabela.alvo(padrao::ERRO), Some(Alvo::Diagnostico)) {
        return Err("a saida de erro nao nasceu apontando para o diagnostico");
    }
    if tabela.abertos() != 2 {
        return Err("a tabela nova nao tem exatamente dois descritores abertos");
    }

    // O primeiro `abrir` não pode entregar a vaga zero, que está livre e é
    // reservada. Entregá-la faria um `ler(0)` funcionar por acidente.
    let primeiro = tabela
        .abrir(vnode)
        .ok_or("a tabela nova recusou a abertura")?;
    if primeiro != PRIMEIRO_LIVRE as u64 {
        crate::log_error!("teste", "o primeiro descritor foi {}", primeiro);
        return Err("abrir entregou um numero que nao e o primeiro livre");
    }
    if !matches!(tabela.alvo(primeiro), Some(Alvo::Arquivo { .. })) {
        return Err("o arquivo aberto nao ficou como destino de leitura");
    }

    // A posição é do descritor, e avançar um não mexe no outro.
    let segundo = tabela
        .abrir(vnode)
        .ok_or("a segunda abertura foi recusada")?;
    if segundo == primeiro {
        return Err("duas aberturas devolveram o mesmo descritor");
    }
    tabela.avancar(primeiro, 10);
    let em = |t: &Tabela, fd| match t.alvo(fd) {
        Some(Alvo::Arquivo { posicao, .. }) => posicao,
        _ => u64::MAX,
    };
    if em(&tabela, primeiro) != 10 || em(&tabela, segundo) != 0 {
        crate::log_error!(
            "teste",
            "posicoes {} e {}",
            em(&tabela, primeiro),
            em(&tabela, segundo)
        );
        return Err("avancar um descritor mexeu na posicao do outro");
    }

    // Fechar devolve a vaga, e a próxima abertura a reaproveita — o menor
    // número livre, como em qualquer Unix.
    if !tabela.fechar(primeiro) {
        return Err("fechar um descritor aberto falhou");
    }
    if tabela.alvo(primeiro).is_some() {
        return Err("o descritor fechado continua apontando para o arquivo");
    }
    if tabela.fechar(primeiro) {
        return Err("fechar duas vezes o mesmo descritor deu certo na segunda");
    }
    let terceiro = tabela
        .abrir(vnode)
        .ok_or("a terceira abertura foi recusada")?;
    if terceiro != primeiro {
        return Err("a vaga fechada nao foi reaproveitada");
    }
    // E a posição do reaproveitado começa do zero, e não de onde o anterior
    // parou. Sem isto, o segundo dono do número leria do meio do arquivo.
    if em(&tabela, terceiro) != 0 {
        return Err("o descritor reaproveitado herdou a posicao do anterior");
    }

    // E a tabela tem fim. Um processo que abra sem fechar recebe uma recusa,
    // e não uma vaga que não existe.
    //
    // Cheia são `MAX - 1`, e não `MAX`: a vaga da entrada padrão nunca é
    // preenchida, porque `abrir` começa depois dela e nada mais escreve ali.
    // A primeira versão deste caso esperava `MAX` e reprovou — o defeito
    // estava no caso, e a conta certa é esta.
    while tabela.abrir(vnode).is_some() {}
    if tabela.abertos() != MAX - 1 {
        crate::log_error!("teste", "{} abertos com a tabela cheia", tabela.abertos());
        return Err("a tabela nao encheu ate a ultima vaga que ela entrega");
    }
    if tabela.alvo(padrao::ENTRADA).is_some() {
        return Err("encher a tabela preencheu a vaga reservada");
    }

    // Um número que não cabe num `usize`, e um dentro do teto mas fora da
    // tabela: os dois têm de sair como "não existe", e não em pânico.
    if tabela.alvo(u64::MAX).is_some() || tabela.fechar(u64::MAX) {
        return Err("um descritor absurdo foi aceito");
    }
    if tabela.alvo(MAX as u64).is_some() {
        return Err("um descritor de fora da tabela foi aceito");
    }

    Ok(())
}

/// Um processo sem privilégio abre um arquivo do disco, lê e fecha.
///
/// # O que este caso prova que nenhum outro prova
///
/// A pilha inteira numa linha só: um programa em ring 3 chama `abrir`, o
/// kernel resolve o caminho pelo VFS, acha o arquivo no Btrfs, guarda o vnode
/// na tabela **daquele processo**, entrega um número; o programa chama `ler`
/// com esse número, os bytes saem do disco e chegam à memória dele; ele os
/// escreve de volta pelo descritor de saída, e o texto que aparece no log é o
/// que o `mkfs.btrfs` pôs na imagem.
///
/// E o programa confere o kernel de dentro: ele sai com
/// [`CODIGO_DE_FALHA_DO_LEITOR`](crate::usuario::exemplo::CODIGO_DE_FALHA_DO_LEITOR)
/// se `abrir` devolver erro, se `ler` não trouxer nada, se abrir um diretório
/// **não** for recusado com o motivo certo, se `fechar` recusar — ou se a
/// leitura **depois** do `fechar` der certo, que é o que denunciaria um
/// `fechar` que não fecha.
///
/// # A herança, provada pelo filho
///
/// O leitor bifurca com o arquivo já aberto, e o filho lê por aquele mesmo
/// número. É a única prova possível de que a tabela é herdada: com uma tabela
/// nova, o descritor do pai não existiria do lado do filho e a leitura dele
/// sairia com "descritor invalido".
///
/// Os dois leem do começo, e isso também é afirmado aqui: cada um levou a
/// própria cópia da posição. Não é o que o Unix faz — lá pai e filho
/// compartilham a posição —, e a diferença está documentada na tabela em vez
/// de ser descoberta.
fn usuario_abre_le_e_fecha_um_arquivo() -> Resultado {
    use alloc::format;

    extern "C" fn hospedar(_argumento: u64) -> ! {
        match crate::usuario::programa::executar(crate::usuario::exemplo::bytes_do_leitor()) {
            Ok(_) => unreachable!("executar nao retorna em caso de sucesso"),
            Err(falha) => {
                crate::log_error!("teste", "o leitor nao entrou: {}", falha.motivo());
                crate::fios::terminar()
            }
        }
    }

    let (aberturas_antes, leituras_antes, bytes_antes) = crate::usuario::estatisticas_de_arquivo();
    let saidas_antes = crate::usuario::estatisticas_de_processo().2;

    let bifurcacoes_antes = crate::usuario::estatisticas_de_processo().0;
    crate::fios::criar("teste-leitor", hospedar, 0)?;

    // Duas saídas: a do pai e a do filho que ele bifurcou.
    esperar_ate(
        || crate::usuario::estatisticas_de_processo().2 >= saidas_antes + 2,
        600,
    )?;

    let sucesso = format!(
        "processo encerrou com codigo {}",
        crate::usuario::exemplo::CODIGO_DO_LEITOR
    );
    let do_filho = format!(
        "processo encerrou com codigo {}",
        crate::usuario::exemplo::CODIGO_DO_FILHO_DO_LEITOR
    );
    let falha = format!(
        "processo encerrou com codigo {}",
        crate::usuario::exemplo::CODIGO_DE_FALHA_DO_LEITOR
    );

    let (mut viu_sucesso, mut viu_filho, mut viu_falha, mut viu_conteudo) =
        (false, false, false, false);
    crate::log::ultimos(64, crate::log::Level::Trace, |r| {
        if r.subsistema != "usuario" {
            return;
        }
        let m = r.mensagem();
        viu_sucesso |= m == sucesso;
        viu_filho |= m == do_filho;
        viu_falha |= m == falha;
        // O conteúdo vem com a quebra de linha que está no arquivo; o
        // registro guarda o texto como veio.
        viu_conteudo |=
            r.level == crate::log::Level::Info && m.trim_end() == NO_SAUDACAO.trim_end();
    });

    if viu_falha {
        return Err("o leitor reprovou alguma das chamadas que ele mesmo confere");
    }
    if !viu_conteudo {
        return Err("o conteudo do arquivo nao apareceu escrito pelo processo");
    }
    if !viu_sucesso {
        return Err("o leitor nao saiu com o codigo dele");
    }
    if !viu_filho {
        return Err("o filho nao leu pelo descritor que o pai abriu");
    }
    if crate::usuario::estatisticas_de_processo().0 != bifurcacoes_antes + 1 {
        return Err("o leitor nao se bifurcou exatamente uma vez");
    }

    // E os contadores acompanharam: **uma** abertura — a do diretório foi
    // recusada e não conta —, e duas leituras que trouxeram bytes, uma de
    // cada lado da bifurcação. A leitura no descritor fechado não conta, e é
    // isso que distingue "recusou" de "leu zero bytes".
    let (aberturas, leituras, bytes) = crate::usuario::estatisticas_de_arquivo();
    if aberturas != aberturas_antes + 1 {
        crate::log_error!("teste", "{} aberturas", aberturas - aberturas_antes);
        return Err("a abertura do diretorio foi contada, ou a do arquivo nao");
    }
    if leituras != leituras_antes + 2 {
        crate::log_error!("teste", "{} leituras", leituras - leituras_antes);
        return Err("a leitura no descritor fechado foi contada como leitura");
    }
    // Os dois leram o arquivo inteiro, cada um do começo: é a soma que
    // denuncia um filho que tivesse herdado a posição já avançada.
    if bytes - bytes_antes != 2 * NO_SAUDACAO.len() as u64 {
        crate::log_error!("teste", "{} bytes lidos", bytes - bytes_antes);
        return Err("os dois lados nao leram o arquivo inteiro cada um");
    }

    Ok(())
}

/// A ausência de framebuffer é sempre defeito, nas duas arquiteturas.
///
/// # Por que isto já foi condicional, e por que não é mais
///
/// Porque a tolerância boa demais transformou este caso num que passava
/// justamente quando deveria falhar. Injetando um stride menor que a largura,
/// a tela foi corretamente recusada no boot e o caso continuou dizendo `ok`:
/// o único que olha para o framebuffer de verdade parou de olhar, em
/// silêncio, no exato cenário em que ele importa.
///
/// A correção de então foi exigir tela no x86 e tolerar a falta no ARM, onde
/// a `virt` do QEMU não expunha vídeo nenhum. Era verdade sobre a máquina, e
/// virou mentira no momento em que a máquina passou a receber um adaptador e
/// o kernel passou a saber programá-lo — ver [`crate::tela::bochs`].
///
/// Deixá-la condicional agora seria pior que antes: a tolerância cobriria
/// exatamente a arquitetura onde o caminho é novo, e portanto a única em que
/// há algo a provar. Uma pessoa precisa enxergar o Duke nas duas, então a
/// ausência descreve defeito nas duas.
fn sem_framebuffer() -> Resultado {
    Err("esta maquina deveria ter framebuffer e nao tem")
}

/// Roda `f` sem que outro fio escreva no console no meio.
///
/// # Por que os casos de tela precisam disto
///
/// Porque eles imprimem e depois conferem o que ficou — o cursor, a grade,
/// os pixels, o que atravessou para o dispositivo —, e o console é de todo
/// mundo. Entre uma coisa e outra, qualquer fio preemptivo pode imprimir: o
/// coletor de fios registra cada vez que recolhe um morto, e ele acorda a
/// cada tique. A linha dele cai no meio do caso.
///
/// Medido, e não suposto: com a suíte em release sobre o `virtio-gpu`, o
/// registro do coletor entrou duas vezes em três rodadas entre o `"zq\u{8}"`
/// do caso de apagar e a conferência. Numa, desceu o cursor uma linha — "o
/// apagar voltou alem do comeco da linha"; na outra, desenhou o `[` dele na
/// célula recém-apagada — "a celula apagada ainda tem tinta". O console
/// estava certo nas duas; o caso é que não era dono da tela que conferia.
///
/// # Por que mascarar as interrupções resolve
///
/// Porque a máquina tem um núcleo, e quem tira a vez de um fio é o timer.
/// Sem a interrupção dele, nenhum outro fio roda até o fim de `f`, e o que
/// está na tela é só o que o caso escreveu. O tique não se perde: fica
/// pendente e chega quando elas voltam.
///
/// `f` não pode esperar por interrupção nenhuma — ela não viria. Os casos
/// que usam isto desenham, leem memória e falam com o `virtio-gpu`, que
/// responde por varredura.
///
/// Nem pode precisar de uma trava que outro fio segure com as interrupções
/// ligadas: esse fio, preemptado no meio, nunca mais rodaria para soltá-la.
/// As que estes casos tocam — o log, o heap, o console, a linha do
/// interpretador, o `virtio-gpu` — são todas tomadas com as interrupções já
/// mascaradas, pela mesma razão de poderem ser usadas de dentro de um
/// handler, e ninguém é preemptado segurando uma delas.
fn sem_intrusos<R>(f: impl FnOnce() -> R) -> R {
    crate::arch::sem_interrupcoes(f)
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
/// endereço que o iniciador entregou, a geometria que ele declarou, e a
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
/// No x86 não há faixas declaradas, porque a entrega já as classifica: o
/// firmware marca o que é dele, o iniciador marca o que é seu, e o alocador
/// nunca vê nenhuma das duas como livre. Lá este caso passa sem verificar
/// nada, e isso é honesto: não há o que verificar.
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
/// arquiteturas: no x86 o iniciador mapeia a memória física num deslocamento
/// que o protocolo fixa, e um endereço fixo poderia cair em cima dele.
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

/// Um frame reciclado chega zerado ao próximo dono.
///
/// # O que estava sem proteção
///
/// [`crate::paginacao::mapear_novo`] zera todo frame que entrega, e o
/// comentário daquela linha diz por quê: entregar um frame sujo vaza dados do
/// dono anterior, e *"quando houver processos, seria uma falha de
/// isolamento"*. Há processos — `user.run`, `bifurcar`, `executar` —, e o
/// carregador monta o BSS de um programa contando exatamente com isso.
///
/// Medido: apagando a zeragem, a suíte inteira passava. Um vazamento entre
/// donos não quebra nada — só entrega bytes a quem não deveria vê-los, e
/// quanto mais interessante o byte, mais provável que o dono anterior fosse
/// o kernel.
///
/// # Por que vários frames, e não um
///
/// Porque o alocador é determinístico sobre o mesmo bitmap: liberar um frame
/// e pedir outro devolve sempre a mesma resposta, e não há como forçá-lo a
/// devolver justamente aquele. Sujando vários de uma vez e pedindo-os de
/// volta em bloco, o conjunto livre é o mesmo das duas vezes — então são os
/// mesmos frames que voltam, e o caso confere que são.
fn paginacao_frame_reciclado_vem_zerado() -> Resultado {
    const QUANTOS: usize = 8;
    const SUJEIRA: u8 = 0xA5;
    let tamanho = crate::frames::TAMANHO_FRAME as usize;

    let mut enderecos = [0u64; QUANTOS];
    let mut sujos = [0u64; QUANTOS];

    // Primeira passada: mapear, sujar a página inteira, devolver o frame.
    for i in 0..QUANTOS {
        let virtual_ = endereco_virtual_livre().ok_or("nenhum endereco virtual livre")?;
        enderecos[i] = virtual_;
        sujos[i] = crate::paginacao::mapear_novo(virtual_, crate::arch::Permissoes::DADOS)
            .map_err(|_| "mapeamento recusado na primeira passada")?;

        // SAFETY: a página acabou de ser mapeada para escrita e é só nossa.
        unsafe { core::ptr::write_bytes(virtual_ as *mut u8, SUJEIRA, tamanho) };
    }
    for &virtual_ in &enderecos {
        crate::paginacao::desmapear_e_liberar(virtual_).map_err(|_| "liberacao falhou")?;
    }

    // Segunda passada: os mesmos frames voltam, e precisam voltar limpos.
    let mut reaproveitados = 0;
    let mut sujo_encontrado = false;

    for &virtual_ in &enderecos {
        let frame = crate::paginacao::mapear_novo(virtual_, crate::arch::Permissoes::DADOS)
            .map_err(|_| "mapeamento recusado na segunda passada")?;

        if sujos.contains(&frame) {
            reaproveitados += 1;
        }

        // SAFETY: a página é nossa e está mapeada.
        let bytes = unsafe { core::slice::from_raw_parts(virtual_ as *const u8, tamanho) };
        if bytes.iter().any(|&b| b != 0) {
            sujo_encontrado = true;
        }
    }

    for &virtual_ in &enderecos {
        let _ = crate::paginacao::desmapear_e_liberar(virtual_);
    }

    // Nenhum frame reaproveitado significa que o experimento não aconteceu.
    // Um caso que passa sem ter medido nada é pior que um caso que falha.
    if reaproveitados == 0 {
        return Err("nenhum frame voltou do lote sujado; o caso nao mediu nada");
    }
    if sujo_encontrado {
        crate::log_error!(
            "teste",
            "{} de {} frames reaproveitados, e ao menos um trouxe bytes do dono anterior",
            reaproveitados,
            QUANTOS
        );
        return Err("frame reciclado vazou dados do dono anterior");
    }

    Ok(())
}

/// O frame do endereço zero nunca volta à circulação.
///
/// `frames::init` o reserva de propósito, para que zero continue significando
/// "nenhum frame" em todo lugar que o usa como sentinela — e para que uma
/// desreferência de ponteiro nulo continue produzindo falha diagnosticável em
/// vez de corromper dados de alguém.
///
/// Medido: desligando a reserva, a suíte inteira passava.
fn frames_nunca_entrega_o_frame_zero() -> Resultado {
    if crate::frames::esta_livre(0) {
        return Err("o frame zero esta na lista de livres");
    }

    // Liberá-lo não pode recolocá-lo em circulação: a reserva vale contra
    // quem o devolve por engano, não só contra a inicialização.
    crate::frames::liberar(0);
    if crate::frames::esta_livre(0) {
        return Err("liberar o frame zero o devolveu a circulacao");
    }
    Ok(())
}

/// A tela em que o kernel desenha está mapeada no espaço em que ele roda.
///
/// # O que este caso protege
///
/// Que "há uma tela registrada" e "dá para escrever nela" não são a mesma
/// afirmação. [`crate::tela::registrar`] guarda um endereço; quem garante
/// que aquele endereço traduz é o mapa de páginas, e os dois são montados
/// em momentos diferentes por código diferente.
///
/// No x86 quem mapeia é o iniciador, antes de o kernel existir. No ARM o
/// kernel adota a tela do firmware com a MMU **desligada** e depois liga a
/// sua própria — e o mapa de identidade dele cobre o que é utilizável,
/// enquanto o framebuffer é declarado reservado. Se o bloco da tela não
/// entrasse no mapa, a primeira linha de log depois de a MMU ligar seria
/// uma falha de tradução, e ela viria da parte do kernel que existe
/// justamente para quando a serial não responde.
///
/// Os dois extremos são conferidos, e não só a base: uma tela que atravessa
/// a fronteira de um bloco não está mapeada só porque o começo dela está.
fn tela_esta_mapeada_no_espaco_do_kernel() -> Resultado {
    let Some(tela) = crate::tela::tela() else {
        return sem_framebuffer();
    };

    let (base, bytes) = tela.faixa();
    if bytes == 0 {
        return Err("a tela diz ocupar zero bytes");
    }

    // Saturante pela mesma razão que [`crate::tela::Tela::faixa`]: a
    // extensão vem da geometria, que vem da entrega, e um `u64` no teto
    // estouraria a soma numa compilação de depuração.
    let ultimo = base.saturating_add(bytes - 1);
    for endereco in [base, ultimo] {
        if crate::arch::traduzir(endereco).is_none() {
            crate::log_error!(
                "teste",
                "a tela vai de {:#x} a {:#x} e {:#x} nao traduz",
                base,
                ultimo,
                endereco
            );
            return Err("um extremo da tela nao traduz no espaco do kernel");
        }
    }

    // E a aritmética que decide **quais** blocos a tela exige do mapa de
    // identidade. Ela é exercitada aqui com telas que não existem nesta
    // máquina porque na que existe ela não tem efeito nenhum: a RAM
    // utilizável já cobre o framebuffer do `ramfb`, e `cobrir_a_tela`
    // acrescenta zero blocos. Sem estas afirmações, um deslocamento errado
    // ou um limite trocado passaria até o dia em que ela fosse necessária.
    #[cfg(target_arch = "aarch64")]
    {
        use crate::arch::aarch64::mmu::blocos_da_tela;

        const GIB: u64 = 1024 * 1024 * 1024;

        // Uma tela inteira dentro de um bloco ocupa só ele.
        if blocos_da_tela(GIB + 0x3d0_0000, 3 * 1024 * 1024) != Some((1, 1)) {
            return Err("uma tela dentro de um bloco pediu mais de um");
        }
        // Uma que atravessa a fronteira pede os dois.
        if blocos_da_tela(2 * GIB - 4096, 8192) != Some((1, 2)) {
            return Err("uma tela que atravessa a fronteira pediu um bloco so");
        }
        // Uma que termina exatamente na fronteira **não** atravessa: o
        // índice sai do último byte, e não do primeiro depois do fim.
        if blocos_da_tela(2 * GIB - 4096, 4096) != Some((1, 1)) {
            return Err("uma tela que acaba na fronteira invadiu o bloco seguinte");
        }
        // Sem tela não há bloco a pedir.
        if blocos_da_tela(GIB, 0).is_some() {
            return Err("uma tela de zero bytes pediu um bloco");
        }
        // E uma fora do espaço de 39 bits não tem entrada de topo que a
        // cubra: devolver um índice aqui escreveria fora da tabela.
        if blocos_da_tela(512 * GIB, 4096).is_some() {
            return Err("uma tela fora do espaco de 39 bits pediu um bloco");
        }
        // Uma extensão absurda não estoura nem escapa: o último índice é
        // recortado no fim da tabela. A geometria vem da entrega, que é dado
        // de fora, e a única conferência sobre ela é de coerência — nada
        // limita a magnitude dos campos.
        if blocos_da_tela(GIB, u64::MAX) != Some((1, 511)) {
            return Err("uma tela de extensao absurda escapou do fim da tabela");
        }
    }

    Ok(())
}

/// Uma geometria de tela incoerente é recusada, e a tela em uso sobrevive.
///
/// O `stride` é quantos pixels vão de uma linha à seguinte, e pode exceder a
/// largura visível. O limite que o leitor de pixel confere é a **largura**,
/// mas o endereço que ele calcula usa o **stride**: com um stride menor que a
/// largura, um ponto dentro do limite cai fora da linha, e perto da última
/// linha cai fora do framebuffer inteiro.
///
/// Medido: aceitando stride menor que a largura, a suíte inteira passava.
fn tela_recusa_geometria_incoerente() -> Resultado {
    let antes = crate::tela::tela().map(|t| (t.largura, t.altura, t.stride, t.bytes_por_pixel));

    // Endereço qualquer: a geometria é conferida **antes** de qualquer
    // registro, então nada aqui chega a ser desreferenciado.
    //
    // SAFETY: cada chamada abaixo traz uma geometria que `registrar` tem de
    // recusar, e uma recusa não guarda o ponteiro nem lê por ele. É
    // exatamente isso que o caso afirma.
    unsafe {
        // stride menor que a largura
        crate::tela::registrar(0x1000u64, 64, 64, 32, 4, crate::tela::Formato::Bgr);
        // largura zero
        crate::tela::registrar(0x1000u64, 0, 64, 64, 4, crate::tela::Formato::Bgr);
        // altura zero
        crate::tela::registrar(0x1000u64, 64, 0, 64, 4, crate::tela::Formato::Bgr);
        // menos bytes por pixel do que o formato toca
        crate::tela::registrar(0x1000u64, 64, 64, 64, 1, crate::tela::Formato::Bgr);
    }

    let depois = crate::tela::tela().map(|t| (t.largura, t.altura, t.stride, t.bytes_por_pixel));
    if depois != antes {
        crate::log_error!("teste", "{:?} -> {:?}", antes, depois);
        return Err("uma geometria incoerente substituiu a tela em uso");
    }
    Ok(())
}

/// Uma mensagem que não cabe no registro diz quanto ficou de fora.
///
/// # Por que isso importa mais do que parece
///
/// O corte acontece numa fronteira de caractere, então a mensagem truncada
/// tem cara de mensagem inteira. Medido, mandando trezentos caracteres ao
/// log: cento e sessenta ficaram, o registro terminou num ponto de aparência
/// perfeitamente legítima, e nenhum campo dizia que havia mais. Um agente
/// lendo `log.tail` via um fato que o kernel não afirmou.
fn log_conta_o_que_nao_coube() -> Resultado {
    // Cento e oitenta caracteres: acima dos 160 que cabem, e o bastante para
    // que a diferença seja um número redondo de conferir.
    const LONGA: &str = concat!(
        "0123456789012345678901234567890123456789",
        "0123456789012345678901234567890123456789",
        "0123456789012345678901234567890123456789",
        "0123456789012345678901234567890123456789",
        "01234567890123456789",
    );

    let guardados =
        crate::log::registrar(crate::log::Level::Debug, "teste", format_args!("{}", LONGA));

    if guardados >= LONGA.len() {
        return Err("o registro afirmou ter guardado uma mensagem que nao cabe nele");
    }

    let mut achou = false;
    let mut visto = (0usize, 0u16);
    crate::log::ultimos(4, crate::log::Level::Trace, |registro| {
        if registro
            .mensagem()
            .starts_with("012345678901234567890123456789")
        {
            achou = true;
            visto = (registro.mensagem().len(), registro.perdidos());
        }
    });

    if !achou {
        return Err("o registro longo nao apareceu no anel");
    }
    let (guardada, perdidos) = visto;
    if perdidos == 0 {
        return Err("o registro nao diz que a mensagem foi cortada");
    }
    if guardada + perdidos as usize != LONGA.len() {
        crate::log_error!(
            "teste",
            "{} guardados + {} perdidos != {} enviados",
            guardada,
            perdidos,
            LONGA.len()
        );
        return Err("guardados mais perdidos nao somam a mensagem enviada");
    }
    if guardados != guardada {
        return Err("o numero devolvido nao e o que foi guardado");
    }

    // E a metade que impede um conserto barulhento: uma mensagem que cabe não
    // pode ser marcada como cortada.
    let curta = crate::log::registrar(crate::log::Level::Debug, "teste", format_args!("cabe"));
    if curta != 4 {
        return Err("uma mensagem curta devolveu um tamanho que nao e o dela");
    }
    let mut marcada = false;
    crate::log::ultimos(1, crate::log::Level::Trace, |registro| {
        marcada = registro.perdidos() > 0;
    });
    if marcada {
        return Err("uma mensagem que cabe foi marcada como cortada");
    }
    Ok(())
}

/// Uma linha acima do teto é contada à parte, e não indexa a tabela.
///
/// O número da linha vem do controlador de interrupção, não de nós. No GIC
/// ele chega a 1020; a tabela aqui tem 256 entradas. Indexá-la com o número
/// cru seria leitura fora dos limites — pânico num build de depuração, e
/// memória alheia num de release.
///
/// O desvio existe e nunca foi exercitado: nas duas máquinas em que este
/// kernel roda, nenhuma linha passa de 48. Medido, trocando o desvio por um
/// `% MAX_LINHAS`: a suíte inteira passava, e o contador de fora do teto
/// ficava parado enquanto interrupções eram contabilizadas na linha errada.
///
/// A chamada é pública, então não há por que esperar por hardware que a
/// produza: basta chamá-la.
fn irq_linha_acima_do_teto_vai_para_o_contador_separado() -> Resultado {
    let fora_antes = crate::irq::fora_do_teto();
    let total_antes = crate::irq::total();
    let ultima_antes = crate::irq::contagem_da_linha(crate::irq::MAX_LINHAS - 1);

    for linha in [
        crate::irq::MAX_LINHAS,
        crate::irq::MAX_LINHAS + 1,
        1020,
        usize::MAX,
    ] {
        crate::irq::contabilizar(linha);
    }

    if crate::irq::fora_do_teto() != fora_antes + 4 {
        return Err("as linhas acima do teto nao foram para o contador separado");
    }
    // `>=` e não `==`: o total conta também as interrupções de verdade, e o
    // timer dispara a cem por segundo entre uma leitura e a outra. Exigir
    // igualdade aqui seria exigir que o relógio parasse.
    if crate::irq::total() < total_antes + 4 {
        return Err("o total nao contou as linhas acima do teto");
    }
    // A que um `% MAX_LINHAS` teria sujado: `usize::MAX % 256` cai em 255.
    if crate::irq::contagem_da_linha(crate::irq::MAX_LINHAS - 1) != ultima_antes {
        return Err("uma linha acima do teto foi contabilizada numa linha real");
    }

    // E a metade que impede um conserto estrito demais: uma linha válida
    // continua sendo contada onde deve. Duzentos porque nada nas duas
    // máquinas interrompe ali — uma linha real subiria sozinha entre as duas
    // leituras.
    let valida = 200;
    let antes = crate::irq::contagem_da_linha(valida);
    crate::irq::contabilizar(valida);
    if crate::irq::contagem_da_linha(valida) != antes + 1 {
        return Err("uma linha valida deixou de ser contada");
    }
    Ok(())
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

/// Depois de muitas rodadas fora de ordem, o heap volta ao que era.
///
/// # Por que este caso, se já há um de fusão
///
/// Porque o que existe cobre o caso fácil: três blocos do mesmo tamanho,
/// liberados na ordem inversa da alocação. Um alocador com fusão quebrada
/// ainda passa nele.
///
/// O que estilhaça uma lista livre é o outro cenário — tamanhos e
/// alinhamentos variados, liberados fora de ordem, repetidas vezes. É aí que
/// aparecem as duas falhas que não travam nada e só se veem no relatório:
///
/// - **Vazamento.** Uma sobra pequena demais para caber um descritor que
///   fosse aceita e esquecida sumiria alguns bytes por alocação. Com o tempo,
///   um heap que encolhe sem que ninguém esteja segurando nada.
/// - **Estilhaço.** Uma fusão que não acontece deixa `livre` intacto e
///   `maior_bloco` cada vez menor: memória de sobra, e nenhuma peça grande o
///   bastante.
///
/// Por isso as quatro conferências, e não só `livre`. Cada uma pega uma coisa
/// que as outras deixam passar.
fn heap_volta_ao_zero_depois_de_estilhacar() -> Resultado {
    use core::alloc::Layout;

    const RESERVADOS: usize = 24;
    let antes = crate::heap::estatisticas();

    // Gerador determinístico: um caso que muda de comportamento a cada
    // execução não é um caso, é uma loteria. A sequência é a mesma sempre, e
    // um defeito que ela pegue é reproduzível.
    let mut semente = 0x2545_F491_4F6C_DD1Du64;
    let mut sortear = move |teto: usize| {
        semente ^= semente << 13;
        semente ^= semente >> 7;
        semente ^= semente << 17;
        (semente % teto as u64) as usize
    };

    let mut vivos: [Option<(*mut u8, Layout)>; RESERVADOS] = [None; RESERVADOS];

    for rodada in 0..400 {
        let vaga = sortear(RESERVADOS);

        // Meio a meio entre encher e esvaziar: a alternância é o que mistura
        // a lista, e liberar sempre na ordem inversa não misturaria nada.
        if let Some((ponteiro, layout)) = vivos[vaga].take() {
            // SAFETY: veio de `tentar_alocar` com este mesmo layout.
            unsafe { crate::heap::devolver(ponteiro, layout) };
            continue;
        }

        // Tamanhos que cruzam a fronteira do nó da lista (16 bytes) nos dois
        // sentidos: é ali que mora a decisão de aceitar ou recusar a sobra.
        let tamanho = 1 + sortear(600);
        let alinhamento = 1usize << (3 + sortear(6));
        let Ok(layout) = Layout::from_size_align(tamanho, alinhamento) else {
            return Err("layout invalido no sorteio");
        };

        let ponteiro = crate::heap::tentar_alocar(layout);
        if ponteiro.is_null() {
            crate::log_error!(
                "teste",
                "rodada {}: {} bytes alinhados em {} falharam com {} livres (maior {})",
                rodada,
                tamanho,
                alinhamento,
                crate::heap::estatisticas().livre,
                crate::heap::estatisticas().maior_bloco
            );
            return Err("o heap recusou uma alocacao que cabia");
        }
        if !(ponteiro as usize).is_multiple_of(alinhamento) {
            return Err("o heap devolveu um ponteiro desalinhado");
        }

        // Escrever no bloco inteiro é o que transforma uma sobreposição em
        // falha visível: dois blocos vivos no mesmo lugar se corrompem, e a
        // conferência de fusão no fim acusa.
        // SAFETY: a região acabou de ser entregue e é só nossa.
        unsafe { core::ptr::write_bytes(ponteiro, (rodada & 0xFF) as u8, tamanho) };

        vivos[vaga] = Some((ponteiro, layout));
    }

    for vaga in vivos.iter_mut() {
        if let Some((ponteiro, layout)) = vaga.take() {
            // SAFETY: mesma justificativa.
            unsafe { crate::heap::devolver(ponteiro, layout) };
        }
    }

    let depois = crate::heap::estatisticas();

    if depois.alocado != antes.alocado {
        crate::log_error!("teste", "alocado {} -> {}", antes.alocado, depois.alocado);
        return Err("o contador de alocado nao voltou ao inicial");
    }
    if depois.livre != antes.livre {
        crate::log_error!("teste", "livre {} -> {}", antes.livre, depois.livre);
        return Err("bytes vazaram do heap");
    }
    if depois.blocos_livres != antes.blocos_livres {
        crate::log_error!(
            "teste",
            "blocos livres {} -> {}",
            antes.blocos_livres,
            depois.blocos_livres
        );
        return Err("a lista livre nao voltou ao numero de blocos inicial");
    }
    if depois.maior_bloco != antes.maior_bloco {
        crate::log_error!(
            "teste",
            "maior bloco {} -> {}",
            antes.maior_bloco,
            depois.maior_bloco
        );
        return Err("o heap ficou estilhacado depois do ciclo");
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

/// O mapa de memória que chegou no boot coube inteiro na tabela.
///
/// # O defeito que este caso fecha
///
/// O iniciador entregava 133 regiões no x86 e o kernel guardava 64. Um aviso
/// saía no log e a suíte passava inteira: nada afirmava que o mapa tinha
/// chegado completo. Custava 28 MiB de RAM — 93 utilizáveis onde o firmware
/// anunciava 121 livres — e o número que sobrava era plausível.
///
/// Aqui a afirmação é sobre o boot desta rodada, e não sobre um mapa
/// forjado: é o mapa de verdade que precisa ter cabido. Por isso ele reprova
/// no x86 por UEFI, que é onde o firmware descreve o mapa em pedaços, e passa
/// trivialmente no ARM por `-kernel`, cujo device tree tem uma região só.
fn machine_o_mapa_do_boot_coube_inteiro() -> Resultado {
    let sem_vaga = crate::machine::regioes_sem_vaga();
    let totais = crate::machine::estatisticas();
    crate::log_info!(
        "teste",
        "mapa do boot: {} regioes guardadas, {} sem vaga, {} MiB utilizaveis",
        totais.regioes,
        sem_vaga,
        totais.utilizavel / 1024 / 1024
    );
    if sem_vaga != 0 {
        return Err("regioes de memoria do boot ficaram de fora da tabela");
    }

    // E a fusão aconteceu de fato. Sem esta metade, tirar a fusão do
    // registro não reprovaria nada: as 132 regiões do x86 cabem nas 256
    // vagas, e a tabela só voltaria a encher na primeira máquina com um mapa
    // maior. O mapa guardado não pode ter duas vizinhas que se fundiriam.
    let mut anterior: Option<crate::machine::Regiao> = None;
    let mut fundiveis = 0;
    crate::machine::com_regioes(|r| {
        if let Some(a) = anterior
            && crate::machine::fundir(&a, r).is_some()
        {
            fundiveis += 1;
        }
        anterior = Some(*r);
    });
    if fundiveis != 0 {
        crate::log_error!(
            "teste",
            "{} pares de regioes vizinhas ficaram separados",
            fundiveis
        );
        return Err("o mapa guardado tem regioes vizinhas do mesmo tipo sem fundir");
    }
    Ok(())
}

/// A fusão junta só o que é contínuo e do mesmo tipo.
///
/// Sobre a função, e não sobre o mapa da máquina: acrescentar regiões falsas
/// ao mapa vivo as publicaria em `memory.regions` pelo resto da rodada.
///
/// As recusas são as que importam. Fundir uma faixa utilizável a uma
/// reservada entregaria ao alocador memória que não é dele; fundir através de
/// um buraco daria a ele endereços que não existem; e fundir sobrepostas
/// esconderia o mapa incoerente que `memoria: regioes coerentes` acusa.
fn machine_funde_so_vizinhas_do_mesmo_tipo() -> Resultado {
    use crate::machine::{Regiao, TipoRegiao, fundir};

    let a = Regiao {
        inicio: 0x1000,
        fim: 0x3000,
        tipo: TipoRegiao::Utilizavel,
    };
    let contigua = Regiao {
        inicio: 0x3000,
        fim: 0x8000,
        tipo: TipoRegiao::Utilizavel,
    };
    match fundir(&a, &contigua) {
        Some(r) if r.inicio == 0x1000 && r.fim == 0x8000 && r.tipo == TipoRegiao::Utilizavel => {}
        Some(_) => return Err("a fusao de duas vizinhas nao cobre as duas exatamente"),
        None => return Err("duas vizinhas do mesmo tipo nao foram fundidas"),
    }

    let reservada = Regiao {
        tipo: TipoRegiao::Reservada,
        ..contigua
    };
    if fundir(&a, &reservada).is_some() {
        return Err("uma faixa utilizavel foi fundida a uma reservada");
    }
    let depois_do_buraco = Regiao {
        inicio: 0x4000,
        ..contigua
    };
    if fundir(&a, &depois_do_buraco).is_some() {
        return Err("a fusao atravessou um buraco entre as duas faixas");
    }
    let sobreposta = Regiao {
        inicio: 0x2000,
        ..contigua
    };
    if fundir(&a, &sobreposta).is_some() {
        return Err("duas faixas sobrepostas foram fundidas");
    }
    // E a ordem: a nova vem depois da anterior, não antes.
    if fundir(&contigua, &a).is_some() {
        return Err("a fusao aceitou uma faixa que termina onde a anterior comeca");
    }
    Ok(())
}

// ===========================================================================
// O virtio-gpu
// ===========================================================================

/// Registra que um caso de virtio-gpu não se aplica a esta máquina.
///
/// Os casos passam numa máquina sem o dispositivo, e o log diz por quê: a
/// máquina que os exercita é a de `--video virtio`, que o CI sobe à parte.
fn sem_virtio_gpu(caso: &str) -> Resultado {
    crate::log_info!(
        "teste",
        "{}: esta maquina nao tem a tela sobre um virtio-gpu",
        caso
    );
    Ok(())
}

/// A tela mora onde o monitor a mostra.
///
/// Numa máquina linear, nada precisa ser descarregado. Numa com a tela sobre
/// o virtio-gpu, precisa — e a geometria da tela é a que o dispositivo
/// descreve. Uma tela registrada sobre o recurso sem o descarregador ligado
/// seria desenhada na memória e nunca vista.
fn video_a_tela_mora_onde_o_monitor_a_mostra() -> Resultado {
    let sobre_virtio = crate::virtio::gpu::tem_a_tela();
    if sobre_virtio != crate::tela::precisa_descarregar() {
        return Err("a tela esta sobre o virtio-gpu e ninguem a descarrega, ou o contrario");
    }
    if !sobre_virtio {
        return sem_virtio_gpu("video: a tela mora onde o monitor a mostra");
    }
    let tela = crate::tela::tela().ok_or("a tela sobre o virtio-gpu nao foi publicada")?;
    if crate::virtio::gpu::tamanho_da_tela() != Some((tela.largura, tela.altura)) {
        return Err("a tela do kernel nao tem a geometria que o dispositivo descreve");
    }
    if crate::virtio::gpu::na_varredura() != Some(crate::virtio::gpu::RECURSO_DA_TELA) {
        return Err("o recurso na tela 0 nao e o da tela do kernel");
    }
    Ok(())
}

/// Escrever no console leva ao dispositivo só o que sujou.
///
/// É a diferença para o Redox, que transfere o quadro inteiro a cada
/// atualização. A sonda de fora não pega isso — o monitor mostraria a mesma
/// imagem —, e por isso a afirmação é daqui: depois de um caractere, nada
/// fica sujo, e o que atravessou cabe na célula dele.
fn video_escrever_descarrega_so_o_que_sujou() -> Resultado {
    if !crate::virtio::gpu::tem_a_tela() {
        return sem_virtio_gpu("video: escrever descarrega so o que sujou");
    }
    let g = crate::tela::console::geometria().ok_or("sem geometria de console")?;
    let (coluna, linha, descargas_antes, descargas_depois, sujo, t) = sem_intrusos(|| {
        crate::serial_println!();
        let (coluna, linha) = crate::tela::console::cursor_em_celulas();
        let (_, descargas_antes, _) = crate::virtio::gpu::contadores();
        crate::serial_print!("Q");
        let (_, descargas_depois, _) = crate::virtio::gpu::contadores();
        let sujo = crate::tela::sujo();
        let t = crate::virtio::gpu::ultima_transferencia();
        crate::serial_println!();
        (coluna, linha, descargas_antes, descargas_depois, sujo, t)
    });

    if sujo.is_some() {
        return Err("a escrita deixou a tela suja em vez de descarrega-la");
    }
    if descargas_depois <= descargas_antes {
        return Err("a escrita nao descarregou nada");
    }
    let (x0, y0) = (
        g.margem_x + coluna * g.largura_da_celula,
        g.margem_y + linha * g.altura_da_celula,
    );
    let dentro = t.largura > 0
        && t.altura > 0
        && t.x >= x0
        && t.y >= y0
        && t.x + t.largura <= x0 + g.largura_da_celula
        && t.y + t.altura <= y0 + g.altura_da_celula;
    if !dentro {
        crate::log_error!(
            "teste",
            "transferido {},{} {}x{}; a celula e {},{} {}x{}",
            t.x,
            t.y,
            t.largura,
            t.altura,
            x0,
            y0,
            g.largura_da_celula,
            g.altura_da_celula
        );
        return Err("o que atravessou para o dispositivo nao e a celula do caractere");
    }
    Ok(())
}

/// Uma superfície apresenta só o dano, e a tela volta ao kernel depois dela.
///
/// É o trait pelo qual o compositor entrega a tela: criar, desenhar,
/// apresentar um retângulo. Aqui com uma superfície própria, fora do
/// compositor. O dano atravessa recortado; um dano hostil, que o recorte do
/// Redox faria dar a volta, vira nada — e não um comando que o dispositivo
/// recusa. E ao soltar a superfície, a tela 0 volta ao recurso do kernel e a
/// memória volta ao alocador.
fn video_superficie_apresenta_so_o_dano() -> Resultado {
    use crate::grafico::virtio::AdaptadorVirtio;
    use crate::grafico::{AdaptadorGrafico, Dano, Superficie};

    if !crate::virtio::gpu::tem_a_tela() {
        return sem_virtio_gpu("video: superficie apresenta so o dano");
    }
    let (vivas_antes, _) = crate::grafico::memoria::vivas();
    let (_, _, recusas_antes) = crate::virtio::gpu::contadores();
    let mut adaptador = AdaptadorVirtio;

    let resultado = (|| {
        let mut superficie = adaptador.criar_superficie(64, 32)?;
        for (i, pixel) in superficie.pixels_mut().iter_mut().enumerate() {
            *pixel = 0x0000_8000 | i as u32 & 0xFF;
        }

        let levado = adaptador.atualizar(0, &superficie, Dano::novo(8, 8, 16, 8))?;
        if levado != Dano::novo(8, 8, 16, 8) {
            return Err("o dano dentro da superficie nao atravessou inteiro");
        }
        let t = crate::virtio::gpu::ultima_transferencia();
        if (t.x, t.y, t.largura, t.altura) != (8, 8, 16, 8) {
            return Err("o que atravessou nao foi o dano");
        }
        if crate::virtio::gpu::na_varredura() != Some(superficie.recurso()) {
            return Err("apresentar a superficie nao a pos na tela");
        }

        // O dano hostil do Redox: perto do fim do tipo, com uma largura que
        // dá a volta na soma.
        let hostil = adaptador.atualizar(0, &superficie, Dano::novo(u32::MAX - 1, 0, 10, 10))?;
        if !hostil.vazio() {
            return Err("um dano fora da superficie virou um retangulo");
        }
        Ok(())
    })();

    // Solta a superfície (se ela chegou a existir, já saiu de escopo acima).
    if crate::virtio::gpu::na_varredura() != Some(crate::virtio::gpu::RECURSO_DA_TELA) {
        return Err("ao soltar a superficie, a tela nao voltou ao kernel");
    }
    resultado?;
    if crate::grafico::memoria::vivas().0 != vivas_antes {
        return Err("a memoria da superficie nao voltou");
    }
    if crate::virtio::gpu::contadores().2 != recusas_antes {
        return Err("o dispositivo recusou algum comando da superficie");
    }
    Ok(())
}

/// Anexar memória fragmentada usa mais de uma página de entradas.
///
/// Logo depois do boot as páginas de uma superfície são fisicamente
/// vizinhas, e o anexo cabe numa entrada ou poucas: o caminho de várias
/// páginas de entradas nunca rodaria. Aqui cada página vira uma entrada — 300
/// delas, duas páginas —, e o dispositivo tem de aceitar e mostrar.
fn video_anexar_memoria_fragmentada() -> Resultado {
    use crate::grafico::virtio::AdaptadorVirtio;
    use crate::grafico::{AdaptadorGrafico, Dano};

    if !crate::virtio::gpu::tem_a_tela() {
        return sem_virtio_gpu("video: anexar memoria fragmentada");
    }
    let mut adaptador = AdaptadorVirtio;
    let superficie = adaptador.criar_superficie_fragmentada(640, 480)?;
    let entradas = crate::virtio::gpu::entradas_do_ultimo_anexo();
    if entradas != 300 {
        crate::log_error!("teste", "{} entradas no anexo", entradas);
        return Err("o anexo sem fundir nao mandou uma entrada por pagina");
    }
    adaptador.atualizar(0, &superficie, Dano::novo(0, 0, 640, 480))?;
    Ok(())
}

/// Uma recusa do dispositivo volta como erro, com o nome que a especificação
/// dá a ela — e não como pânico, que é o que o `assert_eq!` do Redox faria.
fn video_recusa_do_dispositivo_e_erro() -> Resultado {
    if !crate::virtio::gpu::tem_a_tela() {
        return sem_virtio_gpu("video: recusa do dispositivo e erro");
    }
    let (_, _, antes) = crate::virtio::gpu::contadores();
    let r = crate::virtio::gpu::Retangulo {
        x: 0,
        y: 0,
        largura: 8,
        altura: 8,
    };
    match crate::virtio::gpu::transferir_sem_conferir(999, r) {
        Err(motivo) if motivo.contains("ERR_INVALID_RESOURCE_ID") => {}
        Err(motivo) => {
            crate::log_error!("teste", "recusa: {}", motivo);
            return Err("a recusa voltou com outro nome");
        }
        Ok(()) => return Err("um recurso inexistente foi aceito"),
    }
    if crate::virtio::gpu::contadores().2 != antes + 1 {
        return Err("a recusa nao foi contada");
    }
    Ok(())
}

// ===========================================================================
// A árvore semântica
// ===========================================================================

/// Chama um comando do registro como o canal chamaria — validação e handler —
/// e devolve a resposta inteira.
///
/// Num `String` do heap, e não no `Buffer` de tamanho fixo: a árvore carrega
/// o texto do console, que passa fácil de um kilobyte.
fn chamar(nome: &str, params: &str) -> Result<alloc::string::String, &'static str> {
    let cmd = registry::encontrar(nome).ok_or("comando ausente do registro")?;
    if registry::validar(cmd, Json(params.as_bytes())).is_err() {
        return Err("o registro recusou os parametros");
    }
    let mut saida = alloc::string::String::new();
    {
        let mut w = JsonWriter::new(&mut saida);
        (cmd.handler)(Json(params.as_bytes()), &mut w).map_err(|_| "a resposta nao foi escrita")?;
    }
    Ok(saida)
}

/// O console da árvore, e a linha de comando dentro dele se houver.
fn console_da_arvore(arvore: &str) -> Result<(Json<'_>, Option<Json<'_>>), &'static str> {
    let raiz = Json(arvore.as_bytes())
        .member("root")
        .ok_or("a arvore nao tem raiz")?;
    let console = raiz
        .member("children")
        .and_then(|c| c.item(0))
        .ok_or("a tela nao tem o console como filho")?;
    let linha = console.member("children").and_then(|c| c.item(0));
    Ok((console, linha))
}

/// O texto do console na árvore, desescapado.
///
/// A árvore o publica como string JSON: as quebras de linha chegam como `\n`
/// e as aspas como `\"`. Comparar o texto cru com o que foi escrito
/// compararia duas grafias da mesma coisa.
fn texto_do_console(console: &Json<'_>) -> Result<alloc::string::String, &'static str> {
    let valor = console.member("value").ok_or("o console nao tem valor")?;
    let mut buffer = alloc::vec![0u8; valor.as_str().map_or(0, str::len)];
    valor
        .desescapar_em(&mut buffer)
        .map(alloc::string::String::from)
        .ok_or("o texto do console nao e uma string JSON valida")
}

/// A árvore descreve a tela que existe, e só ela.
///
/// Gerada, e não escrita à mão: a raiz tem a geometria da tela desta rodada,
/// e a linha de comando só aparece quando o interpretador está atendendo — a
/// suíte roda no lugar dele, então aqui ela **não** pode aparecer. Uma árvore
/// escrita à mão a publicaria sempre.
fn ui_a_arvore_descreve_a_tela_que_existe() -> Resultado {
    let arvore = chamar("ui.tree", "{}")?;
    let raiz = Json(arvore.as_bytes()).member("root").ok_or("sem raiz")?;
    let Some(tela) = crate::tela::tela() else {
        return if raiz.is_null() {
            Ok(())
        } else {
            Err("sem tela, a arvore publicou uma raiz")
        };
    };

    if raiz.member("role").and_then(|v| v.as_str()) != Some("screen") {
        crate::log_error!("teste", "arvore: {}", arvore);
        return Err("a raiz nao e a tela");
    }
    let moldura = raiz.member("frame").ok_or("a raiz nao tem moldura")?;
    if moldura.member("width").and_then(|v| v.as_u64()) != Some(tela.largura as u64)
        || moldura.member("height").and_then(|v| v.as_u64()) != Some(tela.altura as u64)
    {
        return Err("a moldura da raiz nao e a geometria da tela");
    }

    let (console, linha) = console_da_arvore(&arvore)?;
    if console.member("role").and_then(|v| v.as_str()) != Some("text_area") {
        return Err("o filho da tela nao e o console");
    }
    if console
        .member("frame")
        .and_then(|m| m.member("y"))
        .and_then(|v| v.as_u64())
        != Some(crate::tela::ALTURA_DA_BARRA as u64)
    {
        return Err("a moldura do console nao comeca abaixo da barra superior");
    }
    if linha.is_some() {
        return Err("a arvore publicou a linha de comando sem interpretador atendendo");
    }
    Ok(())
}

/// O texto que a árvore publica é o que está nos pixels.
///
/// É a afirmação que dá sentido à árvore. Escreve uma marca no console, acha
/// a marca no valor do console na árvore — e então confere, glifo por glifo,
/// que naquela linha e coluna da tela está desenhado exatamente aquele
/// caractere. Uma grade que guardasse o texto numa posição e o desenho fosse
/// para outra passaria na primeira metade e reprovaria na segunda.
///
/// Sem quebra de linha depois da marca: um `\n` na última linha da tela a
/// limparia antes da conferência.
fn ui_o_texto_da_arvore_e_o_que_esta_na_tela() -> Resultado {
    use crate::tela::console::geometria;

    let Some(g) = geometria() else {
        return Ok(());
    };
    sem_intrusos(|| texto_da_arvore_e_o_que_esta_na_tela(&g))
}

fn texto_da_arvore_e_o_que_esta_na_tela(g: &crate::tela::console::Geometria) -> Resultado {
    use crate::tela::console::{caractere, conferir_glifo};

    const MARCA: &str = "arvore-marca-7Q";
    crate::serial_println!();
    crate::serial_print!("{}", MARCA);

    let arvore = chamar("ui.tree", "{}")?;
    let (console, _) = console_da_arvore(&arvore)?;
    let texto = texto_do_console(&console)?;
    if !texto.contains(MARCA) {
        crate::serial_println!();
        return Err("o texto escrito no console nao apareceu na arvore");
    }

    // Onde a grade diz que a marca está.
    let (coluna_do_cursor, linha) = crate::tela::console::cursor_em_celulas();
    let tamanho = MARCA.len() as u32;
    let Some(coluna) = coluna_do_cursor.checked_sub(tamanho) else {
        crate::serial_println!();
        return Err("a marca quebrou de linha, e o caso nao sabe onde ela ficou");
    };
    let resultado = MARCA.chars().enumerate().try_for_each(|(i, c)| {
        let coluna = coluna + i as u32;
        if caractere(coluna, linha) != Some(c) {
            return Err("a grade nao tem a marca onde o cursor diz que ela esta");
        }
        conferir_glifo(
            c,
            g.margem_x + coluna * g.largura_da_celula,
            g.margem_y + linha * g.altura_da_celula,
        )
    });
    crate::serial_println!();
    resultado
}

/// Apagar apaga na tela e na árvore.
///
/// O console desenhava o glifo de substituição para `\u{8}` e avançava: uma
/// pessoa que apagasse via um `?` aparecer. Aqui a célula apagada tem de
/// estar só com fundo, a anterior intacta, e a grade tem de concordar.
fn ui_apagar_apaga_na_tela_e_na_arvore() -> Resultado {
    use crate::tela::console::{caractere, conferir_celula_vazia, conferir_glifo, geometria};

    let Some(g) = geometria() else {
        return Ok(());
    };
    sem_intrusos(|| {
        crate::serial_println!();
        crate::serial_print!("zq\u{8}");
        let (coluna, linha) = crate::tela::console::cursor_em_celulas();
        let resultado = (|| {
            let anterior = coluna
                .checked_sub(1)
                .ok_or("o apagar voltou alem do comeco da linha")?;
            let x = |c: u32| g.margem_x + c * g.largura_da_celula;
            let y = g.margem_y + linha * g.altura_da_celula;
            if caractere(coluna, linha).is_some() {
                return Err("a grade ainda tem o caractere apagado");
            }
            if caractere(anterior, linha) != Some('z') {
                return Err("o apagar levou junto o caractere anterior");
            }
            conferir_celula_vazia(x(coluna), y)?;
            conferir_glifo('z', x(anterior), y)
        })();
        crate::serial_println!();
        resultado
    })
}

/// As ações da árvore passam pelo caminho de quem está na frente da máquina.
///
/// `set_value` e `confirm` sobre a linha de comando: o valor aparece na
/// árvore e na tela, o comando é executado pelo interpretador, e o log diz
/// quem pediu. E o caminho da pessoa, pelas mesmas funções, registra a outra
/// origem — é a distinção que a auditoria vai precisar.
fn ui_agir_pela_linha_de_comando() -> Resultado {
    if crate::tela::tela().is_none() {
        return Ok(());
    }
    crate::interpretador::ativar_para_teste();
    let resultado = agir_pela_linha_de_comando();
    crate::interpretador::desativar_para_teste();
    resultado
}

fn agir_pela_linha_de_comando() -> Resultado {
    let valor_da_linha = || -> Result<alloc::string::String, &'static str> {
        let arvore = chamar("ui.tree", "{}")?;
        let (_, linha) = console_da_arvore(&arvore)?;
        let linha = linha.ok_or("a linha de comando nao apareceu na arvore")?;
        // Desescapado: a árvore publica o valor como string JSON, e as aspas
        // de uma linha com parâmetros chegam como `\"`.
        let mut buffer = [0u8; 256];
        Ok(alloc::string::String::from(
            linha
                .member("value")
                .and_then(|v| v.desescapar_em(&mut buffer))
                .unwrap_or("<sem valor>"),
        ))
    };
    let ok = |resposta: &str| {
        Json(resposta.as_bytes())
            .member("ok")
            .and_then(|v| v.as_bool())
    };
    let revisao = || -> u64 { crate::ui::revisao() };

    // As ações que ela aceita, como a árvore as publica.
    let arvore = chamar("ui.tree", "{}")?;
    let (_, linha) = console_da_arvore(&arvore)?;
    let linha = linha.ok_or("a linha de comando nao apareceu com o interpretador atendendo")?;
    let acoes = linha
        .member("actions")
        .ok_or("a linha de comando nao lista acoes")?;
    let publicadas: alloc::vec::Vec<&str> =
        (0..8).filter_map(|i| acoes.item(i)?.as_str()).collect();
    if publicadas != ["confirm", "cancel", "set_value"] {
        crate::log_error!("teste", "acoes: {:?}", publicadas);
        return Err("a linha de comando nao publicou confirm, cancel e set_value");
    }

    // set_value, e o valor aparece na árvore e no texto do console.
    let antes = revisao();
    let r = chamar(
        "ui.act",
        r#"{"id":3,"action":"set_value","value":"agent.ping"}"#,
    )?;
    if ok(&r) != Some(true) {
        crate::log_error!("teste", "resposta: {}", r);
        return Err("set_value na linha de comando foi recusado");
    }
    if valor_da_linha()? != "agent.ping" {
        return Err("a linha de comando nao ficou com o valor definido");
    }
    if revisao() <= antes {
        return Err("a revisao da arvore nao mudou depois de uma acao");
    }
    let arvore = chamar("ui.tree", "{}")?;
    let (console, _) = console_da_arvore(&arvore)?;
    let texto = texto_do_console(&console)?;
    if !texto.ends_with("duke> agent.ping") {
        return Err("o valor definido nao foi desenhado depois do prompt");
    }

    // Um valor com aspas escapadas chega à linha com as aspas, e não com as
    // barras: é o que deixa um agente passar parâmetros em JSON.
    let r = chamar(
        "ui.act",
        r#"{"id":3,"action":"set_value","value":"log.tail {\"count\":1}"}"#,
    )?;
    if ok(&r) != Some(true) || valor_da_linha()? != r#"log.tail {"count":1}"# {
        crate::log_error!("teste", "resposta: {} linha: {:?}", r, valor_da_linha());
        return Err("as aspas escapadas nao chegaram resolvidas a linha");
    }

    // confirm executa pelo interpretador, e o log diz que foi o agente.
    let r = chamar("ui.act", r#"{"id":3,"action":"confirm"}"#)?;
    if Json(r.as_bytes())
        .member("executed")
        .and_then(|v| v.as_str())
        != Some("log.tail")
    {
        crate::log_error!("teste", "resposta: {}", r);
        return Err("confirm nao executou o comando da linha");
    }
    if !valor_da_linha()?.is_empty() {
        return Err("a linha nao ficou vazia depois de confirmada");
    }
    if !log_tem("executado: log.tail (agente)") {
        return Err("o log nao registrou o comando com a origem do agente");
    }

    // cancel esvazia.
    chamar("ui.act", r#"{"id":3,"action":"set_value","value":"xyz"}"#)?;
    let r = chamar("ui.act", r#"{"id":3,"action":"cancel"}"#)?;
    if ok(&r) != Some(true) || !valor_da_linha()?.is_empty() {
        return Err("cancel nao esvaziou a linha de comando");
    }

    // E a pessoa, pelas mesmas funções, registra a outra origem.
    crate::interpretador::definir("agent.ping")?;
    crate::interpretador::confirmar(crate::ui::Origem::Pessoa);
    if !log_tem("executado: agent.ping (pessoa)") {
        return Err("o log nao distinguiu a pessoa do agente");
    }
    Ok(())
}

/// Alguma das últimas linhas do log tem este texto?
fn log_tem(texto: &str) -> bool {
    let mut achou = false;
    crate::log::ultimos(32, Level::Trace, |r| achou |= r.mensagem().contains(texto));
    achou
}

/// Um registro de log que chega durante a edição não parte a linha.
///
/// Todo registro é ecoado no console, e o console é a tela em que se digita.
/// Antes, o registro era desenhado depois do que estava digitado, e o resto
/// da digitação continuava embaixo dele — a linha que seria executada não era
/// nenhuma das que estavam na tela. Aqui o registro tem de aparecer acima, e a
/// linha `duke> abc` tem de existir uma vez só, inteira, por último.
fn ui_registro_nao_parte_a_linha_digitada() -> Resultado {
    if crate::tela::tela().is_none() {
        return Ok(());
    }
    crate::interpretador::ativar_para_teste();
    let resultado = sem_intrusos(|| {
        crate::interpretador::definir("abc")?;
        crate::log_info!("teste", "registro-por-cima");
        let arvore = chamar("ui.tree", "{}")?;
        let (console, linha) = console_da_arvore(&arvore)?;
        let texto = texto_do_console(&console)?;
        let mut linhas = texto.rsplit('\n');
        if linhas.next() != Some("duke> abc") {
            crate::log_error!("teste", "fim do console: {:?}", texto.rsplit('\n').next());
            return Err("a linha digitada nao ficou inteira e por ultimo");
        }
        let acima = linhas.next();
        if !acima.is_some_and(|l| l.contains("registro-por-cima")) {
            crate::log_error!("teste", "acima da linha: {:?}", acima);
            return Err("o registro nao apareceu logo acima da linha digitada");
        }
        if texto.matches("duke> abc").count() != 1 {
            return Err("a linha digitada ficou na tela duas vezes");
        }
        // E a moldura do campo acompanha: ele começa na linha nova.
        let (_, linha_do_cursor) = crate::tela::console::cursor_em_celulas();
        let g = crate::tela::console::geometria().ok_or("sem geometria")?;
        let y = linha
            .and_then(|l| l.member("frame"))
            .and_then(|m| m.member("y"))
            .and_then(|v| v.as_u64());
        if y != Some((g.margem_y + linha_do_cursor * g.altura_da_celula) as u64) {
            return Err("a moldura do campo ficou na linha antiga");
        }
        Ok(())
    });
    crate::interpretador::desativar_para_teste();
    resultado
}

/// O que a árvore recusa, ela recusa sem mexer em nada.
///
/// Uma ação sobre um elemento que não a aceita, sobre um elemento que não
/// existe, com um nome que não é ação, ou com um valor que uma pessoa não
/// conseguiria digitar. Em todos, `ok` é falso e a linha que estava lá
/// continua lá — recusar depois de ter apagado seria pior que aceitar.
fn ui_acoes_recusadas_nao_deixam_rastro() -> Resultado {
    if crate::tela::tela().is_none() {
        return Ok(());
    }
    // Sem interpretador, a linha de comando não existe.
    let r = chamar("ui.act", r#"{"id":3,"action":"confirm"}"#)?;
    if Json(r.as_bytes()).member("ok").and_then(|v| v.as_bool()) != Some(false) {
        return Err("confirm foi aceito sem a linha de comando existir");
    }

    crate::interpretador::ativar_para_teste();
    let resultado = recusas_com_a_linha_ativa();
    crate::interpretador::desativar_para_teste();
    resultado
}

fn recusas_com_a_linha_ativa() -> Resultado {
    crate::interpretador::definir("abc")?;
    let longo = "x".repeat(crate::interpretador::LINHA_MAX + 1);
    let valor_longo = alloc::format!(r#"{{"id":3,"action":"set_value","value":"{}"}}"#, longo);
    let pedidos: [(&str, &str); 7] = [
        (
            r#"{"id":3,"action":"press"}"#,
            "press aceito por um campo de texto",
        ),
        (
            r#"{"id":2,"action":"set_value","value":"x"}"#,
            "set_value aceito pelo console",
        ),
        (
            r#"{"id":99,"action":"confirm"}"#,
            "acao aceita num elemento que nao existe",
        ),
        (
            r#"{"id":3,"action":"voar"}"#,
            "acao que nao existe foi aceita",
        ),
        (
            r#"{"id":3,"action":"set_value"}"#,
            "set_value aceito sem valor",
        ),
        (
            r#"{"id":3,"action":"set_value","value":"café"}"#,
            "valor que nao se digita foi aceito",
        ),
        (
            r#"{"id":3,"action":"set_value","value":"a\x"}"#,
            "escape invalido foi aceito",
        ),
    ];
    for (pedido, erro) in pedidos
        .iter()
        .copied()
        .chain([(valor_longo.as_str(), "valor longo demais foi aceito")])
    {
        let r = chamar("ui.act", pedido)?;
        if Json(r.as_bytes()).member("ok").and_then(|v| v.as_bool()) != Some(false) {
            crate::log_error!("teste", "pedido: {} resposta: {}", pedido, r);
            return Err(erro);
        }
        if crate::interpretador::com_valor(|v| v != "abc") {
            crate::log_error!("teste", "pedido: {}", pedido);
            return Err("uma acao recusada mexeu na linha de comando");
        }
    }
    // E o log registra a recusa como recusa. Registrar antes de agir punha
    // na trilha de auditoria uma ação que não aconteceu.
    if !log_tem("agente: set_value no elemento 3 recusado") {
        return Err("o log nao registrou a recusa como recusa");
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

/// Um pai espera o filho, colhe o código de saída dele, e o segundo pedido é
/// recusado.
///
/// # O que este caso prova que o de `bifurcar` não provava
///
/// Que o pai sabe **qual** filho saiu e **com que código**. Até aqui havia um
/// `bifurcar` e um campo global de última saída: com dois processos saindo,
/// esse campo guarda o último, e "o último" é uma pergunta que ninguém quer
/// fazer. O caso da bifurcação contorna isso lendo os dois códigos do anel de
/// log — o que funciona para um teste e não serve de nada para um programa.
///
/// O programa `paciente` faz as três conferências do lado de lá, em ring 3,
/// e cada uma mata uma parte diferente de `esperar`:
///
/// - o id colhido é o que `bifurcar` devolveu ao pai;
/// - o código de saída chegou ao ponteiro que o pai passou — o slot começa
///   envenenado com [`crate::usuario::exemplo::VENENO_DO_SLOT`], então um
///   `esperar` que não escrevesse produziria 101 em vez de 52;
/// - a segunda espera é **recusada**, porque o filho já foi colhido. Sem
///   ela, esquecer de marcar a colheita devolveria o mesmo filho para
///   sempre.
///
/// # Por que a última saída volta a servir aqui
///
/// Porque a espera **ordena** as duas saídas. O filho sai primeiro, o pai
/// depois — por construção, não por sorte do escalonador. Num programa que
/// espera, "a última saída" deixa de ser indeterminada e passa a ser a do
/// pai, e é por isso que este caso pode afirmar um número em vez de vasculhar
/// o log.
fn usuario_espera_o_filho_e_colhe_o_codigo() -> Resultado {
    static COMECOU: AtomicBool = AtomicBool::new(false);

    extern "C" fn hospedar(_argumento: u64) -> ! {
        COMECOU.store(true, SeqCst);
        match crate::usuario::programa::executar(crate::usuario::exemplo::bytes_do_paciente()) {
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
    let (_, _, saidas_antes) = crate::usuario::estatisticas_de_processo();
    let (colhidos_antes, _) = crate::fios::colheita();

    crate::fios::criar("teste-paciente", hospedar, 0)?;

    // Duas saídas: a do filho e a do pai, nessa ordem.
    esperar_ate(
        || crate::usuario::estatisticas_de_processo().2 >= saidas_antes + 2,
        600,
    )?;

    if !COMECOU.load(SeqCst) {
        return Err("o fio hospedeiro nunca rodou");
    }

    let (colhidos, _) = crate::fios::colheita();
    if colhidos != colhidos_antes + 1 {
        crate::log_error!(
            "teste",
            "colheitas: {} antes, {} depois",
            colhidos_antes,
            colhidos
        );
        return Err("o pai nao colheu exatamente um filho");
    }

    match crate::usuario::ultima_saida() {
        Some(codigo) if codigo == crate::usuario::exemplo::CODIGO_DO_PACIENTE => Ok(()),
        Some(codigo) if codigo == crate::usuario::exemplo::CODIGO_DE_FALHA_DO_PACIENTE => {
            Err("o paciente reprovou uma das proprias conferencias")
        }
        Some(codigo) if codigo == crate::usuario::exemplo::VENENO_DO_SLOT + 1 => {
            Err("esperar devolveu o id mas nao escreveu o codigo de saida")
        }
        Some(codigo) => {
            crate::log_error!("teste", "o paciente saiu com {}", codigo);
            Err("o paciente saiu com um codigo que nao e de ninguem")
        }
        None => Err("nenhum processo saiu"),
    }
}

/// Um pai distingue "o filho saiu com zero" de "o filho foi morto".
///
/// # A falha silenciosa que este caso fecha
///
/// Nem todo processo sai por `sair`. Um morto por falha de página ou de
/// proteção termina sem código nenhum, e a primeira versão de `esperar`
/// escrevia **zero** nesse caso — que é um código de saída legítimo, e o
/// mais comum de todos. O pai lia zero e concluía sucesso.
///
/// Não há como consertar isso dentro de um número: todo `i64` é um código
/// válido, então não existe sentinela. A segunda palavra do desfecho é a
/// saída, e este caso é o único lugar onde ela é exercitada com `MORTO`.
///
/// O programa `orfao` faz o filho ler a memória do kernel — o mesmo que o
/// `invasor` faz — e exige, do lado do pai, que o desfecho diga que ele foi
/// morto. Se o filho **sobreviver** à leitura, ele chega ao `sair` e o caso
/// reprova com outro código: aí o defeito é da proteção, e não da espera.
fn usuario_pai_sabe_que_o_filho_foi_morto() -> Resultado {
    extern "C" fn hospedar(_argumento: u64) -> ! {
        match crate::usuario::programa::executar(crate::usuario::exemplo::bytes_do_orfao()) {
            Ok(_) => unreachable!("executar nao retorna em caso de sucesso"),
            Err(_) => crate::fios::terminar(),
        }
    }

    crate::usuario::limpar_ultima_saida();
    let (_, _, saidas_antes) = crate::usuario::estatisticas_de_processo();

    crate::fios::criar("teste-orfao", hospedar, 0)?;

    // Uma saída só: o filho morre de falha, e quem chama `sair` é o pai.
    esperar_ate(
        || crate::usuario::estatisticas_de_processo().2 > saidas_antes,
        600,
    )?;

    match crate::usuario::ultima_saida() {
        Some(codigo) if codigo == crate::usuario::exemplo::CODIGO_DO_ORFAO => Ok(()),
        Some(codigo) if codigo == crate::usuario::exemplo::CODIGO_DE_FALHA_DO_ORFAO => {
            Err("o pai nao soube que o filho tinha sido morto, ou o filho sobreviveu")
        }
        Some(codigo) => {
            crate::log_error!("teste", "o orfao saiu com {}", codigo);
            Err("o orfao saiu com um codigo que nao e de ninguem")
        }
        None => Err("nenhum processo saiu"),
    }
}

/// Um filho que terminou e ainda não foi colhido fica de pé até a colheita.
///
/// # O que esta regra custa, e por que ela existe assim mesmo
///
/// Uma vaga de fio — das dezesseis — e o espaço de endereços do filho, presos
/// entre a saída dele e a pergunta do pai. É caro, e é o preço de a resposta
/// existir: o que resta de um processo morto é um número, e o coletor
/// recolhendo a vaga antes da pergunta destruiria a única cópia dele.
///
/// O caso afirma o outro lado da regra, que é o que a torna segura: assim que
/// o pai colhe, o zumbi vai embora. Sem isso, "guardar até a pergunta" viraria
/// "guardar para sempre" — e dezesseis processos que bifurcassem deixariam a
/// tabela cheia.
///
/// # O que este caso não pega, medido
///
/// A regra em si. Apagando a condição do zumbi de [`crate::fios`], o coletor
/// volta a recolher o filho antes da pergunta — e **este caso continua
/// passando**, porque a janela entre a saída do filho e a passada do coletor
/// dura um tique, e a sondagem aqui é apertada o bastante para enxergar o
/// zumbi dentro dela. Quem reprova é o caso do paciente, que pergunta depois
/// e não acha mais ninguém.
///
/// Os dois casos são complementares e nenhum dos dois sozinho basta: este vê
/// o estado, aquele vê a consequência.
fn fios_zumbi_espera_a_colheita_e_some_depois_dela() -> Resultado {
    extern "C" fn hospedar(_argumento: u64) -> ! {
        match crate::usuario::programa::executar(crate::usuario::exemplo::bytes_do_paciente()) {
            Ok(_) => unreachable!("executar nao retorna em caso de sucesso"),
            Err(_) => crate::fios::terminar(),
        }
    }

    let (_, zumbis_antes) = crate::fios::colheita();
    if zumbis_antes != 0 {
        return Err("a tabela ja tinha zumbi antes do caso comecar");
    }

    let (_, _, saidas_antes) = crate::usuario::estatisticas_de_processo();
    crate::fios::criar("teste-zumbi", hospedar, 0)?;

    // O filho sai primeiro e o pai fica esperando: existe uma janela em que a
    // tabela tem exatamente um zumbi. Ela é curta — o pai acorda no mesmo
    // instante —, então a sondagem tem de ser apertada.
    let viu_zumbi = esperar_ate(|| crate::fios::colheita().1 > 0, 600).is_ok();

    esperar_ate(
        || crate::usuario::estatisticas_de_processo().2 >= saidas_antes + 2,
        600,
    )?;

    if !viu_zumbi {
        return Err("o filho morto nunca apareceu como zumbi");
    }

    // E depois da colheita ele some. O coletor roda a cada tique, então damos
    // alguns a ele — o que não pode é o zumbi ficar.
    esperar_ate(|| crate::fios::colheita().1 == 0, 600)
        .map_err(|_| "o zumbi continuou na tabela depois de colhido")
}

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
    use crate::usuario::descritores::padrao as descritor;
    use crate::usuario::{despachar, erro, numero};

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

/// Clonar não copia página nenhuma, e o pai fica tão protegido quanto o filho.
///
/// # O que este caso vê que o anterior não vê
///
/// [`memoria_clonar_copia_o_conteudo`] prova que os dois espaços ficam
/// independentes. Ele passa igualmente bem com cópia integral e com cópia na
/// escrita — e passava, antes de a segunda existir. O que ele não pergunta é
/// **quanto custou**, e é aí que mora a diferença inteira.
///
/// Aqui a conta é explícita: um clone de `PAGINAS` páginas pode gastar
/// tabelas de tradução, mas não pode gastar uma página de dados. Se gastar,
/// o `fork` voltou a copiar tudo — e nada mais no sistema teria notado.
///
/// # A direção que se esquece
///
/// O caso escreve **no pai** depois de clonar, e confere que o filho não viu.
/// É a metade que falta em quase toda primeira implementação de cópia na
/// escrita: tirar a escrita do filho é óbvio, porque o filho é o novo; tirar
/// a escrita do pai não é, porque o pai é quem está rodando e tudo continua
/// funcionando até ele encostar na própria memória.
fn memoria_clonar_compartilha_sem_copiar() -> Resultado {
    use crate::arch::{self, Permissoes};

    const ALVO: u64 = crate::usuario::BASE;
    const PAGINAS: u64 = 8;
    const MARCA_ORIGINAL: u64 = 0x5A5A_0000_0000_0000;
    const MARCA_DO_PAI: u64 = 0xBEBE_0000_0000_0000;

    let privada = arch::ENTRADA_PRIVADA as usize;
    let kernel = arch::espaco_do_kernel();

    arch::sem_interrupcoes(|| {
        // O balanço do alocador cobre as duas metades da contagem de donos: o
        // que o `fork` compartilhou, o que as escritas separaram em cópias
        // novas, e o que as duas mortes precisam devolver. Um dono anotado e
        // nunca solto não produz sintoma em lugar nenhum — produz um frame
        // que o alocador nunca mais entrega, e só esta subtração o mostra.
        let (livres_no_inicio, _) = crate::frames::estatisticas();
        let original = crate::paginacao::Espaco::novo(privada)?;

        // SAFETY: as raízes vêm de `Espaco::novo` e carregam as entradas de
        // topo do kernel; voltamos ao espaço do kernel antes de largar
        // qualquer uma delas.
        unsafe {
            arch::trocar_espaco(original.raiz());
            for i in 0..PAGINAS {
                let endereco = ALVO + i * arch::TAMANHO_PAGINA;
                crate::paginacao::mapear_novo(endereco, Permissoes::DADOS_USUARIO)?;
                core::ptr::write_volatile(endereco as *mut u64, MARCA_ORIGINAL | i);
            }

            // Medido **depois** de montar o original: o que interessa é o
            // custo do clone, e não o do espaço que ele clona.
            let (livres_antes, _) = crate::frames::estatisticas();
            let clone = crate::paginacao::Espaco::clonar_o_ativo(privada)?;
            let (livres_depois, _) = crate::frames::estatisticas();

            // O pai escreve **antes** de o filho ser lido. Numa cópia na
            // escrita correta, esta escrita tira uma cópia particular para o
            // pai e deixa o frame original com o filho.
            for i in 0..PAGINAS {
                core::ptr::write_volatile(
                    (ALVO + i * arch::TAMANHO_PAGINA) as *mut u64,
                    MARCA_DO_PAI | i,
                );
            }

            arch::trocar_espaco(clone.raiz());
            let mut intrusas = 0;
            for i in 0..PAGINAS {
                let lido =
                    core::ptr::read_volatile((ALVO + i * arch::TAMANHO_PAGINA) as *const u64);
                if lido != (MARCA_ORIGINAL | i) {
                    intrusas += 1;
                }
            }

            arch::trocar_espaco(kernel);
            drop(clone);
            drop(original);

            if intrusas > 0 {
                crate::log_error!(
                    "teste",
                    "{} das {} paginas do filho mudaram quando o pai escreveu",
                    intrusas,
                    PAGINAS
                );
                return Err("escrever no pai alterou o filho: o pai ficou gravavel");
            }

            // As tabelas de tradução do clone são frames de verdade e saem da
            // mesma conta, então o teto não é zero. Mas oito páginas de dados
            // cabem numa tabela de folha só, e o caminho até ela tem um nível
            // por tabela: bem abaixo de `PAGINAS`.
            let gastos = livres_antes.saturating_sub(livres_depois);
            if gastos as u64 >= PAGINAS {
                crate::log_error!(
                    "teste",
                    "clonar {} paginas custou {} frames",
                    PAGINAS,
                    gastos
                );
                return Err("o clone copiou as paginas em vez de compartilha-las");
            }

            let (livres_no_fim, _) = crate::frames::estatisticas();
            if livres_no_fim != livres_no_inicio {
                crate::log_error!(
                    "teste",
                    "{} frames livres antes do fork, {} depois das duas mortes",
                    livres_no_inicio,
                    livres_no_fim
                );
                return Err("o fork deixou frames para tras");
            }
            Ok(())
        }
    })
}

/// Um frame compartilhado só volta ao alocador quando o último dono o solta.
///
/// # Por que a contagem merece um caso que não passa por espaço nenhum
///
/// Porque o erro que ela existe para impedir não tem sintoma perto de onde
/// acontece. Um frame devolvido cedo demais continua legível e gravável por
/// quem ainda o usa — até o alocador entregá-lo a outro dono, em outro
/// momento, para outra coisa. O que aparece é corrupção num lugar que nunca
/// tocou no `fork`.
///
/// Exercitar [`crate::frames::compartilhar`] e [`crate::frames::soltar`]
/// direto, sem tabelas de página no meio, é o que separa "a contagem está
/// certa" de "o `fork` funciona" — duas perguntas que um caso de ponta a
/// ponta responde juntas e não sabe distinguir quando falha.
fn memoria_frame_compartilhado_sobrevive_ao_primeiro_dono() -> Resultado {
    let frame = crate::frames::alocar().ok_or("sem frame para o caso")?;

    if crate::frames::donos(frame) != 1 {
        crate::frames::liberar(frame);
        return Err("um frame recem-alocado devia ter um dono");
    }

    if !crate::frames::compartilhar(frame) || !crate::frames::compartilhar(frame) {
        crate::frames::liberar(frame);
        return Err("compartilhar um frame alocado devia ser aceito");
    }
    if crate::frames::donos(frame) != 3 {
        crate::frames::liberar(frame);
        return Err("a contagem de donos nao acompanhou os compartilhamentos");
    }

    // Os dois primeiros soltam sem devolver: é a afirmação central. Cada um
    // numa variável própria, e não num `||`: o curto-circuito faria a segunda
    // chamada não acontecer no dia em que a primeira passasse a devolver
    // `true` — e o caso denunciaria o erro deixando o frame com um dono a
    // mais, que é o oposto do que ele existe para provar.
    let primeiro = crate::frames::soltar(frame);
    let segundo = crate::frames::soltar(frame);
    if primeiro || segundo {
        return Err("o frame voltou ao alocador antes do ultimo dono");
    }
    if crate::frames::esta_livre(frame) {
        return Err("o frame voltou ao alocador antes do ultimo dono");
    }
    if crate::frames::donos(frame) != 1 {
        return Err("sobrou dono demais depois de dois soltarem");
    }

    if !crate::frames::soltar(frame) {
        return Err("o ultimo a soltar devia devolver o frame");
    }
    if !crate::frames::esta_livre(frame) {
        return Err("o frame nao voltou ao alocador depois do ultimo dono");
    }

    // A segunda metade é o que acontece quando alguém devolve ao alocador um
    // frame que **ainda tinha dono**. É engano — o caminho certo é `soltar` —
    // e `liberar` o denuncia no log. O que não pode acontecer é a contagem
    // sobreviver: o próximo dono do frame nasceria com um sócio que ele nunca
    // teve, e a primeira escrita dele iria para uma cópia que ninguém lê.
    let enganado = crate::frames::alocar().ok_or("sem frame para a segunda metade")?;
    if !crate::frames::compartilhar(enganado) {
        crate::frames::liberar(enganado);
        return Err("compartilhar um frame alocado devia ser aceito");
    }
    crate::frames::liberar(enganado);

    // O alocador não promete devolver o mesmo endereço na chamada seguinte:
    // a busca recomeça na palavra do bitmap que acabou de mudar e entrega o
    // primeiro bit livre dela, que pode ser outro. São 64 frames por palavra,
    // então recolher até 64 basta para reencontrar aquele — e todos voltam
    // logo abaixo.
    let mut recolhidos = [0u64; 64];
    let mut quantos = 0;
    let mut reciclado = None;
    while quantos < recolhidos.len() {
        let Some(outro) = crate::frames::alocar() else {
            break;
        };
        recolhidos[quantos] = outro;
        quantos += 1;
        if outro == enganado {
            reciclado = Some(crate::frames::donos(outro));
            break;
        }
    }
    for outro in &recolhidos[..quantos] {
        crate::frames::liberar(*outro);
    }

    match reciclado {
        None => return Err("o frame devolvido nao voltou a circulacao"),
        Some(1) => {}
        Some(donos) => {
            crate::log_error!("teste", "o frame reciclado nasceu com {} donos", donos);
            return Err("a contagem de donos sobreviveu a volta ao alocador");
        }
    }

    // Um frame livre não tem dono. Responder `1` aqui faria quem decide pela
    // contagem concluir que tem exclusividade sobre memória que o alocador
    // está prestes a entregar a outro.
    if crate::frames::donos(frame) != 0 {
        return Err("um frame livre nao devia ter dono");
    }

    // Compartilhar um frame **livre** é o pedido mais perigoso que a função
    // recebe: aceitar faria o próximo dono nascer com um sócio que ele nunca
    // teve, e a primeira escrita dele iria para uma cópia que ninguém lê.
    if crate::frames::compartilhar(frame) {
        return Err("compartilhar um frame livre foi aceito");
    }
    Ok(())
}

/// O filho morre sem levar as páginas do pai.
///
/// # A falha que não faz barulho
///
/// Quando o filho é desmontado, o percurso que devolve as tabelas dele chega
/// nas folhas — e as folhas, desde a cópia na escrita, são frames que o
/// **pai** também usa. Devolvê-las ao alocador não quebra nada na hora: o pai
/// continua lendo e escrevendo normalmente, porque o frame ainda está lá.
/// Quebra quando o alocador entrega aquele frame a outra coisa, em outro
/// momento, e as duas passam a escrever uma por cima da outra.
///
/// Por isso o caso não se contenta com "o conteúdo do pai sobreviveu": ele
/// pergunta ao alocador se os frames continuam ocupados. É a única pergunta
/// que distingue "está certo" de "ainda não deu tempo de dar errado".
fn memoria_filho_morto_nao_leva_as_paginas_do_pai() -> Resultado {
    use crate::arch::{self, Permissoes};

    const ALVO: u64 = crate::usuario::BASE;
    const PAGINAS: u64 = 6;
    const MARCA: u64 = 0xF110_0000_0000_0000;

    let privada = arch::ENTRADA_PRIVADA as usize;
    let kernel = arch::espaco_do_kernel();

    arch::sem_interrupcoes(|| {
        let original = crate::paginacao::Espaco::novo(privada)?;
        let mut frames = [0u64; PAGINAS as usize];

        // SAFETY: as raízes vêm de `Espaco::novo` e de `clonar_o_ativo`, e
        // carregam as entradas de topo do kernel; voltamos ao espaço do
        // kernel antes de largar qualquer uma delas.
        unsafe {
            arch::trocar_espaco(original.raiz());
            for i in 0..PAGINAS {
                let endereco = ALVO + i * arch::TAMANHO_PAGINA;
                frames[i as usize] =
                    crate::paginacao::mapear_novo(endereco, Permissoes::DADOS_USUARIO)?;
                core::ptr::write_volatile(endereco as *mut u64, MARCA | i);
            }

            let clone = crate::paginacao::Espaco::clonar_o_ativo(privada)?;

            arch::trocar_espaco(kernel);
            drop(clone);
            arch::trocar_espaco(original.raiz());

            let mut soltos = 0;
            for frame in frames {
                if crate::frames::esta_livre(frame) {
                    soltos += 1;
                }
            }

            let mut perdidas = 0;
            for i in 0..PAGINAS {
                let lido =
                    core::ptr::read_volatile((ALVO + i * arch::TAMANHO_PAGINA) as *const u64);
                if lido != (MARCA | i) {
                    perdidas += 1;
                }
            }

            arch::trocar_espaco(kernel);
            drop(original);

            if soltos > 0 {
                crate::log_error!(
                    "teste",
                    "{} dos {} frames do pai voltaram ao alocador com a morte do filho",
                    soltos,
                    PAGINAS
                );
                return Err("desmontar o filho devolveu frames que o pai ainda usa");
            }
            if perdidas > 0 {
                return Err("o conteudo do pai nao sobreviveu a morte do filho");
            }
            Ok(())
        }
    })
}

/// Só uma página gravável pode virar cópia na escrita.
///
/// # Por que a recusa é a parte importante
///
/// A resolução da marca **devolve a escrita** à página. Uma página de código,
/// somente leitura e executável, marcada por engano, viraria gravável na
/// primeira tentativa de escrever nela — e o `W^X` do processo teria caído
/// por um caminho que ninguém percorre de propósito.
///
/// O `fork` de hoje não comete esse engano: ele só marca o que o processo já
/// enxergava como gravável. O caso existe para o próximo chamador, que ainda
/// não foi escrito e não terá como saber sozinho que a marca carrega essa
/// consequência.
fn memoria_marca_recusa_pagina_somente_leitura() -> Resultado {
    use crate::arch::{self, Permissoes};

    const GRAVAVEL: u64 = crate::usuario::BASE;
    const SO_LEITURA: u64 = crate::usuario::BASE + crate::arch::TAMANHO_PAGINA;

    const APENAS_LEITURA: Permissoes = Permissoes {
        escrita: false,
        executavel: false,
        dispositivo: false,
        usuario: true,
    };

    let privada = arch::ENTRADA_PRIVADA as usize;
    let kernel = arch::espaco_do_kernel();

    arch::sem_interrupcoes(|| {
        let espaco = crate::paginacao::Espaco::novo(privada)?;

        // SAFETY: a raiz veio de `Espaco::novo` e carrega as entradas de topo
        // do kernel; voltamos ao espaço do kernel antes de largá-la.
        let desfecho = unsafe {
            arch::trocar_espaco(espaco.raiz());

            crate::paginacao::mapear_novo(GRAVAVEL, Permissoes::DADOS_USUARIO)?;

            let frame = crate::paginacao::mapear_novo(SO_LEITURA, Permissoes::DADOS_USUARIO)?;
            arch::desmapear(SO_LEITURA)?;
            arch::mapear_frame(SO_LEITURA, frame, APENAS_LEITURA)?;

            let marcou_gravavel = arch::marcar_copia_na_escrita(GRAVAVEL);
            let virou_marcada = arch::copia_na_escrita_em(GRAVAVEL).is_some();
            // Marcar de novo é o caso do neto, e precisa ser aceito sem
            // mudar nada: a página já saiu de gravável na primeira vez.
            let remarcou = arch::marcar_copia_na_escrita(GRAVAVEL);

            let marcou_so_leitura = arch::marcar_copia_na_escrita(SO_LEITURA);
            let so_leitura_ficou_marcada = arch::copia_na_escrita_em(SO_LEITURA).is_some();

            arch::trocar_espaco(kernel);
            (
                marcou_gravavel,
                virou_marcada,
                remarcou,
                marcou_so_leitura,
                so_leitura_ficou_marcada,
            )
        };
        drop(espaco);

        let (marcou, virou, remarcou, recusou, vazou) = desfecho;
        if marcou.is_err() {
            return Err("marcar uma pagina gravavel foi recusado");
        }
        if !virou {
            return Err("a pagina gravavel nao ficou marcada");
        }
        if remarcou.is_err() {
            return Err("remarcar uma pagina ja marcada foi recusado");
        }
        if recusou.is_ok() || vazou {
            return Err("uma pagina somente leitura virou copia na escrita");
        }
        Ok(())
    })
}

/// Sem ninguém com quem dividir, resolver a marca não tira cópia nenhuma.
///
/// # O caso que paga o `fork` barato
///
/// Bifurcar e o filho sair logo em seguida é o que quase todo programa faz.
/// Nesse caminho o pai fica com o espaço inteiro marcado e nenhum sócio, e a
/// primeira escrita em cada página só precisa desfazer a marca. Tirar uma
/// cópia ali seria alocar um frame, copiar 4 KiB e devolver o original —
/// trabalho cujo resultado é bit a bit o estado inicial.
///
/// O caso mede pelos contadores porque é a única forma de ver a diferença: o
/// conteúdo e as permissões ficam idênticos dos dois jeitos, e um `fork` que
/// copiasse sempre passaria em todos os outros casos desta suíte.
fn memoria_copia_na_escrita_nao_copia_sem_socio() -> Resultado {
    use crate::arch::{self, Permissoes};

    const ALVO: u64 = crate::usuario::BASE;
    const PAGINAS: u64 = 4;

    let privada = arch::ENTRADA_PRIVADA as usize;
    let kernel = arch::espaco_do_kernel();

    arch::sem_interrupcoes(|| {
        let original = crate::paginacao::Espaco::novo(privada)?;

        // SAFETY: a raiz veio de `Espaco::novo` e carrega as entradas de topo
        // do kernel; voltamos ao espaço do kernel antes de largá-la.
        unsafe {
            arch::trocar_espaco(original.raiz());
            for i in 0..PAGINAS {
                crate::paginacao::mapear_novo(
                    ALVO + i * arch::TAMANHO_PAGINA,
                    Permissoes::DADOS_USUARIO,
                )?;
            }

            let clone = crate::paginacao::Espaco::clonar_o_ativo(privada)?;

            // O filho morre sem nunca ter rodado. Agora o pai é o único dono
            // de tudo, e as marcas continuam lá.
            arch::trocar_espaco(kernel);
            drop(clone);
            arch::trocar_espaco(original.raiz());

            let (_, resolvidas_antes, copiadas_antes) =
                crate::paginacao::estatisticas_de_copia_na_escrita();

            for i in 0..PAGINAS {
                core::ptr::write_volatile((ALVO + i * arch::TAMANHO_PAGINA) as *mut u64, i);
            }

            let (_, resolvidas, copiadas) = crate::paginacao::estatisticas_de_copia_na_escrita();
            arch::trocar_espaco(kernel);
            drop(original);

            // Sem esta metade o caso passaria de graça: zero resoluções e
            // zero cópias satisfariam a comparação seguinte, e é exatamente
            // o que se veria se as páginas nunca tivessem sido marcadas.
            if resolvidas - resolvidas_antes != PAGINAS {
                crate::log_error!(
                    "teste",
                    "{} escritas produziram {} resolucoes",
                    PAGINAS,
                    resolvidas - resolvidas_antes
                );
                return Err("as paginas do pai nao ficaram marcadas depois do fork");
            }
            if copiadas != copiadas_antes {
                crate::log_error!(
                    "teste",
                    "{} copias para um dono so",
                    copiadas - copiadas_antes
                );
                return Err("resolver com um dono so tirou copia a toa");
            }
            Ok(())
        }
    })
}

/// O neto de um `fork` nasce com a memória de dados gravável.
///
/// # O caso que só aparece na segunda geração
///
/// Depois do primeiro `fork`, as páginas do filho estão marcadas e **sem** o
/// bit de escrita. Bifurcá-lo de novo é o momento em que um clone que leia só
/// o descritor erra: ele copia "somente leitura" para o neto, que nasce com
/// os dados protegidos e morre na primeira escrita — longe do `fork` que
/// causou, e com uma falha de página que parece um erro do programa.
///
/// A primeira geração não vê isso. O pai original tem o bit ligado, e ler o
/// descritor dá a resposta certa por acidente.
fn memoria_fork_do_fork_mantem_a_escrita() -> Resultado {
    use crate::arch::{self, Permissoes};

    const ALVO: u64 = crate::usuario::BASE;
    const MARCA_DO_AVO: u64 = 0xA0A0_A0A0_A0A0_A0A0;
    const MARCA_DO_NETO: u64 = 0x0E70_0E70_0E70_0E70;

    let privada = arch::ENTRADA_PRIVADA as usize;
    let kernel = arch::espaco_do_kernel();

    arch::sem_interrupcoes(|| {
        let avo = crate::paginacao::Espaco::novo(privada)?;

        // SAFETY: as três raízes vêm de `Espaco::novo` ou de `clonar_o_ativo`
        // e carregam as entradas de topo do kernel; voltamos ao espaço do
        // kernel antes de largar qualquer uma delas.
        unsafe {
            arch::trocar_espaco(avo.raiz());
            crate::paginacao::mapear_novo(ALVO, Permissoes::DADOS_USUARIO)?;
            core::ptr::write_volatile(ALVO as *mut u64, MARCA_DO_AVO);

            let filho = crate::paginacao::Espaco::clonar_o_ativo(privada)?;

            // O neto é clonado **de dentro do filho**, que é onde as páginas
            // já estão marcadas.
            arch::trocar_espaco(filho.raiz());
            let neto = crate::paginacao::Espaco::clonar_o_ativo(privada)?;

            arch::trocar_espaco(neto.raiz());
            let herdado = core::ptr::read_volatile(ALVO as *const u64);
            core::ptr::write_volatile(ALVO as *mut u64, MARCA_DO_NETO);
            let escrito = core::ptr::read_volatile(ALVO as *const u64);

            arch::trocar_espaco(avo.raiz());
            let no_avo = core::ptr::read_volatile(ALVO as *const u64);

            arch::trocar_espaco(kernel);
            drop(neto);
            drop(filho);
            drop(avo);

            if herdado != MARCA_DO_AVO {
                return Err("o neto nao herdou o conteudo do avo");
            }
            if escrito != MARCA_DO_NETO {
                return Err("o neto nao conseguiu escrever na propria memoria");
            }
            if no_avo != MARCA_DO_AVO {
                return Err("a escrita do neto alcancou o avo");
            }
            Ok(())
        }
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

/// O espaço de um processo morto volta ao alocador sem que ninguém peça.
///
/// # O que mudou, e por que isto precisa de um caso
///
/// O espaço de endereços morre no `Drop` do fio que o hospeda, e por muito
/// tempo esse `Drop` só acontecia quando **outra** criação escolhia a vaga do
/// morto. Num kernel que roda um processo de cada vez isso quase não aparece;
/// num que bifurca, a tabela fica com até dezesseis espaços retidos sem
/// nenhum dono vivo, e o sintoma não é uma falha — é memória que some.
///
/// O caso mede exatamente a diferença: cria um fio que carrega um programa,
/// espera ele morrer, e **não cria mais nada**. Se o alocador não voltar ao
/// número de antes sozinho, não há coletor.
///
/// # A metade que impede o caso de passar de graça
///
/// Um caso que só compare o antes e o depois passa igualmente bem se o fio
/// nunca tiver ocupado nada. Por isso o próprio fio anota quantos frames
/// havia livres **enquanto ele estava vivo**: a comparação com esse número é
/// o que prova que houve o que recolher. Anotar de fora seria uma corrida —
/// o coletor pode desmontá-lo antes de a suíte olhar.
fn fios_coletor_recolhe_o_espaco_do_processo_morto() -> Resultado {
    static PRONTO: AtomicBool = AtomicBool::new(false);
    static LIVRES_COM_ELE_VIVO: AtomicU64 = AtomicU64::new(0);

    extern "C" fn efemero(_argumento: u64) -> ! {
        // Um fio que hospeda um processo segura bem mais que a própria
        // pilha: a raiz de tradução, as tabelas e todas as páginas do
        // programa.
        if crate::usuario::programa::carregar(crate::usuario::exemplo::bytes()).is_err() {
            crate::fios::terminar()
        }

        let (livres, _) = crate::frames::estatisticas();
        LIVRES_COM_ELE_VIVO.store(livres as u64, SeqCst);
        PRONTO.store(true, SeqCst);
        crate::fios::terminar()
    }

    PRONTO.store(false, SeqCst);
    LIVRES_COM_ELE_VIVO.store(0, SeqCst);

    // Drena o que os casos anteriores deixaram, para a medida começar de um
    // estado conhecido. Duas voltas vazias seguidas, e não uma: um fio que
    // estivesse cedendo a vez neste instante ainda não está recolhível, e
    // uma volta só o perderia para depois da medida.
    //
    // Chamar `recolher_terminados` daqui também é o que mantém a função
    // chamável de fora do coletor — se só ele a chamasse, ela seria um
    // detalhe dele em vez de uma operação do módulo.
    let mut vazias = 0;
    let limite = crate::tempo::ticks().saturating_add(100);
    while vazias < 2 && crate::tempo::ticks() < limite {
        if crate::fios::recolher_terminados() == 0 {
            vazias += 1;
        } else {
            vazias = 0;
        }
        crate::fios::ceder();
    }

    let (livres_antes, _) = crate::frames::estatisticas();
    let recolhidos_antes = crate::fios::recolhidos();

    crate::fios::criar("teste-processo-efemero", efemero, 0)?;
    esperar_ate(|| PRONTO.load(SeqCst), 200)?;

    // O ponto do caso: daqui em diante a suíte não cria nada nem recolhe
    // nada. Antes do coletor, esta espera terminava no teto.
    esperar_ate(|| crate::fios::recolhidos() > recolhidos_antes, 200)?;

    let (livres_depois, _) = crate::frames::estatisticas();
    let com_ele_vivo = LIVRES_COM_ELE_VIVO.load(SeqCst);

    if com_ele_vivo >= livres_antes as u64 {
        crate::log_error!(
            "teste",
            "{} frames livres antes, {} com o fio vivo",
            livres_antes,
            com_ele_vivo
        );
        return Err("o fio nao chegou a ocupar nada, e o caso nao mediria nada");
    }

    if livres_depois != livres_antes {
        crate::log_error!(
            "teste",
            "{} frames livres antes, {} com o fio vivo, {} depois de recolhido",
            livres_antes,
            com_ele_vivo,
            livres_depois
        );
        return Err("o coletor nao devolveu tudo que o processo morto ocupava");
    }
    Ok(())
}

/// O coletor não recolhe o fio que está executando.
///
/// # A única forma de provar isto é ficar de pé no chão que ele desmontaria
///
/// A vaga do fio atual é pulada mesmo quando ele já está marcado como
/// encerrado, e o motivo é concreto: um fio que chamou `sair` **continua
/// executando** sobre a própria pilha de kernel até ceder a vez. Recolhê-lo
/// desmapearia essa pilha por baixo dos quadros que estão nela, e a
/// instrução seguinte morreria numa falha que não aponta para lugar nenhum.
///
/// O caso constrói exatamente essa situação: um fio se marca encerrado e,
/// ainda rodando, pede a coleta. Com a guarda, ele sobrevive e registra que
/// passou por ali. Sem ela, a máquina não chega ao fim da suíte — que é o
/// desfecho honesto, porque é literalmente o que aconteceria.
///
/// Medido: apagando a comparação com a vaga atual, o kernel morre aqui com
/// um *double fault* — a falha de pilha tentando empilhar o quadro da falha
/// de pilha, que é a assinatura exata de um `rsp` apontando para o nada.
fn fios_coletor_nao_recolhe_quem_esta_de_pe() -> Resultado {
    static SOBREVIVEU: AtomicBool = AtomicBool::new(false);

    extern "C" fn suicida(_argumento: u64) -> ! {
        crate::fios::marcar_terminado(None);

        // Daqui até o `descansar` este fio está marcado como encerrado e
        // ainda é o fio atual — a janela que a guarda protege. Quantos
        // outros fios saíram na passada não interessa ao caso: o que ele
        // afirma é que **este** não saiu.
        crate::fios::recolher_terminados();

        // Escrever numa variável estática, e não numa local, é de propósito:
        // a local moraria na pilha que a coleta teria desmapeado, e o caso
        // mediria o próprio acidente em vez de sobreviver a ele. Mas a
        // chamada acima já usou a pilha à vontade, então chegar nesta linha
        // é a prova.
        SOBREVIVEU.store(true, SeqCst);

        crate::fios::descansar()
    }

    SOBREVIVEU.store(false, SeqCst);
    crate::fios::criar("teste-suicida", suicida, 0)?;
    esperar_ate(|| SOBREVIVEU.load(SeqCst), 200)?;
    Ok(())
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
                    &mut |pagina| {
                        // A pergunta é sobre o que o **processo** pode fazer,
                        // e não sobre o bit de escrita do descritor. Depois
                        // de um `fork` os dois deixam de ser a mesma coisa:
                        // uma página de cópia na escrita tem a escrita
                        // desligada na tabela e volta a ser gravável na
                        // primeira tentativa. Contar pelo bit daria um `W^X`
                        // que parece intacto justamente no caso em que ele
                        // poderia ter sido perdido.
                        let gravavel = pagina.gravavel_para_o_processo();
                        if pagina.permissoes.executavel {
                            EXECUTAVEIS.fetch_add(1, SeqCst);
                        }
                        if gravavel {
                            GRAVAVEIS.fetch_add(1, SeqCst);
                        }
                        if gravavel && pagina.permissoes.executavel {
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
/// O anel zero não consegue executar uma página de usuário.
///
/// # A proteção que existia numa arquitetura só
///
/// O ARM põe `PXN` em toda página de usuário desde sempre, e o comentário
/// que faz isso diz que é "a mesma proteção que o x86 chama de SMEP". Não
/// era: o x86 deste kernel nunca tocou no `CR4`, nem aqui nem no
/// iniciador. A afirmação de paridade estava no código e a paridade não.
///
/// A diferença é concreta. Um ponteiro de função corrompido ou um salto
/// calculado sobre dado do usuário levava o kernel a executar o código do
/// processo **com privilégio total** — enquanto no ARM a mesma coisa é uma
/// falha de permissão na instrução seguinte.
///
/// # Por que este caso afirma o bit, e não o desvio
///
/// Porque provar a proteção de verdade exige saltar para uma página de
/// usuário a partir do anel zero, e o desfecho disso é uma falha fatal. O
/// kernel tem como declarar uma falha esperada — é assim que o estouro de
/// pilha é testado —, mas esse mecanismo **encerra o emulador**, então só
/// cabe um caso desses por execução, e a vaga já é do estouro de pilha.
///
/// Sobra afirmar o bit: com a CPU oferecendo SMEP, o `CR4` tem de estar com
/// ele ligado ao fim do boot. É falsificável — apagando a linha que o liga,
/// este caso reprova — e é tudo que se consegue afirmar sem gastar a única
/// falha fatal da rodada.
///
/// O ARM não entra: lá a proteção é por bit de página, aplicada em
/// `bits_de` a cada mapeamento, e quem a exercita é todo caso que entra em
/// ring 3.
fn x86_anel_zero_nao_executa_pagina_de_usuario() -> Resultado {
    #[cfg(not(target_arch = "x86_64"))]
    {
        crate::log_info!("teste", "no ARM a mesma protecao e o PXN, por pagina");
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    {
        let (tem, ligado) = crate::arch::atual::protecao_de_execucao();
        if !tem {
            // Não é aprovação: é a máquina dizendo que não tem como oferecer
            // a proteção. Fica dito no log, porque uma linha destas numa
            // execução de CI quer dizer que este caso parou de afirmar algo.
            crate::log_warn!("teste", "esta cpu nao oferece SMEP; nada a afirmar");
            return Ok(());
        }
        if !ligado {
            return Err("a cpu oferece SMEP e o kernel nao o ligou");
        }
        Ok(())
    }
}

/// Ninguém registra uma linha de log com a trava de outro na mão.
///
/// # O travamento que este caso existe para impedir
///
/// Quatro APIs deste kernel entregam um callback **segurando a trava
/// delas**, e com as interrupções mascaradas: [`crate::log::ultimos`] com o
/// anel, `machine::com_regioes` com o mapa, `pci::com_dispositivos` com o
/// inventário e `irq::com_contadores` com os nomes das linhas.
///
/// Um callback que registre uma linha dali de dentro trava o núcleo. O
/// `Mutex` de spin não é reentrante, ninguém pode soltá-lo porque as
/// interrupções estão mascaradas, e não há outro núcleo para socorrer. Não
/// é um travamento provável — é um travamento **total**, na primeira vez.
///
/// # Por que ele ainda não aconteceu, e por que isso não basta
///
/// Porque todos os callbacks de hoje obedecem: os drivers copiam o que
/// acharam para uma local e registram depois; os comandos do agente
/// escrevem numa porta que já vem travada de quem os chamou. A regra é
/// seguida por unanimidade e não estava escrita em lugar nenhum — que é
/// exatamente como ela sobrevive até alguém escrever o callback óbvio.
///
/// Este caso a escreve de um jeito que não depende de ninguém ler: as
/// quatro APIs declaram o escopo com [`crate::log::SobTrava`], `registrar`
/// conta quem desobedeceu, e aqui o número tem de ser zero.
///
/// `fios::com_inscricoes` mostra a saída melhor, e é a razão de ela não
/// entrar nesta lista: ela monta um retrato sob a trava e chama o callback
/// **fora** dela. Onde isso cabe, dispensa a regra.
fn log_ninguem_registra_sob_trava_alheia() -> Resultado {
    // Uma volta por cada uma das quatro, para que o caso exercite os escopos
    // em vez de só ler um contador que ninguém mexeu.
    crate::log::ultimos(8, crate::log::Level::Trace, |_| {});
    crate::machine::com_regioes(|_| {});
    crate::pci::com_dispositivos(|_| {});
    crate::irq::com_contadores(|_, _, _| {});

    let quantos = crate::log::registros_sob_trava();
    if quantos != 0 {
        crate::log_error!(
            "teste",
            "{} linha(s) registradas de dentro de um callback travado",
            quantos
        );
        return Err("alguem registrou log com a trava de outro na mao");
    }
    Ok(())
}

/// A checagem de estouro aritmético está ligada nesta compilação.
///
/// # Por que um caso, e num kernel
///
/// Porque o padrão do Rust em release é **dar a volta**: uma soma que não
/// cabe vira um número menor, sem aviso. Num programa comum isso é uma conta
/// errada; aqui é um tamanho que vira índice fora da faixa e um endereço que
/// aponta para memória de outra pessoa, com o sintoma aparecendo longe da
/// causa. O perfil de release liga a checagem de propósito, e este caso é o
/// que impede que ela suma sem ninguém notar.
///
/// # Duas tentativas de conferir isso pelo binário, e por que as duas falharam
///
/// A primeira procurava a mensagem `attempt to add with overflow` nos bytes
/// do ELF. Desligando a checagem, a mensagem **continua lá**: as
/// dependências e a própria `core` a carregam, e o `rustc` emite uma cópia
/// só que todos os pontos referenciam.
///
/// A segunda procurava o símbolo `panic_const_add_overflow`, que de fato
/// some do binário de produção quando a checagem sai — medido, 6.483.896
/// bytes com ele contra 6.401.400 sem. Só que na compilação de teste ele
/// aparece de qualquer jeito, vindo de outro lugar do link. Contar tampouco
/// serve: o número muda por motivos que não são este.
///
/// A resposta certa é a do próprio compilador. `cfg!(overflow_checks)` não
/// é uma pista sobre o artefato, é o que o `rustc` sabe sobre a compilação
/// que ele está fazendo — e é exato nos dois perfis.
fn kernel_checagem_de_estouro_ligada() -> Resultado {
    if cfg!(overflow_checks) {
        return Ok(());
    }
    Err("esta compilacao da a volta em vez de parar quando uma conta nao cabe")
}

/// Um fio parado dorme de verdade com as interrupções mascaradas, e acorda.
///
/// # Por que este caso existe
///
/// Os dois caminhos que estacionam um fio — ele terminou, ou espera um filho
/// — são alcançados **de dentro de uma chamada de sistema**, e no x86 o
/// `syscall` chega com `IF` limpo por causa do `SFMask`. Um `hlt` ali dorme
/// até um NMI, e girar no lugar dele gira até o fim do mundo: o timer não
/// chega nos dois casos. [`crate::arch::dormir_parado`] existe para isso.
///
/// # A primeira versão deste caso não testava nada, e a mutação provou
///
/// Ela exigia só que a função **voltasse** com a máscara intacta. Trocando a
/// implementação pelo `esperar_interrupcao` de antes — que com `IF` limpo
/// cai num `spin_loop`, ou seja, uma instrução e pronto —, o caso continuou
/// passando: girar também volta, e também mantém a máscara. A afirmação não
/// distinguia dormir de não fazer nada.
///
/// O que distingue é uma interrupção ter sido **atendida**. No x86 dormir
/// exige ligar as interrupções, então quem dorme de verdade sai do sono com
/// pelo menos uma servida, e [`crate::irq::total`] sobe. Com o `spin_loop`
/// ela não sobe, e o caso reprova.
///
/// # Por que o ARM afirma menos, e não é desleixo
///
/// Porque lá `wfi` acorda com a interrupção **pendente e mascarada** — ele
/// não a entrega. O fio dorme, acorda e segue com a máscara na mão, sem
/// handler nenhum ter rodado: `irq::total` não sobe nem quando está tudo
/// certo. Exigir o mesmo número dos dois lados seria exigir do ARM uma
/// consequência que a instrução dele não tem.
///
/// Sobra o que vale nos dois: a função volta, e a máscara volta com ela. É
/// a metade fraca, e está dito que é.
fn arch_dormir_parado_acorda_mascarado() -> Resultado {
    let irqs_antes = crate::irq::total();

    let mascarado_dentro = crate::arch::sem_interrupcoes(|| {
        // Se esta chamada não voltar, a suíte estoura o teto. É o ponto.
        crate::arch::dormir_parado();
        crate::arch::interrupcoes_habilitadas()
    });

    if mascarado_dentro {
        return Err("dormir_parado devolveu o controle com as interrupcoes ligadas");
    }
    if !crate::arch::interrupcoes_habilitadas() {
        return Err("a regiao mascarada nao devolveu as interrupcoes ao sair");
    }

    // A metade falsificável, só onde ela existe. Ver o cabeçalho.
    #[cfg(target_arch = "x86_64")]
    if crate::irq::total() == irqs_antes {
        crate::log_error!("teste", "irqs antes e depois: {}", irqs_antes);
        return Err("dormir_parado voltou sem nenhuma interrupcao ter sido atendida");
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = irqs_antes;

    Ok(())
}

/// Quantos registros de um subsistema contêm um trecho.
///
/// Existe para os casos que afirmam que **alguma coisa foi dita**. Contar
/// antes e depois, em vez de só procurar, é o que distingue a linha que
/// este caso provocou de uma igual que outro caso deixou no anel.
///
/// Hoje só o caso do device tree a usa, e ele só existe no ARM.
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
fn contar_no_log(subsistema: &str, trecho: &str) -> usize {
    let mut quantos = 0;
    crate::log::ultimos(256, crate::log::Level::Trace, |r| {
        if r.subsistema == subsistema && r.mensagem().contains(trecho) {
            quantos += 1;
        }
    });
    quantos
}

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
    // Primeiro, e não junto dos outros do compositor: ele confere que a
    // camada do console adotou o que o boot desenhou, e os casos de console
    // redesenham o banner — depois deles, a camada teria a faixa de acento
    // com ou sem a adoção.
    Caso {
        nome: "compositor: o console e a camada de baixo",
        f: compositor_o_console_e_a_camada_de_baixo,
    },
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
        nome: "rpc: recusa parametro nao declarado",
        f: protocolo_recusa_parametro_nao_declarado,
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
        nome: "fdt: ignora propriedade menor que uma celula",
        f: fdt_ignora_propriedade_menor_que_uma_celula,
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
        nome: "console: o texto chega ao framebuffer",
        f: console_texto_chega_ao_framebuffer,
    },
    Caso {
        nome: "console: quebra na borda e rola no pe",
        f: console_quebra_na_borda_e_rola,
    },
    Caso {
        nome: "console: rolar leva a linha de comando",
        f: console_rolar_leva_a_linha_de_comando,
    },
    Caso {
        nome: "console: o log humano chega a tela",
        f: console_log_humano_chega_a_tela,
    },
    Caso {
        nome: "teclado: o codigo vira o caractere certo",
        f: teclado_codigo_vira_caractere,
    },
    Caso {
        nome: "teclado: shift muda a letra e depois solta",
        f: teclado_shift_muda_e_solta,
    },
    Caso {
        nome: "teclado: soltar nao digita de novo",
        f: teclado_soltar_nao_digita,
    },
    Caso {
        nome: "usuario: programas compilados rodam",
        f: usuario_programas_compilados_rodam,
    },
    Caso {
        nome: "eventos: o canal dorme, entrega e recusa",
        f: eventos_canal_dorme_entrega_e_recusa,
    },
    Caso {
        nome: "usb: o relatorio hid vira teclas",
        f: usb_relatorio_hid_vira_teclas,
    },
    Caso {
        nome: "console: a linha vira nome e parametros",
        f: console_linha_vira_nome_e_parametros,
    },
    Caso {
        nome: "vfs: o caminho chega ao conteudo do arquivo",
        f: vfs_caminho_chega_ao_conteudo,
    },
    Caso {
        nome: "vfs: recusa o que nao da para resolver",
        f: vfs_recusa_o_que_nao_resolve,
    },
    Caso {
        nome: "vfs: a montagem mais longa ganha",
        f: vfs_montagem_mais_longa_ganha,
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
        nome: "irq: linha acima do teto vai a parte",
        f: irq_linha_acima_do_teto_vai_para_o_contador_separado,
    },
    Caso {
        nome: "log: conta o que nao coube",
        f: log_conta_o_que_nao_coube,
    },
    Caso {
        nome: "frames: nunca entrega o frame zero",
        f: frames_nunca_entrega_o_frame_zero,
    },
    Caso {
        nome: "tela: recusa geometria incoerente",
        f: tela_recusa_geometria_incoerente,
    },
    Caso {
        nome: "tela: o framebuffer esta mapeado no espaco do kernel",
        f: tela_esta_mapeada_no_espaco_do_kernel,
    },
    Caso {
        nome: "paginacao: frame reciclado vem zerado",
        f: paginacao_frame_reciclado_vem_zerado,
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
        nome: "heap: volta ao zero depois de estilhacar",
        f: heap_volta_ao_zero_depois_de_estilhacar,
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
        nome: "machine: o mapa do boot coube inteiro",
        f: machine_o_mapa_do_boot_coube_inteiro,
    },
    Caso {
        nome: "machine: funde so vizinhas do mesmo tipo",
        f: machine_funde_so_vizinhas_do_mesmo_tipo,
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
        nome: "memoria: clonar compartilha sem copiar",
        f: memoria_clonar_compartilha_sem_copiar,
    },
    Caso {
        nome: "memoria: frame compartilhado sobrevive ao primeiro dono",
        f: memoria_frame_compartilhado_sobrevive_ao_primeiro_dono,
    },
    Caso {
        nome: "memoria: filho morto nao leva as paginas do pai",
        f: memoria_filho_morto_nao_leva_as_paginas_do_pai,
    },
    Caso {
        nome: "memoria: a marca recusa pagina somente leitura",
        f: memoria_marca_recusa_pagina_somente_leitura,
    },
    Caso {
        nome: "memoria: copia na escrita nao copia sem socio",
        f: memoria_copia_na_escrita_nao_copia_sem_socio,
    },
    Caso {
        nome: "memoria: fork do fork mantem a escrita",
        f: memoria_fork_do_fork_mantem_a_escrita,
    },
    Caso {
        nome: "memoria: espaco destruido devolve tudo",
        f: memoria_espaco_destruido_devolve_tudo,
    },
    Caso {
        nome: "fios: o coletor recolhe o espaco do processo morto",
        f: fios_coletor_recolhe_o_espaco_do_processo_morto,
    },
    Caso {
        nome: "fios: o coletor nao recolhe quem esta de pe",
        f: fios_coletor_nao_recolhe_quem_esta_de_pe,
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
        nome: "usuario: espera o filho e colhe o codigo dele",
        f: usuario_espera_o_filho_e_colhe_o_codigo,
    },
    Caso {
        nome: "fios: o zumbi espera a colheita e some depois dela",
        f: fios_zumbi_espera_a_colheita_e_some_depois_dela,
    },
    Caso {
        nome: "arch: dormir parado acorda com as interrupcoes mascaradas",
        f: arch_dormir_parado_acorda_mascarado,
    },
    Caso {
        nome: "fdt: busca que para no meio avisa",
        f: fdt_busca_que_para_no_meio_avisa,
    },
    Caso {
        nome: "fdt: o relato diz para que era a busca",
        f: fdt_o_relato_do_percurso_diz_para_que_era,
    },
    Caso {
        nome: "mmio: mapeamento que falha no meio desfaz tudo",
        f: mmio_mapeamento_que_falha_no_meio_desfaz_tudo,
    },
    Caso {
        nome: "gpt: cabecalho absurdo e recusado",
        f: gpt_cabecalho_absurdo_e_recusado,
    },
    Caso {
        nome: "grafico: o dano recorta nas bordas",
        f: grafico_dano_recorta_nas_bordas,
    },
    Caso {
        nome: "grafico: o dano une",
        f: grafico_dano_une,
    },
    Caso {
        nome: "grafico: atualizar leva so o dano, nos quatro formatos",
        f: grafico_atualizar_leva_so_o_dano,
    },
    Caso {
        nome: "grafico: dano hostil nao escreve",
        f: grafico_dano_hostil_nao_escreve,
    },
    Caso {
        nome: "grafico: superficie devolve os frames",
        f: grafico_superficie_devolve_os_frames,
    },
    Caso {
        nome: "grafico: superficie que falha no meio desfaz",
        f: grafico_superficie_que_falha_no_meio_desfaz,
    },
    Caso {
        nome: "grafico: a faixa reaproveita e funde",
        f: grafico_a_faixa_reaproveita_e_funde,
    },
    Caso {
        nome: "grafico: soltar superficies devolve a faixa",
        f: grafico_soltar_superficies_devolve_a_faixa,
    },
    Caso {
        nome: "compositor: a camada de cima vence",
        f: compositor_a_camada_de_cima_vence,
    },
    Caso {
        nome: "compositor: mover nao deixa rastro",
        f: compositor_mover_nao_deixa_rastro,
    },
    Caso {
        nome: "compositor: ordem de empilhamento",
        f: compositor_ordem_de_empilhamento,
    },
    Caso {
        nome: "compositor: escrever debaixo nao vaza",
        f: compositor_escrever_debaixo_nao_vaza,
    },
    Caso {
        nome: "compositor: camada na borda",
        f: compositor_camada_na_borda,
    },
    Caso {
        nome: "compositor: transparencia",
        f: compositor_transparencia,
    },
    Caso {
        nome: "agente: ve as camadas",
        f: agente_ve_as_camadas,
    },
    Caso {
        nome: "barra: esta no topo",
        f: barra_esta_no_topo,
    },
    Caso {
        nome: "barra: o relogio anda",
        f: barra_o_relogio_anda,
    },
    Caso {
        nome: "barra: press do agente limpa",
        f: barra_press_do_agente_limpa,
    },
    Caso {
        nome: "barra: F1 da pessoa pressiona",
        f: barra_f1_da_pessoa_pressiona,
    },
    Caso {
        nome: "barra: limpar guarda a linha",
        f: barra_limpar_guarda_a_linha,
    },
    Caso {
        nome: "video: a tela mora onde o monitor a mostra",
        f: video_a_tela_mora_onde_o_monitor_a_mostra,
    },
    Caso {
        nome: "video: escrever descarrega so o que sujou",
        f: video_escrever_descarrega_so_o_que_sujou,
    },
    Caso {
        nome: "video: superficie apresenta so o dano",
        f: video_superficie_apresenta_so_o_dano,
    },
    Caso {
        nome: "video: anexar memoria fragmentada",
        f: video_anexar_memoria_fragmentada,
    },
    Caso {
        nome: "video: recusa do dispositivo e erro",
        f: video_recusa_do_dispositivo_e_erro,
    },
    Caso {
        nome: "ui: a arvore descreve a tela que existe",
        f: ui_a_arvore_descreve_a_tela_que_existe,
    },
    Caso {
        nome: "ui: o texto da arvore e o que esta na tela",
        f: ui_o_texto_da_arvore_e_o_que_esta_na_tela,
    },
    Caso {
        nome: "ui: apagar apaga na tela e na arvore",
        f: ui_apagar_apaga_na_tela_e_na_arvore,
    },
    Caso {
        nome: "ui: agir pela linha de comando",
        f: ui_agir_pela_linha_de_comando,
    },
    Caso {
        nome: "ui: registro nao parte a linha digitada",
        f: ui_registro_nao_parte_a_linha_digitada,
    },
    Caso {
        nome: "ui: acoes recusadas nao deixam rastro",
        f: ui_acoes_recusadas_nao_deixam_rastro,
    },
    Caso {
        nome: "agente: display.info descreve a pilha",
        f: agente_display_info_descreve_a_pilha,
    },
    Caso {
        nome: "tela: desenhar nao regrediu em ordem de grandeza",
        f: tela_desenhar_nao_regrediu_em_ordem_de_grandeza,
    },
    #[cfg(target_arch = "x86_64")]
    Caso {
        nome: "x86: ninguem gira mascarado esperando interrupcao",
        f: x86_ninguem_gira_mascarado_esperando_interrupcao,
    },
    Caso {
        nome: "usuario: o pai sabe que o filho foi morto",
        f: usuario_pai_sabe_que_o_filho_foi_morto,
    },
    Caso {
        nome: "kernel: a checagem de estouro aritmetico esta ligada",
        f: kernel_checagem_de_estouro_ligada,
    },
    Caso {
        nome: "log: ninguem registra com a trava de outro na mao",
        f: log_ninguem_registra_sob_trava_alheia,
    },
    Caso {
        nome: "x86: o anel zero nao executa pagina de usuario",
        f: x86_anel_zero_nao_executa_pagina_de_usuario,
    },
    Caso {
        nome: "pci: regioes atribuidas nao se sobrepoem",
        f: pci_regioes_atribuidas_nao_se_sobrepoem,
    },
    Caso {
        nome: "disco: le as assinaturas de particionamento",
        f: disco_le_as_assinaturas_de_particionamento,
    },
    Caso {
        nome: "disco: cada setor devolve o seu padrao",
        f: disco_cada_setor_devolve_o_seu_padrao,
    },
    Caso {
        nome: "disco: uma leitura so atravessa varias paginas",
        f: disco_leitura_multipla_atravessa_paginas,
    },
    Caso {
        nome: "particoes: a tabela do disco e a que o disco tem",
        f: particoes_tabela_do_disco,
    },
    Caso {
        nome: "btrfs: o superbloco do disco confere",
        f: btrfs_superbloco_confere,
    },
    Caso {
        nome: "btrfs: recusa um superbloco adulterado",
        f: btrfs_recusa_superbloco_adulterado,
    },
    Caso {
        nome: "btrfs: traduz endereco logico para o disco",
        f: btrfs_traduz_endereco_logico,
    },
    Caso {
        nome: "btrfs: recusa perfil de pedaco que nao sabe montar",
        f: btrfs_recusa_perfil_desconhecido,
    },
    Caso {
        nome: "btrfs: le a raiz da arvore de pedacos",
        f: btrfs_le_a_raiz_dos_pedacos,
    },
    Caso {
        nome: "btrfs: a sucessora de uma chave",
        f: btrfs_sucessora_de_chave,
    },
    Caso {
        nome: "btrfs: o percurso atravessa o vao entre folhas",
        f: btrfs_percurso_atravessa_o_vao_entre_folhas,
    },
    Caso {
        nome: "btrfs: a descida escolhe o filho certo",
        f: btrfs_descida_escolhe_o_filho_certo,
    },
    Caso {
        nome: "btrfs: desce pela arvore de arquivos",
        f: btrfs_desce_pela_arvore_de_arquivos,
    },
    Caso {
        nome: "btrfs: acha inode fora da primeira folha",
        f: btrfs_acha_inode_fora_da_primeira_folha,
    },
    Caso {
        nome: "btrfs: percorre os itens de uma folha",
        f: btrfs_percorre_itens_da_folha,
    },
    Caso {
        nome: "btrfs: o mapa completo alcanca os metadados",
        f: btrfs_mapa_completo_alcanca_metadados,
    },
    Caso {
        nome: "btrfs: a raiz do disco esta montada em /",
        f: btrfs_raiz_montada,
    },
    Caso {
        nome: "btrfs: le arquivo embutido e arquivo com extensao",
        f: btrfs_le_os_dois_tipos_de_arquivo,
    },
    Caso {
        nome: "btrfs: classifica cada tipo de extensao",
        f: btrfs_classifica_cada_extensao,
    },
    Caso {
        nome: "mmu: a identidade do iniciador foi largada",
        f: mmu_identidade_largada,
    },
    Caso {
        nome: "vfs: le a partir de um deslocamento",
        f: vfs_le_a_partir_de_um_deslocamento,
    },
    Caso {
        nome: "descritores: a tabela do processo",
        f: descritores_a_tabela_do_processo,
    },
    Caso {
        nome: "usuario: abre, le e fecha um arquivo do disco",
        f: usuario_abre_le_e_fecha_um_arquivo,
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
    Caso {
        nome: "ponteiro: absoluto e relativo",
        f: ponteiro_absoluto_e_relativo,
    },
    Caso {
        nome: "ponteiro: o cursor segue",
        f: ponteiro_o_cursor_segue,
    },
    Caso {
        nome: "ponteiro: clique no botao",
        f: ponteiro_clique_no_botao,
    },
    Caso {
        nome: "ponteiro: eventos do virtio",
        f: ponteiro_eventos_do_virtio,
    },
    Caso {
        nome: "ponteiro: pacote PS/2",
        f: ponteiro_pacote_ps2,
    },
    Caso {
        nome: "ponteiro: relatorio do mouse USB",
        f: ponteiro_relatorio_usb,
    },
];

// ---------------------------------------------------------------------------
// O disco
// ---------------------------------------------------------------------------

/// A assinatura de um MBR, nos dois últimos bytes do setor zero.
///
/// # Por que ela e não uma assinatura nossa
///
/// Porque o disco de testes deixou de ser um padrão que este projeto inventa
/// e passa a ser montado pelas ferramentas do hospedeiro: `sgdisk`,
/// `mkfs.vfat`, `mkfs.btrfs`. Antes o kernel conferia bytes que o `xtask`
/// tinha escrito — as duas metades do mesmo projeto concordando entre si.
/// Agora ele confere marcas que ferramentas de terceiros produziram, e que
/// existem em qualquer disco particionado do mundo.
///
/// O MBR de proteção existe para que uma ferramenta que não entenda GPT veja
/// o disco como ocupado em vez de vazio. Estes dois bytes são o que ela olha.
const ASSINATURA_DE_MBR: [u8; 2] = [0x55, 0xAA];

/// O que o cabeçalho da GPT traz nos primeiros oito bytes do setor um.
const ASSINATURA_DE_GPT: &[u8] = b"EFI PART";

/// A faixa de setores que a GPT reserva e ninguém usa.
///
/// Do fim das entradas de partição até o começo da primeira. É onde o `xtask`
/// grava o padrão por setor, e a razão de ele ainda existir está em
/// [`marca_do_setor`].
const PADRAO_DE: u64 = 34;
const PADRAO_ATE: u64 = 2047;

/// O byte com que o setor `numero` da faixa reservada é preenchido.
///
/// Deriva do número do setor de propósito. Zeros pareceriam plausíveis em
/// qualquer lugar, e um erro de deslocamento — ler o setor 3 quando se pediu o
/// 4 — passaria despercebido. Com um padrão que muda a cada setor, ler o setor
/// errado é indistinguível de não ler nada.
///
/// É metade de um contrato cujo outro lado está em `xtask/src/main.rs`.
/// Duplicá-lo é o preço de o disco ser gerado por um programa que roda no
/// hospedeiro e lido por outro que roda no hóspede — não há lugar comum onde
/// as duas metades caibam. O que impede a divergência é este teste.
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
fn disco_le_as_assinaturas_de_particionamento() -> Resultado {
    let mut setor = [0u8; crate::virtio::blk::TAMANHO_DO_SETOR];
    let Some(resultado) = crate::virtio::blk::com_o_disco(|d| d.ler_setor(0, &mut setor)) else {
        return Err("nao ha disco nesta maquina");
    };
    resultado?;

    if setor[510..512] != ASSINATURA_DE_MBR {
        crate::log_error!(
            "teste",
            "o setor zero termina com {:#04x} {:#04x}",
            setor[510],
            setor[511]
        );
        return Err("o setor zero nao traz a assinatura do disco");
    }

    // E o setor um, que é o cabeçalho da GPT. Ler o setor zero inteiro não
    // prova que a leitura trouxe os 512 bytes: a assinatura mora nos dois
    // últimos, então um driver que só trouxesse o fim do setor passaria. O
    // cabeçalho seguinte é a marca que mora no **começo** de um setor, e os
    // dois juntos cobrem as duas pontas.
    let Some(resultado) = crate::virtio::blk::com_o_disco(|d| d.ler_setor(1, &mut setor)) else {
        return Err("nao ha disco nesta maquina");
    };
    resultado?;

    if &setor[..ASSINATURA_DE_GPT.len()] != ASSINATURA_DE_GPT {
        crate::log_error!(
            "teste",
            "o setor um comeca com {:#04x} {:#04x} {:#04x} {:#04x}",
            setor[0],
            setor[1],
            setor[2],
            setor[3]
        );
        return Err("o setor um nao traz o cabecalho da GPT");
    }

    Ok(())
}

/// Setores diferentes devolvem conteúdos diferentes, e o certo para cada um.
///
/// Ler o setor zero corretamente ainda seria compatível com um driver que
/// ignora o número do setor e devolve sempre o primeiro. Esta é a verificação
/// que fecha essa porta.
fn disco_cada_setor_devolve_o_seu_padrao() -> Resultado {
    // Todos dentro da faixa reservada da GPT, que é onde o padrão mora — ver
    // [`PADRAO_DE`]. Os escolhidos não são consecutivos de propósito: um erro
    // de um setor para cima ou para baixo é o mais provável, e saltos o tornam
    // visível. As duas pontas da faixa entram porque é nelas que um erro de
    // limite aparece.
    const ALVOS: [u64; 6] = [PADRAO_DE, PADRAO_DE + 1, 100, 999, 1500, PADRAO_ATE];

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

    // Aceitar qualquer erro não bastava, e a mutação mostrou por quê:
    // removendo a conferência de capacidade do driver, o pedido chega ao
    // dispositivo, o dispositivo recusa, e `ler_setor` devolve erro do mesmo
    // jeito. O caso passava sem que a guarda existisse.
    //
    // O que distingue é **quem** recusou, e isso está na mensagem — que não é
    // detalhe interno: é o campo `error` que o agente lê em `disk.read`.
    const POR_CAPACIDADE: &str = "setor alem da capacidade do disco";

    let mut setor = [0u8; crate::virtio::blk::TAMANHO_DO_SETOR];
    let resultado = crate::virtio::blk::com_o_disco(|d| {
        let alem = [
            d.ler_setor(capacidade, &mut setor),
            d.ler_setor(capacidade + 1, &mut setor),
            d.ler_setor(u64::MAX, &mut setor),
        ];
        // E o último setor válido continua legível: uma conferência estrita
        // demais custaria o disco inteiro, e seria pior que a que ela troca.
        let ultimo = d.ler_setor(capacidade - 1, &mut setor);
        (alem, ultimo)
    });

    let Some((alem, ultimo)) = resultado else {
        return Err("nao ha disco nesta maquina");
    };

    for r in alem {
        match r {
            Err(motivo) if motivo == POR_CAPACIDADE => {}
            Err(outro) => {
                crate::log_error!("teste", "recusado por outra razao: {}", outro);
                return Err("quem recusou o setor inexistente nao foi o driver");
            }
            Ok(()) => return Err("o disco aceitou ler um setor que nao existe"),
        }
    }
    if ultimo.is_err() {
        return Err("o disco recusou o ultimo setor valido");
    }
    Ok(())
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
