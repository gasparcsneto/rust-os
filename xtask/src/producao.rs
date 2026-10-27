//! A máquina de verdade: a imagem de produção, as chaves de quem a opera e
//! o cliente com que se fala com ela — ver "Pôr uma máquina em produção" em
//! `docs/OPERACAO.md`.
//!
//! # Por que não a imagem de `cargo xtask build`
//!
//! Aquela é a da bancada, e a marca dela (`/etc/duke/imagem`) diz isso:
//!
//! - a chave do Duke é a de `target/chaves/duke.chave`, a mesma em toda
//!   imagem que esta árvore monta;
//! - os agentes, os administradores, os editores e as fontes de hora são
//!   chaves cujas privadas estão em `target/chaves/` — quem tem a árvore
//!   entra como `sistema` pela porta 4;
//! - a pessoa `dev` tem a senha em `target/chaves/pessoa-dev.senha`;
//! - a política é a da bancada: destinos do emulador (`10.0.2.x`), a serial
//!   e a autoridade local com o papel `sistema`;
//! - a raiz leva a âncora TLS da bancada — a privada dela também está em
//!   `target/` —, as redes da PocketIC com a raiz fixada delas, os módulos
//!   de teste do IC e os arquivos que a suíte lê.
//!
//! A imagem daqui é montada do que o operador traz, e de nada disso: a
//! imagem não leva chave do Duke nenhuma — a identidade nasce no primeiro
//! boot da máquina, selada no TPM dela (ver `kernel/src/selo.rs`); os
//! registros, a política, a rede e as fontes de hora são os do operador,
//! conferidos pelos mesmos leitores do kernel; uma chave da bancada em
//! qualquer arquivo recusa a imagem inteira; e a raiz leva os programas, as
//! âncoras TLS públicas e a rede principal do IC — o que é público e é do
//! produto.
//!
//! # O código num slot, o estado na raiz
//!
//! O disco tem a atualização A/B — ver `docs/ATUALIZACAO.md`. O código vem
//! numa imagem de slot assinada pela chave de atualização de quem publica
//! (`cargo xtask publicar`): o kernel e o pacote — os programas do produto,
//! as âncoras TLS públicas e a rede principal do IC. A raiz leva só o que é
//! da máquina: `/etc/duke` — os registros, a política, a rede, e o registro
//! das chaves de atualização em que ela confia. Uma versão nova troca o
//! slot inteiro e não toca a raiz, o journal, o armazém nem o selo da
//! identidade.
//!
//! # A identidade do Duke
//!
//! Não sai daqui. A máquina a sorteia no primeiro boot, sela no TPM dela e
//! mostra a pública no console — no log do boot e no `system.info`, campo
//! `identity.key` —; o operador a lê ali e a dá aos agentes dele, que a
//! fixam (`cargo xtask operar --duke`). Uma cópia da imagem, ou do disco
//! depois do primeiro boot, não leva identidade que abra noutra máquina —
//! ver "A identidade do Duke" em `docs/OPERACAO.md`. O formato de cada
//! arquivo, a política, o gate, a persistência: os mesmos.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use super::{Arquitetura, aleatorios, icp, tls};

/// Os arquivos do diretório do operador.
const NOME: &str = "nome";
const POLITICA: &str = "politica";
const ADMINISTRADORES: &str = "administradores";
const AGENTES: &str = "agentes";
const PESSOAS: &str = "pessoas";
const TEMPO: &str = "tempo";
const EDITORES: &str = "editores";
const REDE: &str = "rede";
const ATUALIZACAO: &str = "atualizacao";

/// O menor tamanho de senha que o provisionamento aceita.
const MENOR_SENHA: usize = 12;

/// Os programas que a imagem de produção leva: os que o kernel lança no
/// boot (o servidor de janelas e o terminal) e os que operam a rede
/// principal do IC (o gestor de canisters e o `livro`, que confere que ela
/// responde). Os outros de `programas/src/bin` são o outro lado de um caso
/// da suíte ou falam com a bancada — `10.0.2.x`, a PocketIC, o eco TLS — e
/// numa máquina de produção seriam só código a mais que um papel com
/// `process.run` alcança.
pub(crate) const PROGRAMAS_DO_PRODUTO: &[&str] = &["janelas", "terminal", "gestor", "livro"];

/// O material do operador, lido do diretório dele.
pub(crate) struct Operador {
    pub nome: String,
    pub politica: String,
    pub administradores: String,
    pub agentes: String,
    /// O nome, o papel e a senha de cada pessoa — a senha lida do arquivo
    /// que a linha aponta, e que não vai para a imagem.
    pub pessoas: Vec<(String, String, String)>,
    pub tempo: Option<String>,
    pub editores: Option<String>,
    pub rede: Option<String>,
    /// O registro das chaves de atualização: as que podem assinar uma
    /// imagem dos slots desta máquina.
    pub atualizacao: String,
    /// Os textos lidos, pelo nome do arquivo, para a busca das chaves da
    /// bancada.
    textos: Vec<(&'static str, String)>,
}

fn ler(dir: &Path, nome: &str) -> Result<Option<String>, String> {
    match std::fs::read_to_string(dir.join(nome)) {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", dir.join(nome).display())),
    }
}

/// Lê o diretório do operador.
pub(crate) fn ler_o_operador(dir: &Path) -> Result<Operador, String> {
    let obrigatorio = |nome: &str| -> Result<String, String> {
        ler(dir, nome)?.ok_or_else(|| {
            format!(
                "o diretório do operador não tem `{nome}` ({})",
                dir.display()
            )
        })
    };
    let nome = obrigatorio(NOME)?.trim().to_string();
    let politica = obrigatorio(POLITICA)?;
    let administradores = obrigatorio(ADMINISTRADORES)?;
    let atualizacao = obrigatorio(ATUALIZACAO)?;
    let agentes = ler(dir, AGENTES)?.unwrap_or_default();
    let tempo = ler(dir, TEMPO)?;
    let editores = ler(dir, EDITORES)?;
    let rede = ler(dir, REDE)?;
    let mut pessoas = Vec::new();
    let texto_das_pessoas = ler(dir, PESSOAS)?.unwrap_or_default();
    for (n, linha) in texto_das_pessoas.lines().enumerate() {
        let linha = linha.split('#').next().unwrap_or("").trim();
        if linha.is_empty() {
            continue;
        }
        let campos: Vec<&str> = linha.split_ascii_whitespace().collect();
        let [nome, papel, arquivo] = campos[..] else {
            return Err(format!(
                "{PESSOAS}, linha {}: `nome papel arquivo-da-senha`",
                n + 1
            ));
        };
        let senha = std::fs::read_to_string(dir.join(arquivo))
            .map_err(|e| format!("{PESSOAS}, linha {}: a senha de `{nome}`: {e}", n + 1))?;
        let senha = senha.strip_suffix('\n').unwrap_or(&senha).to_string();
        pessoas.push((nome.to_string(), papel.to_string(), senha));
    }
    let mut textos = vec![
        (POLITICA, politica.clone()),
        (ADMINISTRADORES, administradores.clone()),
        (AGENTES, agentes.clone()),
        (ATUALIZACAO, atualizacao.clone()),
    ];
    for (nome, texto) in [(TEMPO, &tempo), (EDITORES, &editores), (REDE, &rede)] {
        if let Some(t) = texto {
            textos.push((nome, t.clone()));
        }
    }
    Ok(Operador {
        nome,
        politica,
        administradores,
        agentes,
        pessoas,
        tempo,
        editores,
        rede,
        atualizacao,
        textos,
    })
}

/// As chaves públicas da bancada desta árvore — de cada privada em
/// `target/chaves/`, a X25519 e a Ed25519 —, com o nome do arquivo. Vazio
/// se a árvore nunca montou uma imagem de desenvolvimento.
fn chaves_da_bancada() -> Vec<([u8; 32], String)> {
    let mut chaves = Vec::new();
    let Ok(entradas) = std::fs::read_dir(super::chaves::diretorio()) else {
        return chaves;
    };
    for entrada in entradas.flatten() {
        let caminho = entrada.path();
        if caminho.extension().is_none_or(|e| e != "chave") {
            continue;
        }
        let Some(privada) = std::fs::read_to_string(&caminho)
            .ok()
            .and_then(|t| sigilo::de_hex(t.trim()))
        else {
            continue;
        };
        let nome = caminho.display().to_string();
        chaves.push((sigilo::publica_de(&privada), nome.clone()));
        chaves.push((sigilo::quorum::publica_de_assinatura(&privada), nome));
    }
    chaves
}

/// Cada sequência de 64 dígitos hexadecimais de `texto`, como chave.
fn chaves_no_texto(texto: &str) -> Vec<[u8; 32]> {
    texto
        .split(|c: char| !c.is_ascii_hexdigit())
        .filter(|p| p.len() == 64)
        .filter_map(sigilo::de_hex)
        .collect()
}

/// Confere o material do operador pelos mesmos leitores do kernel, e contra
/// a bancada. Devolve a política lida.
pub(crate) fn conferir(op: &Operador) -> Result<politica::Politica, String> {
    if !sigilo::registro::nome_valido(&op.nome) {
        return Err(format!(
            "`{NOME}`: `{}` não é um nome de máquina (minúsculas, dígitos, `-`, `_`, `.`, até 32)",
            op.nome
        ));
    }
    // Nada da bancada: a política dela, ou uma chave cuja privada está em
    // `target/chaves/`.
    if op.politica.trim() == politica::PADRAO.trim() {
        return Err(format!(
            "`{POLITICA}` é a política da bancada (politica::PADRAO): destinos do emulador, e a serial com o papel sistema"
        ));
    }
    let da_bancada = chaves_da_bancada();
    for (arquivo, texto) in &op.textos {
        for chave in chaves_no_texto(texto) {
            if let Some((_, de)) = da_bancada.iter().find(|(c, _)| *c == chave) {
                return Err(format!(
                    "`{arquivo}` tem a chave {} da bancada ({de}): a privada dela está em target/, fora da máquina",
                    sigilo::hex(&chave)
                ));
            }
        }
    }

    let politica = politica::Politica::ler(&op.politica)
        .map_err(|e| format!("`{POLITICA}` não se lê: {}", e.motivo()))?;
    let existe = |papel: &str| politica.papel(papel).is_some();

    // Os administradores: ao menos um, cada um com a chave de assinatura do
    // quórum, num papel que a política tem e que é teto.
    let mut administradores = Vec::new();
    for (n, linha) in op.administradores.lines().enumerate() {
        match sigilo::registro::ler_linha_de_administrador(linha) {
            Ok(None) => {}
            Ok(Some((chave, nome, papel, assinatura))) => {
                let papel = papel.ok_or_else(|| {
                    format!("{ADMINISTRADORES}, linha {}: `{nome}` sem papel", n + 1)
                })?;
                if assinatura.is_none() {
                    return Err(format!(
                        "{ADMINISTRADORES}, linha {}: `{nome}` sem a chave de assinatura (ed25519:) do quórum",
                        n + 1
                    ));
                }
                if !existe(papel) {
                    return Err(format!(
                        "{ADMINISTRADORES}, linha {}: o papel `{papel}` não está na política",
                        n + 1
                    ));
                }
                administradores.push((chave, nome.to_string(), papel.to_string()));
            }
            Err(e) => {
                return Err(format!(
                    "{ADMINISTRADORES}, linha {}: {}",
                    n + 1,
                    e.motivo()
                ));
            }
        }
    }
    if administradores.is_empty() {
        return Err(format!(
            "`{ADMINISTRADORES}` não tem ninguém: sem administrador, a máquina não muda quem existe"
        ));
    }
    let mut tetos: Vec<&str> = administradores.iter().map(|(_, _, p)| p.as_str()).collect();
    tetos.sort_unstable();
    tetos.dedup();
    politica
        .conferir_alcance_aos_administradores(&tetos)
        .map_err(|m| format!("a política viola o alcance ao administrador: {m}"))?;
    politica
        .conferir_tetos(&tetos)
        .map_err(|m| format!("a política exerce um teto: {m}"))?;
    for operacao in politica::arquivo::OPERACOES_DE_QUORUM {
        if let Some(q) = politica.quorum(operacao)
            && usize::from(q.n) != administradores.len()
        {
            return Err(format!(
                "o quórum de {operacao} é de {} credenciais, e `{ADMINISTRADORES}` tem {}",
                q.n,
                administradores.len()
            ));
        }
    }

    // Os agentes: cada um num papel da política, que não é teto.
    let mut chaves: Vec<[u8; 32]> = administradores.iter().map(|(c, _, _)| *c).collect();
    let mut nomes: Vec<String> = administradores.iter().map(|(_, n, _)| n.clone()).collect();
    for (n, linha) in op.agentes.lines().enumerate() {
        match sigilo::registro::ler_linha(linha) {
            Ok(None) => {}
            Ok(Some((chave, nome, papel))) => {
                let papel = papel
                    .ok_or_else(|| format!("{AGENTES}, linha {}: `{nome}` sem papel", n + 1))?;
                if !existe(papel) || tetos.contains(&papel) {
                    return Err(format!(
                        "{AGENTES}, linha {}: o papel `{papel}` não está na política, ou é o teto de um administrador",
                        n + 1
                    ));
                }
                chaves.push(chave);
                nomes.push(nome.to_string());
            }
            Err(e) => return Err(format!("{AGENTES}, linha {}: {}", n + 1, e.motivo())),
        }
    }
    let mut ordenadas = chaves.clone();
    ordenadas.sort_unstable();
    if ordenadas.windows(2).any(|w| w[0] == w[1]) {
        return Err("a mesma chave em dois registros de agente ou de administrador".into());
    }

    // As pessoas: um papel da política, que não é teto, e uma senha que se
    // possa chamar assim.
    for (nome, papel, senha) in &op.pessoas {
        if !sigilo::registro::nome_valido(nome) || nomes.contains(nome) {
            return Err(format!(
                "{PESSOAS}: `{nome}` fora da regra dos nomes, ou repetido"
            ));
        }
        nomes.push(nome.clone());
        if !existe(papel) || tetos.contains(&papel.as_str()) {
            return Err(format!(
                "{PESSOAS}: o papel `{papel}` de `{nome}` não está na política, ou é o teto de um administrador"
            ));
        }
        if senha.chars().count() < MENOR_SENHA {
            return Err(format!(
                "{PESSOAS}: a senha de `{nome}` tem menos de {MENOR_SENHA} caracteres"
            ));
        }
    }

    // Os editores: a política só confia em quem o registro tem.
    let mut editores = Vec::new();
    for (n, linha) in op.editores.as_deref().unwrap_or("").lines().enumerate() {
        match sigilo::registro::ler_linha_de_editor(linha) {
            Ok(None) => {}
            Ok(Some((_, nome))) => editores.push(nome.to_string()),
            Err(e) => return Err(format!("{EDITORES}, linha {}: {}", n + 1, e.motivo())),
        }
    }
    for papel in politica.papeis() {
        if let Some(e) = papel.editores.iter().find(|e| !editores.contains(e)) {
            return Err(format!(
                "a política faz `{}` confiar no editor `{e}`, que `{EDITORES}` não tem",
                papel.nome
            ));
        }
    }

    // As fontes de hora, e a política dizendo o mesmo que elas.
    if let Some(texto) = &op.tempo {
        let registro = hora::registro::Registro::ler(texto)
            .map_err(|e| format!("`{TEMPO}` não se lê: {e:?}"))?;
        super::conferir_o_tempo_da_imagem(&registro, &politica)?;
    }

    // Os domínios de assinatura que a política usa existem no registro.
    super::chaves::registro_de_dominios(&politica)?;

    // A rede, pelas regras do kernel.
    if let Some(texto) = &op.rede {
        conferir_a_rede(texto)
            .map_err(|(linha, motivo)| format!("`{REDE}`, linha {linha}: {motivo}"))?;
    }

    // A atualização: ao menos uma chave que assine as imagens dos slots, e
    // o quórum que as instala, com a permissão no papel de quem assina. Uma
    // máquina sem um dos dois boota da imagem do provisionamento e nunca
    // mais troca de versão: a saída seria provisionar de novo, e a chave
    // do Duke, que nasce na imagem, iria junto.
    let chaves_de_atualizacao = registro_de_atualizacao(&op.atualizacao)?;
    if chaves_de_atualizacao.is_empty() {
        return Err(format!(
            "`{ATUALIZACAO}` não tem chave: sem ela, nenhuma imagem dos slots tem autoridade, e nenhuma versão nova se instala"
        ));
    }
    let Some(q) = politica.quorum("system.update") else {
        return Err(
            "a política não tem `quorum system.update`: a máquina não teria como instalar uma versão nova"
                .into(),
        );
    };
    let com_a_permissao = administradores
        .iter()
        .filter(|(_, _, papel)| {
            politica
                .papel(papel)
                .is_some_and(|p| p.tem(politica::Permissao::SystemUpdate))
        })
        .count();
    if com_a_permissao < usize::from(q.m) {
        return Err(format!(
            "o quórum de system.update pede {} credenciais, e só {com_a_permissao} administradores têm system.update no papel",
            q.m
        ));
    }
    Ok(politica)
}

/// As chaves de um registro de atualização — o texto de
/// `/etc/duke/atualizacao`, no formato do de editores —, lidas pelo leitor
/// do kernel: a pública e o nome.
pub(crate) fn registro_de_atualizacao(texto: &str) -> Result<Vec<([u8; 32], String)>, String> {
    let mut chaves = Vec::new();
    for (n, linha) in texto.lines().enumerate() {
        match sigilo::registro::ler_linha_de_editor(linha) {
            Ok(None) => {}
            Ok(Some((chave, nome))) => {
                if chaves
                    .iter()
                    .any(|(c, m): &([u8; 32], String)| *c == chave || m == nome)
                {
                    return Err(format!(
                        "{ATUALIZACAO}, linha {}: a chave ou o nome `{nome}` repetidos",
                        n + 1
                    ));
                }
                chaves.push((chave, nome.to_string()));
            }
            Err(e) => return Err(format!("{ATUALIZACAO}, linha {}: {}", n + 1, e.motivo())),
        }
    }
    Ok(chaves)
}

/// Um IPv4 escrito em quatro números de 0 a 255.
fn ipv4(texto: &str) -> Option<[u8; 4]> {
    let partes: Vec<&str> = texto.split('.').collect();
    if partes.len() != 4 {
        return None;
    }
    let mut ip = [0u8; 4];
    for (byte, parte) in ip.iter_mut().zip(partes) {
        if parte.is_empty() || parte.len() > 3 || !parte.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *byte = parte.parse().ok()?;
    }
    Some(ip)
}

/// Confere `/etc/duke/rede` pelas regras de `kernel/src/rede/configuracao.rs`
/// — é metade de um contrato cuja outra metade é aquele leitor; o que
/// impede a divergência é o cenário da bancada que boota a imagem de
/// produção com a rede e lê o endereço no `net.info`. `Err` com a linha
/// (zero para o arquivo inteiro) e o motivo.
pub(crate) fn conferir_a_rede(texto: &str) -> Result<(), (usize, &'static str)> {
    let de_maquina = |ip: [u8; 4]| ip[0] != 0 && ip[0] != 127 && ip[0] < 224;
    let mascara = |p: u8| {
        if p == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(p))
        }
    };
    let na_sub_rede = |ip: [u8; 4], rede: [u8; 4], p: u8| {
        let m = mascara(p);
        let h = u32::from_be_bytes(ip) & !m;
        de_maquina(ip)
            && u32::from_be_bytes(ip) & m == u32::from_be_bytes(rede) & m
            && h != 0
            && h != !m
    };
    let (mut endereco, mut roteador, mut dns) = (None, None, 0);
    for (n, linha) in texto.lines().enumerate() {
        let n = n + 1;
        let linha = linha.trim();
        if linha.is_empty() || linha.starts_with('#') {
            continue;
        }
        let mut campos = linha.split_ascii_whitespace();
        let chave = campos.next().unwrap_or("");
        let valor = campos.next().ok_or((n, "falta o valor"))?;
        if campos.next().is_some() {
            return Err((n, "um valor so por linha"));
        }
        match chave {
            "endereco" if endereco.is_none() => {
                let (ip, prefixo) = valor
                    .split_once('/')
                    .ok_or((n, "falta o prefixo: a.b.c.d/p"))?;
                let ip = ipv4(ip).ok_or((n, "endereco que nao e IPv4"))?;
                let prefixo: u8 = Some(prefixo)
                    .filter(|p| (1..=2).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|p| p.parse().ok())
                    .filter(|p| (1..=30).contains(p))
                    .ok_or((n, "prefixo fora de 1 a 30"))?;
                if !na_sub_rede(ip, ip, prefixo) {
                    return Err((n, "endereco que nao e de uma maquina nesta sub-rede"));
                }
                endereco = Some((ip, prefixo));
            }
            "endereco" => return Err((n, "dois enderecos")),
            "roteador" if roteador.is_none() => {
                let ip = ipv4(valor)
                    .filter(|ip| de_maquina(*ip))
                    .ok_or((n, "roteador que nao e IPv4 de maquina"))?;
                roteador = Some((ip, n));
            }
            "roteador" => return Err((n, "dois roteadores")),
            "dns" => {
                ipv4(valor)
                    .filter(|ip| de_maquina(*ip))
                    .ok_or((n, "dns que nao e IPv4 de maquina"))?;
                dns += 1;
                if dns > 3 {
                    return Err((n, "servidores de DNS demais"));
                }
            }
            _ => return Err((n, "linha que nao e endereco, roteador nem dns")),
        }
    }
    let (ip, prefixo) = endereco.ok_or((0, "falta o endereco"))?;
    if let Some((r, n)) = roteador
        && (!na_sub_rede(r, ip, prefixo) || r == ip)
    {
        return Err((n, "o roteador nao e outra maquina da sub-rede do endereco"));
    }
    Ok(())
}

/// O registro de pessoas da imagem: cada pessoa com um identificador e um
/// sal sorteados, e o verificador Argon2id da senha.
fn registro_de_pessoas(op: &Operador) -> Result<String, String> {
    let mut texto =
        String::from("# As pessoas que podem entrar pelo console. So o verificador da senha.\n");
    for (nome, papel, senha) in &op.pessoas {
        let sorteio = aleatorios()?;
        let mut id = [0u8; 8];
        id.copy_from_slice(&sorteio[..8]);
        let mut sal = [0u8; 16];
        sal.copy_from_slice(&sorteio[8..24]);
        let credencial =
            sigilo::credencial::nova(senha.as_bytes(), sal, sigilo::credencial::Custo::PADRAO)
                .map_err(|e| format!("a credencial de `{nome}`: {}", e.motivo()))?;
        texto.push_str(&sigilo::pessoas::linha(&sigilo::pessoas::Pessoa {
            id: sigilo::pessoas::IdPessoa(id),
            nome: nome.clone(),
            papel: papel.clone(),
            estado: sigilo::pessoas::Estado::Ativa,
            credencial,
        }));
    }
    Ok(texto)
}

/// As redes do IC da imagem de produção: só a principal, com a raiz da
/// imagem — nenhuma da PocketIC da bancada.
fn redes_de_producao() -> String {
    let (nome, host) = icp::REDE_PRINCIPAL;
    format!(
        "# A rede principal do IC: os API boundary nodes, pelo DNS.\nrede {nome} https://{host} dns bls:{}\n",
        icp::raiz_da_rede_principal()
    )
}

/// Os arquivos da raiz de uma imagem de produção: os do operador e a marca
/// com o id `id` — só `/etc/duke`, o que é da máquina, e nenhuma chave do
/// Duke: ela nasce no primeiro boot. O código e os dados públicos vêm no
/// pacote do slot — ver [`arquivos_do_pacote`] —, e uma versão nova os
/// troca sem tocar aqui.
pub(crate) fn arquivos_da_raiz(
    op: &Operador,
    politica: &politica::Politica,
    id: [u8; 16],
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let marca = sigilo::imagem::Marca {
        tipo: sigilo::imagem::Tipo::Producao,
        nome: op.nome.clone(),
        id,
    };
    let mut arquivos = vec![
        (
            "etc/duke/imagem".to_string(),
            sigilo::imagem::escrever(&marca).into_bytes(),
        ),
        (
            "etc/duke/politica".to_string(),
            op.politica.clone().into_bytes(),
        ),
        (
            "etc/duke/administradores".to_string(),
            op.administradores.clone().into_bytes(),
        ),
        (
            "etc/duke/agentes".to_string(),
            op.agentes.clone().into_bytes(),
        ),
        (
            "etc/duke/privado/pessoas".to_string(),
            registro_de_pessoas(op)?.into_bytes(),
        ),
        (
            "etc/duke/editores".to_string(),
            op.editores.clone().unwrap_or_default().into_bytes(),
        ),
        (
            "etc/duke/dominios".to_string(),
            super::chaves::registro_de_dominios(politica)?.into_bytes(),
        ),
        (
            "etc/duke/atualizacao".to_string(),
            op.atualizacao.clone().into_bytes(),
        ),
    ];
    if let Some(t) = &op.tempo {
        arquivos.push(("etc/duke/tempo".to_string(), t.clone().into_bytes()));
    }
    if let Some(r) = &op.rede {
        arquivos.push(("etc/duke/rede".to_string(), r.clone().into_bytes()));
    }
    Ok(arquivos)
}

/// O pacote de uma imagem de produção para `arch`: os programas do
/// produto, as âncoras TLS públicas e a rede principal do IC — o que é
/// público e é do produto, e que uma versão nova troca junto com o kernel.
pub(crate) fn arquivos_do_pacote(arch: Arquitetura) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut arquivos = vec![
        (tls::PUBLICAS_NA_IMAGEM.to_string(), tls::publicas()?),
        (
            icp::REDES_NA_IMAGEM.to_string(),
            redes_de_producao().into_bytes(),
        ),
    ];
    let prefixo = format!("programas/{}/", arch.nome());
    arquivos.extend(
        super::programas_do_disco()?
            .into_iter()
            .filter(|(nome, _)| {
                nome.strip_prefix(&prefixo)
                    .is_some_and(|p| PROGRAMAS_DO_PRODUTO.contains(&p))
            }),
    );
    for programa in PROGRAMAS_DO_PRODUTO {
        let nome = format!("{prefixo}{programa}");
        if !arquivos.iter().any(|(n, _)| *n == nome) {
            return Err(format!(
                "o programa `{programa}` do produto nao compilou para {}",
                arch.nome()
            ));
        }
    }
    Ok(arquivos)
}

/// Os bytes do pacote de [`arquivos_do_pacote`].
pub(crate) fn pacote_do_produto(arch: Arquitetura) -> Result<Vec<u8>, String> {
    let arquivos = arquivos_do_pacote(arch)?;
    let lista: Vec<(&str, &[u8])> = arquivos
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    atualizacao::pacote::montar(&lista).map_err(|m| format!("o pacote do produto: {m}"))
}

/// O resumo de um arquivo, para o registro do que entrou.
fn resumo(bytes: &[u8]) -> String {
    use sha2::Digest;
    sigilo::hex_de(&sha2::Sha256::digest(bytes))
}

/// `cargo xtask provisionar <diretório> --imagem <arquivo>`: o disco de
/// produção de `arch`, do material do operador, em `saida` (ou
/// `target/producao/<nome>-<arch>`): a raiz com `/etc/duke`, o iniciador na
/// ESP, e no slot A a imagem publicada por `cargo xtask publicar` —
/// conferida aqui como o kernel a confere, com o registro de atualização
/// do operador.
pub(crate) fn provisionar(
    arch: Arquitetura,
    release: bool,
    dir: &Path,
    saida: Option<&Path>,
    imagem_do_slot: &Path,
) -> Result<ExitCode, String> {
    let op = ler_o_operador(dir)?;
    let politica = conferir(&op)?;
    let bytes_do_slot =
        std::fs::read(imagem_do_slot).map_err(|e| format!("{}: {e}", imagem_do_slot.display()))?;
    let slot = super::slots::conferir_imagem(&bytes_do_slot, &op.atualizacao, arch)
        .map_err(|m| format!("a imagem {}: {m}", imagem_do_slot.display()))?;
    let saida = saida.map(Path::to_path_buf).unwrap_or_else(|| {
        super::raiz_do_projeto()
            .join("target")
            .join("producao")
            .join(format!("{}-{}", op.nome, arch.nome()))
    });
    // Uma imagem nunca por cima de outra: o registro dela, e o id da marca
    // com que a máquina dela se apresenta, sumiriam.
    if saida.join("duke.img").exists() {
        return Err(format!(
            "{} já tem uma imagem: escolha outra saída, ou apague a anterior sabendo que o registro dela some junto",
            saida.display()
        ));
    }
    std::fs::create_dir_all(&saida)
        .map_err(|e| format!("não foi possível criar {}: {e}", saida.display()))?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&aleatorios()?[..16]);
    let arquivos = arquivos_da_raiz(&op, &politica, id)?;

    // A montagem leva os verificadores das senhas das pessoas — na árvore
    // da raiz e na imagem —: só o dono os lê, e eles somem também quando
    // algo falha no meio.
    let montagem = saida.join("montagem");
    so_do_dono(&montagem, true)?;
    let montada = (|| -> Result<PathBuf, String> {
        let imagem = montagem.join("duke.img");
        let efi = montar_o_disco(arch, release, &imagem, &arquivos, &bytes_do_slot)?;
        std::fs::rename(&imagem, saida.join("duke.img"))
            .map_err(|e| format!("não foi possível mover a imagem: {e}"))?;
        Ok(efi)
    })();
    let _ = std::fs::remove_dir_all(&montagem);
    let efi = montada?;

    let mut registro = format!(
        "# A imagem de producao `{}`, para {}: o que entrou nela.\n\
         # A identidade do Duke nao entra: nasce no primeiro boot, selada no TPM, e a publica aparece no console (system.info, identity.key).\n\
         id {}\niniciador {}\n\
         slot-a {} {}\nmanifesto {}\nversao {}\ngeracao {}\nassinada-por {}\nkernel {} bytes\npacote {} bytes\n",
        op.nome,
        arch.nome(),
        sigilo::hex_de(&id),
        resumo(&std::fs::read(&efi).map_err(|e| e.to_string())?),
        imagem_do_slot.display(),
        resumo(&bytes_do_slot),
        sigilo::hex(&slot.resumo),
        slot.versao,
        slot.geracao,
        slot.chave,
        slot.kernel,
        slot.pacote,
    );
    for (nome, bytes) in &arquivos {
        // O registro de pessoas não entra: o resumo dos verificadores não
        // os protege de quem testa palpites.
        if nome.starts_with("etc/duke/privado/") {
            registro.push_str(&format!("{nome} (privado)\n"));
        } else {
            registro.push_str(&format!("{nome} {}\n", resumo(bytes)));
        }
    }
    std::fs::write(saida.join("registro.txt"), registro)
        .map_err(|e| format!("não foi possível gravar o registro: {e}"))?;
    println!(
        "[xtask] imagem de produção `{}` ({}) em {}\n\
         [xtask] no slot A: a versão {} (geração {}), assinada por `{}`\n\
         [xtask] o que entrou: {}\n\
         [xtask] a identidade do Duke nasce no primeiro boot, selada no TPM da máquina: leia a pública no console (system.info, identity.key) e a dê aos agentes, que a fixam\n\
         [xtask] a imagem leva os verificadores das senhas das pessoas: guarde-a só com o dono",
        op.nome,
        arch.nome(),
        saida.join("duke.img").display(),
        slot.versao,
        slot.geracao,
        slot.chave,
        saida.join("registro.txt").display()
    );
    Ok(ExitCode::SUCCESS)
}

/// O disco de produção em `imagem`: a raiz com `arquivos`, só do dono; o
/// iniciador de `arch` na ESP; e `slot` — uma imagem de slot já conferida
/// — no slot A, com o controle apontando para ela e o B vazio. Devolve o
/// `.efi` do iniciador. É o que o `provisionar` grava e o que a bancada de
/// persistência boota.
pub(crate) fn montar_o_disco(
    arch: Arquitetura,
    release: bool,
    imagem: &Path,
    arquivos: &[(String, Vec<u8>)],
    slot: &[u8],
) -> Result<PathBuf, String> {
    let c = atualizacao::cabecalho::ler(slot).map_err(|m| format!("a imagem do slot: {m}"))?;
    super::montar_disco(imagem, arquivos, super::Extras::Nenhum)?;
    so_do_dono(imagem, false)?;
    let efi = super::build_do_iniciador(arch, release)?;
    super::instalar_so_o_iniciador(arch, imagem, &efi)?;
    super::slots::escrever_imagem_no_slot_a(
        imagem,
        slot,
        atualizacao::manifesto::resumo_do_manifesto(c.manifesto),
    )?;
    Ok(efi)
}

/// `cargo xtask publicar <chave> <versão> <geração>`: a imagem de slot de
/// uma versão do produto para `arch` — o kernel de produção, o pacote do
/// produto e o manifesto, assinado pela chave de atualização em `chave` —,
/// em `saida` (ou `target/atualizacao/<versão>-<arch>.slot`). É a mesma
/// imagem que o `provisionar` põe no slot A de uma máquina nova e que o
/// `operar --encenar` escreve no slot inativo de uma que já roda.
///
/// A imagem não tem segredo: o manifesto diz o que ela é, e a assinatura,
/// quem a publicou. Quem a instala é o quórum da máquina.
pub(crate) fn publicar(
    arch: Arquitetura,
    release: bool,
    chave: &Path,
    versao: &str,
    geracao: &str,
    saida: Option<&Path>,
) -> Result<ExitCode, String> {
    let privada = chave_de_atualizacao(chave)?;
    if !atualizacao::manifesto::versao_valida(versao) {
        return Err(format!(
            "`{versao}` não é uma versão: de 1 a 32 caracteres de [A-Za-z0-9._+-]"
        ));
    }
    let geracao: u64 = geracao
        .parse()
        .ok()
        .filter(|g| *g >= 1)
        .ok_or_else(|| format!("`{geracao}` não é uma geração: um inteiro de 1 em diante"))?;
    let alvo_do_kernel = super::raiz_do_projeto()
        .join("target")
        .join("producao-kernel");
    let elf = super::compilar_o_kernel(arch, release, &[], Some(&alvo_do_kernel))?;
    let kernel = std::fs::read(super::kernel_para_a_esp(&elf)?)
        .map_err(|e| format!("não foi possível ler o kernel: {e}"))?;
    let pacote = pacote_do_produto(arch)?;
    let imagem = super::slots::imagem(
        &super::slots::Pedido {
            arch,
            kernel: &kernel,
            pacote: &pacote,
            versao,
            geracao,
            estado: (
                super::slots::FORMATO_DO_ESTADO,
                super::slots::FORMATO_DO_ESTADO,
            ),
        },
        &privada,
    )?;
    let saida = saida.map(Path::to_path_buf).unwrap_or_else(|| {
        super::raiz_do_projeto()
            .join("target")
            .join("atualizacao")
            .join(format!("{versao}-{}.slot", arch.nome()))
    });
    if let Some(pai) = saida.parent() {
        std::fs::create_dir_all(pai)
            .map_err(|e| format!("não foi possível criar {}: {e}", pai.display()))?;
    }
    std::fs::write(&saida, &imagem.bytes)
        .map_err(|e| format!("não foi possível gravar {}: {e}", saida.display()))?;
    println!(
        "[xtask] a versão {versao} (geração {geracao}) para {} em {}: {} KiB — kernel de {} KiB, pacote de {} KiB\n\
         [xtask] o manifesto, que o quórum assina para instalar: {}\n{}",
        arch.nome(),
        saida.display(),
        imagem.bytes.len() / 1024,
        kernel.len() / 1024,
        pacote.len() / 1024,
        sigilo::hex(&imagem.resumo),
        String::from_utf8_lossy(&imagem.manifesto).trim_end()
    );
    Ok(ExitCode::SUCCESS)
}

/// A privada de uma chave de atualização: o arquivo de
/// `cargo xtask chave atualizacao`, com a semente Ed25519 em hexadecimal.
pub(crate) fn chave_de_atualizacao(arquivo: &Path) -> Result<[u8; 32], String> {
    let texto =
        std::fs::read_to_string(arquivo).map_err(|e| format!("{}: {e}", arquivo.display()))?;
    chave_de_atualizacao_de_texto(&texto).map_err(|e| format!("{}: {e}", arquivo.display()))
}

/// [`chave_de_atualizacao`], do conteúdo do arquivo.
pub(crate) fn chave_de_atualizacao_de_texto(texto: &str) -> Result<[u8; 32], String> {
    sigilo::de_hex(texto.trim()).ok_or_else(|| "não é uma chave de atualização".to_string())
}

/// Deixa `caminho` só para o dono — 0700 num diretório, que é criado se
/// não existe; 0600 num arquivo. É o que se faz com o que leva a privada do
/// Duke.
fn so_do_dono(caminho: &Path, diretorio: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if diretorio {
        std::fs::create_dir_all(caminho)
            .map_err(|e| format!("não foi possível criar {}: {e}", caminho.display()))?;
    }
    let modo = if diretorio { 0o700 } else { 0o600 };
    std::fs::set_permissions(caminho, std::fs::Permissions::from_mode(modo))
        .map_err(|e| format!("não foi possível proteger {}: {e}", caminho.display()))
}

/// Lê uma linha `prefixo <hex>` de um arquivo de chave de administrador.
fn campo_da_chave(texto: &str, prefixo: &str) -> Option<[u8; 32]> {
    texto
        .lines()
        .find_map(|l| l.trim().strip_prefix(prefixo))
        .and_then(|h| sigilo::de_hex(h.trim()))
}

/// A chave de um agente: um arquivo com a privada X25519 em hexadecimal.
pub(crate) fn chave_de_agente(arquivo: &Path) -> Result<[u8; 32], String> {
    let texto =
        std::fs::read_to_string(arquivo).map_err(|e| format!("{}: {e}", arquivo.display()))?;
    chave_de_agente_de_texto(&texto).map_err(|e| format!("{}: {e}", arquivo.display()))
}

/// [`chave_de_agente`], do conteúdo do arquivo.
pub(crate) fn chave_de_agente_de_texto(texto: &str) -> Result<[u8; 32], String> {
    sigilo::de_hex(texto.trim()).ok_or_else(|| "não é uma chave de agente".to_string())
}

/// As duas chaves de um administrador: a privada X25519 da credencial e a
/// Ed25519 com que ela assina um quórum.
pub(crate) fn chave_de_administrador(arquivo: &Path) -> Result<([u8; 32], [u8; 32]), String> {
    let texto =
        std::fs::read_to_string(arquivo).map_err(|e| format!("{}: {e}", arquivo.display()))?;
    chave_de_administrador_de_texto(&texto).map_err(|e| format!("{}: {e}", arquivo.display()))
}

/// [`chave_de_administrador`], do conteúdo do arquivo.
pub(crate) fn chave_de_administrador_de_texto(texto: &str) -> Result<([u8; 32], [u8; 32]), String> {
    match (
        campo_da_chave(texto, "credencial "),
        campo_da_chave(texto, "assinatura "),
    ) {
        (Some(c), Some(a)) => Ok((c, a)),
        _ => {
            Err("não é uma chave de administrador (`credencial <hex>` e `assinatura <hex>`)".into())
        }
    }
}

/// Uma chave nova de `tipo` — `agente`, `administrador`, `editor` ou
/// `atualizacao` —:
/// o conteúdo do arquivo da privada, e a linha do registro que a imagem
/// leva, com o nome do registro.
pub(crate) fn chave_nova(
    tipo: &str,
    nome: &str,
    papel: Option<&str>,
) -> Result<(String, String, &'static str), String> {
    if !sigilo::registro::nome_valido(nome)
        || papel.is_some_and(|p| !sigilo::registro::nome_valido(p))
    {
        return Err(format!(
            "`{nome}` ou o papel fora da regra (minúsculas, dígitos, `-`, `_`, `.`, até 32)"
        ));
    }
    Ok(match (tipo, papel) {
        ("agente", Some(papel)) => {
            let privada = aleatorios()?;
            (
                format!("{}\n", sigilo::hex(&privada)),
                sigilo::registro::linha(&sigilo::publica_de(&privada), nome, Some(papel)),
                AGENTES,
            )
        }
        ("administrador", Some(papel)) => {
            let (credencial, assinatura) = (aleatorios()?, aleatorios()?);
            (
                format!(
                    "credencial {}\nassinatura {}\n",
                    sigilo::hex(&credencial),
                    sigilo::hex(&assinatura)
                ),
                sigilo::registro::linha_de_administrador(
                    &sigilo::publica_de(&credencial),
                    nome,
                    papel,
                    &sigilo::quorum::publica_de_assinatura(&assinatura),
                ),
                ADMINISTRADORES,
            )
        }
        ("editor", None) => {
            let privada = aleatorios()?;
            (
                format!("{}\n", sigilo::hex(&privada)),
                sigilo::registro::linha_de_editor(
                    &sigilo::codigo::publica_do_editor(&privada),
                    nome,
                ),
                EDITORES,
            )
        }
        // A de atualização: assina o manifesto das imagens dos slots, no
        // formato do registro de editores. Não é uma credencial: não entra
        // em porta nenhuma, e não instala nada sozinha — quem instala é o
        // quórum `system.update`.
        ("atualizacao", None) => {
            let privada = aleatorios()?;
            (
                format!("{}\n", sigilo::hex(&privada)),
                sigilo::registro::linha_de_editor(
                    &atualizacao::manifesto::publica_de(&privada),
                    nome,
                ),
                ATUALIZACAO,
            )
        }
        _ => {
            return Err(
                "uso: cargo xtask chave agente|administrador <arquivo> <nome> <papel>, ou chave editor|atualizacao <arquivo> <nome>"
                    .into(),
            );
        }
    })
}

/// `cargo xtask chave <tipo> <arquivo> <nome> [papel]`: uma chave nova,
/// gravada só para o dono, e a linha do registro que a imagem leva.
pub(crate) fn gerar_chave(
    tipo: &str,
    arquivo: &Path,
    nome: &str,
    papel: Option<&str>,
) -> Result<ExitCode, String> {
    let (conteudo, linha, registro) = chave_nova(tipo, nome, papel)?;
    gravar_privada(arquivo, &conteudo)?;
    println!(
        "[xtask] a privada em {} (só o dono lê; ela não vai para a imagem)\n\
         [xtask] a linha para `{registro}` no diretório do operador:\n{}",
        arquivo.display(),
        linha.trim_end()
    );
    Ok(ExitCode::SUCCESS)
}

/// Grava uma privada em `arquivo`, só para o dono, e nunca por cima.
pub(crate) fn gravar_privada(arquivo: &Path, conteudo: &str) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(arquivo)
        .map_err(|e| format!("não foi possível criar {}: {e}", arquivo.display()))?;
    f.write_all(conteudo.as_bytes())
        .map_err(|e| format!("não foi possível escrever {}: {e}", arquivo.display()))
}

/// Quantos bytes cada `update.stage` leva: o maior anexo de um pedido,
/// que é múltiplo do setor.
pub(crate) const PEDACO_DA_ENCENACAO: usize = protocolo::usuario::nativo::MAIOR_ANEXO;
const _: () = assert!(PEDACO_DA_ENCENACAO.is_multiple_of(512));

/// Escreve a imagem de slot `bytes` no slot inativo, um `update.stage` por
/// pedaço, do começo ao fim, e devolve o `update.status` de depois. Nada
/// se instala aqui: a máquina guarda os bytes, e só o quórum
/// `system.update`, com o resumo do manifesto que a resposta diz, arma a
/// versão — conferindo o slot inteiro de novo.
pub(crate) fn encenar(agente: &mut super::AgenteNaPorta, bytes: &[u8]) -> Result<String, String> {
    let c = atualizacao::cabecalho::ler(bytes).map_err(|m| format!("a imagem: {m}"))?;
    let resumo = atualizacao::manifesto::resumo_do_manifesto(c.manifesto);
    for (i, pedaco) in bytes.chunks(PEDACO_DA_ENCENACAO).enumerate() {
        let de = i * PEDACO_DA_ENCENACAO;
        let r = agente.pedir_com_anexo("update.stage", &format!(r#"{{"offset":{de}}}"#), pedaco)?;
        if !r.contains(r#""written":"#) {
            return Err(format!(
                "o update.stage parou no byte {de} de {}\n  {r}",
                bytes.len()
            ));
        }
    }
    let status = agente.pedir("update.status", "{}")?;
    Ok(format!(
        "{status}\n# {} bytes no slot inativo; o manifesto, que o quorum system.update assina: {}",
        bytes.len(),
        sigilo::hex(&resumo)
    ))
}

/// A pública do Duke de `texto`: o hexadecimal que a máquina mostra no
/// console no primeiro boot (`system.info`, `identity.key`), ou o caminho
/// de um arquivo com ele.
fn publica_do_duke(texto: &str) -> Result<[u8; 32], String> {
    sigilo::de_hex(texto.trim())
        .or_else(|| {
            std::fs::read_to_string(texto)
                .ok()
                .and_then(|t| sigilo::de_hex(t.trim()))
        })
        .ok_or_else(|| format!("`{texto}` não é a pública do Duke nem um arquivo com ela"))
}

/// `cargo xtask operar <endereço> <método> [parâmetros]`: um pedido a uma
/// máquina de verdade, pelo canal TCP, como o agente da chave `chave`, com
/// a pública do Duke fixada em `duke`. Com `admin`, o pedido vai como
/// operação administrativa: o desafio, a prova da credencial, e o
/// `admin.execute`. Com `assinaturas`, uma operação de quórum —
/// `admin.revoke` ou `system.update`. Com `imagem`, o `update.stage` da
/// imagem inteira, em pedaços — ver [`encenar`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn operar(
    endereco: &str,
    metodo: &str,
    params: &str,
    chave: &Path,
    duke: &str,
    admin: Option<&Path>,
    assinaturas: &[PathBuf],
    imagem: Option<&Path>,
) -> Result<ExitCode, String> {
    let chave = chave_de_agente(chave)?;
    let duke = publica_do_duke(duke)?;
    let mut agente = super::AgenteNaPorta::conectar_endereco(endereco, &chave, &duke)?;
    let resposta = if let Some(imagem) = imagem {
        if metodo != "update.stage" {
            return Err("--imagem é do update.stage: a imagem vai para o slot inativo".into());
        }
        let bytes = std::fs::read(imagem).map_err(|e| format!("{}: {e}", imagem.display()))?;
        encenar(&mut agente, &bytes)?
    } else if !assinaturas.is_empty() {
        super::quorum_pelo_operador(&mut agente, metodo, params, assinaturas)?
    } else if let Some(admin) = admin {
        let (credencial, _) = chave_de_administrador(admin)?;
        let sessao = agente.pedir("agent.session", "{}")?;
        let sessao: u8 = super::campo_simples(&sessao, "session")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("operar: a sessão não diz o número\n  {sessao}"))?;
        let desafio = agente.pedir("admin.challenge", "{}")?;
        let pedido =
            super::pedido_administrativo_de(&credencial, sessao, &desafio, metodo, params, params)?;
        agente.pedir("admin.execute", &pedido)?
    } else {
        agente.pedir(metodo, params)?
    };
    println!("{resposta}");
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn a_rede_pelas_regras_do_kernel() {
        assert_eq!(
            conferir_a_rede("endereco 192.168.10.5/24\nroteador 192.168.10.1\ndns 9.9.9.9\n"),
            Ok(())
        );
        assert_eq!(conferir_a_rede(""), Err((0, "falta o endereco")));
        assert_eq!(
            conferir_a_rede("endereco 192.168.10.5"),
            Err((1, "falta o prefixo: a.b.c.d/p"))
        );
        assert_eq!(
            conferir_a_rede("endereco 192.168.10.5/31"),
            Err((1, "prefixo fora de 1 a 30"))
        );
        assert_eq!(
            conferir_a_rede("endereco 192.168.10.0/24"),
            Err((1, "endereco que nao e de uma maquina nesta sub-rede"))
        );
        assert_eq!(
            conferir_a_rede("endereco 192.168.10.5/24\nroteador 192.168.11.1"),
            Err((2, "o roteador nao e outra maquina da sub-rede do endereco"))
        );
        assert_eq!(
            conferir_a_rede(
                "endereco 192.168.10.5/24\ndns 1.1.1.1\ndns 2.2.2.2\ndns 3.3.3.3\ndns 4.4.4.4"
            ),
            Err((5, "servidores de DNS demais"))
        );
        assert_eq!(
            conferir_a_rede("endereco 10.0.0.2/8\nmtu 1500"),
            Err((2, "linha que nao e endereco, roteador nem dns"))
        );
    }

    #[test]
    fn os_programas_do_produto_existem() {
        let dir = super::super::raiz_do_projeto().join("programas/src/bin");
        for programa in PROGRAMAS_DO_PRODUTO {
            assert!(
                dir.join(format!("{programa}.rs")).is_file(),
                "o programa `{programa}` do produto nao esta em {}",
                dir.display()
            );
        }
    }

    /// Um diretório de operador válido, num diretório temporário próprio:
    /// a política de exemplo, três administradores, um agente e uma pessoa.
    /// `mudar` ajusta os arquivos antes da leitura.
    fn operador_de_teste(
        caso: &str,
        mudar: impl FnOnce(&Path),
    ) -> Result<politica::Politica, String> {
        operador_lido(caso, mudar).map(|(_, politica)| politica)
    }

    /// [`operador_de_teste`], com o material lido.
    fn operador_lido(
        caso: &str,
        mudar: impl FnOnce(&Path),
    ) -> Result<(Operador, politica::Politica), String> {
        let dir =
            std::env::temp_dir().join(format!("xtask-operador-{caso}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exemplo = super::super::raiz_do_projeto().join("docs/exemplos/producao");
        for nome in [NOME, POLITICA, REDE] {
            std::fs::copy(exemplo.join(nome), dir.join(nome)).unwrap();
        }
        let mut administradores = String::new();
        for nome in ["adm-a", "adm-b", "adm-c"] {
            administradores.push_str(
                &chave_nova("administrador", nome, Some("administrador"))
                    .unwrap()
                    .1,
            );
        }
        std::fs::write(dir.join(ADMINISTRADORES), administradores).unwrap();
        std::fs::write(
            dir.join(AGENTES),
            chave_nova("agente", "operador-1", Some("operador"))
                .unwrap()
                .1,
        )
        .unwrap();
        std::fs::write(dir.join("senha-ana"), "uma senha comprida\n").unwrap();
        std::fs::write(dir.join(PESSOAS), "ana operador senha-ana\n").unwrap();
        std::fs::write(
            dir.join(ATUALIZACAO),
            chave_nova("atualizacao", "publicador-1", None).unwrap().1,
        )
        .unwrap();
        mudar(&dir);
        let resultado =
            ler_o_operador(&dir).and_then(|op| conferir(&op).map(|politica| (op, politica)));
        let _ = std::fs::remove_dir_all(&dir);
        resultado
    }

    /// A raiz de produção não leva chave do Duke nenhuma — ela nasce no
    /// primeiro boot, selada no TPM —, e o resto do `/etc/duke` continua.
    #[test]
    fn a_raiz_de_producao_nao_leva_a_chave_do_duke() {
        let (op, politica) = operador_lido("raiz", |_| {}).unwrap();
        let arquivos = arquivos_da_raiz(&op, &politica, [7; 16]).unwrap();
        let nomes: Vec<&str> = arquivos.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            !nomes.iter().any(|n| n.contains("privado/chave")),
            "{nomes:?}"
        );
        for esperado in [
            "etc/duke/imagem",
            "etc/duke/politica",
            "etc/duke/agentes",
            "etc/duke/administradores",
            "etc/duke/privado/pessoas",
            "etc/duke/atualizacao",
        ] {
            assert!(nomes.contains(&esperado), "falta {esperado}: {nomes:?}");
        }
    }

    #[test]
    fn o_material_do_operador_passa() {
        assert!(operador_de_teste("valido", |_| {}).is_ok());
    }

    #[test]
    fn uma_chave_da_bancada_recusa_a_imagem() {
        let bancada = super::super::chaves::Chaves::garantir().unwrap();
        let linha = sigilo::registro::linha(
            &sigilo::publica_de(&bancada.do_agente(4)),
            "parece-do-operador",
            Some("operador"),
        );
        let r = operador_de_teste("bancada", |dir| {
            let mut agentes = std::fs::read_to_string(dir.join(AGENTES)).unwrap();
            agentes.push_str(&linha);
            std::fs::write(dir.join(AGENTES), agentes).unwrap();
        });
        assert!(r.as_ref().is_err_and(|e| e.contains("da bancada")), "{r:?}");
    }

    #[test]
    fn a_politica_da_bancada_e_recusada() {
        let r = operador_de_teste("padrao", |dir| {
            std::fs::write(dir.join(POLITICA), politica::PADRAO).unwrap();
        });
        assert!(
            r.as_ref().is_err_and(|e| e.contains("política da bancada")),
            "{r:?}"
        );
    }

    #[test]
    fn o_quorum_que_nao_fecha_e_recusado() {
        let r = operador_de_teste("quorum", |dir| {
            let texto = std::fs::read_to_string(dir.join(ADMINISTRADORES)).unwrap();
            let dois: String = texto.lines().take(2).map(|l| format!("{l}\n")).collect();
            std::fs::write(dir.join(ADMINISTRADORES), dois).unwrap();
        });
        assert!(r.as_ref().is_err_and(|e| e.contains("quórum")), "{r:?}");
    }

    #[test]
    fn a_senha_curta_e_recusada() {
        let r = operador_de_teste("senha", |dir| {
            std::fs::write(dir.join("senha-ana"), "onze letras\n").unwrap();
        });
        assert!(
            r.as_ref().is_err_and(|e| e.contains("menos de 12")),
            "{r:?}"
        );
    }

    #[test]
    fn sem_chave_de_atualizacao_e_recusado() {
        let r = operador_de_teste("sem-atualizacao", |dir| {
            std::fs::write(dir.join(ATUALIZACAO), "# ninguem\n").unwrap();
        });
        assert!(
            r.as_ref().is_err_and(|e| e.contains("não tem chave")),
            "{r:?}"
        );
        let r = operador_de_teste("sem-arquivo-de-atualizacao", |dir| {
            std::fs::remove_file(dir.join(ATUALIZACAO)).unwrap();
        });
        assert!(r.as_ref().is_err_and(|e| e.contains(ATUALIZACAO)), "{r:?}");
    }

    #[test]
    fn a_chave_de_atualizacao_da_bancada_e_recusada() {
        let bancada = super::super::chaves::Chaves::garantir().unwrap();
        let linha = sigilo::registro::linha_de_editor(
            &atualizacao::manifesto::publica_de(&bancada.atualizacao),
            "parece-do-operador",
        );
        let r = operador_de_teste("atualizacao-da-bancada", |dir| {
            std::fs::write(dir.join(ATUALIZACAO), &linha).unwrap();
        });
        assert!(r.as_ref().is_err_and(|e| e.contains("da bancada")), "{r:?}");
    }

    #[test]
    fn sem_o_quorum_da_atualizacao_e_recusado() {
        let r = operador_de_teste("sem-quorum-de-atualizacao", |dir| {
            let politica = std::fs::read_to_string(dir.join(POLITICA)).unwrap();
            let sem: String = politica
                .lines()
                .filter(|l| !l.starts_with("quorum system.update"))
                .map(|l| format!("{l}\n"))
                .collect();
            std::fs::write(dir.join(POLITICA), sem).unwrap();
        });
        assert!(
            r.as_ref()
                .is_err_and(|e| e.contains("quorum system.update")),
            "{r:?}"
        );
        // E sem a permissão no papel de quem assina.
        let r = operador_de_teste("sem-permissao-de-atualizacao", |dir| {
            let politica = std::fs::read_to_string(dir.join(POLITICA)).unwrap();
            let sem: String = politica
                .lines()
                .map(|l| {
                    if l.starts_with("papel administrador ") {
                        format!("{}\n", l.replace(" system.update", ""))
                    } else {
                        format!("{l}\n")
                    }
                })
                .collect();
            std::fs::write(dir.join(POLITICA), sem).unwrap();
        });
        assert!(
            r.as_ref()
                .is_err_and(|e| e.contains("system.update no papel")),
            "{r:?}"
        );
    }

    #[test]
    fn a_chave_de_atualizacao_nova_assina_o_que_o_registro_confere() {
        let (privada, linha, registro) = chave_nova("atualizacao", "publicador-1", None).unwrap();
        assert_eq!(registro, ATUALIZACAO);
        let privada = chave_de_atualizacao_de_texto(&privada).unwrap();
        let chaves = registro_de_atualizacao(&linha).unwrap();
        assert_eq!(
            chaves,
            vec![(
                atualizacao::manifesto::publica_de(&privada),
                "publicador-1".to_string()
            )]
        );
        let kernel = b"\x7fELF um kernel de mentira".repeat(64);
        let pacote = atualizacao::pacote::montar(&[("programas/x86_64/livro", b"livro")]).unwrap();
        let i = super::super::slots::imagem(
            &super::super::slots::Pedido {
                arch: Arquitetura::X86_64,
                kernel: &kernel,
                pacote: &pacote,
                versao: "1.0",
                geracao: 1,
                estado: (1, 1),
            },
            &privada,
        )
        .unwrap();
        let c =
            super::super::slots::conferir_imagem(&i.bytes, &linha, Arquitetura::X86_64).unwrap();
        assert_eq!(
            (c.versao.as_str(), c.geracao, c.chave.as_str()),
            ("1.0", 1, "publicador-1")
        );
        // Outra arquitetura, outro registro, um byte trocado: recusadas.
        assert!(
            super::super::slots::conferir_imagem(&i.bytes, &linha, Arquitetura::Aarch64).is_err()
        );
        let (_, outra, _) = chave_nova("atualizacao", "outro", None).unwrap();
        assert!(
            super::super::slots::conferir_imagem(&i.bytes, &outra, Arquitetura::X86_64)
                .is_err_and(|e| e.contains("nao esta no registro"))
        );
        let mut estragada = i.bytes.clone();
        let k = atualizacao::cabecalho::KERNEL_EM as usize;
        estragada[k + 10] ^= 1;
        assert!(
            super::super::slots::conferir_imagem(&estragada, &linha, Arquitetura::X86_64)
                .is_err_and(|e| e.contains("kernel"))
        );
        // E a chave repetida no registro.
        assert!(registro_de_atualizacao(&format!("{linha}{linha}")).is_err());
    }

    #[test]
    fn o_que_leva_a_privada_e_so_do_dono() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("xtask-dono-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let montagem = dir.join("montagem");
        so_do_dono(&montagem, true).unwrap();
        let imagem = montagem.join("duke.img");
        std::fs::write(&imagem, b"x").unwrap();
        so_do_dono(&imagem, false).unwrap();
        let modo = |c: &Path| std::fs::metadata(c).unwrap().permissions().mode() & 0o777;
        assert_eq!((modo(&montagem), modo(&imagem)), (0o700, 0o600));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn as_chaves_de_um_texto() {
        let a = [0xab; 32];
        let texto = format!(
            "{} agente-1 operador\nx ed25519:{} y\n",
            sigilo::hex(&a),
            sigilo::hex(&[0xcd; 32])
        );
        assert_eq!(chaves_no_texto(&texto), vec![a, [0xcd; 32]]);
    }
}
