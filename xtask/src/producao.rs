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
//! chave do Duke é sorteada aqui e só existe dentro dela; os registros, a
//! política, a rede e as fontes de hora são os do operador, conferidos pelos
//! mesmos leitores do kernel; uma chave da bancada em qualquer arquivo
//! recusa a imagem inteira; e a raiz leva os programas, as âncoras TLS
//! públicas e a rede principal do IC — o que é público e é do produto.
//!
//! # O que não muda
//!
//! A identidade do Duke continua nascendo na imagem — é o grupo B de
//! `docs/OPERACAO.md`, e esta ferramenta não o decide: ela só faz com que
//! cada imagem tenha uma chave própria, e que ninguém mais a tenha. O
//! formato de cada arquivo, a política, o gate, a persistência: os mesmos.

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
    Ok(politica)
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

/// Os arquivos da raiz de uma imagem de produção para `arch`: os do
/// operador, a chave do Duke `duke`, a marca com o id `id`, as âncoras
/// públicas, a rede principal do IC e os programas da arquitetura.
pub(crate) fn arquivos_da_imagem(
    arch: Arquitetura,
    op: &Operador,
    politica: &politica::Politica,
    duke: &[u8; 32],
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
            "etc/duke/privado/chave".to_string(),
            format!("{}\n", sigilo::hex(duke)).into_bytes(),
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
        (tls::PUBLICAS_NA_IMAGEM.to_string(), tls::publicas()?),
        (
            icp::REDES_NA_IMAGEM.to_string(),
            redes_de_producao().into_bytes(),
        ),
    ];
    if let Some(t) = &op.tempo {
        arquivos.push(("etc/duke/tempo".to_string(), t.clone().into_bytes()));
    }
    if let Some(r) = &op.rede {
        arquivos.push(("etc/duke/rede".to_string(), r.clone().into_bytes()));
    }
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

/// O resumo de um arquivo, para o registro do que entrou.
fn resumo(bytes: &[u8]) -> String {
    use sha2::Digest;
    sigilo::hex_de(&sha2::Sha256::digest(bytes))
}

/// `cargo xtask provisionar <diretório>`: a imagem de produção de `arch`, do
/// material do operador, em `saida` (ou `target/producao/<nome>-<arch>`).
pub(crate) fn provisionar(
    arch: Arquitetura,
    release: bool,
    dir: &Path,
    saida: Option<&Path>,
) -> Result<ExitCode, String> {
    let op = ler_o_operador(dir)?;
    let politica = conferir(&op)?;
    let saida = saida.map(Path::to_path_buf).unwrap_or_else(|| {
        super::raiz_do_projeto()
            .join("target")
            .join("producao")
            .join(format!("{}-{}", op.nome, arch.nome()))
    });
    // Uma imagem nunca por cima de outra: a chave do Duke da anterior
    // sumiria, e com ela a máquina que já a usa.
    if saida.join("duke.img").exists() {
        return Err(format!(
            "{} já tem uma imagem: escolha outra saída, ou apague a anterior sabendo que a chave do Duke dela some junto",
            saida.display()
        ));
    }
    std::fs::create_dir_all(&saida)
        .map_err(|e| format!("não foi possível criar {}: {e}", saida.display()))?;
    let duke = aleatorios()?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&aleatorios()?[..16]);
    let arquivos = arquivos_da_imagem(arch, &op, &politica, &duke, id)?;

    let montagem = saida.join("montagem");
    let imagem = montagem.join("duke.img");
    super::montar_disco(&imagem, &arquivos, super::Extras::Nenhum)?;
    let alvo_do_kernel = super::raiz_do_projeto()
        .join("target")
        .join("producao-kernel");
    let elf = super::compilar_o_kernel(arch, release, &[], Some(&alvo_do_kernel))?;
    let (efi, kernel) = super::para_a_esp(arch, release, &elf)?;
    super::instalar_iniciador(arch, &imagem, &efi, &kernel)?;
    std::fs::rename(&imagem, saida.join("duke.img"))
        .map_err(|e| format!("não foi possível mover a imagem: {e}"))?;
    let _ = std::fs::remove_dir_all(&montagem);

    let publica = sigilo::hex(&sigilo::publica_de(&duke));
    std::fs::write(saida.join("duke.publica"), format!("{publica}\n"))
        .map_err(|e| format!("não foi possível gravar a pública do Duke: {e}"))?;
    let mut registro = format!(
        "# A imagem de producao `{}`, para {}: o que entrou nela.\nid {}\nduke {publica}\nkernel {}\niniciador {}\n",
        op.nome,
        arch.nome(),
        sigilo::hex_de(&id),
        resumo(&std::fs::read(&kernel).map_err(|e| e.to_string())?),
        resumo(&std::fs::read(&efi).map_err(|e| e.to_string())?),
    );
    for (nome, bytes) in &arquivos {
        // A chave do Duke e o registro de pessoas não entram: o resumo de
        // um segredo de 32 bytes não o protege de quem testa palpites.
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
         [xtask] a pública do Duke, que os agentes fixam: {publica}\n\
         [xtask] o que entrou: {}\n\
         [xtask] a privada do Duke só existe dentro da imagem: guarde a imagem como se guarda a chave",
        op.nome,
        arch.nome(),
        saida.join("duke.img").display(),
        saida.join("registro.txt").display()
    );
    Ok(ExitCode::SUCCESS)
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

/// Uma chave nova de `tipo` — `agente`, `administrador` ou `editor` —:
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
        _ => {
            return Err(
                "uso: cargo xtask chave agente|administrador <arquivo> <nome> <papel>, ou chave editor <arquivo> <nome>"
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

/// A pública do Duke de `texto`: o conteúdo de `duke.publica`, ou o
/// caminho dele.
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
/// `admin.execute`. Com `assinaturas`, um `admin.revoke` pelo quórum.
pub(crate) fn operar(
    endereco: &str,
    metodo: &str,
    params: &str,
    chave: &Path,
    duke: &str,
    admin: Option<&Path>,
    assinaturas: &[PathBuf],
) -> Result<ExitCode, String> {
    let chave = chave_de_agente(chave)?;
    let duke = publica_do_duke(duke)?;
    let mut agente = super::AgenteNaPorta::conectar_endereco(endereco, &chave, &duke)?;
    let resposta = if !assinaturas.is_empty() {
        super::revogar_pelo_operador(&mut agente, params, assinaturas)?
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
        mudar(&dir);
        let resultado = ler_o_operador(&dir).and_then(|op| conferir(&op));
        let _ = std::fs::remove_dir_all(&dir);
        resultado
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
