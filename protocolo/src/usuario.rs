//! A ABI entre o kernel e os programas de usuário.
//!
//! # Por que ela mora aqui
//!
//! Pelo mesmo motivo do resto deste pacote. Enquanto os programas de usuário
//! eram montados à mão no próprio kernel, os números das chamadas de sistema
//! tinham um lado só. Com programas compilados à parte — o pacote
//! `programas` —, eles passaram a ter dois, e dois lados com a mesma lista
//! escrita duas vezes são duas listas que podem divergir: um número trocado
//! não dá erro de compilação, dá um programa que pede para ler e escreve.
//!
//! Aqui estão os números, os erros e o mapa do espaço do usuário. O kernel e
//! os programas incluem este módulo, e nenhum dos dois declara nada disso.

/// Números das chamadas de sistema.
///
/// Iguais nas duas arquiteturas: o que muda é o registrador que carrega cada
/// coisa, e isso é detalhe do backend. No x86, `rax` traz o número e `rdi`,
/// `rsi` e `rdx` os argumentos; no ARM, `x8` e `x0` a `x2`. O retorno volta
/// em `rax` ou `x0`.
pub mod numero {
    /// `sair(codigo)`: encerra o processo. Não retorna.
    pub const SAIR: u64 = 0;
    /// `escrever(descritor, ptr, tamanho)`: manda bytes para onde o
    /// descritor apontar.
    pub const ESCREVER: u64 = 1;
    /// `id()`: devolve o identificador do fio que executa o processo.
    pub const ID: u64 = 2;
    /// `ceder()`: devolve a CPU voluntariamente.
    pub const CEDER: u64 = 3;
    /// `bifurcar()`: duplica o processo. Devolve 0 ao filho e o identificador
    /// do filho ao pai.
    pub const BIFURCAR: u64 = 4;
    /// `executar(ptr, tamanho)`: troca a imagem do processo pela que o nome
    /// indicar. Não retorna em caso de sucesso — retorna noutro programa.
    pub const EXECUTAR: u64 = 5;
    /// `abrir(ptr, tamanho)`: abre o arquivo do caminho e devolve o descritor.
    pub const ABRIR: u64 = 6;
    /// `ler(descritor, ptr, tamanho)`: traz bytes de onde o descritor apontar
    /// e avança a posição dele.
    pub const LER: u64 = 7;
    /// `fechar(descritor)`: devolve a vaga do descritor à tabela.
    pub const FECHAR: u64 = 8;
    /// `esperar(id, ponteiro)`: espera um filho terminar.
    ///
    /// `id` zero espera qualquer filho; diferente de zero, aquele filho. O
    /// ponteiro, quando não é nulo, aponta para **dois** `i64`: o código de
    /// saída e se ele vale. Devolve o identificador do filho colhido.
    ///
    /// É a única chamada deste kernel que **bloqueia**: o fio sai da lista
    /// do escalonador e volta quando um filho sai.
    pub const ESPERAR: u64 = 9;
    /// `mapear(endereco, tamanho)`: dá ao processo memória nova, zerada,
    /// gravável e não executável, em `[endereco, endereco + tamanho)`.
    ///
    /// Quem escolhe o endereço é o processo, dentro de
    /// [`MAPEAVEL`](super::MAPEAVEL), e a faixa inteira precisa estar livre.
    /// Devolve zero, ou um erro — e, no erro, nada foi mapeado.
    pub const MAPEAR: u64 = 10;
    /// `escutar(ptr, tamanho)`: torna o processo o ouvinte do canal de
    /// eventos com o nome dado, e devolve um descritor.
    ///
    /// `ler` nesse descritor entrega eventos inteiros —
    /// [`evento::TAMANHO`](super::evento::TAMANHO) bytes cada — e **bloqueia**
    /// enquanto a fila estiver vazia: o fio sai do escalonador e volta quando
    /// o kernel publicar no canal. Um canal tem um ouvinte só; o segundo
    /// ouve [`erro::OCUPADO`](super::erro::OCUPADO).
    pub const ESCUTAR: u64 = 11;
    /// `superficie(tamanho, endereco)`: cria uma superfície do compositor e
    /// a mapeia no processo, em `endereco`. Devolve um descritor.
    ///
    /// `tamanho` é a largura e a altura empacotadas por
    /// [`superficie::tamanho`](super::superficie::tamanho). Os pixels ficam
    /// em `[endereco, endereco + largura * altura * 4)`, linha a linha, no
    /// formato `0xAARRGGBB`; o processo desenha neles direto, e o
    /// compositor lê dos mesmos frames — nada é copiado.
    ///
    /// A camada nasce **invisível** e na origem: o processo desenha, e só
    /// então a posiciona e a mostra com [`CONTROLAR`]. Uma camada que
    /// aparecesse ao nascer mostraria preto até o primeiro desenho.
    ///
    /// Tudo ou nada, como `mapear`: no erro, não há camada nem página.
    pub const SUPERFICIE: u64 = 12;
    /// `controlar(descritor, operacao, argumento)`: mexe na camada de uma
    /// superfície — ver [`superficie::operacao`](super::superficie::operacao).
    /// Zero, ou um erro.
    pub const CONTROLAR: u64 = 13;
    /// `descrever(descritor, ptr, tamanho)`: diz ao kernel o que a janela
    /// de uma superfície **é** — o título, os botões e os textos —, para a
    /// árvore semântica. O formato está em
    /// [`descricao`](super::descricao). Substitui a descrição anterior
    /// inteira. Zero, ou um erro.
    pub const DESCREVER: u64 = 14;
    /// `terminal(canal)`: abre o pseudo-terminal do kernel — o interpretador
    /// visto de um processo — e devolve um descritor.
    ///
    /// `escrever` nele é digitar: cada caractere chega ao interpretador como
    /// uma tecla. `ler` entrega o que o kernel imprimiu — as respostas do
    /// interpretador e o log —, e **não** bloqueia: devolve zero quando não
    /// há nada. Quem espera, espera no `canal` — o descritor de um canal de
    /// eventos que o processo escuta —, onde o kernel avisa com um evento
    /// [`SAIDA`](super::evento::tipo::SAIDA) quando há o que ler. Assim um
    /// processo espera o teclado, o ponteiro e a saída num lugar só.
    ///
    /// O pseudo-terminal tem um dono só; o segundo ouve
    /// [`OCUPADO`](super::erro::OCUPADO).
    pub const TERMINAL: u64 = 15;
    /// `valor(descritor, ptr, tamanho)`: o texto que um agente pediu para
    /// um campo da janela da superfície `descritor` — ver o tipo `campo` em
    /// [`descricao`](super::descricao).
    ///
    /// O pedido chega como um evento de [`ACAO`](super::evento::tipo::ACAO)
    /// com [`DEFINIR_VALOR`](super::evento::acao::DEFINIR_VALOR), e o texto
    /// não cabe num evento de 32 bytes: ele espera no kernel, numa fila da
    /// superfície, e esta chamada tira o mais antigo. Um por evento, na
    /// ordem dos eventos — dois campos definidos um depois do outro não
    /// trocam de valor.
    ///
    /// Devolve quantos bytes escreveu; [`NAO_ENCONTRADO`](super::erro::NAO_ENCONTRADO)
    /// sem texto esperando; [`TAMANHO_INVALIDO`](super::erro::TAMANHO_INVALIDO)
    /// se o texto não cabe no buffer — e então ele continua na fila.
    pub const VALOR: u64 = 16;
    /// `pedir(ptr, tamanho)`: pede ao sistema um comando do registro — o
    /// mesmo que um agente pede pelo canal e uma pessoa pelo
    /// interpretador —, e devolve o tamanho da resposta.
    ///
    /// O pedido é um objeto JSON-RPC 2.0 (`jsonrpc`, `id`, `method`,
    /// `params`), e a resposta é o envelope do canal, com `result` ou
    /// `error`. Ele passa pelo mesmo gate, com a autoridade do processo — a
    /// de quem o lançou —, e vai para a auditoria. Ver
    /// [`nativo`](super::nativo) e `docs/INTERFACE.md`.
    ///
    /// **Bloqueia** enquanto o comando executa, como `esperar`: o fio sai do
    /// escalonador e volta quando a resposta está pronta. A resposta fica no
    /// kernel até [`RESPOSTA`] a buscar — ela pode não caber no buffer que o
    /// programa tem, e o comando já teve efeito.
    pub const PEDIR: u64 = 17;
    /// `resposta(ptr, capacidade)`: a resposta do último [`PEDIR`].
    ///
    /// Devolve o tamanho dela. Se ele cabe em `capacidade`, os bytes vão
    /// para `ptr` e a resposta sai do kernel; se não cabe, nada é escrito e
    /// ela continua lá — o programa aloca o tamanho devolvido e pede de
    /// novo. [`NAO_ENCONTRADO`](super::erro::NAO_ENCONTRADO) sem resposta
    /// esperando. O próximo `pedir` descarta a que não foi buscada.
    pub const RESPOSTA: u64 = 18;
}

/// A interface nativa: o registro de comandos como API dos programas — ver
/// [`numero::PEDIR`].
pub mod nativo {
    /// O maior pedido, em bytes: o mesmo teto da linha do canal do agente.
    /// Um pedido que não caberia lá também não cabe aqui — o vocabulário é
    /// um só, e os tetos também.
    pub const MAIOR_PEDIDO: usize = 4096;

    /// A versão da interface nativa, que `system.info` publica. Cresce
    /// quando uma chamada de mecanismo é acrescentada ou o envelope muda;
    /// os comandos do registro se descrevem sozinhos, por `agent.describe`.
    pub const VERSAO: u32 = 1;
}

/// Erros devolvidos ao usuário, sempre negativos.
///
/// Negativo porque o valor de retorno é um `i64` e as chamadas que dão certo
/// devolvem zero ou uma contagem. É a convenção do Linux, e existe porque
/// distingue erro de resultado sem precisar de um segundo canal.
pub mod erro {
    pub const NUMERO_INVALIDO: i64 = -1;
    pub const ENDERECO_INVALIDO: i64 = -2;
    pub const TAMANHO_INVALIDO: i64 = -3;
    pub const DESCRITOR_INVALIDO: i64 = -4;
    pub const SEM_MEMORIA: i64 = -5;
    pub const SEM_VAGA_DE_FIO: i64 = -6;
    pub const PROGRAMA_DESCONHECIDO: i64 = -7;
    /// A tabela de descritores do processo está cheia.
    pub const SEM_DESCRITOR: i64 = -8;
    /// O caminho não existe, ou não dá para resolvê-lo.
    pub const NAO_ENCONTRADO: i64 = -9;
    /// O caminho existe e não é um arquivo.
    ///
    /// Distinto de [`NAO_ENCONTRADO`] de propósito: um programa que tente
    /// abrir um diretório merece saber que errou o tipo, e não que o caminho
    /// não existe — a segunda resposta o manda procurar o erro no lugar
    /// errado.
    pub const NAO_EH_ARQUIVO: i64 = -10;
    /// Não há filho por quem esperar.
    ///
    /// Distinto de "nenhum filho terminou ainda", que não é erro e nem chega
    /// ao usuário: aquele caso põe o fio para dormir. Este diz que esperar
    /// seria esperar para sempre.
    pub const SEM_FILHOS: i64 = -11;
    /// Parte da faixa pedida a `mapear` já está mapeada.
    ///
    /// Distinto de [`ENDERECO_INVALIDO`]: a faixa é legítima, e o processo é
    /// que já a usa. Mapear por cima trocaria em silêncio memória que ele
    /// ainda lê por páginas zeradas.
    pub const JA_MAPEADO: i64 = -12;
    /// O canal de eventos já tem ouvinte, ou a tabela de canais está cheia.
    pub const OCUPADO: i64 = -13;
    /// A operação pedida a `controlar` não existe, ou o argumento dela não
    /// faz sentido — uma opacidade acima de 255, um retângulo fora da
    /// superfície.
    pub const ARGUMENTO_INVALIDO: i64 = -14;
    /// Não há compositor: a máquina não tem tela, ou a pilha gráfica não
    /// subiu. Distinto de [`SEM_MEMORIA`]: tentar de novo não adianta.
    pub const SEM_TELA: i64 = -15;
    /// A política recusou: o processo age com a autoridade do agente que o
    /// lançou, e o papel dele não alcança este arquivo, este programa ou
    /// esta chamada. Distinto de [`NAO_ENCONTRADO`]: o caminho pode existir.
    pub const NEGADO: i64 = -16;
    /// O arquivo mudou depois de aberto: o descritor é de um conteúdo que
    /// não existe mais — um arquivo do armazém, gravado por outro. Abrir de
    /// novo dá o de agora. Distinto de [`ENDERECO_INVALIDO`]: o buffer está
    /// certo, e não há metade de um conteúdo e metade de outro para ler.
    pub const MUDOU: i64 = -17;
}

/// As superfícies do compositor, como um processo as vê.
///
/// # O que o processo tem na mão
///
/// Um descritor e uma faixa de memória. A faixa são os pixels da camada —
/// os **mesmos** frames que o compositor lê ao compor, mapeados nos dois
/// lados —, e o descritor é o que o processo passa a `controlar` para mover
/// a camada, mostrá-la e dizer o que mudou nela.
///
/// Desenhar é escrever na faixa; nada aparece até o processo dizer onde
/// escreveu, com [`operacao::DANO`](superficie::operacao::DANO). É o arranjo do Orbital, o compositor do
/// Redox: a janela é memória do cliente, e o compositor recompõe o
/// retângulo que o cliente acusa.
///
/// # O que um `fork` faz com ela
///
/// O filho herda o descritor e **não** herda a faixa: ela não é mapeada no
/// espaço dele, e `controlar` pelo descritor herdado é recusado. A camada é
/// de quem a criou — dois processos desenhando na mesma janela, cada um sem
/// saber do outro, seria o defeito, e não o recurso.
///
/// # Quando ela some
///
/// Quando o processo fecha o descritor, ou quando ele morre: a camada sai
/// da tela, e os frames voltam ao alocador quando o último dos dois lados —
/// o compositor e o espaço do processo — os soltar.
pub mod superficie {
    /// O maior lado, em pixels.
    pub const MAIOR_LADO: u32 = 4096;
    /// O maior tamanho, em bytes: 16 MiB, uma tela de 2048 por 2048.
    ///
    /// O teto é de latência, como o de `mapear`: criar e mapear acontecem
    /// numa chamada só, com as interrupções mascaradas em boa parte dela.
    pub const MAIOR_TAMANHO: u64 = 16 * 1024 * 1024;

    /// A primeira linha da tela que uma superfície de processo pode
    /// ocupar: as de cima são da barra do kernel.
    ///
    /// # Por que o kernel a impõe
    ///
    /// Porque a barra diz quem está agindo na máquina — os agentes
    /// conectados e quem agiu por último. Uma janela que pudesse cobri-la
    /// desenharia uma barra falsa, e receberia o clique de quem acreditasse
    /// nela. A superfície nasce abaixo desta linha, e um
    /// [`MOVER`](operacao::MOVER) para cima dela a leva até ela, e não além:
    /// quem arrasta uma janela para o topo a vê parar na barra, como numa
    /// borda. O programa que guarda a própria posição faz a mesma conta —
    /// ou o ponteiro, que chega em coordenadas da tela, cairia no lugar
    /// errado da janela.
    ///
    /// É a altura da barra em `aparencia`; o kernel confere, ao compilar,
    /// que as duas são a mesma.
    pub const PRIMEIRA_LINHA: i32 = 24;

    /// A posição que o kernel dá a um pedido de levar a superfície a
    /// `(x, y)`: a mesma, com `y` trazido para baixo da barra.
    pub const fn posicao_permitida(x: i32, y: i32) -> (i32, i32) {
        if y < PRIMEIRA_LINHA {
            (x, PRIMEIRA_LINHA)
        } else {
            (x, y)
        }
    }

    /// A largura e a altura num argumento: a largura nos 32 bits de baixo.
    pub const fn tamanho(largura: u32, altura: u32) -> u64 {
        largura as u64 | (altura as u64) << 32
    }

    /// O inverso de [`tamanho`].
    pub const fn de_tamanho(argumento: u64) -> (u32, u32) {
        (argumento as u32, (argumento >> 32) as u32)
    }

    /// Uma posição na tela num argumento: `x` nos 32 bits de baixo. As
    /// duas coordenadas são com sinal — uma janela pode sair pela borda.
    pub const fn posicao(x: i32, y: i32) -> u64 {
        x as u32 as u64 | (y as u32 as u64) << 32
    }

    /// O inverso de [`posicao`].
    pub const fn de_posicao(argumento: u64) -> (i32, i32) {
        (argumento as u32 as i32, (argumento >> 32) as u32 as i32)
    }

    /// Um retângulo **da superfície** num argumento: x, y, largura e
    /// altura, dezesseis bits cada, de baixo para cima. Dezesseis bastam:
    /// o maior lado é [`MAIOR_LADO`].
    pub const fn retangulo(x: u16, y: u16, largura: u16, altura: u16) -> u64 {
        x as u64 | (y as u64) << 16 | (largura as u64) << 32 | (altura as u64) << 48
    }

    /// O inverso de [`retangulo`].
    pub const fn de_retangulo(argumento: u64) -> (u16, u16, u16, u16) {
        (
            argumento as u16,
            (argumento >> 16) as u16,
            (argumento >> 32) as u16,
            (argumento >> 48) as u16,
        )
    }

    /// O que `controlar` sabe fazer com a camada.
    pub mod operacao {
        /// Leva o canto superior esquerdo a
        /// [`posicao`](super::posicao)`(x, y)` — com `y` abaixo da barra:
        /// ver [`PRIMEIRA_LINHA`](super::PRIMEIRA_LINHA).
        pub const MOVER: u64 = 1;
        /// Recompõe o [`retangulo`](super::retangulo) da superfície que o
        /// processo redesenhou.
        pub const DANO: u64 = 2;
        /// Põe a camada no topo — abaixo do cursor.
        pub const FRENTE: u64 = 3;
        /// A opacidade da camada inteira, de 0 (invisível, como ela nasce)
        /// a 255.
        pub const OPACIDADE: u64 = 4;
        /// Como os pixels se misturam com o de baixo: [`OPACA`] ignora o
        /// byte alto, [`ALFA`] o usa como opacidade do pixel.
        pub const MISTURA: u64 = 5;

        /// O teclado: `1` pede que as teclas venham para esta superfície,
        /// como eventos de [`TECLA`](crate::usuario::evento::tipo::TECLA) no
        /// canal de [`ENTRADA`] dela; `0` as devolve ao console. O kernel
        /// também dá o foco sozinho, à superfície em que a pessoa aperta o
        /// botão; e o devolve ao console quando a superfície fecha, ou quando
        /// a pessoa clica fora de toda superfície de processo.
        pub const FOCO: u64 = 6;
        /// Para onde vai a entrada desta superfície: o argumento é o
        /// descritor de um canal de eventos que o processo escuta, e o
        /// ponteiro sobre ela, as teclas com o foco nela e o
        /// [`FOCO_PERDIDO`](crate::usuario::evento::tipo::FOCO_PERDIDO)
        /// passam a ir para ele. Sem isso, vão para o canal das janelas —
        /// ver [`CANAL_DAS_JANELAS`](crate::usuario::evento::CANAL_DAS_JANELAS).
        ///
        /// É o que deixa dois processos terem janelas: cada um recebe o que
        /// acontece nas suas.
        pub const ENTRADA: u64 = 7;

        /// Argumentos de [`MISTURA`].
        pub const OPACA: u64 = 0;
        pub const ALFA: u64 = 1;
    }
}

/// Um evento, como `ler` o entrega a quem escuta um canal.
///
/// # Por que um formato fixo
///
/// Porque o leitor precisa saber onde um evento termina sem ler o seguinte.
/// Trinta e dois bytes, sempre, com o tipo na frente e três campos cujo
/// significado o tipo diz: um evento de ponteiro põe x, y e os botões; um
/// de tecla, o caractere. `ler` só entrega eventos inteiros — um buffer
/// menor que um evento é recusado, em vez de receber metade de um.
///
/// Os bytes são little-endian, escritos e lidos campo a campo por
/// [`Evento::em_bytes`](evento::Evento::em_bytes) e
/// [`Evento::de_bytes`](evento::Evento::de_bytes), e não pela memória da
/// `struct`: o kernel e o programa são compilados à parte, e o layout que
/// importa é o que está escrito aqui.
pub mod evento {
    /// Quantos bytes um evento ocupa no buffer de `ler`.
    pub const TAMANHO: usize = 32;

    /// Os tipos de evento. Cada etapa que publica um tipo novo o declara
    /// aqui, com o que os três campos querem dizer.
    pub mod tipo {
        /// Um evento que só a suíte do kernel publica, para conferir o
        /// canal. `a` é um número que o ouvinte devolve; zero pede que ele
        /// termine.
        pub const TESTE: u32 = 1;
        /// O ponteiro, sobre uma janela ou arrastando uma: `a` e `b` são x e
        /// y na tela, `c` os botões — ver [`BOTAO_ESQUERDO`](super::BOTAO_ESQUERDO).
        ///
        /// O kernel publica quando o ponteiro anda ou um botão muda, se o
        /// que está debaixo dele é uma superfície de processo — ou se o
        /// botão foi apertado sobre uma e ainda não soltou: é o que deixa
        /// arrastar uma janela mais depressa do que ela acompanha.
        pub const PONTEIRO: u32 = 2;
        /// Uma tecla que virou caractere, com o foco numa superfície: `a` é
        /// o código do caractere.
        pub const TECLA: u32 = 3;
        /// Um pedido para abrir uma janela — da barra do kernel, ou da
        /// suíte. `a` é qual, de [`janela`](super::janela); `b` e `c` são a
        /// largura e a altura da tela, para quem vai posicioná-la.
        pub const ABRIR: u32 = 4;
        /// O foco saiu das superfícies deste canal: a pessoa apertou o
        /// botão sobre a de outro processo, ou fora de toda superfície de
        /// processo, e as teclas vão para outro lugar.
        ///
        /// Não chega quando o foco passa de uma superfície a outra do
        /// mesmo canal: quem tem várias janelas sabe, pelo aperto que
        /// recebe, qual delas ficou com ele.
        pub const FOCO_PERDIDO: u32 = 5;
        /// Um pedido para o servidor fechar tudo e sair. Da suíte, que
        /// não deixa um servidor vivo para os casos seguintes.
        pub const ENCERRAR: u32 = 6;
        /// Uma ação sobre um elemento que o servidor descreveu — ver
        /// [`descricao`](crate::usuario::descricao): `a` é o identificador
        /// que o servidor deu ao elemento, `b` a ação, de
        /// [`acao`](super::acao), e `c` quem pediu — ver
        /// [`origem`](super::origem).
        pub const ACAO: u32 = 7;
        /// Há saída nova no pseudo-terminal — ver
        /// [`TERMINAL`](crate::usuario::numero::TERMINAL). Sem campos: quem
        /// recebe lê o descritor até ele devolver zero.
        pub const SAIDA: u32 = 8;
    }

    /// As ações de um evento [`tipo::ACAO`].
    /// Quem pediu uma [`ACAO`](tipo::ACAO), no `c` do evento: a pessoa, ou
    /// o agente de uma sessão do canal.
    ///
    /// Vários agentes operam o Duke ao mesmo tempo, cada um numa sessão; o
    /// processo que recebe a ação sabe de qual veio, e pode dizê-lo adiante
    /// — o Terminal diz ao interpretador quem apertou o Enter.
    pub mod origem {
        /// A pessoa na frente da máquina.
        pub const PESSOA: i64 = -1;

        /// O `c` de uma ação pedida pelo agente da sessão `sessao`.
        pub const fn agente(sessao: u8) -> i64 {
            sessao as i64
        }

        /// A sessão do agente que pediu, se foi um agente.
        pub const fn sessao(c: i64) -> Option<u8> {
            if c >= 0 && c <= u8::MAX as i64 {
                Some(c as u8)
            } else {
                None
            }
        }
    }

    pub mod acao {
        /// Acionar, como um clique num botão — o `press` da árvore.
        pub const PRESSIONAR: i64 = 1;
        /// Confirmar um campo, como o Enter — o `confirm` da árvore.
        pub const CONFIRMAR: i64 = 2;
        /// Esvaziar um campo — o `cancel` da árvore.
        pub const CANCELAR: i64 = 3;
        /// Trocar o texto de um campo — o `set_value` da árvore. O texto
        /// espera no kernel: ver [`VALOR`](crate::usuario::numero::VALOR).
        pub const DEFINIR_VALOR: i64 = 4;
    }

    /// O bit do botão esquerdo em `c` de um evento de ponteiro.
    pub const BOTAO_ESQUERDO: i64 = 1;

    /// O canal onde o kernel publica a entrada das janelas e os pedidos de
    /// abrir uma: quem o escuta é o servidor de janelas.
    pub const CANAL_DAS_JANELAS: &str = "janelas";

    /// O canal que o Terminal escuta: a entrada da janela dele, os avisos
    /// de saída do pseudo-terminal, e o pedido de vir para a frente.
    pub const CANAL_DO_TERMINAL: &str = "terminal";

    /// Que janela um [`tipo::ABRIR`] pede.
    pub mod janela {
        /// Uma janela vazia, que mostra o que se digita nela. A da suíte.
        pub const TESTE: i64 = 1;
        /// "Sobre o Duke": o que é este sistema. Uma só de cada vez — pedir
        /// de novo traz a aberta para a frente. Do botão da barra.
        pub const SOBRE: i64 = 2;
        /// O Terminal: o servidor não o desenha, ele o **lança** — é um
        /// programa à parte, com a janela dele. Do botão da barra, quando
        /// não há Terminal no ar; com um no ar, o pedido vai a ele, no
        /// [`CANAL_DO_TERMINAL`](super::CANAL_DO_TERMINAL), e ele vem para
        /// a frente.
        pub const TERMINAL: i64 = 3;
    }

    /// Um evento: o tipo e três campos.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Evento {
        pub tipo: u32,
        pub a: i64,
        pub b: i64,
        pub c: i64,
    }

    impl Evento {
        /// Os 32 bytes do evento: o tipo, quatro bytes reservados em zero,
        /// e os três campos.
        pub fn em_bytes(&self) -> [u8; TAMANHO] {
            let mut bytes = [0u8; TAMANHO];
            bytes[0..4].copy_from_slice(&self.tipo.to_le_bytes());
            bytes[8..16].copy_from_slice(&self.a.to_le_bytes());
            bytes[16..24].copy_from_slice(&self.b.to_le_bytes());
            bytes[24..32].copy_from_slice(&self.c.to_le_bytes());
            bytes
        }

        /// O evento que os 32 bytes descrevem.
        pub fn de_bytes(bytes: &[u8; TAMANHO]) -> Evento {
            let palavra = |de: usize| {
                let mut oito = [0u8; 8];
                oito.copy_from_slice(&bytes[de..de + 8]);
                i64::from_le_bytes(oito)
            };
            Evento {
                tipo: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                a: palavra(8),
                b: palavra(16),
                c: palavra(24),
            }
        }
    }
}

/// Como um processo descreve uma janela para a árvore semântica — o texto
/// que [`numero::DESCREVER`] recebe.
///
/// # Por que texto
///
/// Porque quem lê é o kernel, que recusa o que não entende, e quem escreve
/// é um programa, que pode imprimir a mesma linha no log para ver o que
/// mandou. Um formato binário seria mais curto e nada mais fácil de
/// conferir.
///
/// # O formato
///
/// Uma linha por coisa, e os campos separados por tabulação:
///
/// ```text
/// janela  <título>
/// botao   <id> <x> <y> <largura> <altura> <rótulo>
/// texto   <id> <x> <y> <largura> <altura> <rótulo> <valor>
/// campo   <id> <x> <y> <largura> <altura> <rótulo> <valor>
/// area    <id> <x> <y> <largura> <altura> <rótulo> <valor>
/// ```
///
/// Um `texto` se lê; um `campo` também se edita — na árvore, ele aceita
/// confirmar, esvaziar e trocar o valor, e cada uma chega ao processo como
/// uma [`ACAO`](evento::tipo::ACAO). Uma `area` é texto de várias linhas que
/// se lê e não se edita, como o console do kernel: a grade do Terminal.
///
/// A linha `janela` vem primeiro, e uma vez. O `id` é do servidor: é o que
/// volta a ele num evento de [`ACAO`](evento::tipo::ACAO) quando alguém
/// aciona o elemento pela árvore. O retângulo é **da superfície**, e o
/// kernel o leva à tela somando a posição da camada. Num rótulo ou num
/// valor, a tabulação, a quebra de linha e a barra invertida vão como
/// `\t`, `\n` e `\\` — ver [`escapar`](descricao::escapar).
/// O que o interpretador do kernel espera de quem digita nele pelo
/// pseudo-terminal — ver [`numero::TERMINAL`].
pub mod terminal {
    /// O que o interpretador escreve antes da linha de comando. Quem lê a
    /// saída acha a linha que se está digitando logo depois dele.
    pub const PROMPT: &str = "duke> ";

    /// Apaga a linha de comando inteira — o Ctrl-U dos terminais. É o
    /// `cancel` da árvore, e o começo de um `set_value`: quem digita não
    /// precisa saber quantas letras há na linha para trocá-la.
    pub const APAGAR_A_LINHA: char = '\u{15}';

    /// O Enter de um agente, sem dizer qual: um marcador, e não uma tecla.
    ///
    /// É o que um widget da linha de comando pede ao ser confirmado pela
    /// árvore — ele não sabe de que sessão veio a ação. O programa que a
    /// recebeu sabe, e troca o marcador por [`confirmar_pelo_agente`] antes
    /// de digitar; o pseudo-terminal não deixa o marcador passar.
    pub const CONFIRMAR_PELO_AGENTE: char = '\u{F8FD}';

    /// O Enter do agente da sessão `sessao`: executa a linha como o Enter, e
    /// o log diz `(agente N)`.
    ///
    /// # Por que um caractere à parte
    ///
    /// Porque o que se escreve no pseudo-terminal chega ao interpretador
    /// pela fila do teclado, a mesma da pessoa. O Terminal sabe quem pediu
    /// — a tecla veio do teclado, ou o `confirm` veio da árvore —, e o
    /// interpretador não; sem este caractere, um comando que o agente
    /// executou pelo Terminal ficaria no log como da pessoa. Da área de uso
    /// privado do Unicode, como as teclas de função do kernel: nenhum
    /// teclado o produz.
    ///
    /// Um processo com o pseudo-terminal pode escrevê-lo sem ter sido
    /// pedido por um agente. Atribuir ao agente o que a pessoa fez é o erro
    /// menos grave dos dois; o registro que a pessoa possa conferir é da
    /// fase 12.
    ///
    /// Um caractere por sessão, de U+F600 a U+F6FF.
    pub const fn confirmar_pelo_agente(sessao: u8) -> char {
        // De U+F600 a U+F6FF é sempre um escalar válido; o `None` não
        // acontece, mas `char::from_u32` é o que existe num `const fn`.
        match char::from_u32(0xF600 + sessao as u32) {
            Some(c) => c,
            None => '\u{F600}',
        }
    }

    /// A sessão do agente cujo Enter é `c`, se `c` é o Enter de um agente.
    pub const fn agente_que_confirmou(c: char) -> Option<u8> {
        let n = c as u32;
        if n >= 0xF600 && n <= 0xF6FF {
            Some((n - 0xF600) as u8)
        } else {
            None
        }
    }
}

pub mod descricao {
    /// O maior texto de descrição, em bytes.
    pub const MAIOR: usize = 2048;
    /// Quantos elementos uma janela descreve, no máximo.
    pub const MAIS_ELEMENTOS: usize = 16;
    /// O maior rótulo ou valor, em bytes, depois de resolvido o escape.
    pub const MAIOR_TEXTO: usize = 512;

    /// Escreve `texto` em `destino` com a tabulação, a quebra de linha e a
    /// barra invertida escapadas.
    pub fn escapar(texto: &str, destino: &mut impl core::fmt::Write) -> core::fmt::Result {
        for c in texto.chars() {
            match c {
                '\t' => destino.write_str("\\t")?,
                '\n' => destino.write_str("\\n")?,
                '\\' => destino.write_str("\\\\")?,
                c => destino.write_char(c)?,
            }
        }
        Ok(())
    }

    /// O inverso de [`escapar`], chamando `f` com cada caractere. Falso num
    /// escape que não é nenhum dos três — texto que ninguém escapou assim.
    pub fn resolver(texto: &str, mut f: impl FnMut(char)) -> bool {
        let mut chars = texto.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                f(c);
                continue;
            }
            match chars.next() {
                Some('t') => f('\t'),
                Some('n') => f('\n'),
                Some('\\') => f('\\'),
                _ => return false,
            }
        }
        true
    }

    /// O que um elemento é, na árvore.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Tipo {
        Botao,
        Texto,
        Campo,
        Area,
    }

    impl Tipo {
        /// A palavra que abre a linha do elemento.
        pub const fn palavra(self) -> &'static str {
            match self {
                Tipo::Botao => "botao",
                Tipo::Texto => "texto",
                Tipo::Campo => "campo",
                Tipo::Area => "area",
            }
        }

        #[cfg(feature = "alloc")]
        fn da_palavra(palavra: &str) -> Option<Tipo> {
            match palavra {
                "botao" => Some(Tipo::Botao),
                "texto" => Some(Tipo::Texto),
                "campo" => Some(Tipo::Campo),
                "area" => Some(Tipo::Area),
                _ => None,
            }
        }

        /// O tipo leva um valor além do rótulo?
        pub const fn tem_valor(self) -> bool {
            matches!(self, Tipo::Texto | Tipo::Campo | Tipo::Area)
        }
    }

    /// Um retângulo, em pixels da superfície.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Retangulo {
        pub x: u32,
        pub y: u32,
        pub largura: u32,
        pub altura: u32,
    }

    #[cfg(feature = "alloc")]
    pub use com_alocacao::*;

    /// O leitor e o escritor, que alocam.
    ///
    /// # Por que os dois aqui
    ///
    /// Porque o formato é um só, e o lugar dele é um só. O leitor morava no
    /// kernel, e cada programa com janela escrevia as linhas à mão: eram
    /// uma leitura e várias escritas do mesmo formato, e nada conferia que
    /// concordavam além de o kernel recusar a descrição inteira quando não
    /// concordavam. Com os dois lado a lado, um teste faz a volta completa.
    #[cfg(feature = "alloc")]
    mod com_alocacao {
        use super::{MAIOR, MAIOR_TEXTO, MAIS_ELEMENTOS, Retangulo, Tipo, escapar, resolver};
        use alloc::string::String;
        use alloc::vec::Vec;
        use core::fmt::Write;

        /// Um elemento que o processo descreveu dentro da janela.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct Elemento {
            pub tipo: Tipo,
            /// O identificador que o processo deu, e que volta a ele numa
            /// ação.
            pub id: i64,
            /// O retângulo, na superfície.
            pub moldura: Retangulo,
            pub rotulo: String,
            pub valor: Option<String>,
        }

        /// O que o processo disse que a janela é.
        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        pub struct Descricao {
            pub titulo: String,
            pub elementos: Vec<Elemento>,
            /// O campo que recebe as teclas agora: o identificador de um
            /// elemento `campo` da descrição, na linha `foco`. É por ele
            /// que o kernel sabe que recurso uma tecla edita, e confere o
            /// arrendamento antes de entregá-la.
            pub foco: Option<i64>,
        }

        impl Descricao {
            /// Lê o texto de uma descrição, ou diz o que não entendeu.
            ///
            /// Tudo ou nada: uma linha errada recusa a descrição inteira, e
            /// quem lê fica com a anterior. Uma árvore com metade de uma
            /// janela descreveria algo que não está na tela.
            pub fn ler(texto: &str) -> Result<Descricao, &'static str> {
                if texto.len() > MAIOR {
                    return Err("descricao grande demais");
                }
                let mut linhas = texto.split('\n').filter(|l| !l.is_empty());
                let primeira = linhas.next().ok_or("descricao vazia")?;
                let titulo = match primeira.split_once('\t') {
                    Some(("janela", titulo)) => resolvido(titulo)?,
                    _ => return Err("a descricao nao comeca pela linha `janela`"),
                };
                let mut elementos = Vec::new();
                let mut foco = None;
                for linha in linhas {
                    if let Some(id) = linha.strip_prefix("foco\t") {
                        if foco.is_some() {
                            return Err("mais de uma linha `foco`");
                        }
                        foco = Some(id.parse::<i64>().map_err(|_| "foco que nao e numero")?);
                        continue;
                    }
                    if elementos.len() == MAIS_ELEMENTOS {
                        return Err("elementos demais");
                    }
                    let mut campos = linha.split('\t');
                    let tipo = campos
                        .next()
                        .and_then(Tipo::da_palavra)
                        .ok_or("linha que nao e `botao`, `texto`, `campo` nem `area`")?;
                    let mut numero = || -> Result<i64, &'static str> {
                        campos
                            .next()
                            .and_then(|c| c.parse().ok())
                            .ok_or("campo numerico ausente ou invalido")
                    };
                    let id = numero()?;
                    let mut lado = || -> Result<u32, &'static str> {
                        u32::try_from(numero()?).map_err(|_| "coordenada negativa ou grande demais")
                    };
                    let moldura = Retangulo {
                        x: lado()?,
                        y: lado()?,
                        largura: lado()?,
                        altura: lado()?,
                    };
                    let rotulo = resolvido(campos.next().ok_or("elemento sem rotulo")?)?;
                    let valor = if tipo.tem_valor() {
                        Some(resolvido(campos.next().ok_or("texto ou campo sem valor")?)?)
                    } else {
                        None
                    };
                    if campos.next().is_some() {
                        return Err("campos demais numa linha");
                    }
                    elementos.push(Elemento {
                        tipo,
                        id,
                        moldura,
                        rotulo,
                        valor,
                    });
                }
                // O foco é de um campo que a descrição tem: um foco num
                // botão, ou num elemento que não existe, não diz que
                // recurso a tecla edita.
                if let Some(id) = foco
                    && !elementos
                        .iter()
                        .any(|e: &Elemento| e.id == id && e.tipo == Tipo::Campo)
                {
                    return Err("foco que nao e um campo da descricao");
                }
                Ok(Descricao {
                    titulo,
                    elementos,
                    foco,
                })
            }
        }

        /// Um rótulo ou valor, com o escape resolvido e o tamanho conferido.
        fn resolvido(texto: &str) -> Result<String, &'static str> {
            let mut saida = String::new();
            if !resolver(texto, |c| saida.push(c)) {
                return Err("escape invalido");
            }
            if saida.len() > MAIOR_TEXTO {
                return Err("rotulo ou valor grande demais");
            }
            Ok(saida)
        }

        /// Escreve uma descrição, com as mesmas regras de quem a lê.
        ///
        /// Os limites são conferidos aqui, e não só no kernel: um texto
        /// longo demais ou elementos demais viram um erro de quem escreve,
        /// no processo, em vez de uma descrição inteira recusada do outro
        /// lado da fronteira sem ninguém saber por quê.
        pub struct Escritor {
            texto: String,
            elementos: usize,
            foco: Option<i64>,
            erro: Option<&'static str>,
        }

        impl Escritor {
            /// Uma descrição nova, da janela com este título.
            pub fn nova(titulo: &str) -> Escritor {
                let mut e = Escritor {
                    texto: String::new(),
                    elementos: 0,
                    foco: None,
                    erro: None,
                };
                e.texto.push_str("janela\t");
                e.campo_de_texto(titulo);
                e
            }

            fn campo_de_texto(&mut self, texto: &str) {
                if texto.len() > MAIOR_TEXTO {
                    self.erro.get_or_insert("rotulo ou valor grande demais");
                }
                let _ = escapar(texto, &mut self.texto);
            }

            /// Acrescenta um elemento. O valor vai só nos tipos que o
            /// levam — ver [`Tipo::tem_valor`] —, e é ignorado nos outros.
            pub fn elemento(
                &mut self,
                tipo: Tipo,
                id: i64,
                moldura: Retangulo,
                rotulo: &str,
                valor: &str,
            ) -> &mut Escritor {
                self.elementos += 1;
                if self.elementos > MAIS_ELEMENTOS {
                    self.erro.get_or_insert("elementos demais");
                }
                let _ = write!(
                    self.texto,
                    "\n{}\t{}\t{}\t{}\t{}\t{}\t",
                    tipo.palavra(),
                    id,
                    moldura.x,
                    moldura.y,
                    moldura.largura,
                    moldura.altura
                );
                self.campo_de_texto(rotulo);
                if tipo.tem_valor() {
                    self.texto.push('\t');
                    self.campo_de_texto(valor);
                }
                self
            }

            /// Declara o campo que recebe as teclas: o identificador de um
            /// elemento `campo` já acrescentado ou ainda por acrescentar.
            pub fn foco(&mut self, id: i64) -> &mut Escritor {
                self.foco = Some(id);
                self
            }

            /// O texto pronto, ou o primeiro limite que ele passou.
            pub fn terminar(mut self) -> Result<String, &'static str> {
                if let Some(erro) = self.erro {
                    return Err(erro);
                }
                if let Some(id) = self.foco {
                    let _ = write!(self.texto, "\nfoco\t{id}");
                }
                if self.texto.len() > MAIOR {
                    return Err("descricao grande demais");
                }
                Ok(self.texto)
            }
        }
    }
}

#[cfg(all(test, feature = "alloc"))]
mod testes {
    #[test]
    fn o_enter_de_cada_agente_diz_qual() {
        use super::terminal::{agente_que_confirmou, confirmar_pelo_agente};
        for sessao in [0u8, 1, 4, 255] {
            assert_eq!(
                agente_que_confirmou(confirmar_pelo_agente(sessao)),
                Some(sessao)
            );
        }
        assert_eq!(agente_que_confirmou('\n'), None);
        assert_eq!(
            agente_que_confirmou(super::terminal::CONFIRMAR_PELO_AGENTE),
            None
        );
        assert_eq!(agente_que_confirmou('\u{F5FF}'), None);
        assert_eq!(agente_que_confirmou('\u{F700}'), None);
        use super::evento::origem;
        assert_eq!(origem::sessao(origem::agente(3)), Some(3));
        assert_eq!(origem::sessao(origem::PESSOA), None);
        assert_eq!(origem::sessao(256), None);
    }

    #[test]
    fn nenhuma_superficie_sobe_acima_da_barra() {
        use super::superficie::{PRIMEIRA_LINHA, posicao_permitida};
        assert_eq!(posicao_permitida(5, 0), (5, PRIMEIRA_LINHA));
        assert_eq!(posicao_permitida(-9, i32::MIN), (-9, PRIMEIRA_LINHA));
        assert_eq!(
            posicao_permitida(0, PRIMEIRA_LINHA - 1),
            (0, PRIMEIRA_LINHA)
        );
        // Na linha, e abaixo dela, a posição pedida vale como veio.
        assert_eq!(posicao_permitida(7, PRIMEIRA_LINHA), (7, PRIMEIRA_LINHA));
        assert_eq!(posicao_permitida(7, 300), (7, 300));
    }

    use super::descricao::*;

    fn r(x: u32, y: u32, largura: u32, altura: u32) -> Retangulo {
        Retangulo {
            x,
            y,
            largura,
            altura,
        }
    }

    #[test]
    fn o_que_se_escreve_e_o_que_se_le() {
        let mut e = Escritor::nova("Sobre\to Duke");
        e.elemento(Tipo::Botao, 1, r(10, 2, 16, 16), "Fechar", "ignorado")
            .elemento(
                Tipo::Texto,
                2,
                r(1, 22, 398, 167),
                "conteudo",
                "linha 1\nlinha\\2",
            )
            .elemento(Tipo::Campo, 3, r(10, 60, 200, 22), "nome", "Ana\tMaria")
            .elemento(Tipo::Area, 4, r(0, 0, 640, 384), "terminal", "duke> \nok");
        let texto = e.terminar().unwrap();
        let d = Descricao::ler(&texto).unwrap();
        assert_eq!(d.titulo, "Sobre\to Duke");
        assert_eq!(d.elementos.len(), 4);
        assert_eq!(d.elementos[3].tipo, Tipo::Area);
        assert_eq!(d.elementos[3].valor.as_deref(), Some("duke> \nok"));
        assert_eq!(d.elementos[2].tipo, Tipo::Campo);
        assert_eq!(d.elementos[2].valor.as_deref(), Some("Ana\tMaria"));
        assert_eq!(d.elementos[0].tipo, Tipo::Botao);
        assert_eq!(d.elementos[0].valor, None);
        assert_eq!(d.elementos[0].moldura, r(10, 2, 16, 16));
        assert_eq!(d.elementos[1].valor.as_deref(), Some("linha 1\nlinha\\2"));
        assert_eq!(d.elementos[1].id, 2);
    }

    /// O foco vai e volta; sem ele, nenhum; e o leitor recusa o foco que
    /// não é de um campo da descrição, ou repetido.
    #[test]
    fn o_foco_e_de_um_campo() {
        let mut e = Escritor::nova("x");
        e.elemento(Tipo::Botao, 1, r(0, 0, 1, 1), "b", "")
            .elemento(Tipo::Campo, 2, r(0, 0, 1, 1), "nome", "")
            .foco(2);
        let texto = e.terminar().unwrap();
        assert!(texto.ends_with("\nfoco\t2"));
        assert_eq!(Descricao::ler(&texto).unwrap().foco, Some(2));
        let mut sem = Escritor::nova("x");
        sem.elemento(Tipo::Campo, 2, r(0, 0, 1, 1), "nome", "");
        assert_eq!(Descricao::ler(&sem.terminar().unwrap()).unwrap().foco, None);
        for ruim in [
            "janela\tx\nbotao\t1\t0\t0\t1\t1\tb\nfoco\t1",
            "janela\tx\ncampo\t2\t0\t0\t1\t1\tc\tv\nfoco\t9",
            "janela\tx\ncampo\t2\t0\t0\t1\t1\tc\tv\nfoco\t2\nfoco\t2",
            "janela\tx\ncampo\t2\t0\t0\t1\t1\tc\tv\nfoco\tdois",
        ] {
            assert!(Descricao::ler(ruim).is_err(), "{ruim:?}");
        }
    }

    #[test]
    fn o_escritor_recusa_o_que_o_leitor_recusaria() {
        let mut e = Escritor::nova("x");
        for i in 0..=MAIS_ELEMENTOS as i64 {
            e.elemento(Tipo::Botao, i, r(0, 0, 1, 1), "b", "");
        }
        assert_eq!(e.terminar(), Err("elementos demais"));

        let longo = "a".repeat(MAIOR_TEXTO + 1);
        let mut e = Escritor::nova("x");
        e.elemento(Tipo::Texto, 1, r(0, 0, 1, 1), "t", &longo);
        assert!(e.terminar().is_err());

        // E o que passa pelo escritor passa pelo leitor, no limite exato.
        let mut e = Escritor::nova("x");
        for i in 0..MAIS_ELEMENTOS as i64 {
            e.elemento(Tipo::Botao, i, r(0, 0, 1, 1), "b", "");
        }
        assert!(Descricao::ler(&e.terminar().unwrap()).is_ok());
    }

    #[test]
    fn o_leitor_recusa_o_que_nao_entende() {
        for ruim in [
            "",
            "botao\t1\t0\t0\t1\t1\tb",
            "janela\tx\ncaixa\t1\t0\t0\t1\t1\tb",
            "janela\tx\nbotao\t1\t-1\t0\t1\t1\tb",
            "janela\tx\nbotao\t1\t0\t0\t1\t1\tb\tsobra",
            "janela\tx\ntexto\t1\t0\t0\t1\t1\tsem valor",
            "janela\tx\ncampo\t1\t0\t0\t1\t1\tsem valor",
            "janela\tx\narea\t1\t0\t0\t1\t1\tsem valor",
            "janela\tx\\q",
        ] {
            assert!(Descricao::ler(ruim).is_err(), "aceitou {ruim:?}");
        }
    }
}

/// Quantos bytes o ponteiro de `esperar` precisa ter — ver
/// [`numero::ESPERAR`].
///
/// Dois `i64`: o código de saída e se ele significa alguma coisa.
///
/// # Por que não basta o código
///
/// Porque nem todo processo sai por `sair`. Um morto por falha de página ou
/// de proteção termina sem código nenhum, e a primeira versão desta chamada
/// escrevia zero nesse caso — que é um código de saída perfeitamente
/// legítimo, e o mais comum de todos. O pai lia zero e concluía que o filho
/// tinha terminado bem.
///
/// É a pior forma de falhar: não há erro, não há ausência, há uma resposta
/// plausível e errada. Um supervisor que reinicia trabalhador que morreu
/// nunca reiniciaria nenhum.
///
/// Não dá para resolver dentro de um número só: **todo** `i64` é um código
/// de saída válido, então não existe sentinela. A segunda palavra é a saída
/// — e ela cabe também para o que vier depois, como qual falha matou o
/// processo.
pub const BYTES_DO_DESFECHO: u64 = 16;

/// O que a segunda palavra do desfecho carrega.
pub mod desfecho {
    /// O processo chamou `sair`, e a primeira palavra é o código dele.
    pub const SAIU: i64 = 1;
    /// O processo foi morto antes de chamar `sair`. A primeira palavra não
    /// significa nada, e é escrita como zero para não vazar lixo.
    pub const MORTO: i64 = 0;
}

/// Os descritores que todo processo recebe abertos.
///
/// Os números são os do Unix, e isso é deliberado: não porque o Duke pretenda
/// ser POSIX, mas porque qualquer pessoa que já escreveu um programa sabe de
/// cor o que 1 e 2 significam. Inventar uma numeração própria cobraria esse
/// conhecimento de volta sem devolver nada.
pub mod padrao {
    /// Leitura. Reservado: ainda não há de onde ler, e **escrever nele é
    /// erro** — é o caso que prova que a tabela é consultada de verdade.
    pub const ENTRADA: u64 = 0;
    /// Saída comum. Vai para o log do kernel em nível `info`.
    pub const SAIDA: u64 = 1;
    /// Saída de erro. Vai para o mesmo log em nível `error`.
    pub const ERRO: u64 = 2;
}

/// Onde o espaço do usuário começa.
///
/// Uma faixa baixa e modesta, bem longe do heap do kernel (64 GiB), das
/// pilhas de fio (128 GiB) e do kernel. No x86 o kernel vive na metade alta,
/// então qualquer endereço aqui é inequivocamente do usuário; no ARM o kernel
/// está em `0x4008_0000`, e por isso a faixa começa acima dos 4 GiB — não há
/// como confundir uma com a outra.
pub const BASE: u64 = 0x0000_0001_0000_0000;
/// Fim exclusivo da faixa do usuário.
pub const TETO: u64 = BASE + 0x1000_0000;

/// Quantas páginas de pilha um processo recebe.
///
/// Dezesseis — 64 KiB. Os programas montados à mão viviam com uma, e um
/// programa compilado não vive: um `format!` com a pilha de depuração de uma
/// função genérica passa de 4 KiB sem ninguém perceber, e o que se perceberia
/// seria a página de guarda.
pub const PAGINAS_DA_PILHA: u64 = 16;

/// O tamanho de página que esta ABI assume nas duas arquiteturas.
pub const PAGINA: u64 = 4096;

/// A faixa onde `mapear` aceita criar memória: `[inicio, fim)`.
///
/// # O mapa, de baixo para cima
///
/// ```text
///   BASE                código e dados do programa (até 64 MiB)
///   BASE + 64 MiB       ┐
///        …              │ MAPEAVEL: o monte e o que mais o processo mapear
///   TETO - 16 MiB       ┘
///        …              não mapeado
///   TETO - 68 KiB       página de guarda
///   TETO - 64 KiB       pilha
///   TETO
/// ```
///
/// Os limites são largos dos dois lados de propósito: uma faixa que
/// encostasse no programa ou na pilha faria um `mapear` legítimo depender
/// do tamanho de um executável, ou de quanto a pilha cresceu.
pub const MAPEAVEL: (u64, u64) = (BASE + 0x0400_0000, TETO - 0x0100_0000);

// O mapa acima só vale se as fatias não se sobrepõem, e é o compilador quem
// confere.
const _: () = assert!(MAPEAVEL.0 < MAPEAVEL.1);
const _: () = assert!(MAPEAVEL.1 <= TETO - (PAGINAS_DA_PILHA + 1) * PAGINA);
const _: () = assert!(MAPEAVEL.0.is_multiple_of(PAGINA) && MAPEAVEL.1.is_multiple_of(PAGINA));

/// O manifesto de um programa, como ele viaja no executável: o conteúdo de
/// uma nota ELF de dono `Duke` e tipo [`TIPO`](manifesto::TIPO), num
/// segmento `PT_NOTE`. O texto é o de `politica::manifesto`; aqui fica só o
/// envelope, que os dois lados — o pacote `programas`, que monta a nota, e
/// o kernel, que a acha — precisam ler igual.
///
/// # O formato de uma nota
///
/// ```text
///   u32 tamanho do dono   u32 tamanho do conteúdo   u32 tipo
///   dono, completado com zeros até múltiplo de 4
///   conteúdo, completado com zeros até múltiplo de 4
/// ```
///
/// O de qualquer ELF: um executável do Duke continua legível por um
/// `readelf -n`.
pub mod manifesto {
    /// O dono das notas do Duke, com o zero final que o formato conta.
    pub const DONO: &[u8; 5] = b"Duke\0";
    /// O tipo da nota do manifesto.
    pub const TIPO: u32 = 1;
    /// O maior manifesto, em bytes. Um manifesto é uma dúzia de linhas; o
    /// teto existe porque o tamanho vem do arquivo.
    pub const MAIOR: usize = 1024;
    /// `PT_NOTE`, o tipo do segmento que leva as notas.
    pub const SEGMENTO_DE_NOTAS: u32 = 4;

    const fn alinhar(n: usize) -> usize {
        (n + 3) & !3
    }

    /// O tamanho da nota que leva `texto`.
    pub const fn tamanho_da_nota(texto: &str) -> usize {
        12 + alinhar(DONO.len()) + alinhar(texto.len())
    }

    /// A nota que leva `texto`, com `N` = [`tamanho_da_nota`]. Em tempo de
    /// compilação: é assim que o pacote `programas` a põe no executável.
    pub const fn nota<const N: usize>(texto: &str) -> [u8; N] {
        assert!(N == tamanho_da_nota(texto), "tamanho de nota errado");
        assert!(texto.len() <= MAIOR, "manifesto grande demais");
        let mut nota = [0u8; N];
        let dono = (DONO.len() as u32).to_le_bytes();
        let conteudo = (texto.len() as u32).to_le_bytes();
        let tipo = TIPO.to_le_bytes();
        let mut i = 0;
        while i < 4 {
            nota[i] = dono[i];
            nota[4 + i] = conteudo[i];
            nota[8 + i] = tipo[i];
            i += 1;
        }
        let mut i = 0;
        while i < DONO.len() {
            nota[12 + i] = DONO[i];
            i += 1;
        }
        let inicio = 12 + alinhar(DONO.len());
        let bytes = texto.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            nota[inicio + i] = bytes[i];
            i += 1;
        }
        nota
    }

    /// O manifesto entre as notas de um segmento `PT_NOTE`: `Ok(None)` se
    /// nenhuma é do Duke com o tipo do manifesto.
    ///
    /// Recusa o segmento malformado — um tamanho que passa do fim, um
    /// manifesto maior que [`MAIOR`] — e o que tem **dois** manifestos: o
    /// kernel não escolhe um, porque escolher é o que um executável
    /// adulterado gostaria que ele fizesse.
    pub fn achar(notas: &[u8]) -> Result<Option<&[u8]>, &'static str> {
        let u32_em = |i: usize| -> Option<usize> {
            let b = notas.get(i..i.checked_add(4)?)?;
            Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
        };
        let mut achado = None;
        let mut i = 0;
        while i < notas.len() {
            let (Some(dono), Some(conteudo), Some(tipo)) =
                (u32_em(i), u32_em(i + 4), u32_em(i + 8))
            else {
                return Err("nota truncada");
            };
            let inicio_do_dono = i + 12;
            let inicio_do_conteudo = inicio_do_dono
                .checked_add(alinhar(dono.min(MAIOR + 1)))
                .ok_or("nota absurda")?;
            if dono > MAIOR || conteudo > usize::MAX / 2 {
                return Err("nota absurda");
            }
            let fim = inicio_do_conteudo
                .checked_add(alinhar(conteudo))
                .ok_or("nota absurda")?;
            if fim > notas.len() {
                return Err("nota passa do fim do segmento");
            }
            let e_do_duke = &notas[inicio_do_dono..inicio_do_dono + dono] == DONO.as_slice();
            if e_do_duke && tipo as u32 == TIPO {
                if conteudo > MAIOR {
                    return Err("manifesto grande demais");
                }
                if achado.is_some() {
                    return Err("dois manifestos");
                }
                achado = Some(&notas[inicio_do_conteudo..inicio_do_conteudo + conteudo]);
            }
            i = fim;
        }
        Ok(achado)
    }

    #[cfg(test)]
    mod testes {
        use super::*;

        const TEXTO: &str = "duke-manifesto 1\nnome a\n";
        const N: usize = tamanho_da_nota(TEXTO);
        const NOTA: [u8; N] = nota::<N>(TEXTO);

        #[test]
        fn a_nota_montada_e_achada() {
            assert_eq!(N % 4, 0);
            assert_eq!(achar(&NOTA), Ok(Some(TEXTO.as_bytes())));
        }

        #[test]
        fn outras_notas_passam_e_dois_manifestos_nao() {
            // Uma nota GNU antes: ignorada.
            let mut gnu = std::vec![4, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0];
            gnu.extend_from_slice(b"GNU\0abcd");
            let mut ambas = gnu.clone();
            ambas.extend_from_slice(&NOTA);
            assert_eq!(achar(&ambas), Ok(Some(TEXTO.as_bytes())));
            assert_eq!(achar(&gnu), Ok(None));
            assert_eq!(achar(&[]), Ok(None));
            let mut duas = NOTA.to_vec();
            duas.extend_from_slice(&NOTA);
            assert_eq!(achar(&duas), Err("dois manifestos"));
        }

        #[test]
        fn tamanhos_do_arquivo_sao_conferidos() {
            assert!(achar(&NOTA[..N - 1]).is_err());
            assert!(achar(&NOTA[..5]).is_err());
            let mut grande = NOTA;
            grande[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(achar(&grande).is_err());
            let mut dono = NOTA;
            dono[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(achar(&dono).is_err());
            // Outro tipo do mesmo dono não é o manifesto.
            let mut outro = NOTA;
            outro[8] = 2;
            assert_eq!(achar(&outro), Ok(None));
        }
    }
}
