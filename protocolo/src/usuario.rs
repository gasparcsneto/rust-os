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
        /// [`posicao`](super::posicao)`(x, y)`.
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

        /// O teclado: `1` pede que as teclas venham para o dono desta
        /// superfície, como eventos de [`TECLA`](crate::usuario::evento::tipo::TECLA)
        /// no canal das janelas; `0` as devolve ao console. O foco também
        /// volta ao console quando a superfície fecha, ou quando a pessoa
        /// clica fora de toda superfície de processo.
        pub const FOCO: u64 = 6;

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
        /// O foco voltou ao kernel: a pessoa clicou fora de toda superfície
        /// de processo, e as teclas voltam ao console.
        pub const FOCO_PERDIDO: u32 = 5;
        /// Um pedido para o servidor fechar tudo e sair. Da suíte, que
        /// não deixa um servidor vivo para os casos seguintes.
        pub const ENCERRAR: u32 = 6;
        /// Uma ação sobre um elemento que o servidor descreveu — ver
        /// [`descricao`](crate::usuario::descricao): `a` é o identificador
        /// que o servidor deu ao elemento, `b` a ação, de
        /// [`acao`](super::acao).
        pub const ACAO: u32 = 7;
    }

    /// As ações de um evento [`tipo::ACAO`].
    pub mod acao {
        /// Acionar, como um clique num botão — o `press` da árvore.
        pub const PRESSIONAR: i64 = 1;
    }

    /// O bit do botão esquerdo em `c` de um evento de ponteiro.
    pub const BOTAO_ESQUERDO: i64 = 1;

    /// O canal onde o kernel publica a entrada das janelas e os pedidos de
    /// abrir uma: quem o escuta é o servidor de janelas.
    pub const CANAL_DAS_JANELAS: &str = "janelas";

    /// Que janela um [`tipo::ABRIR`] pede.
    pub mod janela {
        /// Uma janela vazia, que mostra o que se digita nela. A da suíte.
        pub const TESTE: i64 = 1;
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
/// ```
///
/// A linha `janela` vem primeiro, e uma vez. O `id` é do servidor: é o que
/// volta a ele num evento de [`ACAO`](evento::tipo::ACAO) quando alguém
/// aciona o elemento pela árvore. O retângulo é **da superfície**, e o
/// kernel o leva à tela somando a posição da camada. Num rótulo ou num
/// valor, a tabulação, a quebra de linha e a barra invertida vão como
/// `\t`, `\n` e `\\` — ver [`escapar`](descricao::escapar).
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
