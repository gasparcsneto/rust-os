"""O HTTP/2 da bancada do Duke: o lado do servidor (RFC 9113 e RFC 7541),
para o cliente do pacote `http`.

O `http.py` passa para ca a conexao que comecou com o prefacio do HTTP/2 -
na porta 80, com conhecimento previo (h2c); na 8443, quando o ALPN do TLS
escolheu `h2` - e a funcao que responde cada pedido. Um processo por
conexao, um fio so: as correntes se intercalam quadro a quadro, cada uma
dentro da janela que o cliente deu, e uma rota lenta nao segura as outras.

O que este lado faz de proposito, para o cliente ter o que conferir:

- o HPACK das respostas indexa: o que se repete entre respostas vai pela
  tabela dinamica, e as cadeias vao em Huffman quando encurtam;
- as respostas grandes saem em quadros intercalados entre as correntes;
- as janelas do cliente sao respeitadas, e as do servidor reabertas
  conforme o corpo de um pedido chega.

E as respostas hostis (ver `Resposta2.hostil`), que quebram o protocolo de
um jeito que o cliente tem de recusar.

Nada sai pela saida padrao nem pela de erro: as duas sao a conexao.
"""

import select
import socket
import time

PREFACIO = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Os tipos de quadro.
DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS = 0x0, 0x1, 0x2, 0x3, 0x4
PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = 0x5, 0x6, 0x7, 0x8, 0x9

# As bandeiras.
END_STREAM = 0x1
ACK = 0x1
END_HEADERS = 0x4
PADDED = 0x8
PRIORIDADE = 0x20

# Os codigos de erro.
NO_ERROR, PROTOCOL_ERROR, INTERNAL_ERROR, FLOW_CONTROL_ERROR = 0x0, 0x1, 0x2, 0x3
FRAME_SIZE_ERROR, REFUSED_STREAM, CANCEL, COMPRESSION_ERROR = 0x6, 0x7, 0x8, 0x9
ENHANCE_YOUR_CALM = 0xB

# Os ajustes.
HEADER_TABLE_SIZE, ENABLE_PUSH, MAX_CONCURRENT_STREAMS = 0x1, 0x2, 0x3
INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, MAX_HEADER_LIST_SIZE = 0x4, 0x5, 0x6

# O que o servidor anuncia: as correntes que aceita, e a janela de cada uma.
CORRENTES = 100
JANELA = 65535
JANELA_MAXIMA = (1 << 31) - 1

# O maior quadro e o maior bloco de cabeca que se aceitam do cliente.
MAIOR_QUADRO = 16384
MAIOR_BLOCO = 64 * 1024
# O maior corpo de pedido.
MAIOR_CORPO = 1024 * 1024

# O codigo de Huffman (RFC 7541, Apendice B): o codigo e o tamanho de cada
# simbolo, 0 a 255, e o EOS. Gerado da tabela do pacote `http`, que foi
# transcrita de duas implementacoes e conferida entre elas.
HUFFMAN = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),
    (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
    (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),
    (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),
    (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
    (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),
    (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7),
    (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
    (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
    (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),
    (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5),
    (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),
    (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),
    (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),
    (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),
    (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23),
    (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),
    (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22),
    (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24),
    (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),
    (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),
    (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22),
    (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19),
    (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25),
    (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27),
    (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26),
    (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27),
    (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),
    (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25),
    (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26),
    (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27),
    (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26),
    (0x3fffffff, 30),
]

# A tabela estatica (RFC 7541, Apendice A), da mesma fonte.
ESTATICA = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
]

# Do codigo ao simbolo, para decodificar.
_PELO_CODIGO = {(codigo, bits): simbolo for simbolo, (codigo, bits) in enumerate(HUFFMAN)}


class ErroH2(Exception):
    """Um erro da conexao: o codigo que vai no GOAWAY."""

    def __init__(self, codigo, texto):
        super().__init__(texto)
        self.codigo = codigo


def huffman(dados):
    """`dados` em Huffman, com o preenchimento de uns."""
    acumulado = 0
    bits = 0
    for b in dados:
        codigo, n = HUFFMAN[b]
        acumulado = (acumulado << n) | codigo
        bits += n
    falta = -bits % 8
    acumulado = (acumulado << falta) | ((1 << falta) - 1)
    return acumulado.to_bytes((bits + falta) // 8, "big")


def de_huffman(dados):
    """A cadeia em Huffman `dados`, decodificada; o EOS e o preenchimento
    torto sao erro de compressao."""
    saida = bytearray()
    codigo = 0
    bits = 0
    for byte in dados:
        for desloca in range(7, -1, -1):
            codigo = (codigo << 1) | ((byte >> desloca) & 1)
            bits += 1
            simbolo = _PELO_CODIGO.get((codigo, bits))
            if simbolo is not None:
                if simbolo == 256:
                    raise ErroH2(COMPRESSION_ERROR, "EOS numa cadeia")
                saida.append(simbolo)
                codigo = 0
                bits = 0
            elif bits >= 30:
                raise ErroH2(COMPRESSION_ERROR, "codigo de Huffman invalido")
    if bits > 7 or codigo != (1 << bits) - 1:
        raise ErroH2(COMPRESSION_ERROR, "preenchimento de Huffman torto")
    return bytes(saida)


def ler_inteiro(bloco, pos, prefixo):
    mascara = (1 << prefixo) - 1
    if pos >= len(bloco):
        raise ErroH2(COMPRESSION_ERROR, "bloco cortado")
    valor = bloco[pos] & mascara
    pos += 1
    if valor < mascara:
        return valor, pos
    desloca = 0
    while True:
        if pos >= len(bloco) or desloca > 28:
            raise ErroH2(COMPRESSION_ERROR, "inteiro cortado ou grande")
        b = bloco[pos]
        pos += 1
        valor += (b & 0x7F) << desloca
        if not b & 0x80:
            return valor, pos
        desloca += 7


def por_inteiro(valor, prefixo, bandeiras):
    mascara = (1 << prefixo) - 1
    if valor < mascara:
        return bytes([bandeiras | valor])
    saida = bytearray([bandeiras | mascara])
    valor -= mascara
    while valor >= 0x80:
        saida.append((valor & 0x7F) | 0x80)
        valor >>= 7
    saida.append(valor)
    return bytes(saida)


def ler_cadeia(bloco, pos):
    if pos >= len(bloco):
        raise ErroH2(COMPRESSION_ERROR, "bloco cortado")
    em_huffman = bloco[pos] & 0x80
    n, pos = ler_inteiro(bloco, pos, 7)
    if pos + n > len(bloco):
        raise ErroH2(COMPRESSION_ERROR, "cadeia cortada")
    cru = bytes(bloco[pos:pos + n])
    return (de_huffman(cru) if em_huffman else cru), pos + n


def por_cadeia(dados):
    codificada = huffman(dados)
    if len(codificada) < len(dados):
        return por_inteiro(len(codificada), 7, 0x80) + codificada
    return por_inteiro(len(dados), 7, 0) + dados


def ocupa(nome, valor):
    return 32 + len(nome) + len(valor)


class Tabela:
    """A tabela dinamica de um lado do HPACK: a entrada mais nova na frente."""

    def __init__(self, maximo):
        self.entradas = []
        self.ocupado = 0
        self.maximo = maximo

    def campo(self, indice):
        if 1 <= indice <= len(ESTATICA):
            return ESTATICA[indice - 1]
        i = indice - len(ESTATICA) - 1
        if indice == 0 or i >= len(self.entradas):
            raise ErroH2(COMPRESSION_ERROR, "indice fora das tabelas")
        return self.entradas[i]

    def caber(self):
        while self.ocupado > self.maximo:
            nome, valor = self.entradas.pop()
            self.ocupado -= ocupa(nome, valor)

    def inserir(self, nome, valor):
        tamanho = ocupa(nome, valor)
        if tamanho > self.maximo:
            self.entradas = []
            self.ocupado = 0
            return
        self.entradas.insert(0, (nome, valor))
        self.ocupado += tamanho
        self.caber()


class Decodificador:
    """Os blocos de cabeca dos pedidos."""

    def __init__(self):
        self.tabela = Tabela(4096)

    def decodificar(self, bloco):
        campos = []
        pos = 0
        while pos < len(bloco):
            b = bloco[pos]
            if b & 0x80:
                indice, pos = ler_inteiro(bloco, pos, 7)
                campos.append(self.tabela.campo(indice))
            elif b & 0xC0 == 0x40:
                indice, pos = ler_inteiro(bloco, pos, 6)
                if indice:
                    nome = self.tabela.campo(indice)[0]
                else:
                    nome, pos = ler_cadeia(bloco, pos)
                valor, pos = ler_cadeia(bloco, pos)
                self.tabela.inserir(nome, valor)
                campos.append((nome, valor))
            elif b & 0xE0 == 0x20:
                maximo, pos = ler_inteiro(bloco, pos, 5)
                if campos or maximo > 4096:
                    raise ErroH2(COMPRESSION_ERROR, "atualizacao de tamanho fora do lugar")
                self.tabela.maximo = maximo
                self.tabela.caber()
            else:
                indice, pos = ler_inteiro(bloco, pos, 4)
                if indice:
                    nome = self.tabela.campo(indice)[0]
                else:
                    nome, pos = ler_cadeia(bloco, pos)
                valor, pos = ler_cadeia(bloco, pos)
                campos.append((nome, valor))
        return campos


class Codificador:
    """Os blocos de cabeca das respostas: indexa o que se repete."""

    # O que nao vai para a tabela: muda a cada resposta, ou e segredo.
    SEM_INDEXAR = (b"content-length", b"set-cookie", b"date")

    def __init__(self):
        self.tabela = Tabela(4096)

    def codificar(self, campos):
        bloco = bytearray()
        for nome, valor in campos:
            exato = None
            so_o_nome = None
            for i, (n, v) in enumerate(ESTATICA):
                if n == nome:
                    so_o_nome = so_o_nome or i + 1
                    if v == valor:
                        exato = i + 1
                        break
            if exato is None:
                for i, (n, v) in enumerate(self.tabela.entradas):
                    if n == nome and v == valor:
                        exato = len(ESTATICA) + 1 + i
                        break
            if exato is not None:
                bloco += por_inteiro(exato, 7, 0x80)
                continue
            if nome in self.SEM_INDEXAR:
                bandeiras, prefixo = 0x00, 4
            else:
                bandeiras, prefixo = 0x40, 6
            if so_o_nome:
                bloco += por_inteiro(so_o_nome, prefixo, bandeiras)
            else:
                bloco += por_inteiro(0, prefixo, bandeiras) + por_cadeia(nome)
            bloco += por_cadeia(valor)
            if bandeiras == 0x40:
                self.tabela.inserir(nome, valor)
        return bytes(bloco)


def quadro(tipo, bandeiras, corrente, carga=b""):
    return (
        len(carga).to_bytes(3, "big") + bytes([tipo, bandeiras])
        + (corrente & JANELA_MAXIMA).to_bytes(4, "big") + carga
    )


def ajustes(pares):
    return quadro(SETTINGS, 0, 0, b"".join(i.to_bytes(2, "big") + v.to_bytes(4, "big") for i, v in pares))


def janela(corrente, incremento):
    return quadro(WINDOW_UPDATE, 0, corrente, incremento.to_bytes(4, "big"))


def reinicio(corrente, codigo):
    return quadro(RST_STREAM, 0, corrente, codigo.to_bytes(4, "big"))


def adeus(ultima, codigo):
    return quadro(GOAWAY, 0, 0, ultima.to_bytes(4, "big") + codigo.to_bytes(4, "big"))


class Resposta2:
    """O que o servidor responde a um pedido.

    - `atraso`: segundos antes da cabeca;
    - `pausa`: (n, segundos) - os n primeiros bytes do corpo, a espera, e o
      resto;
    - `nunca`: a resposta nao vem - a corrente fica aberta;
    - `hostil`: em vez de uma resposta, o que quebra o protocolo:
      `reinicia` (RST_STREAM INTERNAL_ERROR), `recusa` (REFUSED_STREAM),
      `adeus` (GOAWAY com ENHANCE_YOUR_CALM, e a conexao fecha), `empurra`
      (um PUSH_PROMISE, que o cliente desligou), `hpack` (um bloco que nao
      se decodifica), `enxurrada` (dois mil PING antes da resposta).
    """

    def __init__(self, status, cabecalhos=(), corpo=b"", atraso=0.0, pausa=None, nunca=False,
                 hostil=None):
        self.status = status
        self.cabecalhos = list(cabecalhos)
        self.corpo = corpo
        self.atraso = atraso
        self.pausa = pausa
        self.nunca = nunca
        self.hostil = hostil


class Corrente:
    def __init__(self, numero, janela_do_cliente):
        self.numero = numero
        self.campos = []
        self.corpo = bytearray()
        self.completo = False
        self.resposta = None
        self.pronta_em = 0.0
        self.cabeca_saiu = False
        self.enviado = 0
        self.janela = janela_do_cliente
        self.reiniciada = False


class Servidor2:
    """Uma conexao HTTP/2: o lado do servidor."""

    def __init__(self, conexao, responder, log, inicio):
        self.conexao = conexao
        self.responder = responder
        self.log = log
        self.entrada = bytearray(inicio)
        self.prefacio = False
        self.decodificador = Decodificador()
        self.codificador = Codificador()
        self.correntes = {}
        self.ultima = 0
        self.pedidos = 0
        self.bloco = None
        # As janelas do cliente: a inicial de cada corrente, e a da conexao.
        self.janela_inicial = 65535
        self.janela = 65535
        self.quadro_do_cliente = 16384
        self.adeus_do_cliente = False
        self.acabou = False
        # O que sai fica aqui ate a volta acabar, e vai numa escrita so,
        # como num servidor de verdade: a cabeca e o corpo de uma resposta
        # no mesmo segmento, e nao um segmento por quadro.
        self.saida = bytearray()

    def mandar(self, dados):
        self.saida += dados

    def despejar(self):
        if self.saida:
            dados = bytes(self.saida)
            self.saida.clear()
            self.conexao.sendall(dados)

    def servir(self):
        self.mandar(ajustes([
            (MAX_CONCURRENT_STREAMS, CORRENTES),
            (INITIAL_WINDOW_SIZE, JANELA),
            (MAX_FRAME_SIZE, MAIOR_QUADRO),
        ]))
        try:
            while not self.acabou:
                self.processar()
                self.produzir()
                self.despejar()
                if self.adeus_do_cliente and not self.pendentes():
                    break
                if self.acabou or not self.ler():
                    break
        except ErroH2 as erro:
            print("http2.py:", erro.codigo, erro, file=self.log, flush=True)
            self.mandar(adeus(self.ultima, erro.codigo))
        self.encerrar()

    def encerrar(self):
        """O fim educado do lado claro: a escrita fecha, e o que o cliente
        ainda mandar e lido e largado ate ele fechar. Um soquete fechado com
        bytes por ler sai com RST, e o reinicio levaria junto o GOAWAY que o
        cliente ainda nao leu. No TLS, o `http.py` faz o fecho do TLS."""
        try:
            self.despejar()
        except OSError:
            return
        if hasattr(self.conexao, "unwrap"):
            return
        try:
            self.conexao.shutdown(socket.SHUT_WR)
            self.conexao.settimeout(2)
            while self.conexao.recv(65536):
                pass
        except OSError:
            pass

    def pendentes(self):
        return any(c.resposta is not None or not c.completo for c in self.correntes.values())

    def proxima_espera(self):
        agora = time.monotonic()
        prazos = [
            c.pronta_em for c in self.correntes.values()
            if c.resposta is not None and not c.resposta.nunca and c.pronta_em > agora
        ]
        return max(0.0, min(prazos) - agora) if prazos else None

    def ler(self):
        """Espera o cliente ou o prazo da proxima resposta. Falso se o
        cliente fechou."""
        pendente = getattr(self.conexao, "pending", None)
        if not (pendente and pendente()):
            espera = self.proxima_espera()
            prontos, _, _ = select.select([self.conexao], [], [], 30 if espera is None else espera)
            if not prontos:
                return espera is not None
        dados = self.conexao.recv(65536)
        if not dados:
            return False
        self.entrada += dados
        return True

    def processar(self):
        if not self.prefacio:
            if len(self.entrada) < len(PREFACIO):
                return
            if bytes(self.entrada[:len(PREFACIO)]) != PREFACIO:
                raise ErroH2(PROTOCOL_ERROR, "sem o prefacio")
            del self.entrada[:len(PREFACIO)]
            self.prefacio = True
        while len(self.entrada) >= 9:
            tamanho = int.from_bytes(self.entrada[:3], "big")
            tipo, bandeiras = self.entrada[3], self.entrada[4]
            corrente = int.from_bytes(self.entrada[5:9], "big") & JANELA_MAXIMA
            if tamanho > MAIOR_QUADRO:
                raise ErroH2(FRAME_SIZE_ERROR, "quadro grande demais")
            if len(self.entrada) < 9 + tamanho:
                return
            carga = bytes(self.entrada[9:9 + tamanho])
            del self.entrada[:9 + tamanho]
            self.quadro(tipo, bandeiras, corrente, carga)

    def quadro(self, tipo, bandeiras, n, carga):
        if self.bloco is not None and (tipo != CONTINUATION or n != self.bloco[0]):
            raise ErroH2(PROTOCOL_ERROR, "quadro no meio de um bloco de cabeca")
        if tipo == SETTINGS:
            if bandeiras & ACK:
                return
            for i in range(0, len(carga) - len(carga) % 6, 6):
                ident = int.from_bytes(carga[i:i + 2], "big")
                valor = int.from_bytes(carga[i + 2:i + 6], "big")
                if ident == INITIAL_WINDOW_SIZE:
                    delta = valor - self.janela_inicial
                    self.janela_inicial = valor
                    for c in self.correntes.values():
                        c.janela += delta
                elif ident == MAX_FRAME_SIZE:
                    self.quadro_do_cliente = valor
            self.mandar(quadro(SETTINGS, ACK, 0))
        elif tipo == WINDOW_UPDATE:
            incremento = int.from_bytes(carga[:4], "big") & JANELA_MAXIMA
            if n == 0:
                self.janela += incremento
            elif n in self.correntes:
                self.correntes[n].janela += incremento
        elif tipo == PING:
            if not bandeiras & ACK:
                self.mandar(quadro(PING, ACK, 0, carga))
        elif tipo == HEADERS:
            if n % 2 == 0 or n <= self.ultima:
                raise ErroH2(PROTOCOL_ERROR, "corrente fora de ordem")
            self.ultima = n
            bloco = carga
            if bandeiras & PADDED:
                bloco = bloco[1:len(bloco) - bloco[0]]
            if bandeiras & PRIORIDADE:
                bloco = bloco[5:]
            self.correntes[n] = Corrente(n, self.janela_inicial)
            self.bloco = (n, bytearray(bloco), bool(bandeiras & END_STREAM))
            if bandeiras & END_HEADERS:
                self.fim_do_bloco()
        elif tipo == CONTINUATION:
            if self.bloco is None:
                raise ErroH2(PROTOCOL_ERROR, "CONTINUATION sem HEADERS")
            self.bloco[1].extend(carga)
            if len(self.bloco[1]) > MAIOR_BLOCO:
                raise ErroH2(ENHANCE_YOUR_CALM, "bloco de cabeca grande demais")
            if bandeiras & END_HEADERS:
                self.fim_do_bloco()
        elif tipo == DATA:
            dados = carga
            if bandeiras & PADDED:
                dados = dados[1:len(dados) - dados[0]]
            c = self.correntes.get(n)
            # O que chegou reabre as janelas na hora: o servidor le tudo.
            if carga:
                self.mandar(janela(0, len(carga)))
            if c is None or c.reiniciada:
                return
            if carga:
                self.mandar(janela(n, len(carga)))
            c.corpo += dados
            if len(c.corpo) > MAIOR_CORPO:
                self.mandar(reinicio(n, CANCEL))
                c.reiniciada = True
                return
            if bandeiras & END_STREAM:
                self.pedido_completo(c)
        elif tipo == RST_STREAM:
            c = self.correntes.get(n)
            if c is not None:
                c.reiniciada = True
                c.resposta = None
        elif tipo == GOAWAY:
            self.adeus_do_cliente = True
        # PRIORITY e os desconhecidos: ignorados.

    def fim_do_bloco(self):
        n, bloco, fim = self.bloco
        self.bloco = None
        c = self.correntes[n]
        c.campos = self.decodificador.decodificar(bytes(bloco))
        if fim:
            self.pedido_completo(c)

    def pedido_completo(self, c):
        c.completo = True
        self.pedidos += 1
        campos = {}
        for nome, valor in c.campos:
            nome = nome.decode("latin-1")
            valor = valor.decode("latin-1")
            # O cookie pode vir partido em varios campos (RFC 9113, 8.2.3).
            if nome == "cookie" and nome in campos:
                campos[nome] += "; " + valor
            else:
                campos.setdefault(nome, valor)
        resposta = self.responder(
            campos.get(":method", ""), campos.get(":path", ""), campos, bytes(c.corpo), self.pedidos
        )
        c.resposta = resposta
        c.pronta_em = time.monotonic() + resposta.atraso
        print("http2.py: pedido", self.pedidos, c.numero, campos.get(":method"),
              campos.get(":path"), file=self.log, flush=True)

    def produzir(self):
        """Manda o que esta pronto: as cabecas, e os corpos intercalados,
        um quadro por corrente de cada vez, dentro das janelas do cliente."""
        while True:
            andou = False
            agora = time.monotonic()
            for c in list(self.correntes.values()):
                r = c.resposta
                if r is None or c.reiniciada or r.nunca or c.pronta_em > agora:
                    continue
                if r.hostil:
                    self.hostil(c)
                    andou = True
                    if self.acabou:
                        return
                    continue
                if not c.cabeca_saiu:
                    # O `server` e o `content-type` se repetem entre as
                    # respostas: da segunda em diante, vem pela tabela.
                    campos = [(b":status", str(r.status).encode()), (b"server", b"bancada do duke")]
                    campos += [(n.lower().encode("latin-1"), v.encode("latin-1"))
                               for n, v in r.cabecalhos]
                    if not any(n == b"content-type" for n, _ in campos):
                        campos.append((b"content-type", b"text/plain"))
                    bloco = self.codificador.codificar(campos)
                    fim = END_STREAM if not r.corpo else 0
                    self.mandar(quadro(HEADERS, END_HEADERS | fim, c.numero, bloco))
                    c.cabeca_saiu = True
                    andou = True
                    if not r.corpo:
                        c.resposta = None
                    continue
                limite = len(r.corpo)
                if r.pausa is not None and c.enviado < r.pausa[0]:
                    limite = r.pausa[0]
                n = min(limite - c.enviado, self.quadro_do_cliente, self.janela, c.janela)
                if n <= 0:
                    if r.pausa is not None and c.enviado == r.pausa[0]:
                        # A metade foi: a espera, e depois o resto.
                        c.pronta_em = agora + r.pausa[1]
                        r.pausa = None
                    continue
                pedaco = r.corpo[c.enviado:c.enviado + n]
                c.enviado += n
                fim = END_STREAM if c.enviado == len(r.corpo) else 0
                self.mandar(quadro(DATA, fim, c.numero, pedaco))
                self.janela -= n
                c.janela -= n
                andou = True
                if fim:
                    c.resposta = None
            if not andou:
                return

    def hostil(self, c):
        r = c.resposta
        c.resposta = None
        if r.hostil == "reinicia":
            self.mandar(reinicio(c.numero, INTERNAL_ERROR))
        elif r.hostil == "recusa":
            self.mandar(reinicio(c.numero, REFUSED_STREAM))
        elif r.hostil == "adeus":
            self.mandar(adeus(c.numero, ENHANCE_YOUR_CALM))
            self.acabou = True
        elif r.hostil == "empurra":
            bloco = self.codificador.codificar([
                (b":method", b"GET"), (b":scheme", b"http"),
                (b":authority", b"bancada.duke"), (b":path", b"/empurrado"),
            ])
            self.mandar(quadro(PUSH_PROMISE, END_HEADERS, c.numero,
                               (c.numero + 1).to_bytes(4, "big") + bloco))
        elif r.hostil == "hpack":
            # O indice zero: o bloco nao se decodifica.
            self.mandar(quadro(HEADERS, END_HEADERS | END_STREAM, c.numero, b"\x80"))
        elif r.hostil == "enxurrada":
            self.mandar(b"".join(quadro(PING, 0, 0, i.to_bytes(8, "big")) for i in range(2000)))
            c.resposta = Resposta2(200, [], b"depois da enxurrada\n")


def servir(conexao, responder, log, inicio=b""):
    """Serve uma conexao HTTP/2 que comecou com `inicio` (o prefacio, se o
    `http.py` ja o leu)."""
    Servidor2(conexao, responder, log, inicio).servir()
