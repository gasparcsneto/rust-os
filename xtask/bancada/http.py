#!/usr/bin/env python3
"""O servidor HTTP da bancada do Duke: o outro lado do cliente HTTP.

O emulador roda este script a cada conexao para 10.0.2.100:80 e para
10.0.2.100:8443 (um `guestfwd` cada), com a conexao nos descritores 0, 1 e
2. Com o segundo argumento `tls`, faz antes o aperto TLS 1.3 como o eco TLS
da bancada - o OpenSSL, pelo modulo `ssl` do Python, com o certificado pelo
nome que o cliente pediu (SNI). Depois, le pedidos HTTP/1.1 ate o cliente
fechar, ou ate uma resposta que fecha a conexao.

Ou fala HTTP/2 (`http2.py`): na porta 80, quando a conexao comeca com o
prefacio do HTTP/2 (h2c, com conhecimento previo); na 8443, quando o ALPN
do TLS escolheu `h2`. As rotas sao as mesmas que fazem sentido sem as
regras de enquadramento do HTTP/1.1 - ver `rota_h2` -, e as hostis do
HTTP/2:

    GET  /h2/reinicia    RST_STREAM com INTERNAL_ERROR, sem resposta
    GET  /h2/recusa      RST_STREAM com REFUSED_STREAM
    GET  /h2/adeus       GOAWAY com ENHANCE_YOUR_CALM, e a conexao fecha
    GET  /h2/empurra     um PUSH_PROMISE, que o cliente desligou
    GET  /h2/hpack       um bloco de cabeca que nao se decodifica
    GET  /h2/enxurrada   dois mil PING antes da resposta
    GET  /h2/lento-meio/<ms>
                         64 KiB do texto: a metade, <ms> de espera, e o
                         resto

Cada rota e um comportamento que a suite e a fumaca conferem:

    GET  /ola            200 "ola, duke\\n", com Content-Length
    GET  /conta          200 com o numero deste pedido na conexao
    GET  /pedacos        200 em pedacos (chunked), com extensao e trailer
    GET  /grande/<n>     200 com n bytes de 0123456789..., com Content-Length
    GET  /ate-fechar     200 sem tamanho: o corpo vai ate o fecho
    POST /eco            200 com o corpo do pedido
    GET  /lento/<ms>     espera <ms>, e 200 "lento\\n"
    GET  /mudo           nada, por trinta segundos
    GET  /corta          promete 100 bytes, manda 10 e fecha
    GET  /torto/<tipo>   uma resposta malformada - ver TORTAS
    GET  /status/<n>     o status <n>, com um corpo curto
    GET  /redireciona    302 para http://bancada.duke/ola
    GET  /fecha          200 com Connection: close
    GET  /codigo/<arquitetura>/<nome>
                         200 com os bytes do programa publicado, de
                         <diretorio>/codigo/<arquitetura>/<nome> (ver
                         xtask/src/codigo.rs); 404 se nao ha
    o resto              404

E as da compressao, com o texto da bancada (ver `texto`), que o programa
`compressao` regenera do mesmo jeito para conferir:

    GET  /texto/<n>      200 com n bytes do texto, como e
    GET  /negocia/<n>    o texto na codificacao que o Accept-Encoding pede
                         - gzip, depois deflate, depois como e -, com Vary
                         e X-Codificacao dizendo qual
    GET  /comprimido/<cod>/<n>
                         o texto em <cod> (gzip, x-gzip, deflate), peca o
                         cliente o que pedir
    GET  /comprimido-pedacos/<cod>/<n>
                         o mesmo, em pedacos (chunked)
    GET  /comprimido-ate-fechar/<cod>/<n>
                         o mesmo, sem tamanho: o corpo vai ate o fecho
    GET  /comprimido-lento/<ms>
                         64 KiB do texto em gzip: a metade, <ms> de espera,
                         e o resto
    GET  /bomba/<cod>/<mib>
                         <mib> MiB de zeros em <cod>, com a maior razao do
                         DEFLATE - um gzip ou um zlib valido
    GET  /estragado/<tipo>
                         um corpo comprimido estragado - ver ESTRAGADOS

E as dos cookies, que o programa `cookies` e o `buscador` usam. A sessao e
um identificador assinado (HMAC-SHA256 com uma chave tirada da chave TLS da
bancada): cada conexao e um processo novo deste script, e a assinatura e o
que deixa conferir uma sessao sem guardar nada.

    GET  /cookies/entrar 200, e uma sessao nova: `sessao`, HttpOnly,
                         SameSite=Lax, Path=/ - e Secure no TLS
    GET  /cookies/privado
                         200 "privado <id>" com uma sessao valida no
                         Cookie, 401 sem
    GET  /cookies/sair   200, e a sessao apagada (Max-Age=0)
    GET  /cookies/.../eco
                         200 com o Cookie que chegou, ou "-" sem nenhum
    GET  /cookies/definir?c=<set-cookie>&c=...
                         200, e um Set-Cookie para cada `c`, como veio
    GET  /cookies/muitos/<n>/<tamanho>
                         200, e <n> cookies `m<i>` de <tamanho> bytes

Nada sai pela saida padrao nem pela de erro: as duas sao a conexao. Os erros
vao para `servidor-http.log`, no diretorio da bancada.
"""

import gzip
import hashlib
import hmac
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse
import zlib

# O vizinho `http2.py` e importado so pela conexao que fala HTTP/2 - ver
# `h2()` -, e sem o cache de bytecode, que o Python escreveria ao lado dele,
# dentro do repositorio.
sys.dont_write_bytecode = True

# O prefacio do HTTP/2: o comeco de uma conexao clara com conhecimento
# previo (RFC 9113, 3.4).
PREFACIO_H2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def h2():
    """O modulo do HTTP/2. Cada conexao e um processo novo, e compilar o
    `http2.py` custa uns 15 ms: a conexao HTTP/1.1 nao paga por ele."""
    import http2

    return http2

# As respostas malformadas de /torto/<tipo>: cada uma quebra uma regra da
# RFC 9112 que o cliente tem de recusar.
TORTAS = {
    # Um LF sozinho no fim da linha de status.
    "lf": b"HTTP/1.1 200 OK\nContent-Length: 2\r\n\r\nok",
    # Um cabecalho dobrado em duas linhas (obs-fold).
    "dobra": b"HTTP/1.1 200 OK\r\nX-A: um\r\n dois\r\nContent-Length: 2\r\n\r\nok",
    # Transfer-Encoding e Content-Length juntos.
    "ambiguo": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
    b"Content-Length: 5\r\n\r\n2\r\nok\r\n0\r\n\r\n",
    # Uma linha de status que nao e uma.
    "status": b"HTTP/1.1 2OO OK\r\nContent-Length: 2\r\n\r\nok",
    # O tamanho de um pedaco que nao e hexadecimal.
    "pedaco": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nok\r\n0\r\n\r\n",
    # Uma versao que o cliente nao fala.
    "versao": b"HTTP/2.0 200 OK\r\nContent-Length: 2\r\n\r\nok",
    # Dois tamanhos que nao concordam.
    "tamanhos": b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok!",
}

# As palavras do texto da bancada - as mesmas do programa `compressao` e
# dos vetores dos testes do pacote http.
PALAVRAS = [b"duke", b"gate", b"politica", b"auditoria", b"conexao", b"pedido",
            b"resposta", b"corpo", b"limite", b"agente", b"pessoa", b"processo",
            b"destino", b"firewall", b"revogacao", b"contencao", b"o", b"a", b"de",
            b"que", b"e", b"um", b"uma", b"nao", b"com", b"por", b"para", b"sem"]


def texto(n):
    """n bytes de texto: palavras escolhidas por um gerador congruente."""
    x = 0x2545F4914F6CDD1D
    saida = bytearray()
    k = 0
    while len(saida) < n:
        x = (x * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        saida += PALAVRAS[(x >> 33) % len(PALAVRAS)]
        k += 1
        saida += b"\n" if k % 12 == 0 else b" "
    return bytes(saida[:n])


def comprimir(cod, dados):
    """`dados` na codificacao `cod`: o gzip e o zlib do Python."""
    if cod in ("gzip", "x-gzip"):
        return gzip.compress(dados, compresslevel=6, mtime=0)
    return zlib.compress(dados, 6)


class Bits:
    """Bits como o DEFLATE os le: do menos significativo para o mais."""

    def __init__(self):
        self.bytes = bytearray()
        self.acumulado = 0
        self.quantos = 0

    def por(self, valor, n):
        self.acumulado |= valor << self.quantos
        self.quantos += n
        while self.quantos >= 8:
            self.bytes.append(self.acumulado & 0xFF)
            self.acumulado >>= 8
            self.quantos -= 8

    def codigo(self, codigo, n):
        self.por(int(format(codigo, "0%db" % n)[::-1], 2), n)

    def zeros(self, n):
        # Ate o fim do byte, os bytes inteiros de uma vez, e o resto.
        primeiro = min(n, (8 - self.quantos) % 8)
        self.por(0, primeiro)
        n -= primeiro
        self.bytes += bytes(n // 8)
        self.por(0, n % 8)

    def fim(self):
        if self.quantos:
            self.por(0, 8 - self.quantos)
        return bytes(self.bytes)


def canonico(comprimentos):
    """O codigo canonico de cada simbolo (RFC 1951, 3.2.2)."""
    contagem = [0] * 16
    for c in comprimentos:
        contagem[c] += 1
    contagem[0] = 0
    proximo = [0] * 16
    codigo = 0
    for c in range(1, 16):
        codigo = (codigo + contagem[c - 1]) << 1
        proximo[c] = codigo
    codigos = []
    for c in comprimentos:
        codigos.append((proximo[c], c))
        proximo[c] += 1
    return codigos


def bomba(cod, mib):
    """<mib> MiB de zeros num bloco DEFLATE dinamico: um literal zero e
    copias de 258 bytes a um byte de distancia, dois bits cada - a maior
    razao do formato, uns 1030 para 1. Um gzip ou um zlib valido: quem
    pede com um teto maior que ele o decodifica inteiro."""
    copias = (mib << 20) // 258
    tamanho = 1 + copias * 258
    b = Bits()
    b.por(1, 1)
    b.por(2, 2)
    b.por(286 - 257, 5)
    b.por(1 - 1, 5)
    b.por(19 - 4, 4)
    # O codigo dos comprimentos: de 0 a 15, quatro bits cada.
    cc = [4] * 16 + [0, 0, 0]
    for s in [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]:
        b.por(cc[s], 3)
    codigos_cc = canonico(cc)
    literal = [0] * 286
    literal[285] = 1
    literal[0] = 2
    literal[256] = 2
    for c in literal + [1]:
        b.codigo(*codigos_cc[c])
    codigos = canonico(literal)
    b.codigo(*codigos[0])
    b.zeros(2 * copias)
    b.codigo(*codigos[256])
    deflate = b.fim()
    if cod in ("gzip", "x-gzip"):
        crc = 0
        zero = bytes(1 << 20)
        falta = tamanho
        while falta:
            k = min(falta, len(zero))
            crc = zlib.crc32(zero[:k], crc)
            falta -= k
        return (b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff" + deflate
                + crc.to_bytes(4, "little") + (tamanho & 0xFFFFFFFF).to_bytes(4, "little"))
    # O Adler-32 de `tamanho` zeros: a soma `a` fica em 1, e a `b` soma 1 a
    # cada byte.
    adler = ((tamanho % 65521) << 16) | 1
    return b"\x78\x9c" + deflate + adler.to_bytes(4, "big")


def estragado(tipo):
    """Os corpos estragados de /estragado/<tipo>: (codificacao, corpo, ate o
    fecho). Cada um quebra o que o cliente tem de conferir."""
    t = texto(4096)
    g = gzip.compress(t, compresslevel=6, mtime=0)
    z = zlib.compress(t, 6)
    meio = len(g) // 2
    if tipo == "crc":
        return "gzip", g[:-8] + bytes([g[-8] ^ 1]) + g[-7:], False
    if tipo == "isize":
        return "gzip", g[:-4] + (len(t) + 1).to_bytes(4, "little"), False
    if tipo == "adler":
        return "deflate", z[:-1] + bytes([z[-1] ^ 1]), False
    if tipo == "dados":
        return "gzip", g[:meio] + bytes([g[meio] ^ 0x55]) + g[meio + 1:], False
    if tipo == "cabeca":
        return "gzip", b"\x1e" + g[1:], False
    if tipo == "cru":
        c = zlib.compressobj(6, zlib.DEFLATED, -15)
        return "deflate", c.compress(t) + c.flush(), False
    if tipo == "sobra":
        return "gzip", g + b"lixo", False
    if tipo == "cortado":
        return "gzip", g[:meio], False
    if tipo == "cortado-fecho":
        return "gzip", g[:meio], True
    if tipo == "desconhecida":
        return "br", os.urandom(64), False
    if tipo == "empilhada":
        return "gzip, gzip", gzip.compress(g, mtime=0), False
    if tipo == "vazio":
        return "gzip", b"", False
    return None


def negociar(aceita):
    """A codificacao que o Accept-Encoding pede: gzip, depois deflate,
    depois como e. Um `q=0` recusa."""
    aceitas = set()
    for item in aceita.split(","):
        nome, _, params = item.strip().partition(";")
        q = 1.0
        for p in params.split(";"):
            chave, _, valor = p.strip().partition("=")
            if chave == "q":
                try:
                    q = float(valor)
                except ValueError:
                    q = 0.0
        if nome and q > 0:
            aceitas.add(nome.strip().lower())
    for cod in ("gzip", "deflate"):
        if cod in aceitas:
            return cod
    return "identity"


def segredo_das_sessoes(diretorio):
    """A chave das sessoes de /cookies: da chave TLS da bancada, que so ela tem."""
    with open(os.path.join(diretorio, "bancada.chave"), "rb") as f:
        return hashlib.sha256(b"duke cookies " + f.read()).digest()


def sessao_nova(segredo):
    ident = os.urandom(6).hex()
    return ident + "." + hmac.new(segredo, ident.encode(), "sha256").hexdigest()[:16]


def sessao_valida(segredo, cookie):
    """O id da primeira `sessao` do Cookie com a assinatura certa."""
    for par in cookie.split(";"):
        nome, _, valor = par.strip().partition("=")
        if nome != "sessao" or "." not in valor:
            continue
        ident, _, assinatura = valor.partition(".")
        certa = hmac.new(segredo, ident.encode(), "sha256").hexdigest()[:16]
        if hmac.compare_digest(assinatura, certa):
            return ident
    return None


def rota_dos_cookies(alvo, cabecalhos, extras, cifrado, diretorio):
    """A resposta de /cookies/..., ou None se o alvo nao e dela."""
    partes = urllib.parse.urlsplit(alvo)
    caminho = partes.path
    if not caminho.startswith("/cookies/"):
        return None
    seguro = "; Secure" if cifrado else ""
    if caminho == "/cookies/entrar":
        valor = sessao_nova(segredo_das_sessoes(diretorio))
        return resposta(200, "OK", b"entrou\n", [
            "Set-Cookie: sessao=" + valor + "; Path=/; HttpOnly; SameSite=Lax" + seguro
        ] + extras)
    if caminho == "/cookies/privado":
        ident = sessao_valida(segredo_das_sessoes(diretorio), cabecalhos.get("cookie", ""))
        if ident is None:
            return resposta(401, "Unauthorized", b"sem sessao\n", extras)
        return resposta(200, "OK", b"privado " + ident.encode() + b"\n", extras)
    if caminho == "/cookies/sair":
        return resposta(200, "OK", b"saiu\n", [
            "Set-Cookie: sessao=; Path=/; Max-Age=0; HttpOnly" + seguro
        ] + extras)
    if re.fullmatch(r"/cookies(/[a-z0-9-]+)*/eco", caminho):
        return resposta(200, "OK", (cabecalhos.get("cookie") or "-").encode() + b"\n", extras)
    if caminho == "/cookies/definir":
        definidos = urllib.parse.parse_qs(partes.query, keep_blank_values=True).get("c", [])
        if len(definidos) > 32 or any("\r" in c or "\n" in c for c in definidos):
            return resposta(400, "Bad Request", b"", extras)
        return resposta(
            200, "OK", b"definidos %d\n" % len(definidos),
            ["Set-Cookie: " + c for c in definidos] + extras,
        )
    m = re.fullmatch(r"/cookies/muitos/([0-9]+)/([0-9]+)", caminho)
    if m and int(m.group(1)) <= 60 and int(m.group(2)) <= 8192:
        n, tamanho = int(m.group(1)), int(m.group(2))
        return resposta(200, "OK", b"muitos %d\n" % n, [
            "Set-Cookie: m%d=%s; Path=/" % (i, "v" * tamanho) for i in range(n)
        ] + extras)
    return None


# O maior pedido que se le: a cabeca e o corpo.
MAIOR_CABECA = 16 * 1024
MAIOR_CORPO = 1024 * 1024


class Fechou(Exception):
    """O cliente fechou, ou mandou o que nao e HTTP."""


def contexto(diretorio, nome, protocolos=("h2", "http/1.1")):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    c.load_cert_chain(
        os.path.join(diretorio, nome + ".pem"),
        os.path.join(diretorio, nome + ".chave"),
    )
    # O ALPN: o HTTP/2 para quem o oferece, o HTTP/1.1 para quem oferece
    # so ele. Quem nao oferece nada fala HTTP/1.1, como sempre.
    c.set_alpn_protocols(list(protocolos))
    return c


def cifrar(diretorio, cru):
    padrao = contexto(diretorio, "bancada")
    outros = {
        "estranho.duke": contexto(diretorio, "estranho"),
        "vencido.duke": contexto(diretorio, "vencido"),
        # Um servidor que nao fala HTTP/2: o ALPN so escolhe o HTTP/1.1.
        "antigo.duke": contexto(diretorio, "antigo", ("http/1.1",)),
    }

    def pelo_nome(conexao, nome, _contexto):
        if nome in outros:
            conexao.context = outros[nome]

    padrao.sni_callback = pelo_nome
    return padrao.wrap_socket(cru, server_side=True)


class Leitor:
    """O que chegou da conexao, lido por linhas e por tamanhos."""

    def __init__(self, conexao, inicio=b""):
        self.conexao = conexao
        self.buffer = inicio

    def encher(self):
        dados = self.conexao.recv(65536)
        if not dados:
            raise Fechou()
        self.buffer += dados

    def cabeca(self):
        while b"\r\n\r\n" not in self.buffer:
            if len(self.buffer) > MAIOR_CABECA:
                raise Fechou()
            self.encher()
        cabeca, self.buffer = self.buffer.split(b"\r\n\r\n", 1)
        return cabeca

    def exatos(self, n):
        while len(self.buffer) < n:
            self.encher()
        dados, self.buffer = self.buffer[:n], self.buffer[n:]
        return dados


def resposta(status, motivo, corpo, extras=()):
    cabecalhos = [b"HTTP/1.1 %d %s" % (status, motivo.encode())]
    cabecalhos += [b"Content-Length: %d" % len(corpo)]
    cabecalhos += [c.encode() for c in extras]
    return b"\r\n".join(cabecalhos) + b"\r\n\r\n" + corpo


def padrao(n):
    return (b"0123456789" * (n // 10 + 1))[:n]


def atender(conexao, log, diretorio, cifrado, inicio=b""):
    leitor = Leitor(conexao, inicio)
    numero = 0
    while True:
        try:
            cabeca = leitor.cabeca()
        except Fechou:
            return
        numero += 1
        linhas = cabeca.split(b"\r\n")
        partes = linhas[0].split(b" ")
        if len(partes) != 3:
            conexao.sendall(resposta(400, "Bad Request", b"", ["Connection: close"]))
            return
        metodo, alvo, _versao = (p.decode("latin-1") for p in partes)
        cabecalhos = {}
        for linha in linhas[1:]:
            nome, _, valor = linha.decode("latin-1").partition(":")
            cabecalhos[nome.strip().lower()] = valor.strip()
        tamanho = int(cabecalhos.get("content-length", "0") or "0")
        if tamanho > MAIOR_CORPO:
            conexao.sendall(resposta(413, "Too Large", b"", ["Connection: close"]))
            return
        corpo = leitor.exatos(tamanho) if tamanho else b""
        fechar = cabecalhos.get("connection", "").lower() == "close"
        extras = ["Connection: close"] if fechar else []

        m = re.fullmatch(
            r"/(grande|lento|status|torto|texto|negocia|comprimido-lento|estragado)/([a-z0-9-]+)",
            alvo,
        )
        rota, arg = (m.group(1), m.group(2)) if m else (alvo, None)
        dos_cookies = (
            rota_dos_cookies(alvo, cabecalhos, extras, cifrado, diretorio)
            if metodo == "GET" else None
        )
        # As da compressao com a codificacao e o tamanho.
        cm = re.fullmatch(
            r"/(comprimido|comprimido-pedacos|comprimido-ate-fechar|bomba)/(gzip|x-gzip|deflate)/([0-9]+)",
            alvo,
        )
        # O codigo publicado: a arquitetura e o nome so do alfabeto que o
        # xtask escreve, e nada de caminho - o arquivo e o deste diretorio.
        codigo = re.fullmatch(r"/codigo/(x86_64|aarch64)/([a-z0-9][a-z0-9-]*)", alvo)
        if dos_cookies is not None:
            conexao.sendall(dos_cookies)
        elif metodo == "GET" and codigo:
            arquivo = os.path.join(diretorio, "codigo", codigo.group(1), codigo.group(2))
            try:
                with open(arquivo, "rb") as f:
                    bytes_do_programa = f.read()
            except OSError:
                conexao.sendall(resposta(404, "Not Found", b"nao ha\n", extras))
            else:
                conexao.sendall(
                    resposta(
                        200,
                        "OK",
                        bytes_do_programa,
                        ["Content-Type: application/octet-stream"] + extras,
                    )
                )
        elif metodo == "GET" and cm and int(cm.group(3)) <= 8 << 20:
            forma, cod, n = cm.group(1), cm.group(2), int(cm.group(3))
            if forma == "bomba":
                corpo_c = bomba(cod, n)
            else:
                corpo_c = comprimir(cod, texto(n))
            codificacao = ["Content-Encoding: " + cod]
            if forma in ("comprimido", "bomba"):
                conexao.sendall(resposta(200, "OK", corpo_c, codificacao + extras))
            elif forma == "comprimido-pedacos":
                pedacos = b"".join(
                    b"%x\r\n" % len(corpo_c[i:i + 1000]) + corpo_c[i:i + 1000] + b"\r\n"
                    for i in range(0, len(corpo_c), 1000)
                )
                conexao.sendall(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                    + "".join(c + "\r\n" for c in codificacao + extras).encode()
                    + b"\r\n" + pedacos + b"0\r\n\r\n"
                )
            else:
                conexao.sendall(
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Encoding: "
                    + cod.encode() + b"\r\n\r\n" + corpo_c
                )
                return
        elif metodo == "GET" and rota == "texto" and arg.isdigit() and int(arg) <= 8 << 20:
            conexao.sendall(resposta(200, "OK", texto(int(arg)), extras))
        elif metodo == "GET" and rota == "negocia" and arg.isdigit() and int(arg) <= 8 << 20:
            cod = negociar(cabecalhos.get("accept-encoding", "identity"))
            dados = texto(int(arg))
            corpo_c = dados if cod == "identity" else comprimir(cod, dados)
            vistos = ["Vary: Accept-Encoding", "X-Codificacao: " + cod]
            if cod != "identity":
                vistos.append("Content-Encoding: " + cod)
            conexao.sendall(resposta(200, "OK", corpo_c, vistos + extras))
        elif metodo == "GET" and rota == "comprimido-lento" and arg.isdigit():
            corpo_c = comprimir("gzip", texto(64 * 1024))
            inteira = resposta(200, "OK", corpo_c, ["Content-Encoding: gzip"] + extras)
            meio = len(inteira) - len(corpo_c) // 2
            conexao.sendall(inteira[:meio])
            time.sleep(int(arg) / 1000)
            conexao.sendall(inteira[meio:])
        elif metodo == "GET" and rota == "estragado" and estragado(arg):
            cod, corpo_e, ate_o_fecho = estragado(arg)
            if ate_o_fecho:
                conexao.sendall(
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Encoding: "
                    + cod.encode() + b"\r\n\r\n" + corpo_e
                )
                return
            conexao.sendall(resposta(200, "OK", corpo_e, ["Content-Encoding: " + cod] + extras))
        elif metodo == "GET" and rota == "/ola":
            conexao.sendall(resposta(200, "OK", b"ola, duke\n", extras))
        elif metodo == "GET" and rota == "/conta":
            conexao.sendall(resposta(200, "OK", str(numero).encode(), extras))
        elif metodo == "GET" and rota == "/pedacos":
            conexao.sendall(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                + "".join(c + "\r\n" for c in extras).encode()
                + b"\r\n"
                + b"5;nome=valor\r\nem pe\r\n"
                + b"7\r\ndacos, \r\n"
                + b"a\r\nde verdade\r\n"
                + b"0\r\nX-Fim: sim\r\n\r\n"
            )
        elif metodo == "GET" and rota == "grande" and arg.isdigit():
            conexao.sendall(resposta(200, "OK", padrao(int(arg)), extras))
        elif metodo == "GET" and rota == "/ate-fechar":
            conexao.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nate o fecho\n")
            return
        elif metodo == "POST" and rota == "/eco":
            conexao.sendall(resposta(200, "OK", corpo, extras))
        elif metodo == "GET" and rota == "lento" and arg.isdigit():
            time.sleep(int(arg) / 1000)
            conexao.sendall(resposta(200, "OK", b"lento\n", extras))
        elif metodo == "GET" and rota == "/mudo":
            time.sleep(30)
            return
        elif metodo == "GET" and rota == "/corta":
            conexao.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789")
            return
        elif metodo == "GET" and rota == "torto" and arg in TORTAS:
            conexao.sendall(TORTAS[arg])
            return
        elif metodo == "GET" and rota == "status" and arg.isdigit():
            n = int(arg)
            conexao.sendall(resposta(n, "Status", b"status %d\n" % n, extras))
        elif metodo == "GET" and rota == "/redireciona":
            conexao.sendall(
                resposta(302, "Found", b"", ["Location: http://bancada.duke/ola"] + extras)
            )
        elif metodo == "GET" and rota == "/fecha":
            conexao.sendall(resposta(200, "OK", b"fechou\n", ["Connection: close"]))
            return
        else:
            conexao.sendall(resposta(404, "Not Found", b"nao ha\n", extras))
        if fechar:
            return
        print("http.py: pedido", numero, metodo, alvo, file=log, flush=True)


# Os cabecalhos que o HTTP/2 nao tem (RFC 9113, 8.2.2).
DA_CONEXAO = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"}


def de_h1(cru):
    """Uma resposta HTTP/1.1 escrita por `resposta`, como resposta HTTP/2: o
    status, os cabecalhos sem os da conexao, e o corpo."""
    cabeca, _, corpo = cru.partition(b"\r\n\r\n")
    linhas = cabeca.decode("latin-1").split("\r\n")
    status = int(linhas[0].split(" ")[1])
    cabecalhos = []
    for linha in linhas[1:]:
        nome, _, valor = linha.partition(":")
        if nome.strip().lower() not in DA_CONEXAO:
            cabecalhos.append((nome.strip(), valor.strip()))
    return h2().Resposta2(status, cabecalhos, corpo)


def rota_h2(diretorio, cifrado):
    """A funcao que responde os pedidos de uma conexao HTTP/2."""

    def responder(metodo, alvo, cabecalhos, corpo, numero):
        R = h2().Resposta2
        dos_cookies = (
            rota_dos_cookies(alvo, cabecalhos, [], cifrado, diretorio) if metodo == "GET" else None
        )
        if dos_cookies is not None:
            return de_h1(dos_cookies)
        hostil = re.fullmatch(r"/h2/(reinicia|recusa|adeus|empurra|hpack|enxurrada)", alvo)
        if metodo == "GET" and hostil:
            return R(200, hostil=hostil.group(1))
        m = re.fullmatch(
            r"/(grande|lento|status|texto|negocia|comprimido-lento|h2/lento-meio)/([a-z0-9-]+)",
            alvo,
        )
        rota, arg = (m.group(1), m.group(2)) if m else (alvo, None)
        cm = re.fullmatch(r"/comprimido/(gzip|x-gzip|deflate)/([0-9]+)", alvo)
        numerico = arg is not None and arg.isdigit()
        if metodo == "GET" and rota == "/ola":
            return R(200, [], b"ola, duke\n")
        if metodo == "GET" and rota == "/conta":
            return R(200, [], str(numero).encode())
        if metodo == "GET" and rota == "grande" and numerico and int(arg) <= 8 << 20:
            return R(200, [("Content-Length", str(int(arg)))], padrao(int(arg)))
        if metodo == "GET" and rota == "texto" and numerico and int(arg) <= 8 << 20:
            return R(200, [("Content-Length", str(int(arg)))], texto(int(arg)))
        if metodo == "POST" and rota == "/eco":
            return R(200, [("Content-Length", str(len(corpo)))], corpo)
        if metodo == "GET" and rota == "lento" and numerico:
            return R(200, [], b"lento\n", atraso=int(arg) / 1000)
        if metodo == "GET" and rota == "h2/lento-meio" and numerico:
            dados = texto(64 * 1024)
            return R(200, [("Content-Length", str(len(dados)))], dados,
                     pausa=(len(dados) // 2, int(arg) / 1000))
        if metodo == "GET" and rota == "comprimido-lento" and numerico:
            corpo_c = comprimir("gzip", texto(64 * 1024))
            return R(200, [("Content-Encoding", "gzip")], corpo_c,
                     pausa=(len(corpo_c) // 2, int(arg) / 1000))
        if metodo == "GET" and rota == "status" and numerico:
            n = int(arg)
            return R(n, [], b"status %d\n" % n)
        if metodo == "GET" and rota == "negocia" and numerico and int(arg) <= 8 << 20:
            cod = negociar(cabecalhos.get("accept-encoding", "identity"))
            dados = texto(int(arg))
            corpo_c = dados if cod == "identity" else comprimir(cod, dados)
            vistos = [("Vary", "Accept-Encoding"), ("X-Codificacao", cod)]
            if cod != "identity":
                vistos.append(("Content-Encoding", cod))
            return R(200, vistos, corpo_c)
        if metodo == "GET" and cm and int(cm.group(2)) <= 8 << 20:
            return R(200, [("Content-Encoding", cm.group(1))],
                     comprimir(cm.group(1), texto(int(cm.group(2)))))
        if metodo == "GET" and rota == "/redireciona":
            return R(302, [("Location", "http://bancada.duke/ola")], b"")
        if metodo == "GET" and rota == "/mudo":
            return R(200, nunca=True)
        return R(404, [], b"nao ha\n")

    return responder


def espiar(conexao):
    """O comeco da conexao, ate dar para dizer se e o prefacio do HTTP/2."""
    dados = b""
    while len(dados) < len(PREFACIO_H2) and PREFACIO_H2.startswith(dados):
        pedaco = conexao.recv(65536)
        if not pedaco:
            break
        dados += pedaco
    return dados


def main():
    diretorio = sys.argv[1]
    cifrado = len(sys.argv) > 2 and sys.argv[2] == "tls"
    log = open(os.path.join(diretorio, "servidor-http.log"), "a")
    # A saida de erro e a conexao: o que o Python escrevesse nela iria para
    # o cliente no meio da conversa.
    os.dup2(log.fileno(), 2)
    sys.stderr = log

    cru = socket.socket(fileno=0)
    cru.settimeout(30)
    try:
        conexao = cifrar(diretorio, cru) if cifrado else cru
        with conexao:
            if cifrado and conexao.selected_alpn_protocol() == "h2":
                h2().servir(conexao, rota_h2(diretorio, cifrado), log)
            else:
                inicio = b"" if cifrado else espiar(conexao)
                if inicio.startswith(PREFACIO_H2):
                    h2().servir(conexao, rota_h2(diretorio, cifrado), log, inicio)
                else:
                    atender(conexao, log, diretorio, cifrado, inicio)
            if cifrado:
                # O fim educado do TLS: o cliente le o fim como fim, e nao
                # como corte.
                try:
                    conexao.unwrap()
                except (ssl.SSLError, OSError):
                    pass
    except (ssl.SSLError, OSError, ValueError) as erro:
        # O cliente recusou o certificado, nao fala TLS, fechou sem aviso,
        # ou mandou o que nao e HTTP: o fim desta conexao, e nao um defeito
        # da bancada.
        print("http.py:", type(erro).__name__, erro, file=log, flush=True)


if __name__ == "__main__":
    main()
