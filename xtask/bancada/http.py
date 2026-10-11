#!/usr/bin/env python3
"""O servidor HTTP da bancada do Duke: o outro lado do cliente HTTP.

O emulador roda este script a cada conexao para 10.0.2.100:80 e para
10.0.2.100:8443 (um `guestfwd` cada), com a conexao nos descritores 0, 1 e
2. Com o segundo argumento `tls`, faz antes o aperto TLS 1.3 como o eco TLS
da bancada - o OpenSSL, pelo modulo `ssl` do Python, com o certificado pelo
nome que o cliente pediu (SNI). Depois, le pedidos HTTP/1.1 ate o cliente
fechar, ou ate uma resposta que fecha a conexao.

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
    o resto              404

Nada sai pela saida padrao nem pela de erro: as duas sao a conexao. Os erros
vao para `servidor-http.log`, no diretorio da bancada.
"""

import os
import re
import socket
import ssl
import sys
import time

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

# O maior pedido que se le: a cabeca e o corpo.
MAIOR_CABECA = 16 * 1024
MAIOR_CORPO = 1024 * 1024


class Fechou(Exception):
    """O cliente fechou, ou mandou o que nao e HTTP."""


def contexto(diretorio, nome):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    c.load_cert_chain(
        os.path.join(diretorio, nome + ".pem"),
        os.path.join(diretorio, nome + ".chave"),
    )
    return c


def cifrar(diretorio, cru):
    padrao = contexto(diretorio, "bancada")
    outros = {
        "estranho.duke": contexto(diretorio, "estranho"),
        "vencido.duke": contexto(diretorio, "vencido"),
    }

    def pelo_nome(conexao, nome, _contexto):
        if nome in outros:
            conexao.context = outros[nome]

    padrao.sni_callback = pelo_nome
    return padrao.wrap_socket(cru, server_side=True)


class Leitor:
    """O que chegou da conexao, lido por linhas e por tamanhos."""

    def __init__(self, conexao):
        self.conexao = conexao
        self.buffer = b""

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


def atender(conexao, log):
    leitor = Leitor(conexao)
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

        m = re.fullmatch(r"/(grande|lento|status|torto)/([a-z0-9]+)", alvo)
        rota, arg = (m.group(1), m.group(2)) if m else (alvo, None)
        if metodo == "GET" and rota == "/ola":
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
            atender(conexao, log)
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
