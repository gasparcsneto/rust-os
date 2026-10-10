#!/usr/bin/env python3
"""O eco TLS da bancada do Duke: o servidor do outro lado do cliente TLS.

O emulador roda este script a cada conexao para 10.0.2.100:443 (um
`guestfwd`), com a conexao nos descritores 0, 1 e 2. Ele faz o aperto TLS
1.3 pelo OpenSSL - o modulo `ssl` do Python -, escolhe o certificado pelo
nome que o cliente pediu (SNI), e devolve o que chegar ate o cliente fechar.

Os nomes, e o certificado de cada um, estao em `xtask/src/tls.rs`. O unico
argumento e o diretorio da bancada, com os certificados e as chaves.

Nada sai pela saida padrao nem pela de erro: as duas sao a conexao, e um
texto ali corromperia o fluxo TLS. Os erros vao para `servidor.log`, no
diretorio da bancada.
"""

import os
import socket
import ssl
import sys


def contexto(diretorio, nome):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    c.load_cert_chain(
        os.path.join(diretorio, nome + ".pem"),
        os.path.join(diretorio, nome + ".chave"),
    )
    return c


def main():
    diretorio = sys.argv[1]
    log = open(os.path.join(diretorio, "servidor.log"), "a")
    # A saida de erro e a conexao: o que o Python escrevesse nela iria para
    # o cliente no meio do TLS.
    os.dup2(log.fileno(), 2)
    sys.stderr = log

    padrao = contexto(diretorio, "bancada")
    outros = {
        "estranho.duke": contexto(diretorio, "estranho"),
        "vencido.duke": contexto(diretorio, "vencido"),
    }

    def pelo_nome(conexao, nome, _contexto):
        if nome in outros:
            conexao.context = outros[nome]

    padrao.sni_callback = pelo_nome

    cru = socket.socket(fileno=0)
    try:
        with padrao.wrap_socket(cru, server_side=True) as tls:
            while True:
                dados = tls.recv(65536)
                if not dados:
                    break
                tls.sendall(dados)
    except (ssl.SSLError, OSError) as erro:
        # O cliente recusou o certificado, nao fala TLS, ou fechou sem
        # aviso: o fim desta conexao, e nao um defeito da bancada.
        print("tls.py:", type(erro).__name__, erro, file=log, flush=True)


if __name__ == "__main__":
    main()
