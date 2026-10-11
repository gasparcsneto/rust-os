#!/usr/bin/env python3
"""A ponte da bancada do Duke: o lado de fora do canal do agente por TCP.

O emulador roda este script a cada conexao para 10.0.2.100:7070 (um
`guestfwd`), com a conexao nos descritores 0, 1 e 2. Ele conecta em
127.0.0.1:<porta> - o `hostfwd` da mesma maquina, que leva a porta do
canal no hospede - e passa os bytes nos dois sentidos, cada um no seu
fio, ate os dois lados fecharem. E por aqui que a suite, de dentro do
kernel, conversa com o canal do kernel como um agente de fora: pela pilha
IP dele, pela rede do emulador e de volta.

Um sentido nao espera o outro: um lado que nao le nao impede o outro de
mandar, como numa conexao TCP de verdade - e a contrapressao que a suite
confere e a do kernel, e nao a desta ponte.

O unico argumento e a porta do hospedeiro. Nada sai pela saida padrao nem
pela de erro: as duas sao a conexao.
"""

import os
import socket
import sys
import threading


def passar(de, para):
    """Copia de `de` para `para` ate `de` fechar; entao fecha o sentido de
    escrita de `para`, e o outro lado ve o fim."""
    try:
        while True:
            dados = de.recv(65536)
            if not dados:
                break
            para.sendall(dados)
    except OSError:
        pass
    try:
        para.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def main():
    # A saida de erro e a conexao: o que o Python escrevesse nela iria para
    # o kernel no meio do canal cifrado.
    nulo = os.open(os.devnull, os.O_WRONLY)
    os.dup2(nulo, 2)
    sys.stderr = open(os.devnull, "w")

    porta = int(sys.argv[1])
    hospede = socket.socket(fileno=0)
    try:
        fora = socket.create_connection(("127.0.0.1", porta), timeout=10)
    except OSError:
        hospede.close()
        return
    fora.settimeout(None)
    volta = threading.Thread(target=passar, args=(fora, hospede), daemon=True)
    volta.start()
    passar(hospede, fora)
    volta.join()
    hospede.close()
    fora.close()


main()
