#!/usr/bin/env python3
"""A bancada do Internet Computer: a PocketIC, o canister da bancada e o
proxy TLS que a suite usa para mentir - ver xtask/src/icp.rs.

Tres papeis, pelo primeiro argumento:

    preparar <url> <dir>
        Com a PocketIC escutando em <url>: cria a instancia - a NNS, a II e
        duas sub-redes de aplicacao, com o tempo quinze minutos atras, e os
        ledgers (ver LEDGERS) -, instala o canister da bancada (o modulo de
        `modulo`) na primeira de aplicacao, e o mesmo modulo num canister
        da NNS, a sub-rede raiz; confere que os ledgers respondem; guarda
        uma resposta de `read_state` desse tempo velho (`velho.cbor`), poe
        a instancia no tempo de verdade, andando sozinha, e escreve
        <dir>/estado.json: a porta do gateway HTTP, a chave da raiz, os dois
        canisters, um canister da faixa da outra sub-rede e os ledgers.

    proxy <dir> <dir-tls>
        O que o emulador roda a cada conexao para 10.0.2.100:4943 (um
        `guestfwd`), com a conexao nos descritores 0, 1 e 2: o TLS 1.3 com
        o certificado de icp.duke e *.icp.duke, da raiz da bancada, e cada
        pedido HTTP repassado ao gateway da PocketIC - e a resposta mexida
        conforme o nome que o cliente pediu (SNI), ver MODOS.

    proxy-claro <dir> <porta>
        So para conferir a bancada no hospedeiro: o mesmo proxy, sem o
        TLS, escutando em 127.0.0.1:<porta>, com o modo pelo Host.

    wasm <arquivo>
        Escreve o modulo do canister.

Nenhuma porta da bancada fica aberta para fora do hospedeiro: a PocketIC e
o gateway escutam em 127.0.0.1, e o emulador fala com o proxy pelo
`guestfwd`.

O que o canister responde, nas consultas (`canister_query`):

    ola                 ("ola"), em Candid
    eco                 os bytes do argumento, como vieram
    recusa              a recusa "nao", pelo `msg_reject`
    candid_truncado     um texto de 5 bytes com 2
    candid_sobra        ("ola") e dois bytes depois
    candid_magica       ("ola") com DIDX no lugar de DIDL
    quem_consulta       (principal), o de quem consultou - o anonimo, ou o
                        auto-autenticado da chave que assinou a consulta.
                        Pelo caminho da chamada (`/api/v4/.../call`), e a
                        consulta replicada: a resposta passa pelo consenso
                        e vem certificada

e nas chamadas de atualizacao (`canister_update`):

    quem                (principal), o de quem chamou - o anonimo, ou o
                        auto-autenticado da chave que assinou
    contar              (nat64), o contador do canister, mais um a cada
                        chamada - o estado muda
    lento               ("lento"), depois de LENTO_VOLTAS voltas de um laco:
                        a chamada que demora

Os ledgers (ICP-4d), os `IcpFeatures` da PocketIC, nos ids da rede
principal - os canisters de sistema que ela sobe e mantem:

    ryjl3-tyaaa-aaaaa-aaaba-cai   o ledger de ICP (`icp_token`), na NNS; o
                                  anonimo comeca com 1 bilhao de ICP
    rkp4c-7iaaa-aaaaa-aaaca-cai   o CMC (`cycles_minting`), na NNS: converte
                                  ICP em cycles
    um5iw-rqaaa-aaaaq-qaaba-cai   o ledger de cycles (`cycles_token`), na
                                  II; o anonimo comeca com 2^127 cycles

Os modos, pelo nome do TLS:

    icp.duke                    honesto
    lenta.icp.duke              o `read_state` volta depois de LENTIDAO_MS
    raiz-errada.icp.duke        honesto: a chave errada e a do arquivo de redes
    bls-invalida.icp.duke       um byte trocado na assinatura do certificado
    sem-assinatura.icp.duke     a resposta da consulta sem as assinaturas dos nos,
                                e a da chamada sem o certificado
    no-de-fora.icp.duke         as assinaturas atribuidas a um no de fora da sub-rede
    assinatura-errada.icp.duke  um byte trocado na assinatura de cada no, e na
                                do certificado da resposta da chamada
    pedido-trocado.icp.duke     o nonce da consulta trocado no caminho: os nos
                                assinam outro pedido
    aninhada.icp.duke           uma delegacao dentro da delegacao
    faixa-errada.icp.duke       o `read_state` de um canister da outra
                                sub-rede: o certificado e da sub-rede errada
    velho.icp.duke              o `read_state` do tempo velho, guardado
    direta.icp.duke             honesto, pelo endereco fixo: a rede da fumaca,
                                sem o DNS da suite
    assincrona.icp.duke         a chamada (`/api/v4/.../call`) responde 202
                                na hora, e vai a PocketIC pela via
                                assincrona (`/api/v2`) so depois de
                                ATRASO_DA_CHAMADA_MS: o cliente acompanha
                                a situacao por `read_state` - desconhecida,
                                e depois a resposta

So a biblioteca padrao do Python: o CBOR, o Candid e o WebAssembly que a
bancada precisa estao aqui, no tamanho do que ela usa.
"""

import base64
import hashlib
import http.client
import json
import os
import socket
import ssl
import sys
import threading
import time
import zlib

# ---------------------------------------------------------------------------
# CBOR: o subconjunto que o IC usa - inteiros, bytes, texto, listas, mapas e
# etiquetas. A leitura aceita os comprimentos indefinidos, que a resposta de
# uma consulta usa; a escrita usa sempre os definidos.
# ---------------------------------------------------------------------------


class Etiqueta:
    """Um valor com etiqueta (o tipo maior 6)."""

    def __init__(self, numero, valor):
        self.numero = numero
        self.valor = valor


def _cabeca(maior, n):
    if n < 24:
        return bytes([maior << 5 | n])
    for info, largura in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * largura):
            return bytes([maior << 5 | info]) + n.to_bytes(largura, "big")
    raise ValueError("inteiro grande demais para o CBOR")


def cbor(v):
    if isinstance(v, Etiqueta):
        return _cabeca(6, v.numero) + cbor(v.valor)
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return _cabeca(0, v) if v >= 0 else _cabeca(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return _cabeca(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode()
        return _cabeca(3, len(b)) + b
    if isinstance(v, list):
        return _cabeca(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        return _cabeca(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise ValueError("tipo fora do CBOR da bancada: %r" % type(v))


def _ler(b, i):
    inicio = b[i]
    maior, info = inicio >> 5, inicio & 31
    i += 1
    if maior == 7:
        valores = {20: False, 21: True, 22: None}
        if info not in valores:
            raise ValueError("valor simples fora do CBOR da bancada")
        return valores[info], i
    if info == 31:
        return _indefinido(b, i, maior)
    if info < 24:
        n = info
    elif info in (24, 25, 26, 27):
        largura = 1 << (info - 24)
        n = int.from_bytes(b[i : i + largura], "big")
        i += largura
    else:
        raise ValueError("informacao adicional reservada")
    if maior == 0:
        return n, i
    if maior == 1:
        return -1 - n, i
    if maior == 2:
        return bytes(b[i : i + n]), i + n
    if maior == 3:
        return bytes(b[i : i + n]).decode(), i + n
    if maior == 4:
        lista = []
        for _ in range(n):
            x, i = _ler(b, i)
            lista.append(x)
        return lista, i
    if maior == 5:
        mapa = {}
        for _ in range(n):
            k, i = _ler(b, i)
            x, i = _ler(b, i)
            mapa[k] = x
        return mapa, i
    x, i = _ler(b, i)
    return Etiqueta(n, x), i


FIM = 0xFF


def _indefinido(b, i, maior):
    """Um item de comprimento indefinido: os pedacos, ou os itens, ate o
    `0xff`."""
    if maior in (2, 3):
        pedacos = []
        while b[i] != FIM:
            pedaco, i = _ler(b, i)
            pedacos.append(pedaco)
        junto = b"".join(p if isinstance(p, bytes) else p.encode() for p in pedacos)
        return (junto if maior == 2 else junto.decode()), i + 1
    if maior == 4:
        lista = []
        while b[i] != FIM:
            x, i = _ler(b, i)
            lista.append(x)
        return lista, i + 1
    if maior == 5:
        mapa = {}
        while b[i] != FIM:
            k, i = _ler(b, i)
            x, i = _ler(b, i)
            mapa[k] = x
        return mapa, i + 1
    raise ValueError("comprimento indefinido num tipo que nao o tem")


def de_cbor(b):
    v, i = _ler(b, 0)
    if i != len(b):
        raise ValueError("bytes depois do valor CBOR")
    return v


AUTODESCRITO = 55799


def sem_etiqueta(v):
    """O valor de dentro da etiqueta de autodescricao, se houver."""
    if isinstance(v, Etiqueta) and v.numero == AUTODESCRITO:
        return v.valor, True
    return v, False


def com_etiqueta(v, tinha):
    return Etiqueta(AUTODESCRITO, v) if tinha else v


# ---------------------------------------------------------------------------
# Candid: os argumentos das duas chamadas ao canister de gerenciamento, e o
# principal da resposta da primeira.
# ---------------------------------------------------------------------------


def leb(n):
    saida = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            saida.append(byte | 0x80)
        else:
            saida.append(byte)
            return bytes(saida)


def sleb(n):
    saida = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        fim = (n == 0 and not byte & 0x40) or (n == -1 and byte & 0x40)
        saida.append(byte if fim else byte | 0x80)
        if fim:
            return bytes(saida)


def idl_hash(nome):
    h = 0
    for c in nome.encode():
        h = (h * 223 + c) % (1 << 32)
    return h


RECORD, VARIANT, VEC, NULL, NAT8, PRINCIPAL = -20, -21, -19, -1, -5, -24


def candid_criar():
    """(record {}): todo campo do `provisional_create_canister_with_cycles`
    e opcional."""
    return b"DIDL" + leb(1) + sleb(RECORD) + leb(0) + leb(1) + sleb(0)


def candid_instalar(canister, wasm):
    """(record { mode = variant { install }; canister_id; wasm_module; arg })."""
    blob, modo = 2, 1
    campos = sorted(
        [
            (idl_hash("arg"), sleb(blob), leb(0)),
            (idl_hash("canister_id"), sleb(PRINCIPAL), b"\x01" + leb(len(canister)) + canister),
            (idl_hash("mode"), sleb(modo), leb(0)),
            (idl_hash("wasm_module"), sleb(blob), leb(len(wasm)) + wasm),
        ]
    )
    tipos = sleb(RECORD) + leb(len(campos))
    tipos += b"".join(leb(h) + t for h, t, _ in campos)
    tipos += sleb(VARIANT) + leb(1) + leb(idl_hash("install")) + sleb(NULL)
    tipos += sleb(VEC) + sleb(NAT8)
    valores = b"".join(v for _, _, v in campos)
    return b"DIDL" + leb(3) + tipos + leb(1) + sleb(0) + valores


def principal_da_criacao(resposta):
    """O `canister_id` de (record { canister_id : principal }): o principal
    e o ultimo valor da mensagem - `01`, o tamanho, os bytes."""
    for n in [10] + [k for k in range(29, 0, -1) if k != 10]:
        if len(resposta) >= n + 2 and resposta[-(n + 2)] == 1 and resposta[-(n + 1)] == n:
            return bytes(resposta[-n:])
    raise ValueError("a criacao nao devolveu um principal")


# ---------------------------------------------------------------------------
# Principal: o texto do IC (base32 com CRC32, em grupos de cinco).
# ---------------------------------------------------------------------------


def principal_texto(b):
    crc = zlib.crc32(b).to_bytes(4, "big")
    t = base64.b32encode(crc + b).decode().lower().rstrip("=")
    return "-".join(t[i : i + 5] for i in range(0, len(t), 5))


def principal_bytes(texto):
    t = texto.replace("-", "").upper()
    t += "=" * (-len(t) % 8)
    b = base64.b32decode(t)
    if zlib.crc32(b[4:]).to_bytes(4, "big") != b[:4]:
        raise ValueError("principal com o CRC errado: " + texto)
    return b[4:]


# ---------------------------------------------------------------------------
# O canister: um modulo WebAssembly montado aqui.
# ---------------------------------------------------------------------------

I32 = 0x7F
I64 = 0x7E
OLA = b"DIDL\x00\x01\x71\x03ola"
NAO = b"nao"
TRUNCADO = b"DIDL\x00\x01\x71\x05ab"
SOBRA = b"DIDL\x00\x01\x71\x03olaXY"
MAGICA = b"DIDX\x00\x01\x71\x03ola"
# (principal): o cabecalho, e depois o tamanho e os bytes de quem chamou.
QUEM = b"DIDL\x00\x01\x68\x01"
QUEM_EM = 128
# (nat64): o cabecalho, e depois os oito bytes do contador.
CONTAR = b"DIDL\x00\x01\x78"
CONTAR_EM = 192
LENTO = b"DIDL\x00\x01\x71\x05lento"
LENTO_EM = 224
# Perto de dois bilhoes de instrucoes: cabe numa fatia de execucao, e leva
# um segundo ou mais na PocketIC.
LENTO_VOLTAS = 300_000_000
DADOS = {
    0: OLA,
    16: NAO,
    32: TRUNCADO,
    48: SOBRA,
    64: MAGICA,
    QUEM_EM: QUEM,
    CONTAR_EM: CONTAR + bytes(8),
    LENTO_EM: LENTO,
}
ECO_EM = 1024
MAIOR_ECO = 60000


def modulo():
    def vec(itens):
        return leb(len(itens)) + b"".join(itens)

    def nome(s):
        return leb(len(s)) + s.encode()

    def secao(numero, conteudo):
        return bytes([numero]) + leb(len(conteudo)) + conteudo

    def tipo(params, resultados):
        return b"\x60" + vec([bytes([p]) for p in params]) + vec([bytes([r]) for r in resultados])

    def const(n):
        return b"\x41" + sleb(n)

    def chama(f):
        return b"\x10" + leb(f)

    def const64(n):
        return b"\x42" + sleb(n)

    def local_get(i):
        return b"\x20" + leb(i)

    def local_set(i):
        return b"\x21" + leb(i)

    # Os tipos: 0 () -> (); 1 (i32 i32) -> (); 2 () -> i32;
    # 3 (i32 i32 i32) -> ().
    tipos = vec([tipo([], []), tipo([I32, I32], []), tipo([], [I32]), tipo([I32] * 3, [])])
    # As importacoes, que sao as funcoes 0 a 6.
    importacoes = [
        ("msg_reply_data_append", 1),
        ("msg_reply", 0),
        ("msg_reject", 1),
        ("msg_arg_data_size", 2),
        ("msg_arg_data_copy", 3),
        ("msg_caller_size", 2),
        ("msg_caller_copy", 3),
    ]
    append, reply, reject, tamanho, copia, quem_tamanho, quem_copia = range(7)
    importa = vec([nome("ic0") + nome(n) + b"\x00" + leb(t) for n, t in importacoes])

    def responde(desloc, dados):
        return const(desloc) + const(len(dados)) + chama(append) + chama(reply)

    # quem: o tamanho de quem chamou num byte depois do cabecalho, os bytes
    # dele depois, e a resposta inteira.
    quem = (
        chama(quem_tamanho)
        + local_set(0)
        + const(QUEM_EM + len(QUEM))
        + local_get(0)
        + b"\x3a\x00\x00"  # i32.store8
        + const(QUEM_EM + len(QUEM) + 1)
        + const(0)
        + local_get(0)
        + chama(quem_copia)
        + const(QUEM_EM)
        + local_get(0)
        + const(len(QUEM) + 1)
        + b"\x6a"  # i32.add
        + chama(append)
        + chama(reply)
    )
    # contar: o contador, na memoria do canister - que fica entre uma
    # chamada e outra -, mais um, e a resposta com ele.
    contador = CONTAR_EM + len(CONTAR)
    contar = (
        const(contador)
        + const(contador)
        + b"\x29\x00\x00"  # i64.load
        + const64(1)
        + b"\x7c"  # i64.add
        + b"\x37\x00\x00"  # i64.store
        + responde(CONTAR_EM, CONTAR + bytes(8))
    )
    # lento: o laco, e a resposta.
    lento = (
        b"\x03\x40"  # loop
        + local_get(0)
        + const64(1)
        + b"\x7c"  # i64.add
        + b"\x22\x00"  # local.tee 0
        + const64(LENTO_VOLTAS)
        + b"\x54"  # i64.lt_u
        + b"\x0d\x00"  # br_if 0
        + b"\x0b"  # end
        + responde(LENTO_EM, LENTO)
    )

    consultas = [
        ("ola", b"\x00", responde(0, OLA)),
        (
            "eco",
            b"\x01\x01" + bytes([I32]),
            chama(tamanho)
            + b"\x21\x00"
            + b"\x20\x00"
            + const(MAIOR_ECO)
            + b"\x4b"
            + b"\x04\x40"
            + const(16)
            + const(len(NAO))
            + chama(reject)
            + b"\x0f"
            + b"\x0b"
            + const(ECO_EM)
            + const(0)
            + b"\x20\x00"
            + chama(copia)
            + const(ECO_EM)
            + b"\x20\x00"
            + chama(append)
            + chama(reply),
        ),
        ("recusa", b"\x00", const(16) + const(len(NAO)) + chama(reject)),
        ("candid_truncado", b"\x00", responde(32, TRUNCADO)),
        ("candid_sobra", b"\x00", responde(48, SOBRA)),
        ("candid_magica", b"\x00", responde(64, MAGICA)),
        # O corpo do `quem`, como consulta: quem consultou.
        ("quem_consulta", b"\x01\x01" + bytes([I32]), quem),
    ]
    atualizacoes = [
        ("quem", b"\x01\x01" + bytes([I32]), quem),
        ("contar", b"\x00", contar),
        ("lento", b"\x01\x01" + bytes([I64]), lento),
    ]
    corpos = consultas + atualizacoes
    primeira = len(importacoes)
    funcoes = vec([leb(0) for _ in corpos])
    memoria = vec([b"\x00\x01"])
    exporta = vec(
        [
            nome(("canister_query " if i < len(consultas) else "canister_update ") + n)
            + b"\x00"
            + leb(primeira + i)
            for i, (n, _, _) in enumerate(corpos)
        ]
    )
    codigo = vec(
        [leb(len(locais + corpo + b"\x0b")) + locais + corpo + b"\x0b" for _, locais, corpo in corpos]
    )
    dados = vec([b"\x00" + const(desloc) + b"\x0b" + leb(len(d)) + d for desloc, d in DADOS.items()])
    return (
        b"\x00asm\x01\x00\x00\x00"
        + secao(1, tipos)
        + secao(2, importa)
        + secao(3, funcoes)
        + secao(5, memoria)
        + secao(7, exporta)
        + secao(10, codigo)
        + secao(11, dados)
    )


# ---------------------------------------------------------------------------
# A PocketIC, pelo REST dela.
# ---------------------------------------------------------------------------


class ErroDaPocketIc(Exception):
    pass


class PocketIc:
    """O servidor da PocketIC em 127.0.0.1: cada pedido e JSON; 202 e uma
    operacao comecada, que se le em `/read_graph`; 409, a instancia ocupada."""

    def __init__(self, url):
        hostporta = url.split("://", 1)[1].rstrip("/")
        self.host, porta = hostporta.split(":")
        self.porta = int(porta)

    def _pedir(self, metodo, caminho, corpo=None):
        c = http.client.HTTPConnection(self.host, self.porta, timeout=600)
        try:
            dados = None if corpo is None else json.dumps(corpo).encode()
            cabecalhos = {"Content-Type": "application/json"} if dados is not None else {}
            c.request(metodo, caminho, body=dados, headers=cabecalhos)
            r = c.getresponse()
            return r.status, r.read()
        finally:
            c.close()

    def chamar(self, metodo, caminho, corpo=None):
        prazo = time.time() + 600
        while time.time() < prazo:
            status, dados = self._pedir(metodo, caminho, corpo)
            # 201 e a instancia criada; 200, o resto.
            if status in (200, 201):
                return json.loads(dados)
            if status == 409:
                time.sleep(0.05)
                continue
            if status == 202:
                op = json.loads(dados)
                while time.time() < prazo:
                    time.sleep(0.02)
                    s, d = self._pedir("GET", "/read_graph/%s/%s" % (op["state_label"], op["op_id"]))
                    if s == 404:
                        continue
                    if s == 200:
                        return json.loads(d)
                    if s in (202, 409):
                        continue
                    raise ErroDaPocketIc("%s %s: %d %s" % (metodo, caminho, s, d[:300]))
                break
            raise ErroDaPocketIc("%s %s: %d %s" % (metodo, caminho, status, dados[:300]))
        raise ErroDaPocketIc("%s %s: a PocketIC nao respondeu no prazo" % (metodo, caminho))


def b64(b):
    return base64.b64encode(b).decode()


def sub_rede():
    return {"state_config": "New", "instruction_config": "Production"}


# Os ledgers, e o simbolo de cada um - ver o cabecalho. O CMC nao tem
# simbolo: responde a taxa de conversao.
LEDGERS = {
    "ledger": ("ryjl3-tyaaa-aaaaa-aaaba-cai", "ICP"),
    "cmc": ("rkp4c-7iaaa-aaaaa-aaaca-cai", None),
    "ledger_de_ciclos": ("um5iw-rqaaa-aaaaq-qaaba-cai", "TCYCLES"),
}


def consultar(pic, instancia, canister, metodo, payload):
    """Uma consulta pela API da PocketIC, do anonimo: os bytes da resposta."""
    resultado = pic.chamar(
        "POST",
        "/instances/%d/read/query" % instancia,
        {
            "sender": b64(b"\x04"),
            "canister_id": b64(principal_bytes(canister)),
            "effective_principal": "None",
            "method": metodo,
            "payload": b64(payload),
        },
    )
    if "Ok" not in resultado:
        raise ErroDaPocketIc("%s de %s falhou: %s" % (metodo, canister, resultado))
    return base64.b64decode(resultado["Ok"])


def conferir_os_ledgers(pic, instancia):
    """Cada ledger responde o simbolo dele, e o CMC a taxa: a PocketIC subiu
    os tres nos ids da rede principal."""
    vazio = b"DIDL" + leb(0) + leb(0)
    for canister, simbolo in LEDGERS.values():
        if simbolo is None:
            consultar(pic, instancia, canister, "get_icp_xdr_conversion_rate", vazio)
            continue
        texto = simbolo.encode()
        esperado = b"DIDL" + leb(0) + leb(1) + sleb(-15) + leb(len(texto)) + texto
        resposta = consultar(pic, instancia, canister, "icrc1_symbol", vazio)
        if resposta != esperado:
            raise ErroDaPocketIc("o simbolo de %s nao e %s: %r" % (canister, simbolo, resposta))


ANanos = 1_000_000_000
ATRAS_NS = 15 * 60 * ANanos


def chamar_gerenciamento(pic, instancia, metodo, payload, efetivo):
    caminho = "/instances/%d/update/" % instancia
    pedido = {
        "sender": b64(b"\x04"),
        "canister_id": b64(b""),
        "effective_principal": efetivo,
        "method": metodo,
        "payload": b64(payload),
    }
    enviado = pic.chamar("POST", caminho + "submit_ingress_message", pedido)
    if "Ok" not in enviado:
        raise ErroDaPocketIc("%s nao entrou: %s" % (metodo, enviado))
    resultado = pic.chamar("POST", caminho + "await_ingress_message", enviado["Ok"])
    if "Ok" not in resultado:
        raise ErroDaPocketIc("%s falhou: %s" % (metodo, resultado))
    return base64.b64decode(resultado["Ok"])


def gateway(porta, metodo, caminho, corpo):
    c = http.client.HTTPConnection("127.0.0.1", porta, timeout=60)
    try:
        c.request(metodo, caminho, body=corpo, headers={"Content-Type": "application/cbor"})
        r = c.getresponse()
        return r.status, r.reason, r.getheader("Content-Type") or "application/cbor", r.read()
    finally:
        c.close()


def preparar(url, diretorio):
    pic = PocketIc(url)
    agora = time.time_ns()
    config = {
        "subnet_config_set": {
            "nns": sub_rede(),
            # A do ledger de cycles.
            "ii": sub_rede(),
            "system": [],
            "application": [sub_rede(), sub_rede()],
            "verified_application": [],
        },
        "http_gateway_config": {"ip_addr": "127.0.0.1"},
        "initial_time": {"Timestamp": {"nanos_since_epoch": agora - ATRAS_NS}},
        "icp_features": {
            "icp_token": "DefaultConfig",
            "cycles_minting": "DefaultConfig",
            "cycles_token": "DefaultConfig",
        },
    }
    criada = pic.chamar("POST", "/instances", config)
    if "Created" not in criada:
        raise ErroDaPocketIc("a instancia nao foi criada: %s" % criada)
    criada = criada["Created"]
    instancia = criada["instance_id"]
    porta = criada["http_gateway_info"]["port"]
    topologia = criada["topology"]["subnet_configs"]
    nns = [s for s, c in topologia.items() if c["subnet_kind"] == "NNS"]
    aplicacao = sorted(s for s, c in topologia.items() if c["subnet_kind"] == "Application")
    if len(nns) != 1 or len(aplicacao) != 2:
        raise ErroDaPocketIc("a topologia nao e a pedida: %s" % sorted(topologia))
    raiz = bytes(
        pic.chamar(
            "POST",
            "/instances/%d/read/pub_key" % instancia,
            {"subnet_id": b64(principal_bytes(nns[0]))},
        )
    )

    # O canister, na primeira sub-rede de aplicacao.
    criacao = chamar_gerenciamento(
        pic,
        instancia,
        "provisional_create_canister_with_cycles",
        candid_criar(),
        {"SubnetId": b64(principal_bytes(aplicacao[0]))},
    )
    canister = principal_da_criacao(criacao)
    chamar_gerenciamento(
        pic,
        instancia,
        "install_code",
        candid_instalar(canister, modulo()),
        {"CanisterId": b64(canister)},
    )
    # E o mesmo modulo na NNS: o canister da sub-rede raiz, que responde sem
    # delegacao - as faixas dele vem de uma leitura a parte.
    criacao = chamar_gerenciamento(
        pic,
        instancia,
        "provisional_create_canister_with_cycles",
        candid_criar(),
        {"SubnetId": b64(principal_bytes(nns[0]))},
    )
    canister_da_raiz = principal_da_criacao(criacao)
    chamar_gerenciamento(
        pic,
        instancia,
        "install_code",
        candid_instalar(canister_da_raiz, modulo()),
        {"CanisterId": b64(canister_da_raiz)},
    )
    conferir_os_ledgers(pic, instancia)

    # O certificado velho: um `read_state` do caminho `subnet`, como o
    # agente pede, ainda no tempo de quinze minutos atras.
    tempo = pic.chamar("GET", "/instances/%d/read/get_time" % instancia)["nanos_since_epoch"]
    envelope = cbor(
        Etiqueta(
            AUTODESCRITO,
            {
                "content": {
                    "request_type": "read_state",
                    "sender": b"\x04",
                    "paths": [[b"subnet"]],
                    "ingress_expiry": tempo + 3 * 60 * ANanos,
                }
            },
        )
    )
    caminho = "/api/v3/canister/%s/read_state" % principal_texto(canister)
    status, _, _, velho = gateway(porta, "POST", caminho, envelope)
    if status != 200:
        raise ErroDaPocketIc("o read_state velho voltou %d: %r" % (status, velho[:200]))
    with open(os.path.join(diretorio, "velho.cbor"), "wb") as f:
        f.write(velho)

    # E o tempo de verdade, andando sozinho.
    pic.chamar("POST", "/instances/%d/auto_progress" % instancia, {"artificial_delay_ms": None})
    prazo = time.time() + 120
    while time.time() < prazo:
        t = pic.chamar("GET", "/instances/%d/read/get_time" % instancia)["nanos_since_epoch"]
        if abs(t - time.time_ns()) < 10 * ANanos:
            break
        time.sleep(0.5)
    else:
        raise ErroDaPocketIc("o tempo da instancia nao chegou ao de agora")

    outra = topologia[aplicacao[1]]["canister_ranges"][0]["start"]["canister_id"]
    estado = {
        "instancia": instancia,
        "gateway": porta,
        "raiz": raiz.hex(),
        "canister": principal_texto(canister),
        "canister_da_raiz": principal_texto(canister_da_raiz),
        "nns": nns[0],
        "sub_rede": aplicacao[0],
        "outra_sub_rede": aplicacao[1],
        "canister_da_outra": principal_texto(base64.b64decode(outra)),
    }
    for nome, (canister, _) in LEDGERS.items():
        estado[nome] = canister
    caminho = os.path.join(diretorio, "estado.json")
    with open(caminho + ".novo", "w") as f:
        json.dump(estado, f, indent=1)
    os.replace(caminho + ".novo", caminho)
    print(json.dumps(estado))


# ---------------------------------------------------------------------------
# O proxy.
# ---------------------------------------------------------------------------

# Mais que uma espera do prazo dos programas (cinco segundos): a leitura
# que espera a resposta lenta acorda vazia, e e decidida de novo pelo gate
# antes de a resposta chegar.
LENTIDAO_MS = 8000
# Quanto a chamada da rede assincrona espera antes de ir a PocketIC: as
# primeiras leituras da situacao a acham desconhecida.
ATRASO_DA_CHAMADA_MS = 1500
MAIOR_CABECA = 16 * 1024
MAIOR_CORPO = 1024 * 1024

MODOS = {
    "icp.duke": "honesto",
    "lenta.icp.duke": "lenta",
    "raiz-errada.icp.duke": "honesto",
    "bls-invalida.icp.duke": "bls-invalida",
    "sem-assinatura.icp.duke": "sem-assinatura",
    "no-de-fora.icp.duke": "no-de-fora",
    "assinatura-errada.icp.duke": "assinatura-errada",
    "pedido-trocado.icp.duke": "pedido-trocado",
    "aninhada.icp.duke": "aninhada",
    "faixa-errada.icp.duke": "faixa-errada",
    "velho.icp.duke": "velho",
    "direta.icp.duke": "honesto",
    "assincrona.icp.duke": "assincrona",
}

# Um no que nenhuma sub-rede tem: um principal auto-autenticado inventado.
NO_DE_FORA = hashlib.sha224(b"duke: no de fora").digest() + b"\x02"


class Fechou(Exception):
    pass


def ler_pedido(conexao, buffer):
    while b"\r\n\r\n" not in buffer:
        if len(buffer) > MAIOR_CABECA:
            raise Fechou()
        dados = conexao.recv(65536)
        if not dados:
            raise Fechou()
        buffer += dados
    cabeca, buffer = buffer.split(b"\r\n\r\n", 1)
    linhas = cabeca.decode("latin-1").split("\r\n")
    metodo, alvo, _ = linhas[0].split(" ", 2)
    cabecalhos = {}
    for linha in linhas[1:]:
        nome, _, valor = linha.partition(":")
        cabecalhos[nome.strip().lower()] = valor.strip()
    tamanho = int(cabecalhos.get("content-length", "0"))
    if tamanho > MAIOR_CORPO:
        raise Fechou()
    while len(buffer) < tamanho:
        dados = conexao.recv(65536)
        if not dados:
            raise Fechou()
        buffer += dados
    corpo, buffer = buffer[:tamanho], buffer[tamanho:]
    return metodo, alvo, cabecalhos, corpo, buffer


def mexer_no_certificado(resposta, f):
    """Aplica `f` ao certificado (decodificado) de uma resposta de
    `read_state`, e remonta tudo."""
    externo, tinha = sem_etiqueta(de_cbor(resposta))
    cert, tinha_cert = sem_etiqueta(de_cbor(externo["certificate"]))
    f(cert)
    externo["certificate"] = cbor(com_etiqueta(cert, tinha_cert))
    return cbor(com_etiqueta(externo, tinha))


def mexer_na_consulta(resposta, f):
    externo, tinha = sem_etiqueta(de_cbor(resposta))
    f(externo)
    return cbor(com_etiqueta(externo, tinha))


def trocar_byte(b, i=-1):
    b = bytearray(b)
    b[i] ^= 0x01
    return bytes(b)


def aninhar(cert):
    delegacao = cert.get("delegation")
    if delegacao is None:
        raise ValueError("o certificado nao tem delegacao para aninhar")
    interno, tinha = sem_etiqueta(de_cbor(delegacao["certificate"]))
    interno["delegation"] = dict(delegacao)
    delegacao["certificate"] = cbor(com_etiqueta(interno, tinha))


def chamar_depois(estado, metodo, alvo, corpo, log):
    """A chamada pela via assincrona do gateway (`/api/v2`), depois de
    ATRASO_DA_CHAMADA_MS. O fio nao e `daemon`: o processo do proxy so sai
    depois de entregar a chamada."""

    def entregar():
        time.sleep(ATRASO_DA_CHAMADA_MS / 1000)
        v2 = alvo.replace("/api/v4/", "/api/v2/", 1)
        try:
            status, _, _, _ = gateway(estado["gateway"], metodo, v2, corpo)
            print("icp.py: assincrona %s %s -> %d" % (metodo, v2, status), file=log, flush=True)
        except OSError as erro:
            print("icp.py: assincrona %s: %s" % (v2, erro), file=log, flush=True)

    threading.Thread(target=entregar).start()


def repassar(estado, diretorio, modo, metodo, alvo, corpo, log=None):
    """O pedido ao gateway, e a resposta mexida conforme o modo."""
    leitura = alvo.endswith("/read_state")
    consulta = alvo.endswith("/query")
    chamada = alvo.endswith("/call")
    if modo == "assincrona" and chamada:
        # O 202 na hora: a chamada foi aceita, e nada mais se sabe dela.
        chamar_depois(estado, metodo, alvo, corpo, log or sys.stderr)
        return 202, "Accepted", "application/cbor", b""
    if modo == "velho" and leitura:
        with open(os.path.join(diretorio, "velho.cbor"), "rb") as f:
            return 200, "OK", "application/cbor", f.read()
    if modo == "faixa-errada" and leitura:
        partes = alvo.split("/")
        partes[4] = estado["canister_da_outra"]
        alvo = "/".join(partes)
    if modo == "pedido-trocado" and consulta:
        envelope, tinha = sem_etiqueta(de_cbor(corpo))
        conteudo = envelope["content"]
        conteudo["nonce"] = trocar_byte(conteudo.get("nonce", b"\x00"))
        corpo = cbor(com_etiqueta(envelope, tinha))
    status, motivo, tipo, resposta = gateway(estado["gateway"], metodo, alvo, corpo)
    if status != 200:
        return status, motivo, tipo, resposta
    if modo == "lenta" and leitura:
        time.sleep(LENTIDAO_MS / 1000)
    elif modo == "bls-invalida" and leitura:
        resposta = mexer_no_certificado(
            resposta, lambda c: c.__setitem__("signature", trocar_byte(c["signature"]))
        )
    elif modo == "aninhada" and leitura:
        resposta = mexer_no_certificado(resposta, aninhar)
    elif modo == "sem-assinatura" and consulta:
        resposta = mexer_na_consulta(resposta, lambda r: r.pop("signatures", None))
    elif modo == "sem-assinatura" and chamada:
        resposta = mexer_na_consulta(resposta, lambda r: r.pop("certificate", None))
    elif modo == "no-de-fora" and consulta:

        def de_fora(r):
            for a in r.get("signatures", []):
                a["identity"] = NO_DE_FORA

        resposta = mexer_na_consulta(resposta, de_fora)
    elif modo == "assinatura-errada" and consulta:

        def errada(r):
            for a in r.get("signatures", []):
                a["signature"] = trocar_byte(a["signature"])

        resposta = mexer_na_consulta(resposta, errada)
    elif modo == "assinatura-errada" and chamada:
        # A recusa antes do consenso nao tem certificado: passa como veio.
        if "certificate" in sem_etiqueta(de_cbor(resposta))[0]:
            resposta = mexer_no_certificado(
                resposta, lambda c: c.__setitem__("signature", trocar_byte(c["signature"]))
            )
    return status, motivo, tipo, resposta


def contexto_tls(diretorio_tls):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    c.load_cert_chain(
        os.path.join(diretorio_tls, "icp.pem"),
        os.path.join(diretorio_tls, "icp.chave"),
    )
    return c


def proxy(diretorio, diretorio_tls):
    log = open(os.path.join(diretorio, "proxy.log"), "a")
    # A saida de erro e a conexao: o que o Python escrevesse nela iria para
    # o cliente no meio da conversa.
    os.dup2(log.fileno(), 2)
    sys.stderr = log
    with open(os.path.join(diretorio, "estado.json")) as f:
        estado = json.load(f)
    nome = {"valor": None}

    def pelo_nome(_conexao, pedido, _contexto):
        nome["valor"] = pedido

    ctx = contexto_tls(diretorio_tls)
    ctx.sni_callback = pelo_nome
    cru = socket.socket(fileno=0)
    cru.settimeout(60)
    try:
        with ctx.wrap_socket(cru, server_side=True) as conexao:
            # O modo e o do nome que o TLS provou, para a conexao inteira.
            modo = MODOS.get(nome["valor"], "honesto")
            atender(conexao, lambda _: modo, estado, diretorio, log)
            try:
                conexao.unwrap()
            except (ssl.SSLError, OSError):
                pass
    except (ssl.SSLError, OSError, ValueError) as erro:
        print("icp.py:", type(erro).__name__, erro, file=log, flush=True)


def atender(conexao, modo_de, estado, diretorio, log):
    """Os pedidos de uma conexao, cada um repassado com o modo dele."""
    buffer = b""
    while True:
        try:
            metodo, alvo, cabecalhos, corpo, buffer = ler_pedido(conexao, buffer)
        except Fechou:
            return
        modo = modo_de(cabecalhos)
        try:
            status, motivo, tipo, resposta = repassar(
                estado, diretorio, modo, metodo, alvo, corpo, log
            )
        except (OSError, ValueError, KeyError) as erro:
            print("icp.py: %s %s: %s" % (modo, alvo, erro), file=log, flush=True)
            status, motivo, tipo, resposta = 502, "Bad Gateway", "text/plain", b"bancada\n"
        print("icp.py: %s %s %s -> %d" % (modo, metodo, alvo, status), file=log, flush=True)
        cabeca = "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n" % (
            status,
            motivo,
            tipo,
            len(resposta),
        )
        conexao.sendall(cabeca.encode() + resposta)


def proxy_claro(diretorio, porta):
    with open(os.path.join(diretorio, "estado.json")) as f:
        estado = json.load(f)
    log = open(os.path.join(diretorio, "proxy-claro.log"), "a")
    escuta = socket.create_server(("127.0.0.1", porta))

    def pelo_host(cabecalhos):
        return MODOS.get(cabecalhos.get("host", "").split(":")[0], "honesto")

    while True:
        conexao, _ = escuta.accept()
        with conexao:
            conexao.settimeout(60)
            try:
                atender(conexao, pelo_host, estado, diretorio, log)
            except OSError as erro:
                print("icp.py:", type(erro).__name__, erro, file=log, flush=True)


def main():
    papel = sys.argv[1] if len(sys.argv) > 1 else ""
    if papel == "preparar" and len(sys.argv) == 4:
        preparar(sys.argv[2], sys.argv[3])
    elif papel == "proxy" and len(sys.argv) == 4:
        proxy(sys.argv[2], sys.argv[3])
    elif papel == "proxy-claro" and len(sys.argv) == 4:
        proxy_claro(sys.argv[2], int(sys.argv[3]))
    elif papel == "wasm" and len(sys.argv) == 3:
        with open(sys.argv[2], "wb") as f:
            f.write(modulo())
    else:
        print(
            "uso: icp.py preparar <url> <dir> | proxy <dir> <dir-tls> | proxy-claro <dir> <porta> | wasm <arquivo>",
            file=sys.stderr,
        )
        sys.exit(2)


if __name__ == "__main__":
    main()
