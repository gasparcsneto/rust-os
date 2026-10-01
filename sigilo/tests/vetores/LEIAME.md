# Vetores de teste do Noise

Os dois arquivos são os vetores do padrão `Noise_IK_25519_ChaChaPoly_BLAKE2s`
retirados, sem alteração, dos arquivos de vetores que acompanham o pacote
[`snow`](https://github.com/mcginty/snow) 0.9.6 (`tests/vectors/`), licenciado
sob MIT ou Apache-2.0:

- `cacophony-ik.json`: gerado pela [Cacophony](https://github.com/centromere/cacophony),
  uma implementação do Noise em Haskell, sem nada em comum com esta nem com o
  `snow`. É o vetor que tem o resumo do aperto (`handshake_hash`) e quatro
  mensagens de transporte depois dele.
- `snow-ik.json`: gerado pelo próprio `snow`, com um prólogo e cargas
  diferentes.

Só os vetores deste padrão foram copiados; o resto dos arquivos cobre padrões
e primitivas que o Duke não usa.
