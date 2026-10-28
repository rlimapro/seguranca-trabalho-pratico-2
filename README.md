# TP3 — Mensageria segura E2E

Implementação incremental em Python, `asyncio` e `cryptography`. O plano completo
e as decisões de protocolo estão em [`AGENTS.md`](AGENTS.md).

## Etapas 0–5

As etapas 0–4 preparam o certificado pinado, framing TCP, primitivas
criptográficas, handshake autenticado e canal administrativo cifrado. A etapa 5
adiciona o rendezvous: o servidor anuncia entradas e saídas, distribuindo
`client_id`, chave pública X25519 e `salt_srv` dentro de frames administrativos
autenticados por AES-GCM. O cliente guarda esses dados em `known_peers` e mostra
o fingerprint `SHA256(pk)[:8]` para conferência manual.

### Na história

Esta etapa cobre a cena 4: Bruno chega depois de Alice, e o servidor usa o
interfone já autenticado para entregar a cada um os dados públicos do outro.
Quando um cliente sai, Alice recebe `PEER_LEFT` e remove Bruno da tabela. Isso
prepara os dados necessários para a derivação local das chaves na etapa 6; aqui
o servidor ainda não calcula chaves E2E e ainda não há troca de mensagens entre
peers. Como a autenticação entre peers não existe, Alice e Bruno ainda precisam
comparar fingerprints por um canal confiável para detectar uma troca maliciosa
de chaves pelo servidor.

## Como executar

Na pasta `tp3/`, com dependências instaladas (`pip install -r requirements.txt`):

```sh
python -m server.handshake_server --host 127.0.0.1 --port 8766 \
  --cert certs/server.crt --key certs/server.key
```

Em outros terminais, conecte dois ou mais clientes:

```sh
python -m client.client --host 127.0.0.1 --port 8766 --pin client/certs/server.crt
```

O cliente permanece conectado e imprime o ID e fingerprint de cada peer que
entrar. `Ctrl-C` encerra a conexão; os demais clientes recebem `PEER_LEFT`.

## Verificação

```sh
python -m pytest -q
```
