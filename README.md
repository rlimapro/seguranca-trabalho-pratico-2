# TP3 — Mensageria segura E2E

Implementação incremental em Python, `asyncio` e `cryptography`. O plano completo
e as decisões de protocolo estão em [`AGENTS.md`](AGENTS.md).

## Etapas 0–6

As etapas 0–4 preparam o certificado pinado, framing TCP, primitivas
criptográficas, handshake autenticado e canal administrativo cifrado. A etapa 5
adiciona o rendezvous: o servidor anuncia entradas e saídas, distribuindo
`client_id`, chave pública X25519 e `salt_srv` dentro de frames administrativos
autenticados por AES-GCM. O cliente guarda esses dados em `known_peers` e mostra
o fingerprint `SHA256(pk)[:8]` para conferência manual. Na etapa 6, cada cliente
usa sua chave privada X25519 e a chave pública recebida para derivar localmente
as chaves direcionais E2E; o servidor não as recebe.

### Na história

As cenas 4 e 5: Bruno chega depois de Alice, e o servidor usa o interfone
autenticado para entregar a cada um os dados públicos do outro. Alice e Bruno
ordenam os salts por `client_id`, calculam `Z_AB` localmente e derivam `A2B` e
`B2A`; a saída indica quando as chaves E2E estão prontas sem exibi-las. Quando
um cliente sai, os demais removem seus metadados e estado de chaves. A etapa
entrega as chaves locais necessárias para mensagens E2E, mas ainda não envia
essas mensagens. A autenticação entre peers também não existe: Alice e Bruno
precisam comparar fingerprints por um canal confiável para detectar uma troca
maliciosa de chaves pelo servidor.

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
entrar, junto da confirmação de que as chaves E2E foram derivadas localmente.
`Ctrl-C` encerra a conexão; os demais clientes recebem `PEER_LEFT`.

## Verificação

```sh
python -m pytest -q
```
