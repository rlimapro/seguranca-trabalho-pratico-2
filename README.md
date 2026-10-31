# TP3 — Mensageria segura E2E

Implementação incremental em Python, `asyncio` e `cryptography`. O plano completo
e as decisões de protocolo estão em [`AGENTS.md`](AGENTS.md).

## Etapas 0–8

As etapas 0–4 preparam o certificado pinado, framing TCP, primitivas
criptográficas, handshake autenticado e canal administrativo cifrado. A etapa 5
adiciona o rendezvous: o servidor anuncia entradas e saídas, distribuindo
`client_id`, chave pública X25519 e `salt_srv` dentro de frames administrativos
autenticados por AES-GCM. O cliente guarda esses dados em `known_peers` e mostra
o fingerprint `SHA256(pk)[:8]` para conferência manual. Na etapa 6, cada cliente
usa sua chave privada X25519 e a chave pública recebida para derivar localmente
as chaves direcionais E2E; o servidor não as recebe. A etapa 7 acrescenta o
envio de mensagens com `/to <id_ou_prefixo> mensagem`: o cliente cifra com
AES-GCM, e o servidor encaminha o frame sem abrir ou alterar seu conteúdo. O
remetente limita o plaintext a 4096 bytes.

### Na história — etapa 8

Na cena 8, o destinatário rejeita uma tag GCM alterada e frames repetidos sem
avançar incorretamente o contador; depois de cada rejeição, mensagens válidas
continuam sendo aceitas. O cliente registra somente o motivo e seu `client_id`.
Tamanho declarado acima de `MAX_FRAME` e frame truncado encerram a conexão
afetada. Esta etapa acrescenta `--attack bitflip` e `--attack replay` para
corromper ou repetir cada mensagem enviada pelo cliente durante a demonstração;
ela não acrescenta novos mecanismos criptográficos nem protege contra MITM na
distribuição de chaves públicas.

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

### Na história — etapa 7

São as cenas 6 e 7: Alice cifra a mensagem com a chave `A2B`, incluindo nonce,
IDs e sequência; o servidor encaminha o frame para Bruno pelo `recipient_id`.
Bruno valida o destinatário e o remetente, autentica e decifra antes de avançar
seu contador. O limite de 4096 bytes mantém cada mensagem dentro do tamanho
aceito pelo framing. A etapa entrega troca E2E em texto, mas ainda não inclui a
demonstração dos ataques de bitflip e replay, que pertence à etapa 8.

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
Envie mensagens com `/to <id_ou_prefixo> mensagem`; prefixos ambíguos ou sem
correspondência são recusados. `Ctrl-C` encerra a conexão; os demais clientes
recebem `PEER_LEFT`.

## Verificação

```sh
python -m pytest -q
```

Para demonstrar rejeições, inicie um cliente com `--attack bitflip` ou
`--attack replay` e envie `/to <id_ou_prefixo> mensagem` para outro cliente. O
primeiro modo altera um bit da tag AES-GCM; o segundo transmite o mesmo frame
duas vezes. O cliente destinatário rejeita o frame afetado e mantém a sessão
ativa.
