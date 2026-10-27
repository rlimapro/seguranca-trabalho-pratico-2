# TP3: Mensageria Segura E2E — Plano Incremental

Stack: Python 3 + `asyncio` + `cryptography`.
Regra: só avance de etapa quando os testes da anterior passarem.
Versionamento: cada etapa deve ser concluída em um commit separado, usando o formato Conventional Commits (`<tipo>(<escopo>): <descrição>`), por exemplo `chore(setup): implementa etapa 0`.

## Decisões de projeto assumidas

| # | Dúvida | Decisão |
|---|---|---|
| 1 | Salt do HKDF entre A e B | O servidor envia o `salt_srv` do peer junto com a `pk` dele. Salt do par = `SHA256(salt_do_menor_id ‖ salt_do_maior_id)[:16]` |
| 2 | Quem é A e B | O `client_id` menor (comparação de bytes) é "A". A envia com `A2B`, B envia com `B2A` |
| 3 | `pk_S` e hash duplo | `pk_S` é uma chave X25519 **efêmera do servidor**, assinada pelo RSA. Calcula-se `H = SHA256(pk_S ‖ pk_C ‖ client_id ‖ salt)` e assina-se diretamente esse digest com RSA-PSS + `Prehashed(SHA256)`, sem aplicar SHA-256 uma segunda vez. A verificação usa os mesmos parâmetros. |
| 4 | Canal cliente↔servidor | ECDH entre `sk_C` e `pk_S` gera `Z_CS`. HKDF gera `C2S` e `S2C` (AES-GCM) para mensagens administrativas |
| 5 | Tipos de mensagem | 1 byte de tipo após o tamanho (ver tabela de formatos) |
| 6 | Autenticidade entre pares | Limitação documentada. O cliente mostra o fingerprint `SHA256(pk)[:8]` de cada peer |
| 7 | `seq_recv` no servidor | Vale só para mensagens administrativas do cliente. O servidor não checa `seq_no` do E2E |
| 8 | Stack | Python + asyncio + `cryptography` |

## Formatos de frame

```text
Frame geral:   [len 4B BE][type 1B][payload]        (len = 1 + tamanho do payload)

Tipos:
0x01 HELLO         cliente -> servidor
0x02 SERVER_HELLO  servidor -> cliente
0x03 PEER_INFO     servidor -> cliente   (cifrado no canal administrativo)
0x04 PEER_LEFT     servidor -> cliente   (cifrado no canal administrativo)
0x05 E2E           cliente -> servidor -> cliente (relay, bytes intactos)
0x06 ERROR         servidor -> cliente   (cifrado no canal administrativo)

HELLO payload:        client_id (16B) | pk_C (32B)
SERVER_HELLO payload: pk_S (32B) | salt_srv (16B) | sig_len (2B) | sig | cert_len (2B) | cert (DER)
Administrativas:      seq (8B BE) | ciphertext+tag
                      nonce = direction (4B) | seq (8B)   (c2s = 0, s2c = 1)
                      AAD   = type (1B) | seq (8B)
PEER_INFO (após decifragem): client_id (16B) | pk (32B) | salt_srv (16B)
PEER_LEFT (após decifragem): client_id (16B)
E2E payload:          nonce (12B) | sender_id (16B) | recipient_id (16B) | seq_no (8B) | ciphertext+tag
                      nonce = IV_base (4B) | seq_no (8B BE)
                      AAD   = sender_id | recipient_id | seq_no
```

Todo frame administrativo (`PEER_INFO`, `PEER_LEFT` e `ERROR`) leva no payload externo `seq (8B BE) | ciphertext+tag`; o plaintext correspondente é o conteúdo indicado acima. O tipo do frame e o `seq` entram no AAD (`type (1B) | seq (8B)`). Assim, IDs, chaves públicas e salts distribuídos por `PEER_INFO` não trafegam em claro. `HELLO` e `SERVER_HELLO` são mensagens de handshake e seguem seus formatos próprios.

## Estrutura do projeto

```text
tp3/
  certs/       server.crt  server.key
  common/      framing.py  protocol.py  crypto.py
  server/      server.py
  client/      client.py
  tests/       test_framing.py  test_crypto.py  test_handshake.py ...
  README.md
```

---

## Etapa 0: Setup e certificado

**Objetivo:** ambiente pronto e certificado RSA gerado.

**Implementar**
- Criar a estrutura de pastas e o ambiente virtual (`pip install cryptography pytest`).
- Gerar o certificado autoassinado:
  `openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=tp3-server"`
- Definir o `server.crt` como "pinado": o cliente carrega uma cópia local e compara com a recebida.

**Teste de aceite**
- Carregar `server.crt` e `server.key` em Python.
- Confirmar que o tamanho da chave RSA é >= 2048 bits.

**Atenção:** nunca versionar `server.key` em repositório público.

---

## Etapa 1: Framing TCP

**Objetivo:** enviar e receber frames delimitados, com tratamento de erro.

**Implementar**
- `send_frame(writer, type, payload)`: escreve `len(4B BE) | type | payload`.
- `recv_frame(reader)`: lê 4B, valida o tamanho, lê exatamente `len` bytes (`readexactly`).
- Definir `MAX_FRAME` (por exemplo 8 KB) e rejeitar comprimento zero ou maior que `MAX_FRAME`.
- Servidor eco simples com `asyncio.start_server`, aceitando vários clientes.

**Testes de aceite**
- Frame normal volta íntegro pelo eco.
- Dois clientes simultâneos funcionam.
- Tamanho declarado absurdo gera erro e o servidor fecha a conexão sem travar.
- Conexão cortada no meio do frame (`IncompleteReadError`) não derruba o servidor.

**Atenção:** TCP é fluxo de bytes, então um `read(n)` simples pode devolver menos que `n`. Use `readexactly`.

---

## Etapa 2: Módulo de criptografia

**Objetivo:** funções puras e testadas, sem rede.

**Implementar em `common/crypto.py`**
- `gen_x25519() -> (sk, pk_raw_32B)`
- `ecdh(sk, pk_peer_raw) -> Z`
- `hkdf_extract_expand(salt, Z, info, length=16)` (HKDF-SHA256)
- `build_nonce(iv_base_or_direction, seq)` (12B, `seq` em big-endian)
- `build_aad_e2e(sender, recipient, seq)` e `build_aad_admin(type, seq)`
- `aes_encrypt(key, nonce, aad, plaintext)` e `aes_decrypt(...)` com `AESGCM`
- `fingerprint(pk) -> hex` (`SHA256(pk)[:8]`)

**Testes de aceite**
- `ecdh(sk_A, pk_B) == ecdh(sk_B, pk_A)`.
- Roundtrip encrypt/decrypt devolve o plaintext.
- Alterar 1 bit do ciphertext, do AAD ou do nonce gera `InvalidTag`.
- `Key_A2B != Key_B2A` com o mesmo `Z` e `salt`.
- Chaves têm 16 bytes e nonce tem 12 bytes.

**Atenção:** `AESGCM.encrypt` já devolve `ciphertext || tag`. Não concatene a tag por conta própria.

---

## Etapa 3: Handshake autenticado (cliente ↔ servidor)

**Objetivo:** cliente confirma que está falando com o servidor legítimo.

**Implementar**
- Cliente: gera `client_id = uuid4().bytes`, par X25519, envia `HELLO`.
- Servidor: gera par efêmero `(sk_S, pk_S)` e `salt_srv` (16B aleatórios), calcula `H = SHA256(pk_S ‖ pk_C ‖ client_id ‖ salt_srv)`, assina diretamente o digest `H` com RSA-PSS (`MGF1(SHA256)`, `Prehashed(SHA256)`, sem hash duplo) e responde `SERVER_HELLO` com o certificado em DER.
- Cliente: compara o cert recebido com o pinado (bytes ou fingerprint), recalcula `H` e verifica a assinatura com a chave pública do cert usando os mesmos parâmetros. Se algo falhar, fecha a conexão.

**Testes de aceite**
- Caminho feliz: handshake conclui.
- Cert diferente do pinado é rejeitado.
- Assinatura com 1 byte alterado é rejeitada.
- Servidor de teste que troca `pk_S`, `salt` ou `client_id` invalida a assinatura.
- Servidor de teste com outra chave RSA (mesmo cert pinado) é rejeitado.

**Atenção:** `salt_length` do PSS e o MGF1 precisam ser iguais na assinatura e na verificação.

---

## Etapa 4: Canal administrativo e tabela `sessions`

**Objetivo:** mensagens do servidor com confidencialidade, integridade e anti-replay.

**Implementar**
- Os dois lados calculam `Z_CS = ECDH(sk_S, pk_C)` / `ECDH(sk_C, pk_S)`.
- `PRK = HKDF-Extract(salt_srv, Z_CS)`; chaves `C2S` e `S2C` com `info=b"C2S"` e `b"S2C"`.
- Funções `send_admin(type, plaintext)` e `recv_admin(...)`, com `seq_send` e `seq_recv` por conexão.
- No fio, toda mensagem administrativa usa `seq (8B BE) | ciphertext+tag`; `type | seq` é o AAD. O servidor só envia a confirmação cifrada depois de derivar as chaves administrativas; o cliente só a decifra depois de validar certificado e assinatura e derivar as mesmas chaves.
- Ao receber mensagem administrativa, validar a tag antes de atualizar `seq_recv`; rejeitar `seq <= seq_recv` sem avançar o contador.
- Servidor: criar `sessions[client_id] = {writer, public_key, salt, seq_send=0, seq_recv=-1}` e descartar `sk_S` e `Z_CS` do log.
- Primeira mensagem de teste: servidor manda um `ERROR` ou confirmação de registro cifrado.

**Testes de aceite**
- Cliente decifra a confirmação do servidor.
- Reenviar a mesma mensagem administrativa (mesmo `seq`) é rejeitado.
- Mensagem administrativa com bitflip é rejeitada.
- `sessions` tem os valores iniciais corretos (`seq_send=0`, `seq_recv=-1`).

**Atenção:** nunca reutilize a mesma chave nas duas direções. Por isso são duas (`C2S` e `S2C`).

---

## Etapa 5: Rendezvous (distribuição de chaves públicas)

**Objetivo:** todos os clientes conhecem as `pk` dos outros.

**Implementar**
- Ao registrar um cliente novo, o servidor envia `PEER_INFO` para ele, uma vez por cliente já conectado (`client_id | pk | salt` do outro).
- O servidor também envia `PEER_INFO` do novo para todos os já conectados.
- Ao desconectar, o servidor remove da `sessions` e envia `PEER_LEFT` aos demais.
- Cliente mantém uma tabela `known_peers` e imprime `client_id` e fingerprint de cada peer.

**Testes de aceite**
- Com 3 clientes conectando em sequência, todos enxergam todos.
- Quando um sai, os outros recebem `PEER_LEFT` e removem da tabela.
- Um cliente nunca recebe a própria `pk` como peer.

**Atenção:** trate a condição de corrida de dois clientes conectando ao mesmo tempo (um lock na `sessions` resolve).

---

## Etapa 6: Derivação das chaves E2E (tabela `peers`)

**Objetivo:** A e B chegam nas mesmas chaves sem o servidor participar.

**Implementar**
- Ao receber `PEER_INFO`, o cliente calcula `Z = ECDH(sk_self, pk_peer)`.
- Cada cliente associa o `salt_srv` recebido no seu handshake ao próprio `client_id`; `PEER_INFO` distribui o `salt_srv` do peer junto da chave pública. Salt do par: `SHA256(salt_do_menor_id ‖ salt_do_maior_id)[:16]`, usando comparação lexicográfica dos 16 bytes dos IDs para ordenar os dois salts. Essa regra determinística garante que ambos derivem o mesmo salt apesar de cada handshake gerar um salt independente.
- `PRK = HKDF-Extract(salt_par, Z)`; `Key_A2B` e `Key_B2A` com `info` `b"A2B"` e `b"B2A"`.
- Se `my_id < peer_id`, sou A: `key_send = A2B`, `key_recv = B2A`. Caso contrário, o inverso.
- Preencher `peers[peer_id] = {public_key, key_send, key_recv, seq_send=0, seq_recv=-1, IV_base_send=random(4), IV_base_recv}` e descartar `Z`.

**Testes de aceite**
- Dois clientes: `key_send` de A == `key_recv` de B e vice-versa (comparar em teste unitário, sem logar as chaves).
- `key_send != key_recv` em cada cliente.
- Dois pares diferentes (A-B e A-C) têm chaves diferentes.

**Atenção:** `IV_base_recv` não precisa ser combinado. O receptor lê o nonce diretamente do frame. Ele serve só para o remetente montar o nonce.

---

## Etapa 7: Mensagem E2E e relay

**Objetivo:** A manda para B, o servidor só repassa.

**Implementar**
- Cliente: monta nonce = `IV_base_send ‖ seq_send`, AAD = `sender ‖ recipient ‖ seq`, cifra com `key_send`, envia o frame `0x05`, depois incrementa `seq_send`.
- Servidor: lê só os 16 bytes de `recipient_id` (offset 28 a 44 do payload), procura em `sessions` e reenvia o frame **inalterado** ao `writer` do destinatário. Se o destinatário não existe, responde `ERROR` (administrativo).
- Cliente destinatário: valida `sender_id` conhecido, reconstrói o AAD e decifra com `key_recv` usando o nonce recebido no frame. `IV_base_recv` não é necessário para decifrar; o receptor não conhece o IV aleatório do remetente. A proteção contra replay é pelo `seq_no`, atualizado apenas após tag válida.
- Limite de 4096 bytes de plaintext no remetente (e checagem de tamanho de frame no servidor).
- Interface mínima de linha de comando: `/to <id_ou_prefixo> mensagem`.

**Testes de aceite**
- A→B e B→A funcionam, com várias mensagens seguidas.
- Três clientes: mensagem de A para B não chega em C.
- O servidor não tem nenhuma chave que decifre o frame (na demo, mostrar o dump do tráfego no servidor).
- Plaintext maior que 4096 bytes é recusado antes de cifrar.

**Atenção:** `seq_send` só incrementa depois de montar o frame. Nunca reutilize `seq` com a mesma chave.

---

## Etapa 8: Ataques e rejeições (os 4 testes obrigatórios)

**Objetivo:** demonstrar proteção contra adulteração e replay.

**Implementar**
- Anti-replay: se `seq_no <= seq_recv`, rejeitar. Só atualizar `seq_recv` **depois** da tag válida.
- Tag inválida: rejeitar, logar apenas o motivo e o `client_id`, e continuar a conexão.
- Framing inválido: tamanho incorreto ou frame truncado fecha a conexão com segurança.
- Modo de ataque para a demo: um proxy (ou flag `--attack`) entre cliente e servidor que (a) inverte 1 bit de um frame E2E e (b) reenvia um frame antigo.

**Testes de aceite**
1. Troca normal: destinatário decifra corretamente.
2. Bitflip: destinatário rejeita por tag inválida.
3. Replay: segunda entrega do mesmo frame é rejeitada.
4. Framing inválido: tamanho incorreto gera desconexão segura.

Verificações extras:
- Após uma rejeição, mensagens legítimas seguintes ainda funcionam.
- Trocar `recipient_id` ou `sender_id` no frame faz a tag falhar (o AAD cobre os ids).

**Atenção:** se atualizar `seq_recv` antes de validar a tag, um atacante consegue "queimar" a sequência.

---

## Etapa 9: Reconexão, logs, documentação e demo

**Objetivo:** fechar os requisitos operacionais e a apresentação.

**Implementar**
- Reconexão com o mesmo `client_id`: handshake completo, novo par efêmero, novo salt, contadores zerados. Se o ID ainda tiver uma conexão ativa, o servidor invalida/fecha a conexão antiga antes de instalar a nova sessão, para não manter duas conexões válidas com a mesma identidade.
- Política de logs: permitido `client_id`, eventos de conexão/desconexão, tamanhos, motivos de rejeição e fingerprints. Proibido `sk`, `Z`, salt, nonce, conteúdo e chaves.
- README com: decisões assumidas, formato dos frames, diagrama de sequência, limite de 4096 bytes e justificativa, limitação de autenticidade entre pares, como rodar.
- Script de demo: sobe servidor, conecta 3 clientes, troca mensagens, executa os 3 ataques.

**Testes de aceite**
- Reconectar gera `PEER_INFO` com `pk` e salt novos, e as chaves E2E mudam.
- `grep` nos logs de uma sessão completa não encontra chaves, salt, nonce nem conteúdo.
- Alguém que não conhece o projeto consegue rodar a demo seguindo o README.
- Servidor trata o erro ao atingir limite de recursos (por exemplo um máximo de conexões configurável).

---

## Mapa para a rubrica

| Critério | Peso | Etapas |
|---|---|---|
| Handshake e rendezvous E2E | 30% | 3, 4, 5, 6 |
| AES-GCM E2E com nonce e `seq_no` | 25% | 2, 7 |
| Replay e tampering demonstrados | 20% | 8 |
| Código organizado, documentação e demo | 15% | 0, 1, 9 |
| Práticas de segurança (logs, chaves) | 10% | 4, 9 |
