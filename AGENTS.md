# TP3: Mensageria Segura E2E — Plano Incremental

Stack: Python 3 + `asyncio` + `cryptography`.
Testes por etapa: cada etapa deve ter sua própria suíte de testes, cobrindo seus critérios de aceite. Uma etapa só é aprovada quando todos os testes da sua suíte passam; não avance para a etapa seguinte enquanto houver teste falhando ou critério de aceite sem cobertura/verificação.
Versionamento: cada etapa deve ser concluída em um commit separado, usando o formato Conventional Commits (`<tipo>(<escopo>): <descrição>`), por exemplo `chore(setup): implementa etapa 0`.
Documentação incremental: cada etapa deve explicar também seu papel na história de Alice e Bruno, como nas etapas 0 e 1 abaixo. Inclua uma seção `Na história` que conecte o que foi implementado às cenas do sistema, explique o que a etapa entrega ao sistema completo e deixe claro o que ainda não faz parte dela.

## O sistema em ação: Alice e Bruno

Suponha que o `client_id` da Alice seja menor que o do Bruno; portanto, Alice é A e Bruno é B.

**Cena 0 — antes de tudo.** O servidor tem `server.key` e `server.crt`. Cada cliente guarda uma cópia somente de `server.crt`.

**Cena 1 — Alice chega.** Ela gera seu par X25519 efêmero e envia `HELLO` com seu `client_id` e sua chave pública.

**Cena 2 — o porteiro se prova.** O servidor gera sua chave X25519 efêmera (`pk_S`) e `salt_srv`, assina o material do handshake com RSA-PSS e envia `SERVER_HELLO` com chave, salt, assinatura e certificado. Alice compara o certificado com o pinado e verifica a assinatura. Se algo falhar, fecha a conexão; se passar, autenticou o servidor.

**Cena 3 — o interfone.** Alice e o servidor calculam `Z_CS` e derivam as chaves administrativas `C2S` e `S2C`. Daqui em diante, confirmações, avisos e erros administrativos trafegam cifrados e numerados. O servidor registra Alice em `sessions`.

**Cena 4 — Bruno chega.** Bruno repete as cenas 1 a 3. O servidor usa o canal administrativo de cada cliente para enviar `PEER_INFO`: cada um recebe a chave pública e o salt associado ao outro.

**Cena 5 — cada um calcula sozinho.** Alice combina sua chave privada com a chave pública de Bruno; Bruno faz o inverso. Ambos chegam ao mesmo `Z_AB`. Como os salts de seus handshakes são diferentes, cada lado calcula `SHA256(salt_do_menor_id ‖ salt_do_maior_id)[:16]`. O HKDF deriva `A2B` e `B2A`: Alice envia com `A2B` e recebe com `B2A`; Bruno faz o inverso. O servidor não participa da derivação E2E.

**Cena 6 — Alice manda “oi”.** Ela monta o nonce (`IV_base ‖ seq`), o AAD e cifra a mensagem com `A2B`. Envia um frame `E2E`. O servidor consulta o `recipient_id` e encaminha os bytes sem alterá-los.

**Cena 7 — Bruno abre.** Ele verifica se o `seq_no` é maior que o último aceito e valida a tag GCM. Se a autenticação passar, decifra a mensagem e atualiza o contador.

**Cena 8 — ataques da demonstração.** No bitflip, a alteração quebra a tag e o frame é rejeitado. No replay, o contador já foi usado e o frame é rejeitado. No framing inválido, o tamanho absurdo ou o frame truncado encerra a conexão afetada com segurança.

**Limitação para a apresentação.** O porteiro poderia trocar as chaves públicas dos peers e se colocar no meio da comunicação. O projeto não impede esse MITM: Alice e Bruno precisam conferir seus fingerprints por um canal confiável.

### Onde entram as etapas 0 e 1

**Etapa 0 — o brasão e a planta do prédio.** `server.key` é a chave privada de assinatura do porteiro e só o servidor deve usá-la. `server.crt` é o certificado público pinado que os clientes conferem na cena 2. O cliente deve carregar apenas o certificado; se acessar a chave privada, o modelo de segurança perde o sentido. A estrutura de pastas organiza a planta: `common/` guarda componentes compartilhados e `server/` e `client/` guardam os componentes de cada lado.

**Etapa 1 — os envelopes padronizados.** TCP é um fluxo contínuo de bytes sem fronteiras de mensagem. O prefixo de quatro bytes informa quantos bytes vêm no frame; o byte de tipo identifica se é `HELLO`, `E2E` ou outro tipo. `MAX_FRAME` limita o tamanho aceito para evitar alocações excessivas com comprimentos maliciosos. Esta etapa entrega o sistema de transporte dos envelopes, sem criptografia. Na história, todas as mensagens passam por `send_frame` e `recv_frame`; sem framing não há troca confiável para as etapas seguintes.

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

## [x] Etapa 0: Setup e certificado

**Objetivo:** ambiente pronto e certificado RSA gerado.

**Na história:** é a cena 0, o brasão e a planta do prédio. O certificado público é copiado para os clientes fixarem; a chave privada fica só no servidor para assinar handshakes. A estrutura separa componentes comuns, servidor e cliente.

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

## [x] Etapa 1: Framing TCP

**Objetivo:** enviar e receber frames delimitados, com tratamento de erro.

**Na história:** é o correio e seus envelopes padronizados. O prefixo marca o fim de cada carta e o byte de tipo informa que mensagem ela carrega. Esta etapa transporta bytes confiavelmente, mas ainda não cifra nem autentica nada.

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

## [x] Etapa 2: Módulo de criptografia

**Objetivo:** funções puras e testadas, sem rede.

**Na história:** prepara as tintas e os lacres que Alice e Bruno usarão depois: X25519/ECDH, HKDF, AES-GCM, nonces, AAD e fingerprints. Sozinha, esta etapa não conecta clientes nem envia mensagens.

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

## [x] Etapa 3: Handshake autenticado (cliente ↔ servidor)

**Objetivo:** cliente confirma que está falando com o servidor legítimo.

**Na história:** são as cenas 1 e 2. Alice envia `HELLO`; o servidor responde com sua chave efêmera assinada. O cliente valida o certificado pinado e a assinatura antes de confiar no servidor. Aqui ainda não há rendezvous nem mensagens entre peers.

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

## [x] Etapa 4: Canal administrativo e tabela `sessions`

**Objetivo:** mensagens do servidor com confidencialidade, integridade e anti-replay.

**Na história:** é a cena 3, o interfone privado entre Alice e o servidor. Eles derivam `C2S` e `S2C`, protegem mensagens administrativas com AES-GCM e registram a sessão. Esse canal não é o canal E2E entre Alice e Bruno.

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

## [x] Etapa 5: Rendezvous (distribuição de chaves públicas)

**Objetivo:** todos os clientes conhecem as `pk` dos outros.

**Na história:** é a cena 4. Quando Bruno chega, o servidor avisa ambos pelo interfone e entrega a cada um a chave pública e o salt do outro. O servidor distribui esses dados, mas ainda não deriva as chaves E2E.

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

## [x] Etapa 6: Derivação das chaves E2E (tabela `peers`)

**Objetivo:** A e B chegam nas mesmas chaves sem o servidor participar.

**Na história:** é a cena 5. Alice e Bruno calculam `Z_AB` localmente e derivam `A2B` e `B2A` com o mesmo salt de par ordenado pelos IDs. A partir daqui cada cliente mantém suas chaves e contadores por peer; o servidor não conhece essas chaves.

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

## [x] Etapa 7: Mensagem E2E e relay

**Objetivo:** A manda para B, o servidor só repassa.

**Na história:** são as cenas 6 e 7. Alice cifra “oi”, inclui nonce, IDs e sequência no frame, e o servidor o encaminha ao Bruno sem alterar os bytes. Bruno valida remetente, sequência e tag antes de decifrar.

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

## [x] Etapa 8: Ataques e rejeições (os 4 testes obrigatórios)

**Objetivo:** demonstrar proteção contra adulteração e replay.

**Na história:** é a cena 8. A demo mostra que bitflip quebra a tag, replay é barrado pelo contador e framing inválido encerra a conexão afetada. Esta etapa demonstra as rejeições e a recuperação, sem introduzir um novo mecanismo criptográfico.

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

## [ ] Etapa 9: Reconexão, logs, documentação e demo

**Objetivo:** fechar os requisitos operacionais e a apresentação.

**Na história:** prepara a apresentação completa: reconexões criam sessões e chaves novas; logs evitam expor segredos; documentação e demo ajudam a explicar as cenas e a limitação de MITM entre peers.

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
