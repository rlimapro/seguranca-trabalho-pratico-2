# Blocos para a apresentação do TP3

O conteúdo está dividido em quatro blocos consecutivos. A ordem acompanha o
protocolo, e as transições mostram como uma parte prepara a seguinte. A união
dos blocos cobre o sistema inteiro, os critérios de avaliação, a demonstração
e as limitações.

Uma divisão sugerida para a dupla é **Pessoa 1: blocos 1 e 3** e **Pessoa 2:
blocos 2 e 4**. Assim, cada pessoa fala em dois momentos, e a apresentação pode
seguir a ordem do fluxo sem interromper a história. Se preferirem, escolham os
blocos de acordo com o interesse, garantindo que todos sejam apresentados.

## Bloco 1 — Entrada, identidade e canal administrativo

### O que contempla

- Cena 0: certificado público pinado nos clientes e chave privada RSA mantida
  apenas pelo servidor.
- Envelopes TCP: `tamanho(4B BE) | tipo(1B) | payload`; o limite
  `MAX_FRAME` rejeita tamanhos inválidos antes de processar o corpo.
- Cenas 1–2: o cliente gera um par X25519 efêmero e envia `HELLO`. O servidor
  gera `pk_S` e `salt_srv`, assina o transcript e responde com
  `SERVER_HELLO`. O cliente compara o certificado pinado e verifica a
  assinatura antes de aceitar o servidor.
- Cena 3: ECDH cliente-servidor produz `Z_CS`; HKDF deriva chaves separadas
  `C2S` e `S2C`. A confirmação de registro e as mensagens administrativas são
  cifradas e numeradas. O servidor registra a sessão.

### Criptografia e conceitos

- **RSA-2048+ e certificado X.509:** certificado autoassinado pinado pelo
  cliente; a chave privada não deve ser distribuída.
- **RSA-PSS, MGF1/SHA-256:** assinatura do material do handshake. O digest
  SHA-256 é assinado com `Prehashed(SHA256)`.
- **X25519/ECDH efêmero:** deriva o segredo de sessão cliente-servidor.
- **HKDF-SHA256:** deriva `C2S` e `S2C` com labels distintos.
- **AES-128-GCM (AEAD):** protege o canal administrativo com chaves de 16
  bytes, tag de 16 bytes, nonce e AAD. AES-GCM é o modo; AES-128 indica o
  tamanho da chave usado neste projeto.
- **SHA-256:** participa do digest do handshake e dos fingerprints.
- **Framing TCP:** delimitação e validação dos envelopes; framing não é
  criptografia.

### Código para mostrar

- `common/framing.py`: `send_frame`, `recv_frame`, `MAX_FRAME`.
- `common/protocol.py`: `encode_hello`, `decode_server_hello`,
  `handshake_digest`.
- `common/crypto.py`: `gen_x25519`, `ecdh`, `hkdf_extract_expand`,
  `build_nonce`, `build_aad_admin`, `aes_encrypt`, `aes_decrypt`.
- `common/admin.py`: `AdminChannel.send_admin`,
  `AdminChannel.decode_admin_frame`.
- `server/handshake_server.py`: `load_server_credentials`,
  `create_server_hello`, `perform_server_handshake`,
  `handle_handshake_client`.
- `client/client.py`: `verify_server_hello`,
  `perform_client_handshake`, `establish_admin_channel`.
- Testes relacionados: `tests/test_framing.py`, `test_handshake.py`,
  `test_admin.py`.

### Transição para o bloco 2

Alice e o servidor agora têm uma sessão autenticada e um canal administrativo.
Quando Bruno chega, o servidor pode entregar a cada um os dados públicos do
outro por esse canal. O próximo bloco mostra como isso permite que os próprios
peers estabeleçam as chaves E2E.

## Bloco 2 — Rendezvous e derivação das chaves entre peers

### O que contempla

- Cena 4: o servidor envia `PEER_INFO` cifrado aos clientes conectados,
  contendo o ID, a chave pública e o salt do peer. Na desconexão, envia
  `PEER_LEFT`.
- Cena 5: cada cliente calcula `Z_AB = ECDH(sk_A, pk_B)` localmente. O servidor
  distribui os dados públicos, mas não calcula nem recebe o segredo E2E.
- Como os handshakes de Alice e Bruno geram salts diferentes, cada cliente
  ordena os salts pelos IDs e calcula
  `SHA256(salt_do_menor_id || salt_do_maior_id)[:16]`. Esse salt comum permite
  que ambos obtenham as mesmas chaves.
- HKDF-SHA256 deriva `A2B` e `B2A`. O ID menor define A; as direções usam
  chaves diferentes. `Z_AB` é descartado após a derivação.
- O cliente mostra fingerprint `SHA256(pk)[:8]` para comparação manual.

### Criptografia e conceitos

- **X25519/ECDH:** acordo de chave efêmero entre dois clientes.
- **HKDF-SHA256:** derivação de chaves direcionais AES-128 a partir de `Z_AB`
  e do salt determinístico do par.
- **SHA-256:** combinação dos salts e fingerprints das chaves públicas.
- A comparação do fingerprint por canal confiável reduz o risco de MITM. O
  sistema não autentica peers ponta a ponta: um servidor malicioso ainda pode
  substituir uma chave pública durante o rendezvous.

### Código para mostrar

- `server/handshake_server.py`: trecho de `handle_handshake_client` que
  cria `sessions` e distribui `PEER_INFO`/`PEER_LEFT`.
- `common/protocol.py`: `encode_peer_info`, `decode_peer_info`,
  `encode_peer_left`, `decode_peer_left`.
- `client/client.py`: `apply_peer_event`.
- `common/peer.py`: `derive_peer_session` e o estado por peer.
- `common/crypto.py`: `ecdh`, `hkdf_extract_expand`, `fingerprint`.
- Testes relacionados: `tests/test_peer_derivation.py` e
  `tests/test_rendezvous.py`.

### Transição para o bloco 3

Alice e Bruno já derivaram chaves locais compatíveis. Agora Alice pode cifrar
uma mensagem para Bruno. O servidor precisa apenas do `recipient_id` para
rotear o frame; Bruno valida a sequência e a tag antes de decifrar.

## Bloco 3 — Mensagem E2E: envio, relay e recepção

### O que contempla

- Cena 6: o cliente monta `nonce = IV_base(4B) | seq_no(8B BE)`, usa
  `sender_id | recipient_id | seq_no` como AAD e cifra com `key_send`.
- O frame E2E contém nonce, IDs, sequência e `ciphertext || tag`. O limite de
  plaintext é 4096 bytes.
- O servidor confere remetente/destinatário para roteamento e encaminha os
  bytes do frame sem decifrá-los nem alterá-los. Ele não checa o contador E2E.
- Cena 7: o destinatário exige um remetente conhecido, verifica o destinatário,
  rejeita sequências repetidas e autentica com AES-GCM. Só após a tag válida
  avança `seq_recv` e revela o plaintext.
- As IDs são autenticadas pelo AAD; uma alteração não produz uma mensagem
  válida.

### Criptografia e conceitos

- **AES-128-GCM:** cifragem autenticada; ciphertext e tag são transmitidos
  juntos.
- **Nonce único por chave/direção:** prefixo aleatório de 4 bytes mais contador
  monotônico de 8 bytes. Nunca reutilizar a sequência com a mesma chave.
- **AAD:** autentica IDs e sequência sem cifrá-los.
- **Anti-replay:** comparação de sequência antes da abertura e atualização do
  estado somente depois da autenticação.

### Código para mostrar

- `common/e2e.py`: `send_e2e`, `receive_e2e`,
  `E2EProtocolError`, `E2EReplayError`, `E2EAuthenticationError`.
- `server/handshake_server.py`: `relay_e2e_frame`.
- `client/client.py`: `send_to_peer`, `_receive_messages`.
- `common/crypto.py`: `build_nonce`, `build_aad_e2e`, `aes_encrypt`,
  `aes_decrypt`.
- Testes relacionados: `tests/test_e2e.py` e
  `tests/test_attacks.py`.

### Transição para o bloco 4

O caminho normal da mensagem já funciona. Para completar a demonstração,
tentem adulterar ou repetir um frame e enviem um frame malformado. O bloco
final mostra as rejeições, a recuperação e os cuidados operacionais.

## Bloco 4 — Ataques, recuperação e operação

### O que contempla

- Cena 8: bitflip invalida a tag GCM; replay é rejeitado pelo contador; um
  tamanho acima de `MAX_FRAME` ou um frame truncado fecha somente a conexão
  afetada. Após bitflip/replay, mensagens legítimas seguintes ainda passam.
- Modos de demonstração no cliente: `--attack bitflip` altera a tag e
  `--attack replay` reenvia o mesmo frame. A interface web oferece os mesmos
  modos e um botão para framing inválido.
- Cena 9: reconexão com o mesmo `client_id` invalida a conexão antiga e cria
  nova sessão, chave efêmera, salt, chaves E2E e contadores.
- Logs podem conter IDs, eventos, tamanhos e motivos; não devem conter chaves,
  segredos ECDH, salts, nonces ou conteúdo.
- `--max-connections` limita conexões simultâneas e rejeita uma conexão extra.
- Demonstração e documentação fecham o percurso. A interface web executa o
  relay e clientes no mesmo processo local para facilitar o estudo; use
  terminais separados ao demonstrar processos reais.

### Criptografia e conceitos

- **AES-128-GCM e tag de autenticação:** detectam adulteração do ciphertext,
  nonce ou AAD.
- **Sequência monotônica:** rejeita replay sem avançar após uma falha de tag.
- **Framing:** limites de tamanho e `readexactly` permitem encerrar com
  segurança frames inválidos ou truncados.
- Não há um novo algoritmo nesta etapa; ela demonstra as propriedades dos
  mecanismos já apresentados.

### Código para mostrar

- `client/client.py`: modo `--attack` e rejeições em `_receive_messages`.
- `common/e2e.py`: tipos de erro e atualizações de sequência.
- `server/handshake_server.py`: substituição de sessão,
  `ConnectionLimiter`, logs e cleanup no `finally`.
- `scripts/demo.py`: `run`, demonstração automatizada com três clientes
  sobre streams em memória.
- `web/app.py` e `web/index.html`: laboratório visual e controles.
- `README.md`: comandos, formatos, diagrama e limitações.
- Testes relacionados: `tests/test_attacks.py`, `test_rendezvous.py`.

### Fechamento

Retomem o fluxo completo: o servidor prova sua identidade; Alice e Bruno
estabelecem chaves localmente; o relay só encaminha os bytes E2E; o destinatário
valida antes de decifrar. O projeto oferece confidencialidade, integridade,
anti-replay e autenticação do servidor, mas não impede MITM entre peers sem a
comparação externa de fingerprints.
