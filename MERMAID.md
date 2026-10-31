# Diagramas de sequência do TP3

Os diagramas seguem os quatro blocos de [BLOCOS.md](BLOCOS.md) e o fluxo
detalhado do protocolo. Campos secretos são representados como operações
locais; nunca são enviados nos frames.

## Bloco 1 — Entrada, identidade e canal administrativo

```mermaid
sequenceDiagram
    autonumber
    actor A as Alice
    participant C as Cliente
    participant F as Framing TCP
    participant S as Servidor
    participant R as Certificado RSA

    Note over S,R: Servidor tem server.key; cliente fixa somente server.crt
    A->>C: Iniciar cliente
    C->>C: Gera client_id e par X25519 efêmero sk_C/pk_C
    C->>F: HELLO(client_id, pk_C)
    F->>S: Frame delimitado HELLO
    S->>S: Gera par X25519 efêmero sk_S/pk_S e salt_srv
    S->>S: H = SHA256(pk_S || pk_C || client_id || salt_srv)
    S->>R: RSA-PSS assina H com SHA-256/Prehashed
    R-->>S: Assinatura
    S->>F: SERVER_HELLO(pk_S, salt_srv, assinatura, cert DER)
    F->>C: Frame delimitado SERVER_HELLO
    C->>C: Compara cert DER com o pin local
    C->>C: Verifica assinatura RSA-PSS sobre o transcript
    alt Certificado ou assinatura inválidos
        C->>F: Fecha a conexão
    else Servidor autenticado
        C->>C: Z_CS = ECDH(sk_C, pk_S)
        C->>C: HKDF-SHA256 deriva C2S e S2C
        S->>S: Registra sessão e contadores administrativos
        S->>S: Z_CS = ECDH(sk_S, pk_C); deriva C2S e S2C
        S->>F: ERROR de confirmação cifrado com AES-128-GCM, seq=0
        F->>C: Frame administrativo autenticado
        C->>C: Decifra e autentica a confirmação
        Note over C,S: C2S e S2C são chaves diferentes; nonce e tipo/seq entram no protocolo
    end
```

## Bloco 2 — Rendezvous e derivação das chaves entre peers

```mermaid
sequenceDiagram
    autonumber
    actor A as Alice
    participant SA as Cliente Alice
    participant S as Servidor relay
    participant SB as Cliente Bruno
    actor B as Bruno

    Note over SA,S: Alice já está registrada e autenticada
    B->>SB: Inicia cliente
    SB->>S: HELLO e handshake autenticado
    S->>S: Registra Bruno em sessions
    S-->>SA: PEER_INFO cifrado no canal administrativo (ID_B, pk_B, salt_B)
    S-->>SB: PEER_INFO cifrado no canal administrativo (ID_A, pk_A, salt_A)
    SA->>SA: Z_AB = ECDH(sk_A, pk_B)
    SB->>SB: Z_AB = ECDH(sk_B, pk_A)
    SA->>SA: salt_par = SHA256(salt_menor_ID || salt_maior_ID)[:16]
    SB->>SB: Calcula o mesmo salt_par usando a ordem dos IDs
    SA->>SA: HKDF-SHA256(Z_AB, salt_par) deriva A2B e B2A
    SB->>SB: Deriva as mesmas chaves direcionais; descarta Z_AB
    Note over SA,SB: O servidor distribui pk/salt, mas não conhece Z_AB nem as chaves E2E
    Note over SA,SB: Fingerprints SHA256(pk)[:8] podem ser comparados por canal confiável
    B->>SB: Desconecta
    SB->>S: TCP fecha
    S->>S: Remove a sessão de Bruno
    S-->>SA: PEER_LEFT cifrado no canal administrativo
    SA->>SA: Remove metadados e chaves locais de Bruno
```

## Bloco 3 — Mensagem E2E: envio, relay e recepção

```mermaid
sequenceDiagram
    autonumber
    actor A as Alice
    participant CA as Cliente Alice
    participant S as Servidor relay
    participant CB as Cliente Bruno
    actor B as Bruno

    A->>CA: /to ID_B mensagem
    CA->>CA: seq = seq_send; nonce = IV_base(4B) || seq(8B BE)
    CA->>CA: AAD = ID_A || ID_B || seq
    CA->>CA: AES-128-GCM cifra com A2B; produz ciphertext || tag
    CA->>S: E2E(nonce, ID_A, ID_B, seq, ciphertext || tag)
    S->>S: Valida formato/remetente e procura recipient_id
    Note over S: Sem key_send/key_recv E2E; não decifra nem verifica tag
    S->>CB: Encaminha o mesmo payload E2E sem alteração
    CB->>CB: Confirma ID_A conhecido, ID_B correto e seq > seq_recv
    CB->>CB: AES-GCM valida tag com A2B como chave de recepção
    alt Tag válida
        CB->>CB: Atualiza seq_recv somente depois da autenticação
        CB-->>B: Exibe plaintext decifrado
    else Tag inválida ou endereço incorreto
        CB->>CB: Rejeita frame; não avança seq_recv
    end
    Note over CA,CB: O sentido B→A usa B2A para enviar e Alice recebe com B2A
```

## Bloco 4 — Ataques, recuperação e operação

```mermaid
sequenceDiagram
    autonumber
    actor A as Alice
    participant CA as Cliente Alice
    participant S as Servidor
    participant CB as Cliente Bruno
    actor B as Bruno

    A->>CA: Envia mensagem de demonstração (bitflip)
    CA->>CA: Cifra E2E e altera um bit da tag
    CA->>S: Frame E2E sintaticamente válido, tag adulterada
    S->>CB: Encaminha bytes opacos
    CB->>CB: AES-GCM rejeita tag; seq_recv não avança
    Note over CB,S: A conexão continua aberta
    A->>CA: Envia mensagem legítima seguinte
    CA->>S: Frame E2E com sequência seguinte
    S->>CB: Relay intacto
    CB->>CB: Tag válida; autentica, decifra e avança seq_recv

    A->>CA: Envia mensagem (modo replay)
    CA->>S: Frame E2E com seq=N
    S->>CB: Relay do primeiro frame
    CB->>CB: Aceita tag e atualiza seq_recv=N
    CA->>S: Reenvia exatamente o frame com seq=N
    S->>CB: Relay do frame repetido
    CB->>CB: Rejeita seq <= seq_recv antes de decifrar

    A->>S: Envia prefixo de tamanho maior que MAX_FRAME ou frame truncado
    S->>S: FrameError/IncompleteReadError
    S-xA: Fecha somente a conexão afetada

    B->>CB: Reconecta usando o mesmo client_id
    CB->>S: Novo HELLO, nova chave X25519 e novo salt
    S->>S: Fecha/substitui sessão antiga; contadores novos
    S-->>CA: PEER_INFO atualizado com pk/salt novos
    Note over CA,CB: Logs registram IDs/eventos/motivos, nunca chaves, Z, salts, nonces ou conteúdo
```
