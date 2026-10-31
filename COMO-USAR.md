# Como usar o TP3

Os comandos abaixo supõem Linux/macOS ou um terminal compatível com shell e
são executados na raiz deste repositório. Para demonstração com processos
separados, mantenha um terminal aberto para o servidor e abra **um terminal
novo para cada cliente**.

## 1. Preparar o ambiente

```sh
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

O servidor precisa de `certs/server.key` (privada, não versionar) e
`certs/server.crt` (certificado público). Se ainda não tiver um par local,
gere-o e atualize a cópia que o cliente fixa:

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/server.key -out certs/server.crt -days 365 \
  -subj "/CN=tp3-server"
cp certs/server.crt client/certs/server.crt
```

Gere a chave no ambiente local e nunca a envie ao Git. Se o certificado mudar,
atualize também `client/certs/server.crt`, ou o cliente recusará o servidor.

## 2. Servidor e clientes em terminais separados

### Terminal 1: iniciar o servidor

Na raiz do repositório:

```sh
python -m server.handshake_server \
  --host 127.0.0.1 --port 8766 \
  --cert certs/server.crt --key certs/server.key \
  --max-connections 100
```

O servidor permanece em execução nesse terminal. Os argumentos são opcionais;
estes são os padrões:

| Argumento | Padrão | Função |
|---|---:|---|
| `--host` | `127.0.0.1` | Endereço de escuta do relay. |
| `--port` | `8766` | Porta TCP do relay. |
| `--cert` | `certs/server.crt` | Certificado público enviado no handshake. |
| `--key` | `certs/server.key` | Chave RSA privada usada para assinar o handshake. |
| `--max-connections` | `100` | Limite de conexões simultâneas aceitas. |

### Terminal 2: conectar Alice

Abra outro terminal, entre na raiz do repositório, ative o ambiente virtual e execute:

```sh
source .venv/bin/activate
python -m client.client \
  --host 127.0.0.1 --port 8766 \
  --pin client/certs/server.crt
```

### Terminal 3: conectar Bruno

Abra mais um terminal e execute o mesmo comando do cliente. Cada processo cria
seu próprio UUID e suas chaves efêmeras. Para Carla ou outros participantes,
abra um terminal por cliente adicional.

Opções do cliente:

| Argumento | Padrão | Função |
|---|---|---|
| `--host` | `127.0.0.1` | Endereço do servidor. |
| `--port` | `8766` | Porta do servidor. |
| `--pin` | `client/certs/server.crt` | Certificado pinado que será comparado com o recebido. |
| `--attack bitflip` | Desativado | Altera um bit da tag de cada frame E2E enviado por esse cliente. |
| `--attack replay` | Desativado | Reenvia cada frame E2E enviado por esse cliente. |

Use `python -m server.handshake_server --help` e
`python -m client.client --help` para exibir as opções no terminal.

### Servidor de eco antigo da etapa de framing (opcional)

O comando abaixo inicia somente um servidor de eco TCP para testar envelopes da
etapa 1. Ele **não** executa handshake, rendezvous ou mensageria E2E; para o
sistema completo, use `server.handshake_server` acima.

```sh
python -m server.server --host 127.0.0.1 --port 8765
```

Opções: `--host` (padrão `127.0.0.1`) e `--port` (padrão `8765`).
`python -m server.server --help` lista essas opções.

## 3. Enviar mensagens e observar ataques

Depois de Alice e Bruno aparecerem como peers e exibirem fingerprints, envie no
terminal do remetente:

```text
/to <id_ou_prefixo> mensagem
```

Use o UUID completo ou um prefixo sem ambiguidade que apareceu na lista de
peers. Por exemplo, substitua o marcador pelo prefixo real de Bruno:

```text
/to a1b2c3d4 Oi, Bruno!
```

O modo padrão envia a mensagem sem alteração. Para demonstrar bitflip ou
replay, encerre aquele processo de cliente com `Ctrl-C` e reinicie-o com uma
das opções:

```sh
python -m client.client --attack bitflip
```

ou:

```sh
python -m client.client --attack replay
```

Os argumentos de host, porta e pin podem ser incluídos como no exemplo anterior.
O ataque selecionado vale para todos os frames E2E enviados por aquele processo;
reinicie o cliente sem `--attack` para voltar ao modo normal. O cliente que
recebe deve registrar a rejeição e continuar conectado. `Ctrl-C` encerra o
cliente; o servidor remove a sessão e notifica os outros com `PEER_LEFT`.

## 4. Laboratório web de estudo

O laboratório ilustra o fluxo com delay visual e permite controlar o relay e os
clientes pela página. Inicie-o em um terminal:

```sh
source .venv/bin/activate
python -m web.app
```

Abra no navegador o endereço informado pelo terminal, normalmente
`http://127.0.0.1:8080`. Se essa porta estiver ocupada, o laboratório tenta as
próximas 20 portas. Também é possível informar uma porta inicial:

```sh
python -m web.app --port 8090
```

Opções web: `--host` (padrão `127.0.0.1`), `--port` (padrão `8080`) e
`--fallback-ports` (padrão `20`). Use `python -m web.app --help` para detalhes.
Na página:

1. Clique **Iniciar servidor**.
2. Crie Alice e Bruno com o botão **+ Cliente**; eles executam handshake e
   rendezvous reais em conexões TCP locais.
3. Acompanhe o diagrama e ajuste o controle **Delay** para desacelerar a
   apresentação dos eventos. O delay só controla a visualização.
4. Escolha remetente e destinatário, digite uma mensagem e selecione **Normal**,
   **Bitflip** ou **Replay** antes de enviar.
5. Use **Enviar tamanho inválido** para mostrar a desconexão segura; use o
   botão `×` de um cliente para visualizar a remoção de sessão e o `PEER_LEFT`.
6. Clique **Parar servidor** ao terminar.

O laboratório gera certificado e chave RSA em memória e não precisa da chave
privada de `certs/server.key`. Ele hospeda clientes e relay no mesmo processo
Python por conveniência de estudo; para demonstrar isolamento entre processos,
use os terminais da seção anterior.

### Estudar por bloco

- **Se ficou com o Bloco 1:** inicie o laboratório, crie Alice e Bruno e
  acompanhe os eventos de `HELLO`, `SERVER_HELLO`, verificação do pin e canal
  administrativo. Abra
  `server/handshake_server.py`, `client/client.py`,
  `common/admin.py` e `common/e2e.py` nos métodos listados em
  [BLOCOS.md](BLOCOS.md).
- **Se ficou com o Bloco 2:** crie um terceiro cliente e acompanhe os eventos
  `PEER_INFO` e “Chaves E2E prontas”; confira os fingerprints sem copiar chaves
  secretas. Desconecte um peer para ver `PEER_LEFT`. Revise
  `common/peer.py`, `common/protocol.py` e os testes indicados em
  [BLOCOS.md](BLOCOS.md).
- **Se ficou com o Bloco 3:** escolha Alice e Bruno no painel e envie uma
  mensagem normal em cada direção. Observe o evento de relay e o plaintext
  exibido apenas após a recepção. Para conferir o limite de 4096 bytes e os
  campos do AAD, leia `send_e2e`, `receive_e2e` e
  `tests/test_e2e.py`/`test_attacks.py`, listados em [BLOCOS.md](BLOCOS.md).
- **Se ficou com o Bloco 4:** inicie o servidor CLI com
  `--max-connections 1` e tente conectar dois clientes em terminais separados;
  observe a rejeição no terminal do servidor. Na interface, envie uma
  mensagem com bitflip ou replay, depois selecione **Normal** e envie outra;
  use também o botão de framing inválido. Para reconexão do mesmo `client_id`,
  rode o teste isolado abaixo; a CLI gera um UUID novo em cada execução.
- **Reconexão com o mesmo `client_id`:** essa condição é coberta pelo teste
  `test_reconnect_replaces_session_and_peers_get_fresh_material`; a CLI cria um
  UUID novo a cada execução. Para estudar o teste isolado:

  ```sh
  python -m pytest -q tests/test_rendezvous.py -k reconnect
  ```

## 5. Demo automatizada e suíte de testes

Na raiz do repositório, com o ambiente virtual ativo:

```sh
python scripts/demo.py
```

O script mostra a troca normal, bitflip, replay, recuperação e framing
inválido. Ele executa os handlers reais sobre streams locais em memória; não
abre terminais/processos nem sockets TCP.

Execute a suíte completa:

```sh
python -m pytest -q
```

Todos os testes por arquivo podem ser selecionados, por exemplo:

```sh
python -m pytest -q tests/test_handshake.py
python -m pytest -q tests/test_admin.py
python -m pytest -q tests/test_peer_derivation.py tests/test_rendezvous.py
python -m pytest -q tests/test_e2e.py tests/test_attacks.py
python -m pytest -q tests/test_framing.py tests/test_crypto.py
```

Ao final, encerre cada cliente com `Ctrl-C` e o servidor com `Ctrl-C`. A chave
privada `certs/server.key` é local e ignorada pelo Git; nunca a adicione ao
repositório.
