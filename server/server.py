"""Temporary TCP echo server used to develop and demonstrate framing."""

from __future__ import annotations

import argparse
import asyncio
import logging

from asyncio import IncompleteReadError, StreamReader, StreamWriter

from common.framing import FrameError, recv_frame, send_frame

logger = logging.getLogger("tp3.echo_server")


async def handle_client(reader: StreamReader, writer: StreamWriter) -> None:
    """Echo complete frames until the peer disconnects or sends an invalid one."""
    peer = writer.get_extra_info("peername")
    logger.info("conexão aceita: %s", peer)

    try:
        while True:
            frame_type, payload = await recv_frame(reader)
            await send_frame(writer, frame_type, payload)
    except IncompleteReadError as exc:
        if exc.partial:
            logger.info("frame truncado; fechando conexão: %s", peer)
    except FrameError as exc:
        logger.info("frame inválido (%s); fechando conexão: %s", exc, peer)
    except (ConnectionError, OSError) as exc:
        logger.info("conexão encerrada (%s): %s", exc, peer)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        logger.info("conexão fechada: %s", peer)


async def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Run the concurrent echo server until interrupted."""
    server = await asyncio.start_server(handle_client, host, port)
    addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    logger.info("servidor de eco ouvindo em %s", addresses)

    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Servidor de eco TCP para a etapa 1 do TP3")
    parser.add_argument("--host", default="127.0.0.1", help="endereço de escuta (padrão: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="porta TCP (padrão: 8765)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(serve(args.host, args.port))
    except KeyboardInterrupt:
        logger.info("servidor interrompido")


if __name__ == "__main__":
    main()
