import asyncio
import struct
import unittest

from common.framing import MAX_FRAME, recv_frame, send_frame
from server.server import handle_client


class MemoryWriter:
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        pass

    def get_extra_info(self, name):
        return ("memory", 0) if name == "peername" else None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def make_reader(data: bytes, *, eof: bool = True) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    if eof:
        reader.feed_eof()
    return reader


class FramingTests(unittest.IsolatedAsyncioTestCase):
    async def test_send_and_receive_roundtrip(self):
        writer = MemoryWriter()
        await send_frame(writer, 0x7F, b"mensagem")
        reader = make_reader(bytes(writer.data))

        self.assertEqual(await recv_frame(reader), (0x7F, b"mensagem"))

    async def test_two_client_handlers_can_echo_concurrently(self):
        readers = [make_reader(b"\x00\x00\x00\x06\x01Alice"), make_reader(b"\x00\x00\x00\x06\x05Bruno")]
        writers = [MemoryWriter(), MemoryWriter()]
        await asyncio.gather(
            handle_client(readers[0], writers[0]),
            handle_client(readers[1], writers[1]),
        )

        echoed = []
        for writer in writers:
            echoed_reader = make_reader(bytes(writer.data))
            echoed.append(await recv_frame(echoed_reader))
            self.assertTrue(writer.closed)
        self.assertEqual(echoed, [(0x01, b"Alice"), (0x05, b"Bruno")])

    async def test_oversized_length_closes_connection(self):
        reader = make_reader(struct.pack("!I", MAX_FRAME + 1))
        writer = MemoryWriter()

        await handle_client(reader, writer)

        self.assertTrue(writer.closed)
        self.assertEqual(writer.data, b"")

    async def test_truncated_frame_closes_connection_without_crashing_handler(self):
        reader = make_reader(struct.pack("!I", 5) + b"\x01ab")
        writer = MemoryWriter()

        await handle_client(reader, writer)

        self.assertTrue(writer.closed)
        self.assertEqual(writer.data, b"")


if __name__ == "__main__":
    unittest.main()
