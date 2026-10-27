"""Length-prefixed framing helpers for asyncio TCP streams."""

from __future__ import annotations

import struct
from asyncio import StreamReader, StreamWriter

MAX_FRAME = 8 * 1024
_HEADER = struct.Struct("!I")


class FrameError(ValueError):
    """Raised when a frame has an invalid declared length or type."""


async def send_frame(writer: StreamWriter, frame_type: int, payload: bytes) -> None:
    """Write one frame as ``length(4B BE) | type(1B) | payload``.

    The length counts the type byte and payload, but not the four-byte prefix.
    """
    if isinstance(frame_type, bool) or not isinstance(frame_type, int):
        raise TypeError("frame_type must be an integer")
    if not 0 <= frame_type <= 0xFF:
        raise ValueError("frame_type must fit in one byte")
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")

    frame_length = 1 + len(payload)
    if frame_length > MAX_FRAME:
        raise FrameError(f"frame exceeds maximum size ({MAX_FRAME} bytes)")

    writer.write(_HEADER.pack(frame_length) + bytes((frame_type,)) + payload)
    await writer.drain()


async def recv_frame(reader: StreamReader) -> tuple[int, bytes]:
    """Read exactly one frame and return its type and payload.

    ``asyncio.IncompleteReadError`` is propagated when the peer closes in the
    middle of the prefix or frame body. Callers can then close that connection
    without affecting other clients.
    """
    (frame_length,) = _HEADER.unpack(await reader.readexactly(_HEADER.size))
    if frame_length == 0:
        raise FrameError("frame length cannot be zero")
    if frame_length > MAX_FRAME:
        raise FrameError(f"frame exceeds maximum size ({MAX_FRAME} bytes)")

    frame = await reader.readexactly(frame_length)
    return frame[0], frame[1:]
