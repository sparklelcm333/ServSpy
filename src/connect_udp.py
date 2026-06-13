import errno
import logging
import socket
import threading

logger = logging.getLogger(__name__)

MAX_DATAGRAM_SIZE = 65535


class UDP:
    def __init__(self, host="0.0.0.0", port=0):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._socket.bind((host, port))
        self._addr = self._socket.getsockname()
        self._stop_event = threading.Event()
        self._recv_thread = None

    @property
    def port(self) -> int:
        return self._addr[1]

    @property
    def local_addr(self) -> tuple[str, int]:
        return self._addr

    def send(self, data, addr):
        self._socket.sendto(data, addr)

    def broadcast(self, data, port):
        self.send(data, ("255.255.255.255", port))

    def serve_forever(self, handler, *, timeout=0.1):
        if self._stop_event.is_set():
            raise RuntimeError("endpoint is closed")
        self._socket.settimeout(timeout)
        while not self._stop_event.is_set():
            try:
                data, addr = self._socket.recvfrom(MAX_DATAGRAM_SIZE)
                try:
                    handler(data, addr)
                except Exception:
                    logger.exception("UDP handler error")
            except TimeoutError:
                continue
            except OSError as e:
                if self._stop_event.is_set():
                    break
                if e.errno in (errno.EBADF, 10038):
                    break
                logger.error("UDP recv error: %s", e)
                raise

    def listen(self, handler):
        if self._recv_thread is not None and self._recv_thread.is_alive():
            return
        if self._stop_event.is_set():
            raise RuntimeError("endpoint is closed")
        self._recv_thread = threading.Thread(
            target=self.serve_forever, args=(handler,), daemon=True,
        )
        self._recv_thread.start()

    def close(self):
        self._stop_event.set()
        try:
            self._socket.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
