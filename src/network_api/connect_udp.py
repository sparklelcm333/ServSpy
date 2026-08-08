import logging
import socket
import threading
import time

logger = logging.getLogger(__name__)

MAX_DATAGRAM = 65535

# Fixed UDP port for service discovery; picked outside the test
# port range (65000-65003) and the default TCP port (65432).
DISCOVERY_PORT = 65004

# Wire-format prefix for discovery announcements.
DISCOVERY_PREFIX = "SERVSPY_DISCOVERY"


class UDP:
    def __init__(self, host="0.0.0.0", port=0):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._socket.bind((host, port))
        self._addr = self._socket.getsockname()
        self._recv_thread = None
        self._closed = False
        self._announce_thread = None

    @property
    def local_addr(self):
        return self._addr

    @property
    def port(self):
        return self._addr[1]

    def send(self, data, addr):
        self._socket.sendto(data, addr)

    def broadcast(self, data, port):
        self.send(data, ("255.255.255.255", port))

    def listen(self, handler):
        if self._closed:
            raise RuntimeError("endpoint is closed")
        if self._recv_thread and self._recv_thread.is_alive():
            return
        self._recv_thread = threading.Thread(target=self._run, args=(handler,), daemon=True)
        self._recv_thread.start()

    def _run(self, handler):
        self._socket.settimeout(0.1)
        while True:
            try:
                data, addr = self._socket.recvfrom(MAX_DATAGRAM)
            except TimeoutError:
                continue
            except OSError:
                if self._closed:
                    return
                raise
            try:
                handler(data, addr)
            except Exception:
                logger.exception(f"handler error from {addr}")

    def announce(self, payload, interval=5.0):
        if self._closed:
            raise RuntimeError("endpoint is closed")
        if self._announce_thread and self._announce_thread.is_alive():
            return
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        self._announce_thread = threading.Thread(
            target=self._announce_loop, args=(payload, interval), daemon=True
        )
        self._announce_thread.start()

    def _announce_loop(self, payload, interval):
        while not self._closed:
            try:
                self.broadcast(payload, DISCOVERY_PORT)
            except OSError:
                if self._closed:
                    return
                raise
            time.sleep(interval)

    def discover(self, timeout=1.0):
        results = []

        def handler(data, addr):
            results.append((addr[0], addr[1], data))

        self.listen(handler)
        time.sleep(timeout)
        return results

    def close(self):
        self._closed = True
        self._socket.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
