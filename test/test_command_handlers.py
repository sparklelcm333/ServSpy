import builtins
import io
from types import SimpleNamespace

import src.command_control_extension_tcp as ctl


def test_command_handler_parsing(server):
    """Verify server parses /command and forwards to the target client socket.

    NOTE: we force the server.running flag here because tests construct the
    server via a fixture with is_extend_command=True (no background loop).
    FIXME: prefer a test-friendly public API to start/mark the server running.
    """
    server.running = True

    class DummySocket:
        def __init__(self):
            self.data = b""

        def sendall(self, b):
            self.data += b

    client_addr = ("127.0.0.1", 12345)
    dummy = DummySocket()

    # populate only the fields used by the handler
    server.clients[client_addr] = {
        "socket": dummy,
        "address": client_addr,
        "connected_time": "now",
    }

    # craft command: /command <cmd> (<client_addr>)
    # wrap the tuple in quotes so the handler's parser (shlex.split) treats it as one token
    # and ast.literal_eval inside the handler can parse it
    cmd = "/command echo_test \"('127.0.0.1', 12345)\""

    ctl._command_handler(None, ("127.0.0.1", 9999), cmd)

    assert dummy.data != b""
    sent = dummy.data.decode("utf-8")
    assert "/command" in sent
    assert "echo_test" in sent
    assert "127.0.0.1" in sent


def test_command_handler_server_setup_triggers_file_transfer(server_client, monkeypatch):
    """Verify server-side setup handler runs the command and triggers file transfer + /command_done."""
    server, client = server_client

    # Intercept writes to prevent tests creating log files on disk.
    # Minimal, deterministic strategy: for any write/append/create open
    # return an in-memory stream; keep other opens unchanged. Also avoid
    # directory creation by making makedirs a no-op.
    orig_open = builtins.open

    def dummy_open(path, mode="r", *a, **kw):
        if any(m in mode for m in ("w", "a", "x")):
            return io.StringIO()
        return orig_open(path, mode, *a, **kw)

    monkeypatch.setattr(builtins, "open", dummy_open)
    monkeypatch.setattr(ctl.os, "makedirs", lambda *a, **k: None)

    # mock subprocess.run to avoid executing real commands
    monkeypatch.setattr(ctl.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout="out", stderr="", returncode=0))

    calls = {}

    def fake_file_transfer(message, file_folder_abspath=None):
        calls["file_transfer"] = message

    def fake_send_message(client_socket, message):
        calls.setdefault("sent", []).append(message)

    monkeypatch.setattr(client, "file_transfer_client_recv_client_start", fake_file_transfer)
    monkeypatch.setattr(client, "send_message", fake_send_message)

    # construct command that _command_handler_server_setup expects
    # format: /command <command> <total_num> <client_id> <client_addr>
    cmd = "/command echo 1 0 ('127.0.0.1', 12345)"

    ctl._command_handler_server_setup(None, ("127.0.0.1", 9999), cmd)

    assert "file_transfer" in calls
    assert any("/command_done" in m for m in calls.get("sent", []))
