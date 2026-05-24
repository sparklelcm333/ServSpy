import importlib.util
import os
import sys

import pytest

# Only add project root to sys.path if src package is not importable
if importlib.util.find_spec("src") is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import src.command_control_extension_tcp as ctl
from src.connect_tcp import TCP_Client_Base, TCP_Server_Base

SERVER_PORT = 65001
CLIENT_PORT = 65000
SERVER2_PORT = 65002
CLIENT2_PORT = 65003


@pytest.fixture
def server(monkeypatch):
    """Create a TCP_Server_Base and inject into command_control_extension_tcp.server_instance.

    Use this fixture when a test only needs a server instance.
    """
    s = TCP_Server_Base(host="127.0.0.1", port=SERVER_PORT, is_extend_command=True)
    monkeypatch.setattr(ctl, "server_instance", s)
    try:
        yield s
    finally:
        s.stop()


@pytest.fixture
def client(monkeypatch):
    """Create a TCP_Client_Base and inject into command_control_extension_tcp.client_instance.

    Use this fixture when a test only needs a client instance.
    """
    c = TCP_Client_Base(host="127.0.0.1", port=CLIENT_PORT, client_host="127.0.0.1", is_extend_command=True)
    monkeypatch.setattr(ctl, "client_instance", c)
    try:
        yield c
    finally:
        c.close()


@pytest.fixture
def server_client(monkeypatch):
    """Create both server and client and inject both module globals.

    Use this when a test requires both sides present.
    """
    s = TCP_Server_Base(host="127.0.0.1", port=SERVER2_PORT, is_extend_command=True)
    c = TCP_Client_Base(host="127.0.0.1", port=CLIENT2_PORT, client_host="127.0.0.1", is_extend_command=True)
    monkeypatch.setattr(ctl, "server_instance", s)
    monkeypatch.setattr(ctl, "client_instance", c)
    try:
        yield s, c
    finally:
        try:
            c.close()
        finally:
            s.stop()
