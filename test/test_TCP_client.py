from src.connect_tcp import TCP_Client_Base


def test_tcp_client_init():
    client = TCP_Client_Base(host="127.0.0.1", port=65003, client_host="127.0.0.1", is_extend_command=True)
    assert client.host == "127.0.0.1"
    assert client.port == 65003  # noqa: PLR2004
    assert callable(client.connect)
