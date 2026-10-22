from homerouterlab.probe.http_status import is_public_ipv4


def test_private_addresses_rejected() -> None:
    for ip in ("192.168.0.1", "10.0.0.1", "172.16.0.1", "127.0.0.1", "169.254.1.1"):
        assert not is_public_ipv4(ip), ip


def test_shared_space_rejected() -> None:
    assert not is_public_ipv4("100.64.0.1")
    assert not is_public_ipv4("100.127.255.254")


def test_public_addresses_accepted() -> None:
    for ip in ("8.8.8.8", "1.1.1.1", "172.32.0.1", "41.223.10.5"):
        assert is_public_ipv4(ip), ip


def test_invalid_rejected() -> None:
    for ip in ("999.1.1.1", "not-an-ip", ""):
        assert not is_public_ipv4(ip)