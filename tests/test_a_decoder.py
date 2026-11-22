import a_decoder


def test_decode_a_2byte_swap_basic():
    out = a_decoder.decode_a_hidden_ips(["45.156.87.243"], method="2byte_swap")
    assert out == ["87.243.45.156"]


def test_decode_a_2byte_swap_filters_invalid_and_dedups():
    out = a_decoder.decode_a_hidden_ips(
        ["45.156.87.243", "45.156.87.243", "not-an-ip", "1.2.3"],
        method="2byte_swap",
    )
    assert out == ["87.243.45.156"]


def test_decode_a_ipv4_1423_reorders_and_sorts_addresses():
    out = a_decoder.decode_a_hidden_ips(
        ["10.23.45.67", "10.34.56.78", "10.1.2.3"],
        method="ipv4_1423",
    )
    assert out == ["10.3.1.2", "10.67.23.45", "10.78.34.56"]


def test_decode_a_ipv4_1423_filters_invalid_and_dedups():
    out = a_decoder.decode_a_hidden_ips(
        [" 10.1.2.255 ", "10.1.2.255", "10.1.2.256", "::1", "invalid"],
        method="ipv4_1423",
    )
    assert out == ["10.255.1.2"]
