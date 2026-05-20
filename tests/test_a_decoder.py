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
