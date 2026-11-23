@test
def _resolv_conf_directives():
    auto config = _parse_resolv_conf(
        "# comment\r\n ; another\r\nnameserver\t192.0.2.53 # main\r\n" + "nameserver 2001:db8::53 ; backup\r\n" + "domain legacy.example\r\nsearch old.example\r\n" + "search corp.example lab.example.\r\n" + "domain later.example\r\n" + "options rotate ndots:0 ndots:3\r\noptions ndots:4\r\n",
        1,
    )
    assert config.nameservers == ["192.0.2.53", "2001:db8::53"]
    assert config.ndots == 4
    assert len(config.search) == 2
    assert config.search[0].labels == [b"corp", b"example"]
    assert config.search[1].labels == [b"lab", b"example"]

@test
def _resolv_conf_ignores_malformed_entries():
    auto config = _parse_resolv_conf(
        "nameserver\nnameserver example.test\nnameserver 256.0.0.1\n" + "nameserver 192.0.2.1:53\nnameserver [2001:db8::1]\n" + "nameserver 2001::1::2\n" + "domain good.test\ndomain .bad\nsearch .bad\n" + "options ndots:-1 ndots: ndots:+3 ndots:1x ndots:2.5\n" + "unknown ndots:3\n",
        1,
    )
    assert len(config.nameservers) == 0
    assert config.ndots == 1
    assert len(config.search) == 1
    assert config.search[0].labels == [b"good", b"test"]

    auto mixed = _parse_resolv_conf(
        "search .bad valid.test broken..example root.test.\n" + "search .bad\nnameserver ::ffff:192.0.2.1\n" + "options ndots:007 ndots:999999999999999999999999\n",
        1,
    )
    assert mixed.nameservers == ["::ffff:192.0.2.1"]
    assert mixed.ndots == 15
    assert len(mixed.search) == 2
    assert mixed.search[0].labels == [b"valid", b"test"]
    assert mixed.search[1].labels == [b"root", b"test"]

@test
def _resolv_conf_empty_and_zero_ndots():
    auto config = _parse_resolv_conf(" \t\n# comment\n; comment\n", 2)
    assert len(config.nameservers) == 0
    assert len(config.search) == 0
    assert config.ndots == 2
    assert _parse_resolv_conf("options ndots:0", 2).ndots == 0
    assert _parse_resolv_conf("options ndots:15", 2).ndots == 15
    assert _parse_resolv_conf("options ndots:16", 2).ndots == 15

@test
def _search_order_below_at_and_above_ndots():
    auto search = [Name([b"corp", b"test"]), Name([b"lab", b"test"])]
    auto below = _candidate_names("a.b", search, 2)
    assert len(below) == 3
    assert below[0].labels == [b"a", b"b", b"corp", b"test"]
    assert below[1].labels == [b"a", b"b", b"lab", b"test"]
    assert below[2].labels == [b"a", b"b"]

    auto at = _candidate_names("a.b.c", search, 2)
    assert len(at) == 3
    assert at[0].labels == [b"a", b"b", b"c"]
    assert at[1].labels == [b"a", b"b", b"c", b"corp", b"test"]
    assert at[2].labels == [b"a", b"b", b"c", b"lab", b"test"]

    auto above = _candidate_names("a.b.c.d", search, 2)
    assert len(above) == 3
    assert above[0].labels == [b"a", b"b", b"c", b"d"]

    auto zero = _candidate_names("a", search, 0)
    assert zero[0].labels == [b"a"]
    assert zero[1].labels == [b"a", b"corp", b"test"]

@test
def _search_absolute_escaped_and_empty_suffixes():
    auto search = [Name([b"corp", b"test"])]
    auto target = _candidate_names("a.", search, 3)
    assert len(target) == 1
    assert target[0].labels == [b"a"]

    auto root = _candidate_names(".", search, 3)
    assert len(root) == 1
    assert len(root[0].labels) == 0

    auto escaped = _candidate_names("a\\.b", search, 1)
    assert len(escaped) == 2
    assert escaped[0].labels == [b"a.b", b"corp", b"test"]
    assert escaped[1].labels == [b"a.b"]

    auto escaped_final = _candidate_names("a\\.", search, 1)
    assert len(escaped_final) == 2
    assert escaped_final[0].labels == [b"a.", b"corp", b"test"]

    auto no_search = _candidate_names("a.b", [], 3)
    assert len(no_search) == 1
    assert no_search[0].labels == [b"a", b"b"]

@test
def _search_deduplicates_and_skips_oversized_expansions():
    auto search = [Name([b"Corp", b"test"]), Name([b"corp", b"TEST"]), Name([])]
    auto result = _candidate_names("host", search, 1)
    assert len(result) == 2
    assert result[0].labels == [b"host", b"Corp", b"test"]
    assert result[1].labels == [b"host"]

    auto label = "012345678901234567890123456789012345678901234567890123456789012"
    auto long_name = label + "." + label + "." + label + "." + label[:61]
    auto within_limit = _candidate_names(long_name, search, 15)
    assert len(within_limit) == 1
    assert len(_name_key(within_limit[0], False)) == 255

@test
def _search_rejects_malformed_queries():
    for name in ["", ".a", "a..b", "a\\", "a\\999"]:
        auto caught = False
        try:
            _candidate_names(name, [Name([b"test"])], 1)
        except WireFormatError:
            caught = True
        assert caught

@test
def _resolver_uses_its_search_order_and_fallback_nameservers():
    auto config = Resolver(nameservers=[], search=[Name([b"corp", b"test"])], ndots=2)
    assert config._effective_nameservers() == ["127.0.0.1", "::1"]
    auto candidates = config._qualify("a.b")
    assert candidates[0].labels == [b"a", b"b", b"corp", b"test"]
    assert candidates[1].labels == [b"a", b"b"]
    config.nameservers = ["192.0.2.53"]
    assert config._effective_nameservers() == ["192.0.2.53"]
