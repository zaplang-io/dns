import dns
import net
import time

def _cache_server() -> bytes:
    auto socket = net.udp_socket()
    net.udp_bind(socket, "127.0.0.1", 0)
    net.set_deadline_ns(socket, time.monotonic_ns() + 3500000000)
    return socket

def _cache_responder(bytes socket, int64 count, int64 ttl, str mode):
    try:
        for index in range(count):
            auto payload, host, port = net.recvfrom(socket, 512)
            auto query = dns.Message.from_wire(bytes(payload))
            auto question = query.question[0]
            auto reply = dns.Message(query.id, 0x8180, query.question, [], [], [])
            if mode == "servfail":
                if index == 0:
                    reply.flags = 0x8182
            elif mode == "nx" or mode == "nodata" and question.rdtype == 1:
                auto zone = dns.Name([b"example", b"test"])
                reply.authority = [
                    dns.RRset(
                        zone,
                        1,
                        6,
                        ttl,
                        [dns.Rdata.SOA(zone, zone, 1, 2, 3, 4, ttl)],
                    ),
                ]
                if mode == "nx":
                    reply.flags = 0x8183
            elif question.rdtype == 28:
                reply.answer = [
                    dns.RRset(
                        question.name,
                        1,
                        28,
                        ttl,
                        [dns.Rdata.AAAA("2001:db8::1")],
                    ),
                ]
            else:
                reply.answer = [
                    dns.RRset(
                        question.name,
                        1,
                        1,
                        ttl,
                        [dns.Rdata.A("192.0.2." + str(index + 1))],
                    ),
                ]
            net.sendto(socket, reply.to_wire(), host, port)
    finally:
        net.close_conn(socket)

def _cached_ipv4(dns.Answer answer) -> str:
    match answer.rrset.items[0]:
        case dns.Rdata.A(address):
            return address
        case _:
            raise ValueError("unexpected test response")

@test
def _positive_cache_returns_fresh_answers_and_flushes():
    auto socket = _cache_server()
    auto cache = dns.Cache(max_size=2)
    auto config = dns.Resolver(
        nameservers=["127.0.0.1"],
        port=net.port(socket),
        cache=cache,
    )
    scope:
        spawn _cache_responder(socket, 2, 60, "positive")
        auto first = config.resolve("host.example.test")
        assert _cached_ipv4(first) == "192.0.2.1"
        first.rrset.items[0] = dns.Rdata.A("203.0.113.1")
        first.response.flags = 0
        auto second = config.resolve("HOST.example.test.")
        assert _cached_ipv4(second) == "192.0.2.1"
        assert second.response.flags == 0x8180
        assert second.qname.labels[0] == b"HOST"
        cache.flush()
        assert _cached_ipv4(config.resolve("host.example.test")) == "192.0.2.2"

@test
def _default_and_zero_ttl_bypass_storage():
    for enabled in [False, True]:
        auto socket = _cache_server()
        auto config = dns.Resolver(nameservers=["127.0.0.1"], port=net.port(socket))
        assert not config.cache.is_some()
        auto ttl = 60
        if enabled:
            config.cache = dns.Cache()
            assert config.cache.unwrap().max_size == 100000
            ttl = 0
        scope:
            spawn _cache_responder(socket, 2, ttl, "positive")
            assert _cached_ipv4(config.resolve("host.example.test")) == "192.0.2.1"
            assert _cached_ipv4(config.resolve("host.example.test")) == "192.0.2.2"

def _expect_cached_negative(dns.Resolver config, str mnemonic, bool nxdomain):
    auto caught = False
    try:
        config.resolve("host.example.test", mnemonic)
    except dns.NXDOMAIN:
        assert nxdomain
        caught = True
    except dns.NoAnswer:
        assert not nxdomain
        caught = True
    assert caught

@test
def _negative_cache_scope_and_typed_errors():
    for nxdomain in [True, False]:
        auto socket = _cache_server()
        auto config = dns.Resolver(
            nameservers=["127.0.0.1"],
            port=net.port(socket),
            cache=dns.Cache(max_size=2),
        )
        auto mode = "nx"
        auto count = 1
        if not nxdomain:
            mode = "nodata"
            count = 2
        scope:
            spawn _cache_responder(socket, count, 60, mode)
            _expect_cached_negative(config, "A", nxdomain)
            _expect_cached_negative(config, "A", nxdomain)
            if nxdomain:
                _expect_cached_negative(config, "AAAA", True)
            else:
                assert config.resolve("host.example.test", "AAAA").rrset.rdtype == 28

@test
def _servfail_is_not_cached():
    auto socket = _cache_server()
    auto config = dns.Resolver(
        nameservers=["127.0.0.1"],
        port=net.port(socket),
        cache=dns.Cache(),
    )
    scope:
        spawn _cache_responder(socket, 2, 60, "servfail")
        auto caught = False
        try:
            config.resolve("host.example.test")
        except dns.ServFail:
            caught = True
        assert caught
        _expect_cached_negative(config, "A", False)

@test
def _invalid_cache_capacity_is_rejected_before_network():
    for capacity in [0, -1]:
        auto config = dns.Resolver(cache=dns.Cache(max_size=capacity))
        auto caught = False
        try:
            config.resolve("host.example.test")
        except ValueError:
            caught = True
        assert caught
