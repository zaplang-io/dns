import dns
import net
import time

def _lookup_socket(str host = "127.0.0.1", int64 port = 0) -> bytes:
    auto sock = net.udp_socket()
    net.udp_bind(sock, host, port)
    net.set_deadline_ns(sock, time.monotonic_ns() + 4000000000)
    return sock

def _resolver_for(bytes socket) -> dns.Resolver:
    return dns.Resolver(nameservers=["127.0.0.1"], port=net.port(socket))

def _sample_rdata(int64 kind) -> dns.Rdata:
    auto name = dns.Name([b"host", b"example", b"test"])
    match kind:
        case 1:
            return dns.Rdata.A("192.0.2.1")
        case 2:
            return dns.Rdata.NS(name)
        case 5:
            return dns.Rdata.CNAME(name)
        case 6:
            return dns.Rdata.SOA(name, name, 7, 10, 20, 30, 40)
        case 12:
            return dns.Rdata.PTR(name)
        case 15:
            return dns.Rdata.MX(10, name)
        case 16:
            return dns.Rdata.TXT([bytes([0, 255]), b"text"])
        case 28:
            return dns.Rdata.AAAA("2001:db8::1")
        case 33:
            return dns.Rdata.SRV(2, 3, 8443, name)
        case _:
            raise ValueError("unexpected fixture record type")

def _typed_responder(bytes socket, int64 count):
    try:
        for index in range(count):
            auto data, host, port = net.recvfrom(socket, 512)
            auto query = dns.Message.from_wire(bytes(data))
            auto question = query.question[0]
            list[dns.Rdata] records = [_sample_rdata(question.rdtype)]
            if question.rdtype == 1:
                records.append(dns.Rdata.A("192.0.2.2"))
            auto rrset = dns.RRset(question.name, 1, question.rdtype, 60, records)
            auto reply = dns.Message(query.id, 0x8180, query.question, [rrset], [], [])
            net.sendto(socket, reply.to_wire(), host, port)
    finally:
        net.close_conn(socket)

@test
def _looks_up_every_tier_one_type_and_iterates_typed_records():
    auto socket = _lookup_socket()
    auto config = _resolver_for(socket)
    auto types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "PTR"]
    auto codes = [1, 28, 5, 15, 16, 2, 6, 33, 12]
    scope:
        spawn _typed_responder(socket, len(types))
        for index in range(len(types)):
            auto result = config.resolve("www.example.test.", rtype=types[index])
            assert result.qname.labels == [b"www", b"example", b"test"]
            assert result.canonical_name.labels == result.qname.labels
            assert result.rrset.rdtype == codes[index] and result.rrset.rdclass == 1
            assert result.ttl == 60
            assert result.nameserver == "127.0.0.1" and result.port == config.port
            assert result.response.answer[0].rdtype == codes[index]

            list[dns.Rdata] records = []
            for record in result:
                records.append(record)
            auto expected_count = 1
            if codes[index] == 1:
                expected_count = 2
                match records[1]:
                    case dns.Rdata.A(address):
                        assert address == "192.0.2.2"
                    case _:
                        assert False
            assert len(records) == expected_count
            auto rr = dns.RRset(
                result.qname,
                1,
                codes[index],
                60,
                [_sample_rdata(codes[index])],
            )
            auto actual = dns.RRset(result.qname, 1, codes[index], 60, [records[0]])
            auto expected_wire = dns.Message(0, 0x8180, [], [rr], [], []).to_wire()
            assert dns.Message(0, 0x8180, [], [actual], [], []).to_wire() == expected_wire

@test
def _reverse_lookup_uses_absolute_ptr_names():
    auto socket = _lookup_socket()
    auto config = _resolver_for(socket)
    config.search = [dns.Name([b"unused", b"test"])]
    scope:
        spawn _typed_responder(socket, 3)
        auto ipv4 = config.resolve_address("192.0.2.1")
        auto mapped = config.resolve_address(ipaddr="::ffff:192.0.2.1")
        auto ipv6 = config.resolve_address("::1")
        assert ipv4.qname.labels == [b"1", b"2", b"0", b"192", b"in-addr", b"arpa"]
        assert mapped.qname.labels == ipv4.qname.labels
        assert ipv6.qname.labels[0] == b"1"
        assert ipv6.qname.labels[32:] == [b"ip6", b"arpa"]
        for result in [ipv4, mapped, ipv6]:
            assert result.rrset.rdtype == 12
            match result.rrset.items[0]:
                case dns.Rdata.PTR(target):
                    assert target.labels == [b"host", b"example", b"test"]
                case _:
                    assert False

def _search_responder(bytes socket):
    try:
        list[list[bytes]] expected = [
            [b"host"],
            [b"host", b"absent", b"test"],
            [b"host", b"present", b"test"],
            [b"host"],
        ]
        for index in range(len(expected)):
            auto data, host, port = net.recvfrom(socket, 512)
            auto query = dns.Message.from_wire(bytes(data))
            assert query.question[0].name.labels == expected[index]
            auto response = dns.Message(query.id, 0x8183, query.question, [], [], [])
            if index == 2:
                response.flags = 0x8180
                response.answer = [
                    dns.RRset(
                        query.question[0].name,
                        1,
                        1,
                        10,
                        [dns.Rdata.A("192.0.2.1")],
                    ),
                ]
            net.sendto(socket, response.to_wire(), host, port)
    finally:
        net.close_conn(socket)

def _expect_nxdomain(dns.Resolver config, str name, bool search):
    auto caught = False
    try:
        config.resolve(name, search=search)
    except dns.NXDOMAIN:
        caught = True
    assert caught

@test
def _exact_by_default_and_opt_in_search():
    auto socket = _lookup_socket()
    auto config = _resolver_for(socket)
    config.search = [dns.Name([b"absent", b"test"]), dns.Name([b"present", b"test"])]
    scope:
        spawn _search_responder(socket)
        _expect_nxdomain(config, "host", False)
        assert config.resolve("host", search=True).qname.labels == [b"host", b"present", b"test"]
        _expect_nxdomain(config, "host.", True)

def _negative_responder(bytes socket, str mode):
    try:
        auto data, host, port = net.recvfrom(socket, 512)
        auto query = dns.Message.from_wire(bytes(data))
        auto question = query.question[0]
        auto response = dns.Message(query.id, 0x8180, query.question, [], [], [])
        if mode == "servfail":
            response.flags = 0x8182
        if mode == "wrong-type":
            response.answer = [
                dns.RRset(question.name, 1, 16, 60, [dns.Rdata.TXT([b"other"])]),
            ]
        if mode == "malformed":
            auto rr = dns.RRset(question.name, 1, 1, 60, [dns.Rdata.A("192.0.2.1")])
            response.answer = [rr]
            auto wire = response.to_wire()
            net.sendto(socket, wire[:len(wire) - 1], host, port)
            return
        if mode == "oversized":
            auto rr = dns.RRset(
                question.name,
                1,
                65280,
                1,
                [dns.Rdata.Generic(bytes("data"))],
            )
            response.answer = [rr]
            auto wire = response.to_wire()
            for index in range(8):
                wire = wire + wire
            net.sendto(socket, wire, host, port)
            return
        net.sendto(socket, response.to_wire(), host, port)
    finally:
        net.close_conn(socket)

@test
def _lookup_preserves_specific_errors():
    for mode in ["empty", "wrong-type", "servfail", "malformed", "oversized"]:
        auto socket = _lookup_socket()
        auto config = _resolver_for(socket)
        auto observed = ""
        scope:
            spawn _negative_responder(socket, mode)
            try:
                config.resolve("host.example.test", "A")
            except dns.NoAnswer:
                observed = "noanswer"
            except dns.ServFail:
                observed = "servfail"
            except dns.WireFormatError:
                observed = "wire"
        if mode == "empty" or mode == "wrong-type":
            assert observed == "noanswer"
        elif mode == "servfail":
            assert observed == "servfail"
        else:
            assert observed == "wire"

@test
def _tries_next_nameserver_and_honors_the_total_deadline():
    auto first = _lookup_socket("127.0.0.1")
    auto second = _lookup_socket("127.0.0.2", net.port(first))
    auto config = dns.Resolver(
        nameservers=["127.0.0.1", "127.0.0.2"],
        timeout=0.1,
        lifetime=1.0,
        port=net.port(first),
    )
    try:
        scope:
            spawn _typed_responder(second, 1)
            auto result = config.resolve("host.example.test")
            assert result.nameserver == "127.0.0.2"
    finally:
        net.close_conn(first)

    auto silent = _lookup_socket()
    try:
        auto bounded = dns.Resolver(
            nameservers=["127.0.0.1"],
            timeout=2.0,
            lifetime=0.02,
            port=net.port(silent),
        )
        auto caught = False
        try:
            bounded.resolve("host.example.test")
        except dns.Timeout:
            caught = True
        assert caught
    finally:
        net.close_conn(silent)
