import dns

def _empty_message(int64 flags) -> dns.Message:
    return dns.Message(0xbeef, flags, [], [], [], [])

def _example_name() -> dns.Name:
    return dns.Name([b"example", b"test"])

def _one_answer(int64 rdtype, dns.Rdata item) -> dns.Message:
    return dns.Message(
        0x1234,
        0x8180,
        [],
        [dns.RRset(_example_name(), 1, rdtype, 60, [item])],
        [],
        [],
    )

def _packet_with_answer(int64 rdtype, int64 rdlength, bytes data) -> bytes:
    return bytes([0, 0, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, rdtype >> 8, rdtype & 255, 0, 1, 0, 0, 0, 60, rdlength >> 8, rdlength & 255]) + data

def _reject_wire(bytes data):
    auto rejected = False
    try:
        dns.Message.from_wire(data)
    except dns.WireFormatError:
        rejected = True
    assert rejected

def _reject_message(dns.Message message):
    auto rejected = False
    try:
        message.to_wire()
    except dns.WireFormatError:
        rejected = True
    assert rejected

@test
def _header_bits_and_empty_sections():
    for bit in range(16):
        auto flags = 1 << bit
        auto wire = _empty_message(flags).to_wire()
        assert wire == bytes([0xbe, 0xef, flags >> 8, flags & 255, 0, 0, 0, 0, 0, 0, 0, 0])
        auto decoded = dns.Message.from_wire(wire)
        assert decoded.id == 0xbeef
        assert decoded.flags == flags
        assert len(decoded.question) == 0
        assert len(decoded.answer) == 0
        assert len(decoded.authority) == 0
        assert len(decoded.additional) == 0
    assert dns.Message.from_wire(_empty_message(0xffff).to_wire()).flags == 0xffff

@test
def _known_query_and_compressed_response():
    auto expected = bytes([0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]) + b"\x07example\x04test\x00\x00\x05\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x07\x04mail\xc0\x0c"
    auto owner = _example_name()
    auto target = dns.Name([b"mail", b"example", b"test"])
    auto question = dns.RRset(owner, 1, 5, 0, [])
    auto cname = dns.RRset(owner, 1, 5, 60, [dns.Rdata.CNAME(target)])
    auto message = dns.Message(0x1234, 0x8180, [question], [cname], [], [])
    assert message.to_wire() == expected

    auto decoded = dns.Message.from_wire(expected)
    assert decoded.question[0].rdtype == 5
    assert decoded.question[0].rdclass == 1
    assert decoded.question[0].name.labels[0] == b"example"
    assert decoded.answer[0].ttl == 60
    match decoded.answer[0].items[0]:
        case dns.Rdata.CNAME(name):
            assert len(name.labels) == 3
            assert name.labels[0] == b"mail"
            assert name.labels[1] == b"example"
            assert name.labels[2] == b"test"
        case _:
            assert False

@test
def _compression_chains_and_rrsets():
    # The third question points to a name whose suffix is itself a pointer.
    auto head = bytes([0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0])
    auto body = b"\x04test\x00\x00\x01\x00\x01\x04mail\xc0\x0c\x00\x01\x00\x01\xc0\x16\x00\x01\x00\x01"
    auto decoded = dns.Message.from_wire(head + body)
    assert len(decoded.question) == 3
    assert decoded.question[2].name.labels[0] == b"mail"
    assert decoded.question[2].name.labels[1] == b"test"

    auto first = dns.RRset(
        dns.Name([b"Example", b"test"]),
        1,
        16,
        90,
        [dns.Rdata.TXT([b"first"])],
    )
    auto second = dns.RRset(
        _example_name(),
        1,
        16,
        30,
        [dns.Rdata.TXT([b"second"]), dns.Rdata.TXT([b"third"])],
    )
    auto another_class = dns.RRset(
        _example_name(),
        3,
        16,
        40,
        [dns.Rdata.TXT([b"other class"])],
    )
    auto message = dns.Message(9, 0, [], [first, second, another_class], [], [])
    auto wire = message.to_wire()
    assert wire[7] == 4
    auto reread = dns.Message.from_wire(wire)
    assert len(reread.answer) == 2
    assert reread.answer[0].ttl == 30
    assert reread.answer[0].name.labels[0] == b"Example"
    assert len(reread.answer[0].items) == 3
    assert reread.answer[1].rdclass == 3

@test
def _typed_records_and_all_sections():
    auto root = dns.Name([])
    auto owner = _example_name()
    auto target = dns.Name([b"server", b"example", b"test"])
    auto answer = dns.RRset(
        owner,
        1,
        15,
        0xffffffff,
        [dns.Rdata.MX(65535, target), dns.Rdata.MX(0, root)],
    )
    auto ns = dns.RRset(owner, 1, 2, 3600, [dns.Rdata.NS(target)])
    auto soa = dns.RRset(
        owner,
        1,
        6,
        123,
        [dns.Rdata.SOA(target, root, 0xffffffff, 7200, 1800, 86400, 60)],
    )
    auto ptr = dns.RRset(owner, 1, 12, 0, [dns.Rdata.PTR(target)])
    auto txt = dns.RRset(
        owner,
        1,
        16,
        0,
        [dns.Rdata.TXT([b"", b"hello", bytes([0, 255])])],
    )
    auto srv = dns.RRset(owner, 1, 33, 0, [dns.Rdata.SRV(1, 2, 65535, target)])
    auto generic = dns.RRset(
        root,
        1,
        65280,
        0,
        [dns.Rdata.Generic(bytes([0xc0, 0x0c, 0xff]))],
    )
    auto message = dns.Message(
        1,
        0x8180,
        [],
        [answer],
        [ns, soa],
        [ptr, txt, srv, generic],
    )
    auto wire = message.to_wire()
    assert wire[4:12] == bytes([0, 0, 0, 2, 0, 2, 0, 4])
    auto decoded = dns.Message.from_wire(wire)
    assert decoded.to_wire() == wire
    assert decoded.answer[0].ttl == 0xffffffff
    match decoded.answer[0].items[0]:
        case dns.Rdata.MX(preference, exchange):
            assert preference == 65535
            assert exchange.labels[0] == b"server"
        case _:
            assert False
    match decoded.authority[0].items[0]:
        case dns.Rdata.NS(name):
            assert name.labels[0] == b"server"
        case _:
            assert False
    match decoded.authority[1].items[0]:
        case dns.Rdata.SOA(mname, rname, serial, refresh, retry, expire, minimum):
            assert mname.labels[2] == b"test"
            assert len(rname.labels) == 0
            assert serial == 0xffffffff
            assert refresh == 7200 and retry == 1800 and expire == 86400 and minimum == 60
        case _:
            assert False
    match decoded.additional[0].items[0]:
        case dns.Rdata.PTR(name):
            assert name.labels[0] == b"server"
        case _:
            assert False
    match decoded.additional[1].items[0]:
        case dns.Rdata.TXT(strings):
            assert len(strings) == 3
            assert strings[0] == b""
            assert strings[1] == b"hello"
            assert strings[2] == bytes([0, 255])
        case _:
            assert False
    match decoded.additional[2].items[0]:
        case dns.Rdata.SRV(priority, weight, port, name):
            assert priority == 1 and weight == 2 and port == 65535
            assert name.labels[0] == b"server"
        case _:
            assert False
    match decoded.additional[3].items[0]:
        case dns.Rdata.Generic(data):
            assert data == bytes([0xc0, 0x0c, 0xff])
        case _:
            assert False

@test
def _truncated_header_sections_and_trailing_data():
    auto message = _one_answer(5, dns.Rdata.CNAME(_example_name()))
    auto wire = message.to_wire()
    for size in range(len(wire)):
        _reject_wire(wire[:size])
    _reject_wire(wire + b"\x00")
    auto empty = _empty_message(0).to_wire()
    for offset in [5, 7, 9, 11]:
        _reject_wire(empty[:offset] + b"\x01" + empty[offset + 1:])

@test
def _invalid_names_and_pointers():
    auto head = bytes([0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0])
    for invalid in [b"\xc0", b"\xc0\x0c", b"\xc0\x0e\x00", b"\xc0\x00", b"\xc0\xff", b"\x01x\xc0\x0c", b"\x40", b"\x80", b"\x02x", b"\x01x"]:
        _reject_wire(head + invalid)
    auto two = bytes([0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0])
    _reject_wire(two + b"\xc0\x12\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01")

@test
def _label_name_and_message_size_boundaries():
    auto label = b""
    for index in range(63):
        label = label + b"x"
    auto exact = dns.Name([label, label, label, label[:61]])
    auto question = dns.RRset(exact, 1, 1, 0, [])
    auto wire = dns.Message(0, 0, [question], [], [], []).to_wire()
    assert len(wire) == 271
    assert len(dns.Message.from_wire(wire).question[0].name.labels[0]) == 63
    for invalid in [dns.Name([b""]), dns.Name([label + b"x"]), dns.Name([label, label, label, label[:62]])]:
        _reject_message(
            dns.Message(0, 0, [dns.RRset(invalid, 1, 1, 0, [])], [], [], []),
        )
    auto head = bytes([0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0])
    auto part = bytes([63]) + label
    _reject_wire(head + part + part + part + part + b"\x00\x00\x01\x00\x01")

    list[int64] octets = []
    for index in range(65513):
        octets.append(0)
    auto root = dns.Name([])
    auto exact_packet = dns.Message(
        0,
        0,
        [],
        [dns.RRset(root, 1, 65280, 0, [dns.Rdata.Generic(bytes(octets[:65512]))])],
        [],
        [],
    )
    auto max_wire = exact_packet.to_wire()
    assert len(max_wire) == 65535
    assert len(dns.Message.from_wire(max_wire).answer) == 1
    _reject_wire(max_wire + b"\x00")
    _reject_message(
        dns.Message(
            0,
            0,
            [],
            [dns.RRset(root, 1, 65280, 0, [dns.Rdata.Generic(bytes(octets))])],
            [],
            [],
        ),
    )

@test
def _invalid_record_lengths_and_data():
    for kind in [1, 2, 5, 6, 12, 15, 16, 28, 33]:
        _reject_wire(_packet_with_answer(kind, 0, b""))
    _reject_wire(_packet_with_answer(1, 3, b"abc"))
    _reject_wire(_packet_with_answer(28, 2, b"ab"))
    _reject_wire(_packet_with_answer(5, 1, b"\x02abc"))
    _reject_wire(_packet_with_answer(5, 2, b"\x00\x00"))
    _reject_wire(_packet_with_answer(16, 2, b"\x02x"))
    _reject_wire(_packet_with_answer(65280, 5, b"abc"))
    _reject_wire(_packet_with_answer(33, 8, b"\x00\x01\x00\x02\x00\x03\xc0\x0c"))
    _reject_message(_one_answer(2, dns.Rdata.CNAME(_example_name())))
    _reject_message(_one_answer(2, dns.Rdata.Generic(b"\x00")))
    _reject_message(_one_answer(16, dns.Rdata.TXT([])))
    _reject_message(_one_answer(15, dns.Rdata.MX(65536, _example_name())))
    _reject_message(_one_answer(33, dns.Rdata.SRV(0, -1, 53, _example_name())))

@test
def _invalid_header_and_section_fields():
    _reject_message(dns.Message(-1, 0, [], [], [], []))
    _reject_message(dns.Message(0, 65536, [], [], [], []))
    auto name = _example_name()
    for invalid in [dns.RRset(name, -1, 16, 0, []), dns.RRset(name, 1, 65536, 0, []), dns.RRset(name, 1, 16, 1, []), dns.RRset(name, 1, 16, 0, [dns.Rdata.TXT([b"x"])])]:
        _reject_message(dns.Message(0, 0, [invalid], [], [], []))
    for invalid in [dns.RRset(name, 1, 16, 0, []), dns.RRset(name, 1, 16, -1, [dns.Rdata.TXT([b"x"])]), dns.RRset(name, 1, 16, 0x100000000, [dns.Rdata.TXT([b"x"])])]:
        _reject_message(dns.Message(0, 0, [], [invalid], [], []))

@test
def _public_query_constructor():
    auto names = ["A", "NS", "CNAME", "SOA", "PTR", "MX", "TXT", "AAAA", "SRV"]
    auto codes = [1, 2, 5, 6, 12, 15, 16, 28, 33]
    for index in range(len(names)):
        auto query = dns.Message.query("www.Example.test.", names[index])
        assert query.id >= 0 and query.id <= 65535
        assert query.flags == 0x0100
        assert len(query.question) == 1
        assert len(query.answer) == 0
        assert len(query.authority) == 0
        assert len(query.additional) == 0
        auto wire = query.to_wire()
        assert wire[2:12] == b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        assert wire[12:30] == b"\x03www\x07Example\x04test\x00"
        assert wire[30:] == bytes([0, codes[index], 0, 1])
        auto decoded = dns.Message.from_wire(data=wire)
        assert decoded.id == query.id
        assert decoded.question[0].rdtype == codes[index]
        assert decoded.question[0].rdclass == 1

    auto escaped = dns.Message.query(rtype="mx", name="mail\\.box.\\000\\255")
    assert escaped.question[0].name.labels[0] == b"mail.box"
    assert escaped.question[0].name.labels[1] == bytes([0, 255])
    auto root = dns.Message.query(".", "NS")
    assert len(root.question[0].name.labels) == 0
    assert root.to_wire()[12:] == b"\x00\x00\x02\x00\x01"

def _reject_query(str name, str kind):
    auto rejected = False
    try:
        dns.Message.query(name, kind)
    except dns.WireFormatError:
        rejected = True
    assert rejected

@test
def _invalid_query_inputs():
    for name in ["", ".example", "example..test", "example..", "example\\", "example\\0", "example\\01a", "example\\256", "é.test"]:
        _reject_query(name, "A")
    for kind in ["", "UNKNOWN", " A", "AAAA ", "28"]:
        _reject_query("example.test", kind)
    auto label = "012345678901234567890123456789012345678901234567890123456789012"
    assert len(label) == 63
    _reject_query(label + "x.test", "A")
    _reject_query(label + "." + label + "." + label + "." + label, "A")

@test
def _known_ipv4_and_ipv6_wire_data():
    auto ipv4 = bytes([192, 0, 2, 255])
    auto ipv6 = bytes(
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xca, 0xfe],
    )
    auto a = dns.Message.from_wire(_packet_with_answer(1, 4, ipv4))
    auto aaaa = dns.Message.from_wire(_packet_with_answer(28, 16, ipv6))
    match a.answer[0].items[0]:
        case dns.Rdata.A(address):
            assert address == "192.0.2.255"
        case _:
            assert False
    match aaaa.answer[0].items[0]:
        case dns.Rdata.AAAA(address):
            assert address == "2001:db8::cafe"
        case _:
            assert False
    assert a.to_wire()[21:] == bytes([0, 4]) + ipv4
    assert aaaa.to_wire()[21:] == bytes([0, 16]) + ipv6

    auto input = _one_answer(
        28,
        dns.Rdata.AAAA("2001:0DB8:0000:0000:0000:0000:0000:CAFE"),
    )
    assert input.to_wire() == _one_answer(28, dns.Rdata.AAAA("2001:db8::cafe")).to_wire()
    auto edge = [
        dns.Rdata.AAAA("::"),
        dns.Rdata.AAAA("::1"),
        dns.Rdata.AAAA("::ffff:192.0.2.1"),
    ]
    auto texts = ["::", "::1", "::ffff:192.0.2.1"]
    for index in range(len(edge)):
        auto decoded = dns.Message.from_wire(_one_answer(28, edge[index]).to_wire())
        match decoded.answer[0].items[0]:
            case dns.Rdata.AAAA(address):
                assert address == texts[index]
            case _:
                assert False
    for address in ["0.0.0.0", "255.255.255.255"]:
        auto decoded = dns.Message.from_wire(
            _one_answer(1, dns.Rdata.A(address)).to_wire(),
        )
        match decoded.answer[0].items[0]:
            case dns.Rdata.A(actual):
                assert actual == address
            case _:
                assert False

@test
def _invalid_addresses_and_widths():
    for address in ["", "192.0.2", "192.0.2.256", "192.000.2.1", "192.0.2.1 ", "::1", "example.test"]:
        _reject_message(_one_answer(1, dns.Rdata.A(address)))
    for address in ["", "192.0.2.1", "1::2::3", "2001:db8::10000", "fe80::1%eth0", "1:2:3:4:5:6:7"]:
        _reject_message(_one_answer(28, dns.Rdata.AAAA(address)))
    auto zeros = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    for width in [3, 5]:
        _reject_wire(_packet_with_answer(1, width, zeros[:width]))
    for width in [15, 17]:
        _reject_wire(_packet_with_answer(28, width, zeros[:width]))

@test
def _public_dns_exception_family():
    auto caught = False
    try:
        dns.Message.from_wire(b"")
    except dns.DNSException:
        caught = True
    assert caught

    caught = False
    try:
        raise dns.TransportError("exchange failed")
    except dns.ResponseError:
        assert False
    except dns.DNSException as message:
        assert message == "exchange failed"
        caught = True
    assert caught

    caught = False
    try:
        raise dns.Timeout("deadline expired")
    except Exception as message:
        assert message == "deadline expired"
        caught = True
    assert caught

    caught = False
    try:
        raise ValueError("unrelated")
    except dns.DNSException:
        assert False
    except ValueError:
        caught = True
    assert caught
