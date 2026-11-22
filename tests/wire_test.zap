def _empty_message(int64 flags) -> Message:
    return Message(0xbeef, flags, [], [], [], [])

def _example_name() -> Name:
    return Name([b"example", b"test"])

def _one_answer(int64 rdtype, Rdata item) -> Message:
    return Message(
        0x1234,
        0x8180,
        [],
        [RRset(_example_name(), 1, rdtype, 60, [item])],
        [],
        [],
    )

def _packet_with_answer(int64 rdtype, int64 rdlength, bytes data) -> bytes:
    return bytes([0, 0, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, rdtype >> 8, rdtype & 255, 0, 1, 0, 0, 0, 60, rdlength >> 8, rdlength & 255]) + data

def _reject_wire(bytes data):
    auto rejected = False
    try:
        _decode(data)
    except WireFormatError:
        rejected = True
    assert rejected

def _reject_message(Message message):
    auto rejected = False
    try:
        message.to_wire()
    except WireFormatError:
        rejected = True
    assert rejected

@test
def _header_bits_and_empty_sections():
    for bit in range(16):
        auto flags = 1 << bit
        auto wire = _empty_message(flags).to_wire()
        assert wire == bytes([0xbe, 0xef, flags >> 8, flags & 255, 0, 0, 0, 0, 0, 0, 0, 0])
        auto decoded = _decode(wire)
        assert decoded.id == 0xbeef
        assert decoded.flags == flags
        assert len(decoded.question) == 0
        assert len(decoded.answer) == 0
        assert len(decoded.authority) == 0
        assert len(decoded.additional) == 0
    assert _decode(_empty_message(0xffff).to_wire()).flags == 0xffff

@test
def _known_query_and_compressed_response():
    auto expected = bytes([0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]) + b"\x07example\x04test\x00\x00\x05\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x07\x04mail\xc0\x0c"
    auto owner = _example_name()
    auto target = Name([b"mail", b"example", b"test"])
    auto question = RRset(owner, 1, 5, 0, [])
    auto cname = RRset(owner, 1, 5, 60, [Rdata.CNAME(target)])
    auto message = Message(0x1234, 0x8180, [question], [cname], [], [])
    assert message.to_wire() == expected

    auto decoded = _decode(expected)
    assert decoded.question[0].rdtype == 5
    assert decoded.question[0].rdclass == 1
    assert decoded.question[0].name.labels[0] == b"example"
    assert decoded.answer[0].ttl == 60
    match decoded.answer[0].items[0]:
        case Rdata.CNAME(name):
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
    auto decoded = _decode(head + body)
    assert len(decoded.question) == 3
    assert decoded.question[2].name.labels[0] == b"mail"
    assert decoded.question[2].name.labels[1] == b"test"

    auto first = RRset(Name([b"Example", b"test"]), 1, 16, 90, [Rdata.TXT([b"first"])])
    auto second = RRset(
        _example_name(),
        1,
        16,
        30,
        [Rdata.TXT([b"second"]), Rdata.TXT([b"third"])],
    )
    auto another_class = RRset(
        _example_name(),
        3,
        16,
        40,
        [Rdata.TXT([b"other class"])],
    )
    auto message = Message(9, 0, [], [first, second, another_class], [], [])
    auto wire = message.to_wire()
    assert wire[7] == 4
    auto reread = _decode(wire)
    assert len(reread.answer) == 2
    assert reread.answer[0].ttl == 30
    assert reread.answer[0].name.labels[0] == b"Example"
    assert len(reread.answer[0].items) == 3
    assert reread.answer[1].rdclass == 3

@test
def _typed_records_and_all_sections():
    auto root = Name([])
    auto owner = _example_name()
    auto target = Name([b"server", b"example", b"test"])
    auto answer = RRset(
        owner,
        1,
        15,
        0xffffffff,
        [Rdata.MX(65535, target), Rdata.MX(0, root)],
    )
    auto ns = RRset(owner, 1, 2, 3600, [Rdata.NS(target)])
    auto soa = RRset(
        owner,
        1,
        6,
        123,
        [Rdata.SOA(target, root, 0xffffffff, 7200, 1800, 86400, 60)],
    )
    auto ptr = RRset(owner, 1, 12, 0, [Rdata.PTR(target)])
    auto txt = RRset(owner, 1, 16, 0, [Rdata.TXT([b"", b"hello", bytes([0, 255])])])
    auto srv = RRset(owner, 1, 33, 0, [Rdata.SRV(1, 2, 65535, target)])
    auto generic = RRset(root, 1, 65280, 0, [Rdata.Generic(bytes([0xc0, 0x0c, 0xff]))])
    auto message = Message(1, 0x8180, [], [answer], [ns, soa], [ptr, txt, srv, generic])
    auto wire = message.to_wire()
    assert wire[4:12] == bytes([0, 0, 0, 2, 0, 2, 0, 4])
    auto decoded = _decode(wire)
    assert decoded.to_wire() == wire
    assert decoded.answer[0].ttl == 0xffffffff
    match decoded.answer[0].items[0]:
        case Rdata.MX(preference, exchange):
            assert preference == 65535
            assert exchange.labels[0] == b"server"
        case _:
            assert False
    match decoded.authority[0].items[0]:
        case Rdata.NS(name):
            assert name.labels[0] == b"server"
        case _:
            assert False
    match decoded.authority[1].items[0]:
        case Rdata.SOA(mname, rname, serial, refresh, retry, expire, minimum):
            assert mname.labels[2] == b"test"
            assert len(rname.labels) == 0
            assert serial == 0xffffffff
            assert refresh == 7200 and retry == 1800 and expire == 86400 and minimum == 60
        case _:
            assert False
    match decoded.additional[0].items[0]:
        case Rdata.PTR(name):
            assert name.labels[0] == b"server"
        case _:
            assert False
    match decoded.additional[1].items[0]:
        case Rdata.TXT(strings):
            assert len(strings) == 3
            assert strings[0] == b""
            assert strings[1] == b"hello"
            assert strings[2] == bytes([0, 255])
        case _:
            assert False
    match decoded.additional[2].items[0]:
        case Rdata.SRV(priority, weight, port, name):
            assert priority == 1 and weight == 2 and port == 65535
            assert name.labels[0] == b"server"
        case _:
            assert False
    match decoded.additional[3].items[0]:
        case Rdata.Generic(data):
            assert data == bytes([0xc0, 0x0c, 0xff])
        case _:
            assert False

@test
def _truncated_header_sections_and_trailing_data():
    auto message = _one_answer(5, Rdata.CNAME(_example_name()))
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
    auto exact = Name([label, label, label, label[:61]])
    auto question = RRset(exact, 1, 1, 0, [])
    auto wire = Message(0, 0, [question], [], [], []).to_wire()
    assert len(wire) == 271
    assert len(_decode(wire).question[0].name.labels[0]) == 63
    for invalid in [Name([b""]), Name([label + b"x"]), Name([label, label, label, label[:62]])]:
        _reject_message(Message(0, 0, [RRset(invalid, 1, 1, 0, [])], [], [], []))
    auto head = bytes([0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0])
    auto part = bytes([63]) + label
    _reject_wire(head + part + part + part + part + b"\x00\x00\x01\x00\x01")

    list[int64] octets = []
    for index in range(65513):
        octets.append(0)
    auto root = Name([])
    auto exact_packet = Message(
        0,
        0,
        [],
        [RRset(root, 1, 65280, 0, [Rdata.Generic(bytes(octets[:65512]))])],
        [],
        [],
    )
    auto max_wire = exact_packet.to_wire()
    assert len(max_wire) == 65535
    assert len(_decode(max_wire).answer) == 1
    _reject_wire(max_wire + b"\x00")
    _reject_message(
        Message(
            0,
            0,
            [],
            [RRset(root, 1, 65280, 0, [Rdata.Generic(bytes(octets))])],
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
    _reject_message(_one_answer(2, Rdata.CNAME(_example_name())))
    _reject_message(_one_answer(2, Rdata.Generic(b"\x00")))
    _reject_message(_one_answer(16, Rdata.TXT([])))
    _reject_message(_one_answer(15, Rdata.MX(65536, _example_name())))
    _reject_message(_one_answer(33, Rdata.SRV(0, -1, 53, _example_name())))

@test
def _invalid_header_and_section_fields():
    _reject_message(Message(-1, 0, [], [], [], []))
    _reject_message(Message(0, 65536, [], [], [], []))
    auto name = _example_name()
    for invalid in [RRset(name, -1, 16, 0, []), RRset(name, 1, 65536, 0, []), RRset(name, 1, 16, 1, []), RRset(name, 1, 16, 0, [Rdata.TXT([b"x"])])]:
        _reject_message(Message(0, 0, [invalid], [], [], []))
    for invalid in [RRset(name, 1, 16, 0, []), RRset(name, 1, 16, -1, [Rdata.TXT([b"x"])]), RRset(name, 1, 16, 0x100000000, [Rdata.TXT([b"x"])])]:
        _reject_message(Message(0, 0, [], [invalid], [], []))
