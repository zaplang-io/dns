@test
def _selects_owner_class_type_and_alias_ttl():
    auto qname = _query_name("Alias.example.")
    auto middle = _query_name("middle.example.")
    auto target = _query_name("Target.example.")
    auto question = RRset(qname, 1, 1, 0, [])
    auto first = RRset(_query_name("alias.example"), 1, 5, 40, [Rdata.CNAME(middle)])
    auto then = RRset(middle, 1, 5, 7, [Rdata.CNAME(target)])
    auto found = RRset(
        _query_name("target.example"),
        1,
        1,
        30,
        [Rdata.A("192.0.2.1"), Rdata.A("192.0.2.2")],
    )
    auto wrong_class = RRset(qname, 3, 1, 0, [Rdata.A("192.0.2.9")])
    auto unrelated = RRset(
        _query_name("unrelated.example"),
        1,
        1,
        0,
        [Rdata.A("192.0.2.8")],
    )
    auto answer = _select_answer(
        question,
        Message(
            1,
            0x8180,
            [question],
            [wrong_class, unrelated, found, then, first],
            [],
            [],
        ),
        "192.0.2.53",
        53,
    )
    assert answer.qname.labels == qname.labels
    assert answer.canonical_name.labels == target.labels
    assert answer.rrset.name.labels == [b"target", b"example"]
    assert len(answer.rrset.items) == 2
    assert answer.ttl == 7

    auto cname_question = RRset(qname, 1, 5, 0, [])
    auto cname = _select_answer(cname_question, answer.response, "192.0.2.53", 53)
    assert cname.rrset.rdtype == 5
    assert cname.ttl == 40
    assert cname.canonical_name.labels == qname.labels

@test
def _aliases_reject_loops_and_conflicting_targets():
    auto start = _query_name("start.example.")
    auto middle = _query_name("middle.example.")
    auto question = RRset(start, 1, 1, 0, [])
    auto first = RRset(start, 1, 5, 30, [Rdata.CNAME(middle)])
    auto cycle = RRset(middle, 1, 5, 20, [Rdata.CNAME(_query_name("START.example"))])
    auto conflict = RRset(start, 1, 5, 30, [Rdata.CNAME(middle), Rdata.CNAME(start)])
    list[list[RRset]] failures = [[first, cycle], [conflict]]
    for records in failures:
        auto caught = False
        try:
            _select_answer(
                question,
                Message(1, 0x8180, [question], records, [], []),
                "192.0.2.53",
                53,
            )
        except ResponseError:
            caught = True
        assert caught

@test
def _alias_chain_length_boundary():
    auto root = _query_name("h0.example")
    auto question = RRset(root, 1, 1, 0, [])
    for links in [16, 17]:
        list[RRset] answers = []
        for index in range(links):
            auto owner = _query_name("h" + str(index) + ".example")
            auto target = _query_name("h" + str(index + 1) + ".example")
            answers.append(RRset(owner, 1, 5, 10, [Rdata.CNAME(target)]))
        auto terminal = _query_name("h" + str(links) + ".example")
        answers.append(RRset(terminal, 1, 1, 30, [Rdata.A("192.0.2.1")]))
        auto caught = False
        try:
            auto answer = _select_answer(
                question,
                Message(1, 0x8180, [question], answers, [], []),
                "192.0.2.53",
                53,
            )
            assert answer.canonical_name.labels == terminal.labels
        except ResponseError:
            caught = True
        assert caught == (links == 17)

@test
def _reverse_names_and_mapped_ipv6():
    assert _reverse_name("192.0.2.255").labels == [b"255", b"2", b"0", b"192", b"in-addr", b"arpa"]
    assert _reverse_name("::ffff:192.0.2.255").labels == _reverse_name("192.0.2.255").labels
    auto v6 = _reverse_name("2001:db8::cafe")
    assert len(v6.labels) == 34
    assert v6.labels[:4] == [b"e", b"f", b"a", b"c"]
    assert v6.labels[24:] == [b"8", b"b", b"d", b"0", b"1", b"0", b"0", b"2", b"ip6", b"arpa"]
    for invalid in ["", "192.0.2", "192.0.2.999", "a.example", "[::1]", "1::2::3"]:
        auto caught = False
        try:
            _reverse_name(invalid)
        except ValueError:
            caught = True
        assert caught
