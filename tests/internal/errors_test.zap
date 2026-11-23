@test
def _response_status_rcodes():
    _check_response_status(0x8180)
    for rcode in range(1, 16):
        auto caught = 0
        try:
            _check_response_status(0x8180 | rcode)
        except NXDOMAIN as message:
            assert message == "DNS name does not exist"
            caught = 3
        except ServFail as message:
            assert message == "DNS server failure"
            caught = 2
        except ResponseError as message:
            assert rcode != 2 and rcode != 3
            assert message == "DNS response error code " + str(rcode)
            caught = rcode
        assert caught == rcode

@test
def _truncation_takes_precedence_over_rcode():
    for rcode in range(16):
        auto caught = False
        try:
            _check_response_status(0x8380 | rcode)
        except Truncated:
            caught = True
        assert caught

@test
def _nodata_and_selected_answers():
    auto name = Name([b"example", b"test"])
    auto empty = RRset(name, 1, 1, 0, [])
    auto present = RRset(name, 1, 1, 0, [Rdata.A("192.0.2.1")])
    _check_response_status(0x8180)
    _require_answer([present])
    _require_answer([empty, present])
    list[list[RRset]] missing = [[], [empty]]
    for selected in missing:
        auto caught = False
        try:
            _require_answer(selected)
        except NoAnswer:
            caught = True
        assert caught
