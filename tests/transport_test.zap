import dns
import net
import time

def _udp_server_socket(int64 port) -> bytes:
    auto server = net.udp_socket()
    net.udp_bind(server, "127.0.0.1", port)
    net.set_deadline_ns(server, time.monotonic_ns() + 5000000000)
    return server

def _answer(dns.Message query) -> dns.Message:
    auto rr = dns.RRset(
        query.question[0].name,
        1,
        16,
        60,
        [dns.Rdata.TXT([bytes([0, 255, 128])])],
    )
    return dns.Message(query.id, 0x8180, query.question, [rr], [], [])

def _assert_txt(dns.Message request, dns.Message reply):
    assert request.id == reply.id
    assert request.question[0].name.labels == reply.question[0].name.labels
    match reply.answer[0].items[0]:
        case dns.Rdata.TXT(strings):
            assert strings == [bytes([0, 255, 128])]
        case _:
            assert False

def _udp_responder(bytes server, int64 count):
    try:
        for index in range(count):
            auto payload, host, port = net.recvfrom(server, 512)
            auto query = dns.Message.from_wire(bytes(payload))
            net.sendto(server, _answer(query).to_wire(), host, port)
    finally:
        net.close_conn(server)

def _client_query(int64 port, int64 index):
    auto query = dns.Message.query("host" + str(index) + ".example.test", "TXT")
    auto reply, tcp = dns.udp_with_fallback(query, "127.0.0.1", timeout=2.0, port=port)
    assert not tcp
    _assert_txt(query, reply)

@test
def _concurrent_coroutine_udp_exchanges():
    auto server = _udp_server_socket(0)
    auto port = net.port(server)
    scope:
        spawn _udp_responder(server, 12)
        for index in range(12):
            spawn _client_query(port, index)

def _send_unrelated_udp_replies(bytes server):
    try:
        auto payload, host, port = net.recvfrom(server, 512)
        auto query = dns.Message.from_wire(bytes(payload))
        auto answer = _answer(query)

        auto rogue = _udp_server_socket(0)
        try:
            auto refused = dns.Message(answer.id, 0x8185, answer.question, [], [], [])
            net.sendto(rogue, refused.to_wire(), host, port)
        finally:
            net.close_conn(rogue)

        auto wrong_id = dns.Message(
            answer.id + 1 & 65535,
            0x8380,
            answer.question,
            [],
            [],
            [],
        )
        net.sendto(server, wrong_id.to_wire(), host, port)
        auto wrong_question = dns.Message.query("wrong.example.test", "TXT")
        auto wrong_name = dns.Message(
            answer.id,
            0x8380,
            wrong_question.question,
            [],
            [],
            [],
        )
        net.sendto(server, wrong_name.to_wire(), host, port)
        auto wrong_type = dns.Message.query("host.example.test", "A")
        auto wrong_qtype = dns.Message(
            answer.id,
            0x8380,
            wrong_type.question,
            [],
            [],
            [],
        )
        net.sendto(server, wrong_qtype.to_wire(), host, port)
        auto wrong_opcode = dns.Message(answer.id, 0x8b80, answer.question, [], [], [])
        net.sendto(server, wrong_opcode.to_wire(), host, port)
        auto oversized_unrelated = wrong_id.to_wire()
        for index in range(5):
            oversized_unrelated = oversized_unrelated + oversized_unrelated
        assert len(oversized_unrelated) > 512
        net.sendto(server, oversized_unrelated, host, port)
        net.sendto(server, query.to_wire(), host, port)
        net.sendto(server, answer.to_wire(), host, port)
    finally:
        net.close_conn(server)

@test
def _udp_ignores_wrong_peer_id_and_question():
    auto server = _udp_server_socket(0)
    auto port = net.port(server)
    auto query = dns.Message.query("host.example.test", "TXT")
    scope:
        spawn _send_unrelated_udp_replies(server)
        auto reply, tcp = dns.udp_with_fallback(query, "127.0.0.1", port=port)
        assert not tcp
        _assert_txt(query, reply)

def _send_truncated_udp(bytes server):
    try:
        auto payload, host, port = net.recvfrom(server, 512)
        auto query = dns.Message.from_wire(bytes(payload))
        auto header = dns.Message(query.id, 0x8380, query.question, [], [], []).to_wire()
        # ANCOUNT claims an answer even though the datagram ends at the question.
        auto truncated = header[:6] + b"\x00\x01" + header[8:]
        net.sendto(server, truncated, host, port)
    finally:
        net.close_conn(server)

def _read_exact(bytes socket, int64 count) -> bytes:
    auto data = b""
    while len(data) < count:
        auto chunk = bytes(net.recv(socket, count - len(data)))
        assert len(chunk) > 0
        data = data + chunk
    return data

def _send_tcp_reply(bytes listener, str mode):
    try:
        auto socket = net.accept(listener)
        try:
            net.set_deadline_ns(socket, time.monotonic_ns() + 3000000000)
            auto prefix = _read_exact(socket, 2)
            auto size = int64(prefix[0]) << 8 | int64(prefix[1])
            auto query = dns.Message.from_wire(_read_exact(socket, size))
            auto reply = _answer(query)
            if mode == "mismatch":
                reply.id = reply.id + 1 & 65535
            if mode == "truncated":
                reply.flags = 0x8380
            auto wire = reply.to_wire()
            auto frame = bytes([len(wire) >> 8, len(wire) & 255]) + wire
            match mode:
                case "partial":
                    net.send(socket, frame[:8])
                case "short":
                    net.send(socket, b"\x00\x0b")
                case "slow":
                    net.send(socket, frame[:1])
                    time.sleep(0.25)
                case _:
                    net.send(socket, frame[:1])
                    time.sleep(0.01)
                    net.send(socket, frame[1:7])
                    time.sleep(0.01)
                    net.send(socket, frame[7:])
        finally:
            net.close_conn(socket)
    finally:
        net.close_listener(listener)

@test
def _fallback_accepts_fragmented_tcp_reply():
    auto listener = net.listen("127.0.0.1", 0)
    auto server = _udp_server_socket(net.port(listener))
    auto port = net.port(server)
    net.set_deadline_ns(listener, time.monotonic_ns() + 5000000000)
    auto query = dns.Message.query("host.example.test", "TXT")
    scope:
        spawn _send_truncated_udp(server)
        spawn _send_tcp_reply(listener, "reply")
        auto reply, tcp = dns.udp_with_fallback(query, "127.0.0.1", port=port)
        assert tcp
        _assert_txt(query, reply)

def _fallback_error(str mode):
    auto listener = net.listen("127.0.0.1", 0)
    auto server = _udp_server_socket(net.port(listener))
    auto port = net.port(server)
    net.set_deadline_ns(listener, time.monotonic_ns() + 5000000000)
    auto query = dns.Message.query("host.example.test", "TXT")
    auto observed = ""
    auto timeout = 2.0
    if mode == "slow":
        timeout = 0.1
    scope:
        spawn _send_truncated_udp(server)
        spawn _send_tcp_reply(listener, mode)
        try:
            dns.udp_with_fallback(query, "127.0.0.1", timeout=timeout, port=port)
        except dns.TransportError:
            observed = "partial"
        except dns.WireFormatError:
            observed = "short"
        except dns.ResponseError:
            observed = "mismatch"
        except dns.Truncated:
            observed = "truncated"
        except dns.Timeout:
            observed = "slow"
    assert observed == mode

@test
def _fallback_rejects_bad_frames_and_times_out():
    for mode in ["partial", "short", "mismatch", "truncated", "slow"]:
        _fallback_error(mode)

@test
def _fallback_reports_tcp_connection_refused():
    auto listener = net.listen("127.0.0.1", 0)
    auto server = _udp_server_socket(net.port(listener))
    auto port = net.port(server)
    net.close_listener(listener)
    auto query = dns.Message.query("host.example.test", "TXT")
    auto caught = False
    scope:
        spawn _send_truncated_udp(server)
        try:
            dns.udp_with_fallback(query, "127.0.0.1", port=port)
        except dns.TransportError:
            caught = True
    assert caught

@test
def _silent_udp_and_immediate_timeout():
    auto server = _udp_server_socket(0)
    auto port = net.port(server)
    auto query = dns.Message.query("host.example.test", "TXT")
    try:
        for seconds in [0.0, 0.02]:
            auto caught = False
            auto before = time.monotonic_ns()
            try:
                dns.udp_with_fallback(query, "127.0.0.1", timeout=seconds, port=port)
            except dns.Timeout:
                caught = True
            assert caught
            if seconds > 0.0:
                assert time.monotonic_ns() - before >= 20000000
    finally:
        net.close_conn(server)

def _send_large_udp_reply(bytes server, bool valid):
    try:
        auto payload, host, port = net.recvfrom(server, 1024)
        auto query = dns.Message.from_wire(bytes(payload))
        list[int64] octets = []
        for index in range(700):
            octets.append(255)
        auto rr = dns.RRset(
            query.question[0].name,
            1,
            65280,
            1,
            [dns.Rdata.Generic(bytes(octets))],
        )
        auto wire = dns.Message(query.id, 0x8180, query.question, [rr], [], []).to_wire()
        assert len(wire) > 512
        if valid:
            assert len(query.additional) == 1
        net.sendto(server, wire, host, port)
    finally:
        net.close_conn(server)

@test
def _udp_rejects_oversize_and_honors_edns_limit():
    for edns in [False, True]:
        auto server = _udp_server_socket(0)
        auto port = net.port(server)
        auto query = dns.Message.query("host.example.test", "TXT")
        if edns:
            query.additional = [
                dns.RRset(dns.Name([]), 1232, 41, 0, [dns.Rdata.Generic(b"")]),
            ]
        auto rejected = False
        scope:
            spawn _send_large_udp_reply(server, edns)
            try:
                auto reply, tcp = dns.udp_with_fallback(query, "127.0.0.1", port=port)
                assert not tcp
                assert reply.answer[0].rdtype == 65280
            except dns.WireFormatError:
                rejected = True
        assert rejected != edns

@test
def _exchange_rejects_invalid_endpoint_and_message():
    auto query = dns.Message.query("host.example.test", "TXT")
    for where in ["", "localhost", "256.0.0.1", "[::1]"]:
        auto rejected = False
        try:
            dns.udp_with_fallback(query, where)
        except ValueError:
            rejected = True
        assert rejected
    for port in [0, -1, 65536]:
        auto rejected = False
        try:
            dns.udp_with_fallback(query, "127.0.0.1", port=port)
        except ValueError:
            rejected = True
        assert rejected
    for invalid in [_answer(query), dns.Message(0, 0, [], [], [], [])]:
        auto rejected = False
        try:
            dns.udp_with_fallback(invalid, "127.0.0.1")
        except dns.WireFormatError:
            rejected = True
        assert rejected

@test
def _udp_exchange_with_ipv6_nameserver():
    auto server = net.udp_socket6()
    net.udp_bind(server, "::1", 0)
    net.set_deadline_ns(server, time.monotonic_ns() + 5000000000)
    auto port = net.port(server)
    auto query = dns.Message.query("ipv6.example.test", "TXT")
    scope:
        spawn _udp_responder(server, 1)
        auto reply, tcp = dns.udp_with_fallback(query, "::1", port=port)
        assert not tcp
        _assert_txt(query, reply)

def _respond_nxdomain(bytes server):
    try:
        auto payload, host, port = net.recvfrom(server, 512)
        auto query = dns.Message.from_wire(bytes(payload))
        auto response = dns.Message(query.id, 0x8183, query.question, [], [], [])
        net.sendto(server, response.to_wire(), host, port)
    finally:
        net.close_conn(server)

@test
def _transport_preserves_dns_response_codes():
    auto server = _udp_server_socket(0)
    auto port = net.port(server)
    auto query = dns.Message.query("missing.example.test", "TXT")
    scope:
        spawn _respond_nxdomain(server)
        auto reply, tcp = dns.udp_with_fallback(query, "127.0.0.1", port=port)
        assert not tcp
        assert reply.flags & 15 == 3
        assert len(reply.answer) == 0
