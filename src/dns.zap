# RFC 1035 messages, using dnspython's section and record-data model.

import crypto
import fs
import math
import net
import sys

# Common catch type for query, response, wire, and transport failures.
@exception
struct DNSException:
    str message

# Raised when a DNS message or a record has an invalid wire representation.
@exception(DNSException)
struct WireFormatError:
    str message

# A server returned a DNS error code.
@exception(DNSException)
struct ResponseError:
    str message

# The server returned NXDOMAIN.
@exception(ResponseError)
struct NXDOMAIN:
    str message

# The response has no usable records for the requested name, class, and type.
@exception(DNSException)
struct NoAnswer:
    str message

# The server returned SERVFAIL.
@exception(ResponseError)
struct ServFail:
    str message

# The TC bit is set. UDP callers can retry the query over TCP.
@exception(DNSException)
struct Truncated:
    str message

# A query timeout or the overall resolution lifetime expired.
@exception(DNSException)
struct Timeout:
    str message

# A DNS exchange failed at the transport layer.
@exception(DNSException)
struct TransportError:
    str message

# An absolute DNS name as wire labels. An empty list represents the root.
struct Name:
    list[bytes] labels

# Typed Tier-1 data. Generic retains an unfamiliar type's bytes.
enum Rdata:
    A(str address)
    NS(Name target)
    CNAME(Name target)
    SOA(Name mname, Name rname, int64 serial, int64 refresh, int64 retry, int64 expire, int64 minimum)
    PTR(Name target)
    MX(int64 preference, Name exchange)
    TXT(list[bytes] strings)
    AAAA(str address)
    SRV(int64 priority, int64 weight, int64 port, Name target)
    Generic(bytes data)

# Records sharing an owner, class and type. Questions have no items.
struct RRset:
    Name name
    int64 rdclass
    int64 rdtype
    int64 ttl
    list[Rdata] items

# One DNS message. Counts are derived from its four sections.
struct Message:
    int64 id
    int64 flags
    list[RRset] question
    list[RRset] answer
    list[RRset] authority
    list[RRset] additional

    def query(str name, str rtype) -> Message:
        "Build a recursive IN query with a random ID from an ASCII DNS name and type mnemonic."
        auto owner = _query_name(name)
        auto question = RRset(owner, 1, _query_type(rtype), 0, [])
        auto entropy = crypto.random_bytes(2)
        auto id = int64(entropy[0]) << 8 | int64(entropy[1])
        return Message(id, 0x0100, [question], [], [], [])

    def from_wire(bytes data) -> Message:
        "Decode one complete DNS message. Raise WireFormatError for malformed input."
        return _decode(data)

    def to_wire(self) -> bytes:
        "Encode a complete DNS message, compressing eligible domain names."
        return _encode(self)

def _query_name(str text) -> Name:
    auto parsed = _parse_query_name(text)
    return parsed[0]

def _parse_query_name(str text) -> (Name, bool):
    auto data = bytes(text)
    if data == b".":
        return (Name([]), True)
    if len(data) == 0:
        raise WireFormatError("empty DNS name; use '.' for the root")
    list[bytes] labels = []
    list[int64] label = []
    auto index = 0
    while index < len(data):
        auto octet = int64(data[index])
        index = index + 1
        if octet == 46:
            if len(label) == 0:
                raise WireFormatError("empty DNS label")
            labels.append(bytes(label))
            label = []
            continue
        if octet == 92:
            if index == len(data):
                raise WireFormatError("incomplete DNS name escape")
            octet = int64(data[index])
            index = index + 1
            if octet >= 48 and octet <= 57:
                if len(data) - index < 2:
                    raise WireFormatError(
                        "DNS numeric escapes require three decimal digits",
                    )
                auto tens = int64(data[index]) - 48
                auto units = int64(data[index + 1]) - 48
                if tens < 0 or tens > 9 or units < 0 or units > 9:
                    raise WireFormatError(
                        "DNS numeric escapes require three decimal digits",
                    )
                octet = (octet - 48) * 100 + tens * 10 + units
                index = index + 2
                if octet > 255:
                    raise WireFormatError("DNS name escape exceeds one octet")
                label.append(octet)
                continue
        if octet < 32 or octet > 126:
            raise WireFormatError("DNS query names require ASCII or decimal escapes")
        label.append(octet)
    auto absolute = len(label) == 0
    if not absolute:
        labels.append(bytes(label))
    auto name = Name(labels)
    _name_key(name, False)
    return (name, absolute)

def _query_type(str mnemonic) -> int64:
    match mnemonic.upper():
        case "A":
            return 1
        case "NS":
            return 2
        case "CNAME":
            return 5
        case "SOA":
            return 6
        case "PTR":
            return 12
        case "MX":
            return 15
        case "TXT":
            return 16
        case "AAAA":
            return 28
        case "SRV":
            return 33
        case _:
            raise WireFormatError("unknown DNS query type: " + mnemonic)

def _pack_address(str family, str address) -> bytes:
    try:
        return net.inet_pton(family, address)
    except ValueError:
        raise WireFormatError("invalid " + family + " address: " + address)

def _name_key(Name name, bool fold_case) -> bytes:
    list[int64] octets = []
    for label in name.labels:
        if len(label) == 0 or len(label) > 63:
            raise WireFormatError("DNS labels must contain 1 to 63 octets")
        octets.append(len(label))
        for index in range(len(label)):
            auto value = int64(label[index])
            if fold_case and value >= 65 and value <= 90:
                value = value + 32
            octets.append(value)
        if len(octets) >= 255:
            raise WireFormatError("expanded DNS name exceeds 255 octets")
    octets.append(0)
    return bytes(octets)

struct _Writer:
    list[int64] octets
    dict[bytes, int64] suffixes

    def _room(self, int64 count):
        if count > 65535 - len(self.octets):
            raise WireFormatError("DNS message exceeds 65535 octets")

    def _word(self, int64 value, int64 width):
        self._room(width)
        auto shift = width * 8
        if value < 0 or value >= 1 << shift:
            raise WireFormatError("integer does not fit its DNS field")
        while shift > 0:
            shift = shift - 8
            self.octets.append(value >> shift & 255)

    def _copy(self, bytes data):
        self._room(len(data))
        for index in range(len(data)):
            self.octets.append(int64(data[index]))

    def _name(self, Name name, bool compress):
        auto suffix = _name_key(name, False)
        if not compress:
            self._copy(suffix)
            return
        auto consumed = 0
        for label in name.labels:
            auto key = suffix[consumed:]
            if key in self.suffixes:
                self._word(49152 | self.suffixes[key], 2)
                return
            auto offset = len(self.octets)
            if offset < 16384:
                self.suffixes[key] = offset
            self._word(len(label), 1)
            self._copy(label)
            consumed = consumed + len(label) + 1
        self._word(0, 1)

    def _rdata(self, int64 rdtype, Rdata item):
        auto actual_type = _rdata_type(item)
        if actual_type != 0 and actual_type != rdtype:
            raise WireFormatError("RRset type and record data disagree")
        match item:
            case Rdata.A(address):
                self._copy(_pack_address("ipv4", address))
            case Rdata.NS(target):
                self._name(target, True)
            case Rdata.CNAME(target):
                self._name(target, True)
            case Rdata.SOA(mname, rname, serial, refresh, retry, expire, minimum):
                self._name(mname, True)
                self._name(rname, True)
                self._word(serial, 4)
                self._word(refresh, 4)
                self._word(retry, 4)
                self._word(expire, 4)
                self._word(minimum, 4)
            case Rdata.PTR(target):
                self._name(target, True)
            case Rdata.MX(preference, exchange):
                self._word(preference, 2)
                self._name(exchange, True)
            case Rdata.TXT(strings):
                if len(strings) == 0:
                    raise WireFormatError("TXT requires at least one character string")
                for part in strings:
                    self._word(len(part), 1)
                    self._copy(part)
            case Rdata.AAAA(address):
                self._copy(_pack_address("ipv6", address))
            case Rdata.SRV(priority, weight, port, target):
                self._word(priority, 2)
                self._word(weight, 2)
                self._word(port, 2)
                # RFC 2782 forbids compression of the SRV target.
                self._name(target, False)
            case Rdata.Generic(data):
                if _is_typed(rdtype):
                    raise WireFormatError("Tier-1 records require typed RDATA")
                self._copy(data)

    def _question(self, RRset question):
        self._name(question.name, True)
        self._word(question.rdtype, 2)
        self._word(question.rdclass, 2)
        if len(question.items) != 0 or question.ttl != 0:
            raise WireFormatError("DNS questions contain only a name, class and type")

    def _section(self, list[RRset] section):
        for rrset in section:
            for item in rrset.items:
                self._name(rrset.name, True)
                self._word(rrset.rdtype, 2)
                self._word(rrset.rdclass, 2)
                self._word(rrset.ttl, 4)
                auto length_at = len(self.octets)
                self._word(0, 2)
                auto start = len(self.octets)
                self._rdata(rrset.rdtype, item)
                auto size = len(self.octets) - start
                self.octets[length_at] = size >> 8
                self.octets[length_at + 1] = size & 255

def _is_typed(int64 rdtype) -> bool:
    return rdtype == 1 or rdtype == 2 or rdtype == 5 or rdtype == 6 or rdtype == 12 or rdtype == 15 or rdtype == 16 or rdtype == 28 or rdtype == 33

def _rdata_type(Rdata item) -> int64:
    match item:
        case Rdata.A(_):
            return 1
        case Rdata.NS(_):
            return 2
        case Rdata.CNAME(_):
            return 5
        case Rdata.SOA(_, _, _, _, _, _, _):
            return 6
        case Rdata.PTR(_):
            return 12
        case Rdata.MX(_, _):
            return 15
        case Rdata.TXT(_):
            return 16
        case Rdata.AAAA(_):
            return 28
        case Rdata.SRV(_, _, _, _):
            return 33
        case Rdata.Generic(_):
            return 0

def _record_count(list[RRset] section) -> int64:
    auto count = 0
    for rrset in section:
        auto size = len(rrset.items)
        if size == 0:
            raise WireFormatError("resource record section contains an empty RRset")
        if size > 65535 - count:
            raise WireFormatError("DNS section has too many records")
        count = count + size
    return count

def _encode(Message msg) -> bytes:
    auto writer = _Writer([], {})
    writer._word(msg.id, 2)
    writer._word(msg.flags, 2)
    writer._word(len(msg.question), 2)
    writer._word(_record_count(msg.answer), 2)
    writer._word(_record_count(msg.authority), 2)
    writer._word(_record_count(msg.additional), 2)
    for question in msg.question:
        writer._question(question)
    writer._section(msg.answer)
    writer._section(msg.authority)
    writer._section(msg.additional)
    return bytes(writer.octets)

struct _Reader:
    bytes data
    int64 pos
    int64 limit

    def _require(self, int64 count):
        if count > self.limit - self.pos:
            raise WireFormatError("incomplete DNS field at byte " + str(self.pos))

    def _word(self, int64 width) -> int64:
        self._require(width)
        auto value = 0
        for offset in range(width):
            value = value << 8 | int64(self.data[self.pos + offset])
        self.pos = self.pos + width
        return value

    def _copy(self, int64 size) -> bytes:
        self._require(size)
        auto start = self.pos
        self.pos = self.pos + size
        return self.data[start:self.pos]

    def _name(self, bool compress) -> Name:
        list[bytes] labels = []
        auto cursor = self.pos
        auto boundary = self.limit
        auto pointer_ceiling = self.pos
        auto followed_pointer = False
        auto expanded_size = 1

        while cursor < boundary:
            auto octet = int64(self.data[cursor])
            cursor = cursor + 1
            if octet == 0:
                if not followed_pointer:
                    self.pos = cursor
                return Name(labels)
            if octet >= 192:
                if not compress:
                    raise WireFormatError("compressed name is prohibited in this field")
                if cursor >= boundary:
                    raise WireFormatError("incomplete DNS compression pointer")
                auto target = (octet & 63) << 8 | int64(self.data[cursor])
                if target < 12 or target >= pointer_ceiling:
                    raise WireFormatError(
                        "DNS compression pointer must point backward to a name",
                    )
                if not followed_pointer:
                    self.pos = cursor + 1
                    followed_pointer = True
                boundary = cursor - 1
                pointer_ceiling = target
                cursor = target
                continue
            if octet > 63:
                raise WireFormatError("unsupported DNS label prefix")
            if octet > boundary - cursor:
                raise WireFormatError("incomplete DNS label")
            expanded_size = expanded_size + octet + 1
            if expanded_size > 255:
                raise WireFormatError("expanded DNS name exceeds 255 octets")
            labels.append(self.data[cursor:cursor + octet])
            cursor = cursor + octet
        raise WireFormatError("missing DNS name terminator")

    def _rdata(self, int64 rdtype) -> Rdata:
        if rdtype == 1:
            if self.limit - self.pos != 4:
                raise WireFormatError("A RDATA must contain 4 octets")
            return Rdata.A(net.inet_ntop("ipv4", self._copy(4)))
        if rdtype == 2:
            return Rdata.NS(self._name(True))
        if rdtype == 5:
            return Rdata.CNAME(self._name(True))
        if rdtype == 6:
            auto mname = self._name(True)
            auto rname = self._name(True)
            auto serial = self._word(4)
            auto refresh = self._word(4)
            auto retry = self._word(4)
            auto expire = self._word(4)
            auto minimum = self._word(4)
            return Rdata.SOA(mname, rname, serial, refresh, retry, expire, minimum)
        if rdtype == 12:
            return Rdata.PTR(self._name(True))
        if rdtype == 15:
            auto preference = self._word(2)
            return Rdata.MX(preference, self._name(True))
        if rdtype == 16:
            if self.pos == self.limit:
                raise WireFormatError("TXT requires at least one character string")
            list[bytes] strings = []
            while self.pos < self.limit:
                auto size = self._word(1)
                strings.append(self._copy(size))
            return Rdata.TXT(strings)
        if rdtype == 28:
            if self.limit - self.pos != 16:
                raise WireFormatError("AAAA RDATA must contain 16 octets")
            return Rdata.AAAA(net.inet_ntop("ipv6", self._copy(16)))
        if rdtype == 33:
            auto priority = self._word(2)
            auto weight = self._word(2)
            auto port = self._word(2)
            return Rdata.SRV(priority, weight, port, self._name(False))
        return Rdata.Generic(self._copy(self.limit - self.pos))

    def _questions(self, int64 count) -> list[RRset]:
        list[RRset] questions = []
        for index in range(count):
            auto name = self._name(True)
            auto rdtype = self._word(2)
            auto rdclass = self._word(2)
            questions.append(RRset(name, rdclass, rdtype, 0, []))
        return questions

    def _section(self, int64 count) -> list[RRset]:
        list[RRset] section = []
        dict[(bytes, int64, int64), int64] offsets = {}
        for record in range(count):
            auto name = self._name(True)
            auto rdtype = self._word(2)
            auto rdclass = self._word(2)
            auto ttl = self._word(4)
            auto size = self._word(2)
            self._require(size)
            auto packet_end = self.limit
            auto rdata_end = self.pos + size
            self.limit = rdata_end
            auto item = self._rdata(rdtype)
            self.limit = packet_end
            if self.pos != rdata_end:
                raise WireFormatError(
                    "record data does not consume its declared length",
                )

            auto key = (_name_key(name, True), rdclass, rdtype)
            if key in offsets:
                auto rrset = section[offsets[key]]
                if ttl < rrset.ttl:
                    rrset.ttl = ttl
                rrset.items.append(item)
            else:
                offsets[key] = len(section)
                section.append(RRset(name, rdclass, rdtype, ttl, [item]))
        return section

def _decode(bytes data) -> Message:
    if len(data) > 65535:
        raise WireFormatError("DNS message exceeds 65535 octets")
    auto reader = _Reader(data, 0, len(data))
    auto id = reader._word(2)
    auto flags = reader._word(2)
    auto qdcount = reader._word(2)
    auto ancount = reader._word(2)
    auto nscount = reader._word(2)
    auto arcount = reader._word(2)
    auto question = reader._questions(qdcount)
    auto answer = reader._section(ancount)
    auto authority = reader._section(nscount)
    auto additional = reader._section(arcount)
    if reader.pos != len(data):
        raise WireFormatError("trailing octets after DNS message")
    return Message(id, flags, question, answer, authority, additional)

# The query layer checks status after validating the response header. A truncated
# UDP body can be incomplete, so this check needs only the header flags.
def _check_response_status(int64 flags):
    if flags & 0x0200 != 0:
        raise Truncated("DNS response is truncated")
    auto rcode = flags & 0x000f
    if rcode == 0:
        return
    if rcode == 3:
        raise NXDOMAIN("DNS name does not exist")
    if rcode == 2:
        raise ServFail("DNS server failure")
    raise ResponseError("DNS response error code " + str(rcode))

# The resolver passes the RRsets selected after following aliases and matching
# the requested type. An empty selection under NOERROR represents NODATA.
def _require_answer(list[RRset] selected):
    for rrset in selected:
        if len(rrset.items) > 0:
            return
    raise NoAnswer("DNS response has no records of the requested type")

# A budget shared by all queries in one resolution. Every attempt computes its
# deadline from the same lifetime limit and its own monotonic start time.
struct _DeadlineBudget:
    int64 _timeout_ns
    int64 _lifetime_deadline_ns

    def _start(f64 timeout, f64 lifetime, int64 now_ns) -> _DeadlineBudget:
        auto timeout_ns = _duration_ns(timeout)
        auto lifetime_ns = _duration_ns(lifetime)
        return _DeadlineBudget(timeout_ns, _add_duration(now_ns, lifetime_ns))

    def _attempt_deadline(self, int64 now_ns) -> int64:
        auto deadline = min(
            _add_duration(now_ns, self._timeout_ns),
            self._lifetime_deadline_ns,
        )
        _check_deadline(deadline, now_ns)
        return deadline

def _duration_ns(f64 seconds) -> int64:
    if not math.isfinite(seconds) or seconds < 0.0:
        raise ValueError("DNS duration must be finite and nonnegative")
    auto nanos = math.ceil(seconds * 1000000000.0)
    # 2^63 is exactly representable as f64; int64 max is rounded up to it.
    if nanos >= 9223372036854775808.0:
        return 9223372036854775807
    return int64(nanos)

def _add_duration(int64 now_ns, int64 duration_ns) -> int64:
    if now_ns < 0:
        raise ValueError("DNS monotonic timestamp must be nonnegative")
    auto limit = 9223372036854775807
    if duration_ns > limit - now_ns:
        return limit
    return now_ns + duration_ns

# Check before applying a socket deadline and after receiving a reply.
def _check_deadline(int64 deadline_ns, int64 now_ns):
    if now_ns >= deadline_ns:
        raise Timeout("DNS query deadline expired")

# Resolver settings for UDP/TCP DNS lookups. Timeout and lifetime are in seconds.
struct Resolver:
    list[str] nameservers = ["127.0.0.1", "::1"]
    list[Name] search = []
    int64 ndots = 1
    f64 timeout = 2.0
    f64 lifetime = 5.0

    def from_file(str path) -> Resolver:
        "Load resolver settings. A missing file returns the defaults."
        auto text = ""
        try:
            text = fs.read_file(path)
        except FileNotFoundError:
            return Resolver()

        auto config = Resolver()
        auto parsed = _parse_resolv_conf(text, config.ndots)
        if len(parsed.nameservers) > 0:
            config.nameservers = parsed.nameservers
        config.search = parsed.search
        config.ndots = parsed.ndots
        return config

    def system() -> Resolver:
        "Read /etc/resolv.conf on Linux and macOS. Elsewhere return defaults."
        if sys.platform() in ["linux", "darwin"]:
            return Resolver.from_file("/etc/resolv.conf")
        return Resolver()

    def _effective_nameservers(self) -> list[str]:
        if len(self.nameservers) == 0:
            return Resolver().nameservers
        return self.nameservers

    def _qualify(self, str name) -> list[Name]:
        return _candidate_names(name, self.search, self.ndots)

# The directives understood by the resolver. Defaults for the other resolver
# settings do not depend on the file.
struct _ResolverFile:
    list[str] nameservers
    list[Name] search
    int64 ndots

def _parse_resolv_conf(str text, int64 default_ndots) -> _ResolverFile:
    list[str] nameservers = []
    list[Name] search = []
    list[Name] domain = []
    auto ndots = default_ndots
    for line in text.splitlines():
        list[str] fields = []
        for field in line.split():
            if field.startswith("#") or field.startswith(";"):
                break
            fields.append(field)
        if len(fields) < 2:
            continue
        match fields[0]:
            case "nameserver":
                auto address = fields[1]
                if _is_nameserver(address):
                    nameservers.append(address)
            case "search":
                list[Name] valid = []
                for index in range(1, len(fields)):
                    try:
                        valid.append(_query_name(fields[index]))
                    except WireFormatError:
                        pass
                if len(valid) > 0:
                    search = valid
            case "domain":
                try:
                    domain = [_query_name(fields[1])]
                except WireFormatError:
                    pass
            case "options":
                for index in range(1, len(fields)):
                    auto option = fields[index]
                    if option.startswith("ndots:"):
                        ndots = _parse_ndots(option[6:], ndots)
            case _:
                pass
    if len(search) == 0:
        search = domain
    return _ResolverFile(nameservers, search, ndots)

def _is_nameserver(str address) -> bool:
    auto family = "ipv4"
    if address.find(":") >= 0:
        family = "ipv6"
    try:
        net.inet_pton(family, address)
        return True
    except ValueError:
        return False

def _parse_ndots(str text, int64 previous) -> int64:
    auto digits = bytes(text)
    if len(digits) == 0:
        return previous
    auto value = 0
    for index in range(len(digits)):
        auto digit = int64(digits[index]) - 48
        if digit < 0 or digit > 9:
            return previous
        # Keep arbitrarily long decimal options within the POSIX resolver limit.
        value = min(value * 10 + digit, 15)
    return value

# Normalized absolute names, in query order. The dots counted here are label
# separators, so an escaped literal dot does not affect the ndots threshold.
def _candidate_names(str text, list[Name] search, int64 ndots) -> list[Name]:
    auto parsed = _parse_query_name(text)
    auto name = parsed[0]
    if parsed[1] or len(search) == 0:
        return [name]

    list[Name] result = []
    dict[bytes, bool] seen = {}
    auto key = _name_key(name, True)
    auto absolute_first = len(name.labels) - 1 >= ndots
    if absolute_first:
        result.append(name)
        seen[key] = True

    for suffix in search:
        list[bytes] labels = []
        for label in name.labels:
            labels.append(label)
        for label in suffix.labels:
            labels.append(label)
        auto candidate = Name(labels)
        try:
            auto candidate_key = _name_key(candidate, True)
            if candidate_key not in seen:
                result.append(candidate)
                seen[candidate_key] = True
        except WireFormatError:
            # A search expansion may be too long while the bare name is valid.
            pass

    if not absolute_first and key not in seen:
        result.append(name)
    return result
