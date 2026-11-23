@test
def _cache_expiry_and_key_isolation():
    auto cache = Cache(max_size=4)
    auto name = _query_name("Host.example.")
    auto other_case = _query_name("host.EXAMPLE")
    auto other = _query_name("other.example")
    auto value = _CacheValue.Positive(b"wire", "192.0.2.53", 53)
    cache._put(name, 1, 1, value, 2, 100)
    assert cache._get(other_case, 1, 1, 2000000099).is_some()
    assert not cache._get(name, 28, 1, 100).is_some()
    assert not cache._get(name, 1, 3, 100).is_some()
    assert not cache._get(other, 1, 1, 100).is_some()
    assert not cache._get(name, 1, 1, 2000000100).is_some()
    assert not cache._get(name, 1, 1, 2000000101).is_some()

@test
def _cache_zero_ttl_shrinks_and_replacement_refreshes_expiry():
    auto cache = Cache(max_size=2)
    auto name = _query_name("host.example")
    auto value = _CacheValue.Positive(b"wire", "192.0.2.53", 53)
    cache._put(name, 1, 1, value, 0, 1)
    assert not cache._get(name, 1, 1, 1).is_some()
    cache._put(name, 1, 1, value, 1, 1)
    cache._put(name, 1, 1, value, 2, 2)
    assert cache._get(name, 1, 1, 1000000001).is_some()
    cache._put(name, 1, 1, value, 0, 1000000001)
    assert not cache._get(name, 1, 1, 1000000001).is_some()

@test
def _cache_lru_access_and_single_entry_eviction():
    auto value = _CacheValue.Positive(b"wire", "192.0.2.53", 53)
    auto first = _query_name("first.example")
    auto second = _query_name("second.example")
    auto third = _query_name("third.example")
    auto cache = Cache(max_size=2)
    cache._put(first, 1, 1, value, 10, 0)
    cache._put(second, 1, 1, value, 10, 0)
    assert cache._get(first, 1, 1, 0).is_some()
    cache._put(third, 1, 1, value, 10, 0)
    assert not cache._get(second, 1, 1, 0).is_some()
    assert cache._get(first, 1, 1, 0).is_some()
    assert cache._get(third, 1, 1, 0).is_some()

    auto single = Cache(max_size=1)
    single._put(first, 1, 1, value, 10, 0)
    single._put(second, 1, 1, value, 10, 0)
    assert not single._get(first, 1, 1, 0).is_some()
    assert single._get(second, 1, 1, 0).is_some()
    single.flush()
    assert not single._get(second, 1, 1, 0).is_some()
    single._put(third, 1, 1, value, 10, 0)
    assert single._get(third, 1, 1, 0).is_some()

def _soa(Name owner, int64 rdclass, int64 ttl, int64 minimum) -> RRset:
    return RRset(owner, rdclass, 6, ttl, [Rdata.SOA(owner, owner, 1, 2, 3, 4, minimum)])

@test
def _negative_ttl_uses_closest_same_class_soa_and_alias_ttl():
    auto owner = _query_name("target.deep.example")
    auto outer = _soa(_query_name("example"), 1, 5, 1)
    auto closest = _soa(_query_name("DEEP.example"), 1, 30, 11)
    auto unrelated = _soa(_query_name("other.example"), 1, 1, 1)
    auto wrong_class = _soa(owner, 3, 1, 1)
    auto chain = _AnswerChain(owner, None, 200)
    auto reply = Message(
        0,
        0x8183,
        [],
        [],
        [outer, closest, unrelated, wrong_class],
        [],
    )
    assert _negative_ttl(chain, reply, 1) == 11

    reply.authority = [_soa(owner, 1, 3, 60)]
    assert _negative_ttl(chain, reply, 1) == 3
    assert _negative_ttl(_AnswerChain(owner, None, 2), reply, 1) == 2
    reply.authority = [_soa(owner, 1, 3, 0)]
    assert _negative_ttl(chain, reply, 1) == 0

    reply.authority = [unrelated, wrong_class]
    reply.additional = [closest]
    assert _negative_ttl(chain, reply, 1) == 0

@test
def _negative_cache_expiry_and_alias_specific_nxdomain():
    auto owner = _query_name("host.example")
    auto question = RRset(owner, 1, 1, 0, [])
    auto authority = _soa(_query_name("example"), 1, 4, 2)
    auto cache = Cache(max_size=4)
    auto reply = Message(0, 0x8183, [question], [], [authority], [])
    _remember_nxdomain(cache, question, reply, 1)
    assert cache._get(owner, 28, 1, 2000000000).is_some()
    assert not cache._get(owner, 1, 1, 2000000001).is_some()
    assert not cache._get(owner, 28, 3, 0).is_some()

    auto target = _query_name("missing.example")
    reply.answer = [RRset(owner, 1, 5, 1, [Rdata.CNAME(target)])]
    _remember_nxdomain(cache, question, reply, 1)
    assert cache._get(owner, 1, 1, 1000000000).is_some()
    assert not cache._get(owner, 5, 1, 1).is_some()
    assert not cache._get(target, 1, 1, 1).is_some()
    assert not cache._get(owner, 1, 1, 1000000001).is_some()

    auto empty = Cache(max_size=1)
    reply.answer = []
    reply.authority = []
    _remember_nxdomain(empty, question, reply, 1)
    assert not empty._get(owner, 1, 1, 1).is_some()

@test
def _fresh_namewide_and_type_specific_entries_override_each_other():
    auto cache = Cache(max_size=4)
    auto host = _query_name("host.example")
    auto value = _CacheValue.Positive(b"wire", "192.0.2.53", 53)
    cache._put(host, 1, 1, value, 10, 0)
    cache._put(host, 28, 1, value, 10, 0)
    cache._put(host, 0, 1, _CacheValue.MissingName, 1, 0)
    assert cache._get(host, 28, 1, 0).is_some()
    assert not cache._get(host, 1, 1, 1000000000).is_some()
    assert not cache._get(host, 28, 1, 1000000000).is_some()
    cache._put(host, 0, 1, _CacheValue.MissingName, 10, 0)
    cache._put(host, 1, 1, value, 10, 1)
    assert cache._get(host, 1, 1, 1).is_some()
    assert not cache._get(host, 28, 1, 1).is_some()
