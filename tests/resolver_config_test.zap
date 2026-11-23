import dns
import fs
import os
import sys

def _assert_defaults(dns.Resolver config):
    assert config.nameservers == ["127.0.0.1", "::1"]
    assert len(config.search) == 0
    assert config.ndots == 1
    assert config.timeout == 2.0
    assert config.lifetime == 5.0

@test
def _resolver_defaults_and_explicit_settings():
    auto config = dns.Resolver()
    _assert_defaults(config)

    config.nameservers.append("192.0.2.53")
    config.search.append(dns.Name([b"local"]))
    _assert_defaults(dns.Resolver())

    auto explicit = dns.Resolver(
        nameservers=["192.0.2.53", "2001:db8::53"],
        search=[dns.Name([b"corp", b"test"])],
        ndots=3,
        timeout=0.25,
        lifetime=1.75,
    )
    assert explicit.nameservers == ["192.0.2.53", "2001:db8::53"]
    assert explicit.search[0].labels == [b"corp", b"test"]
    assert explicit.ndots == 3
    assert explicit.timeout == 0.25
    assert explicit.lifetime == 1.75

@test
def _resolver_loads_existing_files():
    auto directory = fs.mkdtemp()
    try:
        auto path = os.path_join(directory, "resolv.conf")
        fs.write_file(
            path,
            "nameserver 192.0.2.53\nsearch corp.test lab.test\noptions ndots:3\n",
        )
        auto config = dns.Resolver.from_file(path=path)
        assert config.nameservers == ["192.0.2.53"]
        assert len(config.search) == 2
        assert config.search[0].labels == [b"corp", b"test"]
        assert config.search[1].labels == [b"lab", b"test"]
        assert config.ndots == 3
        assert config.timeout == 2.0 and config.lifetime == 5.0
    finally:
        fs.rmtree(directory)

@test
def _resolver_falls_back_for_missing_empty_and_invalid_nameservers():
    auto directory = fs.mkdtemp()
    try:
        auto path = os.path_join(directory, "resolv.conf")
        _assert_defaults(dns.Resolver.from_file(path))
        fs.write_file(path, "")
        _assert_defaults(dns.Resolver.from_file(path))
        fs.write_file(path, "nameserver invalid\nsearch corp.test\noptions ndots:0\n")
        auto config = dns.Resolver.from_file(path)
        assert config.nameservers == ["127.0.0.1", "::1"]
        assert config.search[0].labels == [b"corp", b"test"]
        assert config.ndots == 0
        assert config.timeout == 2.0 and config.lifetime == 5.0
    finally:
        fs.rmtree(directory)

@test
def _resolver_propagates_nonmissing_read_failures():
    auto directory = fs.mkdtemp()
    try:
        auto caught = False
        try:
            dns.Resolver.from_file(directory)
        except FileNotFoundError:
            assert False
        except OSError:
            caught = True
        assert caught
    finally:
        fs.rmtree(directory)

@test
def _resolver_system_uses_platform_configuration():
    auto system = dns.Resolver.system()
    if sys.platform() in ["linux", "darwin"]:
        auto direct = dns.Resolver.from_file("/etc/resolv.conf")
        assert system.nameservers == direct.nameservers
        assert system.ndots == direct.ndots
        assert len(system.search) == len(direct.search)
        for index in range(len(system.search)):
            assert system.search[index].labels == direct.search[index].labels
        assert system.timeout == direct.timeout and system.lifetime == direct.lifetime
    else:
        _assert_defaults(system)
