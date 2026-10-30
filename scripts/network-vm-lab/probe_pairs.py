"""Which peer namespaces carry a transaction's traffic, so probes test that transaction's path.

The verifier and the packet monitor used to ping the primary pair (198.51.100.2 <-> .6) for every
case. A transaction on another address set was then never probed: a rolled-back case ended with
forward/reverse true, carried by the primary route (independent review of the 2026-10-30 lab).

A pair is chosen by the transaction's own route. Two address sets are built in; a lab that adds more
lists them in /var/lib/heliopause-vm-lab/probe-pairs.json as
  {"<route>": {"client": ["<namespace>", "<address>"], "workload": ["<namespace>", "<address>"]}}.
A route with no pair fails closed rather than falling back to the primary.
"""
import ipaddress
import json
import re
from pathlib import Path

PAIRS_FILE = Path('/var/lib/heliopause-vm-lab/probe-pairs.json')

DEFAULT_PAIRS = {
    '198.51.100.6/32': (('p6-client', '198.51.100.2'), ('p6-workload', '198.51.100.6')),
    '198.51.100.14/32': (('p6-client', '198.51.100.10'), ('p6-workload', '198.51.100.14')),
}

_NAMESPACE = re.compile(r'[a-z0-9][a-z0-9-]{0,30}')


def _endpoint(value, where):
    if not isinstance(value, list) or len(value) != 2 or not all(isinstance(v, str) for v in value):
        raise ValueError(where + ' must be [namespace, address]')
    namespace, address = value
    if not _NAMESPACE.fullmatch(namespace):
        raise ValueError(where + ' namespace is invalid')
    if ipaddress.ip_address(address).version != 4:
        raise ValueError(where + ' address must be IPv4')
    return (namespace, address)


def load_pairs(path=PAIRS_FILE):
    pairs = dict(DEFAULT_PAIRS)
    if not path.exists():
        return pairs
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict) or len(raw) > 16:
        raise ValueError('probe-pairs.json must be an object of at most 16 routes')
    for route, pair in raw.items():
        network = ipaddress.ip_network(route)
        if network.version != 4 or network.prefixlen != 32:
            raise ValueError('probe pair route must be an IPv4 /32')
        if not isinstance(pair, dict) or set(pair) != {'client', 'workload'}:
            raise ValueError('probe pair must name exactly client and workload')
        pairs[str(network)] = (_endpoint(pair['client'], route + ' client'), _endpoint(pair['workload'], route + ' workload'))
    return pairs


def pair_for(routes, path=PAIRS_FILE):
    """The (client, workload) endpoints for the first route that has a pair; never a fallback."""
    pairs = load_pairs(path)
    for route in routes:
        if route in pairs:
            return pairs[route]
    raise ValueError('no lab probe pair for the transaction routes')
