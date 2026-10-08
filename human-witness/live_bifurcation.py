#!/usr/bin/env python3
"""One confirmed regtest close, then the local tally.

The WIF that signs the Bitcoin input is the witness key. live_require checks
that key's BIP-340 signature over the operation id. Edges that touched the
hub's graph id are rewritten to that same x-only key, which is what weigh
scores. The graph id is an index, not a second identity.

The Bitcoin signature and the operation-id signature are different messages.
The split is still the weight model. This script does not prove a rate.
The builder spend is not a Taproot script path, so the witness lock is ignored.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "btc-root"))
sys.path.insert(0, str(ROOT / "personal-chains"))
sys.path.insert(0, str(ROOT / "human-witness"))

from builder import build  # noqa: E402
from client_observer import LocalView, Outcome, Proposal, consider  # noqa: E402
from live_require import live_require  # noqa: E402
from max_path import Edge, Neighborhood  # noqa: E402
from regtest_anchor import fetch_anchor  # noqa: E402
from schema_encoder import PrivateKey, WitnessSet  # noqa: E402

from bifurcation import barabasi, eigenvector, neighborhood  # noqa: E402

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class IdentityRegistry:
    def __init__(self) -> None:
        self.graph_to_key: dict[int, bytes] = {}
        self.key_to_graph: dict[bytes, int] = {}

    def bind(self, graph_id: int, xonly: bytes) -> None:
        if graph_id in self.graph_to_key or xonly in self.key_to_graph:
            raise SystemExit("identity already bound")
        self.graph_to_key[graph_id] = xonly
        self.key_to_graph[xonly] = graph_id


def wif_secret(wif: str) -> bytes:
    n = 0
    for char in wif:
        n = n * 58 + B58.index(char)
    raw = n.to_bytes(38, "big").lstrip(b"\x00")
    pad = 0
    for char in wif:
        if char != "1":
            break
        pad += 1
    raw = b"\x00" * pad + raw
    if hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        raise SystemExit("bad wif checksum")
    body = raw[:-4]
    if body[0] != 0xEF:
        raise SystemExit("refusing a non-regtest WIF")
    if len(body) != 34 or body[-1] != 1:
        raise SystemExit("compressed regtest WIF required")
    return body[1:33]


def hub_neighborhood(adj, observer: int, hub: int, hub_key: bytes) -> Neighborhood:
    edges = []
    for edge in neighborhood(adj, observer).edges:
        src = hub_key if edge.src == bytes([hub]) else edge.src
        dst = hub_key if edge.dst == bytes([hub]) else edge.dst
        if src == dst:
            continue
        edges.append(Edge(src, dst, edge.weight))
    return Neighborhood(edges)


def run(args: argparse.Namespace) -> dict[str, float]:
    bundle = bytes.fromhex(args.bundle)
    spending = build(
        args.url, args.user, args.password,
        args.txid, args.vout, args.dest, args.amount, args.bundle, args.wif, args.mine_to,
    )
    proof, _lock = fetch_anchor(args.url, args.user, args.password, args.txid, args.vout, spending, bundle)
    key = PrivateKey(wif_secret(args.wif))
    witnesses = WitnessSet(1, (key.sec(),))
    op = hashlib.sha256(b"live-op").digest()
    sig = key.schnorr_sign(op).serialize()
    hub_key = key.xonly()
    require = live_require(witnesses)
    adj = barabasi(args.nodes, 6, __import__("random").Random(args.seed))
    hub = max(range(args.nodes), key=lambda i: eigenvector(adj)[i])
    registry = IdentityRegistry()
    registry.bind(hub, hub_key)
    if registry.key_to_graph[hub_key] != hub:
        raise SystemExit("witness key is not the hub")
    title = bytes([7]) * 32
    nxt = bytes([8]) * 32
    proposal = Proposal(title, nxt, b"live", op, {hub_key: sig}, bundle, bytes.fromhex(args.txid), args.vout, proof)
    advanced = frozen = other = 0
    for observer in range(args.nodes):
        if observer == hub:
            continue
        view = LocalView(title)
        outcome, _ = consider(view, proposal, require, hub_neighborhood(adj, observer, hub, hub_key), bytes([observer]))
        if outcome is Outcome.ADVANCED and view.title_seal == nxt and title in view.spent:
            advanced += 1
        elif outcome is Outcome.SPENT_UNADVANCED and view.title_seal == title and title in view.spent:
            frozen += 1
        else:
            other += 1
    observers = advanced + frozen + other
    if other:
        raise SystemExit(f"objective or anchor failed for {other} observers")
    return {"advanced": advanced / observers, "spent_unadvanced": frozen / observers, "observers": float(observers), "spending": spending}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:18443")
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--txid", required=True)
    parser.add_argument("--vout", type=int, required=True)
    parser.add_argument("--dest", required=True)
    parser.add_argument("--amount", type=float, required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--wif", required=True)
    parser.add_argument("--mine-to", required=True)
    parser.add_argument("--nodes", type=int, default=80)
    parser.add_argument("--seed", type=int, default=1000)
    args = parser.parse_args()
    result = run(args)
    print("spending", result["spending"])
    print(f"advanced {result['advanced']:.3f}")
    print(f"spent_unadvanced {result['spent_unadvanced']:.3f}")
    print(f"observers {int(result['observers'])}")


if __name__ == "__main__":
    main()
