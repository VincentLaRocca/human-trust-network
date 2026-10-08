#!/usr/bin/env python3
"""One confirmed regtest close, then the local tally.

builder broadcasts the spend. fetch_anchor must accept it. live_require checks
one real BIP-340 signature over the operation id. consider() then advances or
holds each local pointer.

The split is still the Barabasi-Albert weight model. A confirmed transaction
is the same proposal for every observer. This script does not prove a rate.
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
    proof = fetch_anchor(args.url, args.user, args.password, args.txid, args.vout, spending, bundle)
    secret = hashlib.sha256(b"regtest-hub-witness").digest()
    key = PrivateKey(secret)
    witnesses = WitnessSet(1, (key.sec(),))
    op = hashlib.sha256(b"live-op").digest()
    sig = key.schnorr_sign(op).serialize()
    hub_key = key.xonly()
    require = live_require(witnesses)
    title = bytes([7]) * 32
    nxt = bytes([8]) * 32
    proposal = Proposal(title, nxt, b"live", op, {hub_key: sig}, bundle, bytes.fromhex(args.txid), args.vout, proof)
    adj = barabasi(args.nodes, 6, __import__("random").Random(args.seed))
    hub = max(range(args.nodes), key=lambda i: eigenvector(adj)[i])
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
