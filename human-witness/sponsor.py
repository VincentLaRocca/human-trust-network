#!/usr/bin/env python3
"""Sponsor pairing for a node key.

A bond is an accountability edge from the introducing key to the node key.
It is not an identity, and it does not raise the node's score. A miss by
the node cuts this client's edge to that node and to the sponsor. The
closed seal stays closed.
"""

from __future__ import annotations

from dataclasses import dataclass

from max_path import Edge, Neighborhood, Reject


@dataclass(frozen=True)
class SponsorBond:
    sponsor: bytes
    node: bytes
    weight: float

    def __post_init__(self) -> None:
        if self.sponsor == self.node:
            raise Reject("sponsor cannot be the node")
        if not 0.0 < self.weight <= 1.0:
            raise Reject("sponsor weight must be in (0, 1]")


def edge(bond: SponsorBond) -> Edge:
    return Edge(bond.sponsor, bond.node, bond.weight)


def merge(neigh: Neighborhood, bonds: list[SponsorBond]) -> Neighborhood:
    """Add introduction edges the observer does not already hold."""
    have = {(item.src, item.dst) for item in neigh.edges}
    extra = [edge(bond) for bond in bonds if (bond.sponsor, bond.node) not in have]
    return Neighborhood(list(neigh.edges) + extra)


def sponsors_of(bonds: list[SponsorBond], node: bytes) -> set[bytes]:
    return {bond.sponsor for bond in bonds if bond.node == node}


def cut_misses(
    neigh: Neighborhood,
    observer: bytes,
    failed: set[bytes],
    bonds: list[SponsorBond],
) -> list[Edge]:
    """Drop this client's edges to missed signers and to their sponsors.

    Also drop the introduction edge itself. Other observers' edges stay.
    """
    blamed = set(failed)
    for node in failed:
        blamed |= sponsors_of(bonds, node)
    kept: list[Edge] = []
    for item in neigh.edges:
        if item.src == observer and item.dst in blamed:
            continue
        if item.dst in failed and item.src in sponsors_of(bonds, item.dst):
            continue
        kept.append(item)
    return kept
