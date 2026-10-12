"""(c) Rewards come only from fees actually paid in sats. Conservation: sum(out) == fees_in exactly.
There is no mint, emission, inflation or block-reward path in this package."""


class RewardError(Exception):
    pass


def distribute(fee_pool_sats: int, cluster_weights: dict, cluster_members: dict):
    """cluster_weights: {cluster_id: weight}; cluster_members: {cluster_id: [attester,...]}.
    Integer sats; remainder goes deterministically by sorted key. A cluster's share is split among its
    members (mirrors gain nothing by multiplying keys)."""
    if not isinstance(fee_pool_sats, int) or fee_pool_sats < 0:
        raise RewardError("fee pool must be non-negative integer sats from real fees")
    tot = sum(cluster_weights.values())
    payouts = {}
    if tot <= 0 or fee_pool_sats == 0:
        return payouts
    alloc = {}
    for cid in sorted(cluster_weights):
        alloc[cid] = int(fee_pool_sats * cluster_weights[cid] // tot)
    rem = fee_pool_sats - sum(alloc.values())
    for cid in sorted(cluster_weights)[:rem]:
        alloc[cid] += 1
    for cid in sorted(alloc):
        mem = sorted(cluster_members[cid])
        base, r = divmod(alloc[cid], len(mem))
        for i, m in enumerate(mem):
            payouts[m] = payouts.get(m, 0) + base + (1 if i < r else 0)
    if sum(payouts.values()) != fee_pool_sats:
        raise RewardError("conservation violated")
    return payouts
