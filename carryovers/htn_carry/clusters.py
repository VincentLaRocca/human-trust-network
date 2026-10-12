"""(g) Correlated/mirrored attesters count as one source and share ONE exposure cap.
Copying is discounted, never slashed."""


class UF:
    def __init__(self, keys):
        self.p = {k: k for k in keys}

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def clusters(registry, epoch, reveals, h_min=3, mirror_min=5, mirror_agree=0.95):
    """reveals: list of (attester, subject, epoch, outcome). Returns {attester: cluster_id}.
    Links: shared funding ancestry (same tx id prefix), newcomers (<h_min epochs) all in one 'new' cluster,
    mirrored outcomes (>=mirror_agree agreement over >=mirror_min shared items)."""
    keys = list(registry.attesters)
    uf = UF(keys + ["__new__"])
    by_tx = {}
    for k, a in registry.attesters.items():
        by_tx.setdefault(a.funding_outpoint.split(":")[0], []).append(k)
        if epoch - a.first_epoch < h_min:
            uf.union(k, "__new__")
    for ks in by_tx.values():
        for k in ks[1:]:
            uf.union(ks[0], k)
    votes = {}
    for a, s, e, o in reveals:
        votes.setdefault(a, {})[(s, e)] = o
    vk = sorted(votes)
    for i, x in enumerate(vk):
        for y in vk[i + 1:]:
            shared = set(votes[x]) & set(votes[y])
            if len(shared) >= mirror_min:
                agree = sum(votes[x][s] == votes[y][s] for s in shared) / len(shared)
                if agree >= mirror_agree:
                    uf.union(x, y)
    return {k: uf.find(k) for k in keys}
