import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from htn_carry.commit import CommitLog, attest_commitment
from htn_carry.registry import Registry


def make_world(n_honest=5, epoch=10, ns="delivery-ns"):
    log, reg = CommitLog(), Registry()
    for i in range(n_honest):
        reg.register(f"h{i}", 250, f"tx{i}:0", 0)
    return log, reg


def commit_reveals(log, votes, ns, epoch):
    """votes: list of (attester, subject, outcome). Commits all, opens reveal phase, returns reveals + floor."""
    rev = []
    for a, s, o in votes:
        salt = f"salt-{a}-{s}-{epoch}"
        seq = log.commit("attest", attest_commitment(a, ns, s, epoch, o, salt))
        rev.append({"attester": a, "namespace": ns, "subject": s, "epoch": epoch, "outcome": o, "salt": salt,
                    "commit_seq": seq})
    floor = log.commit("phase", f"reveal-open-{ns}-{epoch}-{len(log.items)}")
    return rev, floor
