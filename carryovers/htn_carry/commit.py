"""(f)+(g) Commitments. Every input is hashed and sequenced before any output that uses it.
Commit-reveal for attestations: reveal must match an earlier commit."""
import hashlib, json


def h(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class CommitError(Exception):
    pass


class CommitLog:
    """Append-only ordered log. Position = seq (canonical order, D10 rule 2). Shared by every namespace."""

    def __init__(self):
        self.items = []          # (seq, kind, digest)
        self.by_digest = {}

    def commit(self, kind, digest):
        if digest in self.by_digest:
            raise CommitError("duplicate commitment")
        seq = len(self.items)
        self.items.append((seq, kind, digest))
        self.by_digest[digest] = seq
        return seq

    def seq_of(self, digest):
        if digest not in self.by_digest:
            raise CommitError("input never committed")
        return self.by_digest[digest]

    def root(self):
        return h([list(i) for i in self.items])


def attest_commitment(attester, namespace, subject, epoch, outcome, salt):
    return h({"a": attester, "ns": namespace, "s": subject, "e": epoch, "o": outcome, "salt": salt})


def check_reveal(log: CommitLog, commit_seq, reveal_seq_floor, attester, namespace, subject, epoch, outcome, salt):
    """A reveal is valid only if it opens a commitment that was sequenced before the reveal phase opened."""
    d = attest_commitment(attester, namespace, subject, epoch, outcome, salt)
    seq = log.seq_of(d)
    if seq != commit_seq:
        raise CommitError("reveal does not open the claimed commitment")
    if seq >= reveal_seq_floor:
        raise CommitError("late commit: committed after reveal phase opened")
    return True
