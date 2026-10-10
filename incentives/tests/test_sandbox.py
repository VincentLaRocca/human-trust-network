"""Lightning sandbox: safety checks always; live checks only when it is running."""
import hashlib
import os
import threading
import time
from pathlib import Path

import pytest

from htn import sandbox as sb

DEFAULT_PORTS = {8332, 8333, 18332, 18333, 18443, 18444, 38332, 38333, 9735, 10009, 8080}


def test_sandbox_is_hard_wired_to_regtest():
    assert sb.NETWORK == "regtest"
    src = Path(sb.__file__).read_text()
    assert "mainnet" not in src and "--bitcoin.mainnet" not in src and "-testnet" not in src


def test_sandbox_uses_private_non_default_ports():
    ports = {sb.BTC_RPC_PORT} | {p for n in sb.NODES.values() for p in n.values()}
    assert not ports & DEFAULT_PORTS  # never collide with or reach other nodes on this PC
    src = Path(sb.__file__).read_text()
    assert "0.0.0.0" not in src and "-listen=0" in src and "-rpcbind=127.0.0.1" in src


def test_tools_folder_is_gitignored():
    assert "tools/" in (sb.REPO / ".gitignore").read_text().split()


live = pytest.mark.skipif(not sb._bitcoind_up() if (sb.BIN / "bitcoin-cli.exe").exists() else True,
                          reason="sandbox not running (python -m htn sandbox up)")


@live
def test_live_hold_invoice_settles_only_with_secret():
    secret = os.urandom(32)
    h = hashlib.sha256(secret).hexdigest()
    inv = sb.lncli("worker", "addholdinvoice", h, "--amt=500")
    result = {}
    t = threading.Thread(target=lambda: result.update(
        sb.lncli("client", "payinvoice", "--force", "--json", inv["payment_request"], timeout=120)))
    t.start()
    for _ in range(60):
        if sb.lncli("worker", "lookupinvoice", h)["state"] == "ACCEPTED":
            break
        time.sleep(1)
    with pytest.raises(sb.SandboxError):          # wrong secret can't settle
        sb.lncli("worker", "settleinvoice", os.urandom(32).hex())
    assert sb.lncli("worker", "lookupinvoice", h)["state"] == "ACCEPTED"
    sb.lncli("worker", "settleinvoice", secret.hex())
    t.join(60)
    assert sb.lncli("worker", "lookupinvoice", h)["state"] == "SETTLED"
    assert result.get("status") == "SUCCEEDED"


def test_sandbox_hold_expiry_matches_payment_math():
    from htn import payments
    assert f"--invoices.holdexpirydelta={payments.LND_HOLD_EXPIRY_DELTA}" in Path(sb.__file__).read_text()
