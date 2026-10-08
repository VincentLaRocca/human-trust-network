# BTC root

The seal profile. Bitcoin is the timestamp and the one-time spend.

The cold key can spend the control output at any time. There is no delay and no CSV window. Recovery is a race on that outpoint: the confirmed spend wins, and it must anchor a bundle. A sweep with no bundle burns the right.

`operator_cold_leaf.py` is the operator check that a rotation still commits to the genesis cold leaf. The in-process deed and agent ledgers, and the Core regtest builder, are not in this tree yet.
