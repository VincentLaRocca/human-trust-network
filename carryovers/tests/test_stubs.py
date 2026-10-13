import pytest
from htn_carry import stubs


@pytest.mark.parametrize("fn", [n for n in dir(stubs) if n.startswith("STUB_")])
def test_stub_raises_and_is_labeled(fn):
    with pytest.raises(stubs.StubError, match="STUB"):
        getattr(stubs, fn)()
