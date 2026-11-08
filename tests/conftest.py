import pytest

import common
import config
import notifications


@pytest.fixture(autouse=True)
def _isolated_delivery_state(monkeypatch):
    monkeypatch.setattr(common, "_pacer", common.Pacer(0))
    notifications._queue = None


@pytest.fixture
def data_path(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "data_path", tmp_path)
    tmp_path.joinpath("42").mkdir()
    return tmp_path
