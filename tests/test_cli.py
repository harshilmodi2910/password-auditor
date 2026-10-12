import hashlib
import io
import json

import pytest

from auditor.cli import main


def test_password_and_hash_together_as_json(capsys):
    md5 = hashlib.md5(b"x").hexdigest()
    code = main(["--password", "Kq9#Zm2$Xv7!", "--hash", md5, "--json"])
    out, err = capsys.readouterr()
    data = json.loads(out)
    assert code == 0
    assert set(data) == {"password", "hash"}
    assert data["hash"]["tier"] == "broken"
    assert "shell history" in err


def test_stdin_password(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("password\n"))
    code = main(["--stdin"])
    out, _ = capsys.readouterr()
    assert code == 0
    assert "Very Weak" in out
    assert "common" in out


def test_algorithm_without_hash_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        main(["--algorithm", "md5"])
    assert exc.value.code == 2
