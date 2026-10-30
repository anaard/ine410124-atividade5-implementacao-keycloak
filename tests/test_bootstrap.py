import json
import shutil

from jwcrypto import jwk

from scripts import bootstrap
from telemedicina.config import ROOT


# Confere a associação da chave e da senha ao realm e sua preservação ao reiniciar.
def test_bootstrap_creates_matching_public_key_and_preserves_secrets(tmp_path, monkeypatch):
    (tmp_path / "telemedicina").mkdir()
    (tmp_path / "infra").mkdir()
    shutil.copyfile(ROOT / "telemedicina/realm.json", tmp_path / "telemedicina/realm.json")
    monkeypatch.setattr(bootstrap, "ROOT", tmp_path)
    monkeypatch.setattr(bootstrap, "RUNTIME", tmp_path / "runtime")

    bootstrap.main()
    runtime = tmp_path / "runtime"
    before = {name: (runtime / name).read_bytes()
              for name in ("config.json", "doctor-private.jwk", "server-private.jwk")}
    config = json.loads(before["config.json"])
    realm = json.loads((tmp_path / "infra/Telemedicina-Realm-realm.json").read_text())
    doctor = jwk.JWK.from_json(before["doctor-private.jwk"].decode())
    public = json.loads(realm["users"][0]["attributes"]["doctor_jwk"][0])
    assert "d" not in public
    assert jwk.JWK(**public).thumbprint() == doctor.thumbprint()
    assert realm["users"][0]["credentials"][0]["value"] == config["doctor_password"]
    assert "basic" in realm["clients"][0]["defaultClientScopes"]

    bootstrap.main()
    assert before == {name: (runtime / name).read_bytes() for name in before}
