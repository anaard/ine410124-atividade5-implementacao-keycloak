import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = ROOT / "runtime"


# settings: Lê runtime/config.json (criado por scripts/bootstrap.py) e aplica os endereços do Docker.
def settings():
    config = json.loads((RUNTIME / "config.json").read_text())

    # O issuer público (localhost) é o que consta nos tokens e nunca muda;
    # dentro da rede Docker só as requisições de backend trocam o host para "keycloak".
    keycloak = os.environ.get("KEYCLOAK_URL")
    config["oidc_internal_url"] = (
        keycloak.rstrip("/") + "/realms/Telemedicina-Realm"
        if keycloak
        else config["issuer"]
    )

    if os.environ.get("RESOURCE_SERVER_URL"):
        config["server_url"] = os.environ["RESOURCE_SERVER_URL"]

    return config
