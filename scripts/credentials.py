"""Exibe os acessos locais: o admin do Keycloak e a senha do médico gerada no bootstrap."""

from telemedicina.config import settings

config = settings()
print("Console: http://localhost:8080/admin/ - admin / admin")
print("Portal: http://localhost:5000 - dr.silva /", config["doctor_password"])
