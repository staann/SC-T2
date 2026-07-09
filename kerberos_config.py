from crypto_utils import derive_client_key


AS_HOST = "127.0.0.1"
AS_PORT = 8800

TGS_HOST = "127.0.0.1"
TGS_PORT = 8801

SERVICE_HOST = "127.0.0.1"
SERVICE_PORT = 8802

REALM = "KERBEROS-DEMO.UNB"
TGS_ID = "krbtgt"
SERVICE_ID = "notes_service"

TICKET_LIFETIME_SECONDS = 10 * 60


USER_KEYS = {
    "alice": derive_client_key("alice", "alice123"),
    "bob": derive_client_key("bob", "bob123"),
}

KDC_TGS_KEY = derive_client_key("krbtgt", "senha_interna_as_tgs_demo")
SERVICE_KEY = derive_client_key("notes_service", "senha_interna_servico_notas_demo")


if __name__ == "__main__":
    print("kerberos_config OK")
    print(f"Usuarios cadastrados: {', '.join(USER_KEYS.keys())}")
    print(f"Servico protegido: {SERVICE_ID}")
