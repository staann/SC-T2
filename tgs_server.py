import json
import socket
import traceback

from crypto_utils import (
    decrypt_json,
    encrypt_json,
    generate_symmetric_key,
    is_timestamp_fresh,
    key_from_text,
    key_to_text,
    now_ts,
    recv_json,
    send_json,
)
from kerberos_config import (
    KDC_TGS_KEY,
    SERVICE_ID,
    SERVICE_KEY,
    TGS_HOST,
    TGS_ID,
    TGS_PORT,
    TICKET_LIFETIME_SECONDS,
)


USED_AUTHENTICATORS = {}


def build_error(message):
    return {
        "type": "ERROR",
        "message": message,
    }


def authenticator_fingerprint(encrypted_authenticator):
    return json.dumps(encrypted_authenticator, sort_keys=True, separators=(",", ":"))


def reject_replayed_authenticator(encrypted_authenticator):
    current_time = now_ts()

    expired_fingerprints = [
        fingerprint
        for fingerprint, used_at in USED_AUTHENTICATORS.items()
        if current_time - used_at > TICKET_LIFETIME_SECONDS
    ]

    for fingerprint in expired_fingerprints:
        del USED_AUTHENTICATORS[fingerprint]

    fingerprint = authenticator_fingerprint(encrypted_authenticator)

    if fingerprint in USED_AUTHENTICATORS:
        raise ValueError("Authenticator repetido. Possivel tentativa de replay.")

    USED_AUTHENTICATORS[fingerprint] = current_time


def validate_tgt(tgt):
    if tgt.get("ticket_type") != "TGT":
        raise ValueError("Ticket recebido nao e um TGT.")

    if tgt.get("tgs_id") != TGS_ID:
        raise ValueError("TGT nao foi emitido para este TGS.")

    if now_ts() > int(tgt["expires_at"]):
        raise ValueError("TGT expirado.")


def validate_authenticator(authenticator, client_id, encrypted_authenticator):
    if authenticator.get("client_id") != client_id:
        raise ValueError("Authenticator nao pertence ao mesmo cliente do TGT.")

    if not is_timestamp_fresh(authenticator.get("timestamp")):
        raise ValueError("Authenticator antigo ou fora da janela de tempo permitida.")

    reject_replayed_authenticator(encrypted_authenticator)


def handle_tgs_request(request):
    if request.get("type") != "TGS_REQ":
        return build_error("Tipo de requisicao invalido para o TGS.")

    requested_service_id = request.get("service_id")

    if requested_service_id != SERVICE_ID:
        return build_error("Servico solicitado nao existe.")

    encrypted_tgt = request.get("tgt")
    encrypted_authenticator = request.get("authenticator")

    if encrypted_tgt is None or encrypted_authenticator is None:
        return build_error("TGS_REQ incompleto: falta TGT ou authenticator.")

    try:
        tgt = decrypt_json(KDC_TGS_KEY, encrypted_tgt)
        validate_tgt(tgt)

        client_id = tgt["client_id"]
        client_tgs_session_key = key_from_text(tgt["client_tgs_session_key"])

        authenticator = decrypt_json(client_tgs_session_key, encrypted_authenticator)
        validate_authenticator(authenticator, client_id, encrypted_authenticator)

        issued_at = now_ts()
        expires_at = issued_at + TICKET_LIFETIME_SECONDS

        client_service_session_key = generate_symmetric_key()

        service_ticket = encrypt_json(
            SERVICE_KEY,
            {
                "ticket_type": "SERVICE_TICKET",
                "client_id": client_id,
                "service_id": SERVICE_ID,
                "client_service_session_key": key_to_text(client_service_session_key),
                "issued_at": issued_at,
                "expires_at": expires_at,
            },
        )

        encrypted_for_client = encrypt_json(
            client_tgs_session_key,
            {
                "client_id": client_id,
                "service_id": SERVICE_ID,
                "client_service_session_key": key_to_text(client_service_session_key),
                "service_ticket": service_ticket,
                "issued_at": issued_at,
                "expires_at": expires_at,
            },
        )

        return {
            "type": "TGS_REP",
            "encrypted_for_client": encrypted_for_client,
        }

    except Exception as error:
        return build_error(f"Falha ao processar TGS_REQ: {error}")


def start_tgs_server():
    print(f"[TGS] Ticket Granting Server iniciado em {TGS_HOST}:{TGS_PORT}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((TGS_HOST, TGS_PORT))
        server_socket.listen(5)

        while True:
            conn, addr = server_socket.accept()

            with conn:
                try:
                    request = recv_json(conn)
                    response = handle_tgs_request(request)
                    send_json(conn, response)
                    print(f"[TGS] Requisicao processada de {addr}: {request.get('type')}")

                except Exception:
                    traceback.print_exc()
                    send_json(conn, build_error("Erro interno no TGS."))


if __name__ == "__main__":
    start_tgs_server()
