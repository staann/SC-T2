import json
import socket
import traceback

from crypto_utils import (
    decrypt_json,
    encrypt_json,
    is_timestamp_fresh,
    key_from_text,
    now_ts,
    recv_json,
    send_json,
)
from kerberos_config import SERVICE_HOST, SERVICE_ID, SERVICE_KEY, SERVICE_PORT, TICKET_LIFETIME_SECONDS


NOTES_DB = {}
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


def validate_service_ticket(ticket):
    if ticket.get("ticket_type") != "SERVICE_TICKET":
        raise ValueError("Ticket recebido nao e um ticket de servico.")

    if ticket.get("service_id") != SERVICE_ID:
        raise ValueError("Ticket nao foi emitido para este servico.")

    if now_ts() > int(ticket["expires_at"]):
        raise ValueError("Ticket de servico expirado.")


def validate_authenticator(authenticator, client_id, encrypted_authenticator):
    if authenticator.get("client_id") != client_id:
        raise ValueError("Authenticator nao pertence ao mesmo cliente do ticket.")

    if not is_timestamp_fresh(authenticator.get("timestamp")):
        raise ValueError("Authenticator antigo ou fora da janela de tempo permitida.")

    reject_replayed_authenticator(encrypted_authenticator)


def process_notes_action(client_id, action, note_text):
    if client_id not in NOTES_DB:
        NOTES_DB[client_id] = []

    if action == "add_note":
        if not note_text:
            raise ValueError("Texto da nota nao pode estar vazio.")

        NOTES_DB[client_id].append(note_text)

        return {
            "status": "ok",
            "message": "Nota adicionada com sucesso.",
            "notes": NOTES_DB[client_id],
        }

    if action == "list_notes":
        return {
            "status": "ok",
            "message": "Notas recuperadas com sucesso.",
            "notes": NOTES_DB[client_id],
        }

    raise ValueError("Acao desconhecida para o servico de notas.")


def handle_service_request(request):
    if request.get("type") != "SERVICE_REQ":
        return build_error("Tipo de requisicao invalido para o servico.")

    encrypted_ticket = request.get("service_ticket")
    encrypted_authenticator = request.get("authenticator")
    encrypted_request = request.get("encrypted_request")

    if encrypted_ticket is None or encrypted_authenticator is None or encrypted_request is None:
        return build_error("SERVICE_REQ incompleto: falta ticket, authenticator ou requisicao.")

    try:
        ticket = decrypt_json(SERVICE_KEY, encrypted_ticket)
        validate_service_ticket(ticket)

        client_id = ticket["client_id"]
        client_service_session_key = key_from_text(ticket["client_service_session_key"])

        authenticator = decrypt_json(client_service_session_key, encrypted_authenticator)
        validate_authenticator(authenticator, client_id, encrypted_authenticator)

        service_request = decrypt_json(client_service_session_key, encrypted_request)

        result = process_notes_action(
            client_id=client_id,
            action=service_request.get("action"),
            note_text=service_request.get("note_text"),
        )

        encrypted_for_client = encrypt_json(
            client_service_session_key,
            {
                "service_id": SERVICE_ID,
                "client_id": client_id,
                "mutual_auth": int(authenticator["timestamp"]) + 1,
                "result": result,
            },
        )

        return {
            "type": "SERVICE_REP",
            "encrypted_for_client": encrypted_for_client,
        }

    except Exception as error:
        return build_error(f"Falha ao processar SERVICE_REQ: {error}")


def start_notes_service():
    print(f"[SERVICE] Servico de notas protegido iniciado em {SERVICE_HOST}:{SERVICE_PORT}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((SERVICE_HOST, SERVICE_PORT))
        server_socket.listen(5)

        while True:
            conn, addr = server_socket.accept()

            with conn:
                try:
                    request = recv_json(conn)
                    response = handle_service_request(request)
                    send_json(conn, response)
                    print(f"[SERVICE] Requisicao processada de {addr}: {request.get('type')}")

                except Exception:
                    traceback.print_exc()
                    send_json(conn, build_error("Erro interno no servico de notas."))


if __name__ == "__main__":
    start_notes_service()
