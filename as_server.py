import socket
import traceback

from crypto_utils import encrypt_json, generate_symmetric_key, is_timestamp_fresh, key_to_text, now_ts, recv_json, send_json
from kerberos_config import AS_HOST, AS_PORT, KDC_TGS_KEY, TGS_ID, TICKET_LIFETIME_SECONDS, USER_KEYS


def build_error(message):
    return {
        "type": "ERROR",
        "message": message,
    }


def handle_as_request(request):
    if request.get("type") != "AS_REQ":
        return build_error("Tipo de requisicao invalido para o AS.")

    client_id = request.get("client_id")
    requested_tgs_id = request.get("tgs_id")
    request_timestamp = request.get("timestamp")

    if requested_tgs_id != TGS_ID:
        return build_error("TGS solicitado nao existe.")

    if client_id not in USER_KEYS:
        return build_error("Usuario nao cadastrado no AS.")

    if request_timestamp is None:
        return build_error("AS_REQ incompleto: falta timestamp.")

    if not is_timestamp_fresh(request_timestamp):
        return build_error("AS_REQ antigo ou fora da janela de tempo permitida.")

    client_key = USER_KEYS[client_id]

    issued_at = now_ts()
    expires_at = issued_at + TICKET_LIFETIME_SECONDS

    client_tgs_session_key = generate_symmetric_key()

    tgt = encrypt_json(
        KDC_TGS_KEY,
        {
            "ticket_type": "TGT",
            "client_id": client_id,
            "tgs_id": TGS_ID,
            "client_tgs_session_key": key_to_text(client_tgs_session_key),
            "issued_at": issued_at,
            "expires_at": expires_at,
        },
    )

    encrypted_for_client = encrypt_json(
        client_key,
        {
            "client_id": client_id,
            "tgs_id": TGS_ID,
            "client_tgs_session_key": key_to_text(client_tgs_session_key),
            "tgt": tgt,
            "as_request_timestamp": request_timestamp,
            "issued_at": issued_at,
            "expires_at": expires_at,
        },
    )

    return {
        "type": "AS_REP",
        "encrypted_for_client": encrypted_for_client,
    }


def start_as_server():
    print(f"[AS] Servidor de Autenticacao iniciado em {AS_HOST}:{AS_PORT}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((AS_HOST, AS_PORT))
        server_socket.listen(5)

        while True:
            conn, addr = server_socket.accept()

            with conn:
                try:
                    request = recv_json(conn)
                    response = handle_as_request(request)
                    send_json(conn, response)
                    print(f"[AS] Requisicao processada de {addr}: {request.get('type')}")

                except Exception:
                    traceback.print_exc()
                    send_json(conn, build_error("Erro interno no AS."))


if __name__ == "__main__":
    start_as_server()
