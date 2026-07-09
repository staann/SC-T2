import getpass
import sys

from crypto_utils import (
    decrypt_json,
    encrypt_json,
    key_from_text,
    now_ts,
    send_request,
)
from kerberos_config import (
    AS_HOST,
    AS_PORT,
    SERVICE_HOST,
    SERVICE_ID,
    SERVICE_PORT,
    TGS_HOST,
    TGS_ID,
    TGS_PORT,
)
from crypto_utils import derive_client_key


def fail_if_error(response, server_name):
    if response.get("type") == "ERROR":
        raise RuntimeError(f"{server_name} retornou erro: {response.get('message')}")


def request_tgt(client_id, password):
    print("[CLIENT] Derivando chave do usuario a partir da senha com PBKDF2-HMAC-SHA256...")
    client_key = derive_client_key(client_id, password)

    print("[CLIENT] Enviando AS_REQ para o Servidor de Autenticacao...")
    response = send_request(
        AS_HOST,
        AS_PORT,
        {
            "type": "AS_REQ",
            "client_id": client_id,
            "tgs_id": TGS_ID,
        },
    )

    fail_if_error(response, "AS")

    if response.get("type") != "AS_REP":
        raise RuntimeError("Resposta inesperada do AS.")

    try:
        decrypted = decrypt_json(client_key, response["encrypted_for_client"])
    except Exception as error:
        raise RuntimeError("Falha ao descriptografar resposta do AS. Usuario ou senha incorretos.") from error

    print("[CLIENT] AS_REP recebida e descriptografada com sucesso.")
    print("[CLIENT] TGT obtido.")

    return {
        "client_key": client_key,
        "client_tgs_session_key": key_from_text(decrypted["client_tgs_session_key"]),
        "tgt": decrypted["tgt"],
    }


def request_service_ticket(client_id, tgt, client_tgs_session_key):
    print("[CLIENT] Enviando TGS_REQ para o Ticket Granting Server...")

    authenticator = encrypt_json(
        client_tgs_session_key,
        {
            "client_id": client_id,
            "timestamp": now_ts(),
        },
    )

    response = send_request(
        TGS_HOST,
        TGS_PORT,
        {
            "type": "TGS_REQ",
            "service_id": SERVICE_ID,
            "tgt": tgt,
            "authenticator": authenticator,
        },
    )

    fail_if_error(response, "TGS")

    if response.get("type") != "TGS_REP":
        raise RuntimeError("Resposta inesperada do TGS.")

    decrypted = decrypt_json(client_tgs_session_key, response["encrypted_for_client"])

    print("[CLIENT] TGS_REP recebida e descriptografada com sucesso.")
    print("[CLIENT] Ticket de servico obtido.")

    return {
        "client_service_session_key": key_from_text(decrypted["client_service_session_key"]),
        "service_ticket": decrypted["service_ticket"],
    }


def send_notes_request(client_id, client_service_session_key, service_ticket, action, note_text=None):
    timestamp = now_ts()

    authenticator = encrypt_json(
        client_service_session_key,
        {
            "client_id": client_id,
            "timestamp": timestamp,
        },
    )

    encrypted_request = encrypt_json(
        client_service_session_key,
        {
            "action": action,
            "note_text": note_text,
        },
    )

    response = send_request(
        SERVICE_HOST,
        SERVICE_PORT,
        {
            "type": "SERVICE_REQ",
            "service_ticket": service_ticket,
            "authenticator": authenticator,
            "encrypted_request": encrypted_request,
        },
    )

    fail_if_error(response, "Servico de notas")

    if response.get("type") != "SERVICE_REP":
        raise RuntimeError("Resposta inesperada do servico.")

    decrypted = decrypt_json(client_service_session_key, response["encrypted_for_client"])

    expected_mutual_auth = timestamp + 1

    if decrypted.get("mutual_auth") != expected_mutual_auth:
        raise RuntimeError("Falha na autenticacao mutua: resposta do servico nao confere.")

    print("[CLIENT] Autenticacao mutua confirmada.")
    return decrypted["result"]


def show_menu():
    print()
    print("Escolha uma opcao:")
    print("1 - Adicionar nota")
    print("2 - Listar notas")
    print("0 - Sair")


def main():
    print("Cliente Kerberos - Sistema de Notas")
    print("-----------------------------------")

    client_id = input("Usuario: ").strip()
    password = getpass.getpass("Senha: ")

    try:
        tgt_data = request_tgt(client_id, password)

        service_data = request_service_ticket(
            client_id=client_id,
            tgt=tgt_data["tgt"],
            client_tgs_session_key=tgt_data["client_tgs_session_key"],
        )

        while True:
            show_menu()
            option = input("> ").strip()

            if option == "1":
                note_text = input("Digite a nota: ").strip()

                result = send_notes_request(
                    client_id=client_id,
                    client_service_session_key=service_data["client_service_session_key"],
                    service_ticket=service_data["service_ticket"],
                    action="add_note",
                    note_text=note_text,
                )

                print(result["message"])
                print("Notas atuais:", result["notes"])

            elif option == "2":
                result = send_notes_request(
                    client_id=client_id,
                    client_service_session_key=service_data["client_service_session_key"],
                    service_ticket=service_data["service_ticket"],
                    action="list_notes",
                )

                print(result["message"])
                print("Notas atuais:", result["notes"])

            elif option == "0":
                print("Encerrando cliente.")
                break

            else:
                print("Opcao invalida.")

    except Exception as error:
        print(f"[ERRO] {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
