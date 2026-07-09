import sys
import threading
import time

from as_server import start_as_server
from tgs_server import start_tgs_server
from notes_service import start_notes_service
from client import request_tgt, request_service_ticket, send_notes_request
from crypto_utils import derive_client_key, encrypt_json, send_request, now_ts
from kerberos_config import TGS_HOST, TGS_PORT, SERVICE_HOST, SERVICE_PORT, SERVICE_ID


def ok(msg):
    print(f"[OK] {msg}")


def erro(msg):
    print(f"[FALHA] {msg}")
    sys.exit(1)


def iniciar_servidores():
    print("\n[ETAPA] Iniciando AS, TGS e servico...")

    for nome, funcao in [
        ("AS", start_as_server),
        ("TGS", start_tgs_server),
        ("Servico", start_notes_service),
    ]:
        threading.Thread(target=funcao, daemon=True).start()
        print(f"[INFO] {nome} iniciado.")

    time.sleep(1)
    ok("Infraestrutura iniciada.")


def testar_kdf():
    print("\n[TESTE] KDF de senha")

    chave_1 = derive_client_key("alice", "alice123")
    chave_2 = derive_client_key("alice", "alice123")
    chave_errada = derive_client_key("alice", "senha_errada")

    if chave_1 != chave_2:
        erro("A mesma senha gerou chaves diferentes.")

    if chave_1 == chave_errada:
        erro("Senha correta e senha errada geraram a mesma chave.")

    ok("KDF funcionando.")


def testar_senha_errada():
    print("\n[TESTE] Senha incorreta")

    try:
        request_tgt("alice", "senha_errada")
        erro("Senha incorreta foi aceita.")
    except Exception:
        ok("Senha incorreta foi rejeitada.")


def obter_fluxo_valido():
    print("\n[TESTE] Fluxo Kerberos valido")

    tgt_data = request_tgt("alice", "alice123")

    service_data = request_service_ticket(
        client_id="alice",
        tgt=tgt_data["tgt"],
        client_tgs_session_key=tgt_data["client_tgs_session_key"],
    )

    ok("AS e TGS emitiram os tickets corretamente.")
    return tgt_data, service_data


def testar_servico(service_data):
    print("\n[TESTE] Servico protegido")

    nota = f"Nota teste {int(time.time())}"

    resultado = send_notes_request(
        client_id="alice",
        client_service_session_key=service_data["client_service_session_key"],
        service_ticket=service_data["service_ticket"],
        action="add_note",
        note_text=nota,
    )

    if resultado.get("status") != "ok":
        erro("Servico nao retornou status ok.")

    if nota not in resultado.get("notes", []):
        erro("Nota enviada nao apareceu na resposta.")

    ok("Servico protegido aceitou requisicao valida.")
    ok("Autenticacao mutua confirmada.")


def testar_replay_tgs():
    print("\n[TESTE] Bloqueio de replay no TGS")

    tgt_data = request_tgt("alice", "alice123")

    authenticator = encrypt_json(
        tgt_data["client_tgs_session_key"],
        {
            "client_id": "alice",
            "timestamp": now_ts(),
        },
    )

    request = {
        "type": "TGS_REQ",
        "service_id": SERVICE_ID,
        "tgt": tgt_data["tgt"],
        "authenticator": authenticator,
    }

    primeira = send_request(TGS_HOST, TGS_PORT, request)
    segunda = send_request(TGS_HOST, TGS_PORT, request)

    if primeira.get("type") != "TGS_REP":
        erro("Primeira requisicao ao TGS deveria ser aceita.")

    if segunda.get("type") != "ERROR":
        erro("Replay no TGS nao foi bloqueado.")

    ok("TGS bloqueou authenticator repetido.")


def testar_replay_servico():
    print("\n[TESTE] Bloqueio de replay no servico")

    _, service_data = obter_fluxo_valido()

    timestamp = now_ts()

    authenticator = encrypt_json(
        service_data["client_service_session_key"],
        {
            "client_id": "alice",
            "timestamp": timestamp,
        },
    )

    encrypted_request = encrypt_json(
        service_data["client_service_session_key"],
        {
            "action": "list_notes",
            "note_text": None,
        },
    )

    request = {
        "type": "SERVICE_REQ",
        "service_ticket": service_data["service_ticket"],
        "authenticator": authenticator,
        "encrypted_request": encrypted_request,
    }

    primeira = send_request(SERVICE_HOST, SERVICE_PORT, request)
    segunda = send_request(SERVICE_HOST, SERVICE_PORT, request)

    if primeira.get("type") != "SERVICE_REP":
        erro("Primeira requisicao ao servico deveria ser aceita.")

    if segunda.get("type") != "ERROR":
        erro("Replay no servico nao foi bloqueado.")

    ok("Servico bloqueou authenticator repetido.")


def main():
    print("==============================================")
    print(" AUDITORIA AUTOMATICA DO KERBEROS DIDATICO")
    print("==============================================")

    testar_kdf()
    iniciar_servidores()
    testar_senha_errada()

    _, service_data = obter_fluxo_valido()
    testar_servico(service_data)

    testar_replay_tgs()
    testar_replay_servico()

    print("\n==============================================")
    print(" TODOS OS TESTES PASSARAM")
    print("==============================================")


if __name__ == "__main__":
    main()
