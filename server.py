import socket
import ssl
import threading
import json

HOST = '127.0.0.1'
PORT = 8443

# Dicionário para mapear o Nome do Utilizador (CN do certificado) ao socket
clients = {}

def handle_client(conn, addr):
    # Extrair o Common Name (CN) do certificado para usar como ID de login
    cert = conn.getpeercert()
    cn = dict(x[0] for x in cert['subject'])['commonName']
    
    print(f"[+] O utilizador '{cn}' ligou-se a partir de {addr}")
    clients[cn] = conn

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            
            msg_obj = json.loads(data.decode('utf-8'))
            msg_type = msg_obj.get('type')

            if msg_type == 'list':
                # Funcionalidade 2: Listagem dos utilizadores participantes
                active_users = list(clients.keys())
                conn.send(json.dumps({'type': 'list_response', 'users': active_users}).encode('utf-8'))
            
            elif msg_type in ['dh_param', 'chat_msg']:
                # Encaminhar a mensagem para o destinatário
                target = msg_obj.get('to')
                if target in clients:
                    clients[target].send(data)
                else:
                    conn.send(json.dumps({'type': 'error', 'msg': 'Utilizador não encontrado.'}).encode('utf-8'))

    except Exception as e:
        print(f"[-] Erro na ligação com {cn}: {e}")
    finally:
        print(f"[-] O utilizador '{cn}' desligou-se.")
        del clients[cn]
        conn.close()

def start_server():
    # Configurar o contexto SSL para mTLS (Mutual TLS)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED # Exige certificado do cliente (Autenticação)
    context.load_verify_locations(cafile="ca.crt")
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsocket.bind((HOST, PORT))
    bindsocket.listen(5)

    print(f"[*] Servidor WhatsChat seguro a escutar em {HOST}:{PORT}")

    with context.wrap_socket(bindsocket, server_side=True) as ssock:
        while True:
            conn, addr = ssock.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == '__main__':
    start_server()