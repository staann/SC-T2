import socket
import ssl
import threading
import json
import sys
import hashlib
import hmac
import secrets

HOST = '127.0.0.1'
PORT = 8443

# Parâmetros Diffie-Hellman (Num cenário real, seriam gerados dinamicamente ou usar-se-ia um grupo RFC padronizado)
P = 23  # Primo (simplificado para o exemplo)
G = 5   # Gerador

shared_secrets = {} # Dicionário para armazenar as chaves HMAC por utilizador
my_name = ""

def generate_dh_keys():
    private_key = secrets.randbelow(P - 2) + 1
    public_key = pow(G, private_key, P)
    return private_key, public_key

def calculate_hmac(key, message):
    # Funcionalidade 4: Mecanismo de verificação de integridade usando HMAC com SHA256
    return hmac.new(str(key).encode(), message.encode(), hashlib.sha256).hexdigest()

def receive_messages(conn, my_private_key):
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            
            msg = json.loads(data.decode('utf-8'))
            
            if msg['type'] == 'list_response':
                print(f"\n[Utilizadores Online]: {', '.join(msg['users'])}")
            
            elif msg['type'] == 'dh_param':
                # Funcionalidade 3: Receber a chave pública DH e calcular o segredo partilhado
                sender = msg['from']
                other_public_key = msg['public_key']
                shared_secret = pow(other_public_key, my_private_key, P)
                shared_secrets[sender] = shared_secret
                print(f"\n[!] Canal seguro estabelecido com {sender}.")
                
            elif msg['type'] == 'chat_msg':
                sender = msg['from']
                content = msg['content']
                received_mac = msg['hmac']
                
                # Funcionalidade 4 e 5: Verificar a integridade e autenticidade da mensagem
                if sender not in shared_secrets:
                    print(f"\n[ALERTA DE SEGURANÇA] Mensagem recebida de {sender} sem canal seguro estabelecido! Autenticidade não verificada.")
                    continue
                
                expected_mac = calculate_hmac(shared_secrets[sender], content)
                
                if hmac.compare_digest(expected_mac, received_mac):
                    print(f"\n[{sender}]: {content}")
                else:
                    print(f"\n[ALERTA DE INTEGRIDADE] A mensagem de {sender} foi adulterada durante a transmissão!")
                    
        except Exception as e:
            print(f"Erro na receção: {e}")
            break

def start_client(cert_file, key_file):
    global my_name
    
    # Configurar mTLS
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations("ca.crt")
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    secure_conn = context.wrap_socket(conn, server_hostname="ServidorWhatsChat")
    secure_conn.connect((HOST, PORT))
    
    cert = secure_conn.getpeercert()
    my_name = cert_file.split('.')[0].capitalize()
    print(f"[*] Login efetuado com sucesso como {my_name}.")

    my_private_key, my_public_key = generate_dh_keys()

    threading.Thread(target=receive_messages, args=(secure_conn, my_private_key), daemon=True).start()

    print("Comandos: '/list' (ver utilizadores), '/connect <nome>' (abrir canal seguro), ou digite a sua mensagem.")
    current_target = None

    while True:
        user_input = input("")
        if user_input == '/list':
            secure_conn.send(json.dumps({'type': 'list'}).encode())
        elif user_input.startswith('/connect '):
            current_target = user_input.split(' ')[1]
            secure_conn.send(json.dumps({
                'type': 'dh_param',
                'from': my_name,
                'to': current_target,
                'public_key': my_public_key
            }).encode())
            print(f"[*] A iniciar troca de chaves Diffie-Hellman com {current_target}...")
        elif current_target:
            if current_target not in shared_secrets:
                print(f"[-] O canal seguro com {current_target} ainda não foi estabelecido. Aguarde ou reconecte.")
                continue
            
            # Gerar o HMAC e enviar a mensagem
            msg_hmac = calculate_hmac(shared_secrets[current_target], user_input)
            secure_conn.send(json.dumps({
                'type': 'chat_msg',
                'from': my_name,
                'to': current_target,
                'content': user_input,
                'hmac': msg_hmac
            }).encode())
        else:
            print("[-] Selecione um utilizador primeiro com '/connect <nome>'.")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Uso: python client.py <seu_certificado.crt> <sua_chave.key>")
        sys.exit(1)
    start_client(sys.argv[1], sys.argv[2])