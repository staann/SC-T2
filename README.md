# Trabalho Final de SeguranÃ§a Computacional - Kerberos Simplificado

Este projeto implementa uma versÃ£o didÃ¡tica do protocolo Kerberos usando somente criptografia de chave simÃ©trica e primitivas criptogrÃ¡ficas bÃ¡sicas.

A implementaÃ§Ã£o contÃ©m:

- Servidor de AutenticaÃ§Ã£o (AS)
- Ticket Granting Server (TGS)
- ServiÃ§o protegido de notas
- Cliente Kerberos
- DerivaÃ§Ã£o de chave a partir da senha do usuÃ¡rio com PBKDF2-HMAC-SHA256
- Criptografia simÃ©trica com AES-GCM
- EmissÃ£o e validaÃ§Ã£o de tickets
- AutenticaÃ§Ã£o mÃºtua entre cliente e serviÃ§o

## Requisitos

- Python 3.13 ou superior
- Biblioteca `cryptography`

InstalaÃ§Ã£o:

```powershell
py -m pip install -r requirements.txt
```

## UsuÃ¡rios cadastrados para teste

Os usuÃ¡rios de demonstraÃ§Ã£o estÃ£o definidos em `kerberos_config.py`.

```text
UsuÃ¡rio: alice
Senha: alice123

UsuÃ¡rio: bob
Senha: bob123
```

## Como executar

Abra quatro terminais dentro da pasta do projeto.

### Terminal 1 - Servidor de AutenticaÃ§Ã£o

```powershell
py as_server.py
```

### Terminal 2 - Ticket Granting Server

```powershell
py tgs_server.py
```

### Terminal 3 - ServiÃ§o protegido de notas

```powershell
py notes_service.py
```

### Terminal 4 - Cliente

```powershell
py client.py
```

No cliente, entre com um usuÃ¡rio cadastrado, por exemplo:

```text
UsuÃ¡rio: alice
Senha: alice123
```

Depois escolha uma opÃ§Ã£o:

```text
1 - Adicionar nota
2 - Listar notas
0 - Sair
```

## Fluxo Kerberos implementado

1. O cliente solicita autenticaÃ§Ã£o ao AS.
2. O AS gera uma chave de sessÃ£o Cliente-TGS e emite um TGT.
3. O cliente envia o TGT ao TGS junto com um authenticator.
4. O TGS valida o TGT e emite um ticket para o serviÃ§o protegido.
5. O cliente envia o ticket de serviÃ§o ao serviÃ§o de notas junto com outro authenticator.
6. O serviÃ§o valida o ticket, valida o authenticator e responde criptografado com a chave de sessÃ£o Cliente-ServiÃ§o.
7. O cliente confirma a autenticaÃ§Ã£o mÃºtua verificando se a resposta contÃ©m `timestamp + 1`.

## Arquivos principais

```text
crypto_utils.py        FunÃ§Ãµes de criptografia, KDF, envio e recebimento JSON
kerberos_config.py     ConfiguraÃ§Ãµes, usuÃ¡rios, portas e chaves internas
as_server.py           Servidor de AutenticaÃ§Ã£o
tgs_server.py          Ticket Granting Server
notes_service.py       ServiÃ§o protegido de notas
client.py              Cliente Kerberos
requirements.txt       DependÃªncias do projeto
```

