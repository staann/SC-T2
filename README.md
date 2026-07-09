# Trabalho Final de Seguranca Computacional - Kerberos Simplificado

Este projeto implementa uma versao didatica do protocolo Kerberos usando somente criptografia de chave simetrica e primitivas criptograficas basicas.

A implementacao contem:

- Servidor de Autenticacao (AS)
- Ticket Granting Server (TGS)
- Servico protegido de notas
- Cliente Kerberos
- Derivacao de chave a partir da senha do usuario com PBKDF2-HMAC-SHA256
- Criptografia simetrica com AES-GCM
- Emissao e validacao de tickets
- Autenticacao mutua entre cliente e servico

## Requisitos

- Python 3.13 ou superior
- Biblioteca cryptography

Instalacao:

py -m pip install -r requirements.txt

## Usuarios cadastrados para teste

Os usuarios de demonstracao estao definidos em kerberos_config.py.

Usuario: alice
Senha: alice123

Usuario: bob
Senha: bob123

## Como executar

Abra quatro terminais dentro da pasta do projeto.

Terminal 1 - Servidor de Autenticacao:

py as_server.py

Terminal 2 - Ticket Granting Server:

py tgs_server.py

Terminal 3 - Servico protegido de notas:

py notes_service.py

Terminal 4 - Cliente:

py client.py

No cliente, entre com um usuario cadastrado, por exemplo:

Usuario: alice
Senha: alice123

Depois escolha uma opcao:

1 - Adicionar nota
2 - Listar notas
0 - Sair

## Fluxo Kerberos implementado

1. O cliente solicita autenticacao ao AS.
2. O AS gera uma chave de sessao Cliente-TGS e emite um TGT.
3. O cliente envia o TGT ao TGS junto com um authenticator.
4. O TGS valida o TGT e emite um ticket para o servico protegido.
5. O cliente envia o ticket de servico ao servico de notas junto com outro authenticator.
6. O servico valida o ticket, valida o authenticator e responde criptografado com a chave de sessao Cliente-Servico.
7. O cliente confirma a autenticacao mutua verificando se a resposta contem timestamp + 1.

## Arquivos principais

crypto_utils.py        Funcoes de criptografia, KDF, envio e recebimento JSON
kerberos_config.py     Configuracoes, usuarios, portas e chaves internas
as_server.py           Servidor de Autenticacao
tgs_server.py          Ticket Granting Server
notes_service.py       Servico protegido de notas
client.py              Cliente Kerberos
requirements.txt       Dependencias do projeto
relatorio.md           Relatorio tecnico em Markdown
relatorio.pdf          Relatorio tecnico em PDF
