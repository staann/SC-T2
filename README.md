# Trabalho Final de Seguranca Computacional - Kerberos Didatico

Este projeto implementa uma versao didatica do protocolo Kerberos em Python, usando criptografia de chave simetrica e primitivas criptograficas basicas.

A implementacao contem:

- Servidor de Autenticacao (AS)
- Ticket Granting Server (TGS)
- Servico protegido de notas
- Cliente Kerberos
- Derivacao de chave por senha com PBKDF2-HMAC-SHA256
- Criptografia simetrica com AES-GCM
- Emissao e validacao de tickets
- Authenticators com timestamp
- Autenticacao mutua entre cliente e servico
- Bloqueio de replay no TGS
- Bloqueio de replay no servico protegido
- Teste automatico do fluxo Kerberos

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

## Como executar manualmente

Abra quatro terminais dentro da pasta do projeto.

Terminal 1 - Servidor de Autenticacao:

py as_server.py

Terminal 2 - Ticket Granting Server:

py tgs_server.py

Terminal 3 - Servico protegido de notas:

py notes_service.py

Terminal 4 - Cliente:

py client.py

No cliente, entre com um usuario cadastrado.

Exemplo:

Usuario: alice  
Senha: alice123

Depois escolha uma opcao:

1 - Adicionar nota  
2 - Listar notas  
0 - Sair

## Como executar o teste automatico

Tambem e possivel validar o projeto com:

py test_kerberos.py

Esse teste verifica:

- derivacao de chave por senha;
- rejeicao de senha incorreta;
- emissao do TGT pelo AS;
- emissao do ticket de servico pelo TGS;
- acesso ao servico protegido;
- autenticacao mutua;
- bloqueio de replay no TGS;
- bloqueio de replay no servico protegido.

Resultado esperado:

TODOS OS TESTES PASSARAM

## Fluxo Kerberos implementado

1. O cliente deriva sua chave localmente a partir da senha.
2. O cliente envia uma AS_REQ ao Servidor de Autenticacao.
3. O AS valida o usuario, verifica o timestamp e emite um TGT.
4. O cliente envia o TGT ao TGS junto com um authenticator.
5. O TGS valida o TGT, valida o authenticator e emite um ticket de servico.
6. O cliente envia o ticket de servico ao servico de notas junto com outro authenticator.
7. O servico valida o ticket, valida o authenticator e processa a requisicao protegida.
8. O servico responde criptografado com a chave de sessao Cliente-Servico.
9. O cliente confirma a autenticacao mutua verificando timestamp + 1.

## Arquivos principais

crypto_utils.py        Funcoes de criptografia, KDF, envio e recebimento JSON  
kerberos_config.py     Configuracoes, usuarios, portas e chaves internas  
as_server.py           Servidor de Autenticacao  
tgs_server.py          Ticket Granting Server  
notes_service.py       Servico protegido de notas  
client.py              Cliente Kerberos  
test_kerberos.py       Teste automatico do protocolo  
requirements.txt       Dependencias do projeto  
relatorio.md           Relatorio tecnico em Markdown  
relatorio.pdf          Relatorio tecnico em PDF  

## Observacao

Este projeto e uma implementacao didatica. As senhas e chaves de demonstracao ficam no codigo para facilitar a execucao e avaliacao do trabalho.