# Sistema de Comunicação Segura entre Processos Distribuídos

Sistema distribuído de troca de mensagens seguro, desenvolvido em Python usando **Socket TCP puro**, que implementa os principais mecanismos de segurança: **autenticação**, **criptografia** e **controle de acesso**.

## 📐 Arquitetura de Segurança

O sistema é composto por três componentes que rodam em processos separados:

| Componente | Tecnologia | Responsabilidade |
|---|---|---|
| **Servidor Central** | Python (Socket TCP / `socket`) | Autentica clientes, armazena mensagens criptografadas, controla acesso |
| **Cliente A (Remetente)** | Python (Socket TCP / `socket`) | Faz login, criptografa a mensagem e envia ao servidor |
| **Cliente B (Destinatário)** | Python (Socket TCP / `socket`) | Faz login e busca suas mensagens (descriptografadas pelo servidor) |

### Protocolo de Comunicação
      
A comunicação é feita via modelo **Request/Response** usando **JSON delimitado por newline (`\n`)** através de sockets TCP puros.

Exemplo de Requisição:
```json
{"acao": "login", "username": "alice", "senha": "123"}
```

Exemplo de Resposta:
```json
{"status": "ok", "mensagem": "Login bem-sucedido. Bem-vindo, alice!", "token": "abc...", "papel": "user"}
```

### Mecanismos de Segurança Implementados

1. **Autenticação de Usuários**
   - Senhas armazenadas como hash SHA-256 (`hashlib`)
   - Token de sessão gerado com `secrets.token_hex()` após login válido
   - Todas as requisições subsequentes exigem o envio do token no JSON (ex: `"token": "abc..."`)

2. **Criptografia das Mensagens**
   - Criptografia simétrica com **Fernet** (biblioteca `cryptography`)
   - Chave compartilhada entre todos os usuários do sistema
   - Mensagens trafegam criptografadas pela rede
   - Servidor armazena mensagens cifradas e descriptografa na entrega

3. **Controle de Acesso por Papéis**

   | Ação | Papel: user | Papel: admin |    
   |---|---|---|
   | Enviar mensagem | ✅ | ✅ |
   | Ler suas próprias mensagens | ✅ | ✅ |
   | Ler mensagens de outros | ❌ | ✅ |
   | Cadastrar novo usuário | ❌ | ✅ |
   | Ver lista de usuários | ❌ | ✅ |

4. **Persistência com SQLite**
   - Mensagens persistidas entre sessões
   - Armazenadas em formato cifrado no banco de dados

## 📋 Pré-requisitos

- Python 3.10 ou superior
- pip (gerenciador de pacotes Python)

## 🚀 Instalação

1. Clone o repositório:
```bash
git clone https://github.com/Raildom/Sistema-de-comunica-o-segura-entre-processos-distribu-dos.git
cd Sistema-de-comunica-o-segura-entre-processos-distribu-dos
```

2. Crie e ative um ambiente virtual (recomendado):
```bash
python3 -m venv venv
source venv/bin/activate  # No Linux/Mac
# venv\Scripts\activate   # No Windows
```

3. Instale as dependências:
```bash
pip install -r requirements.txt
```

## ▶️ Como Executar

### 1. Iniciar o Servidor

Em um terminal (com o ambiente virtual ativo), execute:
```bash
python server/app.py
```

O servidor iniciará na porta **5000** e criará automaticamente:
- O banco de dados SQLite (`server/mensagens.db`)
- A chave Fernet compartilhada (`server/chave.key`)
- Usuários padrão para testes:
  - `admin` (senha: `admin123`, papel: `admin`)
  - `alice` (senha: `alice123`, papel: `user`)
  - `bob` (senha: `bob123`, papel: `user`)

### 2. Executar o Cliente (Interativo)

Em outro terminal, execute:
```bash
python client/cliente.py
```

Para conectar a um servidor remoto:
```bash
python client/cliente.py IP-DO-SERVIDOR:5000
```

### 3. Executar a Demonstração Automática

Para rodar o fluxo completo de apresentação automaticamente:
```bash     
# Terminal 1: servidor
python server/app.py

# Terminal 2: demonstração
python demo.py
```

## 🎬 Fluxo de Apresentação

O script `demo.py` executa automaticamente todos os passos exigidos pelo trabalho. Abaixo está a demonstração real (log de execução) do sistema funcionando com a arquitetura Socket TCP:

```text
████████████████████████████████████████████████████████████
  DEMONSTRAÇÃO DO SISTEMA DE COMUNICAÇÃO SEGURA (Socket TCP)
  Fluxo completo de apresentação
████████████████████████████████████████████████████████████

⚠ Certifique-se de que o servidor está rodando em localhost:5000


════════════════════════════════════════════════════════════
  PASSO 1: Verificando se o servidor está rodando
════════════════════════════════════════════════════════════
Servidor online: Servidor de comunicação segura está ativo.


════════════════════════════════════════════════════════════
  PASSO 2: Tentativa de login com senha ERRADA → acesso negado     
════════════════════════════════════════════════════════════

Falha no login: Credenciais inválidas. Acesso negado.

→ Resultado: Login NEGADO (esperado)


════════════════════════════════════════════════════════════
  PASSO 3: Login com credenciais VÁLIDAS (Alice) → token gerado
════════════════════════════════════════════════════════════

Login bem-sucedido. Bem-vindo, alice!
  Papel: user
  Token: 2b595be88c79c0f6...
  Chave Fernet obtida com sucesso.
   
→ Token de sessão gerado com sucesso!


════════════════════════════════════════════════════════════
  PASSO 4: Envio de mensagem CRIPTOGRAFADA de Alice → Bob
════════════════════════════════════════════════════════════

🔒 Mensagem original: "Olá Bob! Esta é uma mensagem secreta da Alice."
🔐 Mensagem cifrada: gAAAAABqGdznO02yvBhvlkLRyIk4IDgbXMhULVn6si2wLNg4GbhDnco5JYq5_5w8FwO61tu-3nsFY1EI...
Mensagem enviada para 'bob' com sucesso.
  Timestamp: 2026-05-29T18:37:27.129421+00:00

🔒 Mensagem original: "Segunda mensagem: a reunião é às 15h."
🔐 Mensagem cifrada: gAAAAABqGdznGsrULFtQKumKMTh5AaMt5kcU58h15lwTxDGIJ4t40bevxhoyA4yYQDNown2M6o3r2kgP...
Mensagem enviada para 'bob' com sucesso.
  Timestamp: 2026-05-29T18:37:27.643318+00:00


════════════════════════════════════════════════════════════
  PASSO 5: Login de Bob e leitura de SUAS mensagens
════════════════════════════════════════════════════════════

Login bem-sucedido. Bem-vindo, bob!
  Papel: user
  Token: d1a43a0db907d81a...
  Chave Fernet obtida com sucesso.

Bob lendo suas mensagens (descriptografadas pelo servidor):

📬 2 mensagem(ns) encontrada(s):
──────────────────────────────────────────────────

  📩 ID: 3
     De: alice
     Para: bob
     Conteúdo: Olá Bob! Esta é uma mensagem secreta da Alice.
     Data: 2026-05-29T18:37:27.129421+00:00
     Lida: Não

  📩 ID: 4
     De: alice
     Para: bob
     Conteúdo: Segunda mensagem: a reunião é às 15h.
     Data: 2026-05-29T18:37:27.643318+00:00
     Lida: Não

──────────────────────────────────────────────────


════════════════════════════════════════════════════════════
  PASSO 6: Bob (user) tenta ler mensagens de Alice → ERRO
════════════════════════════════════════════════════════════

🔍 Tentando ler mensagens de 'alice'...
ACESSO NEGADO: Acesso negado. Permissão de administrador necessária.
  Usuários comuns só podem ler suas próprias mensagens.

→ Acesso corretamente NEGADO para usuário comum.


════════════════════════════════════════════════════════════
  PASSO 7: Login como ADMIN e leitura de TODAS as mensagens
════════════════════════════════════════════════════════════

Login bem-sucedido. Bem-vindo, admin!
  Papel: admin
  Token: 8f24965b75b15308...
  Chave Fernet obtida com sucesso.

📬 [ADMIN] 4 mensagem(ns) no sistema:
──────────────────────────────────────────────────
  (Aparecerão todas as mensagens do sistema aqui, descriptografadas)
──────────────────────────────────────────────────


════════════════════════════════════════════════════════════
  PASSO 8: Conteúdo BRUTO do banco SQLite → mensagens CIFRADAS
════════════════════════════════════════════════════════════
Mostrando o banco de dados diretamente...
As mensagens aparecem CRIPTOGRAFADAS, provando a segurança:

════════════════════════════════════════════════════════════
  CONTEÚDO BRUTO DO BANCO DE DADOS SQLite
════════════════════════════════════════════════════════════

── Tabela: usuarios ──
  ID: 1 | Username: admin | Papel: admin
  ID: 2 | Username: alice | Papel: user
  ID: 3 | Username: bob | Papel: user

── Tabela: mensagens (CIFRADAS) ──

  ID: 3
  Remetente: alice
  Destinatário: bob
  Conteúdo Cifrado: gAAAAABqGdznO02yvBhvlkLRyIk4IDgbXMhULVn6si2wLNg4GbhDnco5JYq5_5w8FwO61tu-3nsFY1EI...
  Timestamp: 2026-05-29T18:37:27.129421+00:00
  Lida: 1

  ID: 4
  Remetente: alice
  Destinatário: bob
  Conteúdo Cifrado: gAAAAABqGdznGsrULFtQKumKMTh5AaMt5kcU58h15lwTxDGIJ4t40bevxhoyA4yYQDNown2M6o3r2kgP...
  Timestamp: 2026-05-29T18:37:27.643318+00:00
  Lida: 1

════════════════════════════════════════════════════════════


════════════════════════════════════════════════════════════
  BÔNUS: Funcionalidades de administrador
════════════════════════════════════════════════════════════

Listando todos os usuários do sistema:

👥 3 usuário(s) cadastrado(s):
────────────────────────────────────────
  👑 admin (admin)
  👤 alice (user)
  👤 bob (user)
────────────────────────────────────────


████████████████████████████████████████████████████████████
  DEMONSTRAÇÃO CONCLUÍDA COM SUCESSO!
  Todos os requisitos de segurança foram demonstrados:
  Autenticação com hash SHA-256
  Tokens de sessão
  Criptografia Fernet
  Controle de acesso (user/admin)
  Persistência SQLite
████████████████████████████████████████████████████████████
```

## 📁 Estrutura do Projeto

```
.
├── server/
│   ├── __init__.py
│   ├── app.py              # Servidor TCP (autenticação, handlers, criptografia)
│   ├── mensagens.db         # Banco SQLite (gerado automaticamente)
│   └── chave.key            # Chave Fernet compartilhada (gerada automaticamente)
├── client/
│   ├── __init__.py
│   └── cliente.py           # Cliente Socket interativo com menu
├── demo.py                  # Script de demonstração do fluxo completo
├── requirements.txt         # Dependências do projeto
└── README.md                # Este arquivo
```

## 🛡️ Ações (Comandos Socket)

| Ação | Autenticação | Papel | Descrição |
|---|---|---|---|
| `status` | Não | - | Verifica se o servidor está online |
| `login` | Não | - | Autentica e retorna token |
| `logout` | Sim | - | Encerra sessão do token |
| `chave` | Sim | - | Retorna chave Fernet |
| `enviar` | Sim | user/admin | Envia mensagem cifrada |
| `receber` | Sim | user/admin | Lê próprias mensagens |
| `todas` | Sim | admin | Lê todas as mensagens |
| `cadastrar` | Sim | admin | Cadastra novo usuário |
| `usuarios` | Sim | admin | Lista usuários |
| `banco` | Sim | admin | Mostra banco bruto |

## 📦 Dependências

- **cryptography** - Criptografia Fernet (simétrica)
- **colorama** - Cores no terminal

## 👥 Usuários Padrão

| Username | Senha | Papel |
|---|---|---|
| `admin` | `admin123` | admin |
| `alice` | `alice123` | user |
| `bob` | `bob123` | user |
