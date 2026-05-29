"""
Servidor Central (Socket TCP) - Sistema de Comunicação Segura entre Processos Distribuídos

Responsabilidades:
- Autenticar clientes com login/senha (hash SHA-256)
- Gerenciar tokens de sessão
- Armazenar mensagens criptografadas (Fernet)
- Controlar acesso baseado em papéis (user/admin)

Protocolo: JSON delimitado por newline (\n) sobre TCP.
"""

import hashlib
import secrets
import sqlite3
import socket
import threading
import json
import os
from datetime import datetime, timezone

from cryptography.fernet import Fernet

# 
# Configuração
# 

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "mensagens.db")
KEY_PATH = os.path.join(BASE_DIR, "chave.key")

HOST = "0.0.0.0"
PORT = 5000

# Tokens de sessão ativos: {token: username}
sessoes_ativas: dict[str, str] = {}
lock = threading.Lock()


# 
# Chave de Criptografia Fernet (compartilhada)
# 

def carregar_ou_gerar_chave() -> bytes:
    """Carrega a chave Fernet do arquivo ou gera uma nova."""
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read()
    chave = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(chave)
    return chave


CHAVE_FERNET = carregar_ou_gerar_chave()
fernet = Fernet(CHAVE_FERNET)


# 
# Banco de Dados SQLite
# 

def get_db() -> sqlite3.Connection:
    """Cria e retorna uma conexão com o banco de dados."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def inicializar_banco():
    """Cria as tabelas do banco de dados caso não existam."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Tabela de usuários
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            senha_hash  TEXT    NOT NULL,
            papel       TEXT    NOT NULL DEFAULT 'user'
        )
    """)

    # Tabela de mensagens
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mensagens (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            remetente        TEXT    NOT NULL,
            destinatario     TEXT    NOT NULL,
            conteudo_cifrado BLOB    NOT NULL,
            timestamp        TEXT    NOT NULL,
            lida             INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.commit()

    # Cadastrar admin padrão se não existir
    senha_admin_hash = hashlib.sha256("admin123".encode()).hexdigest()
    try:
        cursor.execute(
            "INSERT INTO usuarios (username, senha_hash, papel) VALUES (?, ?, ?)",
            ("admin", senha_admin_hash, "admin"),
        )
        conn.commit()
        print("[SERVIDOR] Usuário admin padrão criado (senha: admin123)")
    except sqlite3.IntegrityError:
        pass

    # Cadastrar usuários de teste
    for usuario, senha in [("alice", "alice123"), ("bob", "bob123")]:
        senha_hash = hashlib.sha256(senha.encode()).hexdigest()
        try:
            cursor.execute(
                "INSERT INTO usuarios (username, senha_hash, papel) VALUES (?, ?, ?)",
                (usuario, senha_hash, "user"),
            )
            conn.commit()
            print(f"[SERVIDOR] Usuário '{usuario}' criado (senha: {senha})")
        except sqlite3.IntegrityError:
            pass

    conn.close()


# 
# Funções Auxiliares
# 

def hash_senha(senha: str) -> str:
    """Gera o hash SHA-256 de uma senha."""
    return hashlib.sha256(senha.encode()).hexdigest()


def autenticar_token(token: str):
    """
    Verifica se o token é válido.
    Retorna (username, papel) ou (None, None).
    """
    if not token:
        return None, None
    with lock:
        username = sessoes_ativas.get(token)
    if not username:
        return None, None
    db = get_db()
    try:
        usuario = db.execute(
            "SELECT username, papel FROM usuarios WHERE username = ?", (username,)
        ).fetchone()
    finally:
        db.close()
    if not usuario:
        return None, None
    return usuario["username"], usuario["papel"]


# 
# Handlers de Comandos
# 

def handle_status(dados: dict) -> dict:
    """Verifica se o servidor está rodando."""
    return {
        "status": "ok",
        "mensagem": "Servidor de comunicação segura está ativo.",
    }


def handle_login(dados: dict) -> dict:
    """Autentica um usuário e retorna um token de sessão."""
    username = dados.get("username")
    senha = dados.get("senha")
    if not username or not senha:
        return {"status": "erro", "erro": "Campos 'username' e 'senha' são obrigatórios."}

    senha_hash_enviada = hash_senha(senha)

    db = get_db()
    try:
        usuario = db.execute(
            "SELECT username, senha_hash, papel FROM usuarios WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        db.close()

    if not usuario or usuario["senha_hash"] != senha_hash_enviada:
        return {"status": "erro", "erro": "Credenciais inválidas. Acesso negado."}

    # Gerar token de sessão
    token = secrets.token_hex(32)
    with lock:
        sessoes_ativas[token] = username

    print(f"[SERVIDOR] Login bem-sucedido: {username} (papel: {usuario['papel']})")

    return {
        "status": "ok",
        "mensagem": f"Login bem-sucedido. Bem-vindo, {username}!",
        "token": token,
        "papel": usuario["papel"],
    }


def handle_logout(dados: dict) -> dict:
    """Encerra a sessão do usuário removendo o token."""
    token = dados.get("token")
    if not token:
        return {"status": "erro", "erro": "Token ausente."}
    with lock:
        username = sessoes_ativas.pop(token, None)
    if username:
        print(f"[SERVIDOR] Logout: {username}")
        return {"status": "ok", "mensagem": "Sessão encerrada com sucesso."}
    return {"status": "erro", "erro": "Token inválido."}


def handle_chave(dados: dict) -> dict:
    """Retorna a chave Fernet compartilhada."""
    token = dados.get("token")
    username, papel = autenticar_token(token)
    if not username:
        return {"status": "erro", "erro": "Acesso negado. Token inválido ou ausente."}
    return {"status": "ok", "chave": CHAVE_FERNET.decode()}


def handle_enviar(dados: dict) -> dict:
    """Recebe e armazena uma mensagem criptografada."""
    token = dados.get("token")
    username, papel = autenticar_token(token)
    if not username:
        return {"status": "erro", "erro": "Acesso negado. Token inválido ou ausente."}

    destinatario = dados.get("destinatario")
    conteudo_cifrado = dados.get("conteudo_cifrado")
    if not destinatario or not conteudo_cifrado:
        return {"status": "erro", "erro": "Campos 'destinatario' e 'conteudo_cifrado' são obrigatórios."}

    db = get_db()
    try:
        dest = db.execute(
            "SELECT username FROM usuarios WHERE username = ?", (destinatario,)
        ).fetchone()
        if not dest:
            return {"status": "erro", "erro": f"Usuário destinatário '{destinatario}' não encontrado."}

        timestamp = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO mensagens (remetente, destinatario, conteudo_cifrado, timestamp, lida) VALUES (?, ?, ?, ?, 0)",
            (username, destinatario, conteudo_cifrado.encode("utf-8"), timestamp),
        )
        db.commit()
    finally:
        db.close()

    print(f"[SERVIDOR] Mensagem enviada de '{username}' para '{destinatario}'")

    return {
        "status": "ok",
        "mensagem": f"Mensagem enviada para '{destinatario}' com sucesso.",
        "timestamp": timestamp,
    }


def handle_receber(dados: dict) -> dict:
    """Retorna mensagens do usuário autenticado (descriptografadas)."""
    token = dados.get("token")
    username, papel = autenticar_token(token)
    if not username:
        return {"status": "erro", "erro": "Acesso negado. Token inválido ou ausente."}

    db = get_db()
    try:
        mensagens = db.execute(
            "SELECT id, remetente, destinatario, conteudo_cifrado, timestamp, lida "
            "FROM mensagens WHERE destinatario = ? ORDER BY timestamp ASC",
            (username,),
        ).fetchall()

        resultado = []
        for msg in mensagens:
            try:
                cifrado = msg["conteudo_cifrado"]
                if isinstance(cifrado, bytes):
                    cifrado = cifrado.decode()
                conteudo_decifrado = fernet.decrypt(cifrado.encode()).decode()
            except Exception:
                conteudo_decifrado = "[ERRO: Não foi possível descriptografar]"

            resultado.append({
                "id": msg["id"],
                "remetente": msg["remetente"],
                "destinatario": msg["destinatario"],
                "conteudo": conteudo_decifrado,
                "timestamp": msg["timestamp"],
                "lida": bool(msg["lida"]),
            })

        # Marcar mensagens como lidas
        db.execute(
            "UPDATE mensagens SET lida = 1 WHERE destinatario = ? AND lida = 0",
            (username,),
        )
        db.commit()
    finally:
        db.close()

    return {"status": "ok", "mensagens": resultado, "total": len(resultado)}


def handle_todas(dados: dict) -> dict:
    """[ADMIN] Retorna todas as mensagens do sistema (descriptografadas)."""
    token = dados.get("token")
    username, papel = autenticar_token(token)
    if not username:
        return {"status": "erro", "erro": "Acesso negado. Token inválido ou ausente."}
    if papel != "admin":
        return {"status": "erro", "erro": "Acesso negado. Permissão de administrador necessária."}

    db = get_db()
    try:
        mensagens = db.execute(
            "SELECT id, remetente, destinatario, conteudo_cifrado, timestamp, lida "
            "FROM mensagens ORDER BY timestamp ASC"
        ).fetchall()

        resultado = []
        for msg in mensagens:
            try:
                cifrado = msg["conteudo_cifrado"]
                if isinstance(cifrado, bytes):
                    cifrado = cifrado.decode()
                conteudo_decifrado = fernet.decrypt(cifrado.encode()).decode()
            except Exception:
                conteudo_decifrado = "[ERRO: Não foi possível descriptografar]"

            resultado.append({
                "id": msg["id"],
                "remetente": msg["remetente"],
                "destinatario": msg["destinatario"],
                "conteudo": conteudo_decifrado,
                "timestamp": msg["timestamp"],
                "lida": bool(msg["lida"]),
            })
    finally:
        db.close()

    return {"status": "ok", "mensagens": resultado, "total": len(resultado)}


def handle_cadastrar(dados: dict) -> dict:
    """[ADMIN] Cadastra um novo usuário no sistema."""
    token = dados.get("token")
    username, papel = autenticar_token(token)
    if not username:
        return {"status": "erro", "erro": "Acesso negado. Token inválido ou ausente."}
    if papel != "admin":
        return {"status": "erro", "erro": "Acesso negado. Permissão de administrador necessária."}

    novo_username = dados.get("username_novo")
    nova_senha = dados.get("senha_nova")
    novo_papel = dados.get("papel_novo", "user")

    if not novo_username or not nova_senha:
        return {"status": "erro", "erro": "Campos 'username_novo' e 'senha_nova' são obrigatórios."}

    if novo_papel not in ("user", "admin"):
        return {"status": "erro", "erro": "Papel deve ser 'user' ou 'admin'."}

    senha_hash_val = hash_senha(nova_senha)

    db = get_db()
    try:
        db.execute(
            "INSERT INTO usuarios (username, senha_hash, papel) VALUES (?, ?, ?)",
            (novo_username, senha_hash_val, novo_papel),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return {"status": "erro", "erro": f"Usuário '{novo_username}' já existe."}
    finally:
        db.close()

    print(f"[SERVIDOR] Novo usuário cadastrado pelo admin: {novo_username} (papel: {novo_papel})")

    return {
        "status": "ok",
        "mensagem": f"Usuário '{novo_username}' cadastrado com sucesso.",
        "papel": novo_papel,
    }


def handle_usuarios(dados: dict) -> dict:
    """[ADMIN] Lista todos os usuários cadastrados no sistema."""
    token = dados.get("token")
    username, papel = autenticar_token(token)
    if not username:
        return {"status": "erro", "erro": "Acesso negado. Token inválido ou ausente."}
    if papel != "admin":
        return {"status": "erro", "erro": "Acesso negado. Permissão de administrador necessária."}

    db = get_db()
    try:
        usuarios = db.execute("SELECT username, papel FROM usuarios ORDER BY username").fetchall()
    finally:
        db.close()

    resultado = [{"username": u["username"], "papel": u["papel"]} for u in usuarios]
    return {"status": "ok", "usuarios": resultado, "total": len(resultado)}


def handle_banco(dados: dict) -> dict:
    """[ADMIN/DEBUG] Mostra o conteúdo bruto do banco de dados."""
    token = dados.get("token")
    username, papel = autenticar_token(token)
    if not username:
        return {"status": "erro", "erro": "Acesso negado. Token inválido ou ausente."}
    if papel != "admin":
        return {"status": "erro", "erro": "Acesso negado. Permissão de administrador necessária."}

    db = get_db()
    try:
        usuarios = db.execute("SELECT id, username, papel FROM usuarios").fetchall()
        mensagens = db.execute(
            "SELECT id, remetente, destinatario, conteudo_cifrado, timestamp, lida FROM mensagens"
        ).fetchall()
    finally:
        db.close()

    resultado_usuarios = [
        {"id": u["id"], "username": u["username"], "papel": u["papel"]}
        for u in usuarios
    ]

    resultado_mensagens = []
    for msg in mensagens:
        cifrado = msg["conteudo_cifrado"]
        if isinstance(cifrado, bytes):
            cifrado = cifrado.decode("utf-8", errors="replace")
        resultado_mensagens.append({
            "id": msg["id"],
            "remetente": msg["remetente"],
            "destinatario": msg["destinatario"],
            "conteudo_cifrado": cifrado,
            "timestamp": msg["timestamp"],
            "lida": msg["lida"],
        })

    return {
        "status": "ok",
        "usuarios": resultado_usuarios,
        "mensagens_cifradas": resultado_mensagens,
    }


# Mapeamento de ações para handlers
HANDLERS = {
    "status": handle_status,
    "login": handle_login,
    "logout": handle_logout,
    "chave": handle_chave,
    "enviar": handle_enviar,
    "receber": handle_receber,
    "todas": handle_todas,
    "cadastrar": handle_cadastrar,
    "usuarios": handle_usuarios,
    "banco": handle_banco,
}


# 
# Comunicação TCP
# 

def receber_dados(conn: socket.socket) -> str:
    """Recebe dados do socket até encontrar o delimitador newline."""
    buffer = b""
    while True:
        try:
            dados = conn.recv(4096)
        except (ConnectionResetError, OSError):
            return ""
        if not dados:
            return ""
        buffer += dados
        if b"\n" in buffer:
            mensagem, _ = buffer.split(b"\n", 1)
            return mensagem.decode("utf-8")


def enviar_dados(conn: socket.socket, dados: dict):
    """Envia um dicionário como JSON + newline pelo socket."""
    mensagem = json.dumps(dados, ensure_ascii=False) + "\n"
    conn.sendall(mensagem.encode("utf-8"))


def tratar_cliente(conn: socket.socket, addr: tuple):
    """Trata a conexão de um cliente em loop."""
    print(f"[SERVIDOR] Nova conexão de {addr[0]}:{addr[1]}")

    try:
        while True:
            dados_raw = receber_dados(conn)
            if not dados_raw:
                break

            try:
                dados = json.loads(dados_raw)
            except json.JSONDecodeError:
                enviar_dados(conn, {"status": "erro", "erro": "JSON inválido."})
                continue

            acao = dados.get("acao", "")
            handler = HANDLERS.get(acao)

            if handler:
                resposta = handler(dados)
            else:
                resposta = {"status": "erro", "erro": f"Ação desconhecida: '{acao}'."}

            enviar_dados(conn, resposta)
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        print(f"[SERVIDOR] Conexão encerrada: {addr[0]}:{addr[1]}")
        conn.close()


# 
# Inicialização
# 

if __name__ == "__main__":
    print("=" * 60)
    print("  SERVIDOR DE COMUNICAÇÃO SEGURA (Socket TCP)")
    print("  Sistema Distribuído com Autenticação e Criptografia")
    print("=" * 60)

    inicializar_banco()
    print(f"\n[SERVIDOR] Banco de dados: {DB_PATH}")
    print(f"[SERVIDOR] Chave Fernet carregada de: {KEY_PATH}")
    print(f"[SERVIDOR] Iniciando servidor TCP em {HOST}:{PORT}...\n")

    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((HOST, PORT))
    servidor.listen(5)

    print(f"[SERVIDOR] Aguardando conexões em {HOST}:{PORT}...")

    try:
        while True:
            conn, addr = servidor.accept()
            thread = threading.Thread(target=tratar_cliente, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\n[SERVIDOR] Encerrando servidor...")
    finally:
        servidor.close()
