"""
Cliente (Socket TCP) - Sistema de Comunicação Segura entre Processos Distribuídos

Funcionalidades:
- Login com username/senha via socket TCP
- Obtenção da chave Fernet compartilhada
- Envio de mensagens criptografadas
- Leitura de mensagens (descriptografadas pelo servidor)
- Funções administrativas (cadastro, listagem de usuários, leitura de todas as mensagens)

Protocolo: JSON delimitado por newline (\n) sobre TCP.
"""

import sys
import socket
import json

from cryptography.fernet import Fernet
from colorama import init, Fore, Style

# Inicializar colorama para cores no terminal
init(autoreset=True)

# 
# Configuração
# 

SERVIDOR_IP = "10.252.164.106"
SERVIDOR_PORT = 5000


# 
# Comunicação TCP
# 

def enviar_comando(host: str, port: int, comando: dict) -> dict:
    """
    Conecta ao servidor, envia um comando JSON e retorna a resposta.
    Cada operação abre e fecha uma conexão (modelo request/response simples).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))

        # Enviar comando como JSON + newline
        mensagem = json.dumps(comando, ensure_ascii=False) + "\n"
        sock.sendall(mensagem.encode("utf-8"))

        # Receber resposta
        buffer = b""
        while True:
            dados = sock.recv(4096)
            if not dados:
                break
            buffer += dados
            if b"\n" in buffer:
                resposta_raw, _ = buffer.split(b"\n", 1)
                return json.loads(resposta_raw.decode("utf-8"))

        # Se não recebeu newline mas tem dados
        if buffer:
            return json.loads(buffer.decode("utf-8"))

        return {"status": "erro", "erro": "Servidor não respondeu."}
    except ConnectionRefusedError:
        return {"status": "erro", "erro": f"Não foi possível conectar ao servidor em {host}:{port}"}
    except socket.timeout:
        return {"status": "erro", "erro": "Tempo de conexão esgotado."}
    except json.JSONDecodeError:
        return {"status": "erro", "erro": "Resposta inválida do servidor."}
    except Exception as e:
        return {"status": "erro", "erro": str(e)}
    finally:
        sock.close()


class ClienteSeguro:
    """Cliente para comunicação segura com o servidor central via socket TCP."""

    def __init__(self, host: str = SERVIDOR_IP, port: int = SERVIDOR_PORT):
        self.host = host
        self.port = port
        self.token: str | None = None
        self.username: str | None = None
        self.papel: str | None = None
        self.fernet: Fernet | None = None

    def _cmd(self, comando: dict) -> dict:
        """Envia um comando ao servidor e retorna a resposta."""
        return enviar_comando(self.host, self.port, comando)

    # 
    # Autenticação
    # 

    def login(self, username: str, senha: str) -> bool:
        """Realiza login no servidor e obtém o token de sessão."""
        resp = self._cmd({"acao": "login", "username": username, "senha": senha})

        if resp.get("status") == "ok":
            self.token = resp["token"]
            self.username = username
            self.papel = resp["papel"]
            print(f"\n{Fore.GREEN}{resp['mensagem']}")

            # Obter chave Fernet do servidor
            self._obter_chave()
            return True
        else:
            erro = resp.get("erro", "Erro desconhecido")
            print(f"\n{Fore.RED}Falha no login: {erro}{Style.RESET_ALL}")
            return False

    def logout(self) -> bool:
        """Encerra a sessão no servidor."""
        if not self.token:
            print(f"{Fore.YELLOW} Nenhuma sessão ativa.{Style.RESET_ALL}")
            return False

        resp = self._cmd({"acao": "logout", "token": self.token})

        if resp.get("status") == "ok":
            print(f"\n{Fore.GREEN}Sessão encerrada com sucesso.{Style.RESET_ALL}")
            self.token = None
            self.username = None
            self.papel = None
            self.fernet = None
            return True
        else:
            print(f"\n{Fore.RED}Erro ao encerrar sessão.{Style.RESET_ALL}")
            return False

    def _obter_chave(self):
        """Obtém a chave Fernet compartilhada do servidor."""
        resp = self._cmd({"acao": "chave", "token": self.token})

        if resp.get("status") == "ok":
            chave = resp["chave"]
            self.fernet = Fernet(chave.encode())
        else:
            print(f"{Fore.RED}Erro ao obter chave Fernet.{Style.RESET_ALL}")

    # 
    # Mensagens
    # 

    def enviar_mensagem(self, destinatario: str, conteudo: str) -> bool:
        """
        Criptografa e envia uma mensagem para o destinatário.
        A mensagem é criptografada localmente com Fernet antes do envio.
        """
        if not self.token or not self.fernet:
            print(f"{Fore.YELLOW} Faça login primeiro.{Style.RESET_ALL}")
            return False

        # Criptografar a mensagem antes de enviar
        conteudo_cifrado = self.fernet.encrypt(conteudo.encode()).decode()

        resp = self._cmd({
            "acao": "enviar",
            "token": self.token,
            "destinatario": destinatario,
            "conteudo_cifrado": conteudo_cifrado,
        })

        if resp.get("status") == "ok":
            print(f"{Fore.GREEN}{resp['mensagem']}")
            return True
        else:
            erro = resp.get("erro", "Erro desconhecido")
            print(f"{Fore.RED}Erro ao enviar: {erro}{Style.RESET_ALL}")
            return False

    def ler_mensagens(self) -> list:
        """
        Busca e exibe as mensagens destinadas ao usuário.
        O servidor descriptografa as mensagens antes da entrega.
        """
        if not self.token:
            print(f"{Fore.YELLOW} Faça login primeiro.{Style.RESET_ALL}")
            return []

        resp = self._cmd({"acao": "receber", "token": self.token})

        if resp.get("status") == "ok":
            mensagens = resp["mensagens"]

            if not mensagens:
                print(f"\n{Fore.YELLOW} Nenhuma mensagem encontrada.{Style.RESET_ALL}")
                return []

            print(f"\n{Fore.GREEN} {resp['total']} mensagem(ns) encontrada(s):{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'' * 50}{Style.RESET_ALL}")

            for msg in mensagens:
                status = "" if msg["lida"] else ""
                print(f"\n  {status} ID: {msg['id']}")
                print(f"     De: {Fore.CYAN}{msg['remetente']}{Style.RESET_ALL}")
                print(f"     Para: {Fore.CYAN}{msg['destinatario']}{Style.RESET_ALL}")
                print(f"     Conteúdo: {Fore.GREEN}{msg['conteudo']}{Style.RESET_ALL}")
                print(f"     Data: {msg['timestamp']}")
                print(f"     Lida: {'Sim' if msg['lida'] else 'Não'}")

            print(f"\n{Fore.CYAN}{'' * 50}{Style.RESET_ALL}")
            return mensagens
        else:
            erro = resp.get("erro", "Erro desconhecido")
            print(f"{Fore.RED}Erro ao ler mensagens: {erro}{Style.RESET_ALL}")
            return []

    def ler_mensagens_de_outro(self, username_alvo: str) -> list:
        """
        Tenta ler mensagens de outro usuário.
        Apenas admin tem permissão.
        """
        if not self.token:
            print(f"{Fore.YELLOW} Faça login primeiro.{Style.RESET_ALL}")
            return []

        print(f"\n{Fore.YELLOW} Tentando ler mensagens de '{username_alvo}'...{Style.RESET_ALL}")

        # Tenta acessar o endpoint de todas as mensagens passando o alvo
        resp = self._cmd({"acao": "todas", "token": self.token, "alvo": username_alvo})

        if resp.get("status") == "ok":
            # Admin - filtra mensagens do alvo
            mensagens = [m for m in resp["mensagens"] if m["destinatario"] == username_alvo]

            if not mensagens:
                print(f"{Fore.YELLOW} Nenhuma mensagem encontrada para '{username_alvo}'.{Style.RESET_ALL}")
                return []

            print(f"{Fore.GREEN} {len(mensagens)} mensagem(ns) de '{username_alvo}':{Style.RESET_ALL}")
            for msg in mensagens:
                print(f"\n   ID: {msg['id']}")
                print(f"     De: {msg['remetente']}")
                print(f"     Conteúdo: {Fore.GREEN}{msg['conteudo']}{Style.RESET_ALL}")
                print(f"     Data: {msg['timestamp']}")
            return mensagens
        else:
            erro = resp.get("erro", "Permissão negada")
            print(f"{Fore.RED}ACESSO NEGADO: {erro}{Style.RESET_ALL}")
            print(f"{Fore.RED}  Usuários comuns só podem ler suas próprias mensagens.{Style.RESET_ALL}")
            return []

    # 
    # Administração
    # 

    def cadastrar_usuario(self, username: str, senha: str, papel: str = "user") -> bool:
        """[ADMIN] Cadastra um novo usuário no sistema."""
        if not self.token:
            print(f"{Fore.YELLOW} Faça login primeiro.{Style.RESET_ALL}")
            return False

        resp = self._cmd({
            "acao": "cadastrar",
            "token": self.token,
            "username_novo": username,
            "senha_nova": senha,
            "papel_novo": papel,
        })

        if resp.get("status") == "ok":
            print(f"\n{Fore.GREEN}{resp['mensagem']}{Style.RESET_ALL}")
            return True
        else:
            erro = resp.get("erro", "Erro desconhecido")
            print(f"\n{Fore.RED}{erro}{Style.RESET_ALL}")
            return False

    def listar_usuarios(self) -> list:
        """[ADMIN] Lista todos os usuários do sistema."""
        if not self.token:
            print(f"{Fore.YELLOW} Faça login primeiro.{Style.RESET_ALL}")
            return []

        resp = self._cmd({"acao": "usuarios", "token": self.token})

        if resp.get("status") == "ok":
            print(f"\n{Fore.GREEN} {resp['total']} usuário(s) cadastrado(s):{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'' * 40}{Style.RESET_ALL}")
            for u in resp["usuarios"]:
                icone = "" if u["papel"] == "admin" else ""
                print(f"  {icone} {u['username']} ({u['papel']})")
            print(f"{Fore.CYAN}{'' * 40}{Style.RESET_ALL}")
            return resp["usuarios"]
        else:
            erro = resp.get("erro", "Erro desconhecido")
            print(f"\n{Fore.RED}{erro}{Style.RESET_ALL}")
            return []

    def listar_todas_mensagens(self) -> list:
        """[ADMIN] Lista todas as mensagens do sistema."""
        if not self.token:
            print(f"{Fore.YELLOW} Faça login primeiro.{Style.RESET_ALL}")
            return []

        resp = self._cmd({"acao": "todas", "token": self.token})

        if resp.get("status") == "ok":
            mensagens = resp["mensagens"]

            if not mensagens:
                print(f"\n{Fore.YELLOW} Nenhuma mensagem no sistema.{Style.RESET_ALL}")
                return []

            print(f"\n{Fore.GREEN} [ADMIN] {resp['total']} mensagem(ns) no sistema:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'' * 50}{Style.RESET_ALL}")
            for msg in mensagens:
                print(f"\n   ID: {msg['id']}")
                print(f"     De: {Fore.CYAN}{msg['remetente']}{Style.RESET_ALL}  Para: {Fore.CYAN}{msg['destinatario']}{Style.RESET_ALL}")
                print(f"     Conteúdo: {Fore.GREEN}{msg['conteudo']}{Style.RESET_ALL}")
                print(f"     Data: {msg['timestamp']}")
                print(f"     Lida: {'Sim' if msg['lida'] else 'Não'}")
            print(f"\n{Fore.CYAN}{'' * 50}{Style.RESET_ALL}")
            return mensagens
        else:
            erro = resp.get("erro", "Erro desconhecido")
            print(f"\n{Fore.RED}{erro}{Style.RESET_ALL}")
            return []

    def visualizar_banco(self):
        """[ADMIN/DEBUG] Mostra o conteúdo bruto do banco (mensagens cifradas)."""
        if not self.token:
            print(f"{Fore.YELLOW} Faça login primeiro.{Style.RESET_ALL}")
            return

        resp = self._cmd({"acao": "banco", "token": self.token})

        if resp.get("status") == "ok":
            print(f"\n{Fore.MAGENTA}{'' * 60}")
            print(f"  CONTEÚDO BRUTO DO BANCO DE DADOS SQLite")
            print(f"{'' * 60}{Style.RESET_ALL}")

            print(f"\n{Fore.CYAN} Tabela: usuarios {Style.RESET_ALL}")
            for u in resp["usuarios"]:
                print(f"  ID: {u['id']} | Username: {u['username']} | Papel: {u['papel']}")

            print(f"\n{Fore.CYAN} Tabela: mensagens (CIFRADAS) {Style.RESET_ALL}")
            for msg in resp["mensagens_cifradas"]:
                print(f"\n  ID: {msg['id']}")
                print(f"  Remetente: {msg['remetente']}")
                print(f"  Destinatário: {msg['destinatario']}")
                print(f"  {Fore.RED}Conteúdo Cifrado: {msg['conteudo_cifrado'][:80]}...{Style.RESET_ALL}")
                print(f"  Timestamp: {msg['timestamp']}")
                print(f"  Lida: {msg['lida']}")

            print(f"\n{Fore.MAGENTA}{'' * 60}{Style.RESET_ALL}")
        else:
            erro = resp.get("erro", "Erro desconhecido")
            print(f"\n{Fore.RED}{erro}{Style.RESET_ALL}")


# 
# Menu Interativo
# 

def exibir_menu(cliente: ClienteSeguro):
    """Exibe o menu de opções do cliente."""
    print(f"\n{Fore.CYAN}{'' * 50}")
    if cliente.username:
        papel_str = f" [{cliente.papel.upper()}]" if cliente.papel else ""
        print(f"  Logado como: {Fore.GREEN}{cliente.username}{papel_str}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'' * 50}{Style.RESET_ALL}")

    if not cliente.token:
        print(f"  {Fore.WHITE}1. Login{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}0. Sair{Style.RESET_ALL}")
    else:
        print(f"  {Fore.WHITE}1. Enviar mensagem{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}2. Ler minhas mensagens{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}3. Tentar ler mensagens de outro usuário{Style.RESET_ALL}")
        if cliente.papel == "admin":
            print(f"  4. Listar todas as mensagens{Style.RESET_ALL}")
            print(f"  5. Cadastrar novo usuário{Style.RESET_ALL}")
            print(f"  6. Listar usuários{Style.RESET_ALL}")
            print(f"  7. Ver banco de dados (cifrado){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}8. Logout{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}0. Sair{Style.RESET_ALL}")

    print(f"{Fore.CYAN}{'' * 50}{Style.RESET_ALL}")


def main():
    """Função principal - menu interativo do cliente."""
    host = SERVIDOR_IP
    port = SERVIDOR_PORT

    # Permitir especificar host:port como argumento
    if len(sys.argv) > 1:
        partes = sys.argv[1].split(":")
        host = partes[0]
        if len(partes) > 1:
            port = int(partes[1])

    cliente = ClienteSeguro(host, port)

    print(f"\n{Fore.CYAN}{'' * 50}")
    print(f"  CLIENTE DE COMUNICAÇÃO SEGURA (Socket TCP)")
    print(f"  Servidor: {host}:{port}")
    print(f"{'' * 50}{Style.RESET_ALL}")

    while True:
        exibir_menu(cliente)
        try:
            opcao = input(f"\n{Fore.CYAN}Opção: {Style.RESET_ALL}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Fore.YELLOW}Encerrando...{Style.RESET_ALL}")
            break

        if not cliente.token:
            # Menu sem login
            if opcao == "1":
                username = input(f"  Username: ").strip()
                senha = input(f"  Senha: ").strip()
                cliente.login(username, senha)
            elif opcao == "0":
                print(f"\n{Fore.YELLOW}Encerrando cliente...{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Opção inválida.{Style.RESET_ALL}")
        else:
            # Menu com login
            if opcao == "1":
                destinatario = input(f"  Destinatário: ").strip()
                conteudo = input(f"  Mensagem: ").strip()
                if destinatario and conteudo:
                    cliente.enviar_mensagem(destinatario, conteudo)
                else:
                    print(f"{Fore.RED}Destinatário e mensagem são obrigatórios.{Style.RESET_ALL}")

            elif opcao == "2":
                cliente.ler_mensagens()

            elif opcao == "3":
                username_alvo = input(f"  Username do alvo: ").strip()
                if username_alvo:
                    cliente.ler_mensagens_de_outro(username_alvo)
                else:
                    print(f"{Fore.RED}Username é obrigatório.{Style.RESET_ALL}")

            elif opcao == "4" and cliente.papel == "admin":
                cliente.listar_todas_mensagens()

            elif opcao == "5" and cliente.papel == "admin":
                username = input(f"  Username do novo usuário: ").strip()
                senha = input(f"  Senha: ").strip()
                papel = input(f"  Papel (user/admin) [user]: ").strip() or "user"
                if username and senha:
                    cliente.cadastrar_usuario(username, senha, papel)
                else:
                    print(f"{Fore.RED}Username e senha são obrigatórios.{Style.RESET_ALL}")

            elif opcao == "6" and cliente.papel == "admin":
                cliente.listar_usuarios()

            elif opcao == "7" and cliente.papel == "admin":
                cliente.visualizar_banco()

            elif opcao == "8":
                cliente.logout()

            elif opcao == "0":
                if cliente.token:
                    cliente.logout()
                print(f"\n{Fore.YELLOW}Encerrando cliente...{Style.RESET_ALL}")
                break

            else:
                print(f"{Fore.RED}Opção inválida.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
