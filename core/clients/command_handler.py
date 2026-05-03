
"""
core/clients/command_handler.py — Servidor de comandos para interação remota.
Permite disparar pipelines manualmente via socket.
"""

import socket
import threading
import config
from core.logger import get_logger

logger = get_logger("core.clients.command_handler")

_pipeline_trigger = None

def set_pipeline_trigger(callback):
    """Define a função que será chamada ao receber o comando de scan."""
    global _pipeline_trigger
    _pipeline_trigger = callback

def start_server():
    """Inicia o servidor de comandos em uma thread separada."""
    thread = threading.Thread(target=_listen, daemon=True)
    thread.start()
    return thread

def _listen():
    """Loop de escuta do socket."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("127.0.0.1", config.COMMAND_PORT))
        server.listen(5)
        
        while True:
            client, addr = server.accept()
            data = client.recv(1024).decode().strip().lower()
            
            if data == "run" or data == "scan":
                logger.info("Comando manual recebido: %s", data)
                if _pipeline_trigger:
                    threading.Thread(target=_pipeline_trigger).start()
                    client.send(b"Pipeline disparado com sucesso.\n")
                else:
                    client.send(b"Erro: Trigger do pipeline nao configurado.\n")
            else:
                client.send(b"Comando desconhecido.\n")
            
            client.close()
    except Exception as e:
        logger.error("Erro no servidor de comandos: %s", e)
    finally:
        server.close()
