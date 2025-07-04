import socket
import struct
import hashlib
import threading
import random
import time

# Configurações gerais
PORT = 51511
PEER_REQUEST = 0x1
PEER_LIST = 0x2
ARCHIVE_REQUEST = 0x3
ARCHIVE_RESPONSE = 0x4
ACK = 0x5

BYTES_RECEBIDOS = 2048*16
# Lista de pares conhecidos
peers = set()
lock = threading.Lock()
history_ready_event = threading.Event()


# Histórico de chats
chat_history = []

DEBUG = False

def custom_print(msg):
   if(DEBUG):
      print(msg)

def pack_ip(ip):
 print("Converte um endereço IP (string) para 4 bytes.")
 return socket.inet_aton(ip)

def unpack_ip(data):
 print("Converte 4 bytes para um endereço IP (string).")
 return socket.inet_ntoa(data)

def send_peer_request(sock):
 print("Envia uma mensagem PeerRequest.")
 sock.sendall(struct.pack('!B', PEER_REQUEST))

def handle_peer_list(data):
 print("Processa uma mensagem PeerList.")
 global peers
 num_peers = struct.unpack('!I', data[1:5])[0]
 new_peers = [unpack_ip(data[5 + i * 4:9 + i * 4]) for i in range(num_peers)]
 
 with lock:
     for peer in new_peers:
         if peer not in peers:
             peers.add(peer)
             threading.Thread(target=connect_to_peer, daemon=True, args=(peer,)).start()
     print(f"Número de peers conectados: {len(peers)}")

def connect_to_peer(ip):
    print("Conecta-se a um novo par e inicia o protocolo P2P.")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, PORT))
        print(f"Conectado ao par: {ip}")
        
        # Enviar PeerRequest e depois ArchiveRequest
        send_peer_request(sock)
        time.sleep(0.5)  # pequena espera para garantir resposta do peer
        sock.sendall(struct.pack('!B', ARCHIVE_REQUEST))
        
        while True:
            data = sock.recv(BYTES_RECEBIDOS)
            if not data:
                break

            message_type = data[0]
            if message_type == PEER_LIST:
                print(f'PEER_LIST: {PEER_LIST}')
                handle_peer_list(data)
            elif message_type == ARCHIVE_REQUEST:
                custom_print(f"----{data}")
                print(f'ARCHIVE_REQUEST: {ARCHIVE_REQUEST}')
                send_archive_response(sock)
            elif message_type == ARCHIVE_RESPONSE:
                print(f'ARCHIVE_RESPONSE: {ARCHIVE_RESPONSE}')
                handle_archive_response(data)
            #elif message_type == ACK:
                #print(f'ACK: {ACK}')
    except Exception as e:
        print(f"Erro ao conectar ao par {ip}: {e}")


def send_archive_response(sock):
 print("Envia o histórico de chats atual como ArchiveResponse.")
 global chat_history
 with lock:
     response = struct.pack('!B', ARCHIVE_RESPONSE)
     response += struct.pack('!I', len(chat_history))
     for chat in chat_history:
         response += chat
     sock.sendall(response)

def handle_archive_response(data):
    print("Processa uma mensagem ArchiveResponse.")
    global chat_history
    if len(data) < 5:
        print("❌ Dados muito curtos para conter número de mensagens.")
        return

    num_chats = struct.unpack('!I', data[1:5])[0]
    print(f"Número de chats recebidos: {num_chats}")
    custom_print(f"data: {data}")
    new_history = []
    offset = 5
    for i in range(num_chats):
        if offset >= len(data):
            print(f"❌ Offset fora do intervalo no chat {i+1}")
            break  # para o loop

        n = data[offset]
        expected_len = 1 + n + 32
        if offset + expected_len > len(data):
            print(f"❌ Dados insuficientes para mensagem {i+1}: esperava {expected_len} bytes, mas só há {len(data) - offset}")
            break

        chat = data[offset:offset + expected_len]

        # Imprime mensagem crua em hex para visualização
        custom_print(f"Mensagem {i+1} ({expected_len} bytes): {chat.hex()}")

        new_history.append(chat)
        offset += expected_len

    # Atualiza o histórico com o novo conteúdo recebido
    with lock:
        chat_history = new_history
        print(f"✅ Histórico atualizado com {len(chat_history)} mensagens.")


    if validate_history(new_history):
        with lock:
            if len(new_history) > len(chat_history):
                chat_history = new_history
                print("✅ Histórico atualizado!")
        # Sinaliza que o histórico foi carregado
        history_ready_event.set()



def validate_history(history):
    print(f"Validando histórico com {len(history)} mensagens...")
    if not history:
        return True
    
    for i in range(len(history)):
        chat = history[i]
        n = chat[0]
        text = chat[1:1 + n]
        verifier = chat[1 + n:1 + n + 16]
        md5_hash = chat[1 + n + 16:1 + n + 32]

        print(f"Mensagem {i+1}: {text.decode('ascii', errors='replace')}")
        print(f"Verificador: {verifier.hex()}")
        custom_print(f"MD5 recebido: {md5_hash.hex()}")

        if md5_hash[:2] != b'\x00\x00':
            print("❌ MD5 não começa com dois bytes zero")
            return False

        # Construir sequência S
        prev_20 = b''.join(history[max(0, i - 19):i])
        # Pega os últimos 20 chats anteriores, com tudo (inclusive o hash):
        prev_20 = b''.join(history[max(0, i - 20):i])  # pegar até 20 anteriores

        # Pega o início do chat atual (até o verifier), ignora o hash
        chat_without_hash = chat[:1 + n + 16]  # n (tamanho do texto) + texto + verifier

        # Monta sequência S
        sequence = prev_20 + chat_without_hash # + b'\x00' * 16

        #sequence = prev_20 + chat[:1 + n + 16] + b'\x00' * 16
        
        #print(f"sequence: {sequence}");

        
        calculated_md5 = hashlib.md5(sequence).digest()
        # print("Chat original:", chat)
        # print("chat[:1+n+16]:", chat[:1 + n + 16])
        # print("chat[-16:]:", chat[-16:])
        # print("MD5 esperado:", md5_hash.hex())
        # print("MD5 calculado:", calculated_md5.hex())
        if calculated_md5 != md5_hash:
            print(f"❌ MD5 inválido: esperado {md5_hash.hex()}, calculado {calculated_md5.hex()}")
            return False

    print("✅ Histórico válido.")
    return True

def mine_chat(text):
 print("Minera um novo chat com base no texto fornecido.")
 global chat_history
 text_bytes = text.encode('ascii')
 n = len(text_bytes)
 
 while True:
     verifier = struct.pack('!16B', *[random.randint(0, 255) for _ in range(16)])
     sequence = b''.join(chat_history[-20:]) + struct.pack('!B', n) + text_bytes + verifier + b'\x00' * 16
     md5_hash = hashlib.md5(sequence).digest()
     if md5_hash[:2] == b'\x00\x00':
        print('resolveu')
        print(f'verifier: {verifier}')
        print(f'md5_hash: {md5_hash}')
        return struct.pack('!B', n) + text_bytes + verifier + md5_hash

def broadcast_new_chat(chat):
 print("Dissemina um novo chat para todos os pares.")
 global peers
 with lock:
        for peer in peers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((peer, PORT))
                
                response = struct.pack('!B', ARCHIVE_RESPONSE)
                response += struct.pack('!I', len(chat))  # Apenas 1 chat sendo enviado
                for c in chat:
                    response += c
                print(response)
                sock.sendall(response)

                sock.close()
            except Exception as e:
                print(f"Erro ao enviar chat para {peer}: {e}")


def start_server():
 print("Inicia o servidor para aceitar conexões de outros pares.")
 server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 server_sock.bind(('0.0.0.0', PORT))
 server_sock.listen(5)
 print(f"Servidor escutando na porta {PORT}...")
 
 while True:
     client_sock, addr = server_sock.accept()
     print(f"Conexão recebida de {addr[0]}")
     threading.Thread(target=handle_client, daemon=True, args=(client_sock,)).start()

def handle_client(sock):
 print("Lida com mensagens recebidas de um cliente.")
 try:
     while True:
         data = sock.recv(BYTES_RECEBIDOS)
         if not data:
             break
         
         message_type = data[0]
         if message_type == PEER_REQUEST:
            custom_print(f"Recebida: {PEER_REQUEST}")
            send_peer_list(sock)
         elif message_type == ARCHIVE_REQUEST:
            custom_print(f"Recebida: {ARCHIVE_REQUEST}")
            send_archive_response(sock)
         elif message_type == ARCHIVE_RESPONSE:
            custom_print(f"Recebida: {ARCHIVE_RESPONSE}")
            handle_archive_response(data)
            #sock.sendall(struct.pack('!B', ACK))
 except Exception as e:
     print(f"Erro ao lidar com cliente: {e}")
 finally:
     sock.close()

def send_peer_list(sock):
 print("Envia a lista de pares conhecidos.")
 global peers
 with lock:
     response = struct.pack('!B', PEER_LIST)
     response += struct.pack('!I', len(peers))
     for peer in peers:
         response += pack_ip(peer)
     sock.sendall(response)

def main():
    print("Função principal.")
    initial_peer = 'pugna.snes.dcc.ufmg.br'
    threading.Thread(target=start_server, daemon=True).start()
    threading.Thread(target=connect_to_peer, args=(initial_peer,), daemon=True).start()

    print("⏳ Aguardando recebimento do histórico inicial...")
    history_ready_event.wait(timeout=5)  # Aguarda até 5 segundos
    print("📜 Histórico inicial:")
    with lock:
        for i, chat in enumerate(chat_history, 1):
            exibe_historico(chat, i)

    # Ciclo principal
    while True:
        command = input("Digite 'enviar' para enviar um chat ou 'sair' para sair: ").strip().lower()
        print(f'comando enviado: {command}')
        if command == 'enviar':
            text = "Uai"
            new_chat = mine_chat(text)
            with lock:
                chat_history.append(new_chat)
                print(f'newChat: {chat_history}')
            broadcast_new_chat(new_chat)
        elif command == 'historico':
            with lock:
                print("📜 Histórico atual:")
                for i, chat in enumerate(chat_history, 1):
                    exibe_historico(chat, i)
                print(f'peers: {len(peers)}')
                for peer in peers:
                    print(f'peer: {peer}')
        elif command == 'sair':
            break

def exibe_historico(chat, i):
    try:
        n = chat[0]
        text = chat[1:1 + n].decode('utf-8', errors='replace')
        print(f"{i}. {text}")
    except:
        print(f"{i}. [Erro ao decodificar mensagem]")

def recv_all(sock, n):
    """Lê n bytes do socket, mesmo que venham fragmentados."""
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Conexão fechada antes de receber todos os dados")
        data += packet
    return data

if __name__ == "__main__":
 main()