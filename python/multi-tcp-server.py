import socket

server_ip = "0.0.0.0" # replace with server IP address
server_ports = [50000, 50001, 50002] # list of port numbers

sockets = []
for port in server_ports:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((server_ip, port))
    sock.listen(5)
    sockets.append(sock)
    print("[*] Listening on 0.0.0.0:" + str(port))

while True:
    for sock in sockets:
        (client_sock, client_address) = sock.accept()
        print("Received connection from", client_address)
        data = client_sock.recv(1024)
        print("Received data:", data)
        client_sock.send(b"ACK")
