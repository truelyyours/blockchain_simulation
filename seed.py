from json import dumps
from types import SimpleNamespace
from argparse import ArgumentParser
from socket import AF_INET, SOCK_STREAM, socket
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE


# cmd args parsing
parser = ArgumentParser()
parser.add_argument('-ip', type=str, required=True)
parser.add_argument('-port', type=int, required=True)
parser.add_argument(
    '--outputfile', help="name of output file", default='outputseed.txt')
args = parser.parse_args()


# exactly receive length bytes from sock
def recv_all(sock, length):
    recv_data = []
    while length > 0:
        fragment = sock.recv(length)
        # if zero bytes received than socket closed
        if not fragment:
            break
        length -= len(fragment)
        recv_data.append(fragment)
    return b''.join(recv_data)


def peer_list_to_json(peer_list):
    peer_json = []
    for peer in peer_list:
        peer_json.append({'ip': peer[0], 'port': peer[1]})
    return peer_json


class SeedNode():
    """
    Seed Node class for functions related to seednode
    """

    def __init__(self, ip, port):
        self.peer_list = set()
        self.log_file = open(args.outputfile, 'ab')
        self.ip = ip
        self.port = port
        self.initialize_socket()

    def log(self, message):
        """
        log the message to the logfile and to screen
        """

        if isinstance(message, (str)):
            print(message)
            self.log_file.write((message+'\n').encode())
        elif isinstance(message, (bytes, bytearray)):
            print(message.decode())
            self.log_file.write(message + b'\n')

    def initialize_socket(self):
        """
        Initializes the socket and selector object
        """
        self.selector = DefaultSelector()
        self.socket = socket(AF_INET, SOCK_STREAM)
        self.socket.bind((self.ip, self.port))
        self.socket.listen()
        self.socket.setblocking(False)
        self.selector.register(self.socket, EVENT_READ, data=None)

    def accept_wrapper(self, sock):
        """
        wrapper function to socket.accept() to get the new socket
        object and register it with selector
        """
        conn, addr = sock.accept()
        peer_info_length = int(recv_all(conn, 8).decode())
        peer_info = recv_all(conn, peer_info_length).decode().split(':')
        conn.setblocking(False)
        peer_list_bytes = dumps(peer_list_to_json(self.peer_list)).encode()
        conn.sendall(str(len(peer_list_bytes)).zfill(8).encode())
        conn.sendall(peer_list_bytes)
        # print(self.peer_list)
        # print(peer_info)
        self.log("Connection request {}:{}".format(peer_info[1], peer_info[2]))
        data = SimpleNamespace(addr=addr, inb=b"", outb=b"")
        events = EVENT_READ | EVENT_WRITE
        self.selector.register(conn, events, data=data)
        self.peer_list.add((peer_info[1], peer_info[2]))

    def service_connection(self, key, mask):
        """
        Service a connection request
        """
        sock = key.fileobj
        if mask & EVENT_READ:
            message_len = recv_all(sock, 8)
            if message_len:
                message_len = int(message_len.decode())
                recv_data = recv_all(sock, message_len)
                # print(recv_data)
                if b'Dead Node' in recv_data:
                    self.handle_dead_req(recv_data)
            else:
                # socket closed
                self.selector.unregister(sock)
                sock.close()

    def run(self):
        """
        Main loop
        """
        try:
            while True:
                events = self.selector.select(timeout=None)
                for key, mask in events:
                    if key.data is None:
                        # its from the listening socket, we need to accept
                        # the connection
                        self.accept_wrapper(key.fileobj)
                    else:
                        self.service_connection(key, mask)
        except KeyboardInterrupt:
            print("Exiting")
            self.log_file.close()
        finally:
            self.selector.close()

    def registration_request(self, connection, ip_addr=None, port=None):
        """
        Handle a registratoin request of incoming connection

        Args:
            connection: Socketobject connection of incoming request
            ip_addr : ip_addr of incoming connection (optional)
            port : port of incoming connection (optional)

        Returns:
            None
        """
        pass

    def handle_dead_req(self, dead_message: bytes):
        """
        Parses the dead node request to return the ip of sender and dead
        node. Output to the screen and the log file
        Updates the peerlist
        Args:
            dead_message: message of format "Dead Node:<dead.ip>:timestamp:sender ip"
        Returns:
            tuple: dead_ip
        """
        splitted_message = dead_message.split(b':')
        dead_peer_ip = splitted_message[1].decode()
        dead_peer_port = splitted_message[2].decode()
        try:
            self.peer_list.remove((dead_peer_ip, dead_peer_port))
            # print(self.peer_list)
            self.log(b'Receiving Dead node message ' + dead_message)
        except KeyError:  # ip not in peer list or already removed
            # print("%s:%s does not exist in peer list or already reported" %
            # (dead_peer_ip, dead_peer_port))
            self.log(b'Receiving Dead node message ' + dead_message)


ip_addr, port = [args.ip, args.port]
seedr = SeedNode(ip_addr, port)
seedr.run()
