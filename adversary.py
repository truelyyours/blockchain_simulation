from time import sleep
from random import sample
from hashlib import sha256, sha3_256
from json import load, loads, dumps
from threading import Thread, get_ident
from datetime import datetime
from time import time as utctime
from types import SimpleNamespace
from argparse import ArgumentParser
from socket import AF_INET, SOCK_STREAM, socket
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE
from numpy import random
from networkx import Graph, draw
import matplotlib.pyplot as plt

# parse command line arguments
parser = ArgumentParser()
parser.add_argument('-ip', type=str, required=True)
parser.add_argument('-block_file', type=str, required=True)
parser.add_argument('-port', type=int, required=True)
parser.add_argument('--liveness', help="Enable logging of liveness messages", action="store_true")
parser.add_argument('--outputfile', help="name of output file", default='outputpeer.txt')
parser.add_argument('--time', help="Specify time format to be used", choices=['UNIX',    'UNIX_T',    'HUMAN'], default='UNIX_T')
parser.add_argument('-hashing_power', type=float, required=True)
parser.add_argument('-global_lambda', type=float, required=True)
args = parser.parse_args()

LOG_LIVENESS = args.liveness
TIME_FORMAT = args.time
BLOCK_FILE = args.block_file
hashing_power = args.hashing_power
global_lambda = args.global_lambda
CONNECTED_PERCENT = 10


def time():
    if TIME_FORMAT == 'UNIX':
        return utctime()
    elif TIME_FORMAT == 'UNIX_T':
        return int(utctime())
    elif TIME_FORMAT == 'HUMAN':
        return str(datetime.utcnow()).replace(":", "-")

# graph formed during the process will always be connected (induction)
# number (n/2)+1 is critical for connectedness of the graph


# exactly receive 'length' bytes from sock
def recv_all(sock, length):
    recv_data = []
    while length > 0:
        try:
            fragment = sock.recv(length)
            if not fragment:
                # connection closed by user
                return False
            length -= len(fragment)
            recv_data.append(fragment)
        except ConnectionResetError:
            return False
    return b''.join(recv_data)


def send_format(message: bytes):
    if isinstance(message, (str)):
        message = message.encode()
    return str(len(message)).zfill(8).encode() + message


class Block():
    """
    Contains pervious block hash, merkel root, unix_timestamp
    Block body empty for this assignment
    Merkel root constant because no transactions
    """

    def __init__(self, prev_hash, merkel_root, timestamp, is_adversary=0, parent=None):
        self.prev_hash = prev_hash
        self.merkel_root = "0000"
        self.timestamp = timestamp
        self.children = []
        self.parent = parent
        self.adversary_block = is_adversary
        if parent is not None:
            parent.children.append(self)

    def get_hash(self):
        return sha3_256(str(self).encode()).hexdigest()[-4:]

    def __repr__(self):
        return ",".join([self.prev_hash, '0000', self.timestamp, str(int(self.adversary_block))])

    # def __hash__(self):
        # this method should return integer wtf!
        # return sha3_256(str(self).encode()).hexdigest()[-4:]

    def __len__(self):
        return len(str(self))


def longest_path(root):
    # returns the leaf ending in longest path from root to leaf
    if len(root.children) == 0:
        return (root, 1)
    longest_path_length = 0
    longest_path_leaf = None
    for child in root.children:
        curr_path_leaf, curr_path_length = longest_path(child)
        if curr_path_length > longest_path_length:
            longest_path_leaf = curr_path_leaf
            longest_path_length = curr_path_length + 1
    return (longest_path_leaf, longest_path_length)


def print_tree(root):
    print(str(root), "->", list(map(str, root.children)))
    for child in root.children:
        print_tree(child)


class BlockChainTree:
    """
    self.all_blocks for faster search - set of hash values in tree
    first blocks are nodes at height 1 with prev_hash values = 9e1c
    Above is needed because of no explicit genesis block
    Not really a tree but a forest
    self.database mapping of hash(not prev_hash) to blocks for faster insertion
    """

    def __init__(self):
        self.database = {}
        self.all_blocks_hash = set(["9e1c"])
        self.first_blocks = []

    def get_blockchain(self):
        # returns chain in str format for sending purposes
        # find the longest path in the forest
        all_longest_path_pairs = [longest_path(block) for block in self.first_blocks]
        if len(all_longest_path_pairs) == 0:
            return []
        longest_path_pair = max(all_longest_path_pairs, key=lambda x: x[1])
        chain = [longest_path_pair[0]]
        while chain[-1].prev_hash != "9e1c":
            chain.append(chain[-1].parent)
        return list(reversed(list(map(str, chain))))

    def get_last_block_hash(self):
        all_longest_path_pairs = [longest_path(block) for block in self.first_blocks]
        if len(all_longest_path_pairs) == 0:
            return "9e1c"
        longest_path_pair = max(all_longest_path_pairs, key=lambda x: x[1])
        return longest_path_pair[0].get_hash()

    def insert(self, block):
        # block only has prev_hash, merkel_root, timestamp fields
        if block.get_hash() in self.all_blocks_hash:
            # dont insert already in tree
            return False
        if block.prev_hash == "9e1c":
            # no parent case
            self.first_blocks.append(block)
            self.all_blocks_hash.add(block.get_hash())
            self.database[block.get_hash()] = block
            return True
        elif block.prev_hash in self.all_blocks_hash:
            block.parent = self.database[block.prev_hash]
            self.database[block.get_hash()] = block
            self.database[block.prev_hash].children.append(block)
            self.all_blocks_hash.add(block.get_hash())
            return True
        return False

    def print_blockchain_tree(self):
        print("91ec(genesis)-> ", list(map(str, self.first_blocks)))
        for block in self.first_blocks:
            print_tree(block)

    def print_blockchain_graph(self):
        gra = Graph(name='Blockchain: {}:{}'.format(args.ip, args.port))
        gra.add_node('91ec')
        _ = self.first_blocks.copy()
        edges = [['91ec', self.first_blocks[0].get_hash()]]

        def bfs(root):
            edges.extend([[root.get_hash(), i.get_hash()] for i in root.children])
            for child in root.children:
                bfs(child)

        bfs(self.first_blocks[0])
        gra.add_edges_from(edges)

        # Drawing of graph
        draw(gra, with_labels=True, node_color=['red']+['blue']*(gra.number_of_nodes()-1))
        plt.show()
        # plt.savefig("something.png")


class PeerNode():
    """
    Peer Node class for functions related to peernode
    """

    def __init__(self, ip, port):
        """
        peer list format here is (ip, port)
        connected peer list is of form [ip, port, socket, outstanding messages]
        seed list format is [ip, port, socket]; only connected seeds
        """
        self.ip = ip
        self.port = port
        self.log_file = open(args.outputfile, 'ab')
        self.initialize_master_socket()
        self.peers_list = set()
        self.seeds_list = []
        self.connected_peers_list = []
        self.pending_queue = []
        self.blockchain = BlockChainTree()
        self.register_with_seeds()
        self.connect_to_peers()
        self.create_tree()
        self.mining_thread = Thread(target=self.mining_function)
        self.adversary_thread = Thread(target=self.adversary_function)
        self.killed_threads = set()
        # class for management of block database and longest chain
        # start periodic execution
        self.start_periodic_functions()
        # blocks which needs to be processed
        self.lamda = hashing_power * global_lambda/100.0
        self.mining_thread.start()
        self.adversary_thread.start()

    def process_pending_queue(self):
        for block_string, sender_socket in self.pending_queue:
            prev_hash, merkel_root, timestamp, _ = block_string.split(',')
            time_difference = abs(int(timestamp) - int(utctime()))/1000
            if prev_hash in self.blockchain.all_blocks_hash and time_difference < 60*60:
                if self.blockchain.insert(Block(prev_hash, merkel_root, timestamp)):
                    # only broadcast when insertion successful
                    self.broadcast_block_to_peers(block_string, sender_socket)

        self.pending_queue = []
        self.mining_thread = Thread(target=self.mining_function)
        self.mining_thread.start()

    def mining_function(self):
        # this will be killed while sleeping if new block cums
        # generate waiting time and wait
        waiting_time = random.exponential()/self.lamda
        print("Starting mining process with waiting_time=%s s" % waiting_time)
        sleep(waiting_time)
        # if stop flag is set then abort
        curr_thread_id = get_ident()
        if curr_thread_id in self.killed_threads:
            self.killed_threads.remove(curr_thread_id)
            return

        prev_hash = self.blockchain.get_last_block_hash()
        new_block = Block(prev_hash, "0000", str(int(utctime())), is_adversary=1)
        self.blockchain.insert(new_block)
        print("Generated block: %s" % (str(new_block)))
        self.blockchain.print_blockchain_tree()
        # broadcast it to peers
        self.broadcast_block_to_peers(str(new_block))
        # restart mining thread
        self.mining_function()

    def adversary_function(self):
        waiting_time = 1  # a non zero constant number to have something managable
        sleep(waiting_time)

        new_block = Block('0000', "0000", str(int(utctime())), is_adversary=1)
        # print("Generated block: %s" % (str(new_block)))
        # broadcast it to peers
        self.broadcast_block_to_peers(str(new_block))
        # restart mining thread
        self.adversary_function()

    def log(self, message):
        """
        log the message to the logfile and to screen
        """

        if isinstance(message, (str)):
            print(message)
            self.log_file.write((message + '\n').encode())
        elif isinstance(message, (bytes, bytearray)):
            print(message.decode())
            self.log_file.write(message + b'\n')

    def start_periodic_functions(self):
        liveness_thread = Thread(target=self.send_liveness_request)
        liveness_thread.start()

    def initialize_master_socket(self):
        """
        Initializes the socket and selector object
        """
        self.selector = DefaultSelector()
        self.master_socket = socket(AF_INET, SOCK_STREAM)
        self.master_socket.bind((self.ip, self.port))
        self.master_socket.listen()
        self.master_socket.setblocking(False)
        self.selector.register(self.master_socket, EVENT_READ, data="master")

    def get_and_parse_peer_list(self, s):
        """
        given a seed socket get the peer list and add to self.peers_list
        format of received seeds info is same as seeds_info.json
        recv exact length of peers_list otherwise blocking
        """
        peer_list_length = int(recv_all(s, 8).decode())
        peers_dict = loads(recv_all(s, peer_list_length).decode())
        seed_host, seed_port = s.getpeername()
        self.log("Peer list from seed {} {}".format(seed_host, seed_port))
        for peer in peers_dict:
            self.peers_list.add((peer['ip'], peer['port']))
            self.log("{}:{}".format(peer['ip'], peer['port']))
        self.log("")  # just an additional newline as a separator

    def register_with_seeds(self):
        """
        read seed info from file and register with n/2+1 seeds
        explicit register message required because incoming conn port is not same as conn port
        """
        seeds_info = []
        with open('config.txt', 'r') as info_fd:
            seeds_info = load(info_fd)

        seeds_to_register = seeds_info
        for seed in seeds_to_register:
            s = socket(AF_INET, SOCK_STREAM)
            s.connect((seed['ip'], seed['port']))
            register_message = ("Register:%s:%d" % (self.ip, self.port)).encode()
            s.sendall(send_format(register_message))
            self.get_and_parse_peer_list(s)
            seed['socket'] = s
        # print(self.peers_list)
        self.seeds_list = seeds_to_register

    def create_tree(self):
        # one time use after getting blocks from peers
        # now we have largest valid chain in pending queue
        # pending queue has blocks in order 0,1,....k
        for block_string in self.pending_queue:
            prev_hash, merkel_root, time_stamp, _ = block_string.split(',')
            self.blockchain.insert(Block(prev_hash, merkel_root, time_stamp))
        self.blockchain.print_blockchain_tree()
        self.pending_queue = []

    def recv_blockchain(self, peer_socket):
        """
        Assumption: peer accepting the connection will send blockchain automatically
        without any explicit request
        First 8 bytes are total size of blockchain in bytes in base 10
        Each consecutive 18 bytes are one block
        """
        block_chain_length = int(recv_all(peer_socket, 8).decode())
        block_chain_string = recv_all(peer_socket, block_chain_length).decode()
        print("Received block chain string: ", block_chain_string)
        # if this is chain is valid and larger than the current pending queue
        # then update the current pending queue
        chunk_size = 22
        num_blocks = len(block_chain_string)/chunk_size
        if num_blocks > len(self.pending_queue) and block_chain_string[0:4] == "9e1c":
            # no checking for last block thats why length-1-chunk_size
            for block_chain_index in range(0, block_chain_length-chunk_size-1, chunk_size):
                current_block_hash = sha3_256(block_chain_string[block_chain_index:block_chain_index+chunk_size].encode()).hexdigest()[-4:]
                prev_hash_from_next_block = block_chain_string[block_chain_index+chunk_size:block_chain_index+chunk_size+4]
                # hash of current block should be equal to prev_hash in next block
                if current_block_hash != prev_hash_from_next_block:
                    print("Invalid blockchain received")
                    return
            # chain is valid
            self.pending_queue = [block_chain_string[i:i+chunk_size] for i in range(0, block_chain_length, chunk_size)]

    def connect_to_peers(self):
        """
        connect to  peers (at max 4) after getting peer list from all seeds
        """
        total_connected_peers = 0
        for peer in self.peers_list:
            try:
                s = socket(AF_INET, SOCK_STREAM)
                s.connect((peer[0], int(peer[1])))
                # newly connected peer will need listening port of this peer;
                # (max port is 65535)
                s.sendall(str(self.port).encode().zfill(8))
                data = "peer"
                events = EVENT_READ | EVENT_WRITE
                self.selector.register(s, events, data=data)
                self.connected_peers_list.append([peer[0], peer[1], s, []])
                print("connected to peer with ip %s:%s" % (peer[0], peer[1]))
                total_connected_peers += 1
                try:
                    self.recv_blockchain(s)
                except:
                    print("peer %s:%s was unable to send the blockchain" % (peer[0], peer[1]))
            except:
                # unable to connect to current peer; do nothing
                print("Unable to connect to peer:", peer)
            finally:
                if total_connected_peers >= len(self.peers_list)*CONNECTED_PERCENT/100:
                    break

    def report_peer_death(self, dead_peer_ip, dead_peer_port, current_timestamp):
        """
        sends all seeds the message that peer is dead ):
        """
        dead_message = ("Dead Node:%s:%s:%s:%s" % (dead_peer_ip, dead_peer_port, current_timestamp, self.ip))
        dead_message += '_{}'.format(self.port)
        self.log("Reporting Dead node message " + dead_message)
        dead_message = dead_message.encode()
        for seed in self.seeds_list:
            seed['socket'].sendall(send_format(dead_message))
            # str(len(dead_message)).zfill(8).encode()+dead_message)

    def send_liveness_request(self):
        """
        this function will be executed periodically
        may have to move this function outside of the class
        TODO: try catch 'send' (what happen if connection close and send)
        when a message is liveness reply comes
        remove all timestamps which have lesser value then the received one
        """
        # print("sending liveness request")
        current_timestamp = time()
        request_message = ("Liveness Request:%s:%s" % (current_timestamp, self.ip)).encode()
        request_message += '_{}'.format(self.port).encode()
        for peer in self.connected_peers_list:
            # if there are already 3 outstanding messages in list then peer is
            # ded
            if len(peer[3]) >= 3:
                # print("report death of peer %s:%s" % (peer[0], peer[1]))
                self.report_peer_death(peer[0], peer[1], current_timestamp)
                peer[2].close()
                self.connected_peers_list.remove(peer)
            else:
                # if send fails then peer closed the connection in middle
                try:
                    peer[2].sendall(send_format(request_message))
                except:
                    pass
                peer[3].append(request_message)
        sleep(13)
        self.send_liveness_request()

    def broadcast_block_to_peers(self, block_string, sender_socket=None):
        for peer in self.connected_peers_list:
            try:
                if sender_socket is None or peer[2].getpeername() != sender_socket.getpeername():
                    peer[2].sendall(send_format(str(block_string)))
            except:
                pass

    def send_blockchain(self, peer_socket):
        """
        no need for try catch; function already called from inside try block
        """
        blockchain_string = ''.join(self.blockchain.get_blockchain())
        print("Sending blockchain string: ", blockchain_string)
        peer_socket.sendall(send_format(blockchain_string))

    def accept_wrapper(self, sock):
        """
        incoming connection from new node
        read block chain from disk and send
        """
        try:
            conn, addr = sock.accept()
            listening_port = int(recv_all(conn, 8).decode())
            print("Accepted connection from %s:%s" % (addr[0], addr[1]))
            self.peers_list.add(addr)
            self.connected_peers_list.append((addr[0], listening_port, conn, []))
            self.send_blockchain(conn)
            data = "peer"
            events = EVENT_READ | EVENT_WRITE
            self.selector.register(conn, events, data=data)
        except Exception as e:
            print(e)

    def service_connection(self, key, mask):
        """
        Service a connection request
        Three types of incoming messages and their action
        1. liveness request: send liveness reply
        2. liveness reply: modify outstanding message list of connected peer
        3. block from other
        """
        sock = key.fileobj
        if mask & EVENT_READ:
            message_len = recv_all(sock, 8)
            if message_len:
                message_len = int(message_len.decode())
                recv_data = recv_all(sock, message_len)
                if not recv_data:
                    return
                splitted_message = recv_data.decode().split(":")
                # print(recv_data)
                if b'Liveness Request' in recv_data:
                    if LOG_LIVENESS:
                        self.log(recv_data)
                    liveness_reply = ("Liveness Reply:%s:%s:%s" % (splitted_message[1], splitted_message[2], self.ip)).encode()
                    liveness_reply += '_{}'.format(self.port).encode()
                    try:
                        sock.sendall(send_format(liveness_reply))
                    except:
                        pass
                elif b'Liveness Reply' in recv_data:
                    if LOG_LIVENESS:
                        self.log(recv_data)
                    for peer in self.connected_peers_list:
                        if peer[2] == sock:
                            # keep only those outstanding messages which have
                            # timestamp greater than reply
                            for msg in peer[3]:
                                if msg.decode().split(':')[1] <= splitted_message[1]:
                                    peer[3].remove(msg)
                else:
                    # abort mining thread and put in pending queue
                    block_string = recv_data.decode()
                    print("Block received: %s" % (block_string))
                    # sock is needed so that the block is not send to the sender itself
                    self.pending_queue.append((block_string, sock))
                    self.killed_threads.add(self.mining_thread.ident)
                    # start a new mining thread only after processing the pending queue
                    # self.mining_thread = Thread(target=self.mining_function)
                    # self.mining_thread.start()

            else:
                # socket closed
                self.selector.unregister(sock)
                # close only after dead message report
                # sock.close()
        else:
            if len(self.pending_queue) > 0:
                print("Pending Queue processing start")
                self.process_pending_queue()

    def run(self):
        """
        Main Loop
        """
        try:
            while True:
                events = self.selector.select(timeout=None)
                # start processing the pending queue when no blocks outstanding in network
                for key, mask in events:
                    if key.data == "master":
                        # its from the listening socket, we need to accept
                        # the connection
                        self.accept_wrapper(key.fileobj)
                    elif key.data == "peer":
                        self.service_connection(key, mask)

        except KeyboardInterrupt:
            print('*'*50)
            # self.blockchain.print_blockchain_graph()
            print("Writing blockchain in the database")
            blocks_list = self.blockchain.get_blockchain()
            with open(BLOCK_FILE, 'a') as f:
                f.write("\nblockchain for experiment with interarrival_time=" + str(1/global_lambda))
                for block_string in blocks_list:
                    f.write(block_string+'\n')
            print("Blockchain stored in the database. Current blockchain tree=")
            self.blockchain.print_blockchain_tree()
            self.log_file.close()
            print("Mining Power utilization=", str(len(self.blockchain.get_blockchain())/(len(self.blockchain.all_blocks_hash)-1)))
            print("Exiting")
        finally:
            self.selector.close()


peer = PeerNode(args.ip, args.port)
peer.run()
