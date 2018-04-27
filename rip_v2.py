import socket
from random import random
from time import *
from hashlib import md5
import select
import sys

# GLOBAL VARIABLES
INFINITY = 16
LOCALHOST = "localhost"
TIME_OUT = 30
PERIOD = TIME_OUT / 6
GARBAGE_COLLECTION_TIME = TIME_OUT / 3 * 2


class Entry(object):
    """entry class"""
    def __init__(self, dest_node, first_node, metric, ti=None, flag=True):
        self.dest_node = dest_node  # destination router id
        self.first_node = first_node  # the first router id to destination
        self.metric = metric  # metric of the route
        # time value when the entry is updated
        if not ti:
            self.ti = time()
        else:
            self.ti = ti
        self.garbage_collection_time = None
        self.flag = flag

    def alive_time(self):
        """return time after last updated"""
        return time() - self.ti

    def reset_time(self):
        """reset time"""
        self.ti = time()

    def __repr__(self):
        """change object to string"""
        return "destination: " + str(self.dest_node) + ", " + "first: " + str(self.first_node) + ", " + "metric: " + \
               str(self.metric) + ", " + "time: " + str(self.alive_time())


class EntryTable(object):
    """entry table"""
    def __init__(self):
        self.entries = {}

    def __repr__(self):
        result = ''
        for entry in self.entries.values():
            result += entry.__repr__() + "\n"
        return result

    def get_entry(self, dest_node):
        """return a entry by destination node"""
        return self.entries.get(dest_node)

    def update_entry(self, new_entry):
        """compare received entry with current entry, then decide to update or not, return new entry or None"""
        current_entry = self.get_entry(new_entry.dest_node)
        if not current_entry:  # if entry not existed, add it to entry table
            if new_entry.metric < INFINITY:
                self.entries.update({new_entry.dest_node: new_entry})
        elif current_entry.first_node == new_entry.first_node:  # if current first node == new first node, then update
            if new_entry.metric >= INFINITY:  # for garbage collection
                new_entry.flag = current_entry.flag
                new_entry.garbage_collection_time = current_entry.garbage_collection_time
            self.entries.update(({new_entry.dest_node: new_entry}))
        elif current_entry.metric > new_entry.metric:  # if new metric < current metric, then update
            self.entries.update({new_entry.dest_node: new_entry})

    def remove_entry(self, dest_node):
        """remove entry from entry table"""
        if self.get_entry(dest_node):
            self.entries.pop(dest_node)


class Router(object):
    """router class"""
    def __init__(self, id, inputs, outputs):
        self.id = id
        self.inputs = inputs
        self.outputs = outputs
        self.entry_table = EntryTable()
        self.garbage_collection_time = 0
        self.input_sockets = []
        self.output_socket = None

    @staticmethod
    def create_checksum(payload):
        """create checksum by md5"""
        return md5(bytes(payload, "utf-8")).hexdigest()[:10]

    def verify_checksum(self, income):
        """verify check sum return true if correctness otherwise false"""
        return income[:10] == self.create_checksum(income[10:])

    @staticmethod
    def create_socket(port_no):
        """create socket"""
        my_socket = None
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return my_socket
        except socket.error as e:
            print(e.strerror)
            print("Port " + str(port_no) + " cannot be created")
            if my_socket:
                try:
                    my_socket.close()
                except socket.error:
                    print("Socket with " + str(port_no) + " cannot be closed")

    def create_sockets(self):
        """create input sockets & out socket"""
        for port_no in self.inputs:
            my_socket = self.create_socket(port_no)
            self.input_sockets.append(my_socket)
        if len(self.input_sockets) != 0:
            for i in range(len(self.input_sockets)):
                self.input_sockets[i].bind((LOCALHOST, self.inputs[i]))
            self.output_socket = self.input_sockets[0]

    def create_update_packet(self, output):
        """create an update packet
            HEADER: command(1) version(1) send to router id(2)
            ENTRY: source router id(2) route tag all zeros(2)
                   destination router id(4)
                   Subnet mask all zeros(4)
                   next hop(4)
                   metric(4)
        """
        payload = ""
        header = dec_to_bin(2, 8) + dec_to_bin(2, 8) + dec_to_bin(output.dest_node, 16) + "\n"
        payload += header
        for key, entry in self.entry_table.entries.items():
            entry_header = dec_to_bin(self.id, 16) + dec_to_bin(0, 16) + "\n"
            dest_node, metric, first_node = (entry.dest_node, entry.metric, entry.first_node)
            # Split Horizon with Poisoned Reverse
            if first_node == output.dest_node:  # if the first node == dest node, then metric = INFINITY
                metric = INFINITY
            entry_body = dec_to_bin(dest_node, 32) + "\n" + dec_to_bin(0, 32) + "\n" + dec_to_bin(first_node, 32)\
                + "\n" + dec_to_bin(metric, 32) + "\n"
            payload += entry_header + entry_body
        checksum = self.create_checksum(payload)
        return checksum + payload

    def send_packet(self, output):
        """send update packet to output"""
        packet = self.create_update_packet(output)
        self.output_socket.sendto(bytes(packet, 'utf-8'), (LOCALHOST, output.port_no))

    def process(self, income):
        """deal with update message
           check if successfully processing return true, else drop and return false
        """
        if not self.verify_checksum(income):
            print("Cannot pass checksum")
            return False
        lines = income.split("\n")
        if len(lines) != 0:
            header = lines[0]
            body = lines[1:]
        else:
            print("no payload")
            return False
        if len(body) == 0:
            print("no entry")
            return False
        command = bin_to_dec(header[10:18])
        version = bin_to_dec(header[18:26])
        output_router_id = bin_to_dec(header[26:])
        if output_router_id != self.id:
            print("packet is not for this router")
            return False
        if command != 2:
            print("incorrect command")
            return False
        if version != 2:
            print("incorrect version")
            return False
        entry_number = len(body) // 5
        for i in range(entry_number):
            source_node = bin_to_dec(body[i * 5][:16])
            output = self.outputs.get(source_node)
            dest_node = bin_to_dec(body[i * 5 + 1])
            metric = bin_to_dec(body[i * 5 + 4])
            if dest_node != self.id:
                new_metric = metric + output.metric
                if new_metric > INFINITY:
                    new_metric = INFINITY
                new_entry = Entry(dest_node, source_node, new_metric)
                self.entry_table.update_entry(new_entry)
            else:
                if self.entry_table.get_entry(source_node):
                    self.entry_table.get_entry(source_node).reset_time()  # reset time if neighbour router
                else:
                    new_entry = Entry(source_node, self.id, metric)
                    self.entry_table.update_entry(new_entry)  # create entry if not existed
        print(self.entry_table)
        return True

    @staticmethod
    def receive_packet(my_socket):
        """receive packet and read"""
        packet = my_socket.recvfrom(1024 * 4)
        return packet[0].decode(encoding='utf-8')  # convent md5 to string

    def send_packets_by_outputs(self):
        """Send an update to all routers in outputs"""
        print("send packets to all outputs")
        for key in self.outputs.keys():
            self.send_packet(self.outputs.get(key))

    def timeout(self):
        """set time out entry metric to infinity"""
        for entry in self.entry_table.entries.values():
            if entry.alive_time() > TIME_OUT:
                entry.metric = INFINITY
                print("dest {} metric has become infinity".format(entry.dest_node))
                self.send_packets_by_outputs()

    def garbage_collection(self):
        """remove expired entry from table"""
        keys = []
        for key, entry in self.entry_table.entries.items():
            if entry.flag:
                if entry.metric >= INFINITY:
                    print("GC start")
                    entry.garbage_collection_time = time()
                    entry.flag = False
            elif entry.garbage_collection_time and time() - entry.garbage_collection_time > GARBAGE_COLLECTION_TIME and\
                    not entry.flag:
                print(entry)
                print(entry.garbage_collection_time - time())
                keys.append(key)
        for k in keys:
            self.entry_table.remove_entry(k)
            print("dest {} has been removed".format(k))


class Output(object):
    """output object"""
    def __init__(self, port_no, metric, dest_node):
        self.port_no = int(port_no)
        self.metric = int(metric)
        self.dest_node = int(dest_node)


def dec_to_bin(dec_num, number):
    """convert decimal to binary"""
    bin_num = bin(int(dec_num))
    return "0" * (number - len(bin_num) + 2) + bin_num[2:]


def bin_to_dec(bin_num):
    """convert binary to decimal"""
    return int(bin_num, 2)


def create_router(config_file):
    """create router by config file"""
    lines = config_file.readlines()
    router_id = int(lines[0].replace("router-id ", "").strip('\n'))
    input_ports = []
    inputs_str = lines[1].replace("input-ports ", "").strip('\n')
    inputs = inputs_str.split(", ")
    for ip in inputs:
        input_ports.append(int(ip))
    outputs = {}
    outputs_str = lines[2].replace("outputs ", "").strip('\n')
    output_list = outputs_str.split(", ")
    entries = {}
    for op in output_list:
        elements = op.split("-")
        port_no = int(elements[0])
        metric = int(elements[1])
        dest_node = int(elements[2])
        output = Output(port_no, metric, dest_node)
        outputs.update({dest_node: output})
        entry = Entry(dest_node, router_id, metric)
        entries.update({dest_node: entry})
    new_router = Router(router_id, input_ports, outputs)
    new_router.entry_table.entries = entries
    return new_router


def main():
    config_name = sys.argv[1]
    # config_name = "router1.txt"
    with open(config_name, 'r') as config_file:
        router = create_router(config_file)
    router.create_sockets()
    router.send_packets_by_outputs()
    t = time()
    random_period = (random() * 0.4 + 0.8) * PERIOD
    while True:
        if time() - t >= random_period:  # periodically send updates to output
            router.send_packets_by_outputs()
            t += random_period
            # print(random_period)
            random_period = (random() * 0.4 + 0.8) * PERIOD  # change random period when send updates
            router.timeout()
            router.garbage_collection()
        try:
            r_list, w_list, e_list = select.select(router.input_sockets, [], [], 1)
            if r_list:
                for read in r_list:
                    print(read)
                    packet = router.receive_packet(read)
                    router.process(packet)
        except KeyboardInterrupt:
            print("program has been stopped by Ctrl+C")
            sys.exit()
        except:
            print("Unexpected error: " + sys.exc_info()[0])
            raise


if __name__ == "__main__":
    main()








