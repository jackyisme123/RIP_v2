import socket

import select

my_socket1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
my_socket1.bind(("localhost", 1027))
my_socket2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
my_socket2.bind(("localhost", 1028))
my_socket3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
my_socket3.bind(("localhost", 1029))
while True:
    r_list, w_list, e_list = select.select([my_socket1, my_socket2, my_socket3], [], [], 1)
    if r_list:
        for read in r_list:
            print(read)
            packet = read.recvfrom(1024)
            print(packet[0])

