import socket
import ctypes
from struct import unpack
import binascii
from multiprocessing import Process
import time

scannerlib = ctypes.CDLL('./libscanner.so')


src_ip = socket.gethostbyname(socket.gethostname())
print(src_ip)


def syn_ack_handler():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while True:
        data = sock.recv(0xFFFF)
        header_len = (data[0] & 0x0F) * 4
        tcp_header_start = header_len

        dest_port_bytes = data[tcp_header_start + 2:tcp_header_start + 4]
        dest_port = unpack('!H', dest_port_bytes)[0]

        src_port_bytes = data[tcp_header_start:tcp_header_start + 2]
        src_port = unpack('!H', src_port_bytes)[0]

        src_ip_bytes = data[12:16]
        src_ip = socket.inet_ntoa(src_ip_bytes)

        if dest_port == 60606:
            cont = binascii.hexlify(data)
            if cont[65:68] == b'012':
                with open('rdps.txt', 'a') as file:
                    file.write(f'{src_ip}:{src_port}\n')


def read_file(filename):
    with open(filename, "r") as file:
        addrs = file.read().split("\n")
        return addrs[:-1]

def ip_to_dec(ip_address):
    parts = ip_address.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def main():
    addrs = read_file('ips2.txt')
    
    ips = []
    for addr in addrs:
        ip, _ = addr.split(":")
        ips.append(ip_to_dec(ip))

    sockfd = scannerlib.create_raw_socket()
    if (sockfd < 0):
        raise OSError("Run me as root")

    handler_p = Process(target=syn_ack_handler)
    handler_p.daemon = True
    handler_p.start()

    src_ip_dec = ip_to_dec(src_ip)
    for ip in ips:
        scannerlib.send_syn_dec(sockfd, src_ip_dec, 60606, ip, 3389)
       

    time.sleep(10)

    scannerlib.close_socket(sockfd)
    


if __name__ == "__main__":
    main()