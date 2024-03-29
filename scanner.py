from ctypes import *
import time
from multiprocessing import Process
from threading import Thread
from struct import pack
import socket

import utils

# scannerlib = CDLL('./libscanner.so')
scannerlib2 = CDLL('./libscanner2.so')

class sockaddr_ll(Structure):
    _fields_ = [
        ('sll_family', c_ushort),
        ('sll_protocol', c_ushort),
        ('sll_ifindex', c_int),
        ('sll_hatype', c_ushort),
        ('sll_pkttype', c_ubyte),
        ('sll_halen', c_ubyte),
        ('sll_addr', c_ubyte * 8)
    ]


scannerlib2.buildEtherPacket.restype = POINTER(c_ubyte)
scannerlib2.create_sock.argtypes = [c_char_p, POINTER(sockaddr_ll)]
scannerlib2.create_sock.restype = c_int



class Scanner(Process):
    def __init__(self, chunk, port, src_ip, source_port, iface, src_mac, dst_mac):
        super().__init__()
        self.source_port = source_port
        self.chunk = chunk
        self.src_ip = src_ip
        self.src_ip_dec = utils.ip_to_decimal(self.src_ip)
        self.port = port
        self.iface = create_string_buffer(iface.encode())
        self.src_mac = create_string_buffer(src_mac.encode())
        self.dst_mac = create_string_buffer(dst_mac.encode())
        self.ether_packet = scannerlib2.buildEtherPacket(self.src_mac, self.dst_mac)
        self.socket_address = sockaddr_ll()
        self.sockfd = scannerlib2.create_sock(self.iface, byref(self.socket_address))
        if self.sockfd < 0:
            raise OSError('Run me as root')

    def close(self):
        scannerlib.close_socket(self.sockfd)


    def send_syn(self, src_ip, src_port, dst_ip, dst_port):
        return scannerlib.send_syn(self.sockfd, 
            ctypes.create_string_buffer(src_ip.encode()), 
            src_port, 
            ctypes.create_string_buffer(dst_ip.encode()), 
            dst_port
            )

    def send_syn_dec(self, src_ip, src_port, dst_ip, dst_port):
        return scannerlib2.send_syn(
            self.sockfd,
            self.socket_address,
            self.ether_packet,
            src_ip,
            src_port,
            dst_ip,
            dst_port
        )

    def run(self):
        start = time.time()
        targets_scanned = 0
        print(f'start scanner. {len(self.chunk)=}. src: {self.src_ip} sport: {self.source_port}, dport: {self.port}')

        def calculate_speed():
            while not scan_completed:
                if time.time() - start > 0:  # Avoid division by zero
                    speed = targets_scanned / (time.time() - start)
                    print(f"[{self.name}] Current speed: {speed:.2f} targets/second")
                time.sleep(1)  # Update speed every second

        scan_completed = False
        speed_task = Thread(target=calculate_speed)
        speed_task.start()

        for row in self.chunk:
            starts, ends, _, _ = row
            for ip_dec in range(int(starts), int(ends)):
                targets_scanned += 1

                self.send_syn_dec(self.src_ip_dec, self.source_port, ip_dec, self.port)

        scan_completed = True
        speed_task.join()
        end = time.time()
        print(f"[{self.name}] Scan completed in {end - start:.2f} seconds.")
