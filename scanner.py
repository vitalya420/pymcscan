import ctypes
import time
from multiprocessing import Process
from threading import Thread
from struct import pack
import socket

import utils

scannerlib = ctypes.CDLL('./libscanner.so')



class Scanner(Process):
    def __init__(self, chunk, port, src_ip, source_port):
        super().__init__()
        self.source_port = source_port
        self.chunk = chunk
        self.src_ip = src_ip
        self.src_ip_dec = utils.ip_to_decimal(self.src_ip)
        self.port = port
        self.sockfd = scannerlib.create_raw_socket()
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
        return scannerlib.send_syn_dec(self.sockfd, 
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
