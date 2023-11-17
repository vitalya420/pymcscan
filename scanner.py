import asyncio
import select
import socket
import time
from multiprocessing import Process
from struct import pack

import utils


class Scanner(Process):
    def __init__(self, sock, chunk, port, src_ip, source_port):
        super().__init__()
        self.source_port = source_port
        self.sock = sock
        self.chunk = chunk
        self.src_ip = src_ip
        self.port = port

        self._loop = asyncio.new_event_loop()
        self._semaphore = asyncio.Semaphore(0xF)

    async def scan_rows(self):
        start = time.time()
        targets_scanned = 0
        print(f'start scanner. {len(self.chunk)=}. src: {self.src_ip} sport: {self.source_port}, dport: {self.port}')

        async def calculate_speed():
            while not scan_completed:
                if time.time() - start > 0:  # Avoid division by zero
                    speed = targets_scanned / (time.time() - start)
                    print(f"[{self.name}] Current speed: {speed:.2f} targets/second")
                await asyncio.sleep(1)  # Update speed every second

        scan_completed = False
        speed_task = asyncio.create_task(calculate_speed())

        tasks = []
        for row in self.chunk:
            starts, ends, _, _ = row
            for ip_dec in range(int(starts), int(ends)):
                targets_scanned += 1

                packed_ip = pack('!I', ip_dec)
                ipv4_address = socket.inet_ntoa(packed_ip)

                packet = utils.build_syn_packet(self.src_ip, ipv4_address, self.port, self.source_port)
                task = asyncio.create_task(self.asendto(packet, (ipv4_address, self.port)))
                tasks.append(task)

                if len(tasks) >= self._semaphore._value:
                    await asyncio.gather(*tasks)
                    tasks.clear()

        if tasks:
            await asyncio.gather(*tasks)

        scan_completed = True
        await speed_task

        end = time.time()
        print(f"[{self.name}] Scan completed in {end - start:.2f} seconds.")

    def run(self):
        return self._loop.run_until_complete(self.scan_rows())

    async def asendto(self, packet, addr):
        self._loop.run_in_executor(None, self._sendto, packet, addr)

    def _sendto(self, packet, addr):
        try:
            _, writable, e = select.select([], [self.sock], [])
            for sock in writable:
                sock.sendto(packet, addr)
        except (BlockingIOError, PermissionError):
            self._sendto(packet, addr)

    @staticmethod
    def _create_sock():
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setblocking(False)
        return sock
