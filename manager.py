import asyncio
import binascii
import socket
from struct import unpack

from scanner import Scanner


class ScanManager:
    def __init__(self, source_port: int = 60606, timeout: float = 10, filename: str = 'result.txt',
                 print_opened: bool = False):
        self.print_opened = print_opened
        self.filename = filename
        self.proc = list()
        self.sock = self._create_sock()
        self.source_port = source_port
        self.timeout = timeout

        self._loop: asyncio.AbstractEventLoop
        self._handler_task: asyncio.Task



    def scan_row_chunks(self, chunks: list[list], src_ip, port):
        for chunk in chunks:
            worker = Scanner(chunk, port, src_ip, self.source_port)
            worker.daemon = True
            self.proc.append(worker)

        for p in self.proc:
            p.start()

    async def syn_ack_handler(self):
        while True:
            data = await self._loop.sock_recv(self.sock, 0xFFFF)
            header_len = (data[0] & 0x0F) * 4
            tcp_header_start = header_len

            dest_port_bytes = data[tcp_header_start + 2:tcp_header_start + 4]
            dest_port = unpack('!H', dest_port_bytes)[0]

            src_port_bytes = data[tcp_header_start:tcp_header_start + 2]
            src_port = unpack('!H', src_port_bytes)[0]

            src_ip_bytes = data[12:16]
            src_ip = socket.inet_ntoa(src_ip_bytes)

            if dest_port == self.source_port:
                cont = binascii.hexlify(data)
                if cont[65:68] == b'012':
                    with open(self.filename, 'a') as file:
                        file.write(f'{src_ip}:{src_port}\n')
                    if self.print_opened:
                        print(src_ip, src_port, sep=':')

    async def __aenter__(self):
        self._loop = asyncio.get_event_loop()
        self._handler_task = self._loop.create_task(self.syn_ack_handler())
        await asyncio.sleep(1)  # Give a second to start a task
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        print('waiting')
        for p in self.proc or []:
            await self._loop.run_in_executor(None, p.join)
        print('waiting timeout until handler will killed')
        await asyncio.sleep(self.timeout)
        self._handler_task.cancel()

    @staticmethod
    def _create_sock():
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setblocking(False)
        return sock
