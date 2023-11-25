import time
from ipaddress import ip_network, ip_address

from packet import Packet


def ip_to_decimal(ip):
    return int(ip_address(ip))

def ip_generator(subnet):
    network = ip_network(subnet)
    for ip in network.hosts():
        yield str(ip)


def build_syn_packet(src, dst, dport, sport=60606):
    p = Packet(src, dst, sport, dport)
    return p.generate_packet()


def chunkify(lst, chunks):
    """Yield successive n-sized chunks from lst, including any leftovers in the final chunk."""
    chunk_size = len(lst) // chunks
    for i in range(chunks - 1):
        yield lst[i * chunk_size:(i + 1) * chunk_size]
    # Handle the last chunk separately to include any leftovers
    yield lst[(chunks - 1) * chunk_size:]


def performance_test():
    start = time.time()
    for i in range(1_000_000):
        packet = build_syn_packet('192.168.0.1', '192.168.0.2', 12345)
    end = time.time()

    print(end-start)

if __name__ == '__main__':
    performance_test()