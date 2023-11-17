from ipaddress import ip_network

from packet import Packet


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
