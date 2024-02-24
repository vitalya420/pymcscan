import argparse
import asyncio
import os

import geo
import utils
from manager import ScanManager


def parse_arguments():
    parser = argparse.ArgumentParser(description='Process some parameters.')

    # Define the arguments
    parser.add_argument('--src-ip', type=str, required=True,
                        help='Source IP address')
    parser.add_argument('--src-port', type=int, required=False,
                        help='Source port number', default=60606)
    parser.add_argument('--dst-port', type=int, required=True,
                        help='Target port')
    parser.add_argument('--timeout', type=int, required=False,
                        help='Timeout in seconds', default=10)
    parser.add_argument('--processes', type=int, required=False,
                        help='Number of processes', default=os.cpu_count())
    parser.add_argument('--country', type=str, required=True,
                        help='Country code')
    parser.add_argument('--file', type=str, required=False,
                        help='Result file name')
    parser.add_argument('--print-opened', type=bool, required=False,
                        help='Print opened ports')
    parser.add_argument('--iface', type=str, required=True, help='Network interface name')
    parser.add_argument('--src-mac', type=str, required=True, help='Source MAC address')
    parser.add_argument('--dst-mac', type=str, required=True, help='Destination MAC address')

    args = parser.parse_args()
    return args


async def main(args):
    ips = geo.filter_csv_by_country(args.country)
    chunks = list(utils.chunkify(ips, args.processes))

    async with ScanManager(source_port=args.src_port,
                           timeout=args.timeout,
                           filename=args.file,
                           print_opened=args.print_opened) as scan_manager:
        scan_manager.scan_row_chunks(chunks, args.src_ip, args.dst_port,
                                     args.iface, args.src_mac, args.dst_mac)
    #     # scan_manager.start_processes([
    #     #     '46.0.0.0/8',
    #     # ], 80)
    #     print(scan_manager)


if __name__ == '__main__':
    if os.geteuid() == 0:
        args = parse_arguments()
        asyncio.run(main(args))
    else:
        print('Root access required')
