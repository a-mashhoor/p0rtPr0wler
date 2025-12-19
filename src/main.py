#!/usr/bin/python3

from utils import *
from utils.helpers import *
from utils.args import args_parser
from utils.scanner import *


def main() -> NoReturn:

    if not is_root():
        print("\nTool uses raw socket for analyzing scan results, make sure you are root!\n")
        os._exit(1)

    # read command line argument and parse them
    args, parser = args_parser(ascii_art)

    # if silent arg is on forwarding all of stdout output to null!
    if args.silent:
        f = open(os.devnull, 'w')
        sys.stdout = f

    # banner and ascii art
    if not args.no_banner:
        ascii_art()

    # checking the user internet connection
    if not internet_connection():
        print("No internet connection, Exiting the program")
        if 'f' in locals(): f.close()
        os._exit(1)

    ### Handling target input ###
    target_ip = ''
    if args.host:
        host = UrlCleaner(args.host[0]).valid_url()
        target_ip = FindTarget(host).find_target_ipv4()
        if not target_ip:
            print("FQDN or Ipv4 is not valid\nExiting the program")
            if 'f' in locals(): f.close()
            os._exit(1)


    print(f"\033[1;31m{'Starting the scan':-^100}\033[0m")
    print(f"specified target: {host}")
    print(f"Target IP address: {target_ip}")
    print(f"Scanning started at: {datetime.now().strftime('%d-%m-%y %H:%M:%S')}")
    print("-"  * 100, '\n')

    global ports
    inidcator = ''
    type_of_scan = ''
    ### Handling ports to scan ###
    if args.port:
        indicator = 'single'
        ports = args.port[0]
    elif args.ports_list:
        indicator = 'list'
        ports = args.ports_list
    elif args.port_range:
        indicator = 'range'
        ports = (args.port_range[0], args.port_range[1])
    elif args.all_ports:
        indicator = 'all'
        ports = True

    ### Handling type of scan ###
    if args.tcp_simple_scan:
        type_of_scan = 'Simple_TCP'
    elif args.udp_simple_scan:
        type_of_scan = 'Simple_UDP'
    elif args.udp_tcp_simple_scans:
        type_of_scan = 'Simple_UDP_TCP'
    elif args.tcp_advanced_scan:
        type_of_scan = 'Advanced_TCP'
    elif args.udp_advanced_scan:
        type_of_scan = 'Advanced_UDP'
    elif args.udp_tcp_advanced_scans:
        type_of_scan = 'Advanced_UDP_TCP'


    results = scanner_runner(target_ip, prv_ip(), ports,
                             indicator, args.source_port,
                             type_of_scan)
    if results:
        ### Handling side effects ###
        side_effect(results)

        ### Handling output ###
        if args.Output:
            raw_output(results, *args.Output)

        if args.json_output:
            json_output(results, *args.json_output)
    else:
        print("No results found on target")

    if 'f' in locals(): f.close()

if __name__ == "__main__":
    try:
        main()
        os._exit(os.EX_OK)
    except KeyboardInterrupt:
        sys.stdout.write("\x1b[4A") # cruser up 4 lines
        print("\r\033[1;31mClosing The tool based on Ctrl+C by user order\033[0m")
        os._exit(1)
