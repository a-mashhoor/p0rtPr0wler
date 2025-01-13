from . import *

Usage="Basic usage: p0rtPr0wler -H IP/FQDN -port/ports -type_of_scan -output/json_output\n"

#creatin custom argpatser class
class MyParser(argparse.ArgumentParser):
    def error(self, message):
        print(Usage)
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        os._exit(2)

# argument parse function
def args_parser(ascii_art) -> 'arguments list and parser itslef':

    msg=f"""\033[1;31mThis tool is developed by Arshia Mashhoor
    \runder MIT Open source LICENCE for educational usgae only.
    \rAuthor is not responsible for any abuse!\033[0m\n{'Help':*^100}"""

    parser = MyParser(formatter_class=argparse.RawTextHelpFormatter,
                      prog="P0rtPr0wler",
                      description=msg,
                      epilog=textwrap.dedent(f'''\
                                             \r{'About':-^100}
                                             \nAuthor: Arshia Mashhoor
                                             \nGithub: https://github.com/a-mashhoor/p0rtPr0wler
                                             '''),
                      add_help=True,
                     )

    # if no arguments specified by the user showing the help and exiting the tool
    if len(sys.argv)==1:
        ascii_art()
        print(Usage)
        parser.print_help(sys.stderr)
        os._exit(1)

    ### Adding Command Line Arguments ###

    # input command line argumnet for host/IP
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-H", "--host",
                             nargs=1,
                             action='store',
                             help="Specifiy target domain name or Ip address")


    # input command line argumnets for port/ports
    port_group = parser.add_mutually_exclusive_group(required=True)
    port_group.add_argument("-p", "--port",
                            type=int,
                            nargs=1,
                            action='store',
                            help='specifiy single port to scan')

    port_group.add_argument("-pl", "--ports_list",
                            type=int,
                            nargs='+',
                            action='store',
                            help='specifiy multiple ports to scan')

    port_group.add_argument("-pr", "--port-range",
                            type=int,
                            nargs=2,
                            action='store',
                            help="specifiy a range of ports to scan 1 65535")

    port_group.add_argument("-ap", "--all-ports",
                            action=argparse.BooleanOptionalAction,
                            help="scan all ports")


    # scan type command line arguments
    type_group = parser.add_mutually_exclusive_group(required=True)
    type_group.add_argument("-tSS", "--tcp-simple-scan",
                            action=argparse.BooleanOptionalAction,
                            help="Perform only simple TCP scan")

    type_group.add_argument("-uSS", "--udp-simple-scan",
                            action=argparse.BooleanOptionalAction,
                            help="Perform only simple UDP scan")

    type_group.add_argument("-utSS", "--udp-tcp-simple-scans",
                            action=argparse.BooleanOptionalAction,
                            help="Perform both UDP and TCP simple scans")

    type_group.add_argument("-tSA", "--tcp-advanced-scan",
                            action=argparse.BooleanOptionalAction,
                            help="Advanced TCP scan requires ROOT access")

    type_group.add_argument("-uSA", "--udp-advanced-scan",
                            action=argparse.BooleanOptionalAction,
                            help="Advanced UDP scan requires ROOT access")

    type_group.add_argument("-utSA", "--udp-tcp-advanced-scans",
                            action=argparse.BooleanOptionalAction,
                            help="Advanced UDP and TCP scans requires ROOT access")

    # simple config command line arguments
    parser.add_argument("-sP", "--source-port",
                        nargs=1,
                        type=int,
                        default=12345,
                        help="custom source port to send packets from"
                       )

    parser.add_argument("-nb", "--no-banner",
                        action=argparse.BooleanOptionalAction,
                        help="no banner on stdout")

    parser.add_argument("-s", "--silent",
                        action=argparse.BooleanOptionalAction,
                        help="prints nothing on stdout")


    # output arguments
    output_group = parser.add_mutually_exclusive_group(required=False)
    output_group.add_argument("-o", "--Output",
                              nargs=1,
                              type=argparse.FileType('w', encoding='UTF-8'),
                              help="save output in text (ascii based) file")

    output_group.add_argument("-oj", "--json-output",
                              nargs=1,
                              type=argparse.FileType('w', encoding='UTF-8'),
                              help="Save output in json format")

    # version command line argument
    parser.add_argument("-v", "--version", action='version', version='%(prog)s 1.0.0')

    args = parser.parse_args()

    return args, parser
