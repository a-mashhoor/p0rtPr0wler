from . import *
import subprocess
import os, pwd, grp
from classes.customExceptionsClass import PrvIpFindError, GatewayFindError



""" General Functions """

# some ascii art !
def ascii_art() -> NoReturn:
    banner_1 = pyfiglet.figlet_format("P0rtPr0wler", width=100, justify="center")
    banner_2 = pyfiglet.figlet_format("Concurrent Port Scanner", width=100, justify="center")
    print(f'\033[1;36m{banner_1} \n \033[1;31m{banner_2}\033[0m')
    print("Author: Arshia Mashhoor\ngithub: https://github.com/a-mashhoor/p0rtPr0wler\n")


def is_root() -> bool:
    """
    Cheking user sudo/admin privilages for performing udp test althogh the tool for now only supports
    Unix based/like OS linux/mac/BSD...

    This is script is ment to run on linux , its only tested on linux thus we
    only test for linux :)

    Detect if the script is running with root privileges using multiple checks.
    Logs detailed information about the user, group membership, and execution method.

    Returns:
        bool: True if the script is running as root, False otherwise.
    """
    try:
        effective_uid = os.geteuid()
        if effective_uid != 0:
            print(f"Not running as root: Effective UID is {effective_uid}.")
            return False

        real_user_id = os.getuid()
        real_user_name = pwd.getpwuid(real_user_id).pw_name
        real_groups = [grp.getgrgid(gid).gr_name for gid in os.getgroups()]

        is_sudo = 'SUDO_USER' in os.environ
        if is_sudo:
            sudo_user = os.environ.get('SUDO_USER', 'unknown')
            #print(f"Script is running via sudo. Sudo user: {sudo_user}, Real user: {real_user_name}, Groups: {real_groups}")
        else:
            pass
            #print(f"Script is running as root directly. User: {real_user_name}, Groups: {real_groups}")

        if real_user_name != "root":
            print(f"Real user is not root: User is {real_user_name}.")
            if not is_sudo:
                print("Not running as root and not via sudo.")
                return False

        try:
            root_group = grp.getgrnam('root').gr_gid
            if root_group not in os.getgroups():
                print(f"Not a member of the root group: Groups are {real_groups}.")
                return False
        except KeyError:
            print("Root group not found on this system.")
            return False
        except Exception as e:
            print(f"Error checking group membership: {e}")
            return False

        try:
            # Test if `sudo` is available and functional (if not running as direct root)
            if not is_sudo:
                result = subprocess.run(
                    ["sudo", "-n", "true"],  # Non-interactive test
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )
                if result.returncode == 0:
                    print("Sudo privileges confirmed.")
                else:
                    print("Sudo privileges not available.")
                    return False
        except subprocess.CalledProcessError:
            print("Sudo privileges not available.")
            return False
        except Exception as e:
            print(f"Error testing sudo privileges: {e}")
            return False

        #print("Root privileges confirmed.")
        return True

    except Exception as e:
        print(f"Error during root detection: {e}")
        return False



#internet connection test what way is better to check google!
def internet_connection() -> bool:
    try:
        con = http.client.HTTPConnection("google.com",timeout=3)
        con.request("HEAD", "/")
        con.close()
        return True
    except Exception:
        return False

""" I/O functions """

def names_in_namespace(obj, namespace) -> list[str]:
    return [name for name in namespace if namespace[name] is obj]

def names_in_caller(obj, depth=2) -> list[str]:
    f = inspect.currentframe()
    for _ in range(depth):
        f = f.f_back
    return names_in_namespace(obj, f.f_locals)

def results_iterator(results_dict
                     ) -> Sequence[list[dict]]:
    UDP, TCP, ICMP = [], [], []
    for item in results_dict:
        if item['protocol'] == 'ICMP':
            ICMP.append(item)
        elif item['protocol'] == 'UDP':
            UDP.append(item)
        else:
            TCP.append(item)
    return UDP, TCP, ICMP

def side_effect(results_dict: Sequence[list[dict]]) -> NoReturn:
    UDP, TCP, ICMP = results_iterator(results_dict)

    if ICMP:
        print("ICMP Echo detected on target")

    def print_side_effect (list_):
        name = names_in_caller(list_)
        print(f'''\033[1;31m{f'{name[0]} PROTOCOL OPEN PORTS:':-^100}\033[0m''')
        for item in list_:
            print(f"The Port number: {item['port']} is {item['state']}")

    if not UDP and not TCP:
        print("No open port detected on specified taregt")
    elif TCP and not UDP:
        print_side_effect(TCP)
    elif UDP and not TCP:
        print_side_effect(UDP)
    else:
        print_side_effect(TCP)
        print_side_effect(UDP)


def json_output(results_dict: Sequence[list[dict]],
                file_name: TextIO
                ) -> NoReturn:

    UDP, TCP, ICMP = results_iterator(results_dict)

    if not UDP and not TCP:
        dict_ = None
    else:
        dict_ = [{'UDP Ports': UDP, 'TCP Ports':TCP}]

    dump(dict_, file_name, indent=4, sort_keys=True, allow_nan=True)
    file_name.close()

def raw_output(results_dict: Sequence[list[dict]],
               file_name: TextIO
               ) -> NoReturn:

    UDP, TCP, ICMP = results_iterator(results_dict)

    for _ in TCP:
        file_name.write(f"Prototcol: {_['protocol']}, Port number: {_['port']}, State: {_['state']}")

    for _ in UDP:
        file_name.write(f"Prototcol: {_['protocol']}, Port number: {_['port']}, State: {_['state']}")

    file_name.close()


# validation of input url or list of urls, ip or list of ips
class UrlCleaner(object):
    '''
    URL cleaner class checks for scheme in the url and any directory after
    fqdn (fully quilifed domain name)
    if any exists it will clean the url and return the fqdn
    if not returns input
    '''

    def __init__(self, url: str) -> NoReturn:
        if isinstance(url, str):
            self.url = url

    def valid_url(self) -> str:
        if self.url.startswith(("https://","https","http://","http"))  or "/" in self.url:
            print(f"host: {self.url} starts with scheme or hase directory in it \nCleaning it!\n")
            host = re.split(r":(?<=:)\d+",(re.split("/", self.url.strip("htps:/"))[0]))[0]
        else:
            host = self.url
        return host


""" IP related function """

# findig ip address for target
class FindTarget(object):
    '''
        FindTarget class will is doing 2 things for us
        it will return IPv4 or IPv6 only if the target
        is up
    '''
    def __init__ (self, host: str) -> NoReturn:
        self.host = host

    def find_target_ipv4(self) -> 'IPv4':
        try:
            target = socket.gethostbyname(self.host)
            return target
        except socket.gaierror:
            return None

    def find_target_ipv6(self) -> 'IPv6':
        port = 80
        try:
            res = socket.getaddrinfo(self.host, port, socket.AF_INET6)
            target = res[0][4][0]
            return target
        except socket.gaierror:
            return None



# Getting system private ip addr
def get_default_gateway_linux() -> str:
    with open("/proc/net/route" ,'r') as fh:
        for line in fh:
            fields = line.strip().split()
            if fields:
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                # If not default route or not RTF_GATEWAY, skip it
                    continue
                elif fields[0]:
                    return fields[0]
        else:
            raise GatewayFindError(
                {msg:='Due to NoneType error finding gateaway can not find prv ip address'
                 , errC:=71}
                )


def linux_prv_ip_addr() -> 'private IPv4':
    # geting the default interface gateaway name
    try:
        ifname = get_default_gateway_linux()
    except GatewayFindError as err:
        raise Exception(err)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # return pv ip address
    try:
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915,
                                            pack('256s', ifname[:15].encode()) )[20:24])
    except OSError as err:
        raise PrvIpFindError({msg:='Due to OSError can not find prv ip address' , errC:=72})



# Finding the source ip addr
def prv_ip():
    try:
        return linux_prv_ip_addr()
    except Exception as err:
        l = [ i for i in err.args[0].args[0]]
        print(l[0])
        os._exit(l[1])

