from utils import *
from utils.helpers import linux_prv_ip_addr
from utils.udp_payloads import payload_list
from classes.ScannerClass import Scanner
from classes.customExceptionsClass import *

# no traceback
sys.tracebacklimit = 0

### running the scanner class ###
def scanner_runner(target_ip: str,
                   source_ip: str,
                   ports: Union[int, tuple, list, bool],
                   indicator: str,
                   source_port: int,
                   type_of_scan: str
                   ) -> Sequence[list[dict]] :

    s = Scanner(source_ip = source_ip,
                target_ip = target_ip,
                source_port = source_port,
                ports = ports,
                payload_list = payload_list,
                indicator = indicator,
                type_of_scan = type_of_scan)

    raw_results = s.scanner()
    return raw_results
