from utils import *
from classes.customExceptionsClass import *
from classes.CreatePacketClass import CreatePacket
from classes.SnifferClass import Sniffer
from classes.CreatePortsMatrixClass import CreatePortsMatrix

class Scanner(object):
    '''
        ScannerClass:
    '''
    def __init__(self,
                 source_ip:str,
                 target_ip:str,
                 ports:Union[int, tuple, list, bool],
                 source_port:int,
                 payload_list:Sequence[list[dict]],
                 indicator:str,
                 type_of_scan:str,
                 ) -> NoReturn:

        if type_of_scan not in ['Advanced_UDP_TCP', 'Advanced_UDP',
                                'Advanced_TCP','Simple_UDP_TCP',
                                'Simple_TCP','Simple_UDP'
                                ]:
            raise AssertionError

        if type_of_scan in ['Advanced_UDP_TCP', 'Simple_UDP_TCP']:
            self.concurrent_scan_count = 2
        else:
            self.concurrent_scan_count = 1

        self.target_ip = target_ip
        self.source_ip = source_ip
        self.ports = ports
        self.source_port = source_port
        self.payload_list = payload_list
        self.indicator = indicator
        self.type_of_scan = type_of_scan

        self.time_out = 6
        self.max_packet_size = 65535

        self.lock = threading.Lock()

        self.ports_matrix = []
        self.fnial_result = []
        self.data_list = []

    # create a matrix of ports or pass a list of ports or single port
    # based on the scan type
    def _input_handler(self) -> NoReturn:

        ports = self.ports
        indicator = self.indicator
        # single port
        if isinstance(ports, int) and indicator == "single":
            self.ports_matrix = CreatePortsMatrix(start_range = ports,
                                                 end_range = ports + 1,
                                                 ).range_based_range()

        # scan random ports max -> 65534 ! randoms if 65535 pass to all
        elif isinstance(ports, int) and indicator == "random":
            self.ports_matrix = CreatePortsMatrix(number_for_rand = ports,
                                          ).number_based_range()
        # range of ports
        elif isinstance(ports, tuple) and indicator == "range":
            self.ports_matrix = CreatePortsMatrix(start_range = ports[0],
                                          end_range = ports[1],
                                          ).range_based_range()
        # list of ports
        elif isinstance(ports, list) and indicator == "list":
            self.ports_matrix = CreatePortsMatrix(list_of_ports = ports,
                                                  ).list_based_range()
        # all of ports
        elif isinstance(ports, bool) and indicator == "all":
            self.ports_matrix = CreatePortsMatrix(all_ports = 65535,
                                          ).number_based_range()

    def _capture(self, **kwargs) -> NoReturn:
        def capture(results, lock):
            analyze_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
                                           socket.htons(socket.ETH_P_ALL))
            analyze_socket.setblocking(True)
            data , addr = analyze_socket.recvfrom(self.max_packet_size)
            with lock:
                results.append(data)

        for ev in kwargs['events']:
            while not ev.is_set():
                capture(kwargs['results'], kwargs['lock'])

    def _threading_runner(self, general_target) -> NoReturn:

        def range_threader(main_thread_count, range_):

            if main_thread_count < 10:
                sub_threads = 1
            else:
                sub_threads = 3
            ports_queue = Queue()
            def threader():
                while True:
                    worker = ports_queue.get()
                    general_target(worker)
                    ports_queue.task_done()

            # threads to run on each list of ports
            for x in range(sub_threads):
                t = threading.Thread(target=threader)
                t.daemon = True
                t.start()

            start, end = range_[0],range_[1]
            for w in range(start, end):
                ports_queue.put(w)
            ports_queue.join()


        def thread_creator(threads_list, matrix_of_ports):

            # based of the lenght of the list of range ports
            # we have to create main threads
            count_main_threads = len(matrix_of_ports)
            for i in range(count_main_threads):
                # each of threads will work on a list in matrix of ports
                ports_range_list = matrix_of_ports[i]
                sleep(0.1)
                t = threading.Thread(target=range_threader,
                                     args=(count_main_threads, ports_range_list))
                threads_list.append(t)
                t.start()
            for t in threads_list:
                t.join()


        ports_matrix = self.ports_matrix
        threads_list = []
        # single main thread not necessary but we will create our threads in this manner
        main_thread = threading.Thread(target=thread_creator,
                                       args=(threads_list, ports_matrix))
        main_thread.start()
        main_thread.join()

    def _icmp_send_rcv(self) -> NoReturn:
        ICMP_packet = CreatePacket(prt="ICMP", src_ip=self.source_ip,
                                   target_ip=self.target_ip,  dest_port=53,
                                   type_=8, code=0 ).b_packet()

        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.sendto(ICMP_packet, (self.target_ip, 53)) # send it to dest with the specific port number
        d, a = s.recvfrom(self.max_packet_size)


    def _udp_sender(self, port: int, payload: bytes) -> 'socket':
        lock = self.lock
        UDP_packet = CreatePacket(prt="UDP",payload=payload,
                                  src_ip=self.source_ip,
                                  target_ip=self.target_ip,
                                  src_port=self.source_port,
                                  dest_port=port).b_packet()
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        with lock:
            udp_socket.sendto(UDP_packet, (self.target_ip, port))
        udp_socket.settimeout(self.time_out)
        return udp_socket


    def _advanced_udp_scan(self, udp_event) -> NoReturn:
        udp_payload_list = self.payload_list
        lock = self.lock
        def send_rcv_udp(port):
            for p in udp_payload_list:
                if port == p['port']:
                    payload = p['payloads']
                    for py in payload:
                        if isinstance(py, bytes):
                            u = self._udp_sender(port, py)
                            try:
                                with lock:
                                    u.recvfrom(self.max_packet_size)
                                u.close()
                                break
                            except socket.error:
                                u.close()
                                break
                            except TimeoutError:
                                u.close()
                                break
                        elif isinstance(py, list):
                            for pay in py:
                                u = self._udp_sender(port, pay)
                                try:
                                    with lock:
                                        u.recvfrom(self.max_packet_size)
                                    u.close()
                                    break
                                except socket.error:
                                    u.close()
                                    break
                                except TimeoutError:
                                    u.close()
                                    break

            else:
                u = self._udp_sender(port, b'\x00')
                try:
                    with lock:
                        u.recvfrom(self.max_packet_size)
                    u.close()
                except socket.error:
                    u.close()
                except TimeoutError:
                    u.close()

        self._icmp_send_rcv()
        self._threading_runner(send_rcv_udp)

        udp_event.set()


    def _advanced_tcp_scan(self, tcp_event) -> NoReturn:
        def send_rcv_tcp(dest_port):
            lock = self.lock
            socket.setdefaulttimeout(self.time_out)
            tcp_packet = CreatePacket(prt="TCP",
                                      src_ip=self.source_ip,
                                      target_ip=self.target_ip,
                                      src_port=self.source_port,
                                      dest_port=dest_port).b_packet()
            tcp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            tcp.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            with lock:
                tcp.sendto(tcp_packet, (self.target_ip, dest_port))
                try:
                    tcp.recvfrom(self.max_packet_size)
                except TimeoutError:
                    pass
                except socket.error:
                    pass
            tcp.close

        self._threading_runner(send_rcv_tcp)
        tcp_event.set()

    def _simple_udp_scan(self, event) -> NoReturn:

        payloads = self.payload_list
        def simple_udp_con(port: int, payload: bytes):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as simple_udp_socket:
                simple_udp_socket.settimeout(self.time_out)
                try:
                    simple_udp_socket.sendto(payload, (self.target_ip, port))
                    data, addr = simple_udp_socket.recvfrom(self.max_packet_size)
                except Exception as err:
                    raise err
                except TimeoutError:
                    raise

        def send_rcv_simple_udp(port: int) -> NoReturn:

            for payload in payloads:
                if port == payload['port']:
                    pay = payload['payloads']
                    if isinstance(pay, bytes):
                        try:
                            simple_udp_con(port, pay)
                            break
                        except Exception:
                            pass
                    elif isinstance(pay, list):
                        for p in pay:
                            try:
                                simple_udp_con(port, p)
                                break
                            except Exception:
                                pass
            else:
                try:
                    simple_udp_con(port, b'\x00')
                except:
                    pass

        self._threading_runner(send_rcv_simple_udp)
        event.set()


    def _simple_tcp_scan(self, event):

        def simple_tcp_scanner(port: int):
            socket.setdefaulttimeout(self.time_out)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.time_out)
            try:
                c = s.connect_ex((self.target_ip, port))
                s.close()
            except Exception:
                pass

        self._threading_runner(simple_tcp_scanner)
        event.set()

    def _concurrent_processor_handler(self):

        mp_lock = multiprocessing.Lock()

        with multiprocessing.Manager() as manager:
            targets = []

            if self.concurrent_scan_count == 2:
                if self.type_of_scan == "Advanced_UDP_TCP":
                    targets.append(self._advanced_udp_scan)
                    targets.append (self._advanced_tcp_scan)
                else:
                    targets.append(self._simple_udp_scan)
                    targets.append(self._simple_tcp_scan)

                tcp_event = multiprocessing.Event()
                udp_event = multiprocessing.Event()

                results = manager.list()

                keywords = {'events': [tcp_event, udp_event],
                            'results':results, 'lock':mp_lock}

                p1 = multiprocessing.Process(target=self._capture,
                                             kwargs=keywords)
                p1.start()
                p1.deamon = True
                p2 = multiprocessing.Process(target=targets[0],
                                             args=(udp_event,))

                p3 = multiprocessing.Process(target=targets[1],
                                             args=(tcp_event, ))
                sleep(1)
                p2.start()
                p3.start()
                p2.deamon = True
                p3.deamon = True
                p1.join()
                p2.join()
                p3.join()

                if not p2.is_alive() and not p3.is_alive():
                    sleep(1)
                    p1.terminate()
                    for i in results:
                        self.data_list.append(i)

            else:
                if self.type_of_scan == "Advanced_UDP":
                    targets.append(self._advanced_udp_scan)
                elif self.type_of_scan == "Advanced_TCP":
                    targets.append(self._advanced_tcp_scan)
                elif self.type_of_scan == "Simple_UDP":
                    targets.append(self._simple_udp_scan)
                else:
                    targets.append(self._simple_tcp_scan)

                event = multiprocessing.Event()

                results = manager.list()
                keywords = {'events': [event] , 'results': results, 'lock':
                            mp_lock}
                p1 = multiprocessing.Process(target=self._capture,
                                             kwargs=keywords)
                p1.start()
                p1.deamon = True
                p2 = multiprocessing.Process(target=targets[0],
                                             args=(event,))
                sleep(1)
                p2.start()
                p2.deamon = True
                p1.join()
                p2.join()

                if not p2.is_alive():
                    sleep(1)
                    p1.terminate()
                    for i in results:
                        self.data_list.append(i)


    def scanner(self) -> Sequence[list[dict]]:
        self._input_handler()
        self._concurrent_processor_handler()

        def clean_results(self, raw_results:list[dict]) -> Sequence[list[dict]]:
            raw_results = list(filter(lambda i: i is not None, raw_results))
            raw_results = list({frozenset(r.items()) for r in raw_results})
            self.final_results = [dict(i) for i in raw_results]

        def analayzing_results(self) -> Sequence[list[dict]]:
            raw_data = self.data_list
            raw_results = []
            for data in raw_data:
                raw_results.append(Sniffer(data,
                                    src_ip=self.source_ip,
                                    dest_ip=self.target_ip).final_analyzer())
            return raw_results

        clean_results(self, analayzing_results(self))
        return self.final_results

    def __repr__(self) -> str:
        msg = f"""Source IP: {self.source_ip} Target IP: {self.target_ip}
        SRC_PORT: {self.source_port}
        PORT/PORTS: {self.ports if not isinstance(self.ports, bool) else 'All ports'}
        Payload List:{self.payload_list} \n\n Type of scan: {self.type_of_scan}
        """
        return msg
    def __str__(self) -> str:
        msg = f"""Source IP: {self.source_ip} Target IP: {self.target_ip}
        SRC_PORT: {self.source_port}
        PORT/PORTS: {self.ports if not isinstance(self.ports, bool) else 'All ports'}
        Payload List:{self.payload_list} \n\n Type of scan: {self.type_of_scan}
        """
        return msg
