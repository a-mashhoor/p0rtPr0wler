from utils import *
from classes.customExceptionsClass import *

class CreatePacket(object):

    '''
        CreatePacket class:
        any class instances can take multiple arguments (named or
        positional)
        starting with prt which stands for protocol to be created
        the class supports 3 major protocols ICMP TCP and UDP the prt
        takes string "ICMP" | "TCP" | "UDP"
        next arg is payload which is optional and it is there for a
        solo reason! a UDP payload based on the port! we are not
        massing around with TCP payloads because there is no need
        and we are not massing around with ICMP payloads because
        our intentions are pure we don't want to create any dangrous
        death ping like packets!
        the next 2 args are source ip and destination (target) ip
        which are reuired and if for any reasons the user won't provide
        any we'll raise an exception
        in some terms we reinvented the wheel for sake of Education
        the class works based on internet protocol so it will
        create an IP header and calculates it cheksum
        this class will create a complete packet based on the given
        protocol
        protocols can be TCP, UDP or ICMP
        the class will calculate the cheksum for each given protcol

    '''
    # init constructor
    def __init__(self, prt: str ='',
                 payload: Union[str, bytes, None] = None,
                 ip_vr: int = 4,
                 src_ip: Union[str, None] = None,
                 target_ip: Union[str, None] = None,
                 src_port: int = 12345,
                 dest_port: int = 80,
                 ttl:int = 64,
                 ICMP_id: int = 4660,
                 type_: int = 8,
                 code:int = 0
                 ) -> NoReturn:

        # Input error handeling

        if not prt or prt not in ['ICMP', 'UDP', 'TCP']:
            raise UnkownPacketError(
                    {msg:='the Protocol is not supported by the class!', errC:=21})

        if src_ip is None or target_ip is None:
            raise NoIpProvidedError({msg:='Must provide both src ip and dest ip', errC:=10})
        elif not all(isinstance(_, str) for _ in [src_ip, target_ip]):
            raise NoIpProvidedError({msg:='Must provide both src ip and dest ip', errC:=11})
        elif not src_ip or not target_ip:
            raise NoIpProvidedError({msg:='Must provide both src ip and dest ip', errC:=12})

        if not all(isinstance(_, int) for _ in [src_port, dest_port, ttl, ICMP_id, type_, code]):
            raise ValueError

        ### Initialization and declarations class instance attributes  ###


        # config class instance attributes
        # porotcol to be sent
        """
        In the Ip header which is a layer 3 protcol we can see a protcol
        field we only support 3 protcols
        0x01 or 1 in decimal -> ICMP
        0x06 or 6 in decimal -> TCP
        0x11 or 17 in decimal -> UDP
        """
        self.prt = prt
        p = 1  if self.prt == "ICMP" else (17 if self.prt == "UDP" else 6)

        # general class instance attributes

        # if the user wants to send only udp packet
        if payload is None:
            self.payload = b''
        # if the user wants packet
        else:
            try:
                if type(payload) is not bytes: # yes i know i can use isinstance here
                    self.payload = payload.encode()
                else:
                    self.payload = payload
            except AttributeError:
                raise WrongPayloadError({msg:='you must use a valid payload', errC:=11})

        # IP segment class instance attributes
        self.version = ip_vr
        self.ihl = 5
        self.type_of_service = 0
        self.total_length = 40
        self.identification = 43981
        self.flags = 0
        self.fragment_offset = 0
        self.ttl = ttl
        self.protocol = p
        self.IP_header_checksum = 0 # for now we'll use zero bytes for checksum
        self.src_ip = socket.inet_aton(src_ip)
        self.dest_ip = socket.inet_aton(target_ip)
        self.v_ihl = (self.version << 4) + self.ihl
        self.flg_flgoff = (self.flags << 13) + self.fragment_offset

        # ICMP segment class instance attributes
        self.type_of_message = type_
        self.code = code
        self.ICMP_header_checksum = 0
        self.ICMP_id = ICMP_id
        self.ICMP_seq = 1
        self.ICMP_payload = dest_port

        # TCP segment class instance attributes
        self.src_port = src_port
        self.dest_port = dest_port
        self.seq_no = 0
        self.ack_no = 0
        self.data_offset = 5
        self.reserved = 0
        self.ns, self.cwr, self.ece, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin = \
                0, 0, 0, 0, 0, 0, 0, 1, 0;
        self.window_size = 28944
        self.TCP_header_checksum = 0
        self.urg_pointer = 0
        self.data_offset_res_flags = (self.data_offset << 12) + (self.reserved << 9) + \
                (self.ns << 8) + (self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + \
                (self.ack << 4) + (self.psh << 3) + (self.rst << 2) + (self.syn << 1) + self.fin;

        # UDP segment class instance attributes
        self.UDP_src_port = src_port
        self.UDP_dest_port = dest_port
        if payload is not None:
            # data size + udp packet header size!
            self.UDP_header_length = (len(self.payload) + 8)
        else:
            self.UDP_header_length = 0x8
        # also notable the cheksum is not mandatory but we'll calculate it
        self.UDP_header_checksum = 0x0

        # packet class instance attributes
        self.IP_header = b''
        self.TCP_header = b''
        self.UDP_header = b''
        self.ICMP_header = b''
        self.packet = b''

    # Honsetly this function was a pain in the A! so i used the one in the web and it worked!
    def _calc_checksum(self, header: Sequence[bytes]) -> Sequence[int]:
        checksum = 0
        # Header Must be even!
        if len(header) % 2 != 0:
            header += b"\x00"
        # Calculate checksum
        # because we are iterating through the header python will treat each 16 bit as int
        # so at the end we will return int not bytes
        for i in range(0, len(header), 2):
            checksum += (header[i] << 8) + header[i+1]
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16
        return (~checksum) & 0xffff

    # custom return for better __annotations__
    header_return = {'type':Sequence[bytes],
                     'docstring': 'function returns a computed and build header'}

    """
    we Starting building the headers at the IP header the socket will build us the thernet header
    with the IP protcol in it 0x08 or 8 in decimal
    """
    def _build_IP_header(self) -> header_return:
        # building a packet with cheksum place holder
        tmp = pack("!2B3H2BH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                          self.identification, self.flg_flgoff,
                          self.ttl, self.protocol, self.IP_header_checksum,
                          self.src_ip,
                          self.dest_ip)
        # calculating the checksum and building final ip header part of packet
        self.IP_header = pack("!2B3H2BH4s4s", self.v_ihl, self.type_of_service,
                                     self.total_length, self.identification, self.flg_flgoff,
                                     self.ttl, self.protocol, self._calc_checksum(tmp),
                                     self.src_ip,
                                     self.dest_ip)
        return self.IP_header

    # ICMP header do to it's simple nature does not need any payload or pseudo headers
    def _build_ICMP_header(self) -> header_return:
        tmp = pack('!2B4H', self.type_of_message, self.code,
                          self.ICMP_header_checksum,
                          self.ICMP_id,
                          self.ICMP_seq,
                          self.ICMP_payload
                          )
        self.ICMP_header = pack('!2B4H',
                                       self.type_of_message, self.code,
                                       self._calc_checksum(tmp),
                                       self.ICMP_id,
                                       self.ICMP_seq,
                                       self.ICMP_payload
                                       )
        return self.ICMP_header

    # TCP header is more complicated
    def _build_TCP_header(self) -> header_return:
        tmp = pack("!2H2L4H", self.src_port, self.dest_port,
                   self.seq_no,
                   self.ack_no,
                   self.data_offset_res_flags, self.window_size,
                   self.TCP_header_checksum, self.urg_pointer
                   )
        pseudo_h = pack("!4s4s2BH", self.src_ip, self.dest_ip,
                               self.TCP_header_checksum, self.protocol, len(tmp))
        psh = pseudo_h + tmp
        self.TCP_header = pack("!2H2L4H", self.src_port, self.dest_port,
                                      self.seq_no,
                                      self.ack_no,
                                      self.data_offset_res_flags, self.window_size,
                                      self._calc_checksum(psh), self.urg_pointer)
        return self.TCP_header

    # UDP header also needs a pseudo header for calculating the checksum!
    def _build_UDP_header(self) -> header_return:
        tmp = pack('!4H', self.UDP_src_port, self.UDP_dest_port,
                            self.UDP_header_length,
                            self.UDP_header_checksum
                             )
        pseudo_h = pack("!4s4s2BH",self.src_ip, self.dest_ip,
                               self.UDP_header_checksum, self.protocol, self.UDP_header_length)
        psh = pseudo_h + tmp
        header = pack('!4H', self.UDP_src_port, self.UDP_dest_port,
                            self.UDP_header_length,
                            self._calc_checksum(psh + self.payload)
                             )

        self.UDP_header = (header + self.payload)
        return self.UDP_header

    # finilizing the packet by concatinating the ip_header and selected layer 4 protcol
    def b_packet(self) -> Sequence[bytes]:
        ip_header = self._build_IP_header()
        if self.prt == "ICMP":
            self.packet = (ip_header +  self._build_ICMP_header())
            return self.packet
        elif self.prt == "TCP":
            self.packet = (ip_header + self._build_TCP_header())
            return self.packet
        else:
            self.packet = (ip_header + self._build_UDP_header())
            return self.packet

    def __repr__(self) -> str:
        msg = f"""protocol: {self.prt} source IP: {self.src_ip} dest IP: {self.target_ip}
        source port: {self.src_port}"""
        return msg

    def __str__(self) -> str:
        msg = f"""protocol to create: {self.prt} source IP: {self.src_ip} dest IP: {self.target_ip}
        source port: {self.src_port}"""
        return msg
