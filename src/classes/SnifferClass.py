from utils import *
from classes.customExceptionsClass import *

class Sniffer(object):

    '''
    Sniffer Class:
        the class captures all of traffic on all interfaces
        filters out any packet other than the ones tool generated
        read the packets and analyze them based on some common indicator
        which is different in tcp and udp
        in the end conclude one of the 4 states similer to nmap
        open, filtered, closed, open|filtered for udp
        and for tcp open, closed

    _Ethernet_header_parser(self):
         unlike the creation of packets we need to start parsing by ethernet II header
         in layer 2 frame to determine the packet contains which layer 3 protocol


    _ICMP_payload_parser(self):

            # By design ICMP dosen't have any port support
            # but, remember when we created the packet
            # we added a custom payload to the echo packet
            # the destination port
            # by default when we are using ICMP echo request
            # the target server will return the ICMP payload
            # untouched so we can see the port replyied to our
            # ping request
            # it's not useful but i wanted to demonstrate we can almost use anything as
            # payload for ICMP PING

        In general, we are building our port scanner with the same logic Namp is built,
        which is listening for any direct UDP response or any ICMP response and then
        analyzing the ICMP responses after we send a UDP payload to the target server,
        unfortunately, as we said before ICMP protocol does not support any port or any
        indication by itself that which port is closed in the "type 3" responses. Still,
        the default behavior of ICMP is to return The:
        ( 6 bytes of unused data + IP header + UDP header + UDP payload)
        so we have to check if the length of the payload is greater than normal.
        Then we have to calculate all of the data mentioned above except for the UDP
        payload because that is the last part of the returned data so we can ignore it
        and use the total length to distinguish different parts of the ICMP returned
        payload after that we can check the UDP part of the payload to
        see which port is closed!
        It seems like a lot of work, indeed it is

    _filter(self):

        The function initialize the ip header parser and
        filters any packet other than the ones which
        target src ip responed (our dest ip) and the
        src port (dest port)
        then based on the protcol we'll parse the response
        in this manner we'll capture all the traffic
        and filter all the traffic other than the ones
        tool created


    _fianal_analyzer(self):
        this functions checkes packets and analyze a the final result
        if we send an ICMP echo and recive no ICMP response the target closed is filtering the ICMP
        protcol
        if we send a udp packet and recived a response the port is open! so no furthur work
        if we send a udp packet even after a couple of reteries and stil no packet recived the port
        may open and may not so open|filtered
        if we recived a ICMP response after we send an udp packet with type 3 code 3
        the port is defintly closed
        if we recived a ICMP response after we send an udp packet with type 3 code in 1, 2, 9 ,10,
        13 the port is filtered
        the order of opration is everything here !
        so after every sended packet from our side we need to check the responses for the protcol

        for TCP the is much simpler just an SYN/ACK flag is the indicator we want to
        determine wheter an port is open or not!

        # if lenth is greater than 6 it means the packets contains usefull info
        if type_ == 3 and code == 3 and len(icmp_payload) > 6:

    '''

    def __init__(self,
                 raw_data: Union[None,bytes] = None,
                 src_ip: Union[str,None] = None,
                 dest_ip: Union[str,None] = None
                 ) -> NoReturn:


        ### Initialization and declarations class instance attributes ###
        # raw data class instance attributes
        self.eth_head_raw = raw_data[:14]
        self.ip_head_raw = raw_data[14:]
        self.ICMP_head_raw = None
        self.UDP_head_raw = None
        self.TCP_head_raw = None


        # class instance attributes used in filtering recived packets
        self.src_ip = src_ip
        self.dest_ip = dest_ip

        self.tmp_icmp_r = None
        self.tmp_dict = {}
        self.result = {}

    def _Ethernet_header_parser(self) -> Tuple[str, str, int]:
        dest, src, prototype = unpack('!6s6sH', self.eth_head_raw)
        # one way for extracting mac addr
        dest_mac = ':'.join(f'{byte:02x}' for byte in dest)
        # another way for the finding mac addr (yeah i know i'm showing off )
        src_mac = ':'.join(f'{byte:02x}' for byte in unpack('6B', src))
        protocol = socket.htons(prototype)
        return dest_mac, src_mac, protocol

    def _IP_header_parser(self) -> Union[Tuple[int, int, int, int, str, str],None]:
        # protocol 8(0x800) in the ethernet header means the next part of raw data is ip header
        # protcol 0x806 means the nex part is ARP!
        # we only want to deal with ip header not LLDP, ARP, CAN, FDB or any other layer 2 protcols
        protocol = self._Ethernet_header_parser()[2]
        if protocol == 8:
            version_header_len = self.ip_head_raw[0]
            version = version_header_len >> 4
            header_len = (version_header_len & 15) * 4
            ttl, proto, src, dest = unpack('!8x2B2x4s4s', self.ip_head_raw[:20])
            src_ip = '.'.join(map(str, src))
            dest_ip = '.'.join(map(str, dest))
            # protocol return value from ip header -> 1 == ICMP, 6 == TCP, 17 == UDP, RDP == 27

            if proto == 1:
                self.ICMP_head_raw = self.ip_head_raw[header_len:]
            elif proto == 6:
                self.TCP_head_raw = self.ip_head_raw[header_len:]
            elif proto == 17:
                self.UDP_head_raw = self.ip_head_raw[header_len:]
            else:
                raise UnsupportedProtocolError({msg:="protcol in ip header is not supported", errC:=30})

            return version, header_len, ttl, proto, src_ip, dest_ip
        else:
            return None


    def _TCP_header_parser(self) -> Tuple[int,int,int,int,int,int,int,int,int,int,bytes]:
        r_src_port, r_dest_port, seq, ack, offset_reserved_flags = unpack('!2H2LH',
                                                                            self.TCP_head_raw[:14]
                                                                            )
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        tcp_payload = self.TCP_head_raw[offset:]

        return r_src_port, r_dest_port, seq, ack, flag_urg, flag_ack,\
                flag_psh, flag_rst, flag_syn, flag_fin, tcp_payload

    def _UDP_header_parser(self) -> Tuple[int,int,int,bytes]:
        r_src_port, r_dest_port, length, r_u_checksum =  unpack('!3H2s',
                                                                  self.UDP_head_raw[:8])
        udp_payload = self.UDP_head_raw[8:]
        return r_src_port, r_dest_port, length, r_u_checksum, udp_payload

    def _ICMP_header_parser(self) -> Tuple[int, int]:
        code, type_, checksum = unpack('!2b2s',self.ICMP_head_raw[:4])
        icmp_payload = self.ICMP_head_raw[4:]
        return code, type_, checksum, icmp_payload

    def _ICMP_payload_parser(self) -> dict:
        icmp_unused_len = 4
        ip_header_len = 20
        udp_header_len = 8
        data = self.tmp_icmp_r
        type_ = data[0]
        code = data[1]
        payload = data[3]
        result = {}

        # working on echo results
        if type_ == 8 or type_ == 0:
            result['protocol'] = "ICMP"
            result['icmp_type'] = type_
            result['icmp_code'] = code
            if payload[-2:] != b'\x00':
                result['port'] = unpack('!H',payload[-2:])[0]
            else:
                result['port'] = 'Undefined'
            result['state'] = "Echo"
            return result

        # working on ICMP payload type 3
        elif type_ == 3 and code in [1, 2, 3, 9, 10, 13]:
            icmp_part_of_pyaload = payload[:4]
            ip_part_of_payload = payload[4:24]
            udp_part_of_payload = payload[24:32]
            if payload[32:]:
                rest_of_payload = payload[32:]

            if code == 3:
                result['protocol'] = 'UDP'
                result['port'] = unpack('!H',udp_part_of_payload[:2])[0]
                result['state'] = 'Closed'
                result['icmp_type'] = type_
                result['icmp_code'] = code
                return result

            else:
                result['protocol'] = 'UDP'
                result['port'] = unpack('!H',udp_part_of_payload[:2])[0]
                result['state'] = 'Filtered'
                result['icmp_type'] = type_
                result['icmp_code'] = code
                return result

    def _filter(self) -> dict:
        recvd_ip_header = self._IP_header_parser()
        if recvd_ip_header is not None:

            if recvd_ip_header[0] == 4 and recvd_ip_header[4] == self.dest_ip \
                    and recvd_ip_header[5] == self.src_ip:

                        if recvd_ip_header[3] == 1:
                            self.tmp_dict['protocol'] = "ICMP"
                            self.tmp_dict['data'] = self._ICMP_header_parser()
                            return self.tmp_dict

                        elif recvd_ip_header[3] == 6:
                            self.tmp_dict['protocol'] = "TCP"
                            self.tmp_dict['data'] = self._TCP_header_parser()
                            return self.tmp_dict

                        elif recvd_ip_header[3] == 17:
                            self.tmp_dict['protocol'] = "UDP"
                            self.tmp_dict['data'] = self._UDP_header_parser()
                            return self.tmp_dict

    def final_analyzer(self) -> dict:
        tmp_r = self._filter()
        if tmp_r is not None:
            data = tmp_r['data']

            if tmp_r['protocol'] == 'ICMP':
                self.tmp_icmp_r = data
                self.result = self._ICMP_payload_parser()
                return self.result

            elif tmp_r['protocol'] == 'UDP':
                self.result['protocol'] = 'UDP'
                self.result['port'] = data[0]
                self.result['state'] = 'Open'
                return self.result

            else:
                self.result['protocol'] = 'TCP'
                self.result['port'] = data[0]
                self.result['state'] = 'Open'
                return self.result

    def __repr__(self) -> str:
        msg = f"""data: {self.raw_data} \nsource ip: {self.src_ip}
        \ndestination ip: {self.dest_ip} """
        return msg

    def __str__(self) -> str:
        msg = f"""data: {self.raw_data} \nsource ip: {self.src_ip}
        \ndestination ip: {self.dest_ip} """
        return msg
