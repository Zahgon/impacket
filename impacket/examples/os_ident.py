# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#

import warnings
from impacket import version

warnings.warn(
    '\n'+version.DEPRECATION_WARNING_BANNER,
    DeprecationWarning,
    stacklevel=2, 
)

import math
import array
from six.moves import xrange, reduce

from pcapy import lookupdev, open_live
from impacket.ImpactPacket import UDP, TCPOption, Data, TCP, IP, ICMP, Ethernet
from impacket.ImpactDecoder import EthDecoder
from impacket import LOG



g_nmap1_signature_filename="nmap-os-fingerprints"
g_nmap2_signature_filename="nmap-os-db"


def my_gcd(a, b):
    pass

class os_id_exception:
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class os_id_test:
    
    def __init__(self, id):
        self.__id = id
        self.__my_packet = None
        self.__result_dict = {}

    def test_id(self):
        pass

    def get_test_packet(self):
        pass

    def set_packet(self, packet):
        self.__my_packet = packet

    def get_packet(self):
        return self.__my_packet
        
    def process(self, packet):
        pass

    def add_result(self, name, value):
        self.__result_dict[name] = value
                
    def get_id(self):
        pass
    def is_mine(self, packet):
        pass

    def get_result_dict(self):
        pass

    def get_final_result(self):
        "Returns a string representation of the final result of this test or None if no response was received"
        pass


class icmp_request(os_id_test):
    type_filter = { ICMP.ICMP_ECHO : ICMP.ICMP_ECHOREPLY,
                    ICMP.ICMP_IREQ : ICMP.ICMP_IREQREPLY,
                    ICMP.ICMP_MASKREQ : ICMP.ICMP_MASKREPLY,
                    ICMP.ICMP_TSTAMP : ICMP.ICMP_TSTAMPREPLY }

    def __init__(self, id, addresses, type):
        os_id_test.__init__(self, id)
        self.e = Ethernet()
        self.i = IP()
        self.icmp = ICMP()

        self.i.set_ip_src(addresses[0])
        self.i.set_ip_dst(addresses[1])

        self.__type = type
        self.icmp.set_icmp_type(type)
        
        self.e.contains(self.i)
        self.i.contains(self.icmp)
        self.set_packet(self.e)

    def is_mine(self, packet):

        pass

    def process(self, packet):
        pass


class nmap2_icmp_echo_probe_1(icmp_request):
    # The first one has the IP DF bit set, a type-of-service (TOS)  byte 
    # value of zero, a code of nine (even though it should be zero), 
    # the sequence number 295, a random IP ID and ICMP request identifier, 
    # and a random character repeated 120 times for the data payload.
    sequence_number = 295
    id = 0x5678

    def __init__(self, id, addresses):
        icmp_request.__init__(self, id, addresses, ICMP.ICMP_ECHO)
        self.i.set_ip_df(True)
        self.i.set_ip_tos(0)
        self.icmp.set_icmp_code(9)
        self.icmp.set_icmp_seq(nmap2_icmp_echo_probe_1.sequence_number)
        self.i.set_ip_id(nmap2_icmp_echo_probe_1.id)
        self.icmp.set_icmp_id(nmap2_icmp_echo_probe_1.id)
        self.icmp.contains(Data("I" * 120))
        
    def process(self, packet):
        pass

class nmap2_icmp_echo_probe_2(icmp_request):
    # The second ping query is similar, except a TOS of four 
    # (IP_TOS_RELIABILITY) is used, the code is zero, 150 bytes of data is 
    # sent, and the IP ID, request ID, and sequence numbers are incremented 
    # by one from the previous query values.

    def __init__(self, id, addresses):
        icmp_request.__init__(self, id, addresses, ICMP.ICMP_ECHO)
        self.i.set_ip_df(False)
        self.i.set_ip_tos(4)
        self.icmp.set_icmp_code(0)
        self.icmp.set_icmp_seq(nmap2_icmp_echo_probe_1.sequence_number + 1)
        self.i.set_ip_id(nmap2_icmp_echo_probe_1.id + 1)
        self.icmp.set_icmp_id(nmap2_icmp_echo_probe_1.id + 1)
        self.icmp.contains(Data("I" * 150))
        
    def process(self, packet):
        pass

class udp_closed_probe(os_id_test):

    ip_id = 0x1234 # HARDCODED

    def __init__(self, id, addresses, udp_closed ):

        os_id_test.__init__(self, id )
        self.e = Ethernet()
        self.i = IP()
        self.u = UDP()

        self.i.set_ip_src(addresses[0])
        self.i.set_ip_dst(addresses[1])
        self.i.set_ip_id(udp_closed_probe.ip_id)
        self.u.set_uh_sport(id)
        
        self.u.set_uh_dport( udp_closed )

        self.e.contains(self.i)
        self.i.contains(self.u)
        self.set_packet(self.e)

    def is_mine(self, packet):
        pass


class tcp_probe(os_id_test):

    def __init__(self, id, addresses, tcp_ports, open_port ):

        self.result_string = "[]"
        os_id_test.__init__(self, id)
        self.e = Ethernet()
        self.i = IP()
        self.t = TCP()
        self.i.set_ip_src(addresses[0])
        self.i.set_ip_dst(addresses[1])
        self.i.set_ip_id(0x2323) # HARDCODED
        self.t.set_th_sport(id)

        if open_port:        
            self.target_port = tcp_ports[0]
        else:
            self.target_port = tcp_ports[1]
                
        self.t.set_th_dport(self.target_port)
        
        self.e.contains(self.i)
        self.i.contains(self.t)
        self.set_packet(self.e)
        
        self.source_ip = addresses[0]
        self.target_ip = addresses[1]

    def socket_match(self, ip, tcp):
        # scr ip and port
        pass

    def is_mine(self, packet):
        pass


class nmap_tcp_probe(tcp_probe):

    def __init__(self, id, addresses, tcp_ports, open_port, sequence, options):
        tcp_probe.__init__(self, id, addresses, tcp_ports, open_port)
        self.t.set_th_seq(sequence)
        self.set_resp(False)
        for op in options:
            self.t.add_option(op)

    def set_resp(self,resp):
        pass

class nmap1_tcp_probe(nmap_tcp_probe):
    sequence = 0x8453 # 0xBASE, obviously
    mss = 265

    # From: https://nmap.org/nmap-fingerprinting-old.html
    # [...]
    # Nmap sends these options along with almost every probe packet:
    #   Window Scale=10; NOP; Max Segment Size = 265; Timestamp; End of Ops;
    # [...]
    # From nmap-4.22SOC8/osscan.cc:get_fingerprint(...)
    # [...]
    # "\003\003\012\001\002\004\001\011\010\012\077\077\077\077\000\000\000\000\000\000"
    # [...]
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_WINDOW, 0o12), #\003\003\012
        TCPOption(TCPOption.TCPOPT_NOP), #\001
        TCPOption(TCPOption.TCPOPT_MAXSEG, mss), #\002\004\001\011
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0x3F3F3F3F), #\010\012\077\077\077\077\000\000\000\000
        TCPOption(TCPOption.TCPOPT_EOL), #\000
        TCPOption(TCPOption.TCPOPT_EOL) #\000
    ]

    def __init__(self, id, addresses, tcp_ports, open_port):
        nmap_tcp_probe.__init__(self, id, addresses, tcp_ports, open_port, 
                                self.sequence, self.tcp_options)

    def set_resp(self,resp):
        if resp:
            self.add_result("Resp", "Y")
        else:
            self.add_result("Resp", "N")

    def process(self, packet):
        pass

    def get_final_result(self):
        pass


class nmap2_tcp_probe(nmap_tcp_probe):
    acknowledgment = 0x181d4f7b

    def __init__(self, id, addresses, tcp_ports, open_port, sequence, options):
        nmap_tcp_probe.__init__(self, id, addresses, tcp_ports, open_port, 
                                sequence, options)
        self.t.set_th_ack(self.acknowledgment)

    def set_resp(self,resp):
        # Responsiveness (R)
        # This test simply records whether the target responded to a given probe. 
        # Possible values are Y and N. If there is no reply, remaining fields 
        # for the test are omitted.
        if resp:
            self.add_result("R", "Y")
        else:
            self.add_result("R", "N")

    def process(self, packet):
        pass

    def get_final_result(self):
        pass


class nmap2_ecn_probe(nmap_tcp_probe):
    # From nmap-4.22SOC8/osscan2.cc:
    # [...]
    # "\003\003\012\001\002\004\005\264\004\002\001\001"
    # [...]

    # From: https://nmap.org/book/osdetect-methods.html
    # [...]
    # This probe tests for explicit congestion notification (ECN) support 
    # in the target TCP stack. ECN is a method for improving Internet 
    # performance by allowing routers to signal congestion problems before 
    # they start having to drop packets. It is documented in RFC 3168. 
    # Nmap tests this by sending a SYN packet which also has the ECN CWR 
    # and ECE congestion control flags set. For an unrelated (to ECN) test, 
    # the urgent field value of 0xF7F5 is used even though the urgent flag 
    # is not set. The acknowledgment number is zero, sequence number is 
    # random, window size field is three, and the reserved bit which 
    # immediately precedes the CWR bit is set. TCP options are WScale (10), 
    # NOP, MSS (1460), SACK permitted, NOP, NOP. The probe is sent to an 
    # open port.
    # [...]
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_WINDOW, 0o12), #\003\003\012
        TCPOption(TCPOption.TCPOPT_NOP), #\001
        TCPOption(TCPOption.TCPOPT_MAXSEG, 1460), #\002\004\005\0264
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED), #\004\002
        TCPOption(TCPOption.TCPOPT_NOP), #\001
        TCPOption(TCPOption.TCPOPT_NOP) #\001
    ]


    def __init__(self, id, addresses, tcp_ports):
        nmap_tcp_probe.__init__(self, id, addresses, tcp_ports, 1, 
                                0x8b6a, self.tcp_options)
        self.t.set_SYN()
        self.t.set_CWR()
        self.t.set_ECE()
        self.t.set_flags(0x800)
        self.t.set_th_urp(0xF7F5)
        self.t.set_th_ack(0)
        self.t.set_th_win(3)
        #self.t.set_th_flags(self.t.get_th_flags() | 0x0100) # 0000 0001 00000000

    def test_id(self):
        pass

    def set_resp(self,resp):
        if resp:
            self.add_result("R", "Y")
        else:
            self.add_result("R", "N")

    def process(self, packet):
        pass

    def get_final_result(self):
        pass

class nmap2_tcp_tests:
    def __init__(self, ip, tcp, sequence, acknowledgment):
        self.__ip = ip
        self.__tcp = tcp
        self.__sequence = sequence
        self.__acknowledgment = acknowledgment

    def get_df(self):
        # IP don't fragment bit (DF)
        # The IP header contains a single bit which forbids routers from fragmenting 
        # a packet. If the packet is too large for routers to handle, they will just 
        # have to drop it (and ideally return a "destination unreachable,
        # fragmentation needed" response). This test records Y if the bit is set, 
        # and N if it isn't.
        pass

    def get_win(self):
        # TCP initial window size (W, W1-W6)
        # This test simply records the 16-bit TCP window size of the received packet. 
        pass

    def get_ack(self):
        # TCP acknowledgment number (A)
        # This test is the same as S except that it tests how the acknowledgment 
        # number in the response compares to the sequence number in the 
        # respective probe.
        # Value	Description
        # Z	    Acknowledgment number is zero.
        # S	    Acknowledgment number is the same as the sequence number in the probe.
        # S+	Acknowledgment number is the same as the sequence number in the probe plus one.
        # O	    Acknowledgment number is something else (other).
        pass

    def get_seq(self):
        # TCP sequence number (S)
        # This test examines the 32-bit sequence number field in the TCP 
        # header. Rather than record the field value as some other tests 
        # do, this one examines how it compares to the TCP acknowledgment 
        # number from the probe that elicited the response. 
        # Value	    Description
        # Z	        Sequence number is zero.
        # A	        Sequence number is the same as the acknowledgment number in the probe.
        # A+	    Sequence number is the same as the acknowledgment number in the probe plus one.
        # O	        Sequence number is something else (other).
        pass

    def get_flags(self):
        # TCP flags (F)
        # This field records the TCP flags in the response. Each letter represents 
        # one flag, and they occur in the same order as in a TCP packet (from 
        # high-bit on the left, to the low ones). So the value SA represents the 
        # SYN and ACK bits set, while the value AS is illegal (wrong order). 
        # The possible flags are shown in Table 8.7.
        # Character	Flag name	            Flag byte value
        # E	        ECN Echo (ECE)	        64
        # U	        Urgent Data (URG)	    32
        # A	        Acknowledgment (ACK)	16
        # P	        Push (PSH)	            8
        # R	        Reset (RST)	            4
        # S	        Synchronize (SYN)	    2
        # F	        Final (FIN)	            1
        
        flags = ""

        if self.__tcp.get_ECE():
            flags += "E"
        if self.__tcp.get_URG():
            flags += "U"
        if self.__tcp.get_ACK():
            flags += "A"
        if self.__tcp.get_PSH():
            flags += "P"
        if self.__tcp.get_RST():
            flags += "R"
        if self.__tcp.get_SYN():
            flags += "S"
        if self.__tcp.get_FIN():
            flags += "F"

        return flags

    def get_options(self):
        # Option Name	                    Character    Argument (if any)
        # End of Options List (EOL)	        L	         
        # No operation (NOP)	            N	         
        # Maximum Segment Size (MSS)	    M	         The value is appended. Many systems 
        #                                                echo the value used in the corresponding probe.
        # Window Scale (WS)	                W	         The actual value is appended.
        # Timestamp (TS)	                T	         The T is followed by two binary characters 
        #                                                representing the TSval and TSecr values respectively. 
        #                                                The characters are 0 if the field is zero 
        #                                                and 1 otherwise.
        # Selective ACK permitted (SACK)	S	        

        pass

    def get_cc(self):
        # Explicit congestion notification (CC)
        # This test is only used for the ECN probe. That probe is a SYN packet 
        # which includes the CWR and ECE congestion control flags. When the 
        # response SYN/ACK is received, those flags are examined to set the 
        # CC (congestion control) test value as described in Table 8.3.

        # Table 8.3. CC test values
        # Value	Description
        # Y	    Only the ECE bit is set (not CWR). This host supports ECN.
        # N	    Neither of these two bits is set. The target does not support 
        #       ECN.
        # S	    Both bits are set. The target does not support ECN, but it 
        #       echoes back what it thinks is a reserved bit.
        # O	    The one remaining combination of these two bits (other).
        pass

    def get_quirks(self):
        # TCP miscellaneous quirks (Q)
        # This tests for two quirks that a few implementations have in their 
        # TCP stack. The first is that the reserved field in the TCP header 
        # (right after the header length) is nonzero. This is particularly 
        # likely to happen in response to the ECN test as that one sets a 
        # reserved bit in the probe. If this is seen in a packet, an "R"
        # is recorded in the Q string.

        # The other quirk Nmap tests for is a nonzero urgent pointer field 
        # value when the URG flag is not set. This is also particularly 
        # likely to be seen in response to the ECN probe, which sets a 
        # non-zero urgent field. A "U" is appended to the Q string when 
        # this is seen.

        # The Q string must always be generated in alphabetical order. 
        # If no quirks are present, the Q test is empty but still shown.

        pass

class nmap2_tcp_probe_2_6(nmap2_tcp_probe):
    sequence = 0x8453 # 0xBASE, obviously
    mss = 265

    # From nmap-4.22SOC8/osscan2.cc:
    # [...]
    # "\003\003\012\001\002\004\001\011\010\012\377\377\377\377\000\000\000\000\004\002"
    # [...]

    # From: https://nmap.org/book/osdetect-methods.html
    # [...]
    # The six T2 through T7 tests each send one TCP probe packet. 
    # With one exception, the TCP options data in each case is (in hex) 
    # 03030A0102040109080AFFFFFFFF000000000402. 
    # Those 20 bytes correspond to window scale (10), NOP, MSS (265), 
    # Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), then SACK permitted. 
    # (...
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_WINDOW, 0o12), #\003\003\012
        TCPOption(TCPOption.TCPOPT_NOP), #\001
        TCPOption(TCPOption.TCPOPT_MAXSEG, mss), #\002\004\001\011
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF), #\010\012\377\377\377\377\000\000\000\000
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED) #\004\002
    ]

    def __init__(self, id, addresses, tcp_ports, open_port):
        nmap2_tcp_probe.__init__(self, id, addresses, tcp_ports, open_port, 
                                 self.sequence, self.tcp_options)

class nmap2_tcp_probe_7(nmap2_tcp_probe):
    sequence = 0x8453 # 0xBASE, obviously
    mss = 265

    # ...)
    # The exception is that T7 uses a Window scale value of 15 rather than 10
    # [...]
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_WINDOW, 0o17), #\003\003\017
        TCPOption(TCPOption.TCPOPT_NOP), #\001
        TCPOption(TCPOption.TCPOPT_MAXSEG, mss), #\002\004\001\011
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF), #\010\012\377\377\377\377\000\000\000\000
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED) #\004\002
    ]

    def __init__(self, id, addresses, tcp_ports, open_port):
        nmap2_tcp_probe.__init__(self, id, addresses, tcp_ports, open_port, 
                                 self.sequence, self.tcp_options)

class nmap_port_unreachable(udp_closed_probe):

    def __init__(self, id, addresses, ports):
        udp_closed_probe.__init__(self, id, addresses, ports[2])
        self.set_resp(False)

    def test_id(self):
        pass

    def set_resp(self, resp):
        pass

    def process(self, packet):
        pass

class nmap1_port_unreachable(nmap_port_unreachable):

    def __init__(self, id, addresses, ports):
        nmap_port_unreachable.__init__(self, id, addresses, ports)
        self.u.contains(Data("A" * 300))

    def test_id(self):
        pass

    def set_resp(self,resp):
        if resp:
            self.add_result("Resp", "Y")
        else:
            self.add_result("Resp", "N")

    def process(self, packet):
        pass

    def get_final_result(self):
        pass

class nmap2_port_unreachable(nmap_port_unreachable):
    # UDP (U1)
    # This probe is a UDP packet sent to a closed port. The character 'C'
    # (0x43) is repeated 300 times for the data field. The IP ID value is 
    # set to 0x1042 for operating systems which allow us to set this. If 
    # the port is truly closed and there is no firewall in place, Nmap 
    # expects to receive an ICMP port unreachable message in return. 
    # That response is then subjected to the R, DF, T, TG, TOS, IPL, UN, 
    # RIPL, RID, RIPCK, RUCK, RUL, and RUD tests. 
    def __init__(self, id, addresses, ports):
        nmap_port_unreachable.__init__(self, id, addresses, ports)
        self.u.contains(Data("C" * 300))
        self.i.set_ip_id(0x1042)

    def test_id(self):
        pass

    def set_resp(self,resp):
        if resp:
            self.add_result("R", "Y")
        else:
            self.add_result("R", "N")

    def process(self, packet):
        pass

    def get_final_result(self):
        pass

class OS_ID:

    def __init__(self, target, ports):
        pcap_dev = lookupdev()
        self.p = open_live(pcap_dev, 600, 0, 3000)
        
        self.__source = self.p.getlocalip()
        self.__target = target
        
        self.p.setfilter("src host %s and dst host %s" % (target, self.__source), 1, 0xFFFFFF00)
        self.p.setmintocopy(10)
        self.decoder = EthDecoder()
        
        self.tests_sent = []
        self.outstanding_count = 0
        self.results = {}
        self.current_id = 12345

        self.__ports = ports

    def releasePcap(self):
        pass

    def get_new_id(self):
        pass
        
    def send_tests(self, tests):
        pass

    def run(self):
        pass

    def get_source(self):
        pass

    def get_target(self):
        return self.__target

    def get_ports(self):
        pass

    def packet_handler(self, len, data):
        pass


class nmap1_tcp_open_1(nmap1_tcp_probe):
    def __init__(self, id, addresses, tcp_ports):
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 1)
        self.t.set_ECE()
        self.t.set_SYN()

    def test_id(self):
        pass

    def is_mine(self, packet):
        pass


class nmap1_tcp_open_2(nmap1_tcp_probe):
    def __init__(self, id, addresses, tcp_ports):
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 1)

    def test_id(self):
        pass

class nmap2_tcp_open_2(nmap2_tcp_probe_2_6):
    # From: https://nmap.org/book/osdetect-methods.html
    # [...]
    # T2 sends a TCP null (no flags set) packet with the IP DF bit set and a 
    # window field of 128 to an open port.
    # ...
    def __init__(self, id, addresses, tcp_ports):
        nmap2_tcp_probe_2_6.__init__(self, id, addresses, tcp_ports, 1)
        self.i.set_ip_df(1)
        self.t.set_th_win(128)

    def test_id(self):
        pass

class nmap1_tcp_open_3(nmap1_tcp_probe):
    def __init__(self, id, addresses, tcp_ports ):
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 1)
        self.t.set_SYN()
        self.t.set_FIN()
        self.t.set_URG()
        self.t.set_PSH()

    def test_id(self):
        pass

class nmap2_tcp_open_3(nmap2_tcp_probe_2_6):
    # ...
    # T3 sends a TCP packet with the SYN, FIN, URG, and PSH flags set and a 
    # window field of 256 to an open port. The IP DF bit is not set.
    # ...
    def __init__(self, id, addresses, tcp_ports ):
        nmap2_tcp_probe_2_6.__init__(self, id, addresses, tcp_ports, 1)
        self.t.set_SYN()
        self.t.set_FIN()
        self.t.set_URG()
        self.t.set_PSH()
        self.t.set_th_win(256)
        self.i.set_ip_df(0)

    def test_id(self):
        pass

class nmap1_tcp_open_4(nmap1_tcp_probe):
    def __init__(self, id, addresses, tcp_ports):
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 1)
        self.t.set_ACK()

    def test_id(self):
        pass

class nmap2_tcp_open_4(nmap2_tcp_probe_2_6):
    # ...
    # T4 sends a TCP ACK packet with IP DF and a window field of 1024 to 
    # an open port.
    # ...
    def __init__(self, id, addresses, tcp_ports ):
        nmap2_tcp_probe_2_6.__init__(self, id, addresses, tcp_ports, 1)
        self.t.set_ACK()
        self.i.set_ip_df(1)
        self.t.set_th_win(1024)

    def test_id(self):
        pass


class nmap1_seq(nmap1_tcp_probe):
    SEQ_UNKNOWN = 0
    SEQ_64K = 1
    SEQ_TD = 2
    SEQ_RI = 4
    SEQ_TR = 8
    SEQ_i800 = 16
    SEQ_CONSTANT = 32

    TS_SEQ_UNKNOWN = 0
    TS_SEQ_ZERO = 1 # At least one of the timestamps we received back was 0
    TS_SEQ_2HZ = 2
    TS_SEQ_100HZ = 3
    TS_SEQ_1000HZ = 4
    TS_SEQ_UNSUPPORTED = 5 # System didn't send back a timestamp

    IPID_SEQ_UNKNOWN = 0
    IPID_SEQ_INCR = 1  # simple increment by one each time
    IPID_SEQ_BROKEN_INCR = 2 # Stupid MS -- forgot htons() so it counts by 256 on little-endian platforms
    IPID_SEQ_RPI = 3 # Goes up each time but by a "random" positive increment
    IPID_SEQ_RD = 4 # Appears to select IPID using a "random" distributions (meaning it can go up or down)
    IPID_SEQ_CONSTANT = 5 # Contains 1 or more sequential duplicates
    IPID_SEQ_ZERO = 6 # Every packet that comes back has an IP.ID of 0 (eg Linux 2.4 does this)

    def __init__(self, id, addresses, tcp_ports):
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 1)
        self.t.set_SYN()
        self.t.set_th_seq(id) # Used to match results with sent packets.

    def process(self, p):
        raise Exception("Method process is meaningless for class %s." % self.__class__.__name__)


class nmap2_seq(nmap2_tcp_probe):
    TS_SEQ_UNKNOWN = 0
    TS_SEQ_ZERO = 1 # At least one of the timestamps we received back was 0
    TS_SEQ_UNSUPPORTED = 5 # System didn't send back a timestamp

    IPID_SEQ_UNKNOWN = 0
    IPID_SEQ_INCR = 1  # simple increment by one each time
    IPID_SEQ_BROKEN_INCR = 2 # Stupid MS -- forgot htons() so it counts by 256 on little-endian platforms
    IPID_SEQ_RPI = 3 # Goes up each time but by a "random" positive increment
    IPID_SEQ_RD = 4 # Appears to select IPID using a "random" distributions (meaning it can go up or down)
    IPID_SEQ_CONSTANT = 5 # Contains 1 or more sequential duplicates
    IPID_SEQ_ZERO = 6 # Every packet that comes back has an IP.ID of 0 (eg Linux 2.4 does this)

    def __init__(self, id, addresses, tcp_ports, options):
        nmap2_tcp_probe.__init__(self, id, addresses, tcp_ports, 1, 
                                 id, options)
        self.t.set_SYN()

    def process(self, p):
        raise Exception("Method process is meaningless for class %s." % self.__class__.__name__)

class nmap2_seq_1(nmap2_seq):
    # Packet #1: window scale (10), 
    #            NOP, 
    #            MSS (1460), 
    #            timestamp (TSval: 0xFFFFFFFF; TSecr: 0), 
    #            SACK permitted. 
    # The window field is 1.
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_WINDOW, 10),
        TCPOption(TCPOption.TCPOPT_NOP),
        TCPOption(TCPOption.TCPOPT_MAXSEG, 1460),
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF),
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED)
    ]

    def __init__(self, id, addresses, tcp_ports):
        nmap2_seq.__init__(self, id, addresses, tcp_ports, self.tcp_options)
        self.t.set_th_win(1)

class nmap2_seq_2(nmap2_seq):
    # Packet #2: MSS (1400), 
    #            window scale (0), 
    #            SACK permitted, 
    #            timestamp (TSval: 0xFFFFFFFF; TSecr: 0), 
    #            EOL. 
    # The window field is 63.
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_MAXSEG, 1400),
        TCPOption(TCPOption.TCPOPT_WINDOW, 0),
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED),
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF),
        TCPOption(TCPOption.TCPOPT_EOL)
    ]

    def __init__(self, id, addresses, tcp_ports):
        nmap2_seq.__init__(self, id, addresses, tcp_ports, self.tcp_options)
        self.t.set_th_win(63)

class nmap2_seq_3(nmap2_seq):
    # Packet #3: Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), 
    #            NOP, 
    #            NOP, 
    #            window scale (5), 
    #            NOP, 
    #            MSS (640). 
    # The window field is 4.
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF),
        TCPOption(TCPOption.TCPOPT_NOP),
        TCPOption(TCPOption.TCPOPT_NOP),
        TCPOption(TCPOption.TCPOPT_WINDOW, 5),
        TCPOption(TCPOption.TCPOPT_NOP),
        TCPOption(TCPOption.TCPOPT_MAXSEG, 640)
    ]

    def __init__(self, id, addresses, tcp_ports):
        nmap2_seq.__init__(self, id, addresses, tcp_ports, self.tcp_options)
        self.t.set_th_win(4)

class nmap2_seq_4(nmap2_seq):
    # Packet #4: SACK permitted, 
    #            Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), 
    #            window scale (10), 
    #            EOL. 
    # The window field is 4.
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED),
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF),
        TCPOption(TCPOption.TCPOPT_WINDOW, 10),
        TCPOption(TCPOption.TCPOPT_EOL)
    ]

    def __init__(self, id, addresses, tcp_ports):
        nmap2_seq.__init__(self, id, addresses, tcp_ports, self.tcp_options)
        self.t.set_th_win(4)
    
class nmap2_seq_5(nmap2_seq):
    # Packet #5: MSS (536), 
    #            SACK permitted,
    #            Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), 
    #            window scale (10), 
    #            EOL. 
    # The window field is 16.
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_MAXSEG, 536),
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED),
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF),
        TCPOption(TCPOption.TCPOPT_WINDOW, 10),
        TCPOption(TCPOption.TCPOPT_EOL)
    ]

    def __init__(self, id, addresses, tcp_ports):
        nmap2_seq.__init__(self, id, addresses, tcp_ports, self.tcp_options)
        self.t.set_th_win(16)
    
class nmap2_seq_6(nmap2_seq):
    # Packet #6: MSS (265), 
    #            SACK permitted, 
    #            Timestamp (TSval: 0xFFFFFFFF; TSecr: 0). 
    # The window field is 512.
    tcp_options = [
        TCPOption(TCPOption.TCPOPT_MAXSEG, 265),
        TCPOption(TCPOption.TCPOPT_SACK_PERMITTED),
        TCPOption(TCPOption.TCPOPT_TIMESTAMP, 0xFFFFFFFF)
    ]

    def __init__(self, id, addresses, tcp_ports):
        nmap2_seq.__init__(self, id, addresses, tcp_ports, self.tcp_options)
        self.t.set_th_win(512)

class nmap1_seq_container(os_id_test):
    def __init__(self, num_seq_samples, responses, seq_diffs, ts_diffs, time_diffs):
        os_id_test.__init__(self, 0)

        self.num_seq_samples = num_seq_samples
        self.seq_responses = responses
        self.seq_num_responses = len(responses)
        self.seq_diffs = seq_diffs
        self.ts_diffs = ts_diffs
        self.time_diffs = time_diffs
        self.pre_ts_seqclass = nmap1_seq.TS_SEQ_UNKNOWN

    def test_id(self):
        pass

    def set_ts_seqclass(self, ts_seqclass):
        pass

    def process(self):
        pass

    def get_final_result(self):
        "Returns a string representation of the final result of this test or None if no response was received"
        pass

    def ipid_sequence(self):
        pass

    def ts_sequence(self):
        pass

    def seq_sequence(self):
        pass

    seqclasses = {
        nmap1_seq.SEQ_64K: '64K',
        nmap1_seq.SEQ_TD: 'TD',
        nmap1_seq.SEQ_RI: 'RI',
        nmap1_seq.SEQ_TR: 'TR',
        nmap1_seq.SEQ_i800: 'i800',
        nmap1_seq.SEQ_CONSTANT: 'C',
        }

    def add_seqclass(self, id):
        pass

    tsclasses = {
        nmap1_seq.TS_SEQ_ZERO: '0',
        nmap1_seq.TS_SEQ_2HZ: '2HZ',
        nmap1_seq.TS_SEQ_100HZ: '100HZ',
        nmap1_seq.TS_SEQ_1000HZ: '1000HZ',
        nmap1_seq.TS_SEQ_UNSUPPORTED: 'U',
        }

    def add_tsclass(self, id):
        pass

    ipidclasses = {
        nmap1_seq.IPID_SEQ_INCR: 'I',
        nmap1_seq.IPID_SEQ_BROKEN_INCR: 'BI',
        nmap1_seq.IPID_SEQ_RPI: 'RPI',
        nmap1_seq.IPID_SEQ_RD: 'RD',
        nmap1_seq.IPID_SEQ_CONSTANT: 'C',
        nmap1_seq.IPID_SEQ_ZERO: 'Z',
        }

    def add_ipidclass(self, id):
        pass


class nmap2_seq_container(os_id_test):
    def __init__(self, num_seq_samples, responses, seq_diffs, ts_diffs, time_diffs):
        os_id_test.__init__(self, 0)

        self.num_seq_samples = num_seq_samples
        self.seq_responses = responses
        self.seq_num_responses = len(responses)
        self.seq_diffs = seq_diffs
        self.ts_diffs = ts_diffs
        self.time_diffs = time_diffs
        self.pre_ts_seqclass = nmap2_seq.TS_SEQ_UNKNOWN

    def test_id(self):
        pass

    def set_ts_seqclass(self, ts_seqclass):
        pass

    def process(self):
        pass

    def get_final_result(self):
        pass

    def calc_ti(self):
        pass

    def calc_ts(self):
        # 1. If any of the responses have no timestamp option, TS 
        #    is set to U (unsupported).
        # 2. If any of the timestamp values are zero, TS is set to 0.
        # 3. If the average increments per second falls within the 
        #    ranges 0-5.66, 70-150, or 150-350, TS is set to 1, 7, or 8, 
        #    respectively. These three ranges get special treatment 
        #    because they correspond to the 2 Hz, 100 Hz, and 200 Hz 
        #    frequencies used by many hosts.
        # 4. In all other cases, Nmap records the binary logarithm of 
        #    the average increments per second, rounded to the nearest 
        #    integer. Since most hosts use 1,000 Hz frequencies, A is 
        #    a common result.

        pass

    def calc_sp(self):
        pass

class nmap2_ops_container(os_id_test):
    def __init__(self, responses):
        os_id_test.__init__(self, 0)

        self.seq_responses = responses
        self.seq_num_responses = len(responses)

    def test_id(self):
        pass

    def process(self):
        pass

    def get_final_result(self):
        pass

class nmap2_win_container(os_id_test):
    def __init__(self, responses):
        os_id_test.__init__(self, 0)

        self.seq_responses = responses
        self.seq_num_responses = len(responses)

    def test_id(self):
        pass

    def process(self):
        pass

    def get_final_result(self):
        pass

class nmap2_t1_container(os_id_test):
    def __init__(self, responses, seq_base):
        os_id_test.__init__(self, 0)

        self.seq_responses = responses
        self.seq_num_responses = len(responses)
        self.seq_base = seq_base

    def test_id(self):
        pass

    def process(self):
        # R, DF, T*, TG*, W-, S, A, F, O-, RD*, Q
        pass

    def get_final_result(self):
        pass

class nmap2_icmp_container(os_id_test):
    def __init__(self, responses):
        os_id_test.__init__(self, 0)

        self.icmp_responses = responses
        self.icmp_num_responses = len(responses)

    def test_id(self):
        pass

    def process(self):
        # R, DFI, T*, TG*, TOSI, CD, SI, DLI*
        pass

    def get_final_result(self):
        pass

class nmap1_tcp_closed_1(nmap1_tcp_probe):
    def __init__(self, id, addresses, tcp_ports):
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 0)
        self.t.set_SYN()

    def test_id(self):
        pass

    def is_mine(self, packet):
        pass

class nmap2_tcp_closed_1(nmap2_tcp_probe_2_6):
    # ...
    # T5 sends a TCP SYN packet without IP DF and a window field of 
    # 31337 to a closed port
    # ...
    def __init__(self, id, addresses, tcp_ports):
        nmap2_tcp_probe_2_6.__init__(self, id, addresses, tcp_ports, 0)
        self.t.set_SYN()
        self.i.set_ip_df(0)
        self.t.set_th_win(31337)

    def test_id(self):
        pass


class nmap1_tcp_closed_2(nmap1_tcp_probe):

    def __init__(self, id, addresses, tcp_ports):
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 0)
        self.t.set_ACK()

    def test_id(self):
        pass


class nmap2_tcp_closed_2(nmap2_tcp_probe_2_6):
    # ...
    # T6 sends a TCP ACK packet with IP DF and a window field of 
    # 32768 to a closed port.
    # ...
    def __init__(self, id, addresses, tcp_ports):
        nmap2_tcp_probe_2_6.__init__(self, id, addresses, tcp_ports, 0)
        self.t.set_ACK()
        self.i.set_ip_df(1)
        self.t.set_th_win(32768)

    def test_id(self):
        pass


class nmap1_tcp_closed_3(nmap1_tcp_probe):

    def __init__(self, id, addresses, tcp_ports):
        nmap1_tcp_probe.__init__(self, id, addresses, tcp_ports, 0)
        self.t.set_FIN()
        self.t.set_URG()
        self.t.set_PSH()

    def test_id(self):
        pass


class nmap2_tcp_closed_3(nmap2_tcp_probe_7):
    # ...
    # T7 sends a TCP packet with the FIN, PSH, and URG flags set and a 
    # window field of 65535 to a closed port. The IP DF bit is not set.
    # ...
    def __init__(self, id, addresses, tcp_ports):
        nmap2_tcp_probe_7.__init__(self, id, addresses, tcp_ports, 0)
        self.t.set_FIN()
        self.t.set_URG()
        self.t.set_PSH()
        self.t.set_th_win(65535)
        self.i.set_ip_df(0)

    def test_id(self):
        pass


class NMAP2_OS_Class:
    def __init__(self, vendor, name, family, device_type):
        self.__vendor = vendor
        self.__name = name
        self.__family = family
        self.__device_type = device_type

    def get_vendor(self):
        return self.__vendor
    def get_name(self):
        return self.__name
    def get_family(self):
        return self.__family
    def get_device_type(self):
        return self.__device_type

class NMAP2_Fingerprint:
    def __init__(self, id, os_class, tests):
        self.__id = id
        self.__os_class = os_class
        self.__tests = tests

    def get_id(self):
        pass
    def get_os_class(self):
        pass
    def get_tests(self):
        pass

    def __str__(self):
        ret = "FP: [%s]" % self.__id
        ret += "\n vendor: %s" % self.__os_class.get_vendor()
        ret += "\n name: %s" % self.__os_class.get_name()
        ret += "\n family: %s" % self.__os_class.get_family()
        ret += "\n device_type: %s" % self.__os_class.get_device_type()

        for test in self.__tests:
            ret += "\n  test: %s" % test
            for pair in self.__tests[test]:
                ret += "\n   %s = [%s]" % (pair, self.__tests[test][pair])

        return ret

    literal_conv = { "RIPL" : { "G" : 0x148 },
                     "RID" : { "G" : 0x1042 },
                     "RUL" : { "G" : 0x134 } }

    def parse_int(self, field, value):
        try:
            return int(value, 16)
        except ValueError:
            if field in NMAP2_Fingerprint.literal_conv:
                if value in NMAP2_Fingerprint.literal_conv[field]:
                    return NMAP2_Fingerprint.literal_conv[field][value]
            return 0

    def match(self, field, ref, value):
        options = ref.split("|")

        for option in options:
            if option.startswith(">"):
                if self.parse_int(field, value) > \
                   self.parse_int(field, option[1:]):
                    return True
            elif option.startswith("<"):
                if self.parse_int(field, value) < \
                   self.parse_int(field, option[1:]):
                    return True
            elif option.find("-") > -1:
                range = option.split("-")
                if self.parse_int (field, value) >= self.parse_int (field, range[0]) and \
                        self.parse_int (field, value) <= self.parse_int (field, range[1]):
                    return True
            else:
                if str(value) == str(option):
                    return True

        return False

    def compare(self, sample, mp):
        pass

class NMAP2_Fingerprint_Matcher:
    def __init__(self, filename):
        self.__filename = filename                

    def find_matches(self, res, threshold):
        pass

    def sections(self, infile, token):
        OUT = 0
        IN = 1
        
        state = OUT
        output = []

        for line in infile:
            line = line.strip()
            if state == OUT:
                if line.startswith(token):
                    state = IN
                    output = [line]
            elif state == IN:
                if line:
                    output.append(line)
                else:
                    state = OUT
                    yield output
                    output = []

        if output:
            yield output

    def fingerprints(self, infile):
        pass

    def matchpoints(self, infile):
        pass

    def parse_line(self, line):
        pass

    def parse_fp(self, fp):
        pass
            
    def parse_mp(self, fp):
        pass
