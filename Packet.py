import socket
import struct

class Packet():

    # General Data

    global_protocol = "Un-Known"
    last_global_proto = ""
    source = ""
    destination = ""
    packet_len = 0
    time = ""

    # Ethernet Attributes

    src_mac = ""
    dst_mac = ""
    type = 0
    data_type = ""

    #-----------------------------


    # Arp Attributes

    hw_type = 0
    protocol_type = 0
    hw_addr_len = 0
    protcol_addr_len = 0
    operation = 0
    arp_src_mac = ""
    arp_src_ip = ""
    arp_dst_mac = ""
    arp_dst_ip = ""

    #----------------------------

    # ICMP Attributes

    icmp_type = 0
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = 0
    icmp_seq = 0
    icmp_data = ""
    icmp_type_string = ""


    #--------------------------------


    # IP Attributes

    version = 0
    ihl = 0  # header length
    tos = ""
    dsc = ""
    total_length = 0 # size of datagram ( header + data )
    id = 0

    ip_flags = 0
    ip_flags_type = ""
    dont_fragment = 0
    more_fragment = 0

    fragment_offset = 0
    ttl = 0
    ip_protocol_code = 0
    ip_protocol = ""
    checksum = ""
    src_ip = ""
    dst_ip = ""

    #--------------------------------

    #Trasport Layer Attributes

    src_port = 0
    dst_port = 0

    # TCP Attributes

    seq_num = 0
    ack_num = 0
    tcp_hdr_len = 0
    reserved = 0
    code_bits = 0
    tcp_flags_type = ""
    window = 0
    tcp_checksum = ""
    urgent = 0


    # UDP Attributes

    udp_len = 0   # length of datagram ( header + data )
    udp_checksum = ""


    # Application Attributes

    payload = ""
    unpacked_payload = ""

    request = False
    respond = False

    # HTTP


    http_header = ""
    http_header_var = ""


    # SSL

    ssl_type = 0
    ssl_version = 0
    ssl_length = 0

    # FTP

    ftp_data = ""



    # General Function


    def __init__(self,packet):
        self.packet = packet



    def get_global_protocol(self):
        return self.global_protocol


    def get_packet_len(self):
        return self.packet_len


    def get_source(self):
        return self.source

    def get_destination(self):
        return self.destination

    def set_time(self,time):
        self.time = time

    def get_time(self):
        return self.time

    def get_last_global_protocol(self):
        return self.last_global_proto

    # Ethernet Functions

    def set_src_mac(self,mac):
        self.src_mac = mac

    def set_dst_mac(self,mac):
        self.dst_mac = mac

    def set_eth_type(self,type):
        self.type = type
        if (type == 8):
            self.data_type = "IP"
        elif (type==1544):
            self.data_type = "ARP"
            self.global_protocol = "ARP"
            self.packet_len += 28




    def get_src_mac(self):
        return self.src_mac

    def get_dst_mac(self):
        return self.dst_mac

    def get_eth_type(self):
        return self.type

    def get_eth_data_type(self):
        return self.data_type

    def parse_ether(self,header):

        self.set_eth_type(socket.ntohs(header[2]))

        dst_mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
            ord(header[0][0]), ord(header[0][1]), ord(header[0][2]), ord(header[0][3]), ord(header[0][4]),
            ord(header[0][5]))
        self.destination = dst_mac
        self.set_dst_mac(dst_mac)

        src_mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
            ord(header[1][0]), ord(header[1][1]), ord(header[1][2]), ord(header[1][3]), ord(header[1][4]),
            ord(header[1][5]))
        self.source = src_mac
        self.set_src_mac(src_mac)

        self.packet_len = 14

    #------------------------------------


    # ARP Functions


    def set_hw_type(self,type):
        self.hw_type = type

    def get_hw_type(self):
        return self.hw_type

    def set_protocol_type(self,type):
        self.protocol_type = type

    def get_protocol_type(self):
        return self.protocol_type

    def set_hw_addr_len(self,len):
        self.hw_addr_len = len

    def get_hw_addr_len(self):
        return self.hw_addr_len

    def set_protocol_addr_len(self,len):
        self.protcol_addr_len = len

    def get_protocol_addr_len(self):
        return self.protcol_addr_len

    def set_operation(self,op):
        self.operation = op

    def get_operation(self):
        return self.operation

    def set_arp_src_mac(self,mac):
        self.arp_src_mac = mac

    def get_arp_src_mac(self):
        return self.arp_src_mac

    def set_arp_src_ip(self,ip):
        self.arp_src_ip = ip

    def get_arp_src_ip(self):
        return self.arp_src_ip

    def set_arp_dst_mac(self,mac):
        self.arp_dst_mac = mac

    def get_arp_dst_mac(self):
        return self.arp_dst_mac

    def set_arp_dst_ip(self,ip):
        self.arp_dst_ip = ip

    def get_arp_dst_ip(self):
        return self.arp_dst_ip


    #----------------------------------------------


    # ICMP Functions :


    def get_icmp_type_string(self):
        return self.icmp_type_string

    def get_icmp_type(self):
        return self.icmp_type

    def get_icmp_code(self):
        return self.icmp_code

    def get_icmp_checksum(self):
        return self.icmp_checksum

    def get_icmp_id(self):
        return self.icmp_id

    def get_icmp_seq(self):
        return self.icmp_seq

    def get_icmp_data(self):
        return self.icmp_data


    def parse_icmp(self,icmp_header):

        self.icmp_type = icmp_header[0]
        if (self.icmp_type == 8):
            self.icmp_type_string = "Ping Request"

        elif (self.icmp_type == 0):
            self.icmp_type_string = "Ping Reply"




        elif (self.icmp_type == 30):
            self.icmp_type_string = "Traceroute"

        self.icmp_code = icmp_header[1]
        self.icmp_checksum = socket.ntohs(icmp_header[2])
        self.icmp_id = icmp_header[3]
        self.icmp_seq = icmp_header[4]
        self.icmp_data = "%s"%(icmp_header[5])






    #-----------------------------------------------


    #IP Functions



    def set_ip_version(self,version):
        self.version = version

    def set_ip_ihl(self,ihl):
        self.ihl = ihl

    def set_ip_tos(self,tos):
        self.tos = tos

    def set_total_length(self,tl):
        self.total_length = tl

    def set_ip_id(self,id):
        self.id = id

    def set_ip_flags(self,flags):
        self.ip_flags = flags

    def set_ip_offset(self,offset):
        self.fragment_offset = offset

    def set_ttl(self,ttl):
        self.ttl = ttl

    def set_ip_protocol(self,protocol):
        self.ip_protocol_code = protocol
        if (protocol == 6):
            self.ip_protocol = "TCP"
            self.global_protocol = "TCP"
            self.last_global_proto = "TCP"
        elif (protocol == 17):
            self.ip_protocol = "UDP"
            self.global_protocol = "UDP"
            self.last_global_proto = "UDP"

        elif (protocol == 2):
            self.global_protocol = "IGMP"
            self.ip_protocol = "ICMP"

        elif (protocol == 1):
            self.global_protocol = "ICMP"
            self.ip_protocol = "ICMP"



    def get_ip_protocol_code(self):
        return self.ip_protocol_code

    def set_ip_checksum(self,checksum):
        self.checksum = checksum

    def set_src_ip(self,ip):
        self.src_ip = ip

    def set_dst_ip(self,ip):
        self.dst_ip = ip

    def get_ip_version(self):
        return self.version

    def get_ip_ihl(self):
        return self.ihl

    def get_ip_tos(self):
        return self.tos

    def get_total_length(self):
        return self.total_length

    def get_ip_id(self):
        return self.id

    def get_ip_flags(self):
        return self.ip_flags

    def get_ip_flags_type(self):
        return self.ip_flags_type

    def get_ip_offset(self):
        return self.fragment_offset

    def get_ttl(self):
        return self.ttl

    def get_ip_protocol(self):
        return self.ip_protocol

    def get_ip_checksum(self):
        return self.checksum

    def get_src_ip(self):
        return self.src_ip

    def get_dst_ip(self):
        return self.dst_ip

    def parse_ip(self,header):

        version_ihl = header[0]
        version = version_ihl >> 4
        self.set_ip_version(version)
        ihl = (version_ihl & 0xF) * 4

        self.set_ip_ihl(ihl)

        tos = header[1]
        self.set_ip_tos(hex(tos))

        total_length = (int)(header[2])
        self.set_total_length(total_length)
        self.packet_len  += total_length

        id = header[3]
        self.set_ip_id(id)

        fragment_flags = header[4]

        flags = fragment_flags >> 13
        if(flags==0):
            self.ip_flags_type = "No Flags"

        elif(flags == 1):
            self.ip_flags_type = " Set Flag : Reserved bit "

        elif (flags == 2):
            self.ip_flags_type = "Set Flag : Don't fragment"
        elif(flags == 3):
            self.ip_flags_type = "Set Flag : More Fragments"

        self.set_ip_flags(hex(flags))

        self.fragment_offset = str(fragment_flags & 0x1FFF)




        ttl = header[5]
        self.set_ttl(ttl)

        protocol = header[6]
        self.set_ip_protocol(protocol)

        checksum = header[7]
        self.set_ip_checksum(hex(checksum))

        src_ip_ = header[8]
        src_ip = socket.inet_ntoa(src_ip_)

        self.source = src_ip
        self.set_src_ip(src_ip)

        dst_ip_ = header[9]
        dst_ip = socket.inet_ntoa(dst_ip_)

        self.destination = dst_ip
        self.set_dst_ip(dst_ip)


#------------------------------------------------


    # Trasport Layer Functions


    def set_src_port(self,port):
        self.src_port = port

    def set_dst_port(self,port):
        self.dst_port = port

    def get_src_port(self):
        return self.src_port

    def get_dst_port(self):
        return self.dst_port

    # TCP Functions


    def set_seq_num(self,seq):
        self.seq_num = seq

    def set_ack_num(self,ack):
        self.ack_num = ack

    def set_tcp_window(self,windowing):
        self.window = windowing

    def set_tcp_checksum(self,checksum):
        self.tcp_checksum = checksum

    def set_tcp_urgent(self,urgent):
        self.urgent = urgent

    def set_tcp_hdr_len(self,len):
        self.tcp_hdr_len = len

    def set_tcp_reserved(self,reserved):
        self.reserved = reserved

    def set_flags(self,bits):
        self.code_bits = bits

    def get_seq_num(self):
        return self.seq_num

    def get_ack_num(self):
        return self.ack_num

    def get_tcp_window(self):
        return self.window

    def get_tcp_checksum(self):
        return self.tcp_checksum

    def get_tcp_urgent(self):
        return self.urgent

    def get_tcp_hdr_len(self):
        return self.tcp_hdr_len

    def get_tcp_reserved(self):
        return self.reserved

    def get_flags(self):
        return self.code_bits

    def get_tcp_window(self):
        return self.window

    def get_tcp_urgent(self):
        return self.urgent

    def get_tcp_flags_type(self):
        return  self.tcp_flags_type

    def parse_tcp(self,tcp_header):



        src_port = tcp_header[0]


        self.set_src_port(src_port)

        dst_port = tcp_header[1]

        self.set_dst_port(dst_port)

        seq = tcp_header[2]
        self.set_seq_num(seq)

        ack = tcp_header[3]
        self.set_ack_num(ack)

        hdr_reserved_flags = tcp_header[4]

        hdr_len = hdr_reserved_flags >> 12

        reserved_flags = hdr_reserved_flags & 0xFFF

        reserved = reserved_flags >> 9

        flags = reserved_flags & 0x1FF

        if (flags == 1):
            self.tcp_flags_type = "FIN"

        elif(flags == 2):
            self.tcp_flags_type = "SYN"

        elif(flags == 4):
            self.tcp_flags_type = "RST"

        elif(flags == 8):
            self.tcp_flags_type = "PSH"

        elif(flags == 16):
            self.tcp_flags_type = "ACK"

        elif (flags == 17):
            self.tcp_flags_type = "ACK-FIN"

        elif (flags == 18):
            self.tcp_flags_type = "SYN-ACK"

        elif (flags == 24):
            self.tcp_flags_type = "ACK-PSH"


        self.set_tcp_hdr_len(hdr_len*4)
        self.set_tcp_reserved(reserved)
        self.set_flags(hex(flags))

        window = tcp_header[5]
        self.window = window

        checksum = tcp_header[6]
        self.set_tcp_checksum(hex(checksum))



        urgent = tcp_header[7]
        self.urgent = urgent






    # UDP Functions


    def set_udp_length(self,len):
        self.udp_len = len


    def set_udp_checksum(self,checksum):
        self.udp_checksum = checksum

    def get_udp_length(self):
        return self.udp_len

    def get_udp_checksum(self):
        return self.udp_checksum


    def parse_udp(self,udp_header):



        src_port = udp_header[0]
        self.set_src_port(src_port)
        dst_port = udp_header[1]
        self.set_dst_port(dst_port)
        len = udp_header[2]
        self.set_udp_length(len)
        checksum = udp_header[3]
        self.set_udp_checksum(hex(checksum))



    # Applications Functions


    def set_payload(self,payload):
        self.payload = payload

    def get_payload(self):
        return self.payload

    def set_unpacked_payload(self,payload):
        self.unpacked_payload = payload


    def get_unpacked_payload(self):
        return self.unpacked_payload

    def get_http_header(self):
        return self.http_header_var

    def get_ssl_type(self):
        return self.ssl_type

    def get_ssl_version(self):
        return self.ssl_version

    def get_ssl_length(self):
        return self.ssl_length

    def get_ftp_data(self):
        return self.ftp_data

    def parse_payload(self,payload):
        self.unpacked_payload = payload

        src_port = self.src_port
        dst_port = self.dst_port

        if (src_port == 80 or dst_port == 80):
            self.parse_http()

        if (src_port == 53 or dst_port == 53):
            self.global_protocol = "DNS"

        if (src_port == 123 or dst_port == 123):
            self.global_protocol = "NTP"

        if (src_port == 5353 or dst_port == 5353):
            self.global_protocol = "MDNS"

        if (src_port == 21 or dst_port == 21):
            self.parse_ftp()






    #  IF HTTP

    def parse_http(self):


        header = self.payload
        new_header = ""
        final = ""
        if "HTTP" in header:     # HEARISTIC DISSECTION  : SEARCHING IN PAYLOAD FOR PROTOCOL SPECIFICATION TO DETERMINE PROTOCOL
            self.global_protocol = "HTTP"
            self.http_header_var = header


    def parse_ftp(self):
        header = self.payload
        if("FTP" in header or "USER" in header or "PASS" in header or "Please" in header or "Quit" in header or "Goodbye" in header or "Login" in header or "SYST" in header ):

            # HEARISTIC DISSECTION  : SEARCHING IN PAYLOAD FOR PROTOCOL SPECIFICATION TO DETERMINE PROTOCOL

            self.global_protocol = "FTP"

            if("221" in header):
                self.ftp_data = "Service Closing ( Goodbye ) ( 221 )"

            if("530" in header):
                self.ftp_data = "Not Logged In ( 530 ) "

            if("220" in header):
                self.ftp_data = "Service Ready ( 220 ) "

            if ("230" in header):
                self.ftp_data = "Login Successful ( 230 ) "










    # Remianing in Packet.py :




    #                 PROTOCOLS (ICMP , ARP ) at Least Main Protocol

    #                 executin program , on linux & windows




















