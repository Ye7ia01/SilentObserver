import pcapy
from struct import unpack
import socket
from Packet import Packet
import threading
import time





# Functions


# find network interfaces on device

def find_devs():
    devices = pcapy.findalldevs()
    return devices


#- ----------------------------------------------------

# sniff on chosen interface


def save(device,file_name):
    session = pcapy.open_live(device,65536,1,0)

    name = str(file_name) + ".pcap"

    saver = session.dump_open(name)

    for i in range(0, len(pckts)):
        saver.dump(hdrs[i], pckts[i])


def sniff(device):
    session = pcapy.open_live(device, 65536, 1, 0)

    #session.setfilter("")

    for i in packets:
        del(i)
    counter = 0

    while (not stop):

        (header, packet) = session.next()

        hdrs.append(header)      # HEADERS CAPTURED IN PCAP FORMAT
        pckts.append(packet)     # PACKETS CAPTURED IN PCAP FORMAT

        # HDRS & PCKTS  USED IN ORDER TO SAVE CAPTURED PACKETS IN PCAP FORMAT
        packets.append(Packet(packet))
        localtime = time.asctime(time.localtime(time.time()))     # TIME THE PACKET WAS CAPTURED
        packets[counter].set_time(localtime)

        eth_length = 14
        ip_length = 20
        tcp_length = 20
        udp_length = 8
        icmp_length = 12

        eth_header = packet[:eth_length]

        eth = unpack('!6s6sH', eth_header)  #  UNPACK : Convert Packet Binaries Into Mentioned Data Types In Arguments
        packets[counter].parse_ether(eth)


        ip = packet[eth_length: eth_length + 20]
        ip_header = unpack('!BBHHHBBH4s4s', ip)
        if (packets[counter].get_eth_data_type() == "IP"):
            packets[counter].parse_ip(ip_header)




        if (packets[counter].get_ip_protocol_code() == 6):
            tcp = packet[eth_length + ip_length: eth_length + ip_length + tcp_length]
            tcp_header = unpack('!HHLLHHHH', tcp)
            packets[counter].parse_tcp(tcp_header)

        elif (packets[counter].get_ip_protocol_code() == 17):
            udp = packet[eth_length + ip_length: eth_length + ip_length + udp_length]
            udp_header = unpack('!HHHH  ', udp)
            packets[counter].parse_udp(udp_header)


        elif (packets[counter].get_ip_protocol_code() == 1):


            packed_hdr = packet[eth_length + ip_length : eth_length + ip_length + icmp_length]
            icmp_header = unpack('BBHHH 4s',packed_hdr)

            packets[counter].parse_icmp(icmp_header)


        data = packet[eth_length + ip_length + udp_length: len(packet) - 1]


        length = len((data))
        string = '!' + str(length) + 's'

        payload = unpack(string,data)

        packets[counter].set_payload(data)
        packets[counter].set_unpacked_payload(payload)

        packets[counter].parse_payload(payload)

        counter += 1



#-----------------------------------------------------------------------------------

# hexdump function


def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c + length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length * 3, hex, printable))
    return ''.join(lines)


#-------------------------------------------------------------------------------------



# cature Thread


def capture(device):



    t1 = threading.Thread(target=sniff, args=(device,))
    t1.start()

def get_packet(count):


    info = []
    if (len(packets) > count):

        info.append(packets[count].get_time())   # 0

        number = str(count+1)
        info.append(number)   # 1

        src_ip = str(packets[count].get_source())
        info.append(src_ip) # 2

        dst_ip = str(packets[count].get_destination())
        info.append(dst_ip) # 3

        global_protocol = str(packets[count].get_global_protocol())
        info.append(global_protocol) # 4

        packet_len = str(packets[count].get_packet_len()) + "( bytes )"
        info.append(packet_len) # 5

        info.append(packets[count].get_last_global_protocol())   # 6

        eth_type = str(packets[count].get_eth_type()) + " ( " + str(
            packets[count].get_eth_data_type()) + " )"

        #print eth_type
        info.append(eth_type) # 7
        dst_mac =str(packets[count].get_dst_mac())
        #print dst_mac
        info.append(dst_mac) # 8
        src_mac = str(packets[count].get_src_mac())
        #print src_mac
        info.append(src_mac) # 9

        if (packets[count].get_eth_type() == 8):  ### IF IP
            version = str(packets[count].get_ip_version()) + "( IPv)" + str(packets[count].get_ip_version())
            #print version
            info.append(version) # 10
            hdr_len =str(packets[count].get_ip_ihl()) + "( bytes )"
            #print hdr_len
            info.append(hdr_len) # 11
            total_len = str(packets[count].get_total_length()) + "( bytes )"
            #print total_len
            info.append(total_len) # 12
            id = str(packets[count].get_ip_id())
            #print id
            info.append(id) # 13
            ttl = str(packets[count].get_ttl()) + "( seconds )"
            info.append(str(packets[count].get_ip_flags())+ " ( " + str(packets[count].get_ip_flags_type()) + " ) ") # 14
            info.append(packets[count].get_ip_offset()) # 15
            #print ttl
            info.append(ttl) # 16
            protocol = str(packets[count].get_ip_protocol_code()) + " ( " + str(
                packets[count].get_ip_protocol()) + " ) "
            #print protocol
            info.append(protocol) # 17
            src_ip = str(packets[count].get_src_ip())
            #print src_ip
            info.append(src_ip) # 18
            dst_ip =  str(packets[count].get_dst_ip())
            #print dst_ip
            info.append(dst_ip) # 19
            checksum = str(packets[count].get_ip_checksum())
            #print checksum
            info.append(checksum) # 20
            tos = str(packets[count].get_ip_tos())
            #print tos
            info.append(tos) # 21

            # ------ IP

        if (packets[count].get_ip_protocol_code() == 17):   # IF UDP
            src_port = str(packets[count].get_src_port())
            #print src_port
            info.append(src_port)  # 22
            dst_port =  str(packets[count].get_dst_port())
            #print dst_port
            info.append(dst_port) # 23
            length = str(packets[count].get_udp_length()) + "( bytes )"
            #print length
            info.append(length) # 24
            checksum =str(packets[count].get_udp_checksum())
            #print checksum
            info.append(checksum) # 25

        elif (packets[count].get_ip_protocol_code() == 6):  ## IF TCP
            src_port = str(packets[count].get_src_port())
            #print src_port
            info.append(src_port) # 22
            dst_port =  str(packets[count].get_dst_port())
            #print dst_port
            info.append(dst_port) # 23
            seq =  str(packets[count].get_seq_num())
            #print seq
            info.append(seq) # 24
            ack =  str(packets[count].get_ack_num())
            #print ack
            info.append(ack) # 25
            checksum =  str(packets[count].get_tcp_checksum())
            #print checksum
            info.append(checksum) # 26
            hdr_len =  str(packets[count].get_tcp_hdr_len()) + "( bytes )"
            #print hdr_len
            info.append(hdr_len) # 27
            reserved =  str(packets[count].get_tcp_reserved())
            #print reserved
            info.append(reserved) # 28
            flags = str(packets[count].get_flags())
            #print flags
            info.append(str(flags) + " ( "  + str(packets[count].get_tcp_flags_type()) + " ) " ) # 29
            info.append(packets[count].get_tcp_window())   # 30
            info.append(packets[count].get_tcp_urgent())   # 31

            # print " Gloabal Protocol : " + packets[count].get_global_protocol()



        elif (packets[count].get_ip_protocol_code() == 1):  #ICMP

            info.append(packets[count].get_icmp_type())    #22
            info.append(packets[count].get_icmp_code())    # 23
            info.append(hex(packets[count].get_icmp_checksum())) #24
            info.append(hex(packets[count].get_icmp_id())) #25
            info.append(packets[count].get_icmp_seq())  # 26
            info.append(packets[count].get_icmp_type_string())  #27









        data = str(hexdump(packets[count].get_payload()))
        #print data
        info.append(data) # IF TCP ( 31) , IF UDP (25 )


        if (packets[count].get_global_protocol() == "HTTP"):
            http =  "" + str((packets[count].get_unpacked_payload()))
            #print http
            info.append(http) # 32

        elif (packets[count].get_global_protocol() == "FTP" ):
            info.append(packets[count].get_ftp_data())

        info.append(packets[count].get_payload())    # 36 if tls , 33 if http ,  , 26 if udp






        return info

    else :

        return info






# GLobal Variables Initialization



packets = []  # array of Packet object

stop = False  # stop flag ( to stop capturing

#save = False

hdrs = []
pckts = []










