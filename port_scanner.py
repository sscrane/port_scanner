#! /usr/bin/env python

import random
import socket
import sys
import time
from datetime import datetime
import scapy.all
from scapy.layers.inet import ICMP, IP, TCP

"""Check whether an IP address is alive (e.g., 127.0.0.1)"""


def check_IP_Alive(IPAddr):
    print("Checking if IP is alive...")
    if IPAddr == "127.0.0.1":
        print("Working on local machine")
        return True

    try:  # Try to connect to given IP
        p = IP(dst=IPAddr) / ICMP()  # create ping
        reply = scapy.all.sr1(p)  # Send ping and wait for response
        if reply is None:  # If IP doesn't respond, assume not alive
            return False

        print("IP is alive ... continuing probe")
        return True

    except Exception as error:  # Catch error
        print("Ending probe because of error: %s" % error)
        return False


""""• Probe(Scan) an IP address for a given set of ports using any of the following scanning
modes:
    o Normal Port Scanning (full TCP connect to the remote IP address)
        § When this mode is requested, you should also grab the banner sent by the server
    o TCP SYN Scanning (only send the initial SYN Packet and then send RST when client responds
        with SYN|ACK)
    o TCP FIN Scanning

"""""

def probe(IPAddr, type, num):  # Normal Port Scanning
    if type == "random":
        list_of_numbers = list(range(1, int(num)))
        random.shuffle(list_of_numbers)
    else:  # Either give numbers in order or randomly
        list_of_numbers = range(1, int(num))  # 65535

    open_ports = 0
    open_ports_info = []
    closed_ports = 0

    today = datetime.now()  # Printing the date and time that the scan starts
    print("Starting port scan on ", IPAddr, " at ", today.strftime("%Y-%m-%d %I:%M:%S"))

    start_time = time.time()  # Start timer on probe
    for i in list_of_numbers:  # Uses full TCP connection, need to grab banner
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((IPAddr, i))  # connect to IP with specific port

            message = "GET /text HTTP/2.0\r\n\r\n".encode()#Send message to get banner
            s.send(message)
            banner = s.recv(1024)
            try:
                service = socket.getservbyport(i)  # get protocol
            except:
                service = "Service Unknown"
            open_ports_info.append(("%d     open    %s   %s" % (i, service, banner)))
            open_ports += 1
            s.close()

        except socket.error as err: #If we can't connect, port is closed
            closed_ports += 1
            s.close()
        except KeyboardInterrupt:
            print("Keyboard Interrupt...Printing already checked ports.")
        except Exception as e:
            print(e)

    end_time = time.time()
    overall_time = end_time - start_time

    print("Open ports found: ", open_ports)
    print("PORT    STATE    SERVICE   BANNER")
    for x in open_ports_info:
        print(x)
    print("\nNot Shown: %i closed ports" % closed_ports)
    pass

    print("Scan done on ", IPAddr, " in ", str(overall_time)[:6], " seconds")


""""• Any of the above host/port scanning methods must also be able to be done sequentially or in random order
    o Probe all 216 TCP ports on a targeted host
    o Scan the ports in order (i.e., from 0 to 65,535)
    o Scan in random order (e.g., instead of first scanning port 1, then port 2, then port 3, etc., 
        randomize the order of ports)
"""

"""• For each open port, port scanner should report both the port number and the service
that normally runs on that port
    o The service can be found by using the getservbyport() and socket.getservbyport() calls in C and 
        Python respectively
    o Report how long it took to conduct the command
    o Report the number of ports that were found to be closed/open
"""


def main():
    #addr = "127.0.0.1"  # Try on 131.229.72.71 for Smith Science Page
    #num = 1000
    #type = "sequential"

    addr = sys.argv[1]
    type = sys.argv[2]
    num = sys.argv[3]


    IP_Alive = check_IP_Alive(addr)
    if IP_Alive is False:
        return

    probe(addr, type, num)


if __name__ == '__main__':
    main()
