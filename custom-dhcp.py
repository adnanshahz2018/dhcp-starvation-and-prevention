# python imports
import datetime
from threading import Thread
from scapy.all import *
from scapy.all import ARP, Ether, DHCP
from time import sleep


INTERFACE = "eth0"
MY_MAC_ADDRESS = get_if_hwaddr(INTERFACE)
MY_IP_ADDRESS = get_if_addr(INTERFACE)

#iplist = ['192.168.122.10','192.168.122.20','192.168.122.30','192.168.122.40','192.168.122.50']
index = 0
iplist  = []
reg_mac_ip      = {}
blacklist_mac   = []

for i in range(2,250):
    iplist.append('192.168.122.'+str(i))

def validate_IP_availability(index):
    response = Ether()/ARP()

    response[Ether].dst = 'FF:FF:FF:FF:FF:FF'
    response[Ether].src = MY_MAC_ADDRESS

    response[ARP].op = 1
    response[ARP].hwsrc = MY_MAC_ADDRESS
    response[ARP].hwdst = '00:00:00:00:00:00'
    response[ARP].psrc  = MY_IP_ADDRESS
    response[ARP].pdst  = iplist[index]

    sendp(response, verbose=0)
    print(response, '\n')

class ARPSpoofer(AnsweringMachine):
    def is_request(self, request):
        sleep(1)
        try:
            request.haslayer('ARP') and request[ARP].op == 2 and request[ARP].pdst == MY_IP_ADDRESS
            if request[ARP].hwsrc in blacklist_mac:
                print('BLACLISTED MAC : ' + request[ARP].hwsrc )
                sleep(1)
                return
            try:
                if reg_mac_ip[request[ARP].hwsrc] != request[ARP].psrc:
                    print('=> Assigned IP   = ', reg_mac_ip[request[ARP].hwsrc])
                    print('=> Claimed IP    = ', request[ARP].psrc)
                    print('BLACKLISTING THE MAC ADDRESS \t *** ' + request[ARP].hwsrc + ' *** \n')
                    blacklist_mac.append(request[ARP].hwsrc)
                    sleep(3)
            except:
                reg_mac_ip[request[ARP].hwsrc] =  request[ARP].psrc
                print('Registering Connection for MAC-IP Pair \t ', request[ARP].hwsrc, ' : ', request[ARP].psrc)
                global index
                if request[ARP].psrc == iplist[index]:
                    index = index + 1
                sleep(2)
        except:
            pass

print('\n\tSIMULATING PROPOSED SOLUTION IN A CUSTOM PYTHON DHCP \n')

arp_spoofer = Thread(target=ARPSpoofer())
arp_spoofer.start()

def handle_dhcp_packet(packet):
    if DHCP in packet and packet[DHCP].options[0][1] == 1:
        # hostname = get_option(packet[DHCP].options, 'hostname')
        print(f"Client with MAC Address ({packet[Ether].src}) is sending DHCP DISCOVER")

        global index
        sleep(0.1)
        validate_IP_availability(index)

sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)

