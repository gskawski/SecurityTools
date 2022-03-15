#!/usr/bin/python3

import scapy.all as scapy
from scapy import *
from struct import *
import argparse
import threading

#flag = 0
def ArpPingSpoof(pkt):
    #global flag
    l1_victim_send = scapy.Ether(dst = pkt.src, src = args.victimethernet)
    l1_reflector_send = scapy.Ether(dst = pkt.src, src = args.reflectorethernet)

    if (pkt.haslayer(scapy.ARP) == True):
        if(pkt.getlayer(scapy.ARP).pdst == args.victimip):
            print('victim arp\n')       
            arp_reply = l1_victim_send / scapy.ARP(hwdst = pkt.hwsrc, hwsrc = args.victimethernet, op = 2, pdst = pkt.psrc, psrc = pkt.pdst)
            scapy.sendp(arp_reply, verbose=True, iface=args.interface)
        else:
            print('reflector arp\n')       
            arp_reply = l1_reflector_send / scapy.ARP(hwdst = pkt.hwsrc, hwsrc = args.reflectorethernet, op = 2, pdst = pkt.psrc, psrc = pkt.pdst)
            scapy.sendp(arp_reply, verbose=True, iface=args.interface)          

    if(pkt.haslayer(scapy.ICMP) == True and pkt.haslayer(scapy.TCP) == False):
        print("ping")
        if (pkt.getlayer(scapy.IP).dst == args.victimip):
            print("hello")
            pkt[scapy.Ether].dst, pkt[scapy.Ether].src = pkt.getlayer(scapy.Ether).src, args.reflectorethernet
            pkt[scapy.IP].dst, pkt[scapy.IP].src = pkt.getlayer(scapy.IP).src, args.reflectorip
            del pkt[scapy.IP].chksum
            #pkt.show2()
            scapy.sendp(pkt, verbose=True, iface=args.interface, return_packets = True)
            return
        if (pkt.getlayer(scapy.IP).dst == args.reflectorip):
            pkt[scapy.Ether].dst, pkt[scapy.Ether].src = pkt.getlayer(scapy.Ether).src, args.reflectorethernet
            pkt[scapy.IP].dst, pkt[scapy.IP].src = pkt.getlayer(scapy.IP).src, args.victimip
            del pkt[scapy.IP].chksum
            #pkt.show2()
            scapy.sendp(pkt, verbose=True, iface=args.interface)
            return

def tcpSpoof(pkt):
    #global flag
    atk_eth_dst = pkt.getlayer(scapy.Ether).src
    if (pkt.haslayer(scapy.TCP) == True):
        print("tcp")
        pkt[scapy.Ether].dst, pkt[scapy.Ether].src = atk_eth_dst, args.reflectorethernet
        pkt[scapy.IP].dst, pkt[scapy.IP].src = pkt.getlayer(scapy.IP).src, args.reflectorip
        del pkt[scapy.IP].chksum
        del pkt[scapy.TCP].chksum
        synack = scapy.srp1(pkt, verbose=True, iface=args.interface)[0][1] #no matter what it stops here because of arp issues        
        synack = scapy.Ether(dst = atk_eth_dst, src = args.reflectorethernet) / synack
        synack[scapy.IP].dst, synack[scapy.IP].src = synack.getlayer(scapy.IP).src, args.victimip
        del synack[scapy.IP].chksum
        del synack[scapy.TCP].chksum
        ack = scapy.srp1(synack, verbose=True, iface=args.interface)[0][1]
        ack = scapy.Ether(dst = atk_eth_dst, src = args.reflectorethernet) / ack
        ack[scapy.IP].dst, ack[scapy.IP].src = ack.getlayer(scapy.IP).src, args.reflectorip
        del ack[scapy.IP].chksum
        del ack[scapy.TCP].chksum
        scapy.sendp(ack, verbose=True, iface=args.interface)
def udpSpoof(pkt):
    if (pkt.haslayer(scapy.UDP) == True and pkt.haslayer(scapy.ICMP) == False and pkt.haslayer(scapy.IPv6) == False): # slack mentioned to filter IPv6
        print("incoming udp")
        #1->3 & 4 -> 1
        pkt[scapy.Ether].dst, pkt[scapy.Ether].src = pkt.getlayer(scapy.Ether).src, args.reflectorethernet #atk_eth_dst
        pkt[scapy.IP].dst, pkt[scapy.IP].src = pkt.getlayer(scapy.IP).src, args.reflectorip
        #pkt[scapy.UDP].sport, pkt[scapy.UDP].dport = pkt.getlayer(scapy.UDP).dport, pkt.getlayer(scapy.UDP).sport
        del pkt[scapy.IP].chksum
        del pkt[scapy.UDP].chksum
        #flag = 1
        synack = scapy.srp1(pkt, filter ="not icmp", verbose=True, iface=args.interface)[0] #
        print("1-> 4 udp")
        print(synack.show())
        # 1-> 4 and 3 -> 1 which is hello? sends a FUCKING ICMP not UDP so I never respond back with UDP only ICMP, I get stuck trying to send UDP from 4 to1 
        synack[scapy.Ether].dst, synack[scapy.Ether].src = synack.getlayer(scapy.Ether).src, args.reflectorethernet
        synack[scapy.IP].dst, synack[scapy.IP].src = synack.getlayer(scapy.IP).src, args.victimip
        #synack[scapy.UDP].sport, synack[scapy.UDP].dport = synack.getlayer(scapy.UDP).dport, synack.getlayer(scapy.UDP).sport
        del synack[scapy.IP].chksum
        del synack[scapy.UDP].chksum # this is a problem says there is no UDP layer
        #ack = scapy.srp1(synack, verbose=True, iface=args.interface)[0][1]
        print("3->1 udp")
        print(synack.show())
        scapy.sendp(synack, filter ="not icmp", verbose=True, iface=args.interface)
        """ack = scapy.srp1(synack, filter ="not icmp", verbose=True, iface=args.interface)
        #flag = 0
        print("done0")
        ack[scapy.Ether].dst, ack[scapy.Ether].src = ack.getlayer(scapy.Ether).src, args.reflectorethernet
        ack[scapy.IP].dst, ack[scapy.IP].src = ack.getlayer(scapy.IP).src, args.reflectorip
        del ack[scapy.IP].chksum
        del ack[scapy.UDP].chksum
        scapy.sendp(ack, verbose=True, iface=args.interface)
        print("done1")"""

def arp_sniff():
    try:
        filter = "((arp or icmp) and (dst host {} or dst host {} or ether dst host ff:ff:ff:ff:ff:ff))".format(args.victimip, args.reflectorip)
        while(True):
            scapy.sniff(iface=args.interface, filter = filter, prn=ArpPingSpoof, store=0) # 
    except KeyboardInterrupt:
        exit(0)

def tcp_sniff():
    try:
        filter = "(tcp and dst host {})".format(args.victimip)
        #while(True):
        scapy.sniff(iface=args.interface, filter = filter, prn=tcpSpoof, store=0) # 
    except KeyboardInterrupt:
        exit(0)

def udp_sniff():
    try:
        filter = "(udp and not icmp and dst host {})".format(args.victimip)
        #while(True):
        scapy.sniff(iface=args.interface, filter = filter, prn=udpSpoof, store=0) # 
    except KeyboardInterrupt:
        exit(0)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", dest = "interface", action="store")
    parser.add_argument("--victim-ip", dest = "victimip", action="store")
    parser.add_argument("--victim-ethernet", dest = "victimethernet", action="store")
    parser.add_argument("--reflector-ip", dest = "reflectorip", action="store")
    parser.add_argument("--reflector-ethernet", dest = "reflectorethernet", action="store")
    parser.add_argument("--counter", type = int, dest = "counter", action="store")
    args = parser.parse_args()

    if args == None:
        exit(0)

    t1 = threading.Thread(target=arp_sniff, args=())
    t1.start()

    t2 = threading.Thread(target=tcp_sniff, args=())
    t2.start()

    t3 = threading.Thread(target=udp_sniff, args=())
    t3.start()

    



