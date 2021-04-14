import scapy.all as scapy
from scapy_http import http
import optparse
def options():
    opt = optparse.OptionParser()
    opt.add_option("-i","--iface",dest="interface",help="enter interface")
    (value,key)=opt.parse_args()
    return value.interface
def sniff(iface):
    scapy.sniff(prn=sniffer,iface=iface,store=False)
def sniffer(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.raw):
            print(packet[scapy.raw].load)


temp = options()
sniff(temp)
