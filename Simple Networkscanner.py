import scapy.all as scapy
import argparse

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for client in answered_list:
        clients_list.append(client[1].psrc)
    return clients_list

def print_result(results_list):
    print("IP\t\tMAC\n------------------------------------")
    for client_ip in results_list:
        print(client_ip + "\t" + get_mac(client_ip))

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    for client in answered_list:
        return client[1].hwsrc

ip_address = input("Enter Target IP: ")
scan_result = scan(ip_address)
print_result(scan_result)
