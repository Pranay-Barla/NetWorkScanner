
import argparse
import scapy.all as scapy

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP/ IP Range.")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)    #this function asks for ip within the ip subnet and stores in the variable
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")    #ether pack sent from mac address to virtual broadcaster mac
    arp_request_broadcast = broadcast/arp_request   #binds arp and broadcast
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]    #sr = send recive , srp gives 2 list
    clients_list = []
    for element in answered_list:
        client_dict = {"IP": element[1].psrc, "Mac": element[1].hwsrc }
        clients_list.append(client_dict)
    return clients_list



def print_results(results_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------------")
    for client in results_list:
        print(client["IP"] + "\t\t" + client["Mac"])


options = get_argument()
scan_result = scan(options.target)
print_results(scan_result)
