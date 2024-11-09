from scapy.all import ARP, Ether, srp

def scan_network(target_ip):
    # ARP request packet si loo helo qalabka ku xiran shabakada
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    # Dir codsiga iyo hel jawaab
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Daabac jawaabaha
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)

# Go'aanso shabakad aad rabto inaad baaro
target_ip = "192.168.1.1/24"  # Change this to your local network range
scan_network(target_ip)
