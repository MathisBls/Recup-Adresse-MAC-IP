import scapy.all as scapy

def scan(ip):
    # Créer une requête ARP pour obtenir les adresses MAC des appareils sur le réseau local
    arp_request = scapy.ARP(pdst=ip)
    
    # Créer un paquet Ethernet pour encapsuler la requête ARP
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # Concaténer le paquet Ethernet avec la requête ARP
    arp_request_broadcast = broadcast/arp_request
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices_list = []
    
    for element in answered_list:
        device_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc, "hostname": get_hostname(element[1].psrc)}
        devices_list.append(device_dict)
    
    return devices_list

def get_hostname(ip):
    try:
        # Utiliser la résolution DNS pour obtenir le nom d'hôte à partir de l'adresse IP
        hostname = scapy.socket.gethostbyaddr(ip)[0]
        return hostname
    except scapy.socket.herror:
        return ""

def display_result(results):
    print("IP Address\t\tMAC Address\t\tHostname")
    print("---------------------------------------------")
    for device in results:
        print(f"{device['ip']}\t\t{device['mac']}\t\t{device['hostname']}")

target_ip = "192.168.1.1/24"

scan_result = scan(target_ip)
display_result(scan_result)
