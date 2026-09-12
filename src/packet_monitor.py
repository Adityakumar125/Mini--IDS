from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parent.parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
from data.ids_data import (
    record_packet,
    record_device,
    get_monitoring_state
)
from src.alerts import generate_alert
from src.detector import IntrusionDetector
import sys
import os
import time

from scapy.all import (
    sniff,
    IP,
    IPv6,
    TCP,
    UDP
)


# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if BASE_DIR not in sys.path:
    sys.path.insert(
        0,
        BASE_DIR
    )


# ============================================================
# IMPORTS
# ============================================================


# ============================================================
# DETECTOR
# ============================================================

detector = IntrusionDetector()


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    # --------------------------------------------------------
    # Check monitoring state
    # --------------------------------------------------------

    if not get_monitoring_state():
        return

    # --------------------------------------------------------
    # Record packet
    # --------------------------------------------------------

    # --------------------------------------------------------
    # Determine IP layer
    # --------------------------------------------------------

    src_ip = None
    dst_ip = None

    if IP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    elif IPv6 in packet:

        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

    else:

        return

    # --------------------------------------------------------
# RECORD CONNECTED DEVICE
# --------------------------------------------------------

    record_device(src_ip)

    
    # --------------------------------------------------------
    # Protocol information
    # --------------------------------------------------------

    protocol = "OTHER"

    src_port = None
    dst_port = None

    if TCP in packet:

        protocol = "TCP"

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:

        protocol = "UDP"

        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # --------------------------------------------------------
    # Packet information
    # --------------------------------------------------------

    packet_size = len(packet)

    # --------------------------------------------------------
    # RECORD PACKET DETAILS
    # --------------------------------------------------------

    record_packet(
        protocol=protocol,
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=src_port,
        destination_port=dst_port,
        packet_size=packet_size
    )

    print("\n" + "=" * 60)
    print("📦 PACKET DETECTED")
    print("=" * 60)

    print(
        f"Source IP       : {src_ip}"
    )

    print(
        f"Destination IP  : {dst_ip}"
    )

    print(
        f"Protocol        : {protocol}"
    )

    print(
        f"Source Port     : {src_port}"
    )

    print(
        f"Destination Port: {dst_port}"
    )

    print(
        f"Packet Size     : {packet_size} bytes"
    )

    # --------------------------------------------------------
    # DETECTION
    # --------------------------------------------------------

    alert = detector.analyze_packet(
        src_ip=src_ip,
        dst_port=dst_port,
        packet_size=packet_size
    )

    # --------------------------------------------------------
    # ALERT
    # --------------------------------------------------------

    if alert:

        print("🚨 ALERT DETECTED")
        print(alert)

        generate_alert(alert)


# ============================================================
# PACKET MONITOR
# ============================================================

def start_monitoring():

    print("=" * 60)
    print("🛡️ MINI IDS - PACKET MONITOR")
    print("=" * 60)

    print(
        "Listening for network packets..."
    )

    print(
        "Monitoring state is controlled "
        "by the dashboard."
    )

    print(
        "Press CTRL+C to stop.\n"
    )

    try:

        while True:

            # ------------------------------------------------
            # Check monitoring state
            # ------------------------------------------------

            if not get_monitoring_state():

                time.sleep(1)

                continue

            # ------------------------------------------------
            # Capture packets
            # ------------------------------------------------

            sniff(
                prn=packet_callback,
                store=False,
                timeout=1
            )

    except KeyboardInterrupt:

        print(
            "\n🛑 Packet monitor stopped."
        )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    start_monitoring()
