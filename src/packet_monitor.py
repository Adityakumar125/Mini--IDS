import sys
import os
import time

from scapy.all import sniff, IP, IPv6, TCP, UDP


# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


# ============================================================
# IMPORTS
# ============================================================

from src.detector import IntrusionDetector
from src.alerts import generate_alert

from data.ids_data import (
    record_packet,
    get_monitoring_state
)


# ============================================================
# DETECTOR
# ============================================================

detector = IntrusionDetector()


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    try:

        # ------------------------------------------------------
        # CHECK MONITORING STATE
        # ------------------------------------------------------

        if not get_monitoring_state():
            return


        # ------------------------------------------------------
        # RECORD PACKET
        # ------------------------------------------------------

        record_packet()


        # ------------------------------------------------------
        # DETERMINE IP VERSION
        # ------------------------------------------------------

        src_ip = None
        dst_ip = None

        if IP in packet:

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        elif IPv6 in packet:

            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

        else:

            # Not an IP packet
            return


        # ------------------------------------------------------
        # PROTOCOL / PORT
        # ------------------------------------------------------

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


        # ------------------------------------------------------
        # DISPLAY PACKET
        # ------------------------------------------------------

        print("\n" + "=" * 60)
        print("📦 PACKET DETECTED")
        print("=" * 60)

        print(f"Source IP       : {src_ip}")
        print(f"Destination IP  : {dst_ip}")
        print(f"Protocol        : {protocol}")
        print(f"Source Port     : {src_port}")
        print(f"Destination Port: {dst_port}")
        print(f"Packet Size     : {len(packet)} bytes")


        # ------------------------------------------------------
        # IDS ANALYSIS
        # ------------------------------------------------------

        alert = detector.analyze_packet(
            src_ip=src_ip,
            dst_port=dst_port,
            packet_size=len(packet)
        )


        # ------------------------------------------------------
        # ALERT
        # ------------------------------------------------------

        if alert:

            print("\n🚨 ALERT DETECTED")
            print(alert)

            generate_alert(alert)


    except Exception as error:

        print(
            f"⚠️ Packet processing error: {error}"
        )


# ============================================================
# PACKET MONITOR
# ============================================================

def start_monitoring():

    print("=" * 60)
    print("🛡️ MINI IDS - PACKET MONITOR")
    print("=" * 60)

    print("Listening for network packets...")
    print("Monitoring state is controlled by the dashboard.")
    print("Press CTRL+C to stop.\n")


    try:

        while True:

            # --------------------------------------------------
            # CHECK MONITORING STATE
            # --------------------------------------------------

            if not get_monitoring_state():

                time.sleep(1)

                continue


            # --------------------------------------------------
            # CAPTURE PACKETS
            # --------------------------------------------------

            sniff(
                prn=packet_callback,
                store=False,
                timeout=1
            )


    except KeyboardInterrupt:

        print("\n")
        print("=" * 60)
        print("🛑 MINI IDS PACKET MONITOR STOPPED")
        print("=" * 60)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    start_monitoring()