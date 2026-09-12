from collections import defaultdict
import time
import ipaddress


class IntrusionDetector:

    def __init__(self):

        # ============================================================
        # KNOWN / TRUSTED DEVICES
        # ============================================================

        self.known_devices = {
            "10.97.185.213",
            "10.97.185.225",

            "2409:40e5:117a:a27c:4052:d0e1:b67c:b9a4",
            "2409:40e5:117a:a27c::80",
        }

        # ============================================================
        # TRACKING
        # ============================================================

        self.connection_attempts = defaultdict(list)
        self.packet_times = defaultdict(list)
        self.failed_logins = defaultdict(list)

        # Prevent duplicate alerts
        self.last_alert_time = {}

        # ============================================================
        # THRESHOLDS
        # ============================================================

        # Port scan:
        # 10 different destination ports
        # within 10 seconds

        self.PORT_SCAN_THRESHOLD = 10
        self.PORT_SCAN_WINDOW = 10

        # Packet flood:
        # 250 packets
        # within 10 seconds

        self.PACKET_FLOOD_THRESHOLD = 250
        self.PACKET_FLOOD_WINDOW = 10

        # Failed authentication:
        # 5 attempts
        # within 60 seconds

        self.FAILED_LOGIN_THRESHOLD = 5
        self.FAILED_LOGIN_WINDOW = 60

        # Large packet

        self.LARGE_PACKET_THRESHOLD = 5000

        # Same alert cooldown

        self.ALERT_COOLDOWN = 30

        # Authentication-related ports

        self.AUTH_PORTS = {
            22,      # SSH
            3389,    # RDP
            5900,    # VNC
        }

    # ============================================================
    # IP CLASSIFICATION
    # ============================================================

    def is_local_ip(self, src_ip):

        if not src_ip:
            return False

        try:
            ip = ipaddress.ip_address(src_ip)

        except ValueError:
            return False

        # Ignore loopback

        if ip.is_loopback:
            return False

        # Ignore multicast

        if ip.is_multicast:
            return False

        # Ignore IPv6 link-local

        if ip.version == 6 and ip.is_link_local:
            return False

        # Private/local address

        return ip.is_private

    # ============================================================
    # ALERT COOLDOWN
    # ============================================================

    def can_alert(self, alert_type, src_ip):

        key = (
            alert_type,
            src_ip
        )

        current_time = time.time()

        last_time = self.last_alert_time.get(key)

        if last_time is not None:

            if (
                current_time - last_time
                < self.ALERT_COOLDOWN
            ):
                return False

        self.last_alert_time[key] = current_time

        return True

    # ============================================================
    # UNKNOWN DEVICE DETECTION
    # ============================================================

    def check_unknown_device(self, src_ip):

        if not src_ip:
            return None

        # Trusted device

        if src_ip in self.known_devices:
            return None

        # Only inspect local/private devices

        if not self.is_local_ip(src_ip):
            return None

        if not self.can_alert(
            "UNKNOWN_DEVICE",
            src_ip
        ):
            return None

        return {
            "type": "UNKNOWN_DEVICE",

            "severity": "MEDIUM",

            "source_ip": src_ip,

            "message":
                f"Unknown local device detected: {src_ip}"
        }

    # ============================================================
    # FAILED LOGIN DETECTION
    # ============================================================

    def check_failed_login(self, src_ip):

        if not src_ip:
            return None

        current_time = time.time()

        self.failed_logins[src_ip].append(
            current_time
        )

        # Keep only recent attempts

        self.failed_logins[src_ip] = [
            timestamp
            for timestamp in self.failed_logins[src_ip]
            if (
                current_time - timestamp
                <= self.FAILED_LOGIN_WINDOW
            )
        ]

        if (
            len(self.failed_logins[src_ip])
            >= self.FAILED_LOGIN_THRESHOLD
        ):

            if not self.can_alert(
                "MULTIPLE_FAILED_LOGINS",
                src_ip
            ):
                return None

            return {
                "type":
                    "MULTIPLE_FAILED_LOGINS",

                "severity":
                    "HIGH",

                "source_ip":
                    src_ip,

                "message":
                    (
                        "Multiple failed login attempts "
                        f"detected from {src_ip}"
                    )
            }

        return None

    # ============================================================
    # AUTHENTICATION ATTEMPT DETECTION
    # ============================================================

    def check_auth_attempt(
        self,
        src_ip,
        dst_port
    ):

        if not src_ip or not dst_port:
            return None

        # Convert port safely

        try:
            dst_port = int(dst_port)

        except (TypeError, ValueError):
            return None

        # Only monitor authentication-related ports

        if dst_port not in self.AUTH_PORTS:
            return None

        current_time = time.time()

        self.failed_logins[src_ip].append(
            current_time
        )

        # Keep only recent attempts

        self.failed_logins[src_ip] = [
            timestamp
            for timestamp in self.failed_logins[src_ip]
            if (
                current_time - timestamp
                <= self.FAILED_LOGIN_WINDOW
            )
        ]

        attempts = len(
            self.failed_logins[src_ip]
        )

        if (
            attempts
            >= self.FAILED_LOGIN_THRESHOLD
        ):

            if not self.can_alert(
                "MULTIPLE_FAILED_LOGINS",
                src_ip
            ):
                return None

            return {
                "type":
                    "MULTIPLE_FAILED_LOGINS",

                "severity":
                    "HIGH",

                "source_ip":
                    src_ip,

                "message":
                    (
                        "Multiple authentication attempts "
                        f"detected from {src_ip}"
                    )
            }

        return None

    # ============================================================
    # PORT SCAN DETECTION
    # ============================================================

    def check_port_scan(
        self,
        src_ip,
        dst_port
    ):

        if not src_ip or dst_port is None:
            return None

        # Only monitor local/private sources

        if not self.is_local_ip(src_ip):
            return None

        try:
            dst_port = int(dst_port)

        except (TypeError, ValueError):
            return None

        current_time = time.time()

        self.connection_attempts[src_ip].append(
            (
                current_time,
                dst_port
            )
        )

        # Keep only last 10 seconds

        self.connection_attempts[src_ip] = [
            attempt
            for attempt in self.connection_attempts[src_ip]
            if (
                current_time - attempt[0]
                <= self.PORT_SCAN_WINDOW
            )
        ]

        # Find unique destination ports

        unique_ports = {
            port
            for _, port in self.connection_attempts[src_ip]
        }

        if (
            len(unique_ports)
            >= self.PORT_SCAN_THRESHOLD
        ):

            if not self.can_alert(
                "PORT_SCAN",
                src_ip
            ):
                return None

            return {
                "type":
                    "PORT_SCAN",

                "severity":
                    "HIGH",

                "source_ip":
                    src_ip,

                "message":
                    (
                        "Possible port scan detected "
                        f"from {src_ip}"
                    )
            }

        return None

    # ============================================================
    # PACKET FLOOD DETECTION
    # ============================================================

    def check_packet_flood(self, src_ip):

        if not src_ip:
            return None

        # Only monitor local/private sources

        if not self.is_local_ip(src_ip):
            return None

        current_time = time.time()

        self.packet_times[src_ip].append(
            current_time
        )

        # Keep packets from last 10 seconds

        self.packet_times[src_ip] = [
            timestamp
            for timestamp in self.packet_times[src_ip]
            if (
                current_time - timestamp
                <= self.PACKET_FLOOD_WINDOW
            )
        ]

        packet_count = len(
            self.packet_times[src_ip]
        )

        if (
            packet_count
            >= self.PACKET_FLOOD_THRESHOLD
        ):

            if not self.can_alert(
                "PACKET_FLOOD",
                src_ip
            ):
                return None

            return {
                "type":
                    "PACKET_FLOOD",

                "severity":
                    "HIGH",

                "source_ip":
                    src_ip,

                "message":
                    (
                        "High packet rate detected "
                        f"from {src_ip}"
                    )
            }

        return None

    # ============================================================
    # LARGE PACKET DETECTION
    # ============================================================

    def check_large_packet(
        self,
        src_ip,
        packet_size
    ):

        if not src_ip:
            return None

        try:
            packet_size = int(packet_size)

        except (TypeError, ValueError):
            return None

        if (
            packet_size
            <= self.LARGE_PACKET_THRESHOLD
        ):
            return None

        if not self.can_alert(
            "LARGE_PACKET",
            src_ip
        ):
            return None

        return {
            "type":
                "LARGE_PACKET",

            "severity":
                "MEDIUM",

            "source_ip":
                src_ip,

            "message":
                (
                    "Unusually large packet detected "
                    f"from {src_ip} "
                    f"({packet_size} bytes)"
                )
        }

    # ============================================================
    # MAIN PACKET ANALYSIS
    # ============================================================

    def analyze_packet(
        self,
        src_ip,
        dst_port=None,
        packet_size=0
    ):

        if not src_ip:
            return None

        # ========================================================
        # 1. UNKNOWN DEVICE
        # ========================================================

        alert = self.check_unknown_device(
            src_ip
        )

        if alert:
            return alert

        # ========================================================
        # 2. AUTHENTICATION ATTEMPTS
        # ========================================================

        alert = self.check_auth_attempt(
            src_ip,
            dst_port
        )

        if alert:
            return alert

        # ========================================================
        # 3. PORT SCAN
        # ========================================================

        alert = self.check_port_scan(
            src_ip,
            dst_port
        )

        if alert:
            return alert

        # ========================================================
        # 4. LARGE PACKET
        # ========================================================

        alert = self.check_large_packet(
            src_ip,
            packet_size
        )

        if alert:
            return alert

        # ========================================================
        # 5. PACKET FLOOD
        # ========================================================

        alert = self.check_packet_flood(
            src_ip
        )

        if alert:
            return alert

        return None


# ================================================================
# TEST
# ================================================================

if __name__ == "__main__":

    detector = IntrusionDetector()

    test_ip = "192.168.1.100"

    print("=" * 60)
    print("IDS DETECTOR TEST")
    print("=" * 60)

    # ------------------------------------------------------------
    # TEST 1
    # ------------------------------------------------------------

    print("\n[TEST 1] Unknown device")

    print(
        detector.check_unknown_device(
            test_ip
        )
    )

    # ------------------------------------------------------------
    # TEST 2
    # ------------------------------------------------------------

    print("\n[TEST 2] Port scan")

    for port in range(1, 11):

        alert = detector.check_port_scan(
            test_ip,
            port
        )

        if alert:
            print(alert)

    # ------------------------------------------------------------
    # TEST 3
    # ------------------------------------------------------------

    print("\n[TEST 3] Large packet")

    print(
        detector.check_large_packet(
            test_ip,
            6000
        )
    )

    # ------------------------------------------------------------
    # TEST 4
    # ------------------------------------------------------------

    print("\n[TEST 4] Failed logins")

    # Use a fresh detector because the previous
    # tests may have populated state.

    login_detector = IntrusionDetector()

    for attempt in range(5):

        alert = login_detector.check_failed_login(
            test_ip
        )

        if alert:
            print(alert)

    # ------------------------------------------------------------
    # TEST 5
    # ------------------------------------------------------------

    print("\n[TEST 5] Public Internet filtering")

    public_ip = "8.8.8.8"

    print(
        "Is public IP local?",
        detector.is_local_ip(public_ip)
    )

    print(
        "Port scan from public IP:",
        detector.check_port_scan(
            public_ip,
            22
        )
    )

    print(
        "Packet flood from public IP:",
        detector.check_packet_flood(
            public_ip
        )
    )

    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)