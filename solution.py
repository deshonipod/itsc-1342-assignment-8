# DeShon Harris - Assignment 8
import json
import os


def _extract_from_wireshark_packet(pkt):
    """Pulls protocol and destination IP from a Wireshark JSON packet object if present."""
    source = pkt.get("_source", {})
    layers = source.get("layers", {})

    proto = None
    dst = None

    frame = layers.get("frame", {})
    if isinstance(frame, dict):
        protocols_str = frame.get("frame.protocols", "")
        if isinstance(protocols_str, str) and protocols_str:
            proto = protocols_str.split(":")[-1].upper()

    ip_layer = layers.get("ip", {})
    if isinstance(ip_layer, dict):
        dst = ip_layer.get("ip.dst")

    return proto, dst


def analyze_capture_records(records):
    report = {
        "protocols": {},
        "unique_destinations": []
    }
    unique_dsts = set()

    if not isinstance(records, list):
        return report

    for pkt in records:
        if not isinstance(pkt, dict):
            continue

        if "_source" in pkt:
            proto, dst = _extract_from_wireshark_packet(pkt)
            if proto:
                report["protocols"][proto] = report["protocols"].get(proto, 0) + 1
            if dst:
                unique_dsts.add(dst)
        else:
            proto = str(pkt.get("proto", "UNKNOWN")).upper()
            report["protocols"][proto] = report["protocols"].get(proto, 0) + 1
            if "dst" in pkt and pkt["dst"]:
                unique_dsts.add(pkt["dst"])

    report["unique_destinations"] = sorted(unique_dsts)
    return report


if __name__ == "__main__":
    capture_path = os.path.join(os.path.dirname(__file__), "capture.json")
    if os.path.exists(capture_path):
        with open(capture_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        summary = analyze_capture_records(data)
        print("LIVE CAPTURE SUMMARY:")
        print(summary)
    else:
        print("capture.json not found yet in code/ folder.")