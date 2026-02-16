import ipaddress
import dns.resolver
import time
import csv
from datetime import datetime
from collections import Counter

NETWORK_FILE = "networks.txt"
CSV_OUTPUT = "dnsbl_report.csv"

DNS_TIMEOUT = 2
DELAY = 0.25

resolver = dns.resolver.Resolver()
resolver.timeout = DNS_TIMEOUT
resolver.lifetime = DNS_TIMEOUT


SPAMHAUS_CODES = {
    "127.0.0.2": ("SBL", "Direct spam sources"),
    "127.0.0.3": ("SBL-CSS", "Snowshoe spam"),
    "127.0.0.4": ("XBL", "Infected system"),
    "127.0.0.5": ("XBL", "Infected system"),
    "127.0.0.6": ("XBL", "Infected system"),
    "127.0.0.7": ("XBL", "Infected system"),
    "127.0.0.10": ("PBL", "Policy block list"),
    "127.0.0.11": ("PBL", "Policy block list"),
}


def reverse_ip(ip):
    return ".".join(reversed(ip.split(".")))


def spamhaus_lookup(ip):
    try:
        query = f"{reverse_ip(ip)}.zen.spamhaus.org"
        answers = resolver.resolve(query, "A")
        results = []
        for rdata in answers:
            code = rdata.to_text()
            if code in SPAMHAUS_CODES:
                results.append(SPAMHAUS_CODES[code])
        return results
    except dns.resolver.NXDOMAIN:
        return []
    except Exception:
        return []


def load_networks(path):
    with open(path) as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]


def analyze_network(network):
    net = ipaddress.ip_network(network)
    hits = []

    for ip in net.hosts():
        result = spamhaus_lookup(str(ip))
        if result:
            for r in result:
                hits.append((str(ip), r))
        time.sleep(DELAY)

    return hits, net


def main():
    networks = load_networks(NETWORK_FILE)
    rows = []

    for network in networks:
        print(f"\nПроверка {network}")
        hits, net = analyze_network(network)

        if not hits:
            continue

        types = [r[1][0] for r in hits]
        counter = Counter(types)

        if sum(counter.values()) == net.num_addresses - 2 and len(counter) == 1:
            list_type = list(counter.keys())[0]
            rows.append({
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "target": network,
                "list": f"Spamhaus {list_type}",
                "details": "Entire network listed"
            })
            print(f"[NETWORK] {network} → Spamhaus {list_type}")
        else:
            for ip, (list_type, desc) in hits:
                rows.append({
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                    "target": ip,
                    "list": f"Spamhaus {list_type}",
                    "details": desc
                })
                print(f"[IP] {ip} → Spamhaus {list_type}")

    write_csv(rows)
    print("\nГотово. Отчёт сохранён.")


def write_csv(data):
    with open(CSV_OUTPUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["timestamp", "target", "list", "details"]
        )
        writer.writeheader()
        writer.writerows(data)


if __name__ == "__main__":
    main()
