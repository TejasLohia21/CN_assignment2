import sys
import socket
import time
import csv
import os
import json

def read_domains(file):
    queries = []
    with open(file, newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            # print(row)
            if(row[1] == "URL"):
                continue
            if('.' not in row[1]):
                continue
            if row and row[1]:
                try:
                    frame_len = int(row[3]) 
                except:
                    frame_len = 100 
                queries.append((row[1], frame_len))
    
    return queries


def resolve_single(domain):
    print(f"Resolving domain{domain}")
    start = time.perf_counter()
    try:
        addr_info = socket.getaddrinfo(domain, None)
        duration_ms = (time.perf_counter() - start) * 1000
        ips = list({res[4][0] for res in addr_info})
        return True, duration_ms, ips
    except socket.gaierror:
        return False, None, []

def measure_domains(domains, json_file):
    print(len(domains))
    total_queries = len(domains)
    success_count = 0
    failure_count = 0
    latencies = []
    total_bits_sent = 0

    overall_start = time.perf_counter()
    results = []
    for idx, (domain, frame_len) in enumerate(domains, 1):
        success, latency, ips = resolve_single(domain)
        if success:
            print(f"{domain} resolved")
            success_count += 1
            latencies.append(latency)
            total_bits_sent += frame_len * 8
            results.append({
                "domain": domain,
                "status": "SUCCESS",
                "resolved_ips": ips
            })
        else:
            results.append({
                "domain": domain,
                "status": "FAILED",
                "resolved_ips": []
            })
            failure_count += 1

        if idx % 5 == 0 or idx == total_queries:
            print(f"{idx}/{total_queries} queries processed...")

    total_time = time.perf_counter() - overall_start
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    throughput = total_bits_sent / total_time if total_time > 0 else 0

    summary = {
        "total": total_queries,
        "success": success_count,
        "fail": failure_count,
        "avg_latency_ms": avg_latency,
        "throughput_bps": throughput
    }

    if os.path.exists(json_file):
        with open(json_file, "r") as f:
            try:
                existing = json.load(f)
            except json.JSONDecodeError:
                existing = []
    else:
        existing = []

    existing.append({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "details": results
    })

    with open(json_file, "w") as f:
        json.dump(existing, f, indent=4)

    return summary



def main():
    if len(sys.argv) != 2:
        print("Usage: python3 measure_dns.py <txt_file>")
        sys.exit(1)

    code_, csv_file = sys.argv[0], sys.argv[1]
    socket.setdefaulttimeout(15.0)

    json_file = "Multiserverresolved_host1.json"

    domain_queries = read_domains(csv_file)
    if(domain_queries == []):
        print("error in reading file")
        return 
    stats = measure_domains(domain_queries, json_file)

    print(f"Total queries: {stats['total']}")
    print(f"Successful resolutions: {stats['success']}")
    print(f"Failed resolutions: {stats['fail']}")
    print(f"Average lookup latency: {stats['avg_latency_ms']:.2f} ms")
    print(f"Average throughput: {stats['throughput_bps']:.2f} bits/s")

if __name__ == "__main__":
    main()
