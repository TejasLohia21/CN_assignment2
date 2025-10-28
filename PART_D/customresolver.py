import socket
import time
import sys
from dnslib import DNSRecord
import json

# Root DNS server list
ROOT_SERVERS = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33"
]

def save_log_json(filename, record):
    # Save DNS query logs to JSON file
    try:
        with open(filename, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []

    data.append(record)
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

def ret_step(resp, step):
    if step == 1:
        stage = "Root"
    elif len(resp.auth) > 0 and not resp.rr:
        stage = "TLD"
    else:
        stage = "Authoritative"
    return stage



def perform_iterative_resolution(query_bytes):
    # Perform iterative DNS resolution
    query_packet = DNSRecord.parse(query_bytes)
    qname = str(query_packet.q.qname)
    logs = []
    start_time = time.time()
    servers = ROOT_SERVERS.copy()
    response = None
    step = 0

    while True:
        step += 1
        server = servers[0]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)

        send_time = time.time()
        try:
            sock.sendto(query_bytes, (server, 53))
            data, _ = sock.recvfrom(2048)
            recv_time = time.time()
        except socket.timeout:
            logs.append({
                "step": step,
                "mode": "Iterative",
                "stage_resolution": "Timeout",
                "server": server,
                "rtt": None,
                "response": ["No response (timeout)"]
            })
            sock.close()
            break

        sock.close()
        rtt = (recv_time - send_time) * 1000
        resp = DNSRecord.parse(data)

        stage = ret_step(resp, step)

        out_summary = []
        records = resp.rr or resp.auth or []
        if records:
            for rr in records:
                out_summary.append(f"{rr.rname} :: {rr.rtype} :: {rr.rdata}")
        else:
            out_summary.append("empty response")

        logs.append({
            "step": step,
            "mode": "Iterative",
            "stage_resolution": stage,
            "server": server,
            "rtt": round(rtt, 2),
            "response": out_summary
        })

        if resp.rr:
            response = data
            break

        ip_list = [str(rr.rdata) for rr in resp.ar if rr.rtype == 1]
        if not ip_list:
            ns_names = [str(rr.rdata) for rr in resp.auth if rr.rtype == 2]
            if not ns_names:
                break

            ip_list = []
            for ns in ns_names:
                ns_query = DNSRecord.question(ns)
                new_resp, _, _, _ = perform_iterative_resolution(bytes(ns_query.pack()))
                if new_resp:
                    parsed = DNSRecord.parse(new_resp)
                    for rr in parsed.rr:
                        if rr.rtype == 1:
                            ip_list.append(str(rr.rdata))

        if not ip_list:
            break

        servers = ip_list

    total_time = 1000 * (time.time() - start_time)
    return response, logs, round(total_time, 2), qname


json_file = "PCAP1.json"
print(f"Logging at {json_file}")

with open(json_file, "a") as f:
    timestamp = f"\n DNS :: {time.strftime('%Y-%m-%d %H:%M:%S')} \n"
    print(timestamp.strip())
    print("Listening at 10.0.0.5:53")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("10.0.0.5", 53))

    while True:
        data, client_addr = sock.recvfrom(512)
        recv_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        response, details, duration, qname = perform_iterative_resolution(data)

        status = "SUCCESS" if response else "FAILED"
        if response:
            sock.sendto(response, client_addr)

        record = {
            "timestamp": recv_time,
            "client_ip": client_addr[0],
            "queried_domain": qname,
            "resolution_steps": details,
            "total_time_ms": duration,
            "status": status
        }

        save_log_json(json_file, record)
        print(f"Logged resolution for {qname} ({duration} ms)")