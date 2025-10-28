## Json Code

import socket
import time
import sys
from dnslib import DNSRecord
import json


ROOT_SERVERS = [
    "198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13",
    "192.203.230.10","192.5.5.241","192.112.36.4","198.97.190.53",
    "192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42",
    "202.12.27.33"
]

def save_log_json(json_file, record):
    try:
        with open(json_file, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []

    data.append(record)

    with open(json_file, "w") as f:
        json.dump(data, f, indent=4)

def iterative_resolve(query_data):
    query = DNSRecord.parse(query_data)
    qname = str(query.q.qname)
    log = []
    start_time = time.time()
    current_servers = ROOT_SERVERS.copy()
    response = None
    step = 0

    while True:
        step += 1
        server = current_servers[0]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)

        send_time = time.time()
        try:
            sock.sendto(query_data, (server, 53))
            data, _ = sock.recvfrom(2048)
            recv_time = time.time()
        except socket.timeout:
            log.append({
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

        stage = ''
        if step == 1:
            stage = "Root"
        elif len(resp.auth) > 0 and not resp.rr:
            stage = "TLD"
        else:
            stage = "Authoritative"

        response_summary = []
        records = resp.rr or resp.auth or []
        if records:
            for rr in records:
                response_summary.append(f"{rr.rname} :: {rr.rtype} :: {rr.rdata}")
        else:
            response_summary.append("empty response")

        log.append({
            "step": step,
            "mode": "Iterative",
            "stage_resolution": stage,
            "server": server,
            "rtt": round(rtt, 2),
            "response": response_summary
        })

        if resp.rr:
            response = data
            break

        IP = [str(rr.rdata) for rr in resp.ar if rr.rtype == 1]
        if not IP:
            ns_names = [str(rr.rdata) for rr in resp.auth if rr.rtype == 2]
            if not ns_names:
                break

            IP = []
            for ns in ns_names:
                new_query = DNSRecord.question(ns)
                new_response, _, _, _ = iterative_resolve(bytes(new_query.pack()))
                if new_response:
                    parsing_new = DNSRecord.parse(new_response)
                    for rr in parsing_new.rr:
                        if rr.rtype == 1:
                            IP.append(str(rr.rdata))

        if not IP:
            break

        current_servers = IP

    time_taken = 1000 * (time.time() - start_time)
    return response, log, round(time_taken, 2), qname





json_file = "output_PCAP1.json"
print(f"Logging at {json_file}")

with open(json_file, "a") as f:
    time_run = f"\n DNS :: {time.strftime('%Y-%m-%d %H:%M:%S')} \n"
    print(time_run.strip())

    print("Listening at 10.0.0.5 at port 53")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("10.0.0.5", 53))

    while True:
        data, addr_tuple = sock.recvfrom(512)
        packet_recv = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        response, loggin_detail, timetaken, qname = iterative_resolve(data)
        status = ''
        if response:
            sock.sendto(response, addr_tuple)
            status = "SUCCESS"
        else:
            status = "FAILED"

        record = {
            "timestamp": packet_recv,
            "client_ip": addr_tuple[0],
            "queried_domain": qname,
            "resolution_steps": loggin_detail,
            "total_time_ms": timetaken,
            "status": status
        }

        save_log_json(json_file, record)
        print(f"Logged resolution for {qname} ({timetaken} ms)")
