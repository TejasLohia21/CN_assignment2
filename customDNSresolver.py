import socket
import time
import sys
from dnslib import DNSRecord, RR
import json

# 13 root servers, out of which 13 are accessible from our IP 
ROOT_DNS_SERVERS = [
    "198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13",
    "192.203.230.10","192.5.5.241","192.112.36.4","198.97.190.53",
    "192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42",
    "202.12.27.33"
]

# Will store cache in a heirarchical way
DNS_CACHE = {}

# Cache Addition
def cache_add(record_entry):
    key = (str(record_entry.rname).lower(), record_entry.rtype)
    ttl = record_entry.ttl if record_entry.ttl > 0 else 300
    expiry_time = time.time() + ttl
    cached_record = DNSRecord()
    cached_record.add_answer(RR(record_entry.rname, record_entry.rtype, rdata=record_entry.rdata, ttl=record_entry.ttl))
    DNS_CACHE[key] = {"response": bytes(cached_record.pack()), "expiry": expiry_time}

# Updating the cache
def cache_update(response_record):
    for record_entry in response_record.rr + response_record.auth + response_record.ar:
        cache_add(record_entry)

# Cache retrieval
def cache_lookup(domain, query_type):
    key = (domain.lower(), query_type)
    entry = DNS_CACHE.get(key)
    if entry and entry["expiry"] > time.time():
        return entry["response"]
    elif entry:
        del DNS_CACHE[key]
    return None

# Iterative resolver
def perform_iterative_resolution(raw_query):
    query_packet = DNSRecord.parse(raw_query)
    domain_name = str(query_packet.q.qname)
    query_type = query_packet.q.qtype

    logs = []
    start_time = time.time()
    current_server_list = ROOT_DNS_SERVERS
    final_response = None
    step_count = 0
    cache_status = "MISS"

    cached_data = cache_lookup(domain_name, query_type)
    if cached_data:
        cache_status = "HIT"
        logs.append({
            "step": 0,
            "mode": "Cache",
            "stage": "Cached Response",
            "server": "Local Cache",
            "rtt": 0,
            "response": [f"Cached result for {domain_name} (Type {query_type})"],
            "cache_status": cache_status
        })
        elapsed = (time.time() - start_time) * 1000
        return cached_data, logs, round(elapsed, 2), domain_name

    while True:
        step_count += 1
        got_valid_response = False
        response_data = None
        used_server = None
        send_time = recv_time = None

        for dns_server in current_server_list:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.settimeout(2)
            send_time = time.time()

            try:
                client_socket.sendto(raw_query, (dns_server, 53))
                response_data, _ = client_socket.recvfrom(2048)
                recv_time = time.time()
                got_valid_response = True
                used_server = dns_server
                client_socket.close()
                break
            except socket.timeout:
                logs.append({
                    "step": step_count,
                    "mode": "Iterative",
                    "stage": "Timeout",
                    "server": dns_server,
                    "rtt": None,
                    "response": ["No response (timeout)"],
                    "cache_status": cache_status
                })
                client_socket.close()
                continue

        if not got_valid_response:
            break

        round_trip_time = (recv_time - send_time) * 1000
        parsed_response = DNSRecord.parse(response_data)
        cache_update(parsed_response)

        if step_count == 1:
            stage_type = "Root"
        elif len(parsed_response.auth) > 0 and not parsed_response.rr:
            stage_type = "TLD"
        else:
            stage_type = "Authoritative"

        summary = []
        records = parsed_response.rr or parsed_response.auth or []
        if records:
            for record_entry in records:
                summary.append(f"{record_entry.rname} :: {record_entry.rtype} :: {record_entry.rdata}")
        else:
            summary.append("Empty/Referral response")

        logs.append({
            "step": step_count,
            "mode": "Iterative",
            "stage": stage_type,
            "server": used_server,
            "rtt": round(round_trip_time, 2),
            "response": summary,
            "cache_status": cache_status
        })

        if parsed_response.rr:
            final_response = response_data
            ttl_values = [record_entry.ttl for record_entry in parsed_response.rr]
            ttl = min(ttl_values) if ttl_values else 300
            DNS_CACHE[(domain_name.lower(), query_packet.q.qtype)] = {
                "response": final_response,
                "expiry": time.time() + ttl
            }
            break

        next_server_ips = []
        for record_entry in parsed_response.ar:
            if record_entry.rtype == 1:
                next_server_ips.append(str(record_entry.rdata))

        if not next_server_ips:
            ns_names = [str(record_entry.rdata) for record_entry in parsed_response.auth if record_entry.rtype == 2]
            if not ns_names:
                break
            for ns_domain in ns_names:
                sub_query = DNSRecord.question(ns_domain)
                sub_response, sub_logs, _, _ = perform_iterative_resolution(bytes(sub_query.pack()))
                logs.extend(sub_logs)
                if sub_response:
                    parsed_sub = DNSRecord.parse(sub_response)
                    for record_entry in parsed_sub.rr:
                        if record_entry.rtype == 1:
                            next_server_ips.append(str(record_entry.rdata))

        if not next_server_ips:
            break

        current_server_list = next_server_ips

    elapsed_time = 1000 * (time.time() - start_time)
    return final_response, logs, round(elapsed_time, 2), domain_name

# JSON writer
def write_log(json_filename, log_entry):
    try:
        with open(json_filename, "r") as f:
            existing_logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_logs = []
    existing_logs.append(log_entry)
    with open(json_filename, "w") as f:
        json.dump(existing_logs, f, indent=4)

# Update for json name
log_file = "dns_query_log.json"
print(f"Logging to {log_file}")
print("DNS Resolver active at 10.0.0.5:53") # This code is listening at IP: 10.0.0.5 @ Port Number 53 for UDP packets

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("10.0.0.5", 53))

while True:
    raw_data, client_info = server_socket.recvfrom(2048)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    resolved_data, step_logs, elapsed, domain_name = perform_iterative_resolution(raw_data)
    status = "SUCCESS" if resolved_data else "FAILED"

    if resolved_data:
        server_socket.sendto(resolved_data, client_info)

    log_entry = {
        "timestamp": timestamp,
        "client_ip": client_info[0],
        "queried_domain": domain_name,
        "resolution_steps": step_logs,
        "total_time_ms": elapsed,
        "status": status
    }

    write_log(log_file, log_entry)
    print(f"Resolved {domain_name} in {elapsed} ms")