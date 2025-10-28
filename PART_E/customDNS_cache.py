import socket
import time
import sys
from dnslib import DNSRecord, RR
import json

# Root DNS servers
ROOT_DNS_SERVERS = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33"
]

DNS_CACHE = {}


def add_to_cache(record):
    """Add a record to cache."""
    cache_key = (str(record.rname).lower(), record.rtype)
    ttl = record.ttl if record.ttl > 0 else 300
    expiry_time = time.time() + ttl

    cached_record = DNSRecord()
    cached_record.add_answer(RR(record.rname, record.rtype, rdata=record.rdata, ttl=record.ttl))
    DNS_CACHE[cache_key] = {
        "response": bytes(cached_record.pack()),
        "expiry": expiry_time
    }


def update_cache(response):
    """Update cache using records from a DNS response."""
    for record in response.rr + response.auth + response.ar:
        add_to_cache(record)


def get_from_cache(domain_name, query_type):
    """Retrieve record from cache if still valid."""
    cache_key = (domain_name.lower(), query_type)
    cached_entry = DNS_CACHE.get(cache_key)

    if cached_entry and cached_entry["expiry"] > time.time():
        return cached_entry["response"]
    elif cached_entry:
        del DNS_CACHE[cache_key]
    return None


def resolve_iteratively(raw_query):
    """Perform iterative DNS resolution."""
    parsed_query = DNSRecord.parse(raw_query)
    domain_name = str(parsed_query.q.qname)
    query_type = parsed_query.q.qtype

    logs = []
    start_time = time.time()
    active_servers = ROOT_DNS_SERVERS
    final_response = None
    step_count = 0
    cache_status = "MISS"

    cached_response = get_from_cache(domain_name, query_type)
    if cached_response:
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
        total_time = (time.time() - start_time) * 1000
        return cached_response, logs, round(total_time, 2), domain_name

    while True:
        step_count += 1
        server_ip = active_servers[0]
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.settimeout(2)

        send_time = time.time()
        try:
            udp_socket.sendto(raw_query, (server_ip, 53))
            response_data, _ = udp_socket.recvfrom(2048)
            recv_time = time.time()
        except socket.timeout:
            logs.append({
                "step": step_count,
                "mode": "Iterative",
                "stage": "Timeout",
                "server": server_ip,
                "rtt": None,
                "response": ["No response (timeout)"],
                "cache_status": cache_status
            })
            udp_socket.close()
            break

        udp_socket.close()
        rtt = (recv_time - send_time) * 1000
        parsed_response = DNSRecord.parse(response_data)
        update_cache(parsed_response)

        if step_count == 1:
            stage = "Root"
        elif len(parsed_response.auth) > 0 and not parsed_response.rr:
            stage = "TLD"
        else:
            stage = "Authoritative"

        record_summary = []
        records = parsed_response.rr or parsed_response.auth or []
        if records:
            for record in records:
                record_summary.append(f"{record.rname} :: {record.rtype} :: {record.rdata}")
        else:
            record_summary.append("Empty response")

        logs.append({
            "step": step_count,
            "mode": "Iterative",
            "stage": stage,
            "server": server_ip,
            "rtt": round(rtt, 2),
            "response": record_summary,
            "cache_status": cache_status
        })

        if parsed_response.rr:
            final_response = response_data
            ttl_values = [record.ttl for record in parsed_response.rr]
            ttl = min(ttl_values) if ttl_values else 300
            DNS_CACHE[(domain_name.lower(), parsed_query.q.qtype)] = {
                "response": final_response,
                "expiry": time.time() + ttl
            }
            break

        next_server_ips = []
        for record in parsed_response.ar:
            if record.rtype == 1:  # A record
                next_server_ips.append(str(record.rdata))

        if not next_server_ips:
            ns_names = [str(record.rdata) for record in parsed_response.auth if record.rtype == 2]
            if not ns_names:
                break

            for ns_name in ns_names:
                followup_query = DNSRecord.question(ns_name)
                followup_response, _, _, _ = resolve_iteratively(bytes(followup_query.pack()))
                if followup_response:
                    parsed_followup = DNSRecord.parse(followup_response)
                    for record in parsed_followup.rr:
                        if record.rtype == 1:
                            next_server_ips.append(str(record.rdata))

        if not next_server_ips:
            break

        active_servers = next_server_ips

    total_time = (time.time() - start_time) * 1000
    return final_response, logs, round(total_time, 2), domain_name


def write_log(file_name, log_entry):
    """Save DNS query log to a JSON file."""
    try:
        with open(file_name, "r") as f:
            existing_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        existing_data = []

    existing_data.append(log_entry)

    with open(file_name, "w") as f:
        json.dump(existing_data, f, indent=4)


log_file = "dns_resolution_log.json"
print(f"Logging to {log_file}")
print(f"DNS Resolver active at 10.0.0.5:53")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(("10.0.0.5", 53))

while True:
    raw_data, client_address = server_socket.recvfrom(512)
    request_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    resolved_response, query_log, elapsed_time, domain = resolve_iteratively(raw_data)
    status = "SUCCESS" if resolved_response else "FAILED"

    if resolved_response:
        server_socket.sendto(resolved_response, client_address)

    log_entry = {
        "timestamp": request_time,
        "client_ip": client_address[0],
        "queried_domain": domain,
        "resolution_steps": query_log,
        "total_time_ms": elapsed_time,
        "status": status
    }

    write_log(log_file, log_entry)
    print(f"Resolved {domain} in {elapsed_time} ms")