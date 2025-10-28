import socket
import time
import sys
from dnslib import DNSRecord, RR
import json

ROOT_SERVERS = [
    "198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13",
    "192.203.230.10","192.5.5.241","192.112.36.4","198.97.190.53",
    "192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42",
    "202.12.27.33"
]

CACHE = {}


def put_cache(rr):
    key = (str(rr.rname).lower(), rr.rtype)
    ttl = rr.ttl if rr.ttl > 0 else 300
    expiry = time.time() + ttl

    record = DNSRecord()
    record.add_answer(RR(rr.rname, rr.rtype, rdata=rr.rdata, ttl=rr.ttl))
    response_bytes = bytes(record.pack())

    CACHE[key] = {
        "response": response_bytes,
        "expiry": expiry
    }


def update_cache_from_response(resp):
    for rr in resp.rr + resp.auth + resp.ar:
        put_cache(rr)


def check_cache(qname, qtype):
    key = (qname.lower(), qtype)
    entry = CACHE.get(key)
    if entry and entry["expiry"] > time.time():
        return entry["response"]
    elif entry:
        del CACHE[key] 
    return None


def iterative_resolve(query_data):
    query = DNSRecord.parse(query_data)
    qname = str(query.q.qname)
    log = []
    start_time = time.time()
    current_servers = ROOT_SERVERS
    response = None
    step = 0
    cache_status = "MISS"

    qtype = query.q.qtype
    cached_response = check_cache(qname, qtype)
    if cached_response:
        cache_status = "HIT"
        log.append({
            "step": 0,
            "mode": "Cache",
            "stage_resolution": "Cached Response",
            "server": "Local Cache",
            "rtt": 0,
            "response": [f"Cached result for {qname} (Type {qtype})"],
            "cache_status": cache_status
        })
        time_taken = (time.time() - start_time) * 1000
        return cached_response, log, round(time_taken, 2), qname

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
                "response": ["No response (timeout)"],
                "cache_status": cache_status
            })
            sock.close()
            break

        sock.close()
        rtt = (recv_time - send_time) * 1000
        resp = DNSRecord.parse(data)
        update_cache_from_response(resp)


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
            "response": response_summary,
            "cache_status": cache_status
        })

        if resp.rr:
            response = data
            # update_cache(qname, response)
            ttl_list = [rr.ttl for rr in resp.rr]
            ttl = min(ttl_list) if ttl_list else 300

            CACHE[(qname.lower(), query.q.qtype)] = {
                "response": response,
                "expiry": time.time() + ttl
            }

            break

        IP = []
        for rr in resp.ar:
            if rr.rtype == 1: #corresponds to the A type
                IP.append(str(rr.rdata))

        if not IP:
            ns_names = [str(rr.rdata) for rr in resp.auth if rr.rtype == 2] # rr.type == 2 means Name Server record
            if not ns_names:
                break

            IP = []
            for ns in ns_names:
                new_query_ = DNSRecord.question(ns)
                new_response, _, _, _ = iterative_resolve(bytes(new_query_.pack()))
                if new_response:
                    parsing_new = DNSRecord.parse(new_response)
                    for rr in parsing_new.rr:
                        if rr.rtype == 1: #A record
                            IP.append(str(rr.rdata))

        if not IP: #empty, break
            break

        current_servers = IP

    time_taken = 1000*(time.time() - start_time)
    return response, log, round(time_taken, 2), qname


def save_log_json(json_file, record):
    try:
        with open(json_file, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []

    data.append(record)

    with open(json_file, "w") as f:
        json.dump(data, f, indent=4)

json_file = "output_PCAP4.json"
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
        print(f"✔ Logged resolution for {qname} ({timetaken} ms)")
