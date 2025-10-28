import socket
import struct
import random
import time
from datetime import datetime

ROOT_SERVERS = [
    "198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13",
    "192.203.230.10","192.5.5.241","192.112.36.4","198.97.190.53",
    "192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42",
    "202.12.27.33"
]

CACHE = {}
LOG_FILE = "dns_log.txt"
MAX_RECURSION = 5

def decode_name(data, offset):
    labels = []
    jumped = False
    start_offset = offset

    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            pointer = struct.unpack_from("!H", data, offset)[0] & 0x3FFF
            part, _ = decode_name(data, pointer)
            labels.append(part)
            offset += 2
            jumped = True
            break
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode())
            offset += length

    name = ".".join(labels)
    return name, (offset if not jumped else start_offset + 2)

to_print = False

def ret_parse_dns_response(data):
    answers=[]
    authority=[]
    additional=[]
    (tid, flags, qdcount, ancount, nscount, arcount) = struct.unpack_from("!6H", data, 0)
    offset = 12
    if to_print:
        print(f"Transaction ID: {tid:#04x}")
        print(f"Flags: {flags:016b}")
        print(f"Questions: {qdcount}, Answers: {ancount}, Authority: {nscount}, Additional: {arcount}\n")

    for _ in range(qdcount):
        qname, offset = decode_name(data, offset)
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        if to_print: 
            print("questions :::")
            print(f"  QNAME: {qname}, QTYPE: {qtype}, QCLASS: {qclass}")
            print()

    for _ in range(ancount):
        name, offset = decode_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        if rtype == 1 and rdlength == 4:
            ip = ".".join(map(str, rdata))
            if to_print:
                print("answers ::")
                print(f"  {name} -> {ip} (A, TTL={ttl})")
                print()
            answers.append((name,ip,rtype,ttl))
        else:
            if to_print:
                print("answers ::")
                print(f"  {name}, TYPE={rtype}, RDLENGTH={rdlength}")
                print()

    for _ in range(nscount):
        name, offset = decode_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        rdata, _ = decode_name(data, offset)
        offset += rdlength
        if to_print:
            print("auth:")
            
            print(f"  {name} -> {rdata} (NS, TTL={ttl})")
            print()
        if rtype ==2: #NS
            authority.append((name,rdata,rtype,ttl))


    for _ in range(arcount):
        name, offset = decode_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        if rtype == 1 and rdlength == 4:
            ip = ".".join(map(str, rdata))
            if to_print:
                print("additional sec:")
                print(f"  {name} -> {ip} (A, TTL={ttl})")
                print()
            additional.append((name,ip,rtype,ttl))
        else:
            if to_print:
                print("additional sec:")
                print(f"  {name}, TYPE={rtype}, RDLENGTH={rdlength}")
                print()
    return ancount, nscount, arcount,answers, authority, additional


def build_query(domain):
    tid = random.randint(0,65535)
    flags = 0x0100  # standard query
    qdcount = 1
    ancount = nscount = arcount = 0
    header = struct.pack(">HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)
    qname = b''.join(len(p).to_bytes(1,'big') + p.encode() for p in domain.split('.')) + b'\x00'
    question = qname + struct.pack(">HH",1,1)  # QTYPE=A, QCLASS=IN
    return header + question


def query_dns(server_ip, domain):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        query = build_query(domain)
        try:
            start = time.time()
            sock.sendto(query, (server_ip, 53))
            data, _ = sock.recvfrom(4096)
            rtt = time.time() - start
            return data, rtt
        except socket.timeout:
            return None, None
        except Exception:
            return None, None



def log_step(info):
    with open(LOG_FILE,"a") as f:
        f.write(str(info)+"\n")

def resolve_ns_ip(ns_name):
    # data, _ = query_dns(random.choice(ROOT_SERVERS), ns_name)
    for root in ROOT_SERVERS:
        data, _ = query_dns(root, ns_name)
        if data:
            break

    if not data:
        return None
    _, _, _, answers, _, _ = ret_parse_dns_response(data)
    for _, ip, rtype, _ in answers:
        if rtype == 1:
            return ip
    return None


def c_recursive_resolve(domain,current_servers, recursion_depth=0):

    # if domain in CACHE:
    #     print(f"Cache hit for {domain} → {CACHE[domain]}")
    #     return CACHE[domain], True

  
    if recursion_depth > MAX_RECURSION:
        print(f"Max recursion reached for {domain}")
        return None, False

    

    ret=''
    ansflag=False
    while True:
        next_servers = []
        for server in current_servers:
            print(f"Querying {domain} at {server}")
            data, rtt = query_dns(server, domain)
            if data is None:
                print(f"Timeout from {server}")
                continue
            ancount, nscount, arcount,answers, authority, additional=ret_parse_dns_response(data)

            if answers:
                ip=answers[0][1]
                ret=ip
                ansflag=True
                # CACHE[domain] = ret
                return ret,ansflag

      

            if not ansflag:
                if additional:
                    add_ips = [ip for _, ip, _, _ in additional]
                    ret, ansflag = c_recursive_resolve(domain, add_ips, recursion_depth + 1)
                elif authority:
                    ns_names = [ns for _, ns, _, _ in authority]
                    ip_list = []
                    for ns in ns_names:
                        ip = resolve_ns_ip(ns) 
                        if ip: ip_list.append(ip)
                    if ip_list:
                        ret, ansflag = c_recursive_resolve(domain, ip_list, recursion_depth + 1)


            if ansflag == True:
                break
        if ansflag == True:
                break
    return ret,ansflag

def start_dns_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("10.0.0.5", 53))
    print("DNS resolver running on 10.0.0.5:53")
    while True:
        data, addr = s.recvfrom(512)
        qname, _ = decode_name(data, 12)
        print("request from", addr, "for", qname)
        ip, ok = c_recursive_resolve(qname, ROOT_SERVERS[:])
        if ok:
            tid = struct.unpack_from("!H", data, 0)[0]
            flags = 0x8180
            header = struct.pack(">HHHHHH", tid, flags, 1, 1, 0, 0)
            qname_b = b''.join(len(p).to_bytes(1, 'big') + p.encode() for p in qname.split('.')) + b'\x00'
            question = qname_b + struct.pack(">HH", 1, 1)
            answer = b'\xc0\x0c' + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
            packet = header + question + answer
            s.sendto(packet, addr)
            print("sent", ip, "to", addr)
        else:
            print("failed", qname)



if __name__=="__main__":
    start_dns_server()