# encoding:utf-8
# Python:3.6+
from dnslib import DNSRecord, RR, QTYPE
from dnslib.server import DNSServer, DNSLogger, BaseResolver
from dnslib.dns import A, AAAA, SOA, TXT, NS, CNAME, DNSLabel
from datetime import datetime
import copy, time, requests, threading, json

RESOLVE_HOSTS_IPV4 = ["127.0.0.1"]
RESOLVE_HOSTS_IPV6 = []
RESOLVE_HOSTS_A = []  # 不要更改 / DO NOT MODIFY
RESOLVE_HOSTS_AAAA = []  # 不要更改 / DO NOT MODIFY
UPSTREAM_DOMAIN = "name.sb"
NS_LIST = ["ns1.name.sb", "ns2.name.sb"]
UPSTREAM_KEY = '@wsxcvfr$'


def get_SOA() -> SOA:
    return SOA(
        mname=NS_LIST[0],
        rname=UPSTREAM_DOMAIN,
        times=(
            int(datetime.now().strftime("%y%m%d%H%M")),
            60 * 60 * 1,
            60 * 60 * 3,
            60 * 60 * 24,
            60 * 60 * 1
        )
    )


def get_ACME_TXT_record(domain) -> list or None:
    resp_raw = requests.get("https://" + UPSTREAM_DOMAIN + '/admin/dns_query', params={'domain': domain},
                            headers={'X-Cat-Key': UPSTREAM_KEY})
    if resp_raw.status_code != 200:
        return None
    resp = resp_raw.json()
    return resp['challenges'] if len(resp['challenges']) != 0 else None


class DomainResolver(BaseResolver):
    def resolve(self, request: DNSRecord, handler):
        reply = request.reply()
        qtype = request.q.qtype
        qname = request.q.qname
        if qtype == QTYPE.A:
            for x in RESOLVE_HOSTS_A:
                reply.add_answer(RR(qname, rtype=QTYPE.A, rdata=x, ttl=300))
        elif qtype == QTYPE.AAAA:
            for x in RESOLVE_HOSTS_AAAA:
                reply.add_answer(RR(qname, rtype=QTYPE.AAAA, rdata=x, ttl=300))
        elif qtype == QTYPE.TXT:
            if qname.label[0].decode().lower() == '_acme-challenge':
                base_domain = b'.'.join(qname.label[1:]).lower().decode('utf-8')
                res = get_ACME_TXT_record(base_domain)
                if res is None:
                    reply.add_answer(RR(qname, rtype=QTYPE.TXT, rdata=TXT("?"), ttl=60))
                else:
                    for x in res:
                        reply.add_answer(RR(qname, rtype=QTYPE.TXT, rdata=TXT(x), ttl=60))
            else:
                reply.add_answer(RR(qname, rtype=QTYPE.TXT, rdata=TXT("123456"), ttl=60))
        elif qtype == QTYPE.NS:
            for x in NS_LIST:
                reply.add_ar(RR(qname, rtype=QTYPE.NS, rdata=NS(x), ttl=300))
        elif qtype == QTYPE.SOA:
            reply.add_answer(RR(qname, rtype=QTYPE.SOA, rdata=get_SOA(), ttl=300))
        return reply


def update_dns_db():
    resp_raw = requests.get('https://' + UPSTREAM_DOMAIN + '/admin/dns_query', params={'all': 1},
                            headers={'X-Cat-key': UPSTREAM_KEY, 'Accept': 'application/json'})
    if resp_raw.status_code != 200:
        print("DNS DB retrieve error:not received")
        return
    try:
        resp = resp_raw.json()
    except json.JSONDecodeError:
        return
    if resp['record']['A'] is not None:
        for x in resp['record']['A']:
            if A(x) not in RESOLVE_HOSTS_A:
                RESOLVE_HOSTS_A.append(A(x))
    if resp['record']['AAAA'] is not None:
        for x in resp['record']['AAAA']:
            if AAAA(x) not in RESOLVE_HOSTS_AAAA:
                RESOLVE_HOSTS_AAAA.append(AAAA(x))
    t = threading.Timer(30, update_dns_db)
    t.setDaemon(True)
    t.start()


def main():
    if len(RESOLVE_HOSTS_IPV6) + len(RESOLVE_HOSTS_IPV4) == 0:
        raise RuntimeError("Please set response IPV4/IPV6 addresses!")
    if len(NS_LIST) == 0 or UPSTREAM_DOMAIN == "":
        raise RuntimeError("Please input your upstream domain and Name servers")
    print('Upstream server:%s' % UPSTREAM_DOMAIN)
    for x in NS_LIST:
        print("Name server:%s" % x)
    update_dns_db()
    resolver = DomainResolver()
    udp_server = DNSServer(resolver, port=53)
    udp_server.start_thread()
    print("DNS started")
    while udp_server.isAlive():
        time.sleep(1)


if __name__ == "__main__":
    main()
