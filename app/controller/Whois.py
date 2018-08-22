from flask import Blueprint, abort, jsonify, request
from app.utils import login_required
import whois, idna, requests, datetime, socket, re
from whois import WhoisEntry
from whois.whois import NICClient
from dateutil import parser

bp = Blueprint('whois', __name__)
whois_servers = {
    "ci": "whois.nic.ci",
    "im": "whois.nic.im",
    "bid": "whois.nic.bid",
    "bn": "whois.bnnic.bn",
    "by": "whois.cctld.by",
    "ga": "whois.dot.ga",
    "gl": "whois.nic.gl"
}
CREATE_STRING = ["Created On", "Domain Name Commencement Date", "created..............:", "Creation Date",
                 "Registration Time", "Registration date", "Registered on", "Registered", "created",
                 "Fecha de registro", "Domain registered", "Created", "registered", "[登録年月日]", "Activation"]
EXPIRE_STRING = ["Expiry", "Expiration Date", "[有効期限]", "Expires"]
MANUAL_WHOIS = ["gop", "hn", "hr", "ma"]
as_re_registrar = re.compile("Registrar:(\\s*)(.*)$", re.M)
as_re_regdate = re.compile("Registered on (.*)$", re.M)
bd_re_regdate = re.compile("<th.*>Activation Date</th>\s*<td>(.*)</td>", re.M)
bd_re_expdate = re.compile("<th.*>Expire Date</th>\s*<td>(.*)</td>", re.M)


def SendAndReceive(remote, port, command):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20)
    s.connect((remote, port))
    s.send(('%s' % command).encode())
    chunks = []
    while True:
        chunk = s.recv(4096)
        if chunk == b'':
            break
        chunks.append(chunk)
    msg_bin = b''.join(chunks)
    s.close()
    return msg_bin.decode(errors="backslashreplace")


def get_text_socket(domain) -> None or str:
    try:
        whois_server = None
        iana_resp = SendAndReceive("whois.iana.org", 43, "%s\r\n" % domain)
        for line in iana_resp.splitlines():
            x = line.split(":", 1)
            if len(x) < 2:
                continue
            attr = x[0].strip()
            val = x[1].strip()
            if attr == "whois":
                whois_server = val
        if whois_server is None:
            return None
        whois_resp = SendAndReceive(whois_server, 43, "%s\r\n" % domain)
        return whois_resp
    except OSError as e:
        print(e)
        return None
    except socket.timeout as e:
        print(e)
        return None


@bp.route('/<string:domain>')
@login_required
def whois_query(domain: str):
    if "application/json" not in request.headers['Accept']:
        abort(400)
    try:
        try:
            domain = domain.lower()
            tld = domain.split(".")[-1]
            tld_puny = idna.encode(tld).decode().lower()
        except IndexError:
            tld = None
        res = {"registrar": None, "creation_date": None, "expiration_date": None}
        if tld in whois_servers.keys():
            nic_client = NICClient()
            text = nic_client.whois_lookup({'whoishost': whois_servers[tld]}, domain.encode('idna'), 0)
            res = WhoisEntry.load(domain, text)
        elif tld in MANUAL_WHOIS or tld_puny.startswith("xn--"):
            text = get_text_socket(domain)
            res = WhoisEntry.load(domain, text)
        elif tld == "to":
            r = requests.get('https://www.tonic.to/whois?%s' % domain)
            for row in r.text.splitlines():
                x = row.split(':', maxsplit=1)
                if len(x) != 2:
                    continue
                if x[0] == "Created on":
                    res["creation_date"] = datetime.datetime.strptime(x[1].strip(), '%a %b %d %H:%M:%S %Y')
                elif x[0] == "Expires on":
                    res["expiration_date"] = datetime.datetime.strptime(x[1].strip(), '%a %b %d %H:%M:%S %Y')
        elif tld == "ph":
            r = requests.get("https://whois.dot.ph/?utf8=✓&search=%s" % domain)
            for row in r.text.splitlines():
                xpt = row.find("Registrar:")
                if xpt != -1:
                    res["registrar"] = row[xpt + 10:].replace('<br>', '')
                    continue
                xpt2 = row.find('var createDate = moment(')
                if xpt2 != -1:
                    res["creation_date"] = parser.parse(row[xpt2 + 25:xpt2 + 45])
                xpt2 = row.find('var expiryDate = moment(')
                if xpt2 != -1:
                    res["expiration_date"] = parser.parse(row[xpt2 + 25:xpt2 + 45])
        elif tld == "as":
            text = get_text_socket(domain)
            registrar = as_re_registrar.search(text)
            regdate = as_re_regdate.search(text)
            res['registrar'] = registrar.group(2) if registrar is not None else None
            res['creation_date'] = parser.parse(regdate.group(1)) if regdate is not None else None
        elif tld == "ax":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("created") != -1:
                    res['creation_date'] = datetime.datetime.strptime(x[1].strip(), "%d.%m.%Y")
                if x[0].find("expires") != -1:
                    res['expiration_date'] = datetime.datetime.strptime(x[1].strip(), "%d.%m.%Y")
                if x[0].find("registrar") != -1:
                    res['registrar'] = x[1].strip()
        elif tld == "az":
            r = requests.post("http://www.whois.az/cgi-bin/whois.cgi",
                              data={"lang": "en", "dom": ".az", "domain": ".".join(domain.split(".")[:-1])})
            # NO info
        elif tld == "bd":
            # TODO: csrfPrevention
            r = requests.post("http://bdia.btcl.com.bd/DomainChecker.do?mode=checkDomain",
                              data={'csrfPreventionSalt': 'nMLMAfDhyXDG3XZxpdPr', 'domainName': 'google.com',
                                    'domainExt': '1'},
                              headers={
                                  'Referer': 'http://bdia.btcl.com.bd/domain/domainQueryForBuy/searchDomain.jsp',
                                  'Cookie': 'JSESSIONID=B38CF898EA4B08B5A90678712BB401DD'
                              })
            if r.status_code == 200:
                regdate = bd_re_regdate.search(r.text)
                expdate = bd_re_expdate.search(r.text)
                res['creation_date'] = datetime.datetime.strptime(regdate.group(1), "%d/%m/%Y") \
                    if regdate is not None else None
                res['expiration_date'] = datetime.datetime.strptime(expdate.group(1), "%d/%m/%Y") \
                    if expdate is not None else None
        elif tld == "be":
            txt = get_text_socket("google.be")
            regdate = re.search("Registered:(.*)", txt)
            if regdate is not None:
                res['creation_date'] = datetime.datetime.strptime(regdate.group(1).strip(), "%a %b %d %Y")
            registrar = re.search("Registrar:(.*)\n(.*)Name:(.*)", txt)
            if registrar is not None:
                res['registrar'] = registrar.group(3).strip()
        elif tld == "bo":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Fecha de registro") != -1:
                    res['creation_date'] = datetime.datetime.strptime(x[1].strip(), "%Y-%m-%d")
                if x[0].find("Fecha de vencimiento") != -1:
                    res['expiration_date'] = datetime.datetime.strptime(x[1].strip(), "%Y-%m-%d")
        elif tld == "br":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("created") != -1 and res['creation_date'] is None:
                    res['creation_date'] = datetime.datetime.strptime(x[1].strip()[:8], "%Y%m%d")
                if x[0].find("expires") != -1 and res['expiration_date'] is None:
                    res['expiration_date'] = datetime.datetime.strptime(x[1].strip()[:8], "%Y%m%d")
        elif tld == "bt":
            r = requests.post("https://www.nic.bt/twhois/whoiss.php",
                              data={'dname': ".".join(domain.split(".")[:-1]), 'dsext': 'bt'})
            if r.status_code == 200:
                regdate = re.search("Creation date.*?:(.*)</td>", r.text)
                expdate = re.search("Expiration date.*?:(.*)</td>", r.text)
                registrar = re.search("Registrar.*?:(.*)</td>", r.text)
                if regdate is not None:
                    res['creation_date'] = parser.parse(regdate.group(1))
                if expdate is not None:
                    res['expiration_date'] = parser.parse(expdate.group(1))
                if registrar is not None:
                    res['registrar'] = registrar.group(1)
        elif tld in ["cf", "gq", "ml", "tk"]:
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Domain registered") != -1:
                    res['creation_date'] = datetime.datetime.strptime(x[1].strip(), "%m/%d/%Y")
                if x[0].find("Record will expire on") != -1:
                    res['expiration_date'] = datetime.datetime.strptime(x[1].strip()[:8], "%m/%d/%Y")
        elif tld == "cl":
            text = get_text_socket(domain)
            res = WhoisEntry.load(domain, text)
            res['registrar'] = re.search("Registrar name:(.*)", text).group(1)
        elif tld == "cm":
            # FIXME: not tested
            text = get_text_socket(domain)
            res['registrar'] = re.search("Registrar name:(.*)", text).group(1)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Created") != -1:
                    res['creation_date'] = datetime.datetime.strptime(x[1].strip()[:-3], "%d %b %Y %H:%M")
                if x[0].find("Expires") != -1:
                    res['expiration_date'] = datetime.datetime.strptime(x[1].strip()[:-3], "%d %b %Y %H:%M")
        elif tld == "cn":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Registration Time") != -1:
                    res['creation_date'] = parser.parse(x[1])
                if x[0].find("Expiration Time") != -1:
                    res['expiration_date'] = parser.parse(x[1])
                if x[0].find("Sponsoring Registrar") != -1:
                    res['registrar'] = x[1].strip()
        elif tld == "coop":
            r = requests.get("http://www.coop/whois/?ds=google",
                             headers={'referer': 'http://www.coop/whois/?ds=google',
                                      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36'})
            loc1 = r.text.find("<pre>")
            loc2 = r.text.find("</pre>")
            res = WhoisEntry.load(domain, r.text[loc1 + 5:loc2])
        elif tld == "edu":
            text = get_text_socket(domain)
            res['registrar'] = re.search("Registrant:.*\n\s(.*)", text).group(1)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Domain record activated") != -1:
                    res['creation_date'] = parser.parse(x[1])
                if x[0].find("Expiration Time") != -1:
                    res['expiration_date'] = parser.parse(x[1])
        elif tld == "ee":
            text = get_text_socket(domain)
            res = WhoisEntry.load(domain, text)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("registered") != -1:
                    res['creation_date'] = parser.parse(x[1])
                if x[0].find("expire") != -1:
                    res['expiration_date'] = parser.parse(x[1])
        elif tld == "fi":
            text = get_text_socket(domain)
            res = WhoisEntry.load(domain, text)
            res['registrar'] = re.search("registrar\..*:\s(.*)", text).group(1)
        elif tld == "fm":
            r = requests.post("https://dot.fm/whois/whoisI.cfm",
                              data={'tld': 'fm',
                                    'submitSearch': 'Check+It!+>',
                                    'domain': ".".join(domain.split(".")[:-1])})
            if r.status_code == 200:
                res = WhoisEntry.load(domain, r.text.replace("<br>", ""))
        elif tld == "ga":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("registered") != -1:
                    res['creation_date'] = datetime.datetime.strptime(x[1].strip(), "%m/%d/%Y")
                if x[0].find("expire on") != -1:
                    res['expiration_date'] = datetime.datetime.strptime(x[1].strip(), "%m/%d/%Y")
        elif tld in ["gg", "je"]:
            text = get_text_socket(domain)
            res['registrar'] = re.search("Registrar.*:\n\s*(.*)\s*", text).group(1)
            res['creation_date'] = parser.parse(re.search("Registered on (.*)\s*", text).group(1))
        elif tld == "gh":
            r = requests.get("http://www.nic.gh/whois.php?domain=%s" % domain)
            loc1 = r.text.find("<pre>")
            loc2 = r.text.find("</pre>")
            res = WhoisEntry.load(domain, r.text[loc1 + 5:loc2])
        elif tld == "gm":
            r = requests.get("http://www.nic.gm/htmlpages/whois/%s.htm" % ".".join(domain.split(".")[:-1]))
            if r.status_code == 200:
                res['registrar'] = re.search("Registrar.*?:(.*)", r.text).group(1) \
                    .replace("<B>", "").replace("</B>", "").strip()
                res['creation_date'] = datetime.datetime.strptime(
                    re.search("Registration date:.*?<[bB]>(.*)</[bB]>", r.text).group(1), "%d.%m.%Y")
        elif tld == "gt":
            r = requests.get("https://www.gt/sitio/whois.php?dn=%s.&lang=en" % domain)
            if r.status_code == 200:
                res['expiration_date'] = datetime.datetime.strptime(
                    re.search("<strong>\s*Exp.*?:\s*(.*?)\s*</strong>", r.text, re.M | re.DOTALL).group(1)
                    , "%Y-%b-%d %H:%M:%S")
        elif tld == "hk":
            text = get_text_socket(domain)
            res = WhoisEntry.load(domain, text)
            res['registrar'] = re.search("Registrar Name:(.*)", text).group(1).strip()
        elif tld == "id":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Created On") != -1:
                    res['creation_date'] = parser.parse(x[1].strip())
                if x[0].find("Expiration Date") != -1:
                    res['Expiration Date'] = parser.parse(x[1].strip())
                if x[0].find("Sponsoring Registrar Organization") != -1:
                    res['registrar'] = x[1].strip()
        elif tld == "ie":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Registration Date") != -1:
                    res['creation_date'] = parser.parse(x[1].strip())
                if x[0].find("Renewal Date") != -1:
                    res['Expiration Date'] = parser.parse(x[1].strip())
        elif tld in ["in", "io"]:
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Creation Date") != -1:
                    res['creation_date'] = parser.parse(x[1].strip())
                if x[0].find("Registry Expiry Date") != -1:
                    res['Expiration Date'] = parser.parse(x[1].strip())
                if x[0].find("Registrar") != -1:
                    res['registrar'] = x[1].strip()
        elif tld == "ir":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("expire-date") != -1:
                    res['expiration_date'] = parser.parse(x[1].strip())
                    break
        elif tld == "jp":
            text = SendAndReceive("whois.jprs.jp", 43, "%s/e\r\n" % domain)
            if domain.endswith(".co.jp"):
                res['expiration_date'] = parser.parse(re.search("\[State\].*?\((.*)\)", text).group(1))
                res['creation_date'] = parser.parse(re.search("\[Registered Date\](.*)", text).group(1).strip())
            else:
                res['creation_date'] = parser.parse(re.search("\[Created on\](.*)", text).group(1).strip())
                res['expiration_date'] = parser.parse(re.search("\[Expires on\](.*)", text).group(1).strip())
        elif tld == "kg":
            text = get_text_socket(domain)
            res['creation_date'] = parser.parse(re.search("Record created:(.*)", text).group(1).strip())
            res['expiration_date'] = parser.parse(re.search("Record expires on:(.*)", text).group(1).strip())
            res['registrar'] = re.search("Technical.*?Name:(.*?)[\n\r]", text, re.M | re.DOTALL).group(1).strip()
        elif tld == "kz":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Domain created") != -1:
                    res['creation_date'] = parser.parse(x[1].strip()[:-10])
                if x[0].find("Current Registar") != -1:
                    res['registrar'] = x[1].strip()
        elif tld == "lc":
            r = requests.post("http://www.nic.lc/tools/whois.cgi", data={"input": domain})
            loc1 = r.text.find("<pre>")
            loc2 = r.text.find("</pre>")
            res = WhoisEntry.load(domain, r.text[loc1 + 5:loc2])
        elif tld in ["ls", "mk", "tz"]:
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("registered") != -1 and res['creation_date'] is None:
                    res['creation_date'] = datetime.datetime.strptime(x[1].strip(), "%d.%m.%Y %H:%M:%S")
                if x[0].find("expire") != -1 and res['expiration_date'] is None:
                    res['expiration_date'] = datetime.datetime.strptime(x[1].strip(), "%d.%m.%Y")
                if x[0].find("registrar") != -1 and res['registrar'] is None:
                    res['registrar'] = x[1].strip()
        elif tld == "lt":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Registered") != -1 and res['creation_date'] is None:
                    res['creation_date'] = parser.parse(x[1].strip())
                if x[0].find("Expires") != -1 and res['expiration_date'] is None:
                    res['expiration_date'] = parser.parse(x[1].strip())
                if x[0].find("Registrar") != -1 and res['registrar'] is None:
                    res['registrar'] = x[1].strip()
        elif tld == "ly":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Created") != -1 and res['creation_date'] is None:
                    res['creation_date'] = parser.parse(x[1].strip())
                if x[0].find("Expired") != -1 and res['expiration_date'] is None:
                    res['expiration_date'] = parser.parse(x[1].strip())
                if x[0].find("Registrar") != -1 and res['registrar'] is None:
                    res['registrar'] = x[1].strip()
        elif tld == "md":
            text = get_text_socket(domain)
            res = WhoisEntry.load(domain, text)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Created") != -1 and res['creation_date'] is None:
                    res['creation_date'] = parser.parse(x[1].strip())
                    break
        elif tld == "mo":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("created on") != -1 and res['creation_date'] is None:
                    res['creation_date'] = parser.parse(x[1].strip())
                if x[0].find("expires on") != -1 and res['expiration_date'] is None:
                    res['expiration_date'] = parser.parse(x[1].strip())
        elif tld == "mx":
            text = get_text_socket(domain)
            res = WhoisEntry.load(domain, text)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Created On") != -1:
                    res['creation_date'] = parser.parse(x[1].strip())
                    break
        elif tld == "nc":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Created on") != -1 and res['creation_date'] is None:
                    res['creation_date'] = parser.parse(x[1].strip())
                if x[0].find("Expires on") != -1 and res['expiration_date'] is None:
                    res['expiration_date'] = parser.parse(x[1].strip())
                if x[0].find("Registrar") != -1 and res['registrar'] is None:
                    res['registrar'] = x[1].strip()
        elif tld == "nl":
            text = get_text_socket(domain)
            res['registrar'] = re.search("Registrar:.*\n(.*)", text, re.M).group(1).strip()
        elif tld == "no":
            text = get_text_socket(domain)
            res['creation_date'] = parser.parse(re.search("Created:\s*(.*)", text, re.M).group(1))
        elif tld == "pf":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Created") != -1 and res['creation_date'] is None:
                    res['creation_date'] = datetime.datetime.strptime(x[1].strip(), "%d/%m/%Y")
                if x[0].find("Expire") != -1 and res['expiration_date'] is None:
                    res['expiration_date'] = datetime.datetime.strptime(x[1].strip(), "%d/%m/%Y")
                if x[0].find("Registrar Company Name") != -1 and res['registrar'] is None:
                    res['registrar'] = x[1].strip()
        elif tld == "pl":
            text = get_text_socket(domain)
            res = WhoisEntry.load(domain, text)
            res['registrar'] = re.search("REGISTRAR:.*?\n(.*?)\r", text, re.M | re.DOTALL).group(1)
        elif tld == "ro":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Registered On") != -1 and res['creation_date'] is None:
                    res['creation_date'] = parser.parse(x[1].strip())
                if x[0].find("Expires On") != -1 and res['expiration_date'] is None:
                    res['expiration_date'] = parser.parse(x[1].strip())
                if x[0].find("Registrar") != -1 and res['registrar'] is None:
                    res['registrar'] = x[1].strip()
        elif tld == "rs":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Registration date") != -1 and res['creation_date'] is None:
                    res['creation_date'] = datetime.datetime.strptime(x[1].strip(), "%d.%m.%Y %H:%M:%S")
                if x[0].find("Expiration date") != -1 and res['expiration_date'] is None:
                    res['expiration_date'] = datetime.datetime.strptime(x[1].strip(), "%d.%m.%Y %H:%M:%S")
                if x[0].find("Registrar") != -1 and res['registrar'] is None:
                    res['registrar'] = x[1].strip()
        elif tld == "sa":
            text = get_text_socket(domain)
            res['creation_date'] = parser.parse(re.search("Created on:(.*)", text).group(1))
        elif tld == "si":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("created") != -1 and res['creation_date'] is None:
                    res['creation_date'] = parser.parse(x[1].strip())
                if x[0].find("expire") != -1 and res['expiration_date'] is None:
                    res['expiration_date'] = parser.parse(x[1].strip())
                if x[0].find("Registrar") != -1 and res['registrar'] is None:
                    res['registrar'] = x[1].strip()
        elif tld == "sk":
            text = get_text_socket(domain)
            res['registrar'] = re.search("Registrar:.*?[\r\n]*Name:(.*)", text, re.M).group(1).strip()
            res['creation_date'] = parser.parse(re.search("Created:\s*(.*)", text).group(1))
            res['expiration_date'] = parser.parse(re.search("Valid Until:\s*(.*)", text).group(1))
        elif tld == "sn":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Date de création") != -1 and res['creation_date'] is None:
                    res['creation_date'] = parser.parse(x[1].strip())
                if x[0].find("Date d'expiration") != -1 and res['expiration_date'] is None:
                    res['expiration_date'] = parser.parse(x[1].strip())
                if x[0].find("Registrar") != -1 and res['registrar'] is None:
                    res['registrar'] = x[1].strip()
        elif tld == "tf":
            text = get_text_socket(domain)
            res = WhoisEntry(domain, text)
            res['creation_date'] = parser.parse(re.search("created:\s*(.*)", text).group(1))
        elif tld == "th":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Created date") != -1 and res['creation_date'] is None:
                    res['creation_date'] = datetime.datetime.strptime(x[1].strip(), "%d %b %Y")
                if x[0].find("Exp date") != -1 and res['expiration_date'] is None:
                    res['expiration_date'] = datetime.datetime.strptime(x[1].strip(), "%d %b %Y")
                if x[0].find("Registrar") != -1 and res['registrar'] is None:
                    res['registrar'] = x[1].strip()
        elif tld == "tm":
            text = get_text_socket(domain)
            for row in text.splitlines():
                x = row.split(":", 1)
                if len(x) != 2:
                    continue
                if x[0].find("Expiry") != -1 and res['expiration_date'] is None:
                    res['expiration_date'] = parser.parse(x[1].strip())
                    break
        elif tld == "tn":
            text = get_text_socket(domain)
            res['creation_date'] = parser.parse(re.search("Creation date.*?\s(.*)", text).group(1))
            res['registrar'] = re.search("Registrar.*?\s(.*)", text).group(1)
        elif tld == "tr":
            text = get_text_socket(domain)
            t1 = re.search("Created on.*?\s(.*)\.", text)
            t2 = re.search("Expires on.*?\s(.*)\.", text)
            t3 = re.search("Administrative Contact.*?Organ.*?:\s*(.*?)[\n\r]", text, re.DOTALL | re.M)
            if t1 is not None:
                res['creation_date'] = parser.parse(t1.group(1))
            if t2 is not None:
                res['expiration_date'] = parser.parse(t2.group(1))
            if t3 is not None:
                res['registrar'] = t3.group(1)
        elif tld == "tt":
            r = requests.post("https://www.nic.tt/cgi-bin/search.pl", data={"name": domain, "Search": "Search"})
            if r.status_code == 200:
                res['creation_date'] = parser.parse(
                    re.search("<td>Registration Date</td>.*?(\r\n|\r|\n)*?<td>(.*?)</td>", r.text, re.M).group(2))
                res['expiration_date'] = parser.parse(
                    re.search("<td>Expiration Date</td>.*?(\r\n|\r|\n)*?<td>(.*?)</td>", r.text, re.M).group(2))
        elif tld == "tw":
            text = get_text_socket(domain)
            t2 = re.search("Record expires on\s*(.*)\s*\(", text)
            t1 = re.search("Record created on\s*(.*)\s*\(", text)
            t3 = re.search("Registration Service Provider:(.*)", text)
            if t1 is not None:
                res['creation_date'] = parser.parse(t1.group(1))
            if t2 is not None:
                res['expiration_date'] = parser.parse(t2.group(1))
            if t3 is not None:
                res['registrar'] = t3.group(1).strip()
        elif tld == "ua":
            text = get_text_socket(domain)
            t1 = re.search("created:\s*(.*)", text)
            t2 = re.search("expires:\s*(.*)", text)
            t3 = re.search("registrar:\s*(.*)", text)
            if t1 is not None:
                res['creation_date'] = parser.parse(t1.group(1))
            if t2 is not None:
                res['expiration_date'] = parser.parse(t2.group(1))
            if t3 is not None:
                res['registrar'] = t3.group(1)
        elif tld == "ug":
            text = get_text_socket(domain)
            t1 = re.search("Registered On:\s*(.*)", text)
            t2 = re.search("Expires On:\s*(.*)", text)
            if t1 is not None:
                res['creation_date'] = parser.parse(t1.group(1))
            if t2 is not None:
                res['expiration_date'] = parser.parse(t2.group(1))
        elif tld == "uk":
            text = get_text_socket(domain)
            t1 = re.search("Registered on:\s*(.*)", text)
            t2 = re.search("Expiry date:\s*(.*)", text)
            t3 = re.search("Registrar:\s*(.*?)\[", text, re.M | re.DOTALL)
            if t1 is not None:
                res['creation_date'] = parser.parse(t1.group(1))
            if t2 is not None:
                res['expiration_date'] = parser.parse(t2.group(1))
            if t3 is not None:
                res['registrar'] = t3.group(1)
        elif tld in ["uy", "ve"]:
            text = get_text_socket(domain)
            t1 = re.search("Fecha de .*:\s*(.*)", text)
            t2 = re.search("Ultima.*:\s*(.*)", text)
            if t1 is not None:
                res['creation_date'] = parser.parse(t1.group(1))
            if t2 is not None:
                res['expiration_date'] = parser.parse(t2.group(1))
        elif tld == "uz":
            text = get_text_socket(domain)
            t1 = re.search("Creation Date:\s*(.*)", text)
            t2 = re.search("Expiration Date:\s*(.*)", text)
            t3 = re.search("Registrar:\s*(.*)", text)
            if t1 is not None:
                res['creation_date'] = parser.parse(t1.group(1))
            if t2 is not None:
                res['expiration_date'] = parser.parse(t2.group(1))
            if t3 is not None:
                res['registrar'] = t3.group(1)
        elif tld == "vi":
            r = requests.post("https://secure.nic.vi/whois-lookup/", data={"domain": domain})
            loc1 = r.text.find("<pre ")
            loc2 = r.text.find("</pre>")
            res = WhoisEntry.load(domain, r.text[loc1 + 5:loc2])
        elif tld == "wf":
            text = get_text_socket(domain)
            res = WhoisEntry.load(domain, text)
            t1 = re.search("created:\s*(.*)", text)
            if t1 is not None:
                res['creation_date'] = datetime.datetime.strptime(t1.group(1).strip(), "%d/%m/%Y")
        else:
            try:
                res = whois.whois(idna.encode(domain).decode())
            except (socket.gaierror, ConnectionError, socket.timeout):  # <tld>.whois-servers.net 解析出错
                text = get_text_socket(idna.encode(domain).decode())
                if text is None:
                    abort(404)
                else:
                    res = WhoisEntry.load(domain, text)
    except ValueError as e:
        abort(500)
    for key in ['creation_date', 'expiration_date', 'registrar']:
        try:
            if isinstance(res[key], list):
                res[key] = res[key][0]
        except KeyError:
            res[key] = None
    ret = {'registrar': res['registrar'],
           'register_time': res['creation_date'].date().strftime('%Y-%m-%d') if res['creation_date'] is not None
           else None,
           'expire_time': res['expiration_date'].date().strftime('%Y-%m-%d') if res['expiration_date'] is not None
           else None}
    return jsonify(ret)
