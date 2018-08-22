import requests, re, socket, datetime
from whois import WhoisEntry


def SendAndReceive(remote, port, command):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
    return msg_bin.decode()


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

ga_text="""
Domain name:
      GOOGLE.GA is Active

   Owner contact:
      Organization: Google Inc
      Name:         Mr DNS Admin
      Address:      1600 Amphitheatre  Parkway
      Zipcode:      94043
      City:         Mountain View
      State:        California
      Country:      U.S.A.
      Phone:        +1-650-6234000
      Fax:          +1-650-6188571
      E-mail:       google@domainthenet.net

   Admin contact:
      Organization: Google Inc
      Name:         Mr DNS Admin
      Address:      1600 Amphitheatre  Parkway
      Zipcode:      94043
      City:         Mountain View
      State:        California
      Country:      U.S.A.
      Phone:        +1-650-6234000
      Fax:          +1-650-6188571
      E-mail:       google@domainthenet.net

   Billing contact:
      Organization: Google Inc
      Name:         Mr DNS Admin
      Address:      1600 Amphitheatre  Parkway
      Zipcode:      94043
      City:         Mountain View
      State:        California
      Country:      U.S.A.
      Phone:        +1-650-6234000
      Fax:          +1-650-6188571
      E-mail:       google@domainthenet.net

   Tech contact:
      Organization: Google Inc
      Name:         Mr DNS Admin
      Address:      1600 Amphitheatre  Parkway
      Zipcode:      94043
      City:         Mountain View
      State:        California
      Country:      U.S.A.
      Phone:        +1-650-6234000
      Fax:          +1-650-6188571
      E-mail:       google@domainthenet.net

   Domain Nameservers:
      NS2.GOOGLE.COM
      NS4.GOOGLE.COM
      NS1.GOOGLE.COM
      NS3.GOOGLE.COM

   Domain registered: 06/11/2013
   Record will expire on: 01/31/2019
   Record maintained by: My GA Domain Registry"""
text=ga_text
res={}

print(res)