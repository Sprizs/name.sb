import requests, idna

with open("tlds") as fp:
    r = requests.post('http://localhost/login', data={'username': 'test1', "password": "test1"})
    cki = r.cookies
    lines = fp.readlines()
    for x in lines:
        if x.startswith("#"):
            continue
        x = x.strip()
        if x.find(".") == -1:
            x = "nic.%s" % x
        x_uni = idna.decode(x)
        r = requests.get("http://localhost/whois/%s" % x, cookies=cki, headers={'Accept': "application/json"})
        try:
            if r.status_code == 200:
                res = r.json()
            else:
                print("%s%s:status:%d" % (x, "(%s)" % x_uni if x != x_uni else "", r.status_code))
                continue
        except:
            print("%s%s:json parse error" % x, "(%s)" % x_uni if x != x_uni else "")
        else:
            print("%s%s:%s" % (x, "(%s)" % x_uni if x != x_uni else "", res))
