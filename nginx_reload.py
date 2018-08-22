# encoding:utf-8
# Python:3.6+
import os, subprocess, socketserver, idna
import mysql.connector

NGINX_RELOAD_COMMAND = "sudo systemctl reload nginx"
NGINX_CONFIG_DIRECTORY_FOR_OTHERS = "./cert_cfg/"
PORT = 30001


class ReloadHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.mysql_cnx = mysql.connector.connect(user='index3', password='index3', database='index3')

    def handle(self):
        data = self.request[0].strip()
        print("Received:%s" % str(data))
        try:
            mysql_cnx = mysql.connector.connect(user='index3', password='index3', database='index3')
            query = 'SELECT name AS domain,https_switch AS https FROM domain'
            cursor = mysql_cnx.cursor(buffered=True)
            cursor2 = mysql_cnx.cursor(buffered=True)
            cursor.execute(query)
            result = ""
            for domain, https in cursor:
                https = bool(int(https))
                domain_idn=idna.encode(domain).decode()
                if https:
                    cursor2.execute("SELECT certificate,certificate_key "
                                    "FROM certificates "
                                    "WHERE domain = %s "
                                    "ORDER BY create_time DESC",
                                    (domain_idn,))
                    res = cursor2.fetchone()
                    if res is None:
                        print("%s has no certificate but https set, skipped")
                        continue
                    certificate, certificate_key = res
                    cert_path = NGINX_CONFIG_DIRECTORY_FOR_OTHERS + domain_idn + ".crt"
                    key_path = NGINX_CONFIG_DIRECTORY_FOR_OTHERS + domain_idn + ".key"
                    with open(cert_path, "w") as f:
                        f.write(certificate)
                    with open(key_path, "w") as f:
                        f.write(certificate_key)
                    os.chmod(key_path, 0o600)
                    result += """
server {
    listen 80;
    listen [::]:80;
    server_name %s www.%s;
    return 302 https://$host$request_uri;
}
server {
    listen 443;
    listen [::]:443;
    server_name %s www.%s;
    ssl on;
    ssl_certificate %s;
    ssl_certificate_key %s;
    location / {
        uwsgi_pass unix:/tmp/app.sock;
        include uwsgi_params;
    }
}
        """ % (domain_idn, domain_idn, domain_idn, domain_idn, os.path.abspath(cert_path), os.path.abspath(key_path))
                else:
                    result += """
server {
    listen 80;
    listen [::]:80;
    server_name %s www.%s;
    location / {
        uwsgi_pass unix:/tmp/app.sock;
        include uwsgi_params;
    }
}
        """ % (domain_idn, domain_idn)
            with open(NGINX_CONFIG_DIRECTORY_FOR_OTHERS + "index.conf", "w") as f:
                f.write(result)
            subprocess.run(NGINX_RELOAD_COMMAND, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except PermissionError as e:
            print("Permission Error:" + e.filename)
        except subprocess.CalledProcessError as e:
            print(e.cmd + " error:" + str(e.stderr))
        else:
            print("done")


if __name__ == "__main__":
    with socketserver.UDPServer(("localhost", PORT), ReloadHandler) as server:
        server.serve_forever()
