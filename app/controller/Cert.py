from flask import request, Blueprint, session, jsonify
from sqlalchemy import desc
from app.model import Challenges, Certificates, Domain
from app import db
from app.utils import json_resp_only, login_required
from datetime import datetime, timedelta
import base64, json, requests, OpenSSL, binascii, hashlib, time, idna
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

KEY1 = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDPgytXhv2mp4JA' \
       '\nABX9imTsRpX7V/TeB3ttoQlJ6Zaik3CYZc0uJjnTQEENVQvaPRLFO3wuSWbLFc8Z\nY8fTGzxuYRcRc+4vB0' \
       '+e2n13r6x5xLIAjVdzzQdDcJDqBbfC8gEMCXX5MJ2/IsVI\nMrtUnr6eSQH1BTUsE94eAO6IdzH3j75BMa2iS21nmUjoyR0bdy' \
       '+8qrTVn0DF+xe4\nEH5qLNLeJdOzA/uJg9Lhtp62PvQZXaD5HP8RXxnTi81OiLatswFQP8Lw2cCAn+3c' \
       '\nvsL2AXjw14HtboPglGVNArynInMCFwd2TXxv4j8ZipDiosVbnXr1yfKANFHhrRIU\nCfwPltCPAgMBAAECggEAN3LtWe4QST' \
       '/pZgCf36fjX99cpFTUcZ++M4UcXku0nKyZ\nIZ/SO8qrGO/Kci2PhTlckqdaf2PNu+aP+FDZTGeytivrZhZ8RsTFWcU4UYr3o3IT' \
       '\nvmIGREM89aBWmLH+cHEKJpVAmN2MyU4ZOTmVJP9mIBWSGE7T7ntAlvPYyU5QY73h\nriDYPnDo8+xmFMwkiMDxqFRw24ycs+BbCP' \
       '/1Q6j3zv8503t7837M0athzuYOUPpp\nlQoAr0r1l4iEjzCqupPI5HBbhn+McrnfOXg328F3J+6V/rdp7M+lcW/8dMZ105TW' \
       '\nm9y3Wrplj3Zv7atpzeeJeG4vWTHkKq/Uxon/YfGEQQKBgQD4FdTdsHXn0SCcoiCS\ndCW3QJD3q11XjG5cTXC5cZPbrBADvqXMZ' \
       '/dur00JVzGPM1OjWgroaXaGeQg3A1sO\n5m23Ptmu3K+bzRcm5Ulf0nWiN30WTZHrhkPfPCZY7N4HqahDK5y7BCbqjnf5vHM' \
       '/\nyOGN98VCtb7oFVY5ExxCCT/19QKBgQDWIfhCrnR2qihM1CImAaOmbUahNuzE2MJt' \
       '\nZGHP6U2ZozA7CijdKkeBE4j948psZbxqoBIfLJd1fsuvNTuLUAFKpkF5X283fyp9\nAaQlrs' \
       '/6I5NJocVQIkX3I5w3N7XSOuw4aUhGDGSq0u/7jDuTPKP14XzpsHpdGdFM\n7F0Xhp5V8wKBgAQmGVE7yjz' \
       '+OlVkQLcySg8ufT4nF4CHULEqemAfjiF2Vy442fz5\nICIxvFATrTh/2z44G0aXvOuyynhhDfzJzbvqySkrd6RbYa' \
       '+81eVMV7tGwkjFM1OF\nA02Qa/PAwlXOeInnCM/32c7CYy9B/4tpiJwfMKVU9MRc1vxNXYOdM/yhAoGADHOv' \
       '\nPxlr9laQv176mWExBgWGvOs3u36rV7clpPR5Kbz+mgBOPgYuYEgliDYN2F3WJhEm' \
       '\n3J84M4HrEEY1LzW4zYF7fzZYfk6rxtcol3Rh7bbR4s9AbReBIAz3EZLwxMfeYq1k\noYYo+HIJuIQAFuDI3Ax/ugskInPU4vc' \
       '/tpWCcZcCgYEAzrrAL5Ch+5V82/FwXeyC\nIq2GI3CtdBv0fFPi6RFXFw33hgHoXHw2kJW5E3gIFSBEyy98oTzlY7zwHLV9PKAE' \
       '\ncwUtKYWwlgC5iZ5Nk5Iv+pnDF4oITKDhAss3/6z7fmV6f8SO656nlONm5Rtc0j3p\njdY1t7opcJQWF+YYDasbMok=\n-----END ' \
       'PRIVATE KEY-----\n '
DIRECTORY_URL = "https://acme-staging.api.letsencrypt.org/directory"
STAGING_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
PRODUCTION_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
BITS = 2048
bp = Blueprint('cert', __name__)


@bp.route('/get_certificate', methods=['POST'])
@login_required
@json_resp_only
def request_certificate():
    try:
        domain = request.form.get('domain', None)
        if domain is not None:
            domain = domain.strip()
        is_ok = Domain.query.filter_by(name=domain).filter_by(belongs=session['username']).first()
        if is_ok is None:
            return jsonify({'error': 'domain non exist!'}), 404
        if not is_ok.validated:
            return jsonify({'error': 'domain not validated'}), 404
        latest_cert = Certificates.query.filter_by(domain=domain).order_by(desc(Certificates.create_time)).first()
        if latest_cert is not None and datetime.now() - latest_cert.create_time < timedelta(days=60):
            return jsonify({'error': 'no reason to issue new certificate, validity over 60 days'}), 429
        privkey = request.form.get('privkey', None)  # PEM encoded
        if latest_cert is not None and privkey is None:
            privkey = latest_cert.certificate_key
        client = Client(Account(KEY1, 'hrx@bupt.moe'))
        client.account_register()
        # IDN encode
        domain = idna.encode(domain).decode()
        cert, cert_key = client.obtain_certificate([domain, "www." + domain], privkey)
        cert_now = Certificates(domain, cert, cert_key)
        db.session.add(cert_now)
        db.session.commit()
        return jsonify({}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 403


class Account(object):
    def __init__(self, key, email):
        self.key = key
        self.email = email


class Client(object):
    UA = "Cat.net/acme-client"
    DIRECTORY_URL = PRODUCTION_DIRECTORY_URL
    TIMEOUT = 5
    DIGEST_METHOD = 'sha256'
    ACME_AUTH_STATUS_MAX_CHECK = 5
    ACME_AUTH_STATUS_WAIT = 5

    def __init__(self, account: Account):
        if account is None:
            raise RuntimeError('Account can not be None')
        self.account = account
        try:
            resp = requests.get(self.DIRECTORY_URL, timeout=self.TIMEOUT, headers={'User-Agent': self.UA})
            if resp.status_code not in [200, 201]:
                raise ValueError('get endpoints error')
            endpoints = resp.json()
            self.ACME_GET_NONCE_URL = endpoints['newNonce']
            self.ACME_TOS_URL = endpoints['meta']['termsOfService']
            self.ACME_KEY_CHANGE_URL = endpoints['keyChange']
            self.ACME_NEW_ACCOUNT_URL = endpoints['newAccount']
            self.ACME_NEW_ORDER_URL = endpoints['newOrder']
            self.ACME_REVOKE_CERT_URL = endpoints['revokeCert']
            self.keyid = None
        except:
            exit(1)

    @staticmethod
    def _b64(data: bytes or str) -> str:
        if isinstance(data, str):
            data = data.encode()
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

    @staticmethod
    def stringfy_items(payload):
        if isinstance(payload, str):
            return payload
        for k, v in payload.items():
            if isinstance(k, bytes):
                k = k.decode('utf-8')
            if isinstance(v, bytes):
                v = v.decode('utf-8')
            payload[k] = v
        return payload

    @staticmethod
    def create_key(key_type=OpenSSL.crypto.TYPE_RSA, size=2048) -> bytes:
        key = OpenSSL.crypto.PKey()
        key.generate_key(key_type, size)
        private_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
        return private_key

    def get_keyauthorization(self, dns_token):
        acme_header_jwk_json = json.dumps(self.get_jws_protected_header('GET_THUMBPRINT')['jwk'], sort_keys=True
                                          , separators=(',', ':'))
        acme_thumbprint = self._b64(hashlib.sha256(acme_header_jwk_json.encode('utf-8')).digest())
        acme_keyauthorization = "%s.%s" % (dns_token, acme_thumbprint)
        acme_keyauthorization_base64 = self._b64(hashlib.sha256(acme_keyauthorization.encode("utf-8")).digest())
        return acme_keyauthorization, acme_keyauthorization_base64

    def get_nonce(self):
        resp = requests.get(self.ACME_GET_NONCE_URL, timeout=self.TIMEOUT, headers={'User-Agent': self.UA})
        return resp.headers['Replay-Nonce']

    def get_jws_protected_header(self, url):
        header = {"alg": "RS256", "nonce": self.get_nonce(), "url": url}
        if url in [self.ACME_NEW_ACCOUNT_URL, self.ACME_REVOKE_CERT_URL, 'GET_THUMBPRINT']:
            privkey = load_pem_private_key(self.account.key.encode(), password=None, backend=default_backend())
            public_key_public_numbers = privkey.public_key().public_numbers()
            exponent = "{0:x}".format(public_key_public_numbers.e)
            exponent = "0{0}".format(exponent) if len(exponent) % 2 else exponent
            modulus = "{0:x}".format(public_key_public_numbers.n)
            jwk = {"kty": "RSA", "e": self._b64(binascii.unhexlify(exponent)),
                   "n": self._b64(binascii.unhexlify(modulus))}
            header["jwk"] = jwk
        else:
            header["kid"] = self.keyid
        return header

    def _sign_message(self, message):
        pk = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.account.key.encode())
        return OpenSSL.crypto.sign(pk, message.encode('utf-8'), self.DIGEST_METHOD)

    def _send_signed_request(self, url, payload):
        headers = {'User-Agent': self.UA}
        if payload in ['GET_Z_CHALLENGE', 'DOWNLOAD_Z_CERTIFICATE']:
            resp = requests.get(url, timeout=self.TIMEOUT, headers=headers)
        else:
            payload_base64 = self._b64(json.dumps(payload).encode())
            protected_base64 = self._b64(json.dumps(self.get_jws_protected_header(url)).encode())
            signature_base64 = self._b64(self._sign_message("{0}.{1}".format(protected_base64, payload_base64)))
            data = json.dumps({"protected": protected_base64, "payload": payload_base64, "signature": signature_base64})
            headers.update({'Content-Type': 'application/jose+json'})
            resp = requests.post(url, data=data, timeout=self.TIMEOUT, headers=headers)
        return resp

    def account_register(self):
        payload = {"termsOfServiceAgreed": True, "contact": ["mailto:%s" % self.account.email]}
        resp = self._send_signed_request(self.ACME_NEW_ACCOUNT_URL, payload)
        setattr(self, 'keyid', resp.headers['Location'])
        return resp

    def new_issuance(self, domains):
        ids = []
        for x in domains:
            ids.append({"type": "dns", "value": x})
        payload = {"identifiers": ids}
        url = self.ACME_NEW_ORDER_URL
        resp_raw = self._send_signed_request(url, payload)
        if resp_raw.status_code != 201:
            raise ValueError('error on create new_issuance')
        resp = resp_raw.json()
        return resp['finalize'], resp['authorizations']

    def get_ids_authorization(self, url):
        headers = {'User-Agent': self.UA}
        resp_raw = requests.get(url, timeout=self.TIMEOUT, headers=headers)
        if resp_raw.status_code not in [200, 201]:
            raise ValueError('get_ids_authorization error')
        resp = resp_raw.json()
        ret = {'domain': resp['identifier']['value']}
        for x in resp['challenges']:
            if x['type'] == "dns-01":
                dns_challenge = x
        ret['dns_token'] = dns_challenge['token']
        ret['dns_challenge_url'] = dns_challenge['url']
        ret['url'] = url
        return ret

    def check_authorization_status(self, authorization_url):
        time.sleep(self.ACME_AUTH_STATUS_WAIT)
        check_t = 0
        while True:
            headers = {'User-Agent': self.UA}
            check_resp = requests.get(authorization_url, timeout=self.TIMEOUT, headers=headers)
            auth_status = check_resp.json()['status']
            check_t += 1
            if check_t == self.ACME_AUTH_STATUS_MAX_CHECK:
                raise StopIteration('max check reached')
            if auth_status in ["pending", "valid"]:
                break
            else:
                time.sleep(self.ACME_AUTH_STATUS_WAIT)

    def respond_to_challenge(self, acme_keyauth, dns_challenge_url):
        payload = {'keyAuthorzation': "%s" % acme_keyauth}
        resp_raw = self._send_signed_request(dns_challenge_url, payload)
        return resp_raw

    def send_csr(self, finalize_url, domains, privkey_pem: str):
        x509_req = OpenSSL.crypto.X509Req()
        x509_req.get_subject().CN = domains[0]
        SAN = ', '.join('DNS:' + x for x in domains).encode('utf-8')
        x509_req.add_extensions([OpenSSL.crypto.X509Extension('subjectAltName'.encode('utf-8'),
                                                              critical=False, value=SAN)])
        privkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, privkey_pem.encode())
        x509_req.set_pubkey(privkey)
        x509_req.set_version(2)
        x509_req.sign(privkey, self.DIGEST_METHOD)
        csr = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_ASN1, x509_req)
        resp_raw = self._send_signed_request(finalize_url, {'csr': self._b64(csr)})
        if resp_raw.status_code not in [200, 201]:
            raise ValueError('error in sending csr, return code:%s body:%s' % (resp_raw.status_code, resp_raw.text))
        resp = resp_raw.json()
        return resp['certificate']

    def download_certificate(self, certificate_url):
        resp_raw = self._send_signed_request(certificate_url, payload='DOWNLOAD_Z_CERTIFICATE')
        if resp_raw.status_code not in [200, 201]:
            raise ValueError('error fetching certificate: code=%d resp=%s' % (resp_raw.status_code, resp_raw.content))
        pem_certificate = resp_raw.content.decode('utf-8')
        return pem_certificate

    def obtain_certificate(self, domains: list, certificate_privkey: str = None):
        if len(domains) == 0:
            return
        print("Requested Domain Issue:%s" % str(domains))
        finalize_url, authorizations = self.new_issuance(domains)
        dns_delete = []
        responders = []
        for url in authorizations:
            ids_auth = self.get_ids_authorization(url)
            authorization_url = ids_auth['url']
            dns_name = ids_auth['domain']
            dns_name_idn = idna.encode(dns_name).decode()
            dns_token = ids_auth['dns_token']
            dns_challenge_url = ids_auth['dns_challenge_url']
            acme_keyauthorization, domain_dns_value = self.get_keyauthorization(dns_token)
            new_challenge = Challenges(dns_name_idn, domain_dns_value)
            db.session.add(new_challenge)
            dns_delete.append({'dns_name': dns_name_idn, 'value': domain_dns_value})
            responders.append({
                'authorization_url': authorization_url,
                'acme_keyauthorization': acme_keyauthorization,
                'dns_challenge_url': dns_challenge_url
            })
        db.session.commit()
        for x in responders:
            self.check_authorization_status(x['authorization_url'])
            self.respond_to_challenge(x['acme_keyauthorization'], x['dns_challenge_url'])
        certificate_key = self.create_key().decode() if certificate_privkey is None else certificate_privkey
        certificate_url = self.send_csr(finalize_url, domains, certificate_key)
        certificate = self.download_certificate(certificate_url)
        for x in dns_delete:
            records = Challenges.query.filter_by(domain=x['dns_name']).filter_by(txt_record=x['value']).all()
            if records is not None:
                for y in records:
                    db.session.delete(y)
        db.session.commit()
        return certificate, certificate_key


if __name__ == "__main__":
    # This is only for testing
    acct = Account(KEY1, "hrx@bupt.moe")
    cl = Client(acct)
    cl.DIRECTORY_URL = STAGING_DIRECTORY_URL
    cl.account_register()
    cert, cert_key = cl.obtain_certificate(['www.osn.me', 'osn.me'])
    cert_now = Certificates("osn.me", cert, cert_key)
    db.session.add(cert_now)
    db.session.commit()
