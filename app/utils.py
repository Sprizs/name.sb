from functools import wraps
from flask import session, redirect, url_for, Request, abort, request, jsonify
import requests, json, subprocess, os, secrets
from json import JSONEncoder
from app.model import Offer, User, ChallengeToken, ChallengeReason, Domain, Notification, NotificationType
from app import db, app
from sqlalchemy import desc, exc
from datetime import datetime, date, timedelta


def login_required(func):

    @wraps(func)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for("user.login", redirect=request.path))
        return func(*args, **kwargs)

    return decorated_function


def admin_required(func):
    @wraps(func)
    def decorator(*args, **kwargs):
        try:
            user_now = User.query.filter_by(username=session['username']).first()
            if user_now is None:
                raise KeyError
        except KeyError:
            abort(401)
        if not user_now.have_tag('admin'):
            abort(403)
        return func(*args, **kwargs)

    return decorator


def json_resp_only(func):

    @wraps(func)
    def decorator(*args, **kwargs):
        if "application/json" not in request.headers['Accept']:
            return jsonify({"error": "application/json required in header Accept"}), 400
        return func(*args, **kwargs)

    return decorator


class CustomEncoder(JSONEncoder):
    def default(self, o):
        try:
            if hasattr(o, 'json_object') and callable(getattr(o, 'json_object')):
                return o.json_object()
        except TypeError:
            pass
        return super(CustomEncoder, self).default(o)


def google_recaptcha(req: Request) -> bool:
    recaptcha_resp = requests.post("https://www.recaptcha.net/recaptcha/api/siteverify", data={
        'secret': "6Ldyq1wUAAAAACGHn4IHVzm_-I0thJPRNiXFXI0H",
        'response': req.form['g-recaptcha-response']
    }, timeout=4).json()
    return recaptcha_resp['success'] and recaptcha_resp['hostname'] == req.headers['Host']


def create_challenge(reason: ChallengeReason,
                     validate_period: timedelta = timedelta(minutes=15),
                     commit=True) -> str or None:
    generate_t = 0
    while True:
        generate_t += 1
        if generate_t > 5:
            return None
        token = secrets.token_hex(32)
        try:
            ct_new = ChallengeToken(reason, token, datetime.now() + validate_period)
            db.session.add(ct_new)
            if commit:
                db.session.commit()
        except exc.IntegrityError:
            continue
        else:
            return token


def send_email_mailgun(to, subject, text):
    requests.post('https://api.mailgun.net/v3/%s/messages' % app.config['MAILGUN_DOMAIN'],
                  auth=('api', app.config['MAILGUN_APIKEY']),
                  data={
                      'from': '烧饼米表 Alpha <noreply@mailgun.bupt.moe>',
                      'to': to,
                      'subject': subject,
                      'text': text
                  })


def send_email_sendcloud(to, subject, text):
    # TODO:抛出异常
    raw_resp = requests.post("https://api.sendcloud.net/apiv2/mail/send", data={
        'apiUser': app.config['SENDCLOUD_APIUSER'],
        'apiKey': app.config['SENDCLOUD_APIKEY'],
        'from': app.config['EMAIL_SEND_ADDRESS'],
        'to': to,
        'subject': subject,
        'fromName': '烧饼米表 Alpha <%s>' % app.config['EMAIL_SEND_ADDRESS'],
        'plain': text
    })


def trigger_domain_offer(offer: Offer):
    domain_now = Domain.query.filter_by(name=offer.domain).first()
    if domain_now is None:
        return
    nts = Notification.query.filter_by(username=domain_now.belongs).all()
    for x in nts:
        if x.type == NotificationType.EMAIL:
            send_email_sendcloud(x.address,
                               '%s 的报价' % offer.domain,
                               '时间:%s\n域名:%s\n姓名:%s\n邮箱:%s\n报价:%s' % (
                                   offer.time.strftime("%Y-%m-%d %H:%M:%S"),
                                   offer.domain,
                                   offer.name,
                                   offer.email,
                                   offer.message
                               ))
