from flask import Flask, render_template, session, request, send_from_directory, Response, redirect, url_for, abort
from .config import BasicConfig, HOSTS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError
from datetime import datetime
import jinja2, sys, idna

try:
    app = Flask(__name__)
    app.config.from_object(BasicConfig)
    db = SQLAlchemy(app)
    db.create_all()
except OperationalError as e:
    print("Error:%s" % e.args[0], file=sys.stderr)
    exit(1)

from .controller.User import bp as user_bp  # should be there for db is created now
from .controller.Domain import bp as domain_bp, get_hosted_domain_template, process_offer
from .controller.Whois import bp as whois_bp
from .controller.Admin import bp as admin_bp
from .controller.Cert import bp as cert_bp
from .model import User, Domain, Mibiao, DomainType, Contact, ChallengeReason, ChallengeToken, NotificationType, \
    Notification
from app.utils import CustomEncoder, login_required
from .exceptions import *

app.register_blueprint(user_bp)
app.register_blueprint(domain_bp, url_prefix="/domain")
app.register_blueprint(whois_bp, url_prefix="/whois")
app.register_blueprint(admin_bp, url_prefix="/admin")
app.register_blueprint(cert_bp, url_prefix='/cert')
app.static_folder = 'static'
my_loader = jinja2.ChoiceLoader([
    app.jinja_loader,
    jinja2.FileSystemLoader(__path__),
])
app.jinja_loader = my_loader
app.json_encoder = CustomEncoder


@app.before_request
def check_header_host():
    host = request.headers.get('Host', None)
    try:
        host = idna.decode(host)
    except idna.IDNAError:
        return Response('域名解码错误，请联系 hrx@bupt.moe',status=500)
    if host not in HOSTS:  # 外部访问的第三方域名
        if request.method == "POST":  # 来提交offer的
            offer_resp = process_offer(request)
            if 'application/json' in request.headers['Accept']:
                return Response(status=204) if offer_resp else Response(status=400)
            else:
                return render_template('forsale.default.html', domain=request.path[1:], offer=offer_resp)
        else:
            domain_now = Domain.query.filter_by(name=host).first()
            if domain_now is None or not domain_now.validated:  # 域名不存在或者NS服务器未验证
                return abort(418)  # TODO: 加一个提醒页面
            mibiao_now = Mibiao.query.filter_by(id=domain_now.assign_mibiao).first_or_404()
            if mibiao_now.assign_domain == host:  # 显示米表
                if request.path == "/":
                    def mibiao_static_get_domains(mibiao):
                        ret = {}
                        domains = Domain.query.filter_by(assign_mibiao=mibiao.id).all()
                        for x in domains:
                            if x.name == mibiao.assign_domain:
                                continue
                            if x.typeid is None:
                                ret.setdefault(0, []).append(x)
                            else:
                                ret.setdefault(x.typeid, []).append(x)
                        keys_old = list(ret.keys())
                        for x in keys_old:
                            d_type = DomainType.query.filter_by(id=x).first()
                            ret['无类型' if d_type is None else d_type.text] = ret[x]
                            del ret[x]
                        return ret

                    return render_template('mibiao_nobase_static.html',
                                           mb=mibiao_now,
                                           page='domains',
                                           d=mibiao_static_get_domains(mibiao_now))
                elif request.path == "/contact":
                    contact_now = Contact.query.filter_by(id=mibiao_now.contact).first()
                    return render_template('mibiao_nobase_static.html',
                                           mb=mibiao_now,
                                           page='contact',
                                           contact=contact_now)
                else:
                    if domain_now is None or not domain_now.validated:  # 域名不存在或者NS服务器未验证
                        return abort(418)  # TODO: 加一个提醒页面
                    return render_template('forsale.default.html', domain=request.path[1:])
            else:
                return redirect('//' + mibiao_now.assign_domain + '/' + host)
        # return get_hosted_domain_template(host)

    else:  # 本机访问
        res = check_token()
        if res:
            return res


def check_token() -> Response or None:
    token1 = session.get('token', None)
    token2 = request.headers.get('X-Cat-Token', None)
    token = None
    if token1 is None and token2 is None:  # normal guest
        session.clear()
        return None
    elif token1 is not None and token2 is not None:
        # TODO: SECURITY ISSUE:client have 2 different token, why?
        session.clear()
        if 'application/json' in request.headers['Accept']:
            return Response(status=400)
        else:
            return redirect(url_for('index'))
    token = token1 if token1 is not None else token2
    user_now = User.token(token)
    if user_now is None:
        # TODO: SECURITY ISSUE:client is attempting to guess token, block if necessary
        session.clear()
        if 'application/json' in request.headers['Accept']:
            return Response(status=401)
        else:
            return redirect(url_for('index'))
    # everything is ok, set session
    session['username'] = user_now.username
    return None


@app.after_request
def add_cors_headers(response: Response):
    if request.method == "GET" and response.content_type in ["application/json"]:
        response.headers.add_header('Access-Control-Allow-Origin', '*')
    return response


@app.route('/')
def index():
    return render_template('index.html', session=session)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', session=session)


@app.route('/static2/<string:filename>')
def static2(filename):
    return send_from_directory('uploaded_templates', filename)


@app.route('/challenge_verify/<string:token>')
def challenge_verify(token):
    # TODO: rate limit necessary?
    ct_now: ChallengeToken = ChallengeToken.query.filter_by(token=token).first_or_404()
    rtn = Response('Verify Success', status=200)
    if ct_now.reason.type == ChallengeReason.EMAIL_VERIFY:
        nt_now = Notification.query.filter_by(type=NotificationType.EMAIL).filter_by(
            address=ct_now.reason.note).first_or_404()
        nt_now.verified = True
        db.session.add(nt_now)
        rtn = redirect(url_for('user.settings'))
    db.session.delete(ct_now)
    db.session.commit()
    return rtn
