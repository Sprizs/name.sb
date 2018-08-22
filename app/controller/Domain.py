from flask import Blueprint, request, abort, render_template, session, redirect, url_for, flash, jsonify, Request, \
    Response
from app.model import Domain, PageVisit, Offer, Mibiao, Contact, Certificates, DomainType
from sqlalchemy import desc
from app import db, app
from app.utils import *
from app.config import NGINX_RELOAD_DAEMON_PORT
from app.exceptions import *
from werkzeug.utils import secure_filename
import os, requests, socket, idna
from datetime import datetime, date, timedelta, time
from dnslib import DNSRecord, DNSError

bp = Blueprint('domain', __name__, template_folder='../templates')


@bp.route('/list')
@login_required
def list_domain():
    domains = Domain.query.filter_by(belongs=session['username']).all()
    if 'application/json' in request.headers['Accept']:
        return jsonify(domains)
    return render_template('domain.list.html', domains=domains)


@bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_domain():
    if request.method == "GET":
        return render_template('domain.info.html', method="add")
    elif request.method == "POST":
        try:
            domain = request.form.get('name')
            assign_mibiao = request.form.get('assign_mibiao', None, int)
            if domain is None or domain == "" or len([x for x in domain.split(".") if x != ""]) < 2:
                raise InputValidationError("域名格式不合法")
            domain=domain.strip()
            new_domain = Domain(domain)
            if Domain.query.filter_by(name=request.form['name']).first() is not None:
                raise InputValidationError('域名已存在。如果这是您的域名并且您没有添加，请联系我们')
            new_domain.read_from_form(request.form)
            if new_domain.typeid == '0' or new_domain.typeid == 0:
                new_domain.typeid = None
            new_domain.belongs = session['username']
            if assign_mibiao is None:
                raise InputValidationError('请指定关联的米表或创建米表(-1)')
            elif assign_mibiao == -1:
                db.session.add(new_domain)
                new_mibiao = Mibiao()
                new_mibiao.assign_domain = domain
                db.session.add(new_mibiao)
                db.session.flush()
                new_domain.assign_mibiao = new_mibiao.id
                db.session.add(new_domain)
                db.session.commit()
            else:  # 指定存在的米表
                now_mibiao = Mibiao.query.filter_by(id=assign_mibiao).first()
                if now_mibiao is None:
                    raise InputValidationError('指定的米表不存在')
                domain_chk = Domain.query.filter_by(name=now_mibiao.assign_domain).first()
                if domain_chk is None:
                    raise ServerError('数据库出错，请联系管理员 (#10002)')  # error code: 10002
                if domain_chk.belongs != session['username']:
                    raise InputValidationError("米表编号错误(拒绝访问)")
                new_domain.assign_mibiao = now_mibiao.id
                db.session.add(new_domain)
                db.session.commit()
        except (InputValidationError, ServerError) as e:
            if 'application/json' in request.headers['Accept']:
                return jsonify({'error': e.message}), e.return_code
            flash(e.message, 'error')
            return redirect(url_for('domain.add_domain'))
        else:
            if 'application/json' in request.headers['Accept']:
                return Response(status=201)
            flash('域名成功添加')
            return redirect(url_for('domain.list_domain'))


@bp.route('/add_batch')
@login_required
def add_batch():
    return render_template('domain.add.batch.html')


@bp.route('/modify', methods=['GET', 'POST', 'DELETE'])
@login_required
def modify_domain():
    if request.method == "GET":
        domain_str = request.args.get('domain', None)
        if domain_str is None:
            return redirect(url_for('domain.list_domain'))
        domain = Domain.query.filter_by(name=domain_str, belongs=session['username']).first()
        if domain is None:
            flash('domain %s not exist!' % domain_str, 'error')
            return render_template('domain.list.html')
        return render_template('domain.info.html', method="modify", domain=domain)
    elif request.method == "POST":
        try:
            domain_now = Domain.query.filter_by(name=request.form['name'], belongs=session['username']).first()
            if domain_now is None: raise KeyError
        except KeyError:
            flash('域名未找到', 'error')
            return redirect(url_for('domain.list_domain'))
        assign_mibiao = request.form.get('assign_mibiao', None, int)
        domain_now.read_from_form(request.form)
        if domain_now.typeid == '0' or domain_now.typeid == 0:
            domain_now.typeid = None
        if assign_mibiao is not None:
            mibiao_chk = Mibiao.query.filter_by(id=assign_mibiao).first()
            if mibiao_chk is None:
                flash('米表不存在', 'error')
                return redirect(url_for('domain.list_domain'))
            domain_chk = Domain.query.filter_by(name=mibiao_chk.assign_domain).first()
            if domain_chk is None:
                flash('数据库出错，请联系管理员 (#10001)', 'error')  # error code: 10001
                return redirect(url_for('domain.list_domain'))
            if domain_chk.belongs != session['username']:
                abort(403)
            domain_now.assign_mibiao = assign_mibiao
        db.session.add(domain_now)
        db.session.commit()
        flash('域名更新成功')
        return redirect(url_for('domain.list_domain'))
    elif request.method == "DELETE":
        domain = request.form.get('domain', None)
        if domain is None:
            abort(400)
        else:
            domain = domain.strip()
        domain_now = Domain.query.filter_by(belongs=session['username']).filter_by(name=domain).first_or_404()
        # 检查域名是否为米表域名，若是并且米表有其他域名，拒绝删除
        if domain_now.assign_mibiao is not None:
            mibiao_assigned = Mibiao.query.filter_by(id=domain_now.assign_mibiao).first()
            if mibiao_assigned is not None:
                domains1 = Domain.query.filter_by(assign_mibiao=domain_now.assign_mibiao).all()
                if mibiao_assigned.assign_domain == domain_now.name:
                    if len(domains1) >= 2:  # 如果要删除的域名就是米表绑定域名并且米表所属域名多于1个
                        return jsonify({"error": "米表域名在米表有其他域名时不能被删除"}), 409
                    else:  # 连米表一起删除
                        db.session.delete(mibiao_assigned)
        else:
            raise RuntimeError('assign_mibiao should not be none')
        db.session.delete(domain_now)
        db.session.commit()
        return Response(status=204)


def delete_domain(domain_str: str):
    # TODO: 重做域名删除
    domain_now = Domain.query.filter_by(name=domain_str).first()
    if domain_now is None:
        return


@bp.route('/enable_https', methods=['POST'])
@login_required
def enable_https():
    domain = request.form.get('domain', None)
    is_off = request.form.get('off', 0, int)
    is_off = bool(is_off)
    if domain is None:
        abort(400)
    else:
        domain = domain.strip()
    domain_now = Domain.query.filter_by(name=domain).filter_by(belongs=session['username']).first_or_404()
    domain_idn=idna.encode(domain).decode()
    cert_now = Certificates.query.filter_by(domain=domain_idn).order_by(desc(Certificates.create_time)).first()
    if not is_off and cert_now is None:  # TODO: 过期由另外的daemon解决
        return jsonify({'error': 'No certificate, please visit /cert/get_certificate first'}), 403
    domain_now.https_switch = not is_off
    db.session.add(domain_now)
    db.session.commit()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto("update".encode(), ("localhost", NGINX_RELOAD_DAEMON_PORT))
    except OSError:
        pass
    return jsonify({'msg': 'https %s' % ("off" if is_off else "on")})


def get_hosted_domain_template(host: str, **kwargs):
    if request.path == "/favicon.ico":  # 阻止favicon影响统计
        abort(404)
    domain = Domain.query.filter_by(name=host).first()
    if domain is None:
        abort(418)
    if domain.https_switch and request.scheme == "http":
        return redirect("https://" + host)
    domain = domain.name
    pv = PageVisit(domain, request.remote_addr)
    db.session.add(pv)
    db.session.commit()
    # template_args = {k: v for k, v in template_args.items() if v is not None}
    return render_template("forsale.default.html", domain=domain, **kwargs)


def process_offer(req: Request) -> bool:

    try:
        name = req.form["name"]
        email = req.form["email"]
        msg = req.form["message"]
        if not google_recaptcha(request):
            return False
        new_offer = Offer(req.form.get('domain', None) or req.headers['Host'], email, name, msg)
        new_offer.ip = req.remote_addr
        new_offer.ua_string = req.headers.get('User-Agent', None)
        db.session.add(new_offer)
        db.session.flush()
        trigger_domain_offer(new_offer)
        db.session.commit()
        return True
    except KeyError:
        return False


@bp.route('/stats')
@login_required
def statistics():
    domain_req = request.args.get('domain', None, str)

    def parseDate1(s: str) -> datetime:
        return datetime.strptime(s, "%Y-%m-%d")

    def parseDate2(s: str) -> datetime:
        return datetime.strptime(s, "%Y-%m-%d").replace(hour=23, minute=59, second=59)

    def getBoolean(x) -> bool:
        return bool(int(x))

    date_start_req = request.args.get('start_date', None, parseDate1)
    date_end_req = request.args.get('end_date', None, parseDate2)
    is_detailed = request.args.get('detail', False, getBoolean)
    ignore_date = request.args.get('ignore_date', False, getBoolean)
    if date_start_req is None and date_end_req is None and not ignore_date:
        date_start_req = datetime.now().date()
        date_end_req = date_start_req + timedelta(days=1)
    if domain_req is not None:
        pvs = PageVisit.query.filter(PageVisit.domain == domain_req)
    else:
        pvs = db.session.query(PageVisit, Domain) \
            .filter(PageVisit.domain == Domain.name) \
            .filter(Domain.belongs == session['username']) \
            .with_entities(PageVisit.domain, PageVisit.time, PageVisit.ip)
    if date_start_req is not None:
        pvs = pvs.filter(db.func.date(PageVisit.time) >= date_start_req)
    if date_end_req is not None:
        pvs = pvs.filter(db.func.date(PageVisit.time) <= date_end_req)
    pvs = pvs.all()
    ret = pvs if is_detailed else len(pvs)
    if "application/json" in request.headers['Accept']:
        if ret is None:
            abort(404)
        else:
            return jsonify(ret)
    else:
        if isinstance(ret, list):
            return render_template('stats_iframe.html', stats=ret)
        else:
            return str(ret)


@bp.route('/offer', methods=['GET', 'POST'])
@login_required
def offer():
    if request.method == "GET":
        is_detail = request.args.get('detail', False, bool)
        include_processed = request.args.get('include_processed', False, bool)
        offers = db.session.query(Offer, Domain) \
            .filter(Offer.domain == Domain.name) \
            .filter(Domain.belongs == session['username']) \
            .with_entities(Offer)
        if not include_processed:
            offers = offers.filter(Offer.processed == False)
        offers = offers.all()
        ret = offers
        if not is_detail:
            ret = len(offers)
        if 'application/json' in request.headers['Accept']:
            return jsonify(ret)
        else:
            ret.sort(key=lambda x: x.time, reverse=True)
            return render_template('offer_iframe.html', offers=ret, detail2=include_processed)
    elif request.method == "POST":
        action = request.form.get('action', None)
        oid = request.form.get('id', None)
        now_offer = db.session.query(Domain, Offer) \
            .filter(Offer.domain == Domain.name) \
            .filter(Domain.belongs == session['username']) \
            .filter(Offer.id == oid).with_entities(Offer).first_or_404()
        if action == "processed":
            now_offer.processed = True
            db.session.add(now_offer)
            db.session.commit()
            return jsonify({'msg': 'success marked'})
        else:
            abort(501)


@bp.route('/mibiao', methods=['GET', 'POST'])
@login_required
def mibiao():
    contacts = Contact.query.filter_by(uploader=session['username']).all()
    action = request.args.get('action', None)
    if request.method == "GET":
        mid = request.args.get('id', None, int)
        if action == "add":
            return render_template("mibiao.info.html", contacts=contacts, action="add")
        mbs = db.session.query(Mibiao, Domain) \
            .filter(Domain.belongs == session['username']) \
            .filter(Mibiao.assign_domain == Domain.name).with_entities(Mibiao)
        if mid is None:
            now_mb = mbs.all()
            if "application/json" in request.headers['Accept']:
                return jsonify(now_mb)
            return render_template('mibiao.list.html', mbs=now_mb, contacts=contacts)
        else:
            now_mb = mbs.filter_by(id=mid).first_or_404()
            if "application/json" in request.headers['Accept']:
                return jsonify(now_mb)
            return render_template('mibiao.info.html', mb=now_mb, contacts=contacts)
    elif request.method == "POST":
        mid = request.form.get('id', None, int)
        if mid is not None:
            now_mibiao = db.session.query(Mibiao, Domain).filter(Domain.belongs == session['username']) \
                .filter(Mibiao.assign_domain == Domain.name).filter_by(id=mid).with_entities(Mibiao).first_or_404()
        else:
            now_mibiao = Mibiao()
        if action == "delete":
            try:
                domains = Domain.query.filter_by(assign_mibiao=now_mibiao.id).all()
                if len(domains) > 0:
                    raise InputValidationError('请将绑定在这个米表下面的所有域名转移绑定')
                db.session.delete(now_mibiao)
                db.session.commit()
            except InputValidationError as e:
                flash(e.message, 'error')
                return redirect(url_for("domain.mibiao", id=mid))
            else:
                return redirect(url_for("domain.mibiao"))
        else:
            try:
                now_mibiao.read_from_form(request.form)
                if now_mibiao.contact is None or now_mibiao.contact == "":
                    raise InputValidationError('请选择联系人')
                now_mibiao.contact = int(now_mibiao.contact)
                if now_mibiao.assign_domain is None:
                    abort(400)
                check = Domain.query.filter_by(name=now_mibiao.assign_domain).filter_by(
                    belongs=session['username']).first()
                if check is None:  # 不允许用不存在的域名
                    raise InputValidationError('请使用有效域名')
                if now_mibiao.contact not in [x.id for x in contacts]:  # 米表的联系人应该是自己
                    abort(400)
                db.session.add(now_mibiao)
                db.session.commit()
                flash('米表已添加' if mid is None else '米表已更新')
                return redirect(url_for("domain.mibiao"))
            except InputValidationError as e:
                flash(e.message, 'error')
                if request.method == "POST":
                    return redirect(url_for('domain.mibiao', id=mid))
                return redirect(url_for('domain.mibiao', action="add"))


@bp.route('/mibiao/<string:domain>')
@json_resp_only
def mibiao_public(domain):
    mibiao = Mibiao.query.filter_by(assign_domain=domain).first_or_404()
    contact = Contact.query.filter_by(id=mibiao.contact).first_or_404()
    ret = {
        'title': mibiao.title,
        'description': mibiao.description,
        'contact': {
            'name': contact.name,
            'email': contact.email,
            'phone': contact.phone,
            'wechat': contact.wechat,
            'qq': contact.qq,
            'additional': contact.additional
        },
        'primary_domain': None,
        'sub_domains': [],
        'domain_types': []
    }
    domains = Domain.query.filter_by(assign_mibiao=mibiao.id).all()
    typeids = set()
    for x in domains:
        if x.name == mibiao.assign_domain:
            ret['primary_domain'] = x
        else:
            ret['sub_domains'].append({
                'domain': x.name,
                'description': x.description,
                'typeid': x.typeid
            })
            typeids.add(x.typeid)
    for x in typeids:
        d_type = DomainType.query.filter_by(id=x).first()
        if d_type is not None:
            ret['domain_types'].append({'id': d_type.id, 'text': d_type.text})
    resp = jsonify(ret)
    resp.headers['Access-Control-Allow-Origin'] = "*"
    return resp


@bp.route('/validateNS', methods=['POST'])
@json_resp_only
@login_required
def validate_ns():

    domain = request.form.get('domain', None)
    if domain is not None:
        domain = domain.strip()
    check = Domain.query.filter_by(belongs=session['username']).filter_by(name=domain).first_or_404()
    if request.method == "POST":
        try:
            domain_punycode = idna.encode(domain).decode()
            root_server_resp = DNSRecord.parse(
                DNSRecord.question(domain_punycode, "NS").send("202.12.27.33", timeout=10))
            nic_server = None
            # m.root-servers.net
            for x in root_server_resp.auth + root_server_resp.rr:
                if x.rtype == 2 and x.rname != ".":
                    nic_server = x.rdata.label
            if nic_server is None:
                raise DNSError
            nic_server = str(nic_server)
            dns_resp = DNSRecord.parse(DNSRecord.question(domain_punycode, "NS").send(nic_server, timeout=30))
            success_records = 0
            for x in dns_resp.rr + dns_resp.auth + dns_resp.ar:
                # TODO:这里的NS设为外部config控制
                if (x.rname == domain_punycode or x.rname == domain) \
                        and x.rtype == 2 \
                        and x.rdata.label in ["ns1.name.sb", "ns2.name.sb"]:
                    # qtype 2:NS
                    success_records += 1
                    continue
                else:
                    return jsonify({'error': 'setting error'}), 409
            if success_records < 2:
                return jsonify({'error': 'setting error'}), 409
            check.validated = True
            db.session.add(check)
            db.session.commit()
            return jsonify({'msg': 'success'})
        except socket.timeout:
            return jsonify({'error': 'timeout'}), 504
        except DNSError:
            return jsonify({'error': 'dns query error'}), 408


@bp.route('/domain_type', methods=["GET", "POST"])
@login_required
def domain_type():
    if request.method == "GET":
        owned = request.args.get('owned', None, str)
        try:
            owned = bool(int(owned))
        except (ValueError, TypeError):
            owned = False
            pass
        if owned:
            types = DomainType.query.filter_by(username=session['username']).all()
        else:
            types = db.session.query(DomainType) \
                .filter((DomainType.username == None) | (DomainType.username == session['username'])).all()
        if "application/json" in request.headers['Accept']:
            resp = jsonify(types)
        else:
            resp = str(types)
        resp.headers['Access-Control-Allow-Origin'] = "*"
        return resp
    elif request.method == "POST":
        action = request.args.get('action', None)
        if action == "add":
            text = request.form.get('text', None)
            if text is None or text == "":
                abort(400)
            dt_new = DomainType()
            dt_new.text = text
            dt_new.username = session['username']
            db.session.add(dt_new)
            db.session.flush()
            dts = DomainType.query.filter_by(username=session['username']).all()
            if len(dts) > 5:
                db.session.rollback()
                abort(402)
            for x in dts:
                if x.id != dt_new.id and x.text == dt_new.text:
                    db.session.rollback()
                    abort(409)
            db.session.commit()
        elif action == "edit":
            tid = request.form.get('id', None, int)
            if tid is None:
                abort(400)
            dt_now = DomainType.query.filter_by(id=tid).first_or_404()
            text = request.form.get('text', None)
            if text is None or text == "":
                abort(400)
            dt_now.text = text
            db.session.add(dt_now)
            db.session.commit()
        elif action == "delete":
            tid = request.form.get('id', None, int)
            if tid is None:
                abort(400)
            dt_now = DomainType.query.filter_by(id=tid).first_or_404()
            domains = Domain.query.filter_by(typeid=tid).all()
            for x in domains:
                x.typeid = None
                db.session.add(x)
            db.session.delete(dt_now)
            db.session.commit()
        else:
            abort(400)
        return jsonify({"msg": "Operation successful"})
