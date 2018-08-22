from flask import Blueprint, request, abort, render_template, session, redirect, url_for, flash, jsonify, Response
from app.model import User, UserStatus, Contact, SessionKey, NotificationType, Notification
from app import db
from app.utils import *
from app.exceptions import *
from datetime import datetime, timedelta
from sqlalchemy import exc
import secrets

bp = Blueprint('user', __name__, template_folder='../templates')


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "GET":
        return render_template('register.html')
    elif request.method == "POST":
        if User.query.filter_by(username=request.form['username']).first() is not None:
            flash('用户名已存在', 'error')
            return render_template('register.html'), 409
        new_user = User(request.form['username'])
        new_user.set_password(request.form['password'])
        new_user.status = UserStatus.ACTIVE
        if not google_recaptcha(request):
            flash('验证码错误。如果此错误多次出现请联系我们', 'error')
            return render_template('register.html'), 400
        db.session.add(new_user)
        db.session.commit()
        token = new_user.generate_token()
        session['token'] = token
        flash("您已成功注册！欢迎使用我们的服务")
        return redirect(url_for('dashboard'))


@bp.route('/login', methods=['GET', 'POST'])
def login():
    # TODO: rate limit
    if request.method == "GET":
        if 'username' in session:
            return redirect(url_for('dashboard'))
        return render_template('login.html')
    elif request.method == "POST":
        try:
            user = User.query.filter_by(username=request.form['username']).first()
            if user is None or not user.check_password(request.form['password']):
                raise KeyError
            if UserStatus(user.status) != UserStatus.ACTIVE:
                flash("你的账号现在无法登录，请联系我们", "error")
                return render_template('login.html')
            session['token'] = user.generate_token(timedelta(days=30))
            session['nounce'] = secrets.token_hex(4)
            session['username'] = user.username
            redir = request.args.get('redirect', None)
            if redir is not None:
                return redirect(redir)
            else:
                return redirect(url_for('dashboard'))
        except KeyError:
            flash("用户名密码不匹配", "error")
            return render_template('login.html')


@bp.route('/logout')
@login_required
def logout():
    token_now = SessionKey.query.filter_by(token=session['token']).first()
    db.session.delete(token_now)
    db.session.commit()
    session.clear()
    return redirect(url_for('index'))


@bp.route('/user/contact', methods=["GET", "POST"])
@login_required
def contact():
    action = request.args.get("action", None)
    if request.method == "GET":
        cid = request.args.get("id", None)
        if action == "add":  # 添加联系人
            return render_template("contacts.info.html", action="add")
        if cid is None:  # 查询自己所有联系人
            x = Contact.query.filter_by(uploader=session['username']).all()
            return render_template("contacts.list.html", contacts=x)
        else:  # 查询特定的联系人
            x = Contact.query.filter_by(uploader=session['username']).filter_by(id=cid).first_or_404()
            return render_template("contacts.info.html", contact=x)
    elif request.method == "POST":
        if action == "add":
            cid = request.form.get('id', None)
            if cid is None:
                new_contact = Contact(session['username'])
                new_contact.read_from_form(request.form)
                if new_contact.name is None or new_contact.name == "":
                    flash('联系人必须填写姓名', 'error')
                    return redirect(url_for('user.contact', action="add"))
                db.session.add(new_contact)
                db.session.commit()
                flash('联系人已添加')
            else:
                now_contact = Contact.query.filter_by(uploader=session['username']).filter_by(id=cid).first_or_404()
                now_contact.read_from_form(request.form)
                if now_contact.name is None or now_contact.name == "":
                    flash('联系人必须填写姓名', 'error')
                    return redirect(url_for('user.contact', action="add", id=cid))
                db.session.add(now_contact)
                db.session.commit()
                flash('联系人已更新')
            return redirect(url_for('user.contact'))
        elif action == "delete":
            cid = request.form.get('id', None)
            now_contact = Contact.query.filter_by(uploader=session['username']).filter_by(id=cid).first_or_404()
            db.session.delete(now_contact)
            try:
                db.session.commit()
            except exc.IntegrityError:
                flash('联系人正在被某个米表使用，请更改对应的米表之后再删除联系人', 'error')
                return redirect(url_for('user.contact', id=cid))
            flash('联系人已删除')
            return redirect(url_for('user.contact'))
        else:
            abort(400)


@bp.route('/user/changepw', methods=['POST'])
@login_required
def changepassword():
    if request.method == "POST":
        try:
            req = request.get_json()
            _changepw(session['username'], req['new-password'], req['old-password'])
            token_current = session['token']
            SessionKey.query.filter(SessionKey.token != token_current).delete()
            db.session.commit()
        except ObjectNotFoundError:
            abort(404)
        except (KeyError, TypeError):
            abort(400)
        except AuthenticationError:
            return jsonify({'error': "密码错误"}), 401
        else:
            return Response(status=204)


@bp.route('/user/settings', methods=['GET'])
@login_required
def settings():
    return render_template('user_settings.html')


def _changepw(username, new_password, old_password=None):
    now_user = User.query.filter_by(username=username).first()
    if now_user is None:
        raise ObjectNotFoundError
    if old_password is not None and not now_user.check_password(old_password):
        raise AuthenticationError
    now_user.set_password(new_password)
    db.session.add(now_user)
    db.session.commit()


@bp.route('/user/notification', methods=['GET', 'POST'])
@login_required
def notification():
    if request.method == "GET":
        a = request.args.get('a', None, int)
        if a is not None and a != 0:
            return jsonify({k: v for k, v in NotificationType.__members__.items()})
        nts = Notification.query.filter_by(username=session['username']).all()
        if nts is None:
            abort(404)
        return jsonify(nts)
    elif request.method == "POST":
        action = request.args.get('action', None)
        if action == "add":
            # TODO: rate limit / 60s retry
            try:
                # 如果有未验证的玩意先要求之前验证
                if Notification.query.filter_by(username=session['username']).first() is not None:
                    raise InputValidationError('请先完成之前的验证')
                ntype = request.form.get('type', None, int)
                nt_new = Notification()
                nt_new.read_from_form(request.form)
                if ntype is None:
                    abort(400)
                nt_new.type = NotificationType(ntype)
                nt_new.username = session['username']
                db.session.add(nt_new)
                new_challenge = ChallengeReason(ChallengeReason.PLACEHOLDER, '')
                if nt_new.type == NotificationType.EMAIL:
                    new_challenge.type = ChallengeReason.EMAIL_VERIFY
                    new_challenge.note = nt_new.address
                    token = create_challenge(new_challenge,commit=False)
                    send_email_sendcloud(nt_new.address,
                                       '烧饼米表 邮箱验证请求',
                                       '您好，使用此链接来验证您的邮箱:%s' % url_for('challenge_verify', token=token, _external=True))
                db.session.commit()
            except InputValidationError as e:
                flash(e.message,'error')
                return redirect(url_for('user.notification'))
            except exc.IntegrityError as e:
                abort(409)
            except exc.DBAPIError as e:
                print(e)
                abort(500)
            return jsonify({"msg": "created"}), 201
        else:
            ntid = request.form.get('id', None, int)
            if ntid is None:
                abort(400)
            nt_now = Notification.query.filter_by(id=ntid).first_or_404()
            if action == "delete":
                db.session.delete(nt_now)
                db.session.commit()
                return jsonify({'msg': 'deleted'})
            else:
                abort(400)
