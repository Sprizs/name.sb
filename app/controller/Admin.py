from flask import Blueprint, redirect, render_template, abort, request, jsonify
from app.model import User, UserStatus, Domain, Challenges
from app import db
from app.controller.User import _changepw
from app.utils import login_required, admin_required, json_resp_only
from app.exceptions import *
from app.config import LOCAL_IPV4, LOCAL_IPV6, DNS_SYNC_KEY

bp = Blueprint('admin', __name__)


@bp.route('/')
@login_required
@admin_required
def index():
    return render_template('admin.index.html')


@bp.route('/search_user', methods=["POST"])
@login_required
@admin_required
@json_resp_only
def search_user():
    """
    rest only
    """
    # TODO: 分页
    pat = request.form.get('patten', None)
    is_all = request.form.get('is_all', False, bool)
    if is_all:
        ret = User.query.all()
    else:
        if pat is None:
            abort(400)
        ret = User.query.filter(User.username.like("%%%s%%" % pat)).all()
    return jsonify(ret)


@bp.route('/modify_user', methods=["POST"])
@login_required
@admin_required
@json_resp_only
def modify_user():
    """rest only"""
    username = request.form.get('username')
    user_now = User.query.filter_by(username=username).first_or_404()
    tags = request.form.getlist('tags')
    for x in tags:
        if not isinstance(x, str):
            abort(400)
    user_now.set_tag(tags)
    db.session.add(user_now)
    db.session.commit()
    return jsonify({'msg': "update success"})


@bp.route('/changepw', methods=["POST"])
@login_required
@admin_required
@json_resp_only
def change_password():
    try:
        username = request.form.get('username', None)
        new_pass = request.form.get('new_password', None)
        if username is None or new_pass is None:
            abort(400)
        _changepw(username, new_pass)
    except ObjectNotFoundError:
        return jsonify({'error': 'user not found'}), 404
    else:
        return jsonify({'msg': 'password change success'})


@bp.route('/suspend', methods=["POST"])
@login_required
@admin_required
@json_resp_only
def suspend_account():
    try:
        username = request.form.get('username', None)
        level = request.form.get('level', None, int)
        if username is None or level is None:
            abort(400)
        status_req = UserStatus(level)
        user_now = User.query.filter_by(username=username).first_or_404()
        user_now.status = status_req
        db.session.add(user_now)
        db.session.commit()
        return "", 204
    except ValueError:
        abort(400)


@bp.route('/delete_user', methods=['POST'])
@login_required
@admin_required
@json_resp_only
def delete_account():
    try:
        username = request.form.get('username', None)

    except:
        pass


@bp.route('/dns_query')
def dns_query():

    key = request.headers.get('X-Cat-key')
    all = request.args.get('all', False, bool)
    domain = request.args.get('domain', None)
    if key is None or key != DNS_SYNC_KEY:
        abort(403)
    if all:
        domains = Domain.query.all()
        challenges = Challenges.query.all()
        ret = []
        for x in domains:
            ret.append(x.name)
        return jsonify({'record': {'A': LOCAL_IPV4, 'AAAA': LOCAL_IPV6},
                        'domains': ret,
                        'challenges': challenges})
    else:
        if domain is None:
            abort(400)
        challenges = Challenges.query.filter_by(domain=domain).all()
        ret = []
        for x in challenges:
            ret.append(x.txt_record)
        return jsonify({'challenges': ret})
