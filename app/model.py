from datetime import datetime, timedelta
from flask import request
from werkzeug.datastructures import ImmutableDict
from app import db, app
import enum, json, secrets, base64, hashlib


class ReadFormMixin(object):

    ATTRS = []

    def read_from_form(self, form: ImmutableDict):
        for x in self.ATTRS:
            res = form.get(x, None)
            if res == "":
                res = None
            setattr(self, x, res)


# noinspection PyMethodMayBeStatic
class TagMixin(object):
    tag = db.Column(db.TEXT, nullable=True, default="[]")

    def add_tag(self, tag: str) -> None:
        try:
            obj = json.loads(self.tag)
        except json.JSONDecodeError:
            obj = []
        obj.append(tag)
        self.tag = json.dumps(obj)

    def have_tag(self, tag: str) -> bool:
        try:
            obj = json.loads(self.tag)
        except json.JSONDecodeError:
            return False
        return tag in obj

    def delete_tag(self, tag: str) -> None:
        try:
            obj = json.loads(self.tag)
        except json.JSONDecodeError:
            self.tag = json.dumps([])
            return
        obj.remove(tag)
        self.tag = json.dumps(obj)

    def set_tag(self, tags: list) -> None:
        self.tag = json.dumps(tags)


class Domain(db.Model, ReadFormMixin):
    name = db.Column(db.String(128), primary_key=True)  #
    regtime: datetime = db.Column(db.DateTime, nullable=True)
    exptime: datetime = db.Column(db.DateTime, nullable=True)
    registrar = db.Column(db.String(255), nullable=True)
    description = db.Column(db.TEXT, nullable=True)
    belongs = db.Column(db.String(128), db.ForeignKey('user.username'))
    typeid = db.Column(db.Integer, db.ForeignKey('domain_type.id'), nullable=True)
    https_switch = db.Column(db.Boolean, default=False)
    validated = db.Column(db.Boolean, default=False, nullable=False)
    assign_mibiao = db.Column(db.Integer, db.ForeignKey("mibiao.id"))
    # assign_mibiao 不能为空，为了防止首次添加失败数据库里未限定
    # assign_mibiao 从Controller处理，不计入read_from_form
    ATTRS = ["name", "regtime", "exptime", "registrar", "description", "typeid"]

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<Domain %s>' % self.name

    def read_from_form(self, form: ImmutableDict):
        super().read_from_form(form)
        domain = form.get('domain', None)
        if domain is not None and domain != "":
            self.name = domain

    def json_object(self):
        return {
            'name': self.name,
            'regtime': None if self.regtime is None else self.regtime.date().isoformat(),
            'exptime': None if self.regtime is None else self.exptime.date().isoformat(),
            'description': self.description, 'belongs': self.belongs, 'assign_mibiao': self.assign_mibiao,
            'https_switch': self.https_switch, 'validated': self.validated, 'registrar': self.registrar,
            'typeid': self.typeid
        }


class EnumAsInteger(db.TypeDecorator):
    impl = db.Integer  # underlying database type

    def __init__(self, enum_type):
        super(EnumAsInteger, self).__init__()
        self.enum_type = enum_type

    def process_bind_param(self, value, dialect):
        if isinstance(value, self.enum_type):
            return value.value
        raise ValueError('expected %s value, got %s'
                         % (self.enum_type.__name__, value.__class__.__name__))

    def process_result_value(self, value, dialect):
        return self.enum_type(value)

    def copy(self, **kwargs):
        return EnumAsInteger(self.enum_type)


class UserStatus(enum.IntEnum):
    ACTIVE = 1  # 正常
    SUSPENDED = 2  # 被暂停服务
    BANNED = 3  # 被封禁


class User(db.Model, TagMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(128), unique=True, nullable=False)
    password = db.Column(db.String(255))
    status = db.Column(EnumAsInteger(UserStatus), default=1, nullable=False)
    domains = db.relationship('Domain', lazy='dynamic')
    notifications = db.relationship('Notification', lazy='dynamic')

    def __init__(self, username):
        self.username = username

    def __repr__(self):
        return '<User %s>' % self.username

    def set_password(self, password: str):
        salt = secrets.token_hex(8)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        dk_b64 = base64.b64encode(dk).decode()
        self.password = "sha256$%s$%s$%d" % (dk_b64, salt, 100000)

    def check_password(self, password) -> bool:
        try:
            hashfunc, dk_b64, salt, iter_cnt = self.password.split('$')
            iter_cnt = int(iter_cnt)
            dk_now = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iter_cnt)
            return dk_now == base64.b64decode(dk_b64)
        except ValueError:
            return False

    def json_object(self):
        return {
            'id': self.id,
            'username': self.username,
            'status': self.status,
            'tags': json.loads(self.tag) if self.tag is not None else None
        }

    @staticmethod
    def token(token: str):
        if token is None: return None
        token_record = SessionKey.query.filter_by(token=token).first()
        if token_record is None or (token_record.expire_time is not None and token_record.expire_time < datetime.now()):
            return None
        return User.query.filter_by(username=token_record.username).first()

    def generate_token(self, validate_time: timedelta = None) -> str:  # 256bit @ base64
        new_token = SessionKey(self.username, validate_time)
        db.session.add(new_token)
        db.session.commit()
        return new_token.token


class MibiaoTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(30), unique=True)
    __tablename__ = "mibiao_template"

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<Template %s>' % self.display_name


class PageVisit(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain = db.Column(db.String(255), nullable=False)
    time = db.Column(db.DateTime, nullable=False, default=datetime.now())
    ip = db.Column(db.String(50), nullable=True)

    def __init__(self, domain, ip=None):
        self.domain = domain
        self.ip = ip
        self.time = datetime.now()

    def __repr__(self):
        return '<PageVisit %s>' % self.domain

    def json_object(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'time': self.time.isoformat(),
            'ip': self.ip
        }


class Offer(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=True)
    domain = db.Column(db.String(255), nullable=False)
    time = db.Column(db.DateTime)
    email = db.Column(db.String(255), nullable=False)
    message = db.Column(db.TEXT, nullable=True)
    ip = db.Column(db.String(50), nullable=True)
    ua_string = db.Column(db.TEXT, nullable=True)
    processed = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, domain, email, name=None, msg=None):
        self.domain = domain
        self.email = email
        self.name = name
        self.message = msg
        self.processed = False
        self.time = datetime.now()

    def __repr__(self):
        return '<Offer To:%s>' % self.domain

    def json_object(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'time': self.time.isoformat(),
            'name': self.name,
            'email': self.email,
            'message': self.message,
            'ua_string': self.ua_string,
            'processed': self.processed
        }


class Contact(db.Model, ReadFormMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uploader = db.Column(db.String(128), db.ForeignKey("user.username"), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(255), nullable=True)
    wechat = db.Column(db.String(255), nullable=True)
    qq = db.Column(db.String(255), nullable=True)
    additional = db.Column(db.TEXT, nullable=True)
    ATTRS = ['name', 'email', 'phone', 'wechat', 'qq', 'additional']

    def __init__(self, uploader):
        self.uploader = uploader
        for x in self.ATTRS:
            setattr(self, x, None)


class Mibiao(db.Model, ReadFormMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255))
    description = db.Column(db.TEXT)
    contact = db.Column(db.Integer, db.ForeignKey("contact.id"), nullable=True)
    assign_domain = db.Column(db.String(128), unique=True, nullable=False)
    ATTRS = ["title", "description", "contact", "assign_domain"]

    def __init__(self):
        pass

    def json_object(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'contact': self.contact,
            'assign_domain': self.assign_domain
        }


class SessionKey(db.Model):
    username = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(50), nullable=False, primary_key=True)
    expire_time = db.Column(db.DateTime, nullable=True)  # always if null

    def __init__(self, username, lifetime: timedelta = None):
        self.username = username
        self.token = base64.b64encode(secrets.token_bytes(32))
        self.expire_time = None
        if lifetime is not None:
            self.expire_time = datetime.now() + lifetime


class NotificationType(enum.IntEnum):
    EMAIL = 1


class Notification(db.Model, ReadFormMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(128), db.ForeignKey('user.username'), nullable=False)
    type = db.Column(EnumAsInteger(NotificationType), nullable=False)
    address = db.Column(db.String(128), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    ATTRS = ["address"]
    __table_args__ = (
        db.UniqueConstraint('type', 'address', name='unique_ADDR'),
    )

    def json_object(self):
        return {'id': self.id, 'username': self.username, 'type': self.type, 'address': self.address,
                'verified': self.verified}


class Certificates(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain = db.Column(db.String(128), nullable=False) # 这里存储的是punycode域名
    certificate = db.Column(db.TEXT, nullable=False)
    certificate_key = db.Column(db.TEXT, nullable=False)
    create_time = db.Column(db.DateTime, nullable=False, default=datetime.now())

    # certificate and key stored in PEM format
    def __init__(self, domain: str, cert: str, cert_key: str):
        self.domain = domain
        self.certificate = cert
        self.certificate_key = cert_key

    def json_object(self):
        return {'id': self.id, 'domain': self.domain, 'certificate': self.certificate,
                'certificate_key': self.certificate_key}


class Challenges(db.Model):
    # 这个是用来验证HTTPS证书的，请不要和ChallengeToken弄混
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    domain = db.Column(db.String(128), nullable=False)
    txt_record = db.Column(db.String(50), nullable=False)

    def __init__(self, domain, txt_record):
        self.domain = domain
        self.txt_record = txt_record

    def json_object(self):
        return {'id': self.id, 'domain': self.domain, 'txt_record': self.txt_record}


class DomainType(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(128), db.ForeignKey("user.username"), nullable=True)
    # username 放空即为默认类型，由管理员管理
    text = db.Column(db.TEXT)

    def json_object(self):
        return {'id': self.id, 'text': self.text}


class ChallengeReason(object):
    PLACEHOLDER = 0
    EMAIL_VERIFY = 1

    def __init__(self, ctype, note):
        self.type = ctype
        self.note = note


class ChallengeToken(db.Model):
    token = db.Column(db.String(64), primary_key=True)
    expire_time = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.PickleType, nullable=False)

    def __init__(self, reason, token, expire_time):
        self.reason = reason
        self.token = token
        self.expire_time = expire_time


class SecurityEventType(enum.IntEnum):
    GENERAL = 0
    REGISTER = 1
    LOGIN = 2
    LOGOUT = 3
    PASSRESET = 4
    CERT_TRY = 5


class SecurityEvents(db.Model):
    # TODO: 记录 注册/登录/登出/修改密码/申请SSL证书
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    time = db.Column(db.DateTime, nullable=False)
    event_type = db.Column(EnumAsInteger(SecurityEventType), nullable=False, default=SecurityEventType.GENERAL)
    ip = db.Column(db.String(45), nullable=True)
    uid = db.Column(db.Integer, nullable=True)
    note = db.Column(db.Text)

    def __init__(self):
        self.time = datetime.now()
