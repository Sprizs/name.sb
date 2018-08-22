import os

APP_ROOT = os.path.dirname(os.path.abspath(__file__))


class BasicConfig:
    SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://root:root@localhost/index2?charset=utf8mb4"  # mysql addr
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_POOL_SIZE = 20
    SQLALCHEMY_POOL_TIMEOUT = 300
    SECRET_KEY = "test"  # 安装时更改，安装完毕后切勿更改 / Edit on installation, DO NOT change after installation is completed.
    UPLOAD_FOLDER_TPL = os.path.join(APP_ROOT, 'uploaded_templates')
    SERVER_NAME = "localhost"  # 本机域名
    MAILGUN_DOMAIN = os.environ.get("MAILGUN_DOMAIN") or ""
    MAILGUN_APIKEY = os.environ.get('MAILGUN_APIKEY') or ""
    SENDCLOUD_APIUSER = os.environ.get('SENDCLOUD_APIUSER') or ""
    SENDCLOUD_APIKEY = os.environ.get('SENDCLOUD_APIKEY') or ""
    EMAIL_SEND_ADDRESS = ""


# deprecated SERVER_NAME takes everything including routing.
HOSTS = ["localhost", "127.0.0.1", "10.88.88.108"]  # 本机域名，用来识别是否进入系统
# TODO:确定自己的IPV4/IPV6地址
LOCAL_IPV4 = None  # 本机IPV4地址 None or list
LOCAL_IPV6 = None  # 本机IPV6地址 None or list
DNS_SYNC_KEY = "@wsxcvfr$"  # NS服务器同步密钥
NGINX_RELOAD_DAEMON_PORT = 30001  # Nginx Reloader 监听端口
