#! /bin/bash
# This project require Python 3.6+
# packages (for Debian):
sudo apt install mysql-server mysql-client gcc python3-dev make libdpkg-perl libmariadbclient-dev virtualenv
wget https://github.com/chriskuehl/python3.6-debian-stretch/releases/download/v3.6.3-1-deb9u1/{python3.6_3.6.3-1.deb9u1_amd64,python3.6-minimal_3.6.3-1.deb9u1_amd64,python3.6-dev_3.6.3-1.deb9u1_amd64,libpython3.6_3.6.3-1.deb9u1_amd64,libpython3.6-minimal_3.6.3-1.deb9u1_amd64,libpython3.6-stdlib_3.6.3-1.deb9u1_amd64,libpython3.6-dev_3.6.3-1.deb9u1_amd64}.deb
sudo dpkg -i *.deb
# 如果是
git clone git@git.tt:icewing/index3.do.git
cd index3.do
virtualenv -p python3.6 venv
source ./venv/bin/activate
pip install -r requirements.txt
pip install uwsgi
#初始化数据库，请自行更改
sudo mysql -uroot -p < init.sql
#venv下，如果系统uwsgi只能使用系统的Python3
#pip install uwsgi
#然后用venv/bin/uwsgi来执行
