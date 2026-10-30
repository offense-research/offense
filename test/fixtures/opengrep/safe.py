import os
import subprocess
import requests
from flask import request, send_from_directory
from werkzeug.utils import secure_filename


def bound_query(cursor):
    cursor.execute('SELECT * FROM users WHERE name = %s', (request.args.get('name'),))
    cursor.execute('SELECT * FROM users WHERE id = ' + str(int(request.args.get('id'))))


def fixed_executable():
    return subprocess.run(['/usr/bin/printf', '%s', request.form.get('message')], shell=False)


def safe_filename():
    filename = secure_filename(request.args.get('name'))
    return open(os.path.join('/srv/reports', filename)).read()


def framework_containment():
    return send_from_directory('/srv/reports', request.args.get('name'))


def fixed_destination(request):
    return requests.post('https://api.example.test/submit', json=request.POST)
