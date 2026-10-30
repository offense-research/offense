import os
import pathlib
import subprocess
import requests
from flask import request


def unsafe_sql(cursor):
    name = request.args.get('name')
    # ruleid: purple.python.request-sql-injection
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")


def unsafe_django_sql(request):
    # ruleid: purple.python.request-sql-injection
    User.objects.raw(request.GET.get('query'))


def unsafe_shell():
    command = 'convert ' + request.form.get('filename')
    # ruleid: purple.python.request-command-injection
    subprocess.run(command, shell=True)


def unsafe_os_shell(request):
    # ruleid: purple.python.request-command-injection
    os.system(request.POST.get('command'))


def unsafe_path():
    filename = '/srv/reports/' + request.args.get('name')
    # ruleid: purple.python.request-path-traversal
    return open(filename).read()


def normalized_still_unsafe():
    # ruleid: purple.python.request-path-traversal
    return pathlib.Path(os.path.normpath(request.args.get('name'))).read_text()


def unsafe_proxy(request):
    destination = request.GET.get('url')
    # ruleid: purple.python.request-ssrf
    return requests.get(destination)


def fetch_url(destination):
    # ruleid: purple.python.request-ssrf
    return requests.get(destination)


def proxy_via_helper(request):
    return fetch_url(request.GET.get('url'))
