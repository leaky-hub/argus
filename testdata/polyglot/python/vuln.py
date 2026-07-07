# Deliberately vulnerable appsec fixture. Every issue is planted. DO NOT fix.
import hashlib
import os
import sqlite3
import subprocess


def sql_injection(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # PLANT(py-sqli, min-profile=max, CWE-89): SQL injection via string formatting
    cur.execute("SELECT * FROM users WHERE name = '%s'" % username)
    return cur.fetchall()


def command_injection(host):
    # PLANT(py-cmdi, min-profile=standard, CWE-78): OS command injection via shell=True with concatenation
    return subprocess.check_output("ping -c 1 " + host, shell=True)


def weak_hash(password):
    # PLANT(py-weak-hash, min-profile=standard, CWE-327): weak hash (MD5) over a password (textbook CWE-328; semgrep emits CWE-327)
    return hashlib.md5(password.encode()).hexdigest()


def path_traversal(filename):
    # PLANT(py-path-traversal, min-profile=standard, CWE-22): path traversal via unsanitized user filename joined under a base dir (caught by argus/curated)
    with open(os.path.join("/var/data", filename)) as fh:
        return fh.read()
