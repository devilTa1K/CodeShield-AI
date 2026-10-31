import hashlib
import pickle
import subprocess

DB_PASSWORD = "SuperSecret123!"


def get_user(conn, username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return conn.execute(query).fetchall()


def run_report(filename):
    subprocess.call("cat " + filename, shell=True)


def load_session(blob):
    return pickle.loads(blob)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def calculate(expr):
    return eval(expr)
