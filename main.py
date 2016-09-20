from __future__ import unicode_literals

import datetime
import bottle
import bottle_sqlite
import werkzeug.security
import os.path
import sqlite3
import csv
import io
import xml.sax.saxutils


ROOT = os.path.abspath(".")
REALM = "Stempeluhr"
TEMPLATE_PATH = os.path.join(ROOT, "template.html")
DB_PATH = os.path.join(ROOT, "db.sqlite")

app = bottle.Bottle()
plugin = bottle_sqlite.Plugin(dbfile=DB_PATH)
app.install(plugin)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "create table if not exists benutzer (login text primary key, pwhash text not null);")
        conn.execute(
            "create table if not exists log (benutzer_login text not null, utc text not null, bemerkung text, stempel text not null, uhr text);")
        conn.commit()
    finally:
        conn.close()


def benutzer_anlegen(login, passwort):
    pwhash = werkzeug.security.generate_password_hash(
        passwort, "pbkdf2:sha384:100000", 20)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            "insert into benutzer (login,pwhash) values (?,?)", (login, pwhash))
        conn.commit()
    finally:
        conn.close()


def check(db, login, passwort):
    t = db.execute("select pwhash from benutzer where login=?",
                   (login,)
                   ).fetchone()
    if t is None:
        return False
    return werkzeug.security.check_password_hash(t[0], passwort)


def auth(db):
    login, passwort = bottle.request.auth or (None, None)
    if login is None or not check(db, login, passwort):
        err = bottle.HTTPError(401)
        err.add_header(b'WWW-Authenticate', b'Basic realm="%s"' % REALM)
        raise err
    return login


def gen(login, log_rows, uhr):
    with open(TEMPLATE_PATH, "rb") as f:
        i_tpl = f.read().decode("utf-8")
    st = str("stempel")
    t_tpl = '<tr class={cls}><td>{utc}</td><td>{stempel}</td><td>{uhr}</td><td>{bemerkung}</td></tr>'
    tbody = "\n".join(t_tpl.format(cls=xml.sax.saxutils.quoteattr(format(row[st])), **dict((k, xml.sax.saxutils.escape(format(row[k]))) for k in row.keys()))
                      for row in log_rows)
    return i_tpl.format(login=xml.sax.saxutils.escape(login), tbody=tbody, form_check=len(log_rows), uhr=xml.sax.saxutils.escape(uhr))


@app.get("/export.csv")
def export_csv(db):
    login = auth(db)
    log_rows = db.execute(
        "select utc,bemerkung,stempel,uhr from log where benutzer_login=? order by utc desc", (login,)).fetchall()
    f = io.BytesIO()
    w = csv.writer(f)
    w.writerow(("UTC", "Bemerkung", "Stempel", "Stempeluhr"))
    w.writerows([str(i).encode("utf-8") for i in row] for row in log_rows)
    bottle.response.content_type = "text/csv; charset=utf-8"
    return f.getvalue()


@app.get("/export.tsv")
@app.get("/export.tab")
def export_tsv(db):
    login = auth(db)
    log_rows = db.execute(
        "select utc,bemerkung,stempel,uhr from log where benutzer_login=? order by utc desc", (login,)).fetchall()
    out = ["UTC\tBemerkung\tStempel\tStempeluhr"]
    out.extend("\t".join(("" if i is None else str(i).replace("\t", "    "))
                         for i in row) for row in log_rows)
    bottle.response.content_type = "text/tab-separated-values; charset=utf-8"
    return "\r\n".join(out)


@app.get("/")
def index():
    bottle.redirect("/form/Standard/")


@app.get("/form/<uhr>/")
def get(db, uhr):
    login = auth(db)
    log_rows = db.execute(
        "select utc,bemerkung,stempel,uhr from log where benutzer_login=? order by utc desc", (login,)).fetchall()
    return gen(login, log_rows, uhr)


@app.post("/form/<uhr>/")
def post(db, uhr):
    login = auth(db)
    log_rows = db.execute(
        "select utc,bemerkung,stempel,uhr from log where benutzer_login=? order by utc asc", (login,)).fetchall()
    rf = bottle.request.forms
    if int(rf.get("form_check", 0)) != len(log_rows):
        bottle.error(409)
    utc = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    row = (login, utc, rf.get("bemerkung", None), rf.get("stempel", None), uhr)
    db.execute(
        "insert into log (benutzer_login,utc,bemerkung,stempel,uhr) values (?,?,?,?,?)", row)
    log_rows.append(
        dict(zip(("benutzer_login", "utc", "bemerkung", "stempel", "uhr"), row)))
    log_rows.reverse()
    return gen(login, log_rows, uhr)

if __name__ == "__main__":
    bottle.run(app, debug=True)
