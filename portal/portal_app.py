#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# SIEM Lab - student mission portal (central, multi-team, auto-grading)
#   * serves the 36-question mission with Wazuh query hints
#   * students submit answers; objective questions auto-grade server-side
#   * judgment/discussion questions are stored for instructor grading
#   * per-team progress/score + leaderboard + instructor console
# Answers/accept-lists live ONLY on the server (grading_spec.json). The client
# never receives them. No system commands are executed.
# ============================================================================
import os, re, json, sqlite3, time, threading
from flask import Flask, request, jsonify, session, send_from_directory, g

APP_DIR   = os.path.dirname(os.path.abspath(__file__))
SPEC_PATH = os.environ.get("PORTAL_SPEC", "/opt/siem-lab/answers/grading_spec.json")
DB_PATH   = os.environ.get("PORTAL_DB", "/opt/siem-lab/portal/portal.db")
INSTRUCTOR_KEY = os.environ.get("PORTAL_INSTRUCTOR_KEY", "bridgeworks-instructor")
WAZUH_URL = os.environ.get("PORTAL_WAZUH_URL", "")   # optional explicit dashboard URL

SPEC = json.load(open(SPEC_PATH, encoding="utf-8"))
QByNo = {q["qno"]: q for q in SPEC["questions"]}
_lock = threading.Lock()

app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("PORTAL_SECRET", "siem-lab-portal-secret-change-me")

# ---------------------------------------------------------------- db -------- #
def db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("""CREATE TABLE IF NOT EXISTS sub(
            team TEXT, qno INTEGER, answer TEXT, status TEXT, score INTEGER,
            ts REAL, PRIMARY KEY(team,qno))""")
    return g.db

@app.teardown_appcontext
def _close(e):
    d = g.pop("db", None)
    if d: d.close()

# ------------------------------------------------------------- grading ----- #
def norm(s): return re.sub(r"\s+", " ", (s or "").strip().lower())

def _word(ans_n, tok):
    return re.search(r"(?<!\w)" + re.escape(norm(tok)) + r"(?!\w)", ans_n) is not None

def grade(qno, answer):
    """Return (status, score). status in correct|wrong|manual."""
    q = QByNo[qno]; rule = q["grade"]; m = rule["mode"]
    if m == "manual":
        return ("manual", 0)
    a = norm(answer)
    acc = rule.get("accept", [])
    if m == "contains":
        ok = any(norm(t) in a for t in acc)
    elif m == "word":
        ok = any(_word(a, t) for t in acc)
    elif m == "all":
        ok = all(norm(t) in a for t in acc)
    elif m == "any_n":
        ok = sum(1 for t in acc if norm(t) in a) >= rule.get("n", 1)
    else:
        ok = False
    return ("correct", q["score"]) if ok else ("wrong", 0)

# ------------------------------------------------------- client-safe view -- #
def public_q(q):
    return {k: q[k] for k in ("qno", "section", "type", "sl", "diff", "score",
                              "discuss", "question", "hint", "wazuh")} | \
           {"auto": q["grade"]["mode"] != "manual"}

def team_state(team):
    rows = db().execute("SELECT qno,status,score,answer FROM sub WHERE team=?", (team,)).fetchall()
    return {r["qno"]: {"status": r["status"], "score": r["score"], "answer": r["answer"]} for r in rows}

def team_score(team):
    r = db().execute("SELECT COALESCE(SUM(score),0) s FROM sub WHERE team=?", (team,)).fetchone()
    return r["s"]

# ---------------------------------------------------------------- routes --- #
@app.route("/")
def index():
    return send_from_directory(APP_DIR, "portal.html")

@app.route("/api/config")
def api_config():
    return jsonify(required=SPEC["required"], bonus=SPEC["bonus"], total=SPEC["total"],
                   max_required=sum(q["score"] for q in SPEC["questions"] if q["section"]=="필수"),
                   max_bonus=sum(q["score"] for q in SPEC["questions"] if q["section"]=="보너스"),
                   wazuh_url=WAZUH_URL, team=session.get("team"))

@app.route("/api/login", methods=["POST"])
def api_login():
    name = (request.json or {}).get("team", "").strip()[:40]
    if not name:
        return jsonify(error="팀/이름을 입력하세요"), 400
    session["team"] = name
    return jsonify(team=name)

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.pop("team", None)
    return jsonify(ok=True)

@app.route("/api/questions")
def api_questions():
    team = session.get("team")
    st = team_state(team) if team else {}
    qs = []
    for q in SPEC["questions"]:
        pq = public_q(q)
        s = st.get(q["qno"])
        pq["state"] = ({"status": s["status"], "score": s["score"], "answer": s["answer"]}
                       if s else None)
        qs.append(pq)
    return jsonify(team=team, score=team_score(team) if team else 0, questions=qs)

@app.route("/api/submit", methods=["POST"])
def api_submit():
    team = session.get("team")
    if not team:
        return jsonify(error="먼저 팀 이름으로 시작하세요"), 401
    data = request.json or {}
    qno = int(data.get("qno", 0)); answer = (data.get("answer", "") or "").strip()[:500]
    if qno not in QByNo:
        return jsonify(error="잘못된 문항"), 400
    if not answer:
        return jsonify(error="답안을 입력하세요"), 400
    with _lock:
        d = db()
        prev = d.execute("SELECT status,score FROM sub WHERE team=? AND qno=?",
                         (team, qno)).fetchone()
        if prev and prev["status"] == "correct":
            return jsonify(status="correct", score=prev["score"], locked=True,
                           team_score=team_score(team))
        status, score = grade(qno, answer)
        d.execute("""INSERT INTO sub(team,qno,answer,status,score,ts)
                     VALUES(?,?,?,?,?,?)
                     ON CONFLICT(team,qno) DO UPDATE SET
                       answer=excluded.answer, status=excluded.status,
                       score=excluded.score, ts=excluded.ts""",
                  (team, qno, answer, status, score, time.time()))
        d.commit()
        return jsonify(status=status, score=score, team_score=team_score(team))

@app.route("/api/leaderboard")
def api_leaderboard():
    rows = db().execute("""SELECT team, COALESCE(SUM(score),0) s,
                             SUM(status='correct') solved
                           FROM sub GROUP BY team ORDER BY s DESC, solved DESC LIMIT 30""").fetchall()
    return jsonify(board=[{"team": r["team"], "score": r["s"], "solved": r["solved"]} for r in rows])

# ------------------------------------------------------------ instructor --- #
def _auth_instr():
    return request.args.get("key") == INSTRUCTOR_KEY or \
           (request.json or {}).get("key") == INSTRUCTOR_KEY

@app.route("/api/instructor/submissions")
def api_instr_subs():
    if not _auth_instr(): return jsonify(error="unauthorized"), 403
    rows = db().execute("SELECT team,qno,answer,status,score,ts FROM sub ORDER BY team,qno").fetchall()
    out = []
    for r in rows:
        q = QByNo.get(r["qno"], {})
        out.append({"team": r["team"], "qno": r["qno"], "answer": r["answer"],
                    "status": r["status"], "score": r["score"],
                    "manual": q.get("grade", {}).get("mode") == "manual",
                    "question": q.get("question", ""), "answer_key": q.get("answer", ""),
                    "max": q.get("score", 0)})
    return jsonify(subs=out)

@app.route("/api/instructor/grade", methods=["POST"])
def api_instr_grade():
    if not _auth_instr(): return jsonify(error="unauthorized"), 403
    data = request.json or {}
    team = data.get("team"); qno = int(data.get("qno", 0)); award = int(data.get("award", 0))
    q = QByNo.get(qno)
    if not q or not team: return jsonify(error="bad request"), 400
    award = max(0, min(award, q["score"]))
    with _lock:
        d = db()
        d.execute("""UPDATE sub SET status=?, score=? WHERE team=? AND qno=?""",
                  ("graded", award, team, qno))
        d.commit()
    return jsonify(ok=True, score=award)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORTAL_PORT", "8081")))
