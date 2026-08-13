#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# SIEM Lab - student mission portal (central, per-user login, gamified grading)
#   * preset individual accounts user_1..user_N (password == username)
#   * 36-question mission; objective questions auto-grade server-side
#   * progressive PAID hints (<=3/q), wrong answers cost more than hints
#   * solution explanation revealed on correct
#   * per-user score/progress + leaderboard + instructor console
# Answers/accept-lists/hints/explanations live ONLY on the server. The client
# receives a hint only when it pays for it, and the explanation only on solve.
# No system commands are executed.
# ============================================================================
import os, re, json, sqlite3, time, threading
from flask import Flask, request, jsonify, session, send_from_directory, g

APP_DIR   = os.path.dirname(os.path.abspath(__file__))
SPEC_PATH = os.environ.get("PORTAL_SPEC", "/opt/siem-lab/answers/grading_spec.json")
DB_PATH   = os.environ.get("PORTAL_DB", "/opt/siem-lab/portal/portal.db")
INSTRUCTOR_KEY = os.environ.get("PORTAL_INSTRUCTOR_KEY", "bridgeworks-instructor")
INSTRUCTOR_USER = os.environ.get("PORTAL_INSTRUCTOR_USER", "admin")
INSTRUCTOR_PASS = os.environ.get("PORTAL_INSTRUCTOR_PASS", "p@ssw0rd")
WAZUH_URL = os.environ.get("PORTAL_WAZUH_URL", "")
WAZUH_USER = os.environ.get("PORTAL_WAZUH_USER", "admin")
WAZUH_PASS = os.environ.get("PORTAL_WAZUH_PASS", "")

USER_COUNT = int(os.environ.get("PORTAL_USERS", "20"))
VALID_USERS = {f"user_{i}" for i in range(1, USER_COUNT + 1)}
def valid_login(u, p): return u in VALID_USERS and p == u

# staged unlock: questions grouped into stages; a stage unlocks when the
# previous one is >= UNLOCK_THRESHOLD done. Instructor can override per user.
STAGE_BREAKS = [int(x) for x in os.environ.get("PORTAL_STAGE_BREAKS", "10,20").split(",")]
UNLOCK_THRESHOLD = float(os.environ.get("PORTAL_UNLOCK_THRESHOLD", "0.6"))
NUM_STAGES = len(STAGE_BREAKS) + 1
STAGE_NAMES = ["1단계 · 기초 조회", "2단계 · 상관·판단", "3단계 · 심화(보너스)",
               "4단계", "5단계"]
def stage_of(qno):
    for i, b in enumerate(STAGE_BREAKS):
        if qno <= b: return i + 1
    return NUM_STAGES
def stage_name(s): return STAGE_NAMES[s-1] if s-1 < len(STAGE_NAMES) else f"{s}단계"

# scoring knobs — wrong costs MORE than a hint (discourage guessing)
WRONG_PENALTY = int(os.environ.get("PORTAL_WRONG_PENALTY", "2"))
HINT_PENALTY  = int(os.environ.get("PORTAL_HINT_PENALTY", "1"))
MAX_HINTS     = 3
SCORE_FLOOR   = 0

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
            hints_used INTEGER DEFAULT 0, wrong_count INTEGER DEFAULT 0,
            ts REAL, PRIMARY KEY(team,qno))""")
        g.db.execute("""CREATE TABLE IF NOT EXISTS umeta(
            team TEXT PRIMARY KEY, override INTEGER DEFAULT 0)""")
    return g.db

# --------------------------------------------------------- staged unlock --- #
def stage_qnos(s):
    return [q["qno"] for q in SPEC["questions"] if stage_of(q["qno"]) == s]
def stage_done(team, s):
    qs = stage_qnos(s)
    if not qs: return 0
    ph = ",".join("?" * len(qs))
    r = db().execute(f"SELECT COUNT(*) c FROM sub WHERE team=? AND qno IN ({ph}) "
                     f"AND status IN ('correct','manual','graded')", [team] + qs).fetchone()
    return r["c"]
def get_override(team):
    r = db().execute("SELECT override FROM umeta WHERE team=?", (team,)).fetchone()
    return r["override"] if r else 0
def unlocked_stage(team):
    if not team: return 1
    u = 1
    for s in range(1, NUM_STAGES):
        qs = stage_qnos(s)
        if qs and stage_done(team, s) / len(qs) >= UNLOCK_THRESHOLD:
            u = s + 1
        else:
            break
    return max(u, get_override(team), 1)

@app.teardown_appcontext
def _close(e):
    d = g.pop("db", None)
    if d: d.close()

def row(team, qno):
    return db().execute("SELECT * FROM sub WHERE team=? AND qno=?", (team, qno)).fetchone()

def upsert(team, qno, **cols):
    cur = row(team, qno)
    base = dict(team=team, qno=qno, answer="", status="in_progress", score=0,
                hints_used=0, wrong_count=0, ts=time.time())
    if cur: base.update({k: cur[k] for k in base if k in cur.keys()})
    base.update(cols); base["ts"] = time.time()
    db().execute("""INSERT INTO sub(team,qno,answer,status,score,hints_used,wrong_count,ts)
        VALUES(:team,:qno,:answer,:status,:score,:hints_used,:wrong_count,:ts)
        ON CONFLICT(team,qno) DO UPDATE SET answer=excluded.answer,status=excluded.status,
        score=excluded.score,hints_used=excluded.hints_used,wrong_count=excluded.wrong_count,
        ts=excluded.ts""", base)
    db().commit()

# ------------------------------------------------------------- grading ----- #
def norm(s): return re.sub(r"\s+", " ", (s or "").strip().lower())
def _word(a, tok): return re.search(r"(?<!\w)"+re.escape(norm(tok))+r"(?!\w)", a) is not None

def grade(qno, answer):
    rule = QByNo[qno]["grade"]; m = rule["mode"]
    if m == "manual": return "manual"
    a = norm(answer); acc = rule.get("accept", [])
    if   m == "contains": ok = any(norm(t) in a for t in acc)
    elif m == "word":     ok = any(_word(a, t) for t in acc)
    elif m == "all":      ok = all(norm(t) in a for t in acc)
    elif m == "any_n":    ok = sum(1 for t in acc if norm(t) in a) >= rule.get("n", 1)
    else:                 ok = False
    return "correct" if ok else "wrong"

def hint_cost(hints):
    # progressive: 1st hint -1, 2nd -2, 3rd -3 ... (scaled by HINT_PENALTY step)
    return HINT_PENALTY * hints * (hints + 1) // 2
def final_score(base, wrongs, hints, correct):
    return max(SCORE_FLOOR, base - wrongs*WRONG_PENALTY - hint_cost(hints)) if correct else 0

# ------------------------------------------------------- client-safe view -- #
def public_q(q):
    out = {k: q.get(k) for k in ("qno","section","type","sl","diff","score",
                                 "discuss","question","fmt")}
    out["auto"] = q["grade"]["mode"] != "manual"
    out["max_hints"] = MAX_HINTS
    return out

def state_of(team, qno):
    r = row(team, qno)
    if not r: return None
    s = {"status": r["status"], "score": r["score"], "answer": r["answer"],
         "hints_used": r["hints_used"], "wrong_count": r["wrong_count"]}
    if r["status"] in ("correct", "manual", "graded"):
        s["explain"] = QByNo[qno]["explain"]           # earned -> reveal
    # reveal the hints already paid for
    s["hints"] = QByNo[qno]["hints"][:r["hints_used"]]
    return s

def team_score(team):
    return db().execute("SELECT COALESCE(SUM(score),0) s FROM sub WHERE team=?", (team,)).fetchone()["s"]

# ---------------------------------------------------------------- routes --- #
@app.route("/")
def index(): return send_from_directory(APP_DIR, "portal.html")

@app.route("/guide")
def guide_page(): return send_from_directory(APP_DIR, "guide.html")

@app.route("/api/config")
def api_config():
    return jsonify(required=SPEC["required"], bonus=SPEC["bonus"], total=SPEC["total"],
                   max_required=sum(q["score"] for q in SPEC["questions"] if q["section"]=="필수"),
                   max_bonus=sum(q["score"] for q in SPEC["questions"] if q["section"]=="보너스"),
                   wazuh_url=WAZUH_URL, wazuh_user=WAZUH_USER, wazuh_pass=WAZUH_PASS,
                   team=session.get("team"), role=session.get("role"),
                   dataset_time=SPEC.get("generated_at", ""),
                   wrong_penalty=WRONG_PENALTY, hint_penalty=HINT_PENALTY, max_hints=MAX_HINTS)

@app.route("/api/login", methods=["POST"])
def api_login():
    d = request.json or {}
    u = (d.get("username","") or "").strip().lower(); p = (d.get("password","") or "").strip()
    if u == INSTRUCTOR_USER.lower() and p == INSTRUCTOR_PASS:      # instructor via portal login
        session.pop("team", None); session["role"] = "instructor"
        return jsonify(role="instructor")
    if not valid_login(u, p):
        return jsonify(error="아이디 또는 비밀번호가 올바르지 않습니다"), 401
    session.pop("role", None); session["team"] = u
    return jsonify(team=u, role="student")

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.pop("team", None); session.pop("role", None); return jsonify(ok=True)

@app.route("/api/questions")
def api_questions():
    team = session.get("team")
    unlocked = unlocked_stage(team) if team else 1
    qs = []
    for q in SPEC["questions"]:
        stg = stage_of(q["qno"]); locked = stg > unlocked
        pq = public_q(q); pq["stage"] = stg; pq["locked"] = locked
        if locked:                       # hide content until the stage opens
            pq["question"] = None; pq["fmt"] = None; pq["state"] = None
        else:
            pq["state"] = state_of(team, q["qno"]) if team else None
        qs.append(pq)
    stages = [{"id": s, "name": stage_name(s), "unlocked": s <= unlocked,
               "done": stage_done(team, s) if team else 0, "total": len(stage_qnos(s))}
              for s in range(1, NUM_STAGES + 1)]
    return jsonify(team=team, score=team_score(team) if team else 0,
                   unlocked_stage=unlocked, stages=stages, questions=qs)

@app.route("/api/hint", methods=["POST"])
def api_hint():
    team = session.get("team")
    if not team: return jsonify(error="먼저 로그인하세요"), 401
    qno = int((request.json or {}).get("qno", 0))
    if qno not in QByNo: return jsonify(error="잘못된 문항"), 400
    if stage_of(qno) > unlocked_stage(team):
        return jsonify(error="아직 잠긴 단계의 문항입니다"), 403
    with _lock:
        r = row(team, qno)
        if r and r["status"] == "correct":
            return jsonify(locked=True)
        used = r["hints_used"] if r else 0
        if used >= MAX_HINTS:
            return jsonify(no_more=True, hints_used=used,
                           hints=QByNo[qno]["hints"][:used])
        used += 1
        upsert(team, qno, hints_used=used,
               status=(r["status"] if r and r["status"] in ("wrong",) else "in_progress"))
        return jsonify(hint=QByNo[qno]["hints"][used-1], index=used,
                       remaining=MAX_HINTS-used, penalty=used*HINT_PENALTY,
                       team_score=team_score(team))

@app.route("/api/submit", methods=["POST"])
def api_submit():
    team = session.get("team")
    if not team: return jsonify(error="먼저 로그인하세요"), 401
    d = request.json or {}
    qno = int(d.get("qno", 0)); answer = (d.get("answer","") or "").strip()[:500]
    if qno not in QByNo: return jsonify(error="잘못된 문항"), 400
    if not answer: return jsonify(error="답안을 입력하세요"), 400
    if stage_of(qno) > unlocked_stage(team):
        return jsonify(error="아직 잠긴 단계의 문항입니다"), 403
    with _lock:
        r = row(team, qno)
        if r and r["status"] == "correct":
            return jsonify(status="correct", score=r["score"], locked=True,
                           explain=QByNo[qno]["explain"], team_score=team_score(team))
        hints = r["hints_used"] if r else 0
        wrongs = r["wrong_count"] if r else 0
        res = grade(qno, answer); base = QByNo[qno]["score"]
        if res == "manual":
            upsert(team, qno, answer=answer, status="manual", score=0,
                   hints_used=hints, wrong_count=wrongs)
            return jsonify(status="manual", explain=QByNo[qno]["explain"],
                           team_score=team_score(team))
        if res == "correct":
            sc = final_score(base, wrongs, hints, True)
            upsert(team, qno, answer=answer, status="correct", score=sc,
                   hints_used=hints, wrong_count=wrongs)
            return jsonify(status="correct", score=sc, base=base,
                           wrongs=wrongs, hints=hints, explain=QByNo[qno]["explain"],
                           team_score=team_score(team))
        wrongs += 1
        upsert(team, qno, answer=answer, status="wrong", score=0,
               hints_used=hints, wrong_count=wrongs)
        return jsonify(status="wrong", wrong_count=wrongs, penalty=WRONG_PENALTY,
                       team_score=team_score(team))

@app.route("/api/leaderboard")
def api_leaderboard():
    rows = db().execute("""SELECT team, COALESCE(SUM(score),0) s,
                             SUM(status='correct') solved
                           FROM sub GROUP BY team ORDER BY s DESC, solved DESC LIMIT 40""").fetchall()
    return jsonify(board=[{"team": r["team"], "score": r["s"], "solved": r["solved"]} for r in rows])

# ------------------------------------------------------------ instructor --- #
def _auth_instr():
    return (session.get("role") == "instructor"
            or request.args.get("key") == INSTRUCTOR_KEY
            or (request.json or {}).get("key") == INSTRUCTOR_KEY)

@app.route("/instructor")
def instructor_page():
    return send_from_directory(APP_DIR, "instructor.html")

@app.route("/api/instructor/solutions")
def api_instr_solutions():
    if not _auth_instr(): return jsonify(error="unauthorized"), 403
    # full question data (answers/explanations/hints) for the instructor view
    return jsonify(questions=SPEC["questions"],
                   scoring={"wrong": WRONG_PENALTY, "hint": HINT_PENALTY, "max_hints": MAX_HINTS},
                   required=SPEC["required"], bonus=SPEC["bonus"],
                   max_required=sum(q["score"] for q in SPEC["questions"] if q["section"]=="필수"),
                   max_bonus=sum(q["score"] for q in SPEC["questions"] if q["section"]=="보너스"))

@app.route("/api/instructor/submissions")
def api_instr_subs():
    if not _auth_instr(): return jsonify(error="unauthorized"), 403
    rows = db().execute("SELECT * FROM sub ORDER BY team,qno").fetchall()
    out = []
    for r in rows:
        q = QByNo.get(r["qno"], {})
        out.append({"team": r["team"], "qno": r["qno"], "answer": r["answer"],
                    "status": r["status"], "score": r["score"],
                    "hints_used": r["hints_used"], "wrong_count": r["wrong_count"],
                    "manual": q.get("grade",{}).get("mode")=="manual",
                    "question": q.get("question",""), "answer_key": q.get("answer",""),
                    "max": q.get("score",0)})
    return jsonify(subs=out)

@app.route("/api/instructor/users")
def api_instr_users():
    if not _auth_instr(): return jsonify(error="unauthorized"), 403
    seen = {r["team"] for r in db().execute("SELECT DISTINCT team FROM sub").fetchall()}
    seen |= {r["team"] for r in db().execute("SELECT team FROM umeta").fetchall()}
    users = sorted(VALID_USERS | {s for s in seen if s},
                   key=lambda u: (int(re.findall(r"\d+", u)[0]) if re.findall(r"\d+", u) else 999, u))
    out = [{"team": u, "unlocked": unlocked_stage(u), "override": get_override(u),
            "score": team_score(u),
            "stage_done": [stage_done(u, s) for s in range(1, NUM_STAGES + 1)]}
           for u in users]
    return jsonify(users=out, num_stages=NUM_STAGES,
                   stage_totals=[len(stage_qnos(s)) for s in range(1, NUM_STAGES + 1)],
                   stage_names=[stage_name(s) for s in range(1, NUM_STAGES + 1)])

@app.route("/api/instructor/unlock", methods=["POST"])
def api_instr_unlock():
    if not _auth_instr(): return jsonify(error="unauthorized"), 403
    d = request.json or {}; team = d.get("team"); stage = int(d.get("stage", 0))
    if not team: return jsonify(error="bad request"), 400
    stage = max(0, min(stage, NUM_STAGES))     # 0 = 자동해금만 사용
    with _lock:
        db().execute("INSERT INTO umeta(team,override) VALUES(?,?) "
                     "ON CONFLICT(team) DO UPDATE SET override=excluded.override", (team, stage))
        db().commit()
    return jsonify(ok=True, team=team, override=stage, unlocked=unlocked_stage(team))

@app.route("/api/instructor/grade", methods=["POST"])
def api_instr_grade():
    if not _auth_instr(): return jsonify(error="unauthorized"), 403
    d = request.json or {}
    team = d.get("team"); qno = int(d.get("qno", 0)); award = int(d.get("award", 0))
    q = QByNo.get(qno)
    if not q or not team: return jsonify(error="bad request"), 400
    r = row(team, qno); hints = r["hints_used"] if r else 0
    award = max(0, min(award, q["score"]))
    final = max(0, award - hint_cost(hints))        # hints still cost on manual
    with _lock:
        upsert(team, qno, status="graded", score=final, hints_used=hints)
    return jsonify(ok=True, score=final)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORTAL_PORT", "8081")))
