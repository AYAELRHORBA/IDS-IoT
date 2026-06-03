"""
IDS-IoT SWaT — Flask Dashboard (M4 — Marwa Begdouri Terraf)

État actuel :
  - Données MOCK (live_simulator) tant que M3/Node-RED n'est pas connecté
  - Dès que M3 envoie un POST /api/alert → les vraies alertes remplacent le mock
  - ThingSpeak channel 3397210 intégré (proxy Flask pour éviter CORS)
"""

from flask import Flask, render_template, request, jsonify, Response
import sqlite3, json, random, time, threading, csv, io, urllib.request, urllib.error
from datetime import datetime, timedelta

app = Flask(__name__)
DB = "ids_alerts.db"

# ─── ThingSpeak config ───────────────────────────────────────────
TS_CHANNEL_ID  = "3398006"
TS_READ_KEY    = "7QX7P52Z2U4APRQ3"
TS_WRITE_KEY   = "5ZUMNMBZANUQ0U7L"   # Already in flows.json (Node-RED)
TS_BASE_URL    = "https://api.thingspeak.com"

# ─── DB INIT ────────────────────────────────────────────────────────────────

def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                label      TEXT,
                action     TEXT,
                node_id    TEXT,
                ip         TEXT,
                confidence REAL,
                severity   TEXT,
                timestamp  TEXT
            )
        """)
        con.commit()

# ─── HELPERS ─────────────────────────────────────────────────────────────────

def query(sql, params=()):
    with sqlite3.connect(DB) as con:
        con.row_factory = sqlite3.Row
        return [dict(r) for r in con.execute(sql, params).fetchall()]

def fetch_thingspeak(endpoint, params=""):
    """Proxy ThingSpeak requests from server-side to avoid CORS."""
    url = f"{TS_BASE_URL}/{endpoint}?api_key={TS_READ_KEY}&{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IDS-IoT-Dashboard/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"ThingSpeak HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"error": str(e)}

# ─── PAGES ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html")

@app.route("/history")
def history_page():
    return render_template("history.html")

@app.route("/stats")
def stats_page():
    return render_template("stats.html")

# ─── API ──────────────────────────────────────────────────────────────────────

@app.route("/api/alert", methods=["POST"])
def receive_alert():
    """
    Endpoint for M3 Node-RED to POST real-time alerts (Contrat 3).
    Payload: { label, action, node_id, ip, confidence, severity, timestamp }
    """
    data = request.get_json(force=True)
    required = ["label","action","node_id","ip","confidence","severity","timestamp"]
    if not all(k in data for k in required):
        return jsonify({"error": "missing fields", "required": required}), 400
    with sqlite3.connect(DB) as con:
        con.execute(
            "INSERT INTO alerts (label,action,node_id,ip,confidence,severity,timestamp) VALUES (?,?,?,?,?,?,?)",
            (data["label"], data["action"], data["node_id"], data["ip"],
             data["confidence"], data["severity"], data["timestamp"])
        )
        con.commit()
    print(f"[REAL] Alert received: {data['label']} from {data['node_id']} (conf={data['confidence']})")
    return jsonify({"status": "ok"}), 201

@app.route("/api/stats/overview")
def api_overview():
    total    = query("SELECT COUNT(*) as c FROM alerts")[0]["c"]
    normal   = query("SELECT COUNT(*) as c FROM alerts WHERE label='Normal'")[0]["c"]
    attacks  = total - normal
    last     = query("SELECT * FROM alerts ORDER BY id DESC LIMIT 1")
    avg_conf = query("SELECT ROUND(AVG(confidence),3) as c FROM alerts")[0]["c"] or 0
    node_counts = query("SELECT node_id, COUNT(*) as c FROM alerts GROUP BY node_id ORDER BY c DESC")
    return jsonify({
        "total": total, "normal": normal, "attacks": attacks,
        "attack_rate": round(attacks/max(total,1)*100, 1),
        "last_alert": last[0] if last else None,
        "avg_confidence": avg_conf,
        "node_counts": node_counts
    })

@app.route("/api/stats/node_status")
def api_node_status():
    rows = query("""
        SELECT node_id, label, action, severity, confidence, timestamp
        FROM alerts
        WHERE id IN (SELECT MAX(id) FROM alerts GROUP BY node_id)
    """)
    return jsonify(rows)

@app.route("/api/stats/node_attack_count")
def api_node_attack_count():
    node_id = request.args.get("node_id", "")
    if not node_id:
        return jsonify({"error": "node_id required"}), 400
    normal  = query("SELECT COUNT(*) as c FROM alerts WHERE node_id=? AND label='Normal'", (node_id,))[0]["c"]
    attacks = query("SELECT COUNT(*) as c FROM alerts WHERE node_id=? AND label!='Normal'", (node_id,))[0]["c"]
    return jsonify({"node_id": node_id, "normal": normal, "attacks": attacks})

@app.route("/api/alerts/list")
def api_alerts_list():
    label    = request.args.get("label","")
    node_id  = request.args.get("node_id","")
    severity = request.args.get("severity","")
    page     = int(request.args.get("page", 1))
    per_page = 20
    filters, params = [], []
    if label:    filters.append("label=?");    params.append(label)
    if node_id:  filters.append("node_id=?");  params.append(node_id)
    if severity: filters.append("severity=?"); params.append(severity)
    where = ("WHERE " + " AND ".join(filters)) if filters else ""
    total = query(f"SELECT COUNT(*) as c FROM alerts {where}", params)[0]["c"]
    offset = (page-1)*per_page
    rows = query(
        f"SELECT * FROM alerts {where} ORDER BY id DESC LIMIT ? OFFSET ?",
        params+[per_page, offset]
    )
    return jsonify({"rows": rows, "total": total, "page": page, "per_page": per_page})

@app.route("/api/stats/timeline")
def api_timeline():
    rows = query("""
        SELECT strftime('%H:%M', timestamp) as t,
               SUM(CASE WHEN label='Normal' THEN 1 ELSE 0 END) as normal,
               SUM(CASE WHEN label!='Normal' THEN 1 ELSE 0 END) as attack
        FROM alerts
        GROUP BY strftime('%Y-%m-%d %H:%M', timestamp)
        ORDER BY timestamp DESC LIMIT 60
    """)
    rows.reverse()
    return jsonify(rows)

@app.route("/api/stats/by_type")
def api_by_type():
    rows = query("SELECT label, COUNT(*) as c FROM alerts GROUP BY label ORDER BY c DESC")
    return jsonify(rows)

@app.route("/api/stats/actions")
def api_actions():
    rows = query("SELECT action, COUNT(*) as c FROM alerts GROUP BY action ORDER BY c DESC")
    return jsonify(rows)

@app.route("/api/stats/confidence_dist")
def api_conf_dist():
    buckets = [(0.5,0.6),(0.6,0.7),(0.7,0.8),(0.8,0.9),(0.9,1.01)]
    result = []
    for lo, hi in buckets:
        c = query("SELECT COUNT(*) as c FROM alerts WHERE confidence>=? AND confidence<?", (lo,hi))[0]["c"]
        result.append({"range": f"{int(lo*100)}-{int(hi*100)}%", "count": c})
    return jsonify(result)

# ─── THINGSPEAK PROXY ENDPOINTS ───────────────────────────────────────────────

@app.route("/api/thingspeak/feeds")
def api_ts_feeds():
    """
    Proxy ThingSpeak GET request from server-side.
    Avoids browser CORS issues and works with private channels.
    Channel: 3397210 | Read key: 3OSHK8U3WKBI0CR5
    """
    results = request.args.get("results", "20")
    data = fetch_thingspeak(
        f"channels/{TS_CHANNEL_ID}/feeds.json",
        f"results={results}"
    )
    return jsonify(data)

@app.route("/api/thingspeak/last")
def api_ts_last():
    """Get the most recent ThingSpeak entry."""
    data = fetch_thingspeak(f"channels/{TS_CHANNEL_ID}/feeds/last.json")
    return jsonify(data)

@app.route("/api/thingspeak/status")
def api_ts_status():
    """Check if ThingSpeak channel has any data."""
    data = fetch_thingspeak(
        f"channels/{TS_CHANNEL_ID}/feeds.json",
        "results=1"
    )
    if "error" in data:
        return jsonify({"connected": False, "error": data["error"]})
    feeds = data.get("feeds", [])
    channel = data.get("channel", {})
    return jsonify({
        "connected": True,
        "channel_id": TS_CHANNEL_ID,
        "channel_name": channel.get("name", "IDS-IoT Raffinerie"),
        "has_data": len(feeds) > 0 and any(f.get("field2") for f in feeds),
        "last_entry_id": channel.get("last_entry_id", 0),
        "created_at": channel.get("created_at", ""),
    })

# ─── SSE STREAM ───────────────────────────────────────────────────────────────

@app.route("/api/alerts/stream")
def stream():
    def generate():
        last_id = 0
        while True:
            rows = query("SELECT * FROM alerts WHERE id>? ORDER BY id DESC LIMIT 5", (last_id,))
            if rows:
                last_id = rows[0]["id"]
                yield f"data: {json.dumps(rows)}\n\n"
            else:
                yield ": heartbeat\n\n"
            time.sleep(3)
    return Response(
        generate(), mimetype="text/event-stream",
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"}
    )

@app.route("/api/alerts/export")
def export_csv():
    rows = query("SELECT * FROM alerts ORDER BY id DESC")
    si = io.StringIO()
    w = csv.DictWriter(si, fieldnames=["id","label","action","node_id","ip","confidence","severity","timestamp"])
    w.writeheader()
    w.writerows(rows)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(
        si.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=ids_alerts_{ts}.csv"}
    )

@app.route("/api/health")
def api_health():
    total = query("SELECT COUNT(*) as c FROM alerts")[0]["c"]
    ts_status = fetch_thingspeak(f"channels/{TS_CHANNEL_ID}/feeds.json","results=1")
    ts_ok = "error" not in ts_status
    return jsonify({
        "status": "ok",
        "db_records": total,
        "thingspeak_connected": ts_ok,
        "thingspeak_channel": TS_CHANNEL_ID,
        "timestamp": datetime.now().isoformat()
    })

# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()

    print("\n" + "="*60)
    print("  IDS-IoT SWaT — M4 Dashboard — Marwa Begdouri Terraf")
    print("  URL   : http://localhost:5000")
    print("  Pages : /  |  /alerts  |  /history  |  /stats")
    print("  APIs  : /api/alert (POST from Node-RED)")
    print("          /api/thingspeak/feeds")
    print("          /api/stats/*")
    print()
    print("  DATA  : REAL DATA ONLY")
    print("  SOURCE: MQTT -> Node-RED -> AI -> Flask -> SQLite")
    print("  MOCK  : DISABLED")
    print("="*60 + "\n")

    app.run(
        debug=False,
        host="0.0.0.0",
        port=5000,
        threaded=True
    )