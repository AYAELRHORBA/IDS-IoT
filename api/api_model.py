"""
api_model.py — IDS-IoT SWaT
M2 — Meriem : API Flask IA — port 5001

Structure attendue :
  IDS-IoT/
  ├── models/
  │   ├── ids_model.pkl
  │   ├── scaler.pkl
  │   └── label_encoder.pkl
  └── api/
      └── api_model.py   ← ce fichier

Lancement :
  cd IDS-IoT/api
  python api_model.py

Endpoints :
  POST /predict   → reçoit Contrat 1, retourne Contrat 2
  GET  /health    → statut du service
  GET  /classes   → labels + actions/sévérités
"""

import os
import pickle
import logging

import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS

# ─────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s — %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────
# Chemins — relatifs à la position de api_model.py
# api_model.py est dans  IDS-IoT/api/
# les pkl sont dans      IDS-IoT/models/
# ─────────────────────────────────────────────────────────────────
API_DIR    = os.path.dirname(os.path.abspath(__file__))   # .../IDS-IoT/api
ROOT_DIR   = os.path.dirname(API_DIR)                     # .../IDS-IoT
MODELS_DIR = os.path.join(ROOT_DIR, 'models')             # .../IDS-IoT/models

def pkl_path(filename):
    return os.path.join(MODELS_DIR, filename)

# ─────────────────────────────────────────────────────────────────
# Chargement des modèles au démarrage
# ─────────────────────────────────────────────────────────────────
def load_pkl(filename):
    path = pkl_path(filename)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"\n[ERREUR] Fichier introuvable : {path}"
            f"\n  → Lance d'abord : python train_model.py"
            f"\n  → Les pkl doivent être dans : {MODELS_DIR}"
        )
    with open(path, 'rb') as f:
        return pickle.load(f)

try:
    model         = load_pkl('ids_model.pkl')
    scaler        = load_pkl('scaler.pkl')
    label_encoder = load_pkl('label_encoder.pkl')
    MODEL_NAME    = type(model).__name__
    log.info(f"Modèle chargé    : {MODEL_NAME}")
    log.info(f"Classes          : {label_encoder.classes_.tolist()}")
    log.info(f"Dossier modèles  : {MODELS_DIR}")
except FileNotFoundError as e:
    log.error(str(e))
    raise

# ─────────────────────────────────────────────────────────────────
# Features — même ordre que train_model.py
# ─────────────────────────────────────────────────────────────────
FEATURE_COLS = [
    'freq_msg_per_sec', 'interval_ms', 'payload_size_bytes',
    'payload_entropy',  'nb_connexions', 'node_num', 'ip_last_octet'
]

# ─────────────────────────────────────────────────────────────────
# Application Flask
# ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ── Helpers ──────────────────────────────────────────────────────

def extract_node_num(node_id: str) -> int:
    """'node_3' → 3  |  inconnu → 0"""
    try:
        return int(str(node_id).replace('node_', '').strip())
    except (ValueError, AttributeError):
        return 0

def extract_ip_last_octet(ip: str) -> int:
    """'192.168.1.10' → 10  |  inconnu → 0"""
    try:
        return int(str(ip).split('.')[-1])
    except (ValueError, AttributeError, IndexError):
        return 0

def build_feature_vector(data: dict) -> pd.DataFrame:
    """Transforme le Contrat 1 en DataFrame prêt pour le scaler."""
    row = {
        'freq_msg_per_sec':   float(data.get('freq_msg_per_sec',   1.0)),
        'interval_ms':        float(data.get('interval_ms',        1000)),
        'payload_size_bytes': float(data.get('payload_size_bytes', 64)),
        'payload_entropy':    float(data.get('payload_entropy',    0.5)),
        'nb_connexions':      float(data.get('nb_connexions',      1)),
        'node_num':           float(extract_node_num(data.get('node_id', 'node_0'))),
        'ip_last_octet':      float(extract_ip_last_octet(data.get('ip', '0.0.0.0'))),
    }
    return pd.DataFrame([row], columns=FEATURE_COLS)

def validate_input(data: dict) -> list:
    required = ['node_id', 'ip', 'freq_msg_per_sec', 'interval_ms',
                 'payload_size_bytes', 'payload_entropy', 'nb_connexions']
    return [f"Champ manquant : '{f}'" for f in required if f not in data]

# ── POST /predict ────────────────────────────────────────────────

@app.route('/predict', methods=['POST'])
def predict():
    """
    Reçoit Contrat 1 (de M3 / Node-RED) → retourne Contrat 2.

    Contrat 2 :
    {
        "label":      "DoS",
        "confidence": 0.94,
        "node_id":    "node_1",
        "ip":         "192.168.1.10"
    }
    ⚠️  Pas de timestamp — généré par M3 dans le Nœud Fonction 2
    """
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "JSON invalide ou Content-Type manquant"}), 400

    errors = validate_input(data)
    if errors:
        return jsonify({"error": "Validation échouée", "details": errors}), 422

    try:
        X_df     = build_feature_vector(data)
        X_scaled = scaler.transform(X_df)
        pred_enc = model.predict(X_scaled)
        proba    = model.predict_proba(X_scaled)
        label      = label_encoder.inverse_transform(pred_enc)[0]
        confidence = round(float(proba[0].max()), 4)
    except Exception as e:
        log.error(f"Erreur prédiction : {e}")
        return jsonify({"error": str(e)}), 500

    response = {
        "label":      label,
        "confidence": confidence,
        "node_id":    data.get('node_id', 'unknown'),
        "ip":         data.get('ip',      'unknown')
        # ✅ Pas de timestamp — généré par M3
    }
    log.info(f"node={response['node_id']}  label={label}  conf={confidence:.2f}")
    return jsonify(response), 200

# ── GET /health ──────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "model":   MODEL_NAME,
        "classes": label_encoder.classes_.tolist()
    }), 200

# ── GET /classes ─────────────────────────────────────────────────

@app.route('/classes', methods=['GET'])
def classes():
    label_map = {
        "Normal":             {"action": "ALLOW",      "severity": "OK"},
        "DoS":                {"action": "REJECT",     "severity": "CRITICAL"},
        "Injection_Frozen":   {"action": "QUARANTINE", "severity": "DANGER"},
        "Injection_Aberrant": {"action": "QUARANTINE", "severity": "DANGER"},
        "Physical":           {"action": "QUARANTINE", "severity": "DANGER"},
        "Probe":              {"action": "WATCHLIST",  "severity": "WARNING"},
    }
    return jsonify({
        "classes":   label_encoder.classes_.tolist(),
        "label_map": label_map
    }), 200

# ── 404 ──────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "error": "Route introuvable",
        "disponibles": ["POST /predict", "GET /health", "GET /classes"]
    }), 404

# ── Lancement ────────────────────────────────────────────────────

if __name__ == '__main__':
    log.info("=" * 50)
    log.info("  IDS-IoT SWaT — API Modèle IA")
    log.info(f"  Modèle  : {MODEL_NAME}")
    log.info(f"  Port    : 5001")
    log.info("  Routes  : POST /predict | GET /health | GET /classes")
    log.info("=" * 50)
    app.run(host='0.0.0.0', port=5001, debug=False)