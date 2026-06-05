
#  IDS-IoT SWaT — Système Intelligent de Détection d'Intrusions

> Projet Fin de Module — IoT | Pr. M. EL Brak
> Université Abdelmalek Essaâdi — FST Tanger | 2025/2026

---

##  Description du projet

Système de détection d'intrusions (IDS) pour réseaux IoT industriels, entièrement simulé.
Le système surveille un réseau de 5 capteurs IIoT (raffinerie industrielle) et détecte
en temps réel les cyberattaques via un modèle de Machine Learning (SVM RBF).

**Contexte industriel :** Inspiré du dataset SWaT (Secure Water Treatment) — Singapore
University of Technology and Design (SUTD) — référence académique en sécurité ICS/SCADA.

---

##  Architecture globale

```
 traffic_simulator.py + attack_injector.py
          ↓ MQTT publish (iiot/node_X/data)
   [Mosquitto Broker :1883]
          ↓ MQTT subscribe
      Node-RED
 [Préparer body] → [POST :5001/predict]
          ↓
 API Flask IA (port 5001)
           ↓ {"label","confidence","node_id","ip"}
 [Logique décision] → [Switch ALLOW/REJECT/QUARANTINE/WATCHLIST]
         ↙                    ↘
POST :5000/api/alert      POST ThingSpeak
         ↓                         ↓
 Flask Dashboard       Historique Cloud
     SQLite                ThingSpeak
```

---

##  Les 5 nœuds simulés

| Nœud | IP | Type | Profil réseau | Fréquence | Taille |
|------|----|------|---------------|-----------|--------|
| node_1 | 192.168.1.10 | PLC Réacteur | CBR stable | ~1 msg/sec | ~64B |
| node_2 | 192.168.1.11 | PLC Pompe | CBR stable | ~1 msg/sec | ~64B |
| node_3 | 192.168.1.12 | Capteur Pression | VBR irrégulier | 0.05–0.70 msg/sec | ~80B |
| node_4 | 192.168.1.13 | Capteur Température | VBR irrégulier | 0.05–0.70 msg/sec | ~80B |
| node_5 | 192.168.1.14 | Gateway SCADA | Bulk lourd | ~0.1 msg/sec | ~2048B |

---

##  Les 5 attaques simulées

| Mode | Nœuds ciblés | Signature principale | Décision |
|------|-------------|---------------------|---------|
| `dos` | node_1, node_2 | freq 50–860 msg/sec | 🔴 REJECT |
| `injection_frozen` | node_3 | payload_entropy ≈ 0.0 | 🟠 QUARANTINE |
| `injection_aberrant` | node_3, node_4 | payload_size 700–1600B | 🟠 QUARANTINE |
| `probe` | tous | IP inconnue, nb_connexions 2–10 | 🟡 WATCHLIST |
| `physical` | node_3, node_4 | freq ≈ 0, nb_connexions 0–2 | 🔴 REJECT |

---

##  Résultats du modèle IA

**Modèle sélectionné : SVM (kernel RBF)**

> Random Forest = 1.00 → overfitting sur données simulées
> SVM = 0.989 → résultats réalistes et généralisables

```
              precision    recall  f1-score
DoS               1.00      1.00      1.00
Injection_Aberrant 0.94     0.94      0.94
Injection_Frozen  1.00      1.00      1.00
Normal            1.00      1.00      1.00
Physical          1.00      1.00      1.00
Probe             0.97      0.97      0.97

accuracy                           0.9891
macro avg         0.99      0.99    0.9857
CV 5-fold         0.9938 ± 0.0067
```

**Features utilisées (5 features comportementales) :**
```
freq_msg_per_sec | interval_ms | payload_size_bytes | payload_entropy | nb_connexions
```
---

## Features du Dashboard

- **Tableau de bord (index.html)** : Vue d'ensemble en temps réel avec statistiques globales
- **Alertes (alerts.html)** : Historique et détails des alertes de sécurité détectées
- **Statistiques (stats.html)** : Analyse détaillée des anomalies par type, node, et période
- **Historique (history.html)** : Logs complets des événements réseau
- **Base de données** : Stockage persistant des alertes (`ids_alerts.db`)

---
##  Structure du projet

```
ids-iot/
├── scripts/
│   ├── traffic_simulator.py    ← Trafic normal 
│   ├── attack_injector.py      ← Attaques 
│   ├── record_dataset.py       ← Enregistrement dataset
│   └── check_dataset.py        ← Vérification dataset
├── api/
│   └── api_model.py            ← API Flask IA port 5001
├── data/
│   └── dataset_real.csv        ← Dataset enregistré
├── models/
│   ├── ids_model.pkl           ← Modèle SVM entraîné
│   ├── scaler.pkl              ← StandardScaler
│   ├── label_encoder.pkl       ← LabelEncoder
│   ├── evaluation_dashboard.png
│   └── class_report.png
├── templates/                 ← Dashboard Templates
├── app.py
├── node-red/
│   └── flows.json              ← Flow Node-RED exporté 
├── train_model.py              ← Entraînement RF vs SVM 
├── config/
│   └── mosquitto.conf          ← Configuration broker
├── requirements.txt
└── README.md
```

---

##  Prérequis

```bash
# Python 3.9+
pip install paho-mqtt pandas scikit-learn imbalanced-learn joblib numpy \
            matplotlib seaborn flask flask-cors requests

# Node.js + Node-RED
npm install -g --unsafe-perm node-red

# Palettes Node-RED
node-red → Manage Palette → Install :
  node-red-dashboard
  node-red-contrib-ui-led

# Mosquitto
# Windows : mosquitto.org/download → installer
```

---

##  Lancement complet

### Étape 1 — Démarrer Mosquitto

```bash
net start mosquitto
```

### Étape 2 — Lancer l'API IA 

```bash
cd ids-iot/api
python api_model.py
# → Running on http://localhost:5001
```

### Étape 3 — Lancer Node-RED 

```bash
node-red
# → Ouvrir http://localhost:1880
# → Importer node-red/flows.json
# → Deploy
```

### Étape 4 — Lancer le simulateur de trafic 

```bash
python scripts/traffic_simulator.py
```

### Étape 5 — Lancer le dashboard Flask 

```bash
python app.py
# → Ouvrir http://localhost:5000
```

### Étape 6 — Injecter une attaque pour tester

```bash
python scripts/attack_injector.py --mode dos --duration 30
python scripts/attack_injector.py --mode injection_frozen --duration 30
python scripts/attack_injector.py --mode injection_aberrant --duration 30
python scripts/attack_injector.py --mode probe --duration 30
python scripts/attack_injector.py --mode physical --duration 30
```

---

##  Topics MQTT

| Topic | Description |
|-------|-------------|
| `iiot/node_1/data` | Données PLC Réacteur |
| `iiot/node_2/data` | Données PLC Pompe |
| `iiot/node_3/data` | Données Capteur Pression |
| `iiot/node_4/data` | Données Capteur Température |
| `iiot/node_5/data` | Données Gateway SCADA |
| `iiot/ids/alertes` | Alertes IDS publiées par Node-RED |

---

##  Contrats JSON

### Contrat 1 

```json
{
  "node_id":            "node_1",
  "ip":                 "192.168.1.10",
  "freq_msg_per_sec":   1.02,
  "interval_ms":        998,
  "payload_size_bytes": 64,
  "payload_entropy":    0.52,
  "nb_connexions":      1,
  "ts":                 1717000001,
  "label":              "Normal",
  "attack_type":        "Normal"
}
```

### Contrat 2 

```json
{
  "label":      "DoS",
  "confidence": 0.94,
  "node_id":    "node_1",
  "ip":         "192.168.1.10"
}
```

### Contrat 3 
```json
{
  "label":      "DoS",
  "action":     "REJECT",
  "node_id":    "node_1",
  "ip":         "192.168.1.10",
  "confidence": 0.94,
  "severity":   "CRITICAL",
  "timestamp":  "2026-05-30T14:23:01.123Z"
}
```

---

##  ThingSpeak — Mapping des fields

| Field | Contenu | Valeurs |
|-------|---------|---------|
| `field1` | Node ID | 1–5 |
| `field2` | Attack code | 0=Normal, 1=DoS, 2=Injection, 3=Probe, 5=Physical |
| `field3` | Confidence % | 0–100 |

---

##  API Endpoints

### API IA — port 5001

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/predict` | POST | Prédiction : reçoit Contrat 1, retourne Contrat 2 |
| `/health` | GET | Statut du service + classes disponibles |
| `/classes` | GET | Labels + actions/sévérités |

### Dashboard Flask — port 5000

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/api/alert` | POST | Reçoit alertes depuis Node-RED |
| `/api/recent` | GET | 50 dernières alertes |
| `/api/stats` | GET | Statistiques globales |
| `/api/nodes/status` | GET | Statut actuel de chaque nœud |
| `/api/timeline` | GET | Timeline pour graphes |
| `/api/thingspeak` | GET | Historique depuis ThingSpeak |

---

##  Générer un nouveau dataset

```bash
# Terminal 1 — trafic normal (laisser tourner)
python scripts/traffic_simulator.py

# Terminal 2 — enregistrer le trafic
python scripts/record_dataset.py

# Terminal 3 — injecter les attaques une par une
python scripts/attack_injector.py --mode dos               --duration 90
python scripts/attack_injector.py --mode injection_frozen  --duration 90
python scripts/attack_injector.py --mode injection_aberrant --duration 90
python scripts/attack_injector.py --mode probe             --duration 90
python scripts/attack_injector.py --mode physical          --duration 90

# Arrêter Terminal 2 → dataset_real.csv généré
# Vérifier le dataset
python scripts/check_dataset.py

# Réentraîner le modèle
python train_model.py
```

---

##  Test end-to-end

```bash
# Terminal 1 — écouter tout le trafic MQTT
mosquitto_sub -h localhost -t "iiot/#" -v

# Terminal 2 — trafic normal
python scripts/traffic_simulator.py

# Terminal 3 — attaque DoS 30 secondes
python scripts/attack_injector.py --mode dos --duration 30
```

**Résultat attendu dans Node-RED Debug :**
```
🚨 DoS DÉTECTÉ sur node_1 — 192.168.1.10
action   : REJECT
severity : CRITICAL
confidence : 0.94
```

---

##  Références

- **Dataset SWaT** : iTrust, Singapore University of Technology and Design (SUTD)
  https://itrust.sutd.edu.sg/testbeds/secure-water-treatment-swat/


---

*IDS-IoT SWaT — FST Tanger — 2025/2026*





