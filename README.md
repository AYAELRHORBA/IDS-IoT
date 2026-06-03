# IDS-IoT SWaT — M2 : Data Scientist & API IA

## Rôle de M2

M2 est responsable de l'entraînement du modèle de détection d'intrusions et de l'exposition de ce modèle via une API Flask que Node-RED (M3) appelle en temps réel.

---

## Source des données

Les données utilisées pour l'entraînement proviennent du **trafic réseau simulé via MQTT** par M1 (`traffic_simulator.py` et `attack_injector.py`). Ces messages publiés sur les topics `iiot/node_X/data` ont été collectés et structurés en un dataset CSV.

Le dataset SWaT original (Kaggle) a servi uniquement de **référence et d'inspiration** pour définir les features et les profils d'attaque — il n'est pas utilisé directement pour l'entraînement.

---

## Dataset d'entraînement

| Propriété | Valeur |
|-----------|--------|
| Fichier | `data/dataset_real.csv` |
| Nombre de samples | 905 |
| Nombre de classes | 6 |
| Source | Trafic MQTT simulé par M1 |

### Distribution des classes

| Classe | Samples | % |
|--------|---------|---|
| Normal | 427 | 47.2% |
| Probe | 150 | 16.6% |
| Injection_Aberrant | 91 | 10.1% |
| Physical | 90 | 9.9% |
| DoS | 85 | 9.4% |
| Injection_Frozen | 62 | 6.9% |

---

## Modèle choisi

**Random Forest Classifier** (scikit-learn)

Deux modèles ont été comparés : Random Forest et SVM (kernel RBF). Le Random Forest a été retenu comme modèle final.

### Techniques de prétraitement

- **Feature engineering** : `node_id` converti en entier (`node_num`), `ip` réduit au dernier octet (`ip_last_octet`)
- **Split stratifié** : Train 70% / Validation 15% / Test 15% — stratification garantit la représentation de chaque classe dans les 3 splits
- **Normalisation** : `StandardScaler` fitté uniquement sur le train, appliqué sur val et test
- **SMOTE** : rééquilibrage des classes appliqué sur le train uniquement (avant SMOTE : 633 samples → après : 1794 samples)
- **Cross-validation** : 5-fold stratifié sur train+val

### Features utilisées (7)

```
freq_msg_per_sec, interval_ms, payload_size_bytes,
payload_entropy, nb_connexions, node_num, ip_last_octet
```

---

## Fichiers produits

| Fichier | Rôle | Destinataire |
|---------|------|-------------|
| `train_model.py` | Entraînement, comparaison RF vs SVM, sauvegarde | M4 — rapport |
| `models/ids_model.pkl` | Modèle Random Forest entraîné | `api_model.py` |
| `models/scaler.pkl` | StandardScaler (fit sur train) | `api_model.py` |
| `models/label_encoder.pkl` | Encodeur des 6 classes | `api_model.py` |
| `models/evaluation_dashboard.png` | Figures de comparaison RF vs SVM | M4 — rapport |
| `models/class_report.png` | Précision/Rappel/F1 par classe | M4 — rapport |
| `api/api_model.py` | API Flask port 5001 | M3 — Node-RED |

---

## Structure des dossiers

```
IDS-IoT/
├── data/
│   └── dataset_real.csv        ← données MQTT simulées par M1
├── models/
│   ├── ids_model.pkl
│   ├── scaler.pkl
│   ├── label_encoder.pkl
│   ├── evaluation_dashboard.png
│   └── class_report.png
├── api/
│   └── api_model.py            ← API Flask :5001
└── train_model.py
```

---

## Lancement

### 1. Entraîner le modèle

```bash
cd IDS-IoT
python train_model.py
```

Les fichiers pkl sont sauvegardés automatiquement dans `models/`.

### 2. Lancer l'API

```bash
cd IDS-IoT/api
python api_model.py
```

L'API tourne sur `http://0.0.0.0:5001` (accessible en local et sur le réseau).

---

## Endpoints de l'API

| Méthode | Route | Description |
|---------|-------|-------------|
| `POST` | `/predict` | Reçoit les features d'un nœud, retourne label + confiance |
| `GET` | `/health` | Statut du service et modèle chargé |
| `GET` | `/classes` | Liste des classes et actions associées |

---

## Contrat 2 — Format de réponse de `/predict`

L'API reçoit le **Contrat 1** (JSON de M3/Node-RED) et retourne le **Contrat 2** :

```json
{
  "label":      "DoS",
  "confidence": 0.94,
  "node_id":    "node_1",
  "ip":         "192.168.1.10"
}
```

> ⚠️ Pas de `timestamp` dans la réponse — il est généré par M3 dans le Nœud Fonction 2.

---

## Tester l'API avec Postman

> Utiliser **Postman Desktop** (pas la version web — elle ne peut pas accéder à localhost).

### Test `/predict`

1. Méthode : **POST**
2. URL : `http://127.0.0.1:5001/predict`
3. Onglet **Body** → **raw** → **JSON**
4. Corps :

```json
{
  "node_id":            "node_1",
  "ip":                 "192.168.1.10",
  "freq_msg_per_sec":   1.02,
  "interval_ms":        998,
  "payload_size_bytes": 64,
  "payload_entropy":    0.52,
  "nb_connexions":      1
}
```

5. Cliquer **Send** → réponse `200 OK` :

```json
{
  "label":      "Normal",
  "confidence": 0.995,
  "node_id":    "node_1",
  "ip":         "192.168.1.10"
}
```

### Test `/health`

Méthode **GET** → `http://127.0.0.1:5001/health`

```json
{
  "status":  "ok",
  "model":   "RandomForestClassifier",
  "classes": ["DoS","Injection_Aberrant","Injection_Frozen","Normal","Physical","Probe"]
}
```

### Test depuis PowerShell (sans Postman)

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:5001/predict" `
  -Method POST `
  -ContentType "application/json" `
  -Body '{"node_id":"node_1","ip":"192.168.1.10","freq_msg_per_sec":1.02,"interval_ms":998,"payload_size_bytes":64,"payload_entropy":0.52,"nb_connexions":1}'
```

---

## Prérequis

```bash
pip install flask flask-cors scikit-learn imbalanced-learn pandas numpy matplotlib seaborn
```

Python 3.10+ recommandé.

---

## Intégration avec M3 (Node-RED)

M3 envoie un `POST` à `http://<IP_M2>:5001/predict` avec les features du message MQTT reçu.
L'IP réseau de la machine M2 est visible au démarrage de l'API dans les logs :

```
* Running on http://192.168.1.105:5001
```

**Ce contrat ne change pas sans accord de tout le groupe.**