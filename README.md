


## Livrables produits

| Fichier | Rôle | Destinataire |
|---------|------|-------------|
| `scripts/traffic_simulator.py` | Trafic normal en continu | M3 — tourne pendant la démo |
| `scripts/attack_injector.py` | Injection des 5 attaques | M3 — teste les alertes |
| `scripts/generate_dataset.py` | Génère dataset_test.csv | Script interne |
| `scripts/label_swat.py` | Labellise le dataset SWaT | Script interne |
| `data/dataset_test.csv` | 600 lignes labellisées | **M2** — valide son modèle |
| `config/mosquitto.conf` | Configuration broker MQTT | M3 — référence |

> **Note** : `data/SWaT_labeled.csv` est généré par `label_swat.py`.
> Il n'est pas sur GitHub (trop lourd). Le régénérer avec :
> `python scripts/label_swat.py`

---

## Prérequis

```bash
# Python 3.11+
pip install paho-mqtt pandas scikit-learn joblib numpy matplotlib

# Mosquitto 2.x
# Windows : mosquitto.org/download
# Démarrer : net start mosquitto
```

---

## Structure des dossiers

```
ids-iot/
├── config/
│   └── mosquitto.conf
├── data/
│   └── dataset_test.csv        ← livré à M2
├── scripts/
│   ├── traffic_simulator.py    ← trafic normal
│   ├── attack_injector.py      ← attaques
│   ├── generate_dataset.py     ← génère dataset_test.csv
│   └── label_swat.py           ← labellise SWaT
└── models/                     ← réservé à M2
```

---

## Contrat 1 — Format JSON publié sur MQTT

Chaque message publié sur `iiot/node_X/data` respecte ce format :

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

**Ce contrat ne change pas sans accord de tout le groupe.**

---

## Les 5 nœuds simulés

| Nœud | IP | Type | Profil | Fréquence | Taille |
|------|----|------|--------|-----------|--------|
| node_1 | 192.168.1.10 | PLC Réacteur | CBR stable | 1 msg/sec | 64B |
| node_2 | 192.168.1.11 | PLC Pompe | CBR stable | 1 msg/sec | 64B |
| node_3 | 192.168.1.12 | Capteur Pression | VBR irrégulier | 0.1–0.5 msg/sec | ~80B |
| node_4 | 192.168.1.13 | Capteur Température | VBR irrégulier | 0.1–0.5 msg/sec | ~80B |
| node_5 | 192.168.1.14 | Gateway SCADA | Bulk lourd | 1 msg/10sec | 2048B |

---

## Topics MQTT

| Topic | Rôle |
|-------|------|
| `iiot/node_1/data` | Données PLC Réacteur |
| `iiot/node_2/data` | Données PLC Pompe |
| `iiot/node_3/data` | Données Capteur Pression |
| `iiot/node_4/data` | Données Capteur Température |
| `iiot/node_5/data` | Données Gateway SCADA |
| `iiot/ids/alertes` | Alertes IDS publiées par M3 |

---

## Utilisation — traffic_simulator.py

Lance le trafic normal en continu (à garder ouvert pendant toute la démo) :

```bash
# Infini
python scripts/traffic_simulator.py

# Durée limitée
python scripts/traffic_simulator.py --duration 60
```

---

## Utilisation — attack_injector.py

Lance une attaque en parallèle du simulateur normal :

```bash
python scripts/attack_injector.py --mode dos
python scripts/attack_injector.py --mode injection_frozen
python scripts/attack_injector.py --mode injection_aberrant
python scripts/attack_injector.py --mode probe
python scripts/attack_injector.py --mode physical

# Avec durée limitée
python scripts/attack_injector.py --mode dos --duration 30
```

### Signatures des 5 attaques

| Mode | Nœuds ciblés | Signature principale |
|------|-------------|---------------------|
| `dos` | node_1, node_2 | freq 400–800 msg/s, nb_connexions 50–200 |
| `injection_frozen` | node_3 | payload_entropy = 0.0 exactement |
| `injection_aberrant` | node_3, node_4 | payload_size 1200–1500B, entropy 0.80–0.99 |
| `probe` | tous | ip = 192.168.1.99, nb_connexions = 5 |
| `physical` | node_3, node_4 | freq ≈ 0, nb_connexions = 0 |

---

## Utilisation — generate_dataset.py

Génère le fichier `data/dataset_test.csv` pour M2 :

```bash
python scripts/generate_dataset.py
```

Produit 600 lignes : 200 normales + 80 par type d'attaque.

---

## Test end-to-end

```bash
# Terminal 1 — écouter tout le trafic
cd "C:\Program Files\mosquitto"
mosquitto_sub -h localhost -t "iiot/#" -v

# Terminal 2 — trafic normal
python scripts/traffic_simulator.py

# Terminal 3 — injecter une attaque DoS pendant 30 sec
python scripts/attack_injector.py --mode dos --duration 30
```

---

## Validation réalisée

| Test | Résultat |
|------|---------|
| Mosquitto installé et actif sur port 1883 | ✅ |
| traffic_simulator.py publie sur iiot/node_X/data | ✅ |
| Contrat 1 respecté (ip, ts, label, attack_type...) | ✅ |
| Profils CBR/VBR/Bulk corrects | ✅ |
| attack_injector.py — 5 modes fonctionnels | ✅ |
| Topic iiot/ids/alertes opérationnel | ✅ |
| dataset_test.csv généré et livré à M2 | ✅ |

