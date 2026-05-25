# =============================================================
#  Génère un fichier CSV de test avec des exemples de trafic
#  normal et d'attaques
#
#  Colonnes produites :
#    node_id, ip, freq_msg_per_sec, interval_ms,
#    payload_size_bytes, payload_entropy,
#    nb_connexions, label, attack_type
#
#  Usage :
#    python scripts/generate_dataset.py
#    → produit data/dataset_test.csv
# =============================================================

import pandas as pd
import random
import math
import time
import os

# =============================================================
# PARAMÈTRES DE GÉNÉRATION
#
# On génère suffisamment d'exemples par classe pour qu'on
#  puisse tester toutes les combinaisons.
# Le dataset est équilibré volontairement pour les tests
# (contrairement au dataset réel SWaT qui est déséquilibré).
# =============================================================

N_NORMAL             = 200   # lignes de trafic normal
N_DOS                = 80    # lignes DoS
N_INJECTION_FROZEN   = 80    # lignes Injection_Frozen
N_INJECTION_ABERRANT = 80    # lignes Injection_Aberrant
N_PROBE              = 80    # lignes Probe
N_PHYSICAL           = 80    # lignes Physical

# Profils des 5 nœuds — mêmes que traffic_simulator.py
NODE_PROFILES = {
    "node_1": {"ip": "192.168.1.10", "type": "CBR",  "freq": 1.0,  "size": 64,   "interval_ms": 1000,  "nb_connexions": 1, "entropy": 0.52},
    "node_2": {"ip": "192.168.1.11", "type": "CBR",  "freq": 1.0,  "size": 64,   "interval_ms": 1000,  "nb_connexions": 1, "entropy": 0.50},
    "node_3": {"ip": "192.168.1.12", "type": "VBR",  "freq": 0.3,  "size": 80,   "interval_ms": 3000,  "nb_connexions": 1, "entropy": 0.48},
    "node_4": {"ip": "192.168.1.13", "type": "VBR",  "freq": 0.3,  "size": 80,   "interval_ms": 3000,  "nb_connexions": 1, "entropy": 0.46},
    "node_5": {"ip": "192.168.1.14", "type": "Bulk", "freq": 0.1,  "size": 2048, "interval_ms": 10000, "nb_connexions": 3, "entropy": 0.71},
}

rows = []

# =============================================================
# GÉNÉRATION DU TRAFIC NORMAL
# Respecte les profils CBR / VBR / Bulk de chaque nœud.
# =============================================================

print("Génération du trafic normal...")

for _ in range(N_NORMAL):
    node_id = random.choice(list(NODE_PROFILES.keys()))
    p       = NODE_PROFILES[node_id]
    ptype   = p["type"]

    if ptype == "CBR":
        freq     = round(p["freq"] * random.uniform(0.98, 1.02), 3)
        size     = p["size"]
        interval = p["interval_ms"]
        entropy  = round(p["entropy"] * random.uniform(0.98, 1.02), 4)
        nb_conn  = p["nb_connexions"]

    elif ptype == "VBR":
        freq     = round(random.uniform(0.1, 0.5), 3)
        size     = int(p["size"] * random.uniform(0.85, 1.15))
        interval = int(1000 / freq) if freq > 0 else 3000
        entropy  = round(p["entropy"] * random.uniform(0.90, 1.10), 4)
        nb_conn  = p["nb_connexions"]

    else:  # Bulk
        freq     = round(p["freq"] * random.uniform(0.95, 1.05), 3)
        size     = p["size"]
        interval = p["interval_ms"]
        entropy  = round(p["entropy"] * random.uniform(0.95, 1.05), 4)
        nb_conn  = p["nb_connexions"]

    rows.append({
        "node_id":            node_id,
        "ip":                 p["ip"],
        "freq_msg_per_sec":   freq,
        "interval_ms":        interval,
        "payload_size_bytes": size,
        "payload_entropy":    entropy,
        "nb_connexions":      nb_conn,
        "label":              "Normal",
        "attack_type":        "Normal",
    })

print(f"  {N_NORMAL} lignes normales générées.")

# =============================================================
# GÉNÉRATION DoS
# Fréquence sinusoïdale 400–800 msg/sec + bruit gaussien.
# Cible principale : node_1 et node_2 (PLCs).
# =============================================================

print("Génération DoS...")

targets_dos = ["node_1", "node_2"]
for i in range(N_DOS):
    node_id = random.choice(targets_dos)
    p       = NODE_PROFILES[node_id]
    t       = i * 0.5
    base    = 600 + 200 * math.sin(t / 5)
    bruit   = random.gauss(0, 30)
    freq    = round(max(400, base + bruit), 3)

    rows.append({
        "node_id":            node_id,
        "ip":                 p["ip"],
        "freq_msg_per_sec":   freq,
        "interval_ms":        int(1000 / freq * 1000),
        "payload_size_bytes": random.randint(40, 80),
        "payload_entropy":    round(random.uniform(0.10, 0.20), 4),
        "nb_connexions":      random.randint(50, 200),
        "label":              "Attack",
        "attack_type":        "DoS",
    })

print(f"  {N_DOS} lignes DoS générées.")

# =============================================================
# GÉNÉRATION Injection_Frozen
# payload_entropy = 0.0 → signature principale.
# Cible : node_3 (Capteur Pression — valeur figée à 4.20 bar).
# =============================================================

print("Génération Injection_Frozen...")

for _ in range(N_INJECTION_FROZEN):
    node_id = "node_3"
    p       = NODE_PROFILES[node_id]

    rows.append({
        "node_id":            node_id,
        "ip":                 p["ip"],
        "freq_msg_per_sec":   round(p["freq"] * random.uniform(0.98, 1.02), 3),
        "interval_ms":        p["interval_ms"],
        "payload_size_bytes": p["size"],
        "payload_entropy":    0.0,      # entropie nulle = valeur figée
        "nb_connexions":      p["nb_connexions"],
        "label":              "Attack",
        "attack_type":        "Injection_Frozen",
    })

print(f"  {N_INJECTION_FROZEN} lignes Injection_Frozen générées.")

# =============================================================
# GÉNÉRATION Injection_Aberrant
# Valeurs physiquement impossibles, paquets surdimensionnés.
# Cible : node_3 et node_4.
# =============================================================

print("Génération Injection_Aberrant...")

targets_inj = ["node_3", "node_4"]
for _ in range(N_INJECTION_ABERRANT):
    node_id = random.choice(targets_inj)
    p       = NODE_PROFILES[node_id]

    rows.append({
        "node_id":            node_id,
        "ip":                 p["ip"],
        "freq_msg_per_sec":   round(p["freq"] * random.uniform(0.95, 1.05), 3),
        "interval_ms":        p["interval_ms"],
        "payload_size_bytes": random.randint(1200, 1500),   # paquet surdimensionné
        "payload_entropy":    round(random.uniform(0.80, 0.99), 4),
        "nb_connexions":      p["nb_connexions"],
        "label":              "Attack",
        "attack_type":        "Injection_Aberrant",
    })

print(f"  {N_INJECTION_ABERRANT} lignes Injection_Aberrant générées.")

# =============================================================
# GÉNÉRATION Probe
# IP inconnue 192.168.1.99, tailles très variables.
# Cible tous les nœuds (scan réseau global).
# =============================================================

print("Génération Probe...")

all_nodes = list(NODE_PROFILES.keys())
for _ in range(N_PROBE):
    node_id = random.choice(all_nodes)

    rows.append({
        "node_id":            node_id,
        "ip":                 "192.168.1.99",    # IP inconnue
        "freq_msg_per_sec":   round(random.uniform(8.0, 20.0), 3),
        "interval_ms":        random.randint(50, 500),
        "payload_size_bytes": random.randint(10, 1500),   # très variable
        "payload_entropy":    round(random.uniform(0.70, 0.90), 4),
        "nb_connexions":      5,
        "label":              "Attack",
        "attack_type":        "Probe",
    })

print(f"  {N_PROBE} lignes Probe générées.")

# =============================================================
# GÉNÉRATION Physical
# Nœud quasi-silencieux, nb_connexions = 0.
# Cible : node_3 et node_4 (composants physiques).
# =============================================================

print("Génération Physical...")

targets_phy = ["node_3", "node_4"]
for _ in range(N_PHYSICAL):
    node_id = random.choice(targets_phy)
    p       = NODE_PROFILES[node_id]

    rows.append({
        "node_id":            node_id,
        "ip":                 p["ip"],
        "freq_msg_per_sec":   round(random.uniform(0.0, 0.05), 3),
        "interval_ms":        random.randint(15000, 30000),
        "payload_size_bytes": random.randint(10, 20),
        "payload_entropy":    round(random.uniform(0.02, 0.10), 4),
        "nb_connexions":      0,
        "label":              "Attack",
        "attack_type":        "Physical",
    })

print(f"  {N_PHYSICAL} lignes Physical générées.")

# =============================================================
# MÉLANGER ET SAUVEGARDER
#
# On mélange toutes les lignes pour que le CSV ne soit pas
# trié par type — le modèle doit apprendre à classifier
# sans s'appuyer sur l'ordre des données.
# =============================================================

print("\nMélange et sauvegarde...")

df = pd.DataFrame(rows)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# Créer le dossier data/ si nécessaire
os.makedirs("data", exist_ok=True)
output_path = "data/dataset_test.csv"
df.to_csv(output_path, index=False)

# =============================================================
# RÉSUMÉ
# =============================================================

print(f"\n{'='*50}")
print("RÉSUMÉ — dataset_test.csv")
print(f"{'='*50}")
print(df["attack_type"].value_counts().to_string())
print(f"\nTotal lignes  : {len(df)}")
print(f"Total colonnes : {len(df.columns)}")
print(f"\nColonnes : {list(df.columns)}")
print(f"\nAperçu des 3 premières lignes :")
print(df.head(3).to_string())
print(f"\nFichier sauvegardé : {output_path}")
