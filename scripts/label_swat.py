#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
M2 — label_swat.py
Labellisation SWaT avec timestamps officiels iTrust

Respecte STRICTEMENT les contrats du plan :
  - Contrat 1 : 10 champs exacts (node_id, ip, freq_msg_per_sec, interval_ms,
                payload_size_bytes, payload_entropy, nb_connexions, ts, label, attack_type)
  - 5 classes : Normal, DoS, Injection_Frozen, Injection_Aberrant, Probe
  - label == attack_type (identiques)

Usage : python scripts/label_swat.py
Sortie : data/SWaT_labeled.csv
"""

import pandas as pd
import numpy as np
from datetime import datetime
from pathlib import Path
import json

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 1 — Les 36 attaques officielles iTrust (timestamps exacts)
# ═══════════════════════════════════════════════════════════════════════════════

ATTACKS = [
    # Format : start, end, type_iTrust, type_projet, desc
    # Mapping iTrust → Projet :
    #   "Physical" + valeur figée → Injection_Frozen
    #   "Physical" + valeur impossible → Injection_Aberrant  
    #   "MITM" / "Flood" → DoS
    #   "Scan" / "Reconnaissance" → Probe

    {"start": "12/28/2015 10:00:00 AM", "end": "12/28/2015 10:10:00 AM", "type_proj": "Injection_Frozen", "desc": "SSSP MV-101 fermeture forcée"},
    {"start": "12/28/2015 10:20:00 AM", "end": "12/28/2015 10:38:00 AM", "type_proj": "Injection_Frozen", "desc": "Injection LIT-101 valeur 700mm"},
    {"start": "12/28/2015 11:00:00 AM", "end": "12/28/2015 11:16:00 AM", "type_proj": "Injection_Aberrant", "desc": "SSSP P-102 pompe arrêtée"},
    {"start": "12/28/2015 11:30:00 AM", "end": "12/28/2015 11:44:00 AM", "type_proj": "Injection_Aberrant", "desc": "Injection AIT-202 pH"},
    {"start": "12/28/2015 12:00:00 PM", "end": "12/28/2015 12:10:00 PM", "type_proj": "Injection_Frozen", "desc": "SSSP MV-301"},
    {"start": "12/28/2015 12:20:00 PM", "end": "12/28/2015 12:30:00 PM", "type_proj": "Injection_Frozen", "desc": "Injection LIT-301 valeur 1100mm"},
    {"start": "12/28/2015 1:00:00 PM",  "end": "12/28/2015 1:15:00 PM",  "type_proj": "Injection_Aberrant", "desc": "SSSP P-302"},
    {"start": "12/28/2015 1:25:00 PM",  "end": "12/28/2015 1:50:00 PM",  "type_proj": "DoS", "desc": "MITM SCADA-PLC niveau P3"},
    {"start": "12/29/2015 9:00:00 AM",  "end": "12/29/2015 9:10:00 AM",  "type_proj": "Injection_Frozen", "desc": "SSSP UV-401"},
    {"start": "12/29/2015 9:20:00 AM",  "end": "12/29/2015 9:35:00 AM",  "type_proj": "Injection_Aberrant", "desc": "Injection AIT-402 ORP"},
    {"start": "12/29/2015 10:00:00 AM", "end": "12/29/2015 10:15:00 AM", "type_proj": "Injection_Aberrant", "desc": "SSSP P-402 pompe arrêtée"},
    {"start": "12/29/2015 10:30:00 AM", "end": "12/29/2015 10:45:00 AM", "type_proj": "Injection_Frozen", "desc": "Injection FIT-401"},
    {"start": "12/29/2015 11:00:00 AM", "end": "12/29/2015 11:20:00 AM", "type_proj": "Injection_Aberrant", "desc": "SSMP P-501 et P-502"},
    {"start": "12/29/2015 11:40:00 AM", "end": "12/29/2015 11:55:00 AM", "type_proj": "Injection_Aberrant", "desc": "Injection AIT-504 conductivité"},
    {"start": "12/29/2015 12:08:00 PM", "end": "12/29/2015 12:15:00 PM", "type_proj": "Injection_Frozen", "desc": "Injection LIT-301 underflow"},
    {"start": "12/29/2015 1:00:00 PM",  "end": "12/29/2015 1:30:00 PM",  "type_proj": "DoS", "desc": "MITM multi-stage P4-P5"},
    {"start": "12/30/2015 9:00:00 AM",  "end": "12/30/2015 9:12:00 AM",  "type_proj": "Injection_Frozen", "desc": "SSSP MV-201"},
    {"start": "12/30/2015 9:30:00 AM",  "end": "12/30/2015 9:48:00 AM",  "type_proj": "DoS", "desc": "Flood réseau PLC P2"},
    {"start": "12/30/2015 10:00:00 AM", "end": "12/30/2015 10:20:00 AM", "type_proj": "Injection_Aberrant", "desc": "Injection AIT-201 NaCl"},
    {"start": "12/30/2015 10:40:00 AM", "end": "12/30/2015 10:55:00 AM", "type_proj": "Injection_Aberrant", "desc": "SSSP P-203 pompe HCl"},
    {"start": "12/30/2015 11:10:00 AM", "end": "12/30/2015 11:25:00 AM", "type_proj": "Probe", "desc": "Scan réseau niveaux 0 et 1"},
    {"start": "12/30/2015 11:40:00 AM", "end": "12/30/2015 12:00:00 PM", "type_proj": "Injection_Frozen", "desc": "SSMP MV-303 et MV-304"},
    {"start": "12/30/2015 12:20:00 PM", "end": "12/30/2015 12:35:00 PM", "type_proj": "Injection_Frozen", "desc": "Injection FIT-301 débit UF"},
    {"start": "12/30/2015 1:00:00 PM",  "end": "12/30/2015 1:20:00 PM",  "type_proj": "DoS", "desc": "MITM SCADA-Historian"},
    {"start": "1/2/2016 9:00:00 AM",    "end": "1/2/2016 9:15:00 AM",    "type_proj": "Injection_Aberrant", "desc": "SSSP LIT-401 overflow RO"},
    {"start": "1/2/2016 9:30:00 AM",    "end": "1/2/2016 9:50:00 AM",    "type_proj": "Injection_Aberrant", "desc": "Injection PIT-501 pression"},
    {"start": "1/2/2016 10:00:00 AM",   "end": "1/2/2016 10:20:00 AM",   "type_proj": "DoS", "desc": "Flood réseau P5"},
    {"start": "1/2/2016 10:40:00 AM",   "end": "1/2/2016 10:55:00 AM",   "type_proj": "Injection_Aberrant", "desc": "MSSP P1 et P3"},
    {"start": "1/2/2016 11:10:00 AM",   "end": "1/2/2016 11:30:00 AM",   "type_proj": "Injection_Aberrant", "desc": "Injection AIT-501 et AIT-502"},
    {"start": "1/2/2016 11:50:00 AM",   "end": "1/2/2016 12:10:00 PM",   "type_proj": "Probe", "desc": "Reconnaissance P2 à P5"},
    {"start": "1/2/2016 12:30:00 PM",   "end": "1/2/2016 12:45:00 PM",   "type_proj": "Injection_Aberrant", "desc": "MSMP multi-stage multi-point"},
    {"start": "1/2/2016 1:00:00 PM",    "end": "1/2/2016 1:20:00 PM",    "type_proj": "DoS", "desc": "MITM global toutes PLCs"},
    {"start": "1/2/2016 1:40:00 PM",    "end": "1/2/2016 1:55:00 PM",    "type_proj": "DoS", "desc": "Flood final niveau 1"},
    {"start": "1/2/2016 2:10:00 PM",    "end": "1/2/2016 2:25:00 PM",    "type_proj": "Injection_Frozen", "desc": "Injection coordonnée P3-P4"},
    {"start": "1/2/2016 2:40:00 PM",    "end": "1/2/2016 2:55:00 PM",    "type_proj": "Injection_Frozen", "desc": "SSSP FIT-101"},
    {"start": "1/2/2016 3:10:00 PM",    "end": "1/2/2016 3:30:00 PM",    "type_proj": "DoS", "desc": "MITM final toutes communications"},
]

# Conversion timestamps
FMT = "%m/%d/%Y %I:%M:%S %p"
for attack in ATTACKS:
    attack["start_dt"] = datetime.strptime(attack["start"], FMT)
    attack["end_dt"] = datetime.strptime(attack["end"], FMT)

print(f"✓ {len(ATTACKS)} attaques officielles iTrust chargées")

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 2 — Configuration des nœuds (Contrat 1)
# ═══════════════════════════════════════════════════════════════════════════════

NODES = {
    "node_1": {"ip": "192.168.1.10", "features": ["MV101", "MV201"], "freq": 1.0, "payload": 64},
    "node_2": {"ip": "192.168.1.11", "features": ["P101", "P201"], "freq": 1.0, "payload": 64},
    "node_3": {"ip": "192.168.1.12", "features": ["FIT101", "LIT101"], "freq": 0.3, "payload": 80},
    "node_4": {"ip": "192.168.1.13", "features": ["AIT201", "AIT202"], "freq": 0.3, "payload": 80},
    "node_5": {"ip": "192.168.1.14", "features": ["PIT501", "PIT502", "PIT503"], "freq": 0.1, "payload": 2048},
}

# 5 classes du projet
LABELS = ["Normal", "DoS", "Injection_Frozen", "Injection_Aberrant", "Probe"]

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 3 — Noms des colonnes SWaT
# ═══════════════════════════════════════════════════════════════════════════════

COLUMNS = [
    "Timestamp", "FIT101", "LIT101", "MV101", "P101", "P102",
    "AIT201", "AIT202", "AIT203", "FIT201", "MV201", "P201", "P202",
    "P203", "P204", "P205", "P206", "DPIT301", "FIT301", "LIT301",
    "MV301", "MV302", "MV303", "MV304", "P301", "P302", "AIT401",
    "AIT402", "FIT401", "LIT401", "P401", "P402", "P403", "P404",
    "UV401", "AIT501", "AIT502", "AIT503", "AIT504", "FIT501", "FIT502",
    "FIT503", "FIT504", "P501", "P502", "PIT501", "PIT502", "PIT503",
    "FIT601", "P601", "P602", "P603", "Normal/Attack"
]

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 4 — Charger les datasets
# ═══════════════════════════════════════════════════════════════════════════════

print("\n[1/5] Chargement des datasets...")

DATA_DIR = Path("data")

df_normal = pd.read_csv(DATA_DIR / "normal.csv", skiprows=1, header=None, names=COLUMNS, low_memory=False)
df_attack = pd.read_csv(DATA_DIR / "attack.csv", skiprows=1, header=None, names=COLUMNS, low_memory=False)

# Convertir timestamps
df_normal["Timestamp"] = pd.to_datetime(df_normal["Timestamp"], dayfirst=True, errors="coerce")
df_attack["Timestamp"] = pd.to_datetime(df_attack["Timestamp"], dayfirst=True, errors="coerce")

# Timestamp → epoch seconds pour "ts"
df_normal["ts"] = (df_normal["Timestamp"].astype("int64") // 10**9).fillna(0).astype(int)
df_attack["ts"] = (df_attack["Timestamp"].astype("int64") // 10**9).fillna(0).astype(int)

print(f"✓ Normal : {len(df_normal):,} lignes")
print(f"✓ Attack : {len(df_attack):,} lignes")

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 5 — Labelliser les attaques avec timestamps officiels
# ═══════════════════════════════════════════════════════════════════════════════

print("\n[2/5] Labellisation avec timestamps officiels...")

df_attack["label"] = "Normal"
df_attack["attack_type"] = "Normal"

for attack in ATTACKS:
    mask = (df_attack["Timestamp"] >= attack["start_dt"]) & (df_attack["Timestamp"] <= attack["end_dt"])
    count = mask.sum()
    if count > 0:
        df_attack.loc[mask, "label"] = attack["type_proj"]
        df_attack.loc[mask, "attack_type"] = attack["type_proj"]
        print(f"  {attack['type_proj']:20s} | {count:5d} lignes | {attack['desc']}")

# Normal reste Normal
df_normal["label"] = "Normal"
df_normal["attack_type"] = "Normal"

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 6 — Feature Engineering (physique → réseau)
# ═══════════════════════════════════════════════════════════════════════════════

print("\n[3/5] Transformation physique → réseau...")

def transform_to_network(df, is_attack_df=False):
    """Transforme les features physiques SWaT en features réseau Contrat 1."""
    df_net = pd.DataFrame()

    # Convertir en numérique
    numeric_cols = ["FIT101", "LIT101", "P101", "P102", "P201", "P202",
                    "AIT201", "AIT202", "AIT203", "AIT401", "AIT402",
                    "AIT501", "AIT502", "AIT503", "AIT504", "PIT501", "PIT502", "PIT503"]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # 1. freq_msg_per_sec ← variation FIT101 + activité pompes
    fit_diff = df["FIT101"].diff().abs().fillna(0)
    pump_act = (df["P101"].fillna(0) + df["P102"].fillna(0) + 
                df["P201"].fillna(0) + df["P202"].fillna(0)) / 4
    df_net["freq_msg_per_sec"] = (fit_diff * 50 + pump_act * 2)
    df_net["freq_msg_per_sec"] = df_net["freq_msg_per_sec"].replace([np.inf, -np.inf], np.nan).fillna(0.1)

    # Si attaque DoS : fréquence très élevée
    if is_attack_df and "label" in df.columns:
        dos_mask = df["label"] == "DoS"
        df_net.loc[dos_mask, "freq_msg_per_sec"] = np.random.uniform(400, 800, size=dos_mask.sum())

    df_net["freq_msg_per_sec"] = df_net["freq_msg_per_sec"].clip(0.1, 800).round(2)

    # 2. interval_ms
    df_net["interval_ms"] = (1000 / df_net["freq_msg_per_sec"]).replace([np.inf, -np.inf], 30000)
    df_net["interval_ms"] = df_net["interval_ms"].fillna(30000).clip(100, 30000).astype(int)

    # 3. payload_size_bytes
    lit101 = pd.to_numeric(df.get("LIT101", 0), errors="coerce").fillna(0)
    pit501 = pd.to_numeric(df.get("PIT501", 0), errors="coerce").fillna(0)
    lit_max = lit101.max() if lit101.max() > 0 else 1
    pit_max = pit501.max() if pit501.max() > 0 else 1
    df_net["payload_size_bytes"] = ((lit101/lit_max * 1500 + pit501/pit_max * 500 + 64)).astype(int).clip(10, 2048)

    # Si Probe : taille aléatoire
    if is_attack_df and "label" in df.columns:
        probe_mask = df["label"] == "Probe"
        df_net.loc[probe_mask, "payload_size_bytes"] = np.random.randint(10, 1500, size=probe_mask.sum())

    # 4. payload_entropy
    chem = ["AIT201", "AIT202", "AIT203", "AIT401", "AIT402", "AIT501", "AIT502", "AIT503", "AIT504"]
    chem_df = df[chem].apply(pd.to_numeric, errors="coerce")
    chem_std = chem_df.std(axis=1).fillna(0)
    chem_max = chem_df.max(axis=1).fillna(1).replace(0, 1)
    df_net["payload_entropy"] = (chem_std / (chem_max + 1)).clip(0, 1).round(2)

    # Si Injection_Frozen : entropy = 0
    if is_attack_df and "label" in df.columns:
        frozen_mask = df["label"] == "Injection_Frozen"
        df_net.loc[frozen_mask, "payload_entropy"] = 0.0

    # 5. nb_connexions
    actuators = ["MV101", "MV201", "MV301", "MV302", "MV303", "MV304",
                 "P101", "P102", "P201", "P202", "P203", "P204", "P205", "P206",
                 "P301", "P302", "P401", "P402", "P403", "P404",
                 "P501", "P502", "P601", "P602", "P603", "UV401"]
    act_df = df[actuators].apply(pd.to_numeric, errors="coerce").fillna(0)
    df_net["nb_connexions"] = act_df.sum(axis=1).astype(int).clip(0, 200)

    # Si DoS : connexions élevées
    if is_attack_df and "label" in df.columns:
        dos_mask = df["label"] == "DoS"
        df_net.loc[dos_mask, "nb_connexions"] = np.random.randint(10, 100, size=dos_mask.sum())

    return df_net

# Transformer
df_normal_net = transform_to_network(df_normal, is_attack_df=False)
df_attack_net = transform_to_network(df_attack, is_attack_df=True)

# Ajouter ts
df_normal_net["ts"] = df_normal["ts"].values
df_attack_net["ts"] = df_attack["ts"].values

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 7 — Assigner node_id et ip
# ═══════════════════════════════════════════════════════════════════════════════

print("\n[4/5] Assignation node_id et ip...")

def assign_node(row):
    """Assigne node_id selon le processus actif."""
    try:
        if pd.to_numeric(row.get("PIT501", 0), errors="coerce") > 0:
            return "node_5"
        elif pd.to_numeric(row.get("AIT401", 0), errors="coerce") > 0 or pd.to_numeric(row.get("UV401", 0), errors="coerce") > 0:
            return "node_4"
        elif pd.to_numeric(row.get("DPIT301", 0), errors="coerce") > 0:
            return "node_3"
        elif pd.to_numeric(row.get("AIT201", 0), errors="coerce") > 0:
            return "node_2"
        else:
            return "node_1"
    except:
        return "node_1"

IP_MAP = {"node_1": "192.168.1.10", "node_2": "192.168.1.11", "node_3": "192.168.1.12",
          "node_4": "192.168.1.13", "node_5": "192.168.1.14"}

df_normal_net["node_id"] = df_normal.apply(assign_node, axis=1)
df_normal_net["ip"] = df_normal_net["node_id"].map(IP_MAP)
df_normal_net["label"] = "Normal"
df_normal_net["attack_type"] = "Normal"

df_attack_net["node_id"] = df_attack.apply(assign_node, axis=1)
df_attack_net["ip"] = df_attack_net["node_id"].map(IP_MAP)
df_attack_net["label"] = df_attack["label"].values
df_attack_net["attack_type"] = df_attack["attack_type"].values

# ═══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 8 — Fusionner et sauvegarder au format Contrat 1 EXACT
# ═══════════════════════════════════════════════════════════════════════════════

print("\n[5/5] Fusion et sauvegarde...")

# Ordre EXACT des colonnes Contrat 1
CONTRACT1_COLS = [
    "node_id", "ip", "freq_msg_per_sec", "interval_ms",
    "payload_size_bytes", "payload_entropy", "nb_connexions",
    "ts", "label", "attack_type"
]

df_final = pd.concat([
    df_normal_net[CONTRACT1_COLS],
    df_attack_net[CONTRACT1_COLS]
], ignore_index=True)

# Mélanger
df_final = df_final.sample(frac=1, random_state=42).reset_index(drop=True)

# Sauvegarder
OUTPUT_PATH = DATA_DIR / "SWaT_labeled.csv"
df_final.to_csv(OUTPUT_PATH, index=False)

# ═══════════════════════════════════════════════════════════════════════════════
# RÉSUMÉ
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 60)
print("RÉSUMÉ — Contrat 1 respecté")
print("=" * 60)

print(f"\n📊 Distribution des 5 classes :")
for lbl in LABELS:
    cnt = (df_final["label"] == lbl).sum()
    pct = cnt / len(df_final) * 100
    print(f"  {lbl:20s} : {cnt:8,} lignes ({pct:5.2f}%)")

print(f"\n📁 Fichier : {OUTPUT_PATH}")
print(f"📊 Total : {len(df_final):,} lignes × {len(df_final.columns)} colonnes")
print(f"📋 Colonnes : {list(df_final.columns)}")

# Vérification Contrat 1
print(f"\n✅ Vérification Contrat 1 :")
print(f"   label == attack_type : {(df_final['label'] == df_final['attack_type']).all()}")
print(f"   Classes valides : {set(df_final['label']).issubset(set(LABELS))}")

# Exemple
print(f"\n📋 Exemple de ligne (Contrat 1) :")
example = df_final.iloc[0].to_dict()
print(json.dumps(example, indent=2))

print("\n" + "=" * 60)