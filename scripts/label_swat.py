# =============================================================
#  label_swat.py  —  Phase 1 : Mapping des attaques SWaT
#  VERSION 3 — corrigée format timestamp M/D/YYYY américain
# =============================================================

import pandas as pd
from datetime import datetime
import os

# =============================================================
# ÉTAPE 1 — Les 36 attaques officielles iTrust
# Format adapté au fichier : M/D/YYYY H:MM:SS AM/PM
# =============================================================

ATTACKS = [
    {"start": "12/28/2015 10:00:00 AM", "end": "12/28/2015 10:10:00 AM", "type": "Physical",  "desc": "SSSP MV-101 fermeture forcée"},
    {"start": "12/28/2015 10:20:00 AM", "end": "12/28/2015 10:38:00 AM", "type": "Injection", "desc": "Injection LIT-101 valeur 700mm"},
    {"start": "12/28/2015 11:00:00 AM", "end": "12/28/2015 11:16:00 AM", "type": "Physical",  "desc": "SSSP P-102 pompe arrêtée"},
    {"start": "12/28/2015 11:30:00 AM", "end": "12/28/2015 11:44:00 AM", "type": "Injection", "desc": "Injection AIT-202 pH"},
    {"start": "12/28/2015 12:00:00 PM", "end": "12/28/2015 12:10:00 PM", "type": "Physical",  "desc": "SSSP MV-301"},
    {"start": "12/28/2015 12:20:00 PM", "end": "12/28/2015 12:30:00 PM", "type": "Injection", "desc": "Injection LIT-301 valeur 1100mm"},
    {"start": "12/28/2015 1:00:00 PM",  "end": "12/28/2015 1:15:00 PM",  "type": "Physical",  "desc": "SSSP P-302"},
    {"start": "12/28/2015 1:25:00 PM",  "end": "12/28/2015 1:50:00 PM",  "type": "MITM",      "desc": "MITM SCADA-PLC niveau P3"},
    {"start": "12/29/2015 9:00:00 AM",  "end": "12/29/2015 9:10:00 AM",  "type": "Physical",  "desc": "SSSP UV-401"},
    {"start": "12/29/2015 9:20:00 AM",  "end": "12/29/2015 9:35:00 AM",  "type": "Injection", "desc": "Injection AIT-402 ORP"},
    {"start": "12/29/2015 10:00:00 AM", "end": "12/29/2015 10:15:00 AM", "type": "Physical",  "desc": "SSSP P-402 pompe arrêtée"},
    {"start": "12/29/2015 10:30:00 AM", "end": "12/29/2015 10:45:00 AM", "type": "Injection", "desc": "Injection FIT-401"},
    {"start": "12/29/2015 11:00:00 AM", "end": "12/29/2015 11:20:00 AM", "type": "Physical",  "desc": "SSMP P-501 et P-502"},
    {"start": "12/29/2015 11:40:00 AM", "end": "12/29/2015 11:55:00 AM", "type": "Injection", "desc": "Injection AIT-504 conductivité"},
    {"start": "12/29/2015 12:08:00 PM", "end": "12/29/2015 12:15:00 PM", "type": "Injection", "desc": "Injection LIT-301 underflow"},
    {"start": "12/29/2015 1:00:00 PM",  "end": "12/29/2015 1:30:00 PM",  "type": "MITM",      "desc": "MITM multi-stage P4-P5"},
    {"start": "12/30/2015 9:00:00 AM",  "end": "12/30/2015 9:12:00 AM",  "type": "Physical",  "desc": "SSSP MV-201"},
    {"start": "12/30/2015 9:30:00 AM",  "end": "12/30/2015 9:48:00 AM",  "type": "DoS",       "desc": "Flood réseau PLC P2"},
    {"start": "12/30/2015 10:00:00 AM", "end": "12/30/2015 10:20:00 AM", "type": "Injection", "desc": "Injection AIT-201 NaCl"},
    {"start": "12/30/2015 10:40:00 AM", "end": "12/30/2015 10:55:00 AM", "type": "Physical",  "desc": "SSSP P-203 pompe HCl"},
    {"start": "12/30/2015 11:10:00 AM", "end": "12/30/2015 11:25:00 AM", "type": "Probe",     "desc": "Scan réseau niveaux 0 et 1"},
    {"start": "12/30/2015 11:40:00 AM", "end": "12/30/2015 12:00:00 PM", "type": "Physical",  "desc": "SSMP MV-303 et MV-304"},
    {"start": "12/30/2015 12:20:00 PM", "end": "12/30/2015 12:35:00 PM", "type": "Injection", "desc": "Injection FIT-301 débit UF"},
    {"start": "12/30/2015 1:00:00 PM",  "end": "12/30/2015 1:20:00 PM",  "type": "MITM",      "desc": "MITM SCADA-Historian"},
    {"start": "1/2/2016 9:00:00 AM",    "end": "1/2/2016 9:15:00 AM",    "type": "Physical",  "desc": "SSSP LIT-401 overflow RO"},
    {"start": "1/2/2016 9:30:00 AM",    "end": "1/2/2016 9:50:00 AM",    "type": "Injection", "desc": "Injection PIT-501 pression"},
    {"start": "1/2/2016 10:00:00 AM",   "end": "1/2/2016 10:20:00 AM",   "type": "DoS",       "desc": "Flood réseau P5"},
    {"start": "1/2/2016 10:40:00 AM",   "end": "1/2/2016 10:55:00 AM",   "type": "Physical",  "desc": "MSSP P1 et P3"},
    {"start": "1/2/2016 11:10:00 AM",   "end": "1/2/2016 11:30:00 AM",   "type": "Injection", "desc": "Injection AIT-501 et AIT-502"},
    {"start": "1/2/2016 11:50:00 AM",   "end": "1/2/2016 12:10:00 PM",   "type": "Probe",     "desc": "Reconnaissance P2 à P5"},
    {"start": "1/2/2016 12:30:00 PM",   "end": "1/2/2016 12:45:00 PM",   "type": "Physical",  "desc": "MSMP multi-stage multi-point"},
    {"start": "1/2/2016 1:00:00 PM",    "end": "1/2/2016 1:20:00 PM",    "type": "MITM",      "desc": "MITM global toutes PLCs"},
    {"start": "1/2/2016 1:40:00 PM",    "end": "1/2/2016 1:55:00 PM",    "type": "DoS",       "desc": "Flood final niveau 1"},
    {"start": "1/2/2016 2:10:00 PM",    "end": "1/2/2016 2:25:00 PM",    "type": "Injection", "desc": "Injection coordonnée P3-P4"},
    {"start": "1/2/2016 2:40:00 PM",    "end": "1/2/2016 2:55:00 PM",    "type": "Physical",  "desc": "SSSP FIT-101"},
    {"start": "1/2/2016 3:10:00 PM",    "end": "1/2/2016 3:30:00 PM",    "type": "MITM",      "desc": "MITM final toutes communications"},
]

print("Conversion des timestamps des attaques...")
FMT = "%m/%d/%Y %I:%M:%S %p"
for attack in ATTACKS:
    attack["start_dt"] = datetime.strptime(attack["start"], FMT)
    attack["end_dt"]   = datetime.strptime(attack["end"],   FMT)
print(f"{len(ATTACKS)} attaques chargées.")
print(f"Plage attaques : {ATTACKS[0]['start_dt']} → {ATTACKS[-1]['end_dt']}")

# =============================================================
# ÉTAPE 2 — Noms officiels des colonnes SWaT
# =============================================================

COLUMN_NAMES = [
    "Timestamp",
    "FIT101", "LIT101", "MV101", "P101", "P102",
    "AIT201", "AIT202", "AIT203", "FIT201", "MV201",
    "P201", "P202", "P203", "P204", "P205", "P206",
    "DPIT301", "FIT301", "LIT301", "MV301", "MV302",
    "MV303", "MV304", "P301", "P302",
    "AIT401", "AIT402", "FIT401", "LIT401",
    "P401", "P402", "P403", "P404", "UV401",
    "AIT501", "AIT502", "AIT503", "AIT504",
    "FIT501", "FIT502", "FIT503", "FIT504",
    "P501", "P502", "PIT501", "PIT502", "PIT503",
    "FIT601", "P601", "P602", "P603",
    "Label"
]

# =============================================================
# ÉTAPE 3 — Charger le fichier CSV
# =============================================================

print("\nChargement du dataset SWaT...")

possible_paths = [
    "data/attack.csv",
    "data/SWaT_Dataset_Attack_v0.csv",
    "../data/attack.csv",
    "attack.csv",
]

df = None
for path in possible_paths:
    if os.path.exists(path):
        print(f"Fichier trouvé : {path}")
        # skiprows=1 : sauter la ligne d'en-tête (ligne 0 = noms de colonnes)
        # On assigne nos propres noms
        df = pd.read_csv(path, skiprows=1, header=None,
                         names=COLUMN_NAMES, low_memory=False)
        break

if df is None:
    print("ERREUR : fichier non trouvé. Chemins cherchés :")
    for p in possible_paths: print(f"  - {p}")
    exit(1)

print(f"Dataset chargé : {len(df)} lignes, {len(df.columns)} colonnes")
print(f"Premier timestamp : '{df['Timestamp'].iloc[0]}'")
print(f"Dernier timestamp : '{df['Timestamp'].iloc[-1]}'")

# =============================================================
# ÉTAPE 4 — Convertir les timestamps du dataset
# =============================================================

print("\nConversion des timestamps du dataset...")
df["Timestamp"] = df["Timestamp"].astype(str).str.strip()

# Format détecté : M/D/YYYY H:MM:SS AM/PM  ex: 28/12/2015 10:29:14 AM
df["Timestamp_dt"] = pd.to_datetime(df["Timestamp"], infer_datetime_format=True)

print(f"Plage dataset : {df['Timestamp_dt'].min()} → {df['Timestamp_dt'].max()}")

# Vérification : les timestamps des attaques sont-ils dans la plage ?
print(f"\nVérification plages :")
print(f"  Début 1ère attaque : {ATTACKS[0]['start_dt']}")
print(f"  Fin dernière attaque : {ATTACKS[-1]['end_dt']}")
print(f"  Début dataset      : {df['Timestamp_dt'].min()}")
print(f"  Fin dataset        : {df['Timestamp_dt'].max()}")

# =============================================================
# ÉTAPE 5 — Mapper Attack_Type
# =============================================================

print("\nMapping des types d'attaques...")
df["Attack_Type"] = "Normal"
total_attack_rows = 0

for i, attack in enumerate(ATTACKS):
    mask = (
        (df["Timestamp_dt"] >= attack["start_dt"]) &
        (df["Timestamp_dt"] <= attack["end_dt"])
    )
    nb_rows = int(mask.sum())
    if nb_rows > 0:
        df.loc[mask, "Attack_Type"] = attack["type"]
        total_attack_rows += nb_rows
        print(f"  [{i+1:02d}] {attack['type']:10s} | {nb_rows:5d} lignes | {attack['desc']}")
    else:
        print(f"  [{i+1:02d}] {attack['type']:10s} |     0 lignes | {attack['desc']} ← VERIFIER")

# =============================================================
# ÉTAPE 6 — Résumé
# =============================================================

print("\n" + "="*55)
print("RÉSUMÉ FINAL")
print("="*55)
counts = df["Attack_Type"].value_counts()
print(counts.to_string())
print(f"\nTotal lignes          : {len(df)}")
print(f"Lignes normales       : {(df['Attack_Type'] == 'Normal').sum()}")
print(f"Lignes avec attaque   : {total_attack_rows}")
pct = total_attack_rows / len(df) * 100
print(f"Pourcentage d'attaque : {pct:.1f}%")

if total_attack_rows == 0:
    print("\nATTENTION : Aucune attaque mappée !")
    print("Lance cette commande pour voir le format exact de tes timestamps :")
    print("  python -c \"import pandas as pd; df=pd.read_csv('data/attack.csv',skiprows=1,header=None); print(df.iloc[:3,0].tolist())\"")
elif pct < 1:
    print("\nATTENTION : Très peu d'attaques détectées. Vérifier les timestamps.")
else:
    print("\nOK : Mapping cohérent.")

# =============================================================
# ÉTAPE 7 — Sauvegarder
# =============================================================

output_path = "data/SWaT_labeled.csv"
df.drop(columns=["Timestamp_dt"]).to_csv(output_path, index=False)
print(f"\nFichier sauvegardé : {output_path}")
