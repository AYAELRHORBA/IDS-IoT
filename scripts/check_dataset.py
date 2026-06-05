# check_dataset.py
import pandas as pd

df = pd.read_csv("data/dataset_real.csv")

print("="*60)
print("VÉRIFICATION DATASET")
print("="*60)

# ── 1. Distribution des classes ───────────────────────
print("\n1. Distribution par classe :")
print(df["attack_type"].value_counts().to_string())

# ── 2. Colonnes présentes ─────────────────────────────
print("\n2. Colonnes présentes :")
print(list(df.columns))

# ── 3. Valeurs manquantes ─────────────────────────────
print("\n3. Valeurs manquantes :")
print(df.isnull().sum().to_string())

# ── 4. Variations par classe ──────────────────────────
print("\n4. Variations par feature par classe :")
features = [
    "freq_msg_per_sec",
    "interval_ms",
    "payload_size_bytes",
    "payload_entropy",
    "nb_connexions"
]
print(df.groupby("attack_type")[features].agg(["min","max","std"]).round(3).to_string())

# ── 5. Vérifier séparabilité ─────────────────────────
print("\n5. Moyennes par classe (séparabilité) :")
print(df.groupby("attack_type")[features].mean().round(3).to_string())