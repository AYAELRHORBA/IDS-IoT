# =============================================================
#
#  attack_injector.py — VERSION FINALE CORRIGÉE v3
#  IDS-IoT SWaT | Membre 1 : Aya EL RHORBA
#
#  Corrections v3 :
#    - Bruit naturel important sur toutes les features
#    - Valeurs fixes supprimées (nb_connexions, entropy, ip)
#    - Chevauchement réaliste entre classes pour éviter acc=1.00
#    - DoS peut descendre à 30 msg/sec (zone grise)
#    - Probe : IP variable, nb_connexions 2-10
#    - Physical : nb_connexions 0-2
#    - Injection_Frozen : entropy 0.0-0.08 (pas toujours 0 exact)
#    - Injection_Aberrant : size 700-1600 (plage élargie)
#
#  Usage :
#    python scripts/attack_injector.py --mode dos
#    python scripts/attack_injector.py --mode injection_frozen
#    python scripts/attack_injector.py --mode injection_aberrant
#    python scripts/attack_injector.py --mode probe
#    python scripts/attack_injector.py --mode physical
#    python scripts/attack_injector.py --mode dos --duration 30
#
# =============================================================

import paho.mqtt.client as mqtt
import json
import time
import random
import math
import argparse
from datetime import datetime

# =============================================================
# CONFIGURATION GLOBALE
# =============================================================

BROKER_HOST      = "localhost"
BROKER_PORT      = 1883
PUBLISH_INTERVAL = 2

TOPICS = {
    "node_1": "iiot/node_1/data",
    "node_2": "iiot/node_2/data",
    "node_3": "iiot/node_3/data",
    "node_4": "iiot/node_4/data",
    "node_5": "iiot/node_5/data",
}

NODE_PROFILES = {
    "node_1": {
        "ip": "192.168.1.10", "type": "CBR",
        "freq": 1.0, "size": 64, "interval_ms": 1000,
        "nb_connexions": 1, "entropy": 0.52,
    },
    "node_2": {
        "ip": "192.168.1.11", "type": "CBR",
        "freq": 1.0, "size": 64, "interval_ms": 1000,
        "nb_connexions": 1, "entropy": 0.50,
    },
    "node_3": {
        "ip": "192.168.1.12", "type": "VBR",
        "freq": 0.3, "size": 80, "interval_ms": 3000,
        "nb_connexions": 1, "entropy": 0.48,
    },
    "node_4": {
        "ip": "192.168.1.13", "type": "VBR",
        "freq": 0.3, "size": 80, "interval_ms": 3000,
        "nb_connexions": 1, "entropy": 0.46,
    },
    "node_5": {
        "ip": "192.168.1.14", "type": "Bulk",
        "freq": 0.1, "size": 2048, "interval_ms": 10000,
        "nb_connexions": 3, "entropy": 0.71,
    },
}

# =============================================================
# GÉNÉRATEUR TRAFIC NORMAL
# Utilisé pour les nœuds non ciblés pendant une attaque.
# Bruit large pour créer du chevauchement réaliste avec attaques.
# =============================================================

def generate_normal(node_id, profile):
    ptype = profile["type"]

    if ptype == "CBR":
        freq     = round(profile["freq"] * random.uniform(0.80, 1.20), 3)
        size     = int(profile["size"] * random.uniform(0.80, 1.20))
        interval = int(profile["interval_ms"] * random.uniform(0.80, 1.20))
        entropy  = round(profile["entropy"] * random.uniform(0.80, 1.20), 4)
        nb_conn  = random.choice([1, 1, 1, 2])

    elif ptype == "VBR":
        freq     = round(random.uniform(0.05, 0.70), 3)
        size     = int(profile["size"] * random.uniform(0.60, 1.45))
        interval = int(random.uniform(700, 12000))
        entropy  = round(random.uniform(0.28, 0.72), 4)
        nb_conn  = random.choice([1, 1, 2, 2, 3])

    else:  # Bulk
        freq     = round(profile["freq"] * random.uniform(0.75, 1.25), 3)
        size     = int(profile["size"] * random.uniform(0.88, 1.12))
        interval = int(profile["interval_ms"] * random.uniform(0.75, 1.25))
        entropy  = round(profile["entropy"] * random.uniform(0.82, 1.18), 4)
        nb_conn  = random.choice([2, 3, 3, 3, 4])

    # 8% du temps : pic momentané normal — chevauchement avec DoS
    if random.random() < 0.08:
        freq     = round(freq * random.uniform(3.0, 8.0), 3)
        interval = int(interval * random.uniform(0.15, 0.50))
        nb_conn  = nb_conn + random.randint(1, 3)

    # 3% du temps : taille anormalement grande mais normale
    if random.random() < 0.03:
        size = min(int(size * random.uniform(4.0, 10.0)), 2500)

    return {
        "node_id":            node_id,
        "ip":                 profile["ip"],
        "freq_msg_per_sec":   freq,
        "interval_ms":        interval,
        "payload_size_bytes": size,
        "payload_entropy":    entropy,
        "nb_connexions":      nb_conn,
        "ts":                 int(time.time()),
        "label":              "Normal",
        "attack_type":        "Normal",
    }

# =============================================================
# ATTAQUE 1 — DoS en vagues progressives
#
# Corrections v3 :
#   - freq peut descendre à 30 (zone grise avec normal)
#   - nb_connexions gaussien µ=80 σ=35 (parfois bas)
#   - entropy légèrement plus variable (0.07-0.32)
#   - interval avec bruit ±30%
# =============================================================

def generate_dos(node_id, profile, i):
    """
    DoS en vagues sinusoïdales progressives.
    Fréquence entre 30 et 860 msg/sec.
    Zone grise intentionnelle en bas (30-150) pour
    forcer le modèle à apprendre le pattern global.
    """
    t     = i * 0.3
    base  = 400 + 300 * math.sin(t / 4)
    bruit = random.gauss(0, 80)
    freq  = round(max(30, base + bruit), 3)

    # nb_connexions : gaussien — parfois bas pour zone grise
    nb_conn = max(5, int(random.gauss(80, 35)))

    # interval inversement proportionnel à freq + bruit
    interval = max(1, int((1000 / max(freq, 1)) * random.uniform(0.7, 1.3)))

    return {
        "node_id":            node_id,
        "ip":                 profile["ip"],
        "freq_msg_per_sec":   freq,
        "interval_ms":        interval,
        "payload_size_bytes": random.randint(30, 100),
        "payload_entropy":    round(random.uniform(0.07, 0.32), 4),
        "nb_connexions":      nb_conn,
        "ts":                 int(time.time()),
        "label":              "Attack",
        "attack_type":        "DoS",
    }

# =============================================================
# ATTAQUE 2a — Injection figée
#
# Corrections v3 :
#   - entropy 0.0 seulement 60% du temps
#   - 40% du temps : entropy entre 0.001 et 0.08 (zone grise)
#   - size variable ±25%
#   - nb_connexions variable 1-3
# =============================================================

def generate_injection_frozen(node_id, profile):
    """
    Injection figée : valeur capteur bloquée, répétée en boucle.
    Entropy très proche de 0 mais pas toujours exactement 0.
    Le modèle apprend la zone entropy ≈ 0, pas la valeur exacte.
    """
    # 60% → 0.0 exactement | 40% → zone grise 0.001-0.08
    if random.random() < 0.60:
        entropy = 0.0
    else:
        entropy = round(random.uniform(0.001, 0.08), 4)

    return {
        "node_id":            node_id,
        "ip":                 profile["ip"],
        "freq_msg_per_sec":   round(profile["freq"] * random.uniform(0.85, 1.15), 3),
        "interval_ms":        int(profile["interval_ms"] * random.uniform(0.85, 1.15)),
        "payload_size_bytes": int(profile["size"] * random.uniform(0.80, 1.25)),
        "payload_entropy":    entropy,
        "nb_connexions":      random.choice([1, 1, 2, 2, 3]),
        "ts":                 int(time.time()),
        "label":              "Attack",
        "attack_type":        "Injection_Frozen",
    }

# =============================================================
# ATTAQUE 2b — Injection aberrante
#
# Corrections v3 :
#   - size plage élargie 700-1600 avec gaussienne
#   - entropy 0.70-0.99 (un peu plus bas qu'avant)
#   - nb_connexions parfois 4 ou 5
#   - freq légèrement variable ±20%
# =============================================================

def generate_injection_aberrant(node_id, profile):
    """
    Injection aberrante : valeurs physiquement impossibles.
    Taille paquet surdimensionnée, entropie élevée.
    Plage élargie 700-1600 pour éviter la mémorisation.
    """
    # Size : gaussienne centrée sur 1100 avec bruit σ=150
    size = int(random.gauss(1100, 150))
    size = max(700, min(1600, size))

    return {
        "node_id":            node_id,
        "ip":                 profile["ip"],
        "freq_msg_per_sec":   round(profile["freq"] * random.uniform(0.80, 1.20), 3),
        "interval_ms":        int(profile["interval_ms"] * random.uniform(0.80, 1.20)),
        "payload_size_bytes": size,
        "payload_entropy":    round(random.uniform(0.70, 0.99), 4),
        "nb_connexions":      random.choice([1, 1, 2, 3, 4, 5]),
        "ts":                 int(time.time()),
        "label":              "Attack",
        "attack_type":        "Injection_Aberrant",
    }

# =============================================================
# ATTAQUE 3 — Probe désordonné
#
# Corrections v3 :
#   - nb_connexions distribution pondérée 2-10 (pas toujours 5)
#   - IP variable — parfois .98, .100, .101 (pas toujours .99)
#   - freq gaussienne µ=13 σ=5 (plus de variation)
#   - interval plus large 30-700
# =============================================================

def generate_probe(node_id):
    """
    Probe désordonné depuis IP inconnue.
    nb_connexions distribution pondérée 2-10.
    IP pas toujours 192.168.1.99 pour éviter mémorisation.
    """
    # nb_connexions : distribution pondérée autour de 5
    nb_conn = random.choices(
        [2, 3, 4, 5, 6, 7, 8, 9, 10],
        weights=[5, 10, 15, 25, 20, 12, 8, 3, 2]
    )[0]

    # freq gaussienne — plus de variation naturelle
    freq = round(max(3.0, random.gauss(13, 5)), 3)

    # IP : principalement .99 mais parfois autre IP inconnue
    last_octet = random.choices(
        [99, 98, 100, 101, 102, 50, 75],
        weights=[55, 15, 10, 10, 5, 3, 2]
    )[0]
    ip = f"192.168.1.{last_octet}"

    return {
        "node_id":            node_id,
        "ip":                 ip,
        "freq_msg_per_sec":   freq,
        "interval_ms":        random.randint(30, 700),
        "payload_size_bytes": random.randint(8, 1520),
        "payload_entropy":    round(random.uniform(0.60, 0.93), 4),
        "nb_connexions":      nb_conn,
        "ts":                 int(time.time()),
        "label":              "Attack",
        "attack_type":        "Probe",
    }

# =============================================================
# ATTAQUE 4 — Physical
#
# Corrections v3 :
#   - nb_connexions : 0 (65%), 1 (25%), 2 (10%)
#   - freq 0.0-0.12 (un peu plus large)
#   - interval gaussien µ=21000 σ=5000
#   - entropy 0.01-0.18 (plus large)
# =============================================================

def generate_physical(node_id, profile):
    """
    Attaque physique : composant manipulé, nœud quasi-silencieux.
    nb_connexions entre 0 et 2 — connexion résiduelle possible.
    Valeurs proches de 0 mais jamais identiques.
    """
    # nb_connexions : 0 souvent, parfois 1 ou 2
    nb_conn = random.choices(
        [0, 1, 2],
        weights=[65, 25, 10]
    )[0]

    # freq très basse avec variation naturelle
    freq = round(random.uniform(0.0, 0.12), 3)

    # interval très long avec bruit gaussien
    interval = max(8000, int(random.gauss(21000, 5000)))

    return {
        "node_id":            node_id,
        "ip":                 profile["ip"],
        "freq_msg_per_sec":   freq,
        "interval_ms":        interval,
        "payload_size_bytes": random.randint(8, 35),
        "payload_entropy":    round(random.uniform(0.01, 0.18), 4),
        "nb_connexions":      nb_conn,
        "ts":                 int(time.time()),
        "label":              "Attack",
        "attack_type":        "Physical",
    }

# =============================================================
# LOGIQUE DE CIBLAGE
# =============================================================

ATTACK_TARGETS = {
    "dos":                 ["node_1", "node_2"],
    "injection_frozen":    ["node_3"],
    "injection_aberrant":  ["node_3", "node_4"],
    "probe":               ["node_1", "node_2", "node_3", "node_4", "node_5"],
    "physical":            ["node_3", "node_4"],
}

# =============================================================
# CALLBACKS MQTT
# =============================================================

def on_connect(client, userdata, flags, rc, properties=None):
    rc_value = rc.value if hasattr(rc, "value") else int(rc)
    if rc_value == 0:
        print(f"[MQTT] Connecté → broker {BROKER_HOST}:{BROKER_PORT}")
    else:
        print(f"[MQTT] Erreur connexion — code : {rc_value}")

def on_publish(client, userdata, mid, reason_codes=None, properties=None):
    pass

# =============================================================
# FONCTION PRINCIPALE
# =============================================================

def run_injector(mode, duration=None):

    generators = {
        "dos":                lambda nid, p, i: generate_dos(nid, p, i),
        "injection_frozen":   lambda nid, p, i: generate_injection_frozen(nid, p),
        "injection_aberrant": lambda nid, p, i: generate_injection_aberrant(nid, p),
        "probe":              lambda nid, p, i: generate_probe(nid),
        "physical":           lambda nid, p, i: generate_physical(nid, p),
    }

    targets   = ATTACK_TARGETS[mode]
    generator = generators[mode]

    try:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"ids_injector_{mode}"
        )
    except AttributeError:
        client = mqtt.Client(client_id=f"ids_injector_{mode}")

    client.on_connect = on_connect
    client.on_publish = on_publish

    print(f"\n{'='*60}")
    print(f"  IDS-IoT Attack Injector v3 — Mode : {mode.upper()}")
    print(f"  Cibles  : {', '.join(targets)}")
    print(f"  Topics  : iiot/node_X/data")
    print(f"  Bruit naturel activé — chevauchement réaliste")
    print(f"{'='*60}")

    try:
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    except ConnectionRefusedError:
        print("ERREUR : Mosquitto non démarré. Lance : net start mosquitto")
        return

    client.loop_start()
    time.sleep(0.5)

    print(f"Injection active | Ctrl+C pour arrêter\n")

    start_time = time.time()
    msg_count  = 0
    i          = 0

    try:
        while True:
            if duration and (time.time() - start_time) > duration:
                print(f"\nDurée écoulée ({duration}s). Arrêt.")
                break

            for node_id, profile in NODE_PROFILES.items():
                if node_id in targets:
                    payload = generator(node_id, profile, i)
                elif random.random() < 0.25:
                    payload = generator(node_id, profile, i)
                else:
                    payload = generate_normal(node_id, profile)

                json_payload = json.dumps(payload)
                client.publish(TOPICS[node_id], json_payload, qos=1)
                msg_count += 1

                icon = "🟢" if payload["attack_type"] == "Normal" else "🔴"
                print(
                    f"{icon} [{node_id}] "
                    f"type={payload['attack_type']:22s} | "
                    f"freq={payload['freq_msg_per_sec']:8.3f} | "
                    f"size={payload['payload_size_bytes']:5d}B | "
                    f"entropy={payload['payload_entropy']:.3f} | "
                    f"conn={payload['nb_connexions']}"
                )

            i += 1
            print(f"  → {msg_count} messages | {datetime.now().strftime('%H:%M:%S')}\n")
            time.sleep(PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        print(f"\nInjecteur arrêté. Total : {msg_count} messages publiés.")

    finally:
        client.loop_stop()
        client.disconnect()
        print("Déconnecté du broker MQTT.")

# =============================================================
# POINT D'ENTRÉE
# =============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Injecteur d'attaques IoT v3 — IDS-IoT SWaT"
    )
    parser.add_argument(
        "--mode",
        choices=["dos", "injection_frozen", "injection_aberrant", "probe", "physical"],
        required=True,
        help="Type d'attaque à injecter"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=None,
        help="Durée en secondes (défaut: infini)"
    )
    args = parser.parse_args()
    run_injector(mode=args.mode, duration=args.duration)