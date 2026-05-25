# =============================================================
#  Injecte des attaques simulées sur les nœuds IoT via MQTT.
#  À lancer en parallèle de traffic_simulator.py pendant
#  les tests et la démonstration.
#
#  Usage :
#    python scripts/attack_injector.py --mode dos
#    python scripts/attack_injector.py --mode injection_frozen
#    python scripts/attack_injector.py --mode injection_aberrant
#    python scripts/attack_injector.py --mode probe
#    python scripts/attack_injector.py --mode physical
#    python scripts/attack_injector.py --mode dos --duration 30
#
#  Pour le trafic normal → voir traffic_simulator.py
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
PUBLISH_INTERVAL = 2   # secondes entre chaque cycle d'envoi

# Topics MQTT — Contrat 1 du groupe
TOPICS = {
    "node_1": "iiot/node_1/data",
    "node_2": "iiot/node_2/data",
    "node_3": "iiot/node_3/data",
    "node_4": "iiot/node_4/data",
    "node_5": "iiot/node_5/data",
}

# =============================================================
# PROFILS DES 5 NŒUDS
# Utilisés pour garder les valeurs normales sur les nœuds
# non ciblés par l'attaque en cours.
# =============================================================

NODE_PROFILES = {
    "node_1": {
        "name":            "PLC Réacteur",
        "ip":              "192.168.1.10",
        "type":            "CBR",
        "freq":            1.0,
        "size":            64,
        "interval_ms":     1000,
        "nb_connexions":   1,
        "payload_entropy": 0.52,
    },
    "node_2": {
        "name":            "PLC Pompe",
        "ip":              "192.168.1.11",
        "type":            "CBR",
        "freq":            1.0,
        "size":            64,
        "interval_ms":     1000,
        "nb_connexions":   1,
        "payload_entropy": 0.50,
    },
    "node_3": {
        "name":            "Capteur Pression",
        "ip":              "192.168.1.12",
        "type":            "VBR",
        "freq":            0.3,
        "size":            80,
        "interval_ms":     3000,
        "nb_connexions":   1,
        "payload_entropy": 0.48,
    },
    "node_4": {
        "name":            "Capteur Température",
        "ip":              "192.168.1.13",
        "type":            "VBR",
        "freq":            0.3,
        "size":            80,
        "interval_ms":     3000,
        "nb_connexions":   1,
        "payload_entropy": 0.46,
    },
    "node_5": {
        "name":            "Gateway SCADA",
        "ip":              "192.168.1.14",
        "type":            "Bulk",
        "freq":            0.1,
        "size":            2048,
        "interval_ms":     10000,
        "nb_connexions":   3,
        "payload_entropy": 0.71,
    },
}

# =============================================================
# GÉNÉRATEUR DE TRAFIC NORMAL
# Utilisé pour les nœuds non ciblés pendant une attaque.
# =============================================================

def generate_normal(node_id, profile):
    """Génère un message normal conforme au Contrat 1."""
    ptype = profile["type"]

    if ptype == "CBR":
        freq     = round(profile["freq"] * random.uniform(0.98, 1.02), 3)
        size     = profile["size"]
        interval = profile["interval_ms"]
        entropy  = round(profile["payload_entropy"] * random.uniform(0.98, 1.02), 4)
    elif ptype == "VBR":
        freq     = round(random.uniform(0.1, 0.5), 3)
        size     = int(profile["size"] * random.uniform(0.85, 1.15))
        interval = int(1000 / freq) if freq > 0 else 3000
        entropy  = round(profile["payload_entropy"] * random.uniform(0.90, 1.10), 4)
    else:  # Bulk
        freq     = round(profile["freq"] * random.uniform(0.95, 1.05), 3)
        size     = profile["size"]
        interval = profile["interval_ms"]
        entropy  = round(profile["payload_entropy"] * random.uniform(0.95, 1.05), 4)

    return {
        "node_id":            node_id,
        "ip":                 profile["ip"],
        "freq_msg_per_sec":   freq,
        "interval_ms":        interval,
        "payload_size_bytes": size,
        "payload_entropy":    entropy,
        "nb_connexions":      profile["nb_connexions"],
        "ts":                 int(time.time()),
        "label":              "Normal",
        "attack_type":        "Normal",
    }

# =============================================================
# ATTAQUE 1 — DoS en vagues progressives
#
# Cible principale : node_1 (PLC Réacteur) et node_2 (PLC Pompe)
# La fréquence oscille entre 400 et 800 msg/sec via une fonction
# sinusoïdale + bruit gaussien — jamais le même chiffre.
# L'IA apprend une tendance, pas une valeur fixe.
# =============================================================

def generate_dos(node_id, profile):
    """
    DoS en vagues progressives sur les PLCs.
    freq : oscillation sinusoïdale 400–800 msg/sec
    nb_connexions : 50–200 (saturation)
    payload_entropy : 0.10–0.20 (contenu répétitif)
    """
    t     = time.time()
    base  = 600 + 200 * math.sin(t / 5)
    bruit = random.gauss(0, 30)
    freq  = round(max(400, base + bruit), 3)

    return {
        "node_id":            node_id,
        "ip":                 profile["ip"],
        "freq_msg_per_sec":   freq,
        "interval_ms":        int(1000 / freq * 1000),
        "payload_size_bytes": random.randint(40, 80),
        "payload_entropy":    round(random.uniform(0.10, 0.20), 4),
        "nb_connexions":      random.randint(50, 200),
        "ts":                 int(time.time()),
        "label":              "Attack",
        "attack_type":        "DoS",
    }

# =============================================================
# ATTAQUE 2a — Injection figée
#
# Cible principale : node_3 (Capteur Pression)
# La valeur capteur est bloquée à 4.20 bar exactement,
# répétée indéfiniment. payload_entropy = 0.0
# est la signature principale de cette attaque.
# =============================================================

def generate_injection_frozen(node_id, profile):
    """
    Injection figée : valeur capteur bloquée, répétée en boucle.
    payload_entropy : 0.0 (contenu identique à chaque message)
    freq : normale (l'attaque est subtile)
    """
    return {
        "node_id":            node_id,
        "ip":                 profile["ip"],
        "freq_msg_per_sec":   round(profile["freq"] * random.uniform(0.98, 1.02), 3),
        "interval_ms":        profile["interval_ms"],
        "payload_size_bytes": profile["size"],
        "payload_entropy":    0.0,     # signature principale
        "nb_connexions":      profile["nb_connexions"],
        "ts":                 int(time.time()),
        "label":              "Attack",
        "attack_type":        "Injection_Frozen",
    }

# =============================================================
# ATTAQUE 2b — Injection aberrante
#
# Cible principale : node_3 et node_4
# Valeurs physiquement impossibles (pression = -12.0 ou 99.0).
# Sauts brutaux, payload_entropy très élevée (0.80–0.99).
# =============================================================

def generate_injection_aberrant(node_id, profile):
    """
    Injection aberrante : valeurs impossibles avec sauts brutaux.
    payload_size_bytes : 1200–1500 (paquet surdimensionné)
    payload_entropy : 0.80–0.99 (contenu chiffré ou aléatoire)
    """
    return {
        "node_id":            node_id,
        "ip":                 profile["ip"],
        "freq_msg_per_sec":   round(profile["freq"] * random.uniform(0.95, 1.05), 3),
        "interval_ms":        profile["interval_ms"],
        "payload_size_bytes": random.randint(1200, 1500),
        "payload_entropy":    round(random.uniform(0.80, 0.99), 4),
        "nb_connexions":      profile["nb_connexions"],
        "ts":                 int(time.time()),
        "label":              "Attack",
        "attack_type":        "Injection_Aberrant",
    }

# =============================================================
# ATTAQUE 3 — Probe désordonné
#
# Provient d'une IP inconnue : 192.168.1.99
# Tailles de paquets aléatoires (10 à 1500 bytes).
# same_srv_rate proche de 0, nb_connexions = 5.
# Publie sur des topics inexistants pour scanner le réseau.
# =============================================================

def generate_probe(node_id, profile):
    """
    Probe désordonné depuis IP inconnue 192.168.1.99.
    ip : toujours 192.168.1.99 (IP non enregistrée)
    payload_size_bytes : 10–1500 (très variable = scan de ports)
    nb_connexions : 5 (dst_host_count)
    """
    return {
        "node_id":            node_id,
        "ip":                 "192.168.1.99",   # IP inconnue
        "freq_msg_per_sec":   round(random.uniform(8.0, 20.0), 3),
        "interval_ms":        random.randint(50, 500),
        "payload_size_bytes": random.randint(10, 1500),
        "payload_entropy":    round(random.uniform(0.70, 0.90), 4),
        "nb_connexions":      5,
        "ts":                 int(time.time()),
        "label":              "Attack",
        "attack_type":        "Probe",
    }

# =============================================================
# ATTAQUE 4 — Physical
#
# Cible principale : node_3 et node_4
# Simule la manipulation d'un composant physique
# (fermeture de vanne, arrêt de pompe).
# Le nœud devient quasi-silencieux avec nb_connexions = 0.
# =============================================================

def generate_physical(node_id, profile):
    """
    Attaque physique : composant manipulé, nœud quasi-silencieux.
    freq : 0.0–0.05 msg/sec (quasi-muet)
    interval_ms : 15000–30000ms (très long délai)
    nb_connexions : 0 (connexion physique coupée)
    payload_entropy : 0.02–0.10 (signal d'erreur minimal)
    """
    return {
        "node_id":            node_id,
        "ip":                 profile["ip"],
        "freq_msg_per_sec":   round(random.uniform(0.0, 0.05), 3),
        "interval_ms":        random.randint(15000, 30000),
        "payload_size_bytes": random.randint(10, 20),
        "payload_entropy":    round(random.uniform(0.02, 0.10), 4),
        "nb_connexions":      0,
        "ts":                 int(time.time()),
        "label":              "Attack",
        "attack_type":        "Physical",
    }

# =============================================================
# LOGIQUE DE CIBLAGE
#
# Chaque type d'attaque a des nœuds cibles prioritaires
# basés sur leur rôle dans le réseau ICS/IoT :
#   DoS              → node_1, node_2 (PLCs — cibles DDoS)
#   Injection_Frozen → node_3 (capteur pression — valeur figée)
#   Injection_Aberrant→ node_3, node_4 (capteurs — valeurs aberrantes)
#   Probe            → tous (scan réseau global)
#   Physical         → node_3, node_4 (composants physiques)
#
# Les nœuds non ciblés continuent en mode normal (30% attaqués).
# =============================================================

ATTACK_TARGETS = {
    "dos":                  ["node_1", "node_2"],
    "injection_frozen":     ["node_3"],
    "injection_aberrant":   ["node_3", "node_4"],
    "probe":                ["node_1", "node_2", "node_3", "node_4", "node_5"],
    "physical":             ["node_3", "node_4"],
}

ATTACK_GENERATORS = {
    "dos":                  generate_dos,
    "injection_frozen":     generate_injection_frozen,
    "injection_aberrant":   generate_injection_aberrant,
    "probe":                generate_probe,
    "physical":             generate_physical,
}

# =============================================================
# CALLBACKS MQTT
# =============================================================

def on_connect(client, userdata, flags, rc, properties=None):
    """Appelé quand la connexion au broker est établie."""
    rc_value = rc.value if hasattr(rc, "value") else int(rc)
    if rc_value == 0:
        print(f"[MQTT] Connecté → broker {BROKER_HOST}:{BROKER_PORT}")
    else:
        print(f"[MQTT] Erreur connexion — code : {rc_value}")


def on_publish(client, userdata, mid, reason_codes=None, properties=None):
    """Appelé quand un message est publié avec succès."""
    pass

# =============================================================
# FONCTION PRINCIPALE
# =============================================================

def run_injector(mode, duration=None):
    """
    Lance l'injecteur d'attaques.

    Paramètres :
        mode     : "dos", "injection_frozen", "injection_aberrant",
                   "probe", "physical"
        duration : durée en secondes (None = infini)
    """
    try:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"ids_injector_{mode}"
        )
    except AttributeError:
        client = mqtt.Client(client_id=f"ids_injector_{mode}")

    client.on_connect = on_connect
    client.on_publish = on_publish

    targets   = ATTACK_TARGETS[mode]
    generator = ATTACK_GENERATORS[mode]

    print(f"\n{'='*55}")
    print(f"  IDS-IoT Attack Injector — Mode : {mode.upper()}")
    print(f"  Cibles prioritaires : {', '.join(targets)}")
    print(f"  Topics  : iiot/node_X/data")
    print(f"  Contrat : Contrat 1 du groupe")
    print(f"{'='*55}")
    print(f"Connexion à {BROKER_HOST}:{BROKER_PORT}...")

    try:
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    except ConnectionRefusedError:
        print("ERREUR : Connexion refusée. Lance : net start mosquitto")
        return

    client.loop_start()
    time.sleep(0.5)

    print(f"Injection active | Intervalle : {PUBLISH_INTERVAL}s | Ctrl+C pour arrêter\n")

    start_time = time.time()
    msg_count  = 0

    try:
        while True:
            if duration and (time.time() - start_time) > duration:
                print(f"\nDurée écoulée ({duration}s). Arrêt.")
                break

            for node_id, profile in NODE_PROFILES.items():
                # Nœud ciblé → attaque
                # Nœud non ciblé → 30% de chance d'être attaqué,
                #                   70% reste en normal
                if node_id in targets:
                    payload = generator(node_id, profile)
                elif random.random() < 0.30:
                    payload = generator(node_id, profile)
                else:
                    payload = generate_normal(node_id, profile)

                json_payload = json.dumps(payload)
                client.publish(TOPICS[node_id], json_payload, qos=1)
                msg_count += 1

                icon = "🟢" if payload["attack_type"] == "Normal" else "🔴"
                print(
                    f"{icon} [{node_id}] {profile['name']:20s} | "
                    f"type={payload['attack_type']:22s} | "
                    f"freq={payload['freq_msg_per_sec']:8.2f} msg/s | "
                    f"size={payload['payload_size_bytes']:5d}B | "
                    f"ip={payload['ip']}"
                )

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
        description="Injecteur d'attaques IoT — IDS-IoT SWaT"
    )
    parser.add_argument(
        "--mode",
        choices=["dos", "injection_frozen", "injection_aberrant",
                 "probe", "physical"],
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