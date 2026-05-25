# =============================================================
#
#  Simule 5 nœuds IoT avec profils CBR / VBR / Bulk
#  et publie uniquement du trafic NORMAL sur MQTT.
#
#  Usage :
#    python scripts/traffic_simulator.py
#    python scripts/traffic_simulator.py --duration 60
#
#  Pour les attaques → voir attack_injector.py
# =============================================================

import paho.mqtt.client as mqtt
import json
import time
import random
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
# PROFILS DES 5 NŒUDS — Contrat 1
#
# Trois types de profils réseau :
#   CBR  (Constant Bit Rate)  : fréquence et taille fixes
#   VBR  (Variable Bit Rate)  : fréquence et taille variables
#   Bulk : gros envois peu fréquents
# =============================================================

NODE_PROFILES = {
    "node_1": {
        "name":            "PLC Réacteur",
        "ip":              "192.168.1.10",
        "type":            "CBR",
        "freq":            1.0,        # 1 msg/sec fixe
        "size":            64,         # 64 bytes fixe
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
        "freq":            0.3,        # 0.1 à 0.5 msg/sec variable
        "size":            80,         # ~80 bytes variable
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
        "type":            "Bulk",     # Gros paquets peu fréquents
        "freq":            0.1,        # 1 msg toutes les 10 sec
        "size":            2048,       # 2048 bytes fixe
        "interval_ms":     10000,
        "nb_connexions":   3,
        "payload_entropy": 0.71,
    },
}

# =============================================================
# GÉNÉRATEUR DE TRAFIC NORMAL
#
# Respecte les profils CBR / VBR / Bulk :
#   CBR  → valeurs fixes avec bruit ±2%
#   VBR  → fréquence entre 0.1 et 0.5 msg/sec
#   Bulk → taille fixe 2048B, intervalle 10sec
# =============================================================

def generate_normal(node_id, profile):
    """
    Génère un message JSON de trafic normal
    conforme au Contrat 1 du groupe.
    """
    ptype = profile["type"]

    if ptype == "CBR":
        # Constant Bit Rate : tout fixe, bruit ±2%
        freq     = round(profile["freq"] * random.uniform(0.98, 1.02), 3)
        size     = profile["size"]
        interval = profile["interval_ms"]
        entropy  = round(profile["payload_entropy"] * random.uniform(0.98, 1.02), 4)

    elif ptype == "VBR":
        # Variable Bit Rate : fréquence entre 0.1 et 0.5 msg/sec
        freq     = round(random.uniform(0.1, 0.5), 3)
        size     = int(profile["size"] * random.uniform(0.85, 1.15))
        interval = int(1000 / freq) if freq > 0 else 3000
        entropy  = round(profile["payload_entropy"] * random.uniform(0.90, 1.10), 4)

    else:  # Bulk
        # Gros paquet fixe toutes les 10 secondes
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

def run_simulator(duration=None):
    """
    Lance le simulateur de trafic normal.

    Paramètre :
        duration : durée en secondes (None = infini)
    """
    try:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id="ids_simulator_normal"
        )
    except AttributeError:
        client = mqtt.Client(client_id="ids_simulator_normal")

    client.on_connect = on_connect
    client.on_publish = on_publish

    print(f"\n{'='*55}")
    print(f"  IDS-IoT Traffic Simulator — Trafic NORMAL")
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

    print(f"5 nœuds actifs | Intervalle : {PUBLISH_INTERVAL}s | Ctrl+C pour arrêter\n")

    start_time = time.time()
    msg_count  = 0

    try:
        while True:
            if duration and (time.time() - start_time) > duration:
                print(f"\nDurée écoulée ({duration}s). Arrêt.")
                break

            for node_id, profile in NODE_PROFILES.items():
                payload      = generate_normal(node_id, profile)
                json_payload = json.dumps(payload)
                client.publish(TOPICS[node_id], json_payload, qos=1)
                msg_count += 1

                print(
                    f"🟢 [{node_id}] {profile['name']:20s} | "
                    f"type=Normal               | "
                    f"freq={payload['freq_msg_per_sec']:5.2f} msg/s | "
                    f"size={payload['payload_size_bytes']:5d}B | "
                    f"ip={payload['ip']}"
                )

            print(f"  → {msg_count} messages | {datetime.now().strftime('%H:%M:%S')}\n")
            time.sleep(PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        print(f"\nSimulateur arrêté. Total : {msg_count} messages publiés.")

    finally:
        client.loop_stop()
        client.disconnect()
        print("Déconnecté du broker MQTT.")


# =============================================================
# POINT D'ENTRÉE
# =============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simulateur de trafic normal IoT — IDS-IoT SWaT"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=None,
        help="Durée en secondes (défaut: infini)"
    )
    args = parser.parse_args()
    run_simulator(duration=args.duration)