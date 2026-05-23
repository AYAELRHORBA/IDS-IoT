# =============================================================
#  traffic_simulator.py — Phase 2 : Simulateur de trafic IoT
#  Projet IDS-IoT | Membre 1 : Architecte des Données
# =============================================================
#
#  Ce script simule 5 capteurs IoT qui publient leur trafic
#  réseau via MQTT. Il génère du trafic normal ET des attaques.
#
#  Pour lancer :
#    python scripts/traffic_simulator.py
#
#  Pour lancer en mode attaque :
#    python scripts/traffic_simulator.py --mode flood
#    python scripts/traffic_simulator.py --mode injection
#    python scripts/traffic_simulator.py --mode scan
#    python scripts/traffic_simulator.py --mode mitm
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

BROKER_HOST = "localhost"   # adresse du broker Mosquitto
BROKER_PORT = 1883          # port par défaut MQTT
PUBLISH_INTERVAL = 2        # secondes entre chaque envoi

# Topics MQTT — un par capteur + un pour les alertes
TOPICS = {
    "node_1": "iot/node_1/traffic",
    "node_2": "iot/node_2/traffic",
    "node_3": "iot/node_3/traffic",
    "node_4": "iot/node_4/traffic",
    "node_5": "iot/node_5/traffic",
    "alertes": "iot/ids/alertes",
}

# =============================================================
# PROFILS DES 5 CAPTEURS
# Chaque capteur a un comportement normal différent.
# Ces valeurs servent de référence — si on s'en écarte
# beaucoup, le modèle IA doit le détecter.
# =============================================================

SENSOR_PROFILES = {
    "node_1": {
        "name": "Capteur Température",
        "freq_normal":    2.0,    # messages par seconde en régime normal
        "packet_size":    120,    # taille moyenne des paquets en bytes
        "interval_ms":    500,    # intervalle entre messages (ms)
        "nb_connections": 1,      # connexions simultanées normales
        "payload_entropy": 0.45,  # entropie du contenu JSON (0=simple, 1=complexe)
    },
    "node_2": {
        "name": "Capteur Humidité",
        "freq_normal":    1.0,
        "packet_size":    85,
        "interval_ms":    1000,
        "nb_connections": 1,
        "payload_entropy": 0.40,
    },
    "node_3": {
        "name": "Compteur Intelligent",
        "freq_normal":    3.0,
        "packet_size":    200,
        "interval_ms":    333,
        "nb_connections": 2,
        "payload_entropy": 0.55,
    },
    "node_4": {
        "name": "Caméra IP",
        "freq_normal":    5.0,
        "packet_size":    450,
        "interval_ms":    200,
        "nb_connections": 3,
        "payload_entropy": 0.65,
    },
    "node_5": {
        "name": "Actuateur",
        "freq_normal":    0.5,
        "packet_size":    60,
        "interval_ms":    2000,
        "nb_connections": 1,
        "payload_entropy": 0.35,
    },
}

# =============================================================
# GÉNÉRATEUR DE TRAFIC NORMAL
# Produit un vecteur de features réseau réaliste pour
# un capteur en fonctionnement normal.
# =============================================================

def generate_normal_traffic(node_id, profile):
    """
    Génère un message JSON de trafic normal pour un capteur.
    On ajoute un peu de bruit aléatoire (±10%) pour simuler
    la variabilité naturelle d'un vrai capteur.
    """
    noise = lambda x, pct=0.10: x * (1 + random.uniform(-pct, pct))

    return {
        "node_id":          node_id,
        "sensor_name":      profile["name"],
        "timestamp":        datetime.now().isoformat(),
        "traffic_type":     "normal",

        # Features réseau — ce sont ces valeurs que le modèle IA analyse
        "freq_msg_per_sec": round(noise(profile["freq_normal"]), 3),
        "packet_size_bytes": int(noise(profile["packet_size"])),
        "interval_ms":      int(noise(profile["interval_ms"])),
        "nb_connections":   profile["nb_connections"],
        "payload_entropy":  round(noise(profile["payload_entropy"], 0.05), 4),

        # Données capteur simulées (température, humidité, etc.)
        "sensor_value":     round(random.uniform(18.0, 26.0), 2),
        "unit":             "°C" if "Temp" in profile["name"] else "raw",
        "battery_level":    round(random.uniform(85.0, 100.0), 1),
        "status":           "ok",
    }

# =============================================================
# GÉNÉRATEURS D'ATTAQUES
# Chaque fonction produit un message avec des features
# anormales caractéristiques du type d'attaque.
# =============================================================

def generate_flood_attack(node_id, profile):
    """
    Attaque DoS / Flood :
    Le capteur envoie des messages à une fréquence TRÈS élevée.
    Signes : freq élevée, interval_ms très bas, nb_connections élevé.
    """
    return {
        "node_id":          node_id,
        "sensor_name":      profile["name"],
        "timestamp":        datetime.now().isoformat(),
        "traffic_type":     "flood",

        # Valeurs anormales caractéristiques du flood
        "freq_msg_per_sec": round(random.uniform(45.0, 80.0), 3),  # normal=2, flood=45-80
        "packet_size_bytes": random.randint(40, 100),               # petits paquets répétés
        "interval_ms":      random.randint(10, 25),                 # normal=500ms, flood=10-25ms
        "nb_connections":   random.randint(20, 50),                 # normal=1, flood=20-50
        "payload_entropy":  round(random.uniform(0.10, 0.25), 4),   # contenu répétitif = faible entropie

        "sensor_value":     0.0,
        "unit":             "raw",
        "battery_level":    round(random.uniform(10.0, 30.0), 1),   # batterie qui s'épuise
        "status":           "flood_attack",
    }


def generate_injection_attack(node_id, profile):
    """
    Attaque Injection :
    Le capteur envoie des valeurs falsifiées (fausses mesures).
    Signes : payload_entropy élevée, packet_size anormal,
             valeurs capteur hors plage normale.
    """
    return {
        "node_id":          node_id,
        "sensor_name":      profile["name"],
        "timestamp":        datetime.now().isoformat(),
        "traffic_type":     "injection",

        # Fréquence normale mais contenu falsifié
        "freq_msg_per_sec": round(profile["freq_normal"] * random.uniform(0.9, 1.1), 3),
        "packet_size_bytes": random.randint(1200, 1500),            # paquet trop grand
        "interval_ms":      int(profile["interval_ms"] * random.uniform(0.8, 1.2)),
        "nb_connections":   profile["nb_connections"],
        "payload_entropy":  round(random.uniform(0.90, 0.99), 4),   # entropie très haute = chiffré/injecté

        # Valeur capteur complètement hors plage (attaque physique)
        "sensor_value":     round(random.uniform(200.0, 999.0), 2), # température = 500°C ?!
        "unit":             "INJECTED",
        "battery_level":    round(random.uniform(85.0, 100.0), 1),
        "status":           "injection_attack",
    }


def generate_scan_attack(node_id, profile):
    """
    Attaque Scan / Probe :
    Un attaquant scanne le réseau pour découvrir les capteurs.
    Signes : nb_connections très élevé, interval_ms irrégulier,
             tailles de paquets très variables.
    """
    return {
        "node_id":          node_id,
        "sensor_name":      profile["name"],
        "timestamp":        datetime.now().isoformat(),
        "traffic_type":     "scan",

        "freq_msg_per_sec": round(random.uniform(8.0, 20.0), 3),    # modérément élevé
        "packet_size_bytes": random.randint(20, 1400),               # très variable (scan de ports)
        "interval_ms":      random.randint(50, 500),                 # irrégulier
        "nb_connections":   random.randint(15, 40),                  # beaucoup de connexions = scan
        "payload_entropy":  round(random.uniform(0.70, 0.90), 4),

        "sensor_value":     0.0,
        "unit":             "raw",
        "battery_level":    round(random.uniform(85.0, 100.0), 1),
        "status":           "scan_attack",
    }


def generate_mitm_attack(node_id, profile):
    """
    Attaque MITM (Man-In-The-Middle) :
    Un attaquant intercepte et modifie les communications.
    Signes : légère hausse des délais, entropie modérée,
             nb_connections légèrement élevé (proxy intermédiaire).
    La plus subtile à détecter — les valeurs sont proches du normal.
    """
    return {
        "node_id":          node_id,
        "sensor_name":      profile["name"],
        "timestamp":        datetime.now().isoformat(),
        "traffic_type":     "mitm",

        # Valeurs proches du normal mais légèrement déviées
        "freq_msg_per_sec": round(profile["freq_normal"] * random.uniform(1.1, 1.4), 3),
        "packet_size_bytes": int(profile["packet_size"] * random.uniform(1.2, 1.8)),  # paquets plus grands (overhead chiffrement)
        "interval_ms":      int(profile["interval_ms"] * random.uniform(1.3, 2.0)),   # délai légèrement plus long (interception)
        "nb_connections":   profile["nb_connections"] + random.randint(2, 5),         # connexion proxy
        "payload_entropy":  round(random.uniform(0.75, 0.88), 4),                     # trafic réencapsulé

        "sensor_value":     round(random.uniform(18.0, 26.0), 2),   # valeur normale (attaque transparente)
        "unit":             "°C" if "Temp" in profile["name"] else "raw",
        "battery_level":    round(random.uniform(85.0, 100.0), 1),
        "status":           "mitm_attack",
    }

def generate_physical_attack(node_id, profile):
    """
    Attaque Physical :
    Un attaquant manipule directement un composant physique
    (fermer une vanne, arrêter une pompe, couper un capteur).
    L'effet réseau : le capteur devient quasi-silencieux,
    puis reprend avec des valeurs incohérentes.
    Signes : fréquence très basse, intervalles très longs,
             nb_connections = 0 (connexion coupée),
             valeur capteur nulle ou aberrante.
    """
    return {
        "node_id":          node_id,
        "sensor_name":      profile["name"],
        "timestamp":        datetime.now().isoformat(),
        "traffic_type":     "physical",

        # Le capteur envoie très peu de données — il est perturbé
        "freq_msg_per_sec": round(random.uniform(0.0, 0.3), 3),    # quasi-silencieux
        "packet_size_bytes": random.randint(10, 30),                # minuscules paquets d'état
        "interval_ms":      random.randint(5000, 15000),            # très longs délais entre messages
        "nb_connections":   0,                                      # connexion physique coupée
        "payload_entropy":  round(random.uniform(0.05, 0.20), 4),   # contenu très simple (signal d'erreur)

        "sensor_value":     0.0,                                    # capteur muet ou hors service
        "unit":             "raw",
        "battery_level":    round(random.uniform(0.0, 15.0), 1),    # batterie critique (composant endommagé)
        "status":           "physical_attack",
    }

# =============================================================
# CALLBACKS MQTT
# Ces fonctions sont appelées automatiquement par paho-mqtt
# quand des événements se produisent sur la connexion.
# =============================================================

def on_connect(client, userdata, flags, rc, properties=None):
    """Appelé quand la connexion au broker est établie.

    rc peut être un entier (anciennes versions de paho-mqtt)
    ou un objet ReasonCode (versions récentes).
    On convertit en entier dans les deux cas.
    """
    # Convertir rc en entier quelle que soit la version de paho-mqtt
    rc_value = rc.value if hasattr(rc, 'value') else int(rc)

    codes = {
        0: "Connecté avec succès",
        1: "Protocole refusé",
        2: "Identifiant client rejeté",
        3: "Serveur indisponible",
        4: "Mauvais identifiants",
        5: "Non autorisé",
    }
    msg = codes.get(rc_value, f"Code inconnu : {rc_value}")
    if rc_value == 0:
        print(f"[MQTT] {msg} → broker {BROKER_HOST}:{BROKER_PORT}")
    else:
        print(f"[MQTT] Erreur connexion : {msg}")


def on_publish(client, userdata, mid, reason_codes=None, properties=None):
    """Appelé quand un message est publié avec succès."""
    pass  # silencieux pour ne pas surcharger la console

# =============================================================
# FONCTION PRINCIPALE
# =============================================================

def run_simulator(mode="normal", duration=None):
    """
    Lance le simulateur de trafic.

    Paramètres :
        mode     : "normal", "flood", "injection", "scan", "mitm", "physical"
        duration : durée en secondes (None = infini jusqu'à Ctrl+C)
    """

    # -- Choisir la fonction de génération selon le mode --
    attack_generators = {
        "flood":     generate_flood_attack,
        "injection": generate_injection_attack,
        "scan":      generate_scan_attack,
        "mitm":      generate_mitm_attack,
        "physical":  generate_physical_attack,
    }

    if mode != "normal" and mode not in attack_generators:
        print(f"Mode inconnu : {mode}. Modes valides : normal, flood, injection, scan, mitm, physical")
        return

    # -- Créer le client MQTT --
    # CallbackAPIVersion.VERSION2 = version moderne de paho-mqtt
    try:
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"ids_simulator_{mode}"
        )
    except AttributeError:
        # Compatibilité avec les versions plus anciennes de paho-mqtt
        client = mqtt.Client(client_id=f"ids_simulator_{mode}")

    client.on_connect = on_connect
    client.on_publish = on_publish

    # -- Connexion au broker --
    print(f"\n{'='*55}")
    print(f"  IDS-IoT Traffic Simulator — Mode : {mode.upper()}")
    print(f"{'='*55}")
    print(f"Connexion à {BROKER_HOST}:{BROKER_PORT}...")

    try:
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=60)
    except ConnectionRefusedError:
        print("\nERREUR : Connexion refusée.")
        print("Mosquitto est-il démarré ? Lance : net start mosquitto")
        return
    except OSError as e:
        print(f"\nERREUR réseau : {e}")
        return

    client.loop_start()  # démarre la boucle MQTT en arrière-plan
    time.sleep(0.5)      # attendre que la connexion s'établisse

    print(f"5 capteurs actifs | Intervalle : {PUBLISH_INTERVAL}s | Ctrl+C pour arrêter\n")

    # -- Boucle principale --
    start_time = time.time()
    msg_count = 0

    try:
        while True:
            # Vérifier si la durée est écoulée
            if duration and (time.time() - start_time) > duration:
                print(f"\nDurée écoulée ({duration}s). Arrêt.")
                break

            # Publier un message pour chaque capteur
            for node_id, profile in SENSOR_PROFILES.items():
                topic = TOPICS[node_id]

                # Choisir le générateur selon le mode
                # En mode normal : tous les capteurs normaux
                # En mode attaque : on attaque surtout node_3 (le plus vulnérable)
                if mode == "normal":
                    payload = generate_normal_traffic(node_id, profile)
                elif node_id in ["node_3", "node_4"] or random.random() < 0.3:
                    # Les capteurs node_3 et node_4 sont attaqués en priorité
                    # + 30% de chance d'attaque sur les autres
                    payload = attack_generators[mode](node_id, profile)
                else:
                    # Les autres capteurs continuent normalement
                    payload = generate_normal_traffic(node_id, profile)

                # Sérialiser en JSON et publier
                json_payload = json.dumps(payload, ensure_ascii=False)
                result = client.publish(topic, json_payload, qos=1)

                msg_count += 1

                # Afficher un résumé dans la console
                traffic_type = payload["traffic_type"]
                icon = "🟢" if traffic_type == "normal" else "🔴"
                print(
                    f"{icon} [{node_id}] {profile['name']:20s} | "
                    f"type={traffic_type:10s} | "
                    f"freq={payload['freq_msg_per_sec']:5.1f} msg/s | "
                    f"size={payload['packet_size_bytes']:4d}B | "
                    f"topic={topic}"
                )

            print(f"  → {msg_count} messages publiés | {datetime.now().strftime('%H:%M:%S')}\n")
            time.sleep(PUBLISH_INTERVAL)

    except KeyboardInterrupt:
        print(f"\n\nSimulateur arrêté. Total messages publiés : {msg_count}")

    finally:
        client.loop_stop()
        client.disconnect()
        print("Déconnecté du broker MQTT.")


# =============================================================
# POINT D'ENTRÉE
# =============================================================

if __name__ == "__main__":
    # Lire les arguments de la ligne de commande
    parser = argparse.ArgumentParser(
        description="Simulateur de trafic IoT pour IDS-IoT"
    )
    parser.add_argument(
        "--mode",
        choices=["normal", "flood", "injection", "scan", "mitm", "physical"],
        default="normal",
        help="Mode de simulation (défaut: normal)"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=None,
        help="Durée en secondes (défaut: infini)"
    )
    args = parser.parse_args()

    run_simulator(mode=args.mode, duration=args.duration)