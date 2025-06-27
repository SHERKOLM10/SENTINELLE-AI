import sys
import json
from scapy.all import sniff, IP, TCP, UDP, ICMP
import psutil
import platform
import socket
import mariadb
import os
from dotenv import load_dotenv


load_dotenv()



config_db = {
    'user': os.environ.get('DB_USER'),
    'password': os.environ.get('DB_PASSWORD'),
    'host': os.environ.get('DB_HOST'),
    'port': int(os.environ.get('DB_PORT', 3308)),
    'database': os.environ.get('DB_NAME')
}



class CaptureTrafic:
    """
    Classe responsable de l'initialisation à la BDD et de la capture du trafic réseau
    sur l'interface Wi-Fi de l'ordinateur local.
    """

    def __init__(self):
        """Constructeur de la classe qui initie le module de capture réseau"""
        print("  Initialisation du module de capture de logs.")

        self.nom_interface = self._trouver_interface_wifi()
        if not self.nom_interface:
            raise SystemExit("Aucune interface Wi-Fi active n'a été trouvée.")

        try:
            self.conn = mariadb.connect(**config_db)
            self.cursor = self.conn.cursor()
            print("   -> Connexion à la BDD réussie.")
        except mariadb.Error as e:
            raise SystemExit(f"Erreur lors de la connexion à la BDD: {e}")

    def __del__(self):
        """Fonction pour bien fermer la connexion à la BDD"""
        # CORRECTION : Coquille, 'sef.conn' -> 'self.conn'
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
            print("\n   -> Connexion à la base de données fermée.")

    def _trouver_interface_wifi(self):
        """
        Fonction pour détecter l'interface Wi-Fi active.
        """
        print(" Recherche de l'interface Wi-Fi...")
        os_type = platform.system().lower()
        mots_cles_wifi = {"linux": ["wlan", "wlp"], "windows": ["wi-fi", "sans fil"], "darwin": ["en0"]}.get(os_type,
                                                                                                             [])

        if not mots_cles_wifi:
            return None

        for nom_interface, adresses in psutil.net_if_addrs().items():
            if any(mot in nom_interface.lower() for mot in mots_cles_wifi):
                for addr in adresses:
                    if addr.family == socket.AF_INET:
                        print(f"   -> Interface Wi-Fi trouvée : '{nom_interface}'")
                        return nom_interface
        return None

    def _gestionnaire_paquet(self, paquet):
        """Fonction qui analyse le paquet et l'insère dans la BDD"""


        if not paquet.haslayer(IP):
            return

        ip_source = paquet[IP].src
        ip_destination = paquet[IP].dst
        taille_paquet = len(paquet)
        donnees_brutes = {}

        if paquet.haslayer(TCP):
            protocole = 'TCP'
            donnees_brutes['port_source'] = paquet[TCP].sport
            donnees_brutes['port_destination'] = paquet[TCP].dport
        elif paquet.haslayer(UDP):
            protocole = 'UDP'
            donnees_brutes['port_source'] = paquet[UDP].sport
            donnees_brutes['port_destination'] = paquet[UDP].dport
        elif paquet.haslayer(ICMP):
            protocole = 'ICMP'
        else:
            protocole = f"IP/{paquet[IP].proto}"

        print(f"  [LOG] {ip_source} -> {ip_destination} | {protocole}")

        try:
            requete = """
                      INSERT INTO logs(ip_source, ip_destination, protocole, taille_paquet, donnees_brutes)
                      VALUES (?, ?, ?, ?, ?) \
                      """
            self.cursor.execute(requete, (
                ip_source,
                ip_destination,
                protocole,
                taille_paquet,
                json.dumps(donnees_brutes)
            ))
            self.conn.commit()
        except mariadb.Error as e:
            print(f"Erreur d'insertion BDD : {e}")

    def demarrer_capture(self):
        """Fonction pour lancer la capture de logs"""
        print(f"\nLancement de la capture du trafic sur l'interface Wi-Fi '{self.nom_interface}'...")
        print("   (Appuyez sur Ctrl+C pour arrêter)")

        try:
            # CORRECTION : J'ai harmonisé le nom de la méthode appelée.
            sniff(iface=self.nom_interface, prn=self._gestionnaire_paquet, store=0)
        except PermissionError:
            print("\n ERREUR DE PERMISSION : Le script doit être lancé en tant qu'administrateur.")
        except Exception as e:
            print(f" Une erreur est survenue lors de la capture: {e}")


if __name__ == '__main__':
    captureur = None
    try:
        captureur = CaptureTrafic()
        captureur.demarrer_capture()
    except SystemExit as e:
        print(f" Arrêt du script : {e}")
    except KeyboardInterrupt:
        print(" Capture arrêtée par l'utilisateur.")
    finally:
        print("\n Programme de capture terminé.")