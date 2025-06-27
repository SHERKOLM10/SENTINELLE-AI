import sys
import nmap
import mariadb
import socket
import platform
import ipaddress
import psutil
import netifaces
import os
from dotenv import load_dotenv


# Base de données
load_dotenv()

config_db = {
    'user': os.environ.get('DB_USER'),
    'password': os.environ.get('DB_PASSWORD'),
    'host': os.environ.get('DB_HOST'),
    'port': int(os.environ.get('DB_PORT', 3308)),
    'database': os.environ.get('DB_NAME')
}

class DecouverteReseau:
    """
    Découvre les appareils sur le réseau actif, analyse leurs caractéristiques
    et met à jour la base de données.
    """
    def __init__(self):
        """Initialise la connexion BDD, la configuration réseau et Nmap."""
        print("Initialisation de la connexion à BDD")
        try:
            self.conn = mariadb.connect(**config_db)
            self.cursor = self.conn.cursor()
            print("Connnexion à la base de données réussie")
        except mariadb.Error as e:
            if hasattr(self, 'conn') and self.conn: self.conn.close()
            raise SystemExit(f"Erreur de la connexion à la BDD: {e}")

        self.reseau_local = None
        if not self._configuration_reseau():
            self.conn.close()
            raise SystemExit("Erreur de configuration réseau")
        try:
            self.nmap = nmap.PortScanner()
            print("Module Nmap initialisé")
        except nmap.PortScannerError:
            self.conn.close()
            raise SystemExit("Nmap n'est pas trouvé. Veillez l'installer.")

    def _configuration_reseau(self):
        """Détecte l'adresse IP locale et le réseau associé."""
        print("Détection du réseau actif...")
        try:

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                mon_ip = s.getsockname()[0]

            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.address == mon_ip and addr.family == socket.AF_INET:

                        self.reseau_local = str(ipaddress.IPv4Network(f'{mon_ip}/{addr.netmask}', strict=False))
                        print(f" Réseau Local détecté: {self.reseau_local}")
                        return True
        except Exception as e:
            print(f"Réseau local introuvable: {e}")
        return False

    def __del__(self):
        """Destructeur pour fermer proprement la connexion à la BDD."""
        if hasattr(self, 'conn') and self.conn:
            if self.conn.open:
                self.conn.close()
                print("Connexion à la BDD bien fermée")

    @staticmethod
    def _deduire_type_appareil(info_os):
        """Tente de deviner le type d'appareil à partir de son OS."""
        info_os_lower = info_os.lower() if info_os else ""
        if "router" in info_os_lower: return "Routeur"
        if "linux" in info_os_lower: return "Serveur/Station Linux"
        if "mac os" in info_os_lower: return "Mac OS"
        if "windows" in info_os_lower: return "PC/Station Windows"
        if "android" in info_os_lower or "iphone" in info_os_lower or "ipad" in info_os_lower: return "Appareil Mobile"
        if "printer" in info_os_lower: return "Imprimante"
        return "Inconnu"

    def lancer_decouverte_et_mise_a_jour(self):
        """Orchestre le scan Nmap et la mise à jour de la table appareils_connecte."""
        print(f"\nLancement de la découverte des appareils sur {self.reseau_local}...")

        self.nmap.scan(hosts=self.reseau_local, arguments='-sT -O --osscan-guess')
        adresse_ip_active = []
        print("\nTraitement des résultats et mise à jour dans la BDD....")

        for appareil_ip in self.nmap.all_hosts():
            adresse_ip_active.append(appareil_ip)
            infos = self.nmap[appareil_ip]

            adresse_mac = infos['addresses'].get('mac', '').upper()
            empreinte_os = "Indéterminé"
            if 'osmatch' in infos and infos['osmatch']:
                empreinte_os = infos['osmatch'][0]['name']

            type_appareil = self._deduire_type_appareil(empreinte_os)

            print(f"Appareil trouvé : {appareil_ip} ({type_appareil})")


            requete_sql = """
                INSERT INTO appareils_connecte (adresse_ip, adresse_mac, type_appareil, empreinte_os, statut, derniere_activite)
                VALUES (%s, %s, %s, %s, 'actif', NOW())
                ON DUPLICATE KEY UPDATE
                    adresse_mac = VALUES(adresse_mac),
                    type_appareil = VALUES(type_appareil),
                    empreinte_os = VALUES(empreinte_os),
                    statut = 'actif',
                    derniere_activite = NOW()
                """
            try:
                self.cursor.execute(requete_sql, (appareil_ip, adresse_mac, type_appareil, empreinte_os))
                self.conn.commit()
            except mariadb.Error as e:

                print(f"Erreur lors de l'insertion pour l'IP {appareil_ip}: {e}")


        print("\nVérification des appareils devenus inactifs...")
        if adresse_ip_active:
            placeholders = ', '.join(['%s'] * len(adresse_ip_active))
            requete_inactif = f"UPDATE appareils_connecte SET statut = 'inactif' WHERE adresse_ip NOT IN ({placeholders})"
            self.cursor.execute(requete_inactif, tuple(adresse_ip_active))
            self.conn.commit()
            if self.cursor.rowcount > 0:
                print(f"{self.cursor.rowcount} appareil(s) précédemment actif(s) sont maintenant marqués comme inactifs.")
        else:
            print("Aucun appareil n'est actif. Tous les appareils existants sont marqués comme inactifs.")
            self.cursor.execute("UPDATE appareils_connecte SET statut = 'inactif'")
            self.conn.commit()


if __name__ == "__main__":
    print("DECOUVERTE EN COURS....")
    try:
        decouverte = DecouverteReseau()
        decouverte.lancer_decouverte_et_mise_a_jour()
    except SystemExit as e:
        print(f"Arrêt du script: {e}")
    finally:
        print("\n DECOUVERTE TERMINEE.")