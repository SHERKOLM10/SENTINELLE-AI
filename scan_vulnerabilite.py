import sys
import nmap
import mariadb
from dotenv import load_dotenv

load_dotenv()

config_db = {
    'user': os.environ.get('DB_USER'),
    'password': os.environ.get('DB_PASSWORD'),
    'host': os.environ.get('DB_HOST'),
    'port': int(os.environ.get('DB_PORT', 3308)),
    'database': os.environ.get('DB_NAME')
}



class ScannerVulnerabilite:
    """Scanne les vulnérabilités en classifiant leur sévérité selon une échelle
       simplifiée (Critique, Moyen, Faible) et la convertit en un chiffre."""

    port_critiques = {21, 22, 23, 445, 3389}
    port_moyens = {80, 443, 3306, 5432, 1433, 27017}
    ports_faibles = {53, 123}
    CLES_CRITIQUES = ['rce', 'exécution de code à distance', 'command execution', 'exploitable', 'critique']

    def __init__(self):
        """Constructeur de la classe ScannerVulnerabilites qui initie la base
                de données et le Nmap"""""
        try:
            self.conn = mariadb.connect(**config_db)
            self.cursor = self.conn.cursor()
            print(" Connexion à la base de données réussie.")
        except mariadb.Error as e:
            raise SystemExit(f"Erreur de la connexion à la BD: {e}")

        try:
            self.nmap = nmap.PortScanner()
            print("  Module Nmap initialisé.")
        except nmap.PortScannerError:
            raise SystemExit("Nmap non trouvé. Veuillez l'installer.")

    def __del__(self):
        """Fonction pour fermer la connexion à la base de données"""
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
            print("\n   -> Connexion à la base de données fermée.")

    def _recuperer_appareils_connectes(self):
        """Fonction pour récupérer les appareils connectés dans la base de données pour l'exécution du script"""
        print("\n Récupération des appareils connectés dans la base de données...")
        try:
            self.cursor.execute("SELECT adresse_ip FROM appareils_connecte WHERE statut = 'actif'")
            cibles = [item[0] for item in self.cursor.fetchall()]
            if cibles:
                print(f"{len(cibles)} cible(s) trouvée(s). Début du scan...")
            else:
                print("Aucun appareil trouvé dans la base de données.")
            return cibles
        except mariadb.Error as e:
            print(f"Erreur lors de la récupération des cibles: {e}")
            return []

    def _niveau_severtie(self, port, resultat_script):
        """Fonction pour déterminer le niveau de sévérité des vulnérabiltés"""
        if resultat_script and any(mot in resultat_script.lower() for mot in self.CLES_CRITIQUES):
            return "Critique"
        if port in self.port_critiques:
            return "Critique"
        if port in self.port_moyens:
            return "Moyen"
        if port in self.ports_faibles:
            return "Faible"
        return "Information"

    def _scanner_une_cible(self, ip_cible):
        """Fonction qui lance le scan détaillé sur chaque machine connecté du réseau, ce ci se fait à tour de rôle"""
        print(f"\n    Scan détaillé en cours sur {ip_cible}...")
        try:
            self.nmap.scan(ip_cible, arguments='-sV --script vuln')
            if ip_cible not in self.nmap.all_hosts(): return

            for proto in self.nmap[ip_cible].all_protocols():
                for port in self.nmap[ip_cible][proto].keys():
                    info = self.nmap[ip_cible][proto][port]


                    resultat_script = None
                    type_vulnerabilite = f"Port ouvert : {info.get('product', '')} {info.get('version', '')}"

                    if 'script' in info:
                        for nom_script, resultat in info['script'].items():
                            if 'vuln' in nom_script:
                                resultat_script = resultat
                                type_vulnerabilite = f"Faille détectée par '{nom_script}'"
                                break

                    niveau = self._niveau_severtie(port, resultat_script)

                    severite = {
                        "Critique": 1,
                        "Moyen": 2,
                        "Faible": 3,
                        "Information": 4,
                    }.get(niveau, 4)

                    print(f"Port {port} ouvert. Sévérité : {niveau} (Niveau {severite})")


                    requete = """
                              INSERT INTO scan_vulnerabilites
                                  (ip_cible, port, service, type_vulnerabilite, niveau_severite)
                              VALUES (?, ?, ?, ?, ?) \
                              """

                    self.cursor.execute(requete,
                                        (ip_cible, port, info.get('name', 'inconnu'), type_vulnerabilite, severite))


            self.conn.commit()

        except Exception as e:
            print(f"      -> Une erreur est survenue lors du scan de {ip_cible}: {e}")

    def lancer_scan(self):
        """Fonction qui lance le scan détaillé sur chaque machine connecté du réseau, ce ci se fait à tour de rôle"""
        cible_a_scanner = self._recuperer_appareils_connectes()
        if not cible_a_scanner: return
        for ip in cible_a_scanner:
            self._scanner_une_cible(ip)


if __name__ == "__main__":
    scanneur = None
    try:
        scanneur = ScannerVulnerabilite()
        scanneur.lancer_scan()
    except SystemExit as e:
        print(f"Arrêt du script : {e}")
    finally:
        print("\nLe scan de vulnérabilités est terminé.")