# DATE : 13/03/2025
# AUTEUR : NADHON ET POZOU 
# BUT : CREATION D'UNE BASE DE DONNEES POUR LE PROJET DE GESTION de LA SURVIELLNCE RESEAUX 

print(" Le script DataBase.py démarre...")

import mariadb

class BaseDonnees:
    """
    Classe définissant une base de données caractérisée par :
    - connexion a MariaDB
    - Création de la base de données et des tables
    - Gestion des erreurs et affichage du suivi
    """
    def __init__(self) : 
        """
        Constructeur de la classe BaseDonnees.
        """
        try:
            self.connexion = mariadb.connect(
                user='root',
                password='',
                host='127.0.0.1',
                port=3308,
                )
            self.cursor = self.connexion.cursor()
            print("connexion à MariaDB reussie ")
            self.CREATE_DB()
        except mariadb.Error as capture_erreur:
            print(f"Erreur de connexion à la base de donnees : {capture_erreur}")

    def CREATE_DB(self) :
        """Crée la base de données si elle n'existe pas et lance la création des tables."""
        try:
            self.cursor.execute("CREATE DATABASE IF NOT EXISTS monitoring_db")
            self.cursor.execute("USE monitoring_db")
            print("Base de données `monitoring_db` sélectionnée/créée.")
            self.CREATE_TABLES()
        except mariadb.Error as capture_erreur:
            print(f"Erreur de création de la base de donnee : {capture_erreur}" )

    def CREATE_TABLES(self) :
        """Crée toutes les tables dans le bon ordre de dépendance."""

        requetes = [
            """
            CREATE TABLE IF NOT EXISTS admin (
                id INT AUTO_INCREMENT PRIMARY KEY,
                nom_utilisateur VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                mot_de_passe TEXT NOT NULL,
                role ENUM('admin'),
                date_creation DATETIME DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB""",

            """
            CREATE TABLE IF NOT EXISTS appareils_connecte (
                id INT AUTO_INCREMENT PRIMARY KEY,
                adresse_ip VARCHAR(45) NOT NULL UNIQUE,
                adresse_mac VARCHAR(17) UNIQUE,
                type_appareil VARCHAR(100),
                empreinte_os VARCHAR(255),
                derniere_activite DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                statut ENUM('actif', 'inactif', 'suspect') NOT NULL DEFAULT 'actif'
            ) ENGINE=InnoDB""",
            
            # Les tables qui dépendent des précédentes.
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_source VARCHAR(45) NOT NULL,
                niveau_gravite TINYINT UNSIGNED NOT NULL,
                categorie VARCHAR(100) NOT NULL,
                description TEXT,
                statut ENUM('ouvert', 'investigation', 'resolu') NOT NULL DEFAULT 'ouvert',
                date_incident DATETIME DEFAULT CURRENT_TIMESTAMP,
                date_mise_a_jour TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                utilisateur_id INT,
                CONSTRAINT chk_niveau_gravite CHECK (niveau_gravite BETWEEN 1 AND 7),
                CONSTRAINT fk_incidents_admin FOREIGN KEY (utilisateur_id) REFERENCES admin(id)
                    ON DELETE SET NULL ON UPDATE CASCADE
            ) ENGINE=InnoDB""",

            """
            CREATE TABLE IF NOT EXISTS logs (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                date_capture DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_source VARCHAR(45) NOT NULL,
                ip_destination VARCHAR(45),
                protocole VARCHAR(20) NOT NULL,
                taille_paquet INT,
                donnees_brutes JSON,
                incident_id INT,
                CONSTRAINT fk_logs_incidents FOREIGN KEY (incident_id) REFERENCES incidents(id)
                    ON DELETE SET NULL ON UPDATE CASCADE
            ) ENGINE=InnoDB""",

            """
            CREATE TABLE IF NOT EXISTS scan_vulnerabilites (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_cible VARCHAR(45) NOT NULL,
                port INT UNSIGNED,
                service VARCHAR(100),
                type_vulnerabilite VARCHAR(255) NOT NULL,
                niveau_severite TINYINT UNSIGNED NOT NULL,
                date_scan DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                -- La table 'appareils_connecte' doit exister avant celle-ci.
                CONSTRAINT fk_scan_appareil FOREIGN KEY (ip_cible) REFERENCES appareils_connecte(adresse_ip)
                    ON DELETE CASCADE ON UPDATE CASCADE
            ) ENGINE=InnoDB""",

            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                date_alert DATETIME DEFAULT CURRENT_TIMESTAMP,
                type_alerte VARCHAR(50),
                niveau_gravite ENUM('faible', 'moyen', 'eleve'),
                description TEXT,
                statut ENUM('ouvert', 'resolu') DEFAULT 'ouvert',
                incident_id INT,
                CONSTRAINT fk_alerts_incidents FOREIGN KEY (incident_id) REFERENCES incidents(id)
                    ON DELETE SET NULL ON UPDATE CASCADE
            ) ENGINE=InnoDB""",



            """
            CREATE TABLE IF NOT EXISTS chatbot_interactions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                date_echange DATETIME DEFAULT CURRENT_TIMESTAMP,
                message_utilisateur TEXT NOT NULL,
                reponse_chatbot TEXT NOT NULL,
                utilisateur_id INT,
                -- CORRECTION: La table de référence est 'admin', pas 'users'.
                CONSTRAINT fk_chatbot_admin FOREIGN KEY (utilisateur_id) REFERENCES admin(id)
                    ON DELETE SET NULL ON UPDATE CASCADE
            ) ENGINE=InnoDB"""
        ]
        
        print("Début de la création des tables...")
        for requete in requetes:
            try: 
                self.cursor.execute(requete)

                print("✅ Requête de création de table exécutée avec succès.")
            except mariadb.Error as capture_erreur:
                print(f"❌ Erreur lors de l'exécution de la requête : {capture_erreur}")
                print(f"   Requête en échec : {requete[:150]}...")
        

        self.connexion.commit()
        print("Toutes les créations de tables ont été tentées.")


    def fermer_connexion(self):
        """Ferme la connexion à la base de données."""
        if self.cursor: self.cursor.close()
        if self.connexion: self.connexion.close()
        print("Connexion MariaDB fermee avec succes.")

# creation d'une instance
if __name__ == "__main__":
    db = BaseDonnees()
    db.fermer_connexion()

        


