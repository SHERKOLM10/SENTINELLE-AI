# Sentinelle IA - Application SIEM

Ceci est un projet d'application de surveillance réseau (SIEM) développé avec Flask, SQLAlchemy, et Chart.js.

## Fonctionnalités

*   Dashboard de visualisation des incidents
*   Affichage des appareils connectés, des logs et des incidents de vulnérabilité
*   Assistant IA intégré (via Groq) pour aider à l'analyse
*   Système d'authentification des utilisateurs

## Installation

1.  Clonez le dépôt :
    `git clone https://github.com/SHERKOLM10/SENTINELLE-AI.git`
2.  Créez un environnement virtuel :
    `python -m venv venv`
3.  Activez l'environnement :
    *   Windows : `venv\Scripts\activate`
    *   macOS/Linux : `source venv/bin/activate`
4.  Installez les dépendances :
    `pip install -r requirements.txt`
5.  Créez un fichier `.env` et remplissez les variables nécessaires (`DB_USER`, `DB_PASSWORD`, `SECRET_KEY`, `GROQ_API_KEY`).
6.  Lancez l'application :
    `python sentinelle.py`

## Utilisation

- Accédez à `http://127.0.0.1:5000` dans votre navigateur.
- Connectez-vous avec les identifiants administrateur.