
from flask import Flask, render_template, jsonify, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from dotenv import load_dotenv
import os
import enum
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
import chatbot as assistant_logic


load_dotenv()
app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# Configuration de la base de données
user = os.environ.get('DB_USER')
mot_de_passe = os.environ.get('DB_PASSWORD')
ip_local = os.environ.get('DB_HOST')
port = os.environ.get('DB_PORT')
nom_bdd = os.environ.get('DB_NAME')
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+mysqlconnector://{user}:{mot_de_passe}@{ip_local}:{port}/{nom_bdd}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Initialisation de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'authentification'
login_manager.login_message = "Veuillez vous connecter pour accéder à cette page."
login_manager.login_message_category = "warning"

# --- Définition des Modèles de Données ---

class StatutIncident(enum.Enum):
    ouvert = 'ouvert'; investigation = 'investigation'; resolu = 'resolu'

class admin(db.Model, UserMixin):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    nom_utilisateur = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    mot_de_passe = db.Column(db.Text, nullable=False)
    def avoir_mdp(self, mot_de_passe): self.mot_passe = generate_password_hash(mot_de_passe)
    def checker_mdp(self, mot_de_passe): return check_password_hash(self.mot_de_passe, mot_de_passe)

class ScannerVulnerabilite(db.Model):
    __tablename__ = 'scan_vulnerabilites'
    id = db.Column(db.Integer, primary_key=True)
    ip_cible = db.Column(db.String(45), nullable=False)
    port = db.Column(db.Integer)
    service = db.Column(db.String(100))
    type_vulnerabilite = db.Column(db.String(255), nullable=False)
    niveau_severite = db.Column(db.SmallInteger, nullable=False)
    date_scan = db.Column(db.DateTime, nullable=False)

class AppareilConnecte(db.Model):
    __tablename__ = 'appareils_connecte'
    id = db.Column(db.Integer, primary_key=True)
    adresse_ip = db.Column(db.String(45), nullable=False, unique=True)
    adresse_mac = db.Column(db.String(17), unique=True)
    type_appareil = db.Column(db.String(100))
    empreinte_os = db.Column(db.String(255))
    derniere_activite = db.Column(db.DateTime, nullable=False)
    statut = db.Column(db.String(50), nullable=False, default='actif')

class Incident(db.Model):
    __tablename__ = 'incidents'
    id = db.Column(db.Integer, primary_key=True)
    ip_source = db.Column(db.String(45), nullable=False)
    niveau_gravite = db.Column(db.SmallInteger, nullable=False)
    categorie = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    statut = db.Column(db.Enum(StatutIncident), default=StatutIncident.ouvert, nullable=False)
    date_incident = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.BigInteger, primary_key=True)
    date_capture = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip_source = db.Column(db.String(45), nullable=False)
    ip_destination = db.Column(db.String(45))
    protocole = db.Column(db.String(20), nullable=False)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id'), nullable=True)

class ChatbotInteraction(db.Model):
    __tablename__ = 'chatbot_interactions'
    id = db.Column(db.Integer, primary_key=True)
    message_utilisateur = db.Column(db.Text, nullable=False)
    reponse_chatbot = db.Column(db.Text, nullable=False)

# --- Fonction User Loader pour Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    return admin.query.get(int(user_id))

# --- Routes d'Authentification ---
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def authentification():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        nom_utilisateur = request.form.get('nom_utilisateur')
        mot_de_passe = request.form.get('mot_de_passe')
        user = admin.query.filter_by(nom_utilisateur=nom_utilisateur).first()
        if user and user.checker_mdp(mot_de_passe):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Identifiants incorrects. Veuillez réessayer.', 'danger')
            return redirect(url_for('authentification'))
    return render_template("login.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Vous avez été déconnecté avec succès.', 'success')
    return redirect(url_for('authentification'))

# --- Routes des Pages Protégées ---
@app.route('/dashboard')
@login_required
def dashboard(): return render_template('dashboard.html')

@app.route('/appareils')
@login_required
def appareils(): return render_template('appareils.html')

@app.route('/admins')
@login_required
def admins(): return render_template('admins.html')

@app.route('/incidents')
@login_required
def incidents(): return render_template('incidents.html')

@app.route('/logs')
@login_required
def logs(): return render_template('logs.html')

@app.route('/assistant-ia')
@login_required
def page_assistant_ia(): return render_template('assistant_ai.html')

# --- Routes API (protégées) ---

@app.route('/api/dashboard-data')
@login_required
def get_dashboard_data():
    with app.app_context():
        try:
            total_incidents = db.session.query(ScannerVulnerabilite).filter(ScannerVulnerabilite.niveau_severite <= 4).count()
            incidents_critiques = db.session.query(ScannerVulnerabilite).filter(ScannerVulnerabilite.niveau_severite <= 2).count()
            incidents_faibles = db.session.query(ScannerVulnerabilite).filter(ScannerVulnerabilite.niveau_severite.between(3, 4)).count()
            incidents_query = ScannerVulnerabilite.query.filter(ScannerVulnerabilite.niveau_severite <= 4)
            incidents_par_heure_query = incidents_query.with_entities(func.hour(ScannerVulnerabilite.date_scan).label('heure'), func.count(ScannerVulnerabilite.id).label('nombre')).group_by('heure').order_by('heure').all()
            bar_labels = [f"{h.heure}h" for h in incidents_par_heure_query]
            bar_data = [h.nombre for h in incidents_par_heure_query]
            incidents_par_categorie_query = incidents_query.with_entities(ScannerVulnerabilite.type_vulnerabilite.label('categorie'), func.count(ScannerVulnerabilite.id).label('nombre')).group_by('categorie').order_by(func.count(ScannerVulnerabilite.id).desc()).limit(5).all()
            pie_labels = [c.categorie for c in incidents_par_categorie_query]
            pie_data = [c.nombre for c in incidents_par_categorie_query]
            data = {'kpi': {'total': total_incidents, 'critiques': incidents_critiques, 'faibles': incidents_faibles},'bar_chart': {'labels': bar_labels, 'data': bar_data},'pie_chart': {'labels': pie_labels, 'data': pie_data}}
            return jsonify(data)
        except Exception as e:
            print(f"Erreur Dashboard API: {e}")
            return jsonify({'kpi': {}, 'bar_chart': {}, 'pie_chart': {}}), 500

@app.route('/api/incidents-data')
@login_required
def incidents_data():
    with app.app_context():
        try:
            scans_pertinents = db.session.query(ScannerVulnerabilite).filter(ScannerVulnerabilite.niveau_severite <= 4).order_by(ScannerVulnerabilite.date_scan.desc()).all()
            incidents_virtuels = []
            for scan in scans_pertinents:
                gravite_incident = 1 if scan.niveau_severite <= 2 else 2
                categorie_incident = "Critique" if scan.niveau_severite <= 2 else "Modéré"
                incident_dict = {'id': scan.id,'ip_source': scan.ip_cible,'categorie': categorie_incident,'gravite': gravite_incident,'date': scan.date_scan.strftime('%d/%m/%Y %H:%M:%S'),'description': f"Scan a détecté: '{scan.type_vulnerabilite}' sur le port {scan.port}."}
                incidents_virtuels.append(incident_dict)
            return jsonify(incidents_virtuels)
        except Exception as e:
            print(f"Erreur API (incidents): {e}")
            return jsonify([]), 500

@app.route('/api/appareils-data')
@login_required
def appareils_data():
    with app.app_context():
        appareils_list = AppareilConnecte.query.order_by(AppareilConnecte.derniere_activite.desc()).all()
        data = [{'ip': appareil.adresse_ip, 'mac': appareil.adresse_mac, 'type': appareil.type_appareil,'empreinte_os': appareil.empreinte_os, 'statut': appareil.statut,'derniere_activite': appareil.derniere_activite.strftime('%d/%m/%Y %H:%M:%S')} for appareil in appareils_list]
        return jsonify(data)

@app.route('/api/logs-data')
@login_required
def logs_data():
    with app.app_context():
        logs_list = Log.query.order_by(Log.date_capture.desc()).limit(500).all()
        data = [{'id': log.id, 'date': log.date_capture.strftime('%d/%m/%Y %H:%M:%S'), 'ip_source': log.ip_source,'ip_destination': log.ip_destination, 'protocole': log.protocole,'incident_id': log.incident_id if log.incident_id else 'N/A'} for log in logs_list]
        return jsonify(data)

@app.route('/api/admins', methods=['GET', 'POST'])
@login_required
def admins_get():
    with app.app_context():
        if request.method == 'POST':
            data = request.get_json()
            if not data or not data.get('nom') or not data.get('email') or not data.get('password'):
                return jsonify({'error': 'Données manquantes'}), 400
            if Admin.query.filter_by(nom_utilisateur=data['nom']).first() or Admin.query.filter_by(email=data['email']).first():
                return jsonify({'error': 'Nom d\'utilisateur ou email déjà utilisé'}), 409
            nouvel_admin = Admin(nom_utilisateur=data['nom'], email=data['email'])
            nouvel_admin.avoir_mdp(data['password'])
            db.session.add(nouvel_admin)
            db.session.commit()
            return jsonify({'message': 'Utilisateur créé avec succès'}), 201
        else:
            admins_list = admin.query.all()
            data = [{'id': admin.id, 'nom': admin.nom_utilisateur, 'email': admin.email} for admin in admins_list]
            return jsonify(data)

@app.route('/api/assistant-ai', methods=['POST'])
@login_required
def assistant_api():
    with app.app_context():
        message = request.json.get('message')
        if not message: return jsonify({"error": "Message manquant"}), 400
        db_dependencies = {'Incident': ScannerVulnerabilite, 'AppareilConnecte': AppareilConnecte, 'ChatbotInteraction': ChatbotInteraction, 'func': func, 'db_session': db.session}
        ia_reponse = assistant_logic.gerer_conversation_ia(message, db_dependencies)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Erreur lors du commit de la session du chatbot: {e}")
        return jsonify({"reply": ia_reponse})

# --- Lancement de l'application ---
if __name__ == '__main__':
    app.run(debug=True)