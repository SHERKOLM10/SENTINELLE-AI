
import os
from openai import OpenAI
import json


try:
    client = OpenAI(
        api_key=os.environ.get("GROQ_API_KEY"),
        base_url="https://api.groq.com/openai/v1"
    )
    print("Module Assistant: Client API Groq configuré.")
except Exception as e:
    print(f"Module Assistant: La clé API GROQ_API_KEY est introuvable ou incorrecte: {e}")
    client = None




def generer_rapport_incidents_texte(Incident, func, limite=5, filtre_gravite=None):
    """Interroge la BDD et retourne un rapport textuel des incidents."""
    try:
        query = Incident.query.order_by(Incident.date_incident.desc())
        if filtre_gravite == "critiques":
            query = query.filter(Incident.niveau_gravite == 1)
        elif filtre_gravite == "moyens":
            query = query.filter(Incident.niveau_gravite == 2)
        incidents = query.limit(limite).all()

        if not incidents:
            return "Je n'ai trouvé aucun incident correspondant à vos critères."

        rapport = f"Voici le rapport des {len(incidents)} derniers incidents {filtre_gravite or ''}:\n"
        for inc in incidents:
            rapport += (f"\n- Incident #{inc.id}\n"
                        f"  - Date: {inc.date_incident.strftime('%d/%m/%Y %H:%M')}\n"
                        f"  - Gravité: {inc.niveau_gravite}\n"
                        f"  - Catégorie: {inc.categorie}\n"
                        f"  - Description: {inc.description}\n")
        return rapport
    except Exception as e:
        print(f"Erreur dans generer_rapport_incidents_texte: {e}")
        return "Désolé, une erreur est survenue lors de la génération du rapport."


def get_statut_appareils(AppareilConnecte):
    """Compte les appareils actifs et inactifs."""
    try:
        actifs = AppareilConnecte.query.filter_by(statut='actif').count()
        inactifs = AppareilConnecte.query.filter_by(statut='inactif').count()
        return (f"J'ai trouvé un total de {actifs + inactifs} appareils :\n"
                f"- Appareils Actifs : {actifs}\n"
                f"- Appareils Inactifs : {inactifs}")
    except Exception as e:
        print(f"Erreur dans get_statut_appareils: {e}")
        return "Désolé, je n'ai pas pu récupérer le statut des appareils."


def get_details_appareil(AppareilConnecte, adresse_ip):
    """Recherche les détails d'un appareil."""
    if not adresse_ip:
        return "Veuillez spécifier une adresse IP."
    try:
        appareil = AppareilConnecte.query.filter_by(adresse_ip=adresse_ip).first()
        if not appareil:
            return f"Je n'ai trouvé aucun appareil avec l'adresse IP {adresse_ip}."
        return (f"Voici les détails pour l'appareil {adresse_ip} :\n"
                f"- Adresse MAC : {appareil.adresse_mac or 'N/A'}\n"
                f"- Empreinte OS : {appareil.empreinte_os or 'N/A'}\n"
                f"- Statut : {appareil.statut}\n"
                f"- Dernière Activité : {appareil.derniere_activite.strftime('%d/%m/%Y à %H:%M')}")
    except Exception as e:
        print(f"Erreur dans get_details_appareil: {e}")
        return f"Désolé, une erreur est survenue en cherchant les détails pour {adresse_ip}."




def gerer_conversation_ia(message, models):
    """Gère un message utilisateur, interagit avec l'IA et les outils, et retourne la réponse finale."""
    if not client:
        return "Désolé, la connexion à l'assistant IA n'est pas établie."

    prompt_systeme = """
    Tu es "Sentinelle AI", un assistant expert en cybersécurité. Tu es précis et factuel.
    Si l'utilisateur demande une action spécifique comme un scan ou un rapport, tu DOIS répondre UNIQUEMENT avec un objet JSON valide, sans aucun texte supplémentaire.
    Le format doit être : {"action": "nom_action", "details": {...}}

    Exemples d'actions :
    - Pour "donne le rapport des 5 derniers incidents critiques", réponds: {"action": "rapport_incidents", "details": {"filtre": "critiques", "limite": 5}}
    - Pour "compte les appareils actifs et inactifs" ou "statut des appareils", réponds: {"action": "statut_appareils", "details": {}}
    - Pour "donne-moi les infos sur l'IP 192.168.1.10", réponds: {"action": "details_appareil", "details": {"ip": "192.168.1.10"}}
    - Pour "scan les ports de X", réponds: {"action": "scan_port", "details": {"target": "X"}}

    Pour toute autre question (conseils, explications), réponds normalement en texte clair.
    """

    try:
        response = client.chat.completions.create(
            model="llama3-8b-8192",
            messages=[
                {"role": "system", "content": prompt_systeme},
                {"role": "user", "content": message},
            ],
            temperature=0.2,
            response_format={"type": "json_object"} if any(keyword in message.lower() for keyword in
                                                           ["scan", "rapport", "statut", "details",
                                                            "infos sur"]) else None
        )

        ia_reponse_brute = response.choices[0].message.content
        ia_reponse_finale = ""


        try:
            action_data = json.loads(ia_reponse_brute)
            action = action_data.get("action")
            details = action_data.get("details", {})

            if action == "rapport_incidents":
                ia_reponse_finale = generer_rapport_incidents_texte(
                    Incident=models['Incident'],
                    func=models['func'],
                    limite=details.get("limite", 5),
                    filtre_gravite=details.get("filtre")
                )
            elif action == "statut_appareils":
                ia_reponse_finale = get_statut_appareils(AppareilConnecte=models['AppareilConnecte'])
            elif action == "details_appareil":
                ia_reponse_finale = get_details_appareil(
                    AppareilConnecte=models['AppareilConnecte'],
                    adresse_ip=details.get("ip")
                )
            elif action in ["scan_port", "scan_vuln"]:
                ia_reponse_finale = f"Je lance l'action '{action}' sur la cible '{details.get('target')}'. Je vous préviendrai quand ce sera terminé."
            else:
                ia_reponse_finale = "J'ai détecté une demande d'action, mais je ne sais pas comment la traiter."

        except (json.JSONDecodeError, AttributeError):
            ia_reponse_finale = ia_reponse_brute

        nouvel_echange = models['ChatbotInteraction'](
            message_utilisateur=message,
            reponse_chatbot=ia_reponse_finale
        )
        models['db_session'].add(nouvel_echange)

        return ia_reponse_finale

    except Exception as e:
        print(f"Erreur API (assistant AI): {e}")
        return "L'assistant IA a rencontré un problème."