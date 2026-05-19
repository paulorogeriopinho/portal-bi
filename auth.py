import bcrypt
import re
from typing import Tuple

def validate_password(password: str) -> Tuple[bool, str]:
    """Retorna (válido, mensagem_de_erro)."""
    if len(password) < 8:
        return False, "A senha deve ter pelo menos 8 caracteres."
    if not re.search(r"[A-Z]", password):
        return False, "A senha deve conter pelo menos uma letra maiúscula."
    if not re.search(r"[a-z]", password):
        return False, "A senha deve conter pelo menos uma letra minúscula."
    if not re.search(r"\d", password):
        return False, "A senha deve conter pelo menos um número."
    return True, ""

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))