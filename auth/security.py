import jwt
import time
from datetime import datetime, timedelta
from fastapi import HTTPException
from config import JWT_SECRET
from database import supabase

def create_token(email: str):
    payload = {
        "email": email,
        "iat": int(time.time()),
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expiré")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token invalide")

def check_permission(user, permission: str):
    if not user.get("role") or not user["role"].get(permission):
        raise HTTPException(status_code=403, detail=f"Permission '{permission}' refusée")
