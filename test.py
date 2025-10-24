from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client, Client
from dotenv import load_dotenv
import os
import bcrypt
import jwt
from datetime import datetime, timedelta
import time

# Load env
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------
# Modèles
# ---------------------
class UserRegister(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class ChangePasswordRequest(BaseModel):
    new_password: str

# Mémoire pour limiter tentative de login (simple pour dev)
last_login_attempt = {}

# ---------------------
# Authorizer
# ---------------------
def get_current_user(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token invalide")
    token = authorization.split(" ")[1]

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        email = payload.get("email")
        token_iat = payload.get("iat")
        if not email:
            raise HTTPException(status_code=401, detail="Token invalide")

        user_resp = supabase.table("users").select("*").eq("email", email).execute()
        if not user_resp.data:
            raise HTTPException(status_code=401, detail="Utilisateur introuvable")

        user = user_resp.data[0]

        # Vérifier si le mot de passe a été changé après génération du token
        if "password_changed_at" in user and user["password_changed_at"]:
            if token_iat < user["password_changed_at"]:
                raise HTTPException(status_code=401, detail="Token expiré, mot de passe modifié")

        # Récupérer les permissions du rôle
        if "role_id" in user and user["role_id"]:
            role_resp = supabase.table("roles").select("*").eq("id", user["role_id"]).execute()
            if role_resp.data:
                user["role"] = role_resp.data[0]
            else:
                user["role"] = {}
        else:
            user["role"] = {}

        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expiré")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token invalide")

# ---------------------
# Helpers pour permissions
# ---------------------
def check_permission(user, permission):
    if not user.get("role") or not user["role"].get(permission):
        raise HTTPException(status_code=403, detail=f"Permission '{permission}' refusée")

# ---------------------
# ENDPOINTS
# ---------------------
# Health check
@app.get("/health")
def health():
    return {"test": "hello world"}

# Register
@app.post("/register")
def register(user: UserRegister):
    existing = supabase.table("users").select("*").eq("email", user.email).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Email déjà utilisé")

    hashed_pw = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    # rôle USER par défaut
    role_resp = supabase.table("roles").select("id").eq("name", "USER").execute()
    role_id = role_resp.data[0]["id"] if role_resp.data else None

    supabase.table("users").insert({
        "name": user.name,
        "email": user.email,
        "password": hashed_pw.decode('utf-8'),
        "password_changed_at": int(time.time()),
        "role_id": role_id
    }).execute()

    return {"message": "Utilisateur créé"}

# Login
@app.post("/login")
def login(user: UserLogin):
    now = time.time()
    # Limite une tentative toutes les 5 secondes
    if user.email in last_login_attempt:
        if now - last_login_attempt[user.email] < 5:
            raise HTTPException(status_code=429, detail="Attendez 5 secondes avant de réessayer")
    last_login_attempt[user.email] = now

    resp = supabase.table("users").select("*").eq("email", user.email).execute()
    if not resp.data:
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")

    db_user = resp.data[0]
    
    # Vérifier le rôle et la permission can_post_login
    if "role_id" in db_user and db_user["role_id"]:
        role_resp = supabase.table("roles").select("*").eq("id", db_user["role_id"]).execute()
        if role_resp.data:
            role = role_resp.data[0]
            if not role.get("can_post_login"):
                raise HTTPException(status_code=403, detail="Permission de connexion refusée")
        else:
            raise HTTPException(status_code=403, detail="Rôle introuvable")
    else:
        raise HTTPException(status_code=403, detail="Aucun rôle assigné")
    
    if not bcrypt.checkpw(user.password.encode('utf-8'), db_user["password"].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")

    payload = {
        "email": db_user["email"],
        "iat": int(time.time()),
        "exp": datetime.utcnow() + timedelta(hours=1)  # token valable 1h
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return {"token": token}

# GET MY USER
@app.get("/my-user")
def my_user(current_user=Depends(get_current_user)):
    check_permission(current_user, "can_get_my_user")
    return current_user

# GET ALL USERS
@app.get("/users")
def get_users(current_user=Depends(get_current_user)):
    check_permission(current_user, "can_get_users")
    resp = supabase.table("users").select("name,email,role_id").execute()
    return resp.data

# CHANGE PASSWORD
@app.post("/change-password")
def change_password(request: ChangePasswordRequest, current_user=Depends(get_current_user)):
    hashed_pw = bcrypt.hashpw(request.new_password.encode('utf-8'), bcrypt.gensalt())
    supabase.table("users").update({
        "password": hashed_pw.decode('utf-8'),
        "password_changed_at": int(time.time())
    }).eq("email", current_user["email"]).execute()
    return {"message": "Mot de passe changé, vos tokens existants sont invalidés"}