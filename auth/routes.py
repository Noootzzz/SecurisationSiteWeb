from fastapi import APIRouter, HTTPException
from models import UserRegister, UserLogin
from database import supabase
from auth.security import create_token
import bcrypt
import time

router = APIRouter()

last_login_attempt = {}



@router.post("/register", tags=["Auth"])
def register(user: UserRegister):
    existing = supabase.table("users").select("*").eq("email", user.email).execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Email déjà utilisé")

    hashed_pw = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
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

@router.post("/login", tags=["Auth"])
def login(user: UserLogin):
    now = time.time()
    if user.email in last_login_attempt and now - last_login_attempt[user.email] < 5:
        raise HTTPException(status_code=429, detail="Attendez 5 secondes avant de réessayer")
    last_login_attempt[user.email] = now

    resp = supabase.table("users").select("*").eq("email", user.email).execute()
    if not resp.data:
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")

    db_user = resp.data[0]
    if "role_id" in db_user and db_user["role_id"]:
        role_resp = supabase.table("roles").select("*").eq("id", db_user["role_id"]).execute()
        role = role_resp.data[0] if role_resp.data else None
        if not role or not role.get("can_post_login"):
            raise HTTPException(status_code=403, detail="Permission de connexion refusée")

    if not bcrypt.checkpw(user.password.encode('utf-8'), db_user["password"].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")

    token = create_token(db_user["email"])
    return {"token": token}
