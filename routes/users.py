from fastapi import APIRouter, Request, HTTPException
from models import ChangePasswordRequest
from database import supabase
from auth.security import check_permission
import bcrypt
import time

router = APIRouter()

@router.get("/my-user", tags=["Account"])
def my_user(request: Request):
    user = request.state.user
    check_permission(user, "can_get_my_user")
    return user

@router.get("/users", tags=["Account"])
def get_users(request: Request):
    user = request.state.user
    check_permission(user, "can_get_users")
    resp = supabase.table("users").select("name,email,role_id").execute()
    return resp.data

@router.patch("/change-password", tags=["Account"])
def change_password(request: Request, body: ChangePasswordRequest):
    user = request.state.user
    hashed_pw = bcrypt.hashpw(body.new_password.encode('utf-8'), bcrypt.gensalt())
    supabase.table("users").update({
        "password": hashed_pw.decode('utf-8'),
        "password_changed_at": int(time.time())
    }).eq("email", user["email"]).execute()
    return {"message": "Mot de passe changé, vos tokens existants sont invalidés"}
