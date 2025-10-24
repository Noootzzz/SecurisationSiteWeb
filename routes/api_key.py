from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
import secrets
from database import supabase
from models import ApiKeyCreateRequest

router = APIRouter(tags=["API Keys"])

@router.post("/api-keys")
def create_api_key(request: Request, body: ApiKeyCreateRequest):
    user = request.state.user

    existing = supabase.table("api_keys")\
                       .select("*")\
                       .eq("user_id", user["id"])\
                       .eq("name", body.name)\
                       .execute()
    if existing.data:
        raise HTTPException(status_code=400, detail="Le nom de clé API est déjà utilisé")

    new_key = secrets.token_urlsafe(32)

    supabase.table("api_keys").insert({
        "user_id": user["id"],
        "name": body.name,
        "key": new_key
    }).execute()

    return {"name": body.name, "key": new_key}

@router.get("/api-keys")
def list_api_keys(request: Request):
    user = request.state.user
    resp = supabase.table("api_keys").select("id,name,created_at").eq("user_id", user["id"]).execute()
    return {"api_keys": resp.data}

@router.delete("/api-keys/{key_id}")
def delete_api_key(request: Request, key_id: int):
    user = request.state.user
    supabase.table("api_keys").delete().eq("id", key_id).eq("user_id", user["id"]).execute()
    return {"message": "Clé API supprimée"}
