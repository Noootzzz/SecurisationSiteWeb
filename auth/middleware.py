# from fastapi import Request, HTTPException
# from fastapi.responses import JSONResponse
# from auth.security import decode_token
# from database import supabase
# import jwt

# async def auth_middleware(request: Request, call_next):
#     # On ne protège pas les routes publiques
#     public_routes = ["/login", "/register", "/health", "/get_products", "/all-products", "/docs", "/openapi.json"]
#     if any(request.url.path.startswith(route) for route in public_routes):
#         return await call_next(request)

#     auth_header = request.headers.get("Authorization")
#     if not auth_header or not auth_header.startswith("Bearer "):
#         return JSONResponse({"detail": "Token manquant ou invalide"}, status_code=401)

#     token = auth_header.split(" ")[1]
#     try:
#         payload = decode_token(token)
#         email = payload.get("email")
#         if not email:
#             raise HTTPException(status_code=401, detail="Token invalide")

#         user_resp = supabase.table("users").select("*").eq("email", email).execute()
#         if not user_resp.data:
#             raise HTTPException(status_code=401, detail="Utilisateur introuvable")
#         user = user_resp.data[0]

#         # Vérification si mot de passe modifié après le token
#         if "password_changed_at" in user and user["password_changed_at"]:
#             if payload["iat"] < user["password_changed_at"]:
#                 raise HTTPException(status_code=401, detail="Token expiré, mot de passe modifié")

#         # Récupération du rôle
#         if "role_id" in user and user["role_id"]:
#             role_resp = supabase.table("roles").select("*").eq("id", user["role_id"]).execute()
#             user["role"] = role_resp.data[0] if role_resp.data else {}
#         else:
#             user["role"] = {}

#         request.state.user = user
#         response = await call_next(request)
#         return response

#     except jwt.ExpiredSignatureError:
#         return JSONResponse({"detail": "Token expiré"}, status_code=401)
#     except Exception as e:
#         return JSONResponse({"detail": str(e)}, status_code=401)


from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from auth.security import decode_token
from database import supabase
import jwt

async def auth_middleware(request: Request, call_next):
    # Routes publiques qui n'ont pas besoin d'auth
    public_routes = ["/login", "/register", "/health", "/get_products", "/all-products", "/docs", "/openapi.json"]
    if any(request.url.path.startswith(route) for route in public_routes):
        return await call_next(request)

    auth_header = request.headers.get("Authorization")
    api_key_header = request.headers.get("x-api-key")

    try:
        user = None

        if api_key_header:
            # Authentification via clé API
            key_resp = supabase.table("api_keys").select("*").eq("key", api_key_header).execute()
            if not key_resp.data:
                return JSONResponse({"detail": "Clé API invalide"}, status_code=401)
            user_resp = supabase.table("users").select("*").eq("id", key_resp.data[0]["user_id"]).execute()
            if not user_resp.data:
                return JSONResponse({"detail": "Utilisateur introuvable"}, status_code=401)
            user = user_resp.data[0]

        elif auth_header and auth_header.startswith("Bearer "):
            # Authentification via JWT
            token = auth_header.split(" ")[1]
            payload = decode_token(token)
            email = payload.get("email")
            if not email:
                raise HTTPException(status_code=401, detail="Token invalide")

            user_resp = supabase.table("users").select("*").eq("email", email).execute()
            if not user_resp.data:
                raise HTTPException(status_code=401, detail="Utilisateur introuvable")
            user = user_resp.data[0]

            # Vérification si mot de passe modifié après le token
            if "password_changed_at" in user and user["password_changed_at"]:
                if payload["iat"] < user["password_changed_at"]:
                    raise HTTPException(status_code=401, detail="Token expiré, mot de passe modifié")
        else:
            return JSONResponse({"detail": "Non authentifié"}, status_code=401)

        # Récupération du rôle si nécessaire
        if "role_id" in user and user["role_id"]:
            role_resp = supabase.table("roles").select("*").eq("id", user["role_id"]).execute()
            user["role"] = role_resp.data[0] if role_resp.data else {}
        else:
            user["role"] = {}

        # Stocker l'utilisateur dans l'état de la requête pour l'utiliser dans les routes
        request.state.user = user

        return await call_next(request)

    except jwt.ExpiredSignatureError:
        return JSONResponse({"detail": "Token expiré"}, status_code=401)
    except Exception as e:
        return JSONResponse({"detail": str(e)}, status_code=401)
