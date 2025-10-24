from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from auth.routes import router as auth_router
from routes.users import router as users_router
from routes.products import router as products_router
from routes.api_key import router as api_key_router
from routes.webhook import router as webhook_router
from auth.middleware import auth_middleware

app = FastAPI()

# Middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware d'auth
app.middleware("http")(auth_middleware)

@app.get("/health", tags=["Health"])
def health():
    """
    Simple health check endpoint.
    """
    return {"test": "hello world"}

# Routes
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(products_router)
app.include_router(api_key_router)
app.include_router(webhook_router)
