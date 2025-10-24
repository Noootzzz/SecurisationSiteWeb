from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from database import supabase
import os, hmac, hashlib, base64, json

router = APIRouter(tags=["Webhooks"])

SHOPIFY_WEBHOOK_SECRET = os.getenv("SHOPIFY_SECRET_KEY")

@router.post("/webhooks/shopify-sales")
async def shopify_sales_webhook(request: Request):
    body_bytes = await request.body()
    hmac_header = request.headers.get("x-shopify-hmac-sha256") or request.headers.get("X-Shopify-Hmac-Sha256")

    if not hmac_header:
        raise HTTPException(status_code=400, detail="HMAC manquant")

    digest = hmac.new(
        SHOPIFY_WEBHOOK_SECRET.encode("utf-8"),
        body_bytes,
        hashlib.sha256
    ).digest()
    calculated_hmac = base64.b64encode(digest).decode()
    print(calculated_hmac)
    if not hmac.compare_digest(calculated_hmac, hmac_header):
        raise HTTPException(status_code=401, detail="Signature HMAC invalide")

    payload = json.loads(body_bytes)
    line_items = payload.get("line_items", [])

    for item in line_items:
        shopify_product_id = str(item["product_id"])
        quantity = int(item.get("quantity", 1))

        resp = supabase.table("products").select("*").eq("shopify_id", shopify_product_id).execute()

        if not resp.data:
            print(f"Produit Shopify {shopify_product_id} introuvable dans Supabase")
            continue

        product = resp.data[0]
        new_sales = product["sales_count"] + quantity

        supabase.table("products").update({
            "sales_count": new_sales
        }).eq("shopify_id", shopify_product_id).execute()

    return JSONResponse({"status": "ok"})
