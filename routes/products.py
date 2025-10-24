from fastapi import APIRouter, Request, HTTPException
from httpx import request
from models import OrderCreate, ProductCreate
from database import supabase
from auth.security import check_permission
from shopify_api import create_shopify_product
import bcrypt
import time

router = APIRouter()

@router.get("/all-products", tags=["Products"])
def get_products():
    resp = supabase.table("products").select("*").execute()
    return {"All Products": resp.data}

@router.get("/my-products", tags=["Products"])
def get_my_products(request: Request):
    user = request.state.user
    resp = supabase.table("products").select("*").eq("created_by", user["id"]).execute()
    return {"My Products": resp.data}

@router.post("/products", tags=["Products"])
def create_product(request: Request, product: ProductCreate):
    user = request.state.user
    check_permission(user, "can_post_products")

    if product.image_url and not user["role"].get("can_publish_img", False):
        raise HTTPException(status_code=403, detail="Vous n'avez pas le droit de publier une image")

    try:
        shopify_resp = create_shopify_product(
            name=product.name,
            price=product.price,
            image_url=product.image_url
        )
        shopify_id = shopify_resp["product"]["id"]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur Shopify : {str(e)}")

    product_data = product.dict()
    product_data.update({
        "created_by": user["id"],
        "shopify_id": shopify_id
    })

    insert_resp = supabase.table("products").insert(product_data).execute()

    return {
        "message": "Produit créé",
        "product": insert_resp.data[0],
        "shopify": shopify_resp
    }

@router.get("/my-bestsellers", tags=["Products"])
def my_bestsellers(request: Request):
    user = request.state.user
    check_permission(user, "can_post_products")

    resp = supabase.table("products")\
        .select("*")\
        .eq("created_by", user["id"])\
        .order("sales_count", desc=True)\
        .execute()

    return {"bestsellers": resp.data}

@router.post("/create-order", tags=["Products"])
def create_order(order: OrderCreate, request: Request):
    user = request.state.user
    check_permission(user, "can_post_products")

    updated_products = []

    for item in order.line_items:
        product_id = item.product_id
        quantity = item.quantity

        resp = supabase.table("products").select("id,sales_count").eq("id", product_id).execute()
        if not resp.data:
            continue

        current = resp.data[0].get("sales_count", 0)
        new_count = current + quantity

        supabase.table("products").update({"sales_count": new_count}).eq("id", product_id).execute()

        updated_products.append({"product_id": product_id, "sales_count": new_count})

    return {"message": "Commande créée", "updated_products": updated_products}
