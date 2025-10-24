import requests
from config import SHOPIFY_STORE_URL, SHOPIFY_ACCESS_TOKEN
from typing import Optional


def create_shopify_product(name: str, price: float, image_url: Optional[str] = None):
    url = f"{SHOPIFY_STORE_URL}/admin/api/2025-10/products.json"

    headers = {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
    }
    print("Creating Shopify product with image_url:", image_url)
    payload = {
        "product": {
            "title": name,
            "variants": [
                {"price": str(price)}
            ],
            "images": [{"src": image_url}] if image_url else []
        }
    }
    
    response = requests.post(url, json=payload, headers=headers)
    response.raise_for_status()
    return response.json()
