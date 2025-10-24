from pydantic import BaseModel
from typing import Optional
from typing import List

class UserRegister(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class ChangePasswordRequest(BaseModel):
    new_password: str

class ProductCreate(BaseModel):
    name: str
    sales_count: int = 0
    shopify_id: Optional[str] = None
    price: float
    image_url: Optional[str] = None

class ApiKeyCreateRequest(BaseModel):
    name: str

class LineItem(BaseModel):
    product_id: int
    quantity: int

class OrderCreate(BaseModel):
    line_items: List[LineItem]