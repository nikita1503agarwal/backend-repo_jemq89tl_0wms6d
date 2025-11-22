import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Annotated

from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from pymongo import ASCENDING, DESCENDING
from bson import ObjectId
from dotenv import load_dotenv

load_dotenv()

# App and CORS
app = FastAPI(title="Store Rating API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database
from pymongo import MongoClient
MONGO_URL = os.getenv("DATABASE_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DATABASE_NAME", "store_rating")
client = MongoClient(MONGO_URL)
db = client[DB_NAME]
users_col = db["users"]
stores_col = db["stores"]
reviews_col = db["reviews"]

# Ensure indexes
users_col.create_index("email", unique=True)
reviews_col.create_index([("store_id", ASCENDING), ("user_id", ASCENDING)], unique=True)

# Auth / Security
SECRET_KEY = os.getenv("JWT_SECRET", "supersecret_demo_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE = os.getenv("JWT_EXPIRES_IN", "7d")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# Helpers

def objectid_str(oid):
    return str(oid) if isinstance(oid, ObjectId) else oid


def exp_from_env(default_days: int = 7) -> timedelta:
    val = ACCESS_TOKEN_EXPIRE
    try:
        if isinstance(val, str) and val.endswith("d"):
            return timedelta(days=int(val[:-1]))
        if isinstance(val, str) and val.endswith("h"):
            return timedelta(hours=int(val[:-1]))
        return timedelta(days=int(val))
    except Exception:
        return timedelta(days=default_days)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or exp_from_env())
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Models
class TokenResponse(BaseModel):
    token: str
    user: dict

class UserBase(BaseModel):
    name: str
    email: EmailStr

class UserCreate(UserBase):
    password: str
    role: Optional[str] = Field(default="user")

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RoleUpdate(BaseModel):
    role: str

class StoreBase(BaseModel):
    name: str
    description: Optional[str] = None
    address: Optional[str] = None
    tags: Optional[List[str]] = []
    image_url: Optional[str] = None

class StoreCreate(StoreBase):
    pass

class StoreUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    address: Optional[str] = None
    tags: Optional[List[str]] = None
    image_url: Optional[str] = None

class ReviewCreate(BaseModel):
    rating: int = Field(ge=1, le=5)
    comment: Optional[str] = None

class ReviewUpdate(BaseModel):
    rating: Optional[int] = Field(default=None, ge=1, le=5)
    comment: Optional[str] = None

# Auth dependencies
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = users_col.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise credentials_exception
    user["id"] = objectid_str(user.pop("_id"))
    return user


def require_roles(*roles):
    async def checker(user: Annotated[dict, Depends(get_current_user)]):
        if roles and user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return checker

# Utility aggregations

def store_with_avg_and_reviews(store_id: str, limit_reviews: Optional[int] = None):
    pipeline = [
        {"$match": {"_id": ObjectId(store_id)}},
        {"$lookup": {
            "from": "reviews",
            "localField": "_id",
            "foreignField": "store_id",
            "as": "reviews"
        }},
        {"$addFields": {
            "average_rating": {"$cond": [
                {"$gt": [{"$size": "$reviews"}, 0]},
                {"$round": [{"$avg": "$reviews.rating"}, 2]},
                None
            ]},
            "reviews_count": {"$size": "$reviews"}
        }}
    ]
    if limit_reviews:
        pipeline.append({"$set": {"reviews": {"$slice": ["$reviews", limit_reviews]}}})
    result = list(stores_col.aggregate(pipeline))
    if not result:
        return None
    store = result[0]
    store["id"] = objectid_str(store.pop("_id"))
    # Normalize reviews
    for r in store.get("reviews", []):
        r["id"] = objectid_str(r.pop("_id"))
        r["store_id"] = objectid_str(r.get("store_id"))
        r["user_id"] = objectid_str(r.get("user_id"))
    return store

# Routes
@app.get("/")
def root():
    return {"message": "Store Rating API running"}

# Auth
@app.post("/api/auth/register", response_model=TokenResponse)
def register(payload: UserCreate):
    role = payload.role if payload.role in ["user", "owner", "admin"] else "user"
    try:
        res = users_col.insert_one({
            "name": payload.name,
            "email": payload.email.lower(),
            "password": get_password_hash(payload.password),
            "role": role,
            "created_at": datetime.now(timezone.utc)
        })
    except Exception as e:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = users_col.find_one({"_id": res.inserted_id})
    token = create_access_token({"sub": objectid_str(user["_id"]), "role": user["role"]})
    return {"token": token, "user": {"id": objectid_str(user["_id"]), "name": user["name"], "email": user["email"], "role": user["role"]}}

@app.post("/api/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = users_col.find_one({"email": payload.email.lower()})
    if not user or not verify_password(payload.password, user["password"]):
        raise HTTPException(status_code=400, detail="Invalid email or password")
    token = create_access_token({"sub": objectid_str(user["_id"]), "role": user["role"]})
    return {"token": token, "user": {"id": objectid_str(user["_id"]), "name": user["name"], "email": user["email"], "role": user["role"]}}

# Users
@app.get("/api/users")
def list_users(current=Depends(require_roles("admin"))):
    docs = list(users_col.find({}, {"password": 0}).sort("created_at", DESCENDING))
    for d in docs:
        d["id"] = objectid_str(d.pop("_id"))
    return docs

@app.patch("/api/users/{user_id}/role")
def update_role(user_id: str, payload: RoleUpdate, current=Depends(require_roles("admin"))):
    if payload.role not in ["user", "owner", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    res = users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": payload.role}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    user = users_col.find_one({"_id": ObjectId(user_id)}, {"password": 0})
    user["id"] = objectid_str(user.pop("_id"))
    return user

@app.get("/api/users/me")
def me(current=Depends(get_current_user)):
    return current

# Stores
@app.get("/api/stores")
def get_stores(
    q: Optional[str] = Query(default=None, description="Search query"),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=10, ge=1, le=50),
    sort: Optional[str] = Query(default="created_at"),
    order: Optional[str] = Query(default="desc")
):
    filter_q = {}
    if q:
        filter_q = {"$or": [
            {"name": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
            {"tags": {"$elemMatch": {"$regex": q, "$options": "i"}}}
        ]}
    sort_dir = DESCENDING if order == "desc" else ASCENDING
    skip = (page - 1) * limit

    # Aggregate to compute average
    pipeline = [
        {"$match": filter_q},
        {"$lookup": {
            "from": "reviews",
            "localField": "_id",
            "foreignField": "store_id",
            "as": "reviews"
        }},
        {"$addFields": {
            "average_rating": {"$cond": [
                {"$gt": [{"$size": "$reviews"}, 0]},
                {"$round": [{"$avg": "$reviews.rating"}, 2]},
                None
            ]},
            "reviews_count": {"$size": "$reviews"}
        }},
        {"$project": {"reviews": 0}},
        {"$sort": {sort: sort_dir}},
        {"$skip": skip},
        {"$limit": limit}
    ]
    items = list(stores_col.aggregate(pipeline))
    total = stores_col.count_documents(filter_q)

    for s in items:
        s["id"] = objectid_str(s.pop("_id"))
    return {"items": items, "page": page, "limit": limit, "total": total}

@app.get("/api/stores/{store_id}")
def get_store(store_id: str):
    store = store_with_avg_and_reviews(store_id)
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    return store

@app.post("/api/stores")
def create_store(payload: StoreCreate, current=Depends(require_roles("owner", "admin"))):
    doc = payload.dict()
    now = datetime.now(timezone.utc)
    doc.update({
        "owner_id": ObjectId(current["id"]),
        "created_at": now,
        "updated_at": now
    })
    res = stores_col.insert_one(doc)
    created = stores_col.find_one({"_id": res.inserted_id})
    created["id"] = objectid_str(created.pop("_id"))
    created["owner_id"] = objectid_str(created["owner_id"])
    return created

@app.patch("/api/stores/{store_id}")
def update_store(store_id: str, payload: StoreUpdate, current=Depends(get_current_user)):
    store = stores_col.find_one({"_id": ObjectId(store_id)})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    if current["role"] != "admin" and objectid_str(store["owner_id"]) != current["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    update = {k: v for k, v in payload.dict().items() if v is not None}
    update["updated_at"] = datetime.now(timezone.utc)
    stores_col.update_one({"_id": ObjectId(store_id)}, {"$set": update})
    doc = stores_col.find_one({"_id": ObjectId(store_id)})
    doc["id"] = objectid_str(doc.pop("_id"))
    doc["owner_id"] = objectid_str(doc["owner_id"])
    return doc

@app.delete("/api/stores/{store_id}")
def delete_store(store_id: str, current=Depends(get_current_user)):
    store = stores_col.find_one({"_id": ObjectId(store_id)})
    if not store:
        raise HTTPException(status_code=404, detail="Store not found")
    if current["role"] != "admin" and objectid_str(store["owner_id"]) != current["id"]:
        raise HTTPException(status_code=403, detail="Not allowed")
    stores_col.delete_one({"_id": ObjectId(store_id)})
    return {"message": "Store deleted"}

# Reviews
@app.post("/api/stores/{store_id}/reviews")
def add_or_update_review(store_id: str, payload: ReviewCreate, current=Depends(require_roles("user", "owner", "admin"))):
    # Upsert review by unique (store_id, user_id)
    now = datetime.now(timezone.utc)
    doc = {
        "store_id": ObjectId(store_id),
        "user_id": ObjectId(current["id"]),
        "rating": payload.rating,
        "comment": payload.comment,
        "created_at": now,
        "updated_at": now
    }
    existing = reviews_col.find_one({"store_id": ObjectId(store_id), "user_id": ObjectId(current["id"])})
    if existing:
        reviews_col.update_one({"_id": existing["_id"]}, {"$set": {"rating": payload.rating, "comment": payload.comment, "updated_at": now}})
        review = reviews_col.find_one({"_id": existing["_id"]})
    else:
        res = reviews_col.insert_one(doc)
        review = reviews_col.find_one({"_id": res.inserted_id})
    review["id"] = objectid_str(review.pop("_id"))
    review["store_id"] = objectid_str(review["store_id"])
    review["user_id"] = objectid_str(review["user_id"])
    return review

@app.get("/api/stores/{store_id}/reviews")
def list_reviews(store_id: str, page: int = Query(default=1, ge=1), limit: int = Query(default=10, ge=1, le=50)):
    skip = (page - 1) * limit
    cur = reviews_col.find({"store_id": ObjectId(store_id)}).sort("created_at", DESCENDING).skip(skip).limit(limit)
    items = []
    for r in cur:
        r["id"] = objectid_str(r.pop("_id"))
        r["store_id"] = objectid_str(r["store_id"])
        r["user_id"] = objectid_str(r["user_id"])
        # attach basic user info
        u = users_col.find_one({"_id": ObjectId(r["user_id"])}, {"name": 1})
        r["user_name"] = u.get("name") if u else None
        items.append(r)
    total = reviews_col.count_documents({"store_id": ObjectId(store_id)})
    return {"items": items, "page": page, "limit": limit, "total": total}

@app.patch("/api/reviews/{review_id}")
def update_review(review_id: str, payload: ReviewUpdate, current=Depends(get_current_user)):
    review = reviews_col.find_one({"_id": ObjectId(review_id)})
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    is_author = objectid_str(review["user_id"]) == current["id"]
    if not is_author and current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")
    update = {k: v for k, v in payload.dict().items() if v is not None}
    update["updated_at"] = datetime.now(timezone.utc)
    reviews_col.update_one({"_id": ObjectId(review_id)}, {"$set": update})
    doc = reviews_col.find_one({"_id": ObjectId(review_id)})
    doc["id"] = objectid_str(doc.pop("_id"))
    doc["store_id"] = objectid_str(doc["store_id"])
    doc["user_id"] = objectid_str(doc["user_id"])
    return doc

@app.delete("/api/reviews/{review_id}")
def delete_review(review_id: str, current=Depends(get_current_user)):
    review = reviews_col.find_one({"_id": ObjectId(review_id)})
    if not review:
        raise HTTPException(status_code=404, detail="Review not found")
    is_author = objectid_str(review["user_id"]) == current["id"]
    if not is_author and current["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")
    reviews_col.delete_one({"_id": ObjectId(review_id)})
    return {"message": "Review deleted"}

# Seed helper endpoint (idempotent)
@app.post("/seed")
def seed():
    # Create users
    def upsert_user(name, email, password, role):
        u = users_col.find_one({"email": email})
        if u:
            return u
        users_col.insert_one({
            "name": name,
            "email": email,
            "password": get_password_hash(password),
            "role": role,
            "created_at": datetime.now(timezone.utc)
        })
        return users_col.find_one({"email": email})

    admin = upsert_user("Admin", "admin@demo.local", "Admin@123", "admin")
    owner = upsert_user("Owner", "owner@demo.local", "Owner@123", "owner")
    user = upsert_user("User", "user@demo.local", "User@123", "user")

    # Create stores for owner
    def upsert_store(name, description, address):
        st = stores_col.find_one({"name": name})
        if st:
            return st
        stores_col.insert_one({
            "owner_id": owner["_id"],
            "name": name,
            "description": description,
            "address": address,
            "tags": ["popular", "demo"],
            "image_url": None,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        })
        return stores_col.find_one({"name": name})

    s1 = upsert_store("Sunrise Cafe", "Cozy coffee and brunch.", "123 Main St")
    s2 = upsert_store("Tech Mart", "Gadgets and accessories.", "456 Market Ave")

    # Reviews (mix)
    def upsert_review(store, u, rating, comment):
        existing = reviews_col.find_one({"store_id": store["_id"], "user_id": u["_id"]})
        if existing:
            return existing
        reviews_col.insert_one({
            "store_id": store["_id"],
            "user_id": u["_id"],
            "rating": rating,
            "comment": comment,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        })
        return reviews_col.find_one({"store_id": store["_id"], "user_id": u["_id"]})

    upsert_review(s1, user, 5, "Fantastic coffee and friendly staff!")
    upsert_review(s1, owner, 4, "Nice ambiance.")
    upsert_review(s2, user, 3, "Good selection, average prices.")
    upsert_review(s2, admin, 4, "Helpful staff.")

    return {"message": "Seeded", "users": users_col.count_documents({}), "stores": stores_col.count_documents({}), "reviews": reviews_col.count_documents({})}

# Health/test
@app.get("/test")
def test_database():
    try:
        collections = db.list_collection_names()
        return {"backend": "running", "database": "connected", "collections": collections}
    except Exception as e:
        return {"backend": "running", "database": f"error: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
