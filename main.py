# app.py
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional, List
import uuid, jwt, hashlib

SECRET = "change-me"
ALGO = "HS256"

app = FastAPI()
security = HTTPBearer(auto_error=False)
users = {}
ads = {}

def hash_pw(p: str) -> str:
    return hashlib.sha256(p.encode()).hexdigest()


class LoginRequest(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    password: str
    group: str = "user"

class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    group: Optional[str] = None

class UserOut(BaseModel):
    id: str
    username: str
    group: str

class AdCreate(BaseModel):
    title: str
    description: str
    price: float
    author: str

class AdUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    author: Optional[str] = None

class Ad(BaseModel):
    id: str
    title: str
    description: str
    price: float
    author: str
    created_at: datetime
    owner_id: str


def get_current_user(cred: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if cred is None:
        return None
    try:
        payload = jwt.decode(cred.credentials, SECRET, algorithms=[ALGO])
    except jwt.PyJWTError:
        return None
    return users.get(payload.get("sub"))

def require_user(user=Depends(get_current_user)):
    if not user:
        raise HTTPException(401, "unauthorized")
    return user


@app.post("/login")
def login(data: LoginRequest):
    for u in users.values():
        if u["username"] == data.username and u["password"] == hash_pw(data.password):
            token = jwt.encode(
                {"sub": u["id"], "exp": datetime.utcnow() + timedelta(hours=48)},
                SECRET, algorithm=ALGO,
            )
            return {"token": token}
    raise HTTPException(401, "invalid credentials")


@app.post("/user", response_model=UserOut, status_code=201)
def create_user(data: UserCreate):
    if data.group not in ("user", "admin"):
        raise HTTPException(400, "invalid group")
    uid = str(uuid.uuid4())
    users[uid] = {"id": uid, "username": data.username,
                  "password": hash_pw(data.password), "group": data.group}
    return UserOut(id=uid, username=data.username, group=data.group)


@app.get("/user/{user_id}", response_model=UserOut)
def get_user(user_id: str):
    u = users.get(user_id)
    if not u:
        raise HTTPException(404, "not found")
    return UserOut(id=u["id"], username=u["username"], group=u["group"])


@app.patch("/user/{user_id}", response_model=UserOut)
def update_user(user_id: str, data: UserUpdate, current=Depends(require_user)):
    target = users.get(user_id)
    if not target:
        raise HTTPException(404, "not found")
    if current["group"] != "admin" and current["id"] != user_id:
        raise HTTPException(403, "forbidden")
    if data.username is not None:
        target["username"] = data.username
    if data.password is not None:
        target["password"] = hash_pw(data.password)
    if data.group is not None:
        if current["group"] != "admin":
            raise HTTPException(403, "forbidden")
        if data.group not in ("user", "admin"):
            raise HTTPException(400, "invalid group")
        target["group"] = data.group
    return UserOut(id=target["id"], username=target["username"], group=target["group"])


@app.delete("/user/{user_id}")
def delete_user(user_id: str, current=Depends(require_user)):
    if user_id not in users:
        raise HTTPException(404, "not found")
    if current["group"] != "admin" and current["id"] != user_id:
        raise HTTPException(403, "forbidden")
    del users[user_id]
    return {"status": "deleted"}


@app.post("/advertisement", response_model=Ad, status_code=201)
def create_ad(data: AdCreate, current=Depends(require_user)):
    ad_id = str(uuid.uuid4())
    ad = {"id": ad_id, "created_at": datetime.utcnow(),
          "owner_id": current["id"], **data.model_dump()}
    ads[ad_id] = ad
    return ad


@app.get("/advertisement/{advertisement_id}", response_model=Ad)
def get_ad(advertisement_id: str):
    ad = ads.get(advertisement_id)
    if not ad:
        raise HTTPException(404, "not found")
    return ad


@app.patch("/advertisement/{advertisement_id}", response_model=Ad)
def update_ad(advertisement_id: str, data: AdUpdate, current=Depends(require_user)):
    ad = ads.get(advertisement_id)
    if not ad:
        raise HTTPException(404, "not found")
    if current["group"] != "admin" and current["id"] != ad["owner_id"]:
        raise HTTPException(403, "forbidden")
    for k, v in data.model_dump().items():
        if v is not None:
            ad[k] = v
    return ad


@app.delete("/advertisement/{advertisement_id}")
def delete_ad(advertisement_id: str, current=Depends(require_user)):
    ad = ads.get(advertisement_id)
    if not ad:
        raise HTTPException(404, "not found")
    if current["group"] != "admin" and current["id"] != ad["owner_id"]:
        raise HTTPException(403, "forbidden")
    del ads[advertisement_id]
    return {"status": "deleted"}


@app.get("/advertisement", response_model=List[Ad])
def search_ads(
    title: Optional[str] = None,
    description: Optional[str] = None,
    price: Optional[float] = None,
    author: Optional[str] = None,
):
    result = list(ads.values())
    if title is not None:
        result = [a for a in result if title.lower() in a["title"].lower()]
    if description is not None:
        result = [a for a in result if description.lower() in a["description"].lower()]
    if price is not None:
        result = [a for a in result if a["price"] == price]
    if author is not None:
        result = [a for a in result if author.lower() in a["author"].lower()]
    return result