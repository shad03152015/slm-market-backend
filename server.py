from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import List, Optional
from datetime import datetime, timezone, timedelta
from passlib.context import CryptContext
import jwt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'your-secret-key-change-in-production')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

security = HTTPBearer()

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# Models
class UserRegister(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    email: str

class PerformanceMetrics(BaseModel):
    speed_ms: float
    size_mb: float
    accuracy_percent: float

class SLMCreate(BaseModel):
    name: str
    author: str
    company: str
    date_released: str
    website_url: str
    description: str
    performance_metrics: PerformanceMetrics

class SLMResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    name: str
    author: str
    company: str
    date_released: str
    website_url: str
    description: str
    performance_metrics: PerformanceMetrics
    star_count: int
    created_at: str
    created_by: str

# Auth Helpers
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return email
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Auth Routes
@api_router.post("/auth/register", response_model=Token)
async def register(user: UserRegister):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user.email}, {"_id": 0})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    hashed_password = get_password_hash(user.password)
    user_doc = {
        "email": user.email,
        "hashed_password": hashed_password,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.users.insert_one(user_doc)
    
    # Create token
    access_token = create_access_token(data={"sub": user.email})
    return Token(access_token=access_token, token_type="bearer", email=user.email)

@api_router.post("/auth/login", response_model=Token)
async def login(user: UserLogin):
    # Find user
    db_user = await db.users.find_one({"email": user.email}, {"_id": 0})
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Verify password
    if not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Create token
    access_token = create_access_token(data={"sub": user.email})
    return Token(access_token=access_token, token_type="bearer", email=user.email)

# SLM Routes
@api_router.post("/slms", response_model=SLMResponse, status_code=status.HTTP_201_CREATED)
async def create_slm(slm: SLMCreate, current_user: str = Depends(get_current_user)):
    import uuid
    
    slm_doc = slm.model_dump()
    slm_doc["id"] = str(uuid.uuid4())
    slm_doc["star_count"] = 0
    slm_doc["created_at"] = datetime.now(timezone.utc).isoformat()
    slm_doc["created_by"] = current_user
    
    await db.slms.insert_one(slm_doc)
    return SLMResponse(**slm_doc)

@api_router.get("/slms", response_model=List[SLMResponse])
async def get_slms(
    search: Optional[str] = None,
    company: Optional[str] = None,
    sort_by: str = "stars",  # stars, date, name
    limit: int = 100
):
    # Build query
    query = {}
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"author": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}}
        ]
    if company:
        query["company"] = {"$regex": company, "$options": "i"}
    
    # Build sort
    sort_field = "star_count" if sort_by == "stars" else "date_released" if sort_by == "date" else "name"
    sort_direction = -1 if sort_by in ["stars", "date"] else 1
    
    slms = await db.slms.find(query, {"_id": 0}).sort(sort_field, sort_direction).limit(limit).to_list(limit)
    return [SLMResponse(**slm) for slm in slms]

@api_router.get("/slms/{slm_id}", response_model=SLMResponse)
async def get_slm(slm_id: str):
    slm = await db.slms.find_one({"id": slm_id}, {"_id": 0})
    if not slm:
        raise HTTPException(status_code=404, detail="SLM not found")
    return SLMResponse(**slm)

@api_router.get("/slms/compare/multiple", response_model=List[SLMResponse])
async def compare_slms(ids: str):  # comma-separated IDs
    slm_ids = [id.strip() for id in ids.split(",")]
    slms = await db.slms.find({"id": {"$in": slm_ids}}, {"_id": 0}).to_list(len(slm_ids))
    return [SLMResponse(**slm) for slm in slms]

# Include the router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()