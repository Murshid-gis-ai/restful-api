from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt
from dotenv import load_dotenv
import os
from supabase import create_client
from passlib.context import CryptContext
from pathlib import Path
import logging

# إعداد اللوق
logging.basicConfig(
    filename="log.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)
app = FastAPI()

# إعداد مفاتيح الـ JWT
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

# ✅ قراءة API KEY من .env
API_KEY = os.getenv("API_KEY")
print("API_KEY from .env >>>", API_KEY)


# ✅ دالة التحقق من الـ API Key
def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")

# إعداد Supabase
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# إعداد التشفير
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    email: str
    password: str
    role: str = "user"

class Site(BaseModel):
    id: str
    name: str
    description: str
    image_url: str
    latitude: float
    longitude: float
    city_id: str


# إصدار JWT Token مع role
def create_access_token(data: dict, expires_delta: timedelta = timedelta(hours=1)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token

# التحقق من التوكن
def verify_token(token: str = Header(...)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=403, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=403, detail="Invalid token")

# ✅ Route تسجيل مستخدم جديد (Signup) مع طباعة النتيجة أو الخطأ
@app.post("/signup", summary="User Signup", description="Register a new user and generate an email verification link.")
def signup(user: UserRegister):
    try:
        hashed_password = pwd_context.hash(user.password)
        result = supabase.table("users").insert({
            "email": user.email,
            "password_hash": hashed_password,
            "role": user.role
        }).execute()
        print(f"✅ User {user.email} signed up successfully!")


        # ✅ هنا تضيفين توليد رابط التوثيق
       # ✅ توليد توكن التوثيق وإظهار الرابط
        verification_token = create_access_token({"email": user.email}, expires_delta=timedelta(hours=24))
        print("Verification Link: https://murshidgis.duckdns.org/verify_email?token=" + verification_token)


        return {"message": "User created successfully!"}
    except Exception as e:
        print("Signup Error:", e)
        raise HTTPException(status_code=500, detail=str(e))


# ✅ Route تسجيل الدخول
@app.post("/login", summary="User Login", description="This endpoint allows users to log in and get a JWT token")

def login(user: UserLogin):
    try:
        response = supabase.table("users").select("*").eq("email", user.email).single().execute()
        user_data = response.data

        if not user_data:
            raise HTTPException(status_code=401, detail="User not found")
        
        # ✅ تحقق من التوثيق
        if not user_data.get("is_verified"):
            raise HTTPException(status_code=403, detail="Please verify your email first.")
        
        if not pwd_context.verify(user.password, user_data["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid password")

        token_data = {"sub": user.email, "role": user_data["role"]}
        token = create_access_token(token_data)
        print(f"✅ User {user.email} logged in successfully!")
        return {"access_token": token}

    except Exception as e:
        print("Login Error:", e)
        raise HTTPException(status_code=401, detail="Login Failed")

# ✅ Route محمي ويشيك جديد على الـ role
@app.post("/add_location", summary="Add Location (Admin)", description="Allows admin users to add new locations. Requires JWT token with admin role.")


def add_location(site: Site, payload: dict = Depends(verify_token)):
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    try:
        data = site.dict()
        response = supabase.table("sites").insert(data).execute()

        # اطبعي النتيجة للتجربة
        print("Supabase Insert Response:", response)

        return {"message": "Location added successfully!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




# ✅ Route سحب بيانات من أي جدول مع حماية API KEY
@app.get("/get_data/{table_name}", summary="Get Data From Table", description="Fetches data from the specified Supabase table. Requires JWT token and API Key for protection.")
def get_data(
    table_name: str, 
    payload: dict = Depends(verify_token), 
    api_key: str = Depends(verify_api_key)  # ✅ حماية api key
):
    try:
        response = supabase.table(table_name).select("*").execute()
        return {"data": response.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
# ✅ Model لاستقبال بيانات إعادة تعيين الباسورد
class ResetPassword(BaseModel):
    email: str
    new_password: str

# ✅ Route استرجاع كلمة المرور
@app.post("/reset_password", summary="Reset User Password", description="Allows users to reset their password by providing a registered email and new password.")

def reset_password(data: ResetPassword):
    try:
        # نبحث عن المستخدم بالإيميل
        response = supabase.table("users").select("*").eq("email", data.email).single().execute()
        user_data = response.data

        if not user_data:
            raise HTTPException(status_code=404, detail="User not found")

        # نحدث كلمة المرور المشفرة
        new_hashed_password = pwd_context.hash(data.new_password)
        update_response = supabase.table("users").update({
            "password_hash": new_hashed_password
        }).eq("email", data.email).execute()

        print("Password Reset Response:", update_response)
        return {"message": "Password reset successfully!"}

    except Exception as e:
        print("Reset Password Error:", e)
        raise HTTPException(status_code=500, detail="Something went wrong")
    
    # ✅ Route التحقق من الإيميل
@app.get("/verify_email", summary="Verify User Email", description="Verifies the user's email using the provided JWT token from the verification link.")

def verify_email(token: str):
    try:
        # نفك التوكن ونتأكد منه
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Invalid token")

        # هنا لو عندك حقل is_verified بجدول users تفعّلينه
        update_response = supabase.table("users").update({"is_verified": True}).eq("email", email).execute()
        print("Verification Update:", update_response)
        
        

        print(f"✅ Email verified for: {email}")
        return {"message": "Email verified successfully!"}

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Verification link expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid verification token")


