# main.py
from fastapi import FastAPI, HTTPException, Depends, Header
import hashlib
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timedelta
import secrets
import hashlib
import os

from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# ---------- CONFIG ----------
DATABASE_URL = "sqlite:///./jit_access.db"
DEFAULT_TOKEN_BITS = 32
MAX_TOKEN_BITS = 128
# ----------------------------

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI(title="JIT Access Backend - Binary Token + Admin Dashboard")

# Mount static files (frontend)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/admin")
def serve_admin_dashboard():
    return FileResponse(os.path.join("static", "admin.html"))

# ---------- DB models ----------
class AccessTokenModel(Base):
    __tablename__ = "access_tokens"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    resource = Column(String, index=True)
    token_hash = Column(String, unique=True, index=True)
    bits = Column(Integer, default=DEFAULT_TOKEN_BITS)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, index=True)
    used = Column(Boolean, default=False)
    note = Column(String, nullable=True)

class AccessLog(Base):
    __tablename__ = "access_logs"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    resource = Column(String, index=True)
    access_time = Column(DateTime, default=datetime.utcnow)
    token_id = Column(Integer, ForeignKey("access_tokens.id"))
    token = relationship("AccessTokenModel")

Base.metadata.create_all(bind=engine)

# ---------- Pydantic schemas ----------
class RequestAccessIn(BaseModel):
    username: str = Field(..., example="sarvan")
    resource: str = Field(..., example="admin-dashboard")
    ttl_seconds: int = Field(..., example=30)
    token_bits: Optional[int] = Field(None, example=32)

class RequestAccessOut(BaseModel):
    token: str
    bits: int
    expires_at: datetime

class AccessResponse(BaseModel):
    status: str
    username: Optional[str]
    resource: Optional[str]
    message: Optional[str] = None

class SessionInfo(BaseModel):
    id: int
    username: str
    resource: str
    bits: int
    created_at: datetime
    expires_at: datetime
    used: bool
    note: Optional[str] = None

# ---------- Utils ----------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_token(token_str: str) -> str:
    return hashlib.sha256(token_str.encode("utf-8")).hexdigest()

def generate_binary_token(bits: int) -> str:
    if bits <= 0 or bits > MAX_TOKEN_BITS:
        raise ValueError(f"token bits must be between 1 and {MAX_TOKEN_BITS}")
    num = secrets.randbits(bits)
    return format(num, "b").zfill(bits)

# ---------- Endpoints ----------
@app.post("/request_access", response_model=RequestAccessOut)
def request_access(payload: RequestAccessIn, db: Session = Depends(get_db)):
    bits = payload.token_bits if payload.token_bits is not None else DEFAULT_TOKEN_BITS
    if bits <= 0 or bits > MAX_TOKEN_BITS:
        raise HTTPException(status_code=400, detail=f"token_bits must be between 1 and {MAX_TOKEN_BITS}")
    for _ in range(5):
        token_plain = generate_binary_token(bits)
        token_h = hash_token(token_plain)
        exists = db.query(AccessTokenModel).filter_by(token_hash=token_h).first()
        if not exists:
            break
    else:
        raise HTTPException(status_code=500, detail="Could not generate unique token. Try again.")

    now = datetime.utcnow()
    expires = now + timedelta(seconds=payload.ttl_seconds)

    record = AccessTokenModel(
        username=payload.username,
        resource=payload.resource,
        token_hash=token_h,
        bits=bits,
        created_at=now,
        expires_at=expires,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return RequestAccessOut(token=token_plain, bits=bits, expires_at=record.expires_at)

@app.get("/access/{token}", response_model=AccessResponse)
def access_with_token(token: str, db: Session = Depends(get_db)):
    if any(c not in "01" for c in token):
        raise HTTPException(status_code=400, detail="Token must be a binary string containing only 0 and 1.")
    if len(token) > MAX_TOKEN_BITS:
        raise HTTPException(status_code=400, detail=f"Token length too long (max {MAX_TOKEN_BITS} bits).")

    token_h = hash_token(token)
    record = db.query(AccessTokenModel).filter_by(token_hash=token_h).first()
    if not record:
        raise HTTPException(status_code=404, detail="Token not found or invalid.")

    now = datetime.utcnow()
    if record.used:
        return AccessResponse(status="ACCESS DENIED", username=None, resource=None, message="Token already used.")
    if now > record.expires_at:
        return AccessResponse(status="ACCESS DENIED", username=None, resource=None, message="Token expired.")

    # mark token as used
    record.used = True
    db.commit()

    # log successful access
    log = AccessLog(
        username=record.username,
        resource=record.resource,
        token_id=record.id
    )
    db.add(log)
    db.commit()

    return AccessResponse(status="ACCESS GRANTED", username=record.username, resource=record.resource)

# Admin endpoints
@app.get("/admin/sessions", response_model=List[SessionInfo])
def list_sessions(active_only: Optional[bool] = True, db: Session = Depends(get_db)):
    q = db.query(AccessTokenModel)
    if active_only:
        now = datetime.utcnow()
        q = q.filter(AccessTokenModel.used == False, AccessTokenModel.expires_at > now)
    rows = q.all()
    return [SessionInfo(
                id=r.id,
                username=r.username,
                resource=r.resource,
                bits=r.bits,
                created_at=r.created_at,
                expires_at=r.expires_at,
                used=r.used,
                note=r.note
            ) for r in rows]

@app.post("/admin/revoke/{token_id}")
def revoke_token(token_id: int, db: Session = Depends(get_db)):
    rec = db.query(AccessTokenModel).filter_by(id=token_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Token id not found.")
    if rec.used:
        return {"status": "already_revoked_or_used", "id": rec.id}
    rec.used = True
    rec.note = "revoked by admin"
    db.commit()
    return {"status": "revoked", "id": rec.id}

@app.get("/admin/logs")
def get_access_logs(db: Session = Depends(get_db)):
    logs = db.query(AccessLog).order_by(AccessLog.access_time.desc()).all()
    return [
        {
            "id": log.id,
            "username": log.username,
            "resource": log.resource,
            "access_time": log.access_time.isoformat()
        }
        for log in logs
    ]

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
