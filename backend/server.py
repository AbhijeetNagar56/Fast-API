import base64
import hashlib
import hmac
import json
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta
from io import BytesIO
from typing import Annotated, Optional

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Response,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm import Session, selectinload

from db import Appointment, Base, DB_SCHEMA, Doctor, Report, Slot, User, engine, get_db

JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
PORT = int(os.getenv("PORT", "3000"))
NODE_ENV = os.getenv("NODE_ENV", "development")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

TOKEN_COOKIE_NAME = "token"
TOKEN_EXPIRY = timedelta(days=2)
COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000
MAX_UPLOAD_SIZE_BYTES = 5 * 1024 * 1024
MAX_DOCTORS = 3
ALLOWED_GENDERS = {"Male", "Female", "Other"}
REPORT_CATEGORIES = {"lab", "prescription", "scan", "discharge", "other"}
REPORT_VISIBILITY = {"private", "doctor", "public"}
ALLOWED_MIME_TYPES = {
    "application/pdf",
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/bmp",
}
@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        with engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{DB_SCHEMA}"'))
            connection.execute(text(f'SET search_path TO "{DB_SCHEMA}"'))
            Base.metadata.create_all(bind=connection)
    except ProgrammingError as error:
        message = str(getattr(error, "orig", error))
        if "permission denied" in message.lower():
            raise RuntimeError(
                f"Database user cannot create objects in schema '{DB_SCHEMA}'. "
                f"Grant CREATE/USAGE on that schema or set DB_SCHEMA to a writable schema."
            ) from error
        raise
    yield


app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL if NODE_ENV == "production" else "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    )
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored_value: str) -> bool:
    try:
        salt, stored_hash = stored_value.split("$", 1)
    except ValueError:
        return False

    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    ).hex()
    return hmac.compare_digest(digest, stored_hash)


def create_access_token(user_id: int, role: str) -> str:
    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": int((datetime.utcnow() + TOKEN_EXPIRY).timestamp()),
    }
    return encode_jwt(payload, JWT_SECRET)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def encode_jwt(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_segment = b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_segment = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_segment}.{payload_segment}".encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_segment}.{payload_segment}.{b64url_encode(signature)}"


def set_auth_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=TOKEN_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=NODE_ENV == "production",
        samesite="strict" if NODE_ENV == "production" else "lax",
        max_age=COOKIE_MAX_AGE_MS // 1000,
    )


def parse_age(value: Optional[int | str]) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        age_value = int(value)
    except (TypeError, ValueError):
        return None
    if age_value < 1 or age_value > 120:
        return None
    return age_value


def normalize_date_only(value: str) -> Optional[date]:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%m/%d/%Y"):
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    return None


def get_start_time(slot_time: str) -> str:
    if not slot_time:
        return "09:00"
    start = slot_time.split("-")[0].strip()
    return start or "09:00"


def doctor_summary(doctor: Doctor) -> dict:
    return {
        "id": doctor.id,
        "_id": doctor.id,
        "doctorId": doctor.doctor_id,
        "name": doctor.name,
        "specialization": doctor.specialization,
        "hospital": doctor.hospital,
        "experience": doctor.experience,
        "contact": doctor.contact,
        "email": doctor.email,
        "age": doctor.age,
        "createdAt": doctor.created_at.isoformat() if doctor.created_at else None,
        "updatedAt": doctor.updated_at.isoformat() if doctor.updated_at else None,
    }


def user_profile_payload(user: User) -> dict:
    return {
        "id": user.id,
        "_id": user.id,
        "name": user.name,
        "email": user.email,
        "gender": user.gender,
        "age": user.age,
        "phoneNumber": user.phone_number,
        "registeredDoctors": [doctor_summary(doctor) for doctor in user.registered_doctors],
        "createdAt": user.created_at.isoformat() if user.created_at else None,
        "updatedAt": user.updated_at.isoformat() if user.updated_at else None,
    }


def appointment_for_patient_payload(appointment: Appointment) -> dict:
    return {
        "id": appointment.id,
        "_id": appointment.id,
        "doctorId": appointment.doctor_id,
        "patientId": appointment.patient_id,
        "slotId": appointment.slot_id,
        "requestGroupId": appointment.request_group_id,
        "slotTime": appointment.slot_time,
        "doctorName": appointment.doctor_name,
        "speciality": appointment.speciality,
        "hospitalName": appointment.hospital_name,
        "appointmentDate": appointment.appointment_date.isoformat(),
        "reasonOfAppointment": appointment.reason_of_appointment,
        "status": appointment.status,
        "date": appointment.appointment_date.isoformat(),
        "startTime": get_start_time(appointment.slot_time),
        "reason": appointment.reason_of_appointment,
        "doctor": {
            "name": appointment.doctor_name,
            "specialization": appointment.speciality,
            "hospital": appointment.hospital_name,
        },
        "createdAt": appointment.created_at.isoformat() if appointment.created_at else None,
        "updatedAt": appointment.updated_at.isoformat() if appointment.updated_at else None,
    }


def appointment_for_doctor_payload(appointment: Appointment) -> dict:
    patient = appointment.patient
    patient_payload = None
    if patient:
        patient_payload = {
            "id": patient.id,
            "_id": patient.id,
            "name": patient.name,
            "age": patient.age,
            "gender": patient.gender,
            "phoneNumber": patient.phone_number,
        }

    return {
        "id": appointment.id,
        "_id": appointment.id,
        "patientId": appointment.patient_id,
        "doctorId": appointment.doctor_id,
        "slotId": appointment.slot_id,
        "requestGroupId": appointment.request_group_id,
        "slotTime": appointment.slot_time,
        "doctorName": appointment.doctor_name,
        "speciality": appointment.speciality,
        "hospitalName": appointment.hospital_name,
        "appointmentDate": appointment.appointment_date.isoformat(),
        "reasonOfAppointment": appointment.reason_of_appointment,
        "status": appointment.status,
        "patient": patient_payload,
        "date": appointment.appointment_date.isoformat(),
        "startTime": get_start_time(appointment.slot_time),
        "reason": appointment.reason_of_appointment,
        "createdAt": appointment.created_at.isoformat() if appointment.created_at else None,
        "updatedAt": appointment.updated_at.isoformat() if appointment.updated_at else None,
    }


def slot_payload(slot: Slot) -> dict:
    return {
        "id": slot.id,
        "_id": slot.id,
        "doctorId": slot.doctor_id,
        "date": slot.date,
        "time": slot.time,
        "status": slot.status,
    }


def report_payload(report: Report) -> dict:
    return {
        "id": report.id,
        "_id": report.id,
        "reportId": report.report_id,
        "patientId": report.patient_id,
        "uploadedBy": report.uploaded_by,
        "doctorId": report.doctor_id,
        "title": report.title,
        "category": report.category,
        "fileSize": report.file_size,
        "fileId": report.file_id,
        "visibility": report.visibility,
        "originalFileName": report.original_file_name,
        "mimeType": report.mime_type,
        "createdAt": report.created_at.isoformat() if report.created_at else None,
        "updatedAt": report.updated_at.isoformat() if report.updated_at else None,
    }


def decode_token(token: str) -> dict:
    try:
        header_segment, payload_segment, signature_segment = token.split(".")
        signing_input = f"{header_segment}.{payload_segment}".encode("utf-8")
        expected_signature = hmac.new(
            JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256
        ).digest()
        actual_signature = b64url_decode(signature_segment)
        if not hmac.compare_digest(expected_signature, actual_signature):
            raise ValueError("Signature mismatch")

        payload = json.loads(b64url_decode(payload_segment).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(datetime.utcnow().timestamp()):
            raise ValueError("Token expired")
        return payload
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise HTTPException(status_code=401, detail={"msg": "Token is not valid"}) from error


def require_auth(role: Optional[str] = None):
    def dependency(token: Annotated[Optional[str], Cookie(alias=TOKEN_COOKIE_NAME)] = None) -> dict:
        if not token:
            raise HTTPException(status_code=401, detail={"msg": "No token, authorization denied"})

        payload = decode_token(token)
        if role and payload.get("role") != role:
            raise HTTPException(status_code=403, detail={"msg": "Forbidden"})
        return payload

    return dependency


def get_current_user(
    auth: Annotated[dict, Depends(require_auth("user"))],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    user = db.get(
        User,
        int(auth["sub"]),
        options=[selectinload(User.registered_doctors)],
    )
    if not user:
        raise HTTPException(status_code=404, detail={"msg": "User not found"})
    return user


def get_current_doctor(
    auth: Annotated[dict, Depends(require_auth("doctor"))],
    db: Annotated[Session, Depends(get_db)],
) -> Doctor:
    doctor = db.get(Doctor, int(auth["sub"]))
    if not doctor:
        raise HTTPException(status_code=404, detail={"msg": "Doctor not found"})
    return doctor


class UserSignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class DoctorSignupRequest(BaseModel):
    doctorId: str
    password: str


class DoctorLoginRequest(BaseModel):
    doctorId: str
    password: str


class UserDetailsRequest(BaseModel):
    gender: str
    age: int | str
    phoneNumber: str


class UserUpdateRequest(BaseModel):
    gender: str
    age: int | str
    name: str
    phoneNumber: Optional[str] = None


class DoctorDetailsRequest(BaseModel):
    name: str
    hospital: str
    age: int | str


class DoctorUpdateRequest(BaseModel):
    doctorId: str
    name: str
    age: int | str
    hospital: str
    specialization: Optional[str] = None
    experience: Optional[str] = None
    contact: Optional[str] = None
    email: Optional[str] = None


class DoctorSwapRequest(BaseModel):
    removeId: int
    addId: int


class AddDoctorRequest(BaseModel):
    doctorId: int


class AppointmentCreateRequest(BaseModel):
    doctorId: int
    appointmentDate: str
    reasonOfAppointment: str


class AppointmentStatusRequest(BaseModel):
    status: str


class SlotCreateRequest(BaseModel):
    doctorId: int
    date: str
    times: list[str]


class SlotBookPatientRequest(BaseModel):
    notes: Optional[str] = None


class SlotBookRequest(BaseModel):
    slotId: Optional[int] = None
    slotIds: Optional[list[int]] = None
    patient: Optional[SlotBookPatientRequest] = None


class ChatRequest(BaseModel):
    message: str


@app.exception_handler(HTTPException)
async def http_exception_handler(_request, exc: HTTPException):
    detail = exc.detail
    if isinstance(detail, dict):
        return JSONResponse(status_code=exc.status_code, content=detail)
    return JSONResponse(status_code=exc.status_code, content={"message": detail, "msg": detail})


@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "service": "MediRaksha Backend",
        "environment": NODE_ENV,
    }


@app.post("/api/auth")
async def create_user(payload: UserSignupRequest, response: Response, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(func.lower(User.email) == payload.email.lower()).first()
    if existing_user:
        raise HTTPException(status_code=400, detail={"msg": "User already exists"})

    new_user = User(
        name=payload.name.strip(),
        email=payload.email.lower(),
        password=hash_password(payload.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    set_auth_cookie(response, create_access_token(new_user.id, "user"))
    return {"msg": "User created successfully"}


@app.post("/api/auth/login")
async def login_user(payload: UserLoginRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(func.lower(User.email) == payload.email.lower()).first()
    if not user:
        raise HTTPException(status_code=404, detail={"message": "user not found"})
    if not verify_password(payload.password, user.password):
        raise HTTPException(status_code=400, detail={"msg": "password not correct"})

    token = create_access_token(user.id, "user")
    set_auth_cookie(response, token)
    return {"msg": token}


@app.post("/api/auth/logout")
async def logout(response: Response):
    response.delete_cookie(TOKEN_COOKIE_NAME)
    return {"msg": "Logged out"}


@app.post("/api/auth/doctor")
async def create_doctor(payload: DoctorSignupRequest, response: Response, db: Session = Depends(get_db)):
    existing_doctor = (
        db.query(Doctor)
        .filter(func.lower(Doctor.doctor_id) == payload.doctorId.strip().lower())
        .first()
    )
    if existing_doctor:
        raise HTTPException(status_code=400, detail={"msg": "User already exists"})

    new_doctor = Doctor(
        doctor_id=payload.doctorId.strip(),
        password=hash_password(payload.password),
    )
    db.add(new_doctor)
    db.commit()
    db.refresh(new_doctor)

    set_auth_cookie(response, create_access_token(new_doctor.id, "doctor"))
    return {"msg": "User created successfully"}


@app.post("/api/auth/doctor/login")
async def login_doctor(payload: DoctorLoginRequest, response: Response, db: Session = Depends(get_db)):
    doctor = (
        db.query(Doctor)
        .filter(func.lower(Doctor.doctor_id) == payload.doctorId.strip().lower())
        .first()
    )
    if not doctor:
        raise HTTPException(status_code=404, detail={"message": "user not found"})
    if not verify_password(payload.password, doctor.password):
        raise HTTPException(status_code=400, detail={"msg": "password not correct"})

    set_auth_cookie(response, create_access_token(doctor.id, "doctor"))
    return {"msg": "Login successful"}


@app.post("/api/auth/chat")
async def chat_with_ai(payload: ChatRequest):
    message = payload.message.strip()
    if not message:
        raise HTTPException(status_code=400, detail={"error": "Message is required"})
    if not GROQ_API_KEY:
        raise HTTPException(status_code=500, detail={"error": "AI service failed"})

    try:
        from openai import OpenAI

        client = OpenAI(api_key=GROQ_API_KEY, base_url="https://api.groq.com/openai/v1")
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a healthcare assistant. DO NOT diagnose diseases. "
                        "Provide general health tips, precautions, and lifestyle advice. "
                        "Clearly say when the user should consult a doctor. "
                        "Always add a medical disclaimer at the end. Within 2 or 3 lines."
                    ),
                },
                {"role": "user", "content": message},
            ],
            temperature=0.6,
            max_tokens=500,
        )
    except Exception as error:
        raise HTTPException(status_code=500, detail={"error": "AI service failed"}) from error

    return {"reply": response.choices[0].message.content}


@app.get("/api/home")
async def get_home_profile(current_user: User = Depends(get_current_user)):
    return user_profile_payload(current_user)


@app.patch("/api/home/details")
async def update_home_details(
    payload: UserDetailsRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    parsed_age = parse_age(payload.age)
    phone_number = payload.phoneNumber.strip()

    if payload.gender not in ALLOWED_GENDERS or parsed_age is None or len(phone_number) != 10 or not phone_number.isdigit():
        raise HTTPException(
            status_code=400,
            detail={
                "msg": "Provide valid gender (Male/Female/Other), age (1-120) and a 10-digit phone number"
            },
        )

    current_user.gender = payload.gender
    current_user.age = parsed_age
    current_user.phone_number = phone_number
    db.commit()
    db.refresh(current_user)
    return {"msg": "User details updated successfully", "user": user_profile_payload(current_user)}


@app.patch("/api/home/update")
async def update_home_profile(
    payload: UserUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    parsed_age = parse_age(payload.age)
    if payload.gender not in ALLOWED_GENDERS or parsed_age is None:
        raise HTTPException(
            status_code=400,
            detail={"msg": "Provide valid gender (Male/Female/Other) and age (1-120)"},
        )

    if not payload.name.strip():
        raise HTTPException(status_code=400, detail={"msg": "Name is required"})

    if payload.phoneNumber is not None:
        phone_number = payload.phoneNumber.strip()
        if len(phone_number) != 10 or not phone_number.isdigit():
            raise HTTPException(
                status_code=400,
                detail={"msg": "Phone number must be exactly 10 digits"},
            )
        current_user.phone_number = phone_number

    current_user.name = payload.name.strip()
    current_user.gender = payload.gender
    current_user.age = parsed_age
    db.commit()
    db.refresh(current_user)
    return {"msg": "User details updated successfully", "user": user_profile_payload(current_user)}


@app.post("/api/home/upload")
async def upload_file(
    title: Annotated[str, Form(...)],
    category: Annotated[str, Form(...)],
    visibility: Annotated[str, Form()] = "private",
    doctorId: Annotated[Optional[int], Form()] = None,
    uploadedBy: Annotated[str, Form()] = "patient",
    report: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not title.strip():
        raise HTTPException(status_code=400, detail={"msg": "Report title is required"})
    if category not in REPORT_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail={"msg": f"Category must be one of: {', '.join(sorted(REPORT_CATEGORIES))}"},
        )
    if visibility not in REPORT_VISIBILITY:
        raise HTTPException(
            status_code=400,
            detail={"msg": f"Visibility must be one of: {', '.join(sorted(REPORT_VISIBILITY))}"},
        )
    if report.content_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(status_code=400, detail={"msg": "Only PDF and image files are allowed"})

    content = await report.read()
    if not content:
        raise HTTPException(status_code=400, detail={"msg": "No file received"})
    if len(content) > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(status_code=400, detail={"msg": "File size must be 5MB or less"})

    new_report = Report(
        report_id=f"RPT-{int(datetime.utcnow().timestamp() * 1000)}-{secrets.randbelow(100000):05d}",
        patient_id=current_user.id,
        uploaded_by=uploadedBy.strip() or "patient",
        doctor_id=doctorId,
        title=title.strip(),
        category=category,
        file_size=len(content),
        file_id=str(uuid.uuid4()),
        visibility=visibility,
        original_file_name=report.filename or title.strip(),
        mime_type=report.content_type or "application/octet-stream",
        file_content=content,
    )
    db.add(new_report)
    db.commit()
    db.refresh(new_report)

    return {"msg": "File uploaded successfully", "report": report_payload(new_report)}


@app.get("/api/home/files")
async def get_all_files(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    reports = (
        db.query(Report)
        .filter(Report.patient_id == current_user.id)
        .order_by(Report.created_at.desc())
        .all()
    )
    return [report_payload(report) for report in reports]


@app.get("/api/home/file/{report_id}")
async def get_file_by_id(report_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    report = (
        db.query(Report)
        .filter(Report.id == report_id, Report.patient_id == current_user.id)
        .first()
    )
    if not report:
        raise HTTPException(status_code=404, detail={"msg": "File not found"})

    headers = {
        "Content-Disposition": f'inline; filename="{report.original_file_name or report.title}"'
    }
    return StreamingResponse(
        BytesIO(report.file_content),
        media_type=report.mime_type or "application/octet-stream",
        headers=headers,
    )


@app.delete("/api/home/file/{report_id}")
async def delete_file(report_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    report = (
        db.query(Report)
        .filter(Report.id == report_id, Report.patient_id == current_user.id)
        .first()
    )
    if not report:
        raise HTTPException(status_code=404, detail={"msg": "File not found"})

    db.delete(report)
    db.commit()
    return {"msg": "File deleted successfully"}


@app.get("/api/home/appointments/doctors")
@app.get("/api/home/doctors")
async def search_doctors(
    name: Optional[str] = None,
    specialization: Optional[str] = None,
    _current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(Doctor)
    if name:
        query = query.filter(Doctor.name.ilike(f"%{name.strip()}%"))
    if specialization:
        query = query.filter(Doctor.specialization.ilike(f"%{specialization.strip()}%"))

    doctors = query.order_by(Doctor.name.asc().nullslast()).all()
    return [doctor_summary(doctor) for doctor in doctors]


@app.get("/api/home/my-doctors")
async def get_my_doctors(current_user: User = Depends(get_current_user)):
    return [doctor_summary(doctor) for doctor in current_user.registered_doctors]


@app.post("/api/home/my-doctors")
async def add_my_doctor(
    payload: AddDoctorRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doctor = db.get(Doctor, payload.doctorId)
    if not doctor:
        raise HTTPException(status_code=404, detail={"msg": "Doctor not found"})

    existing_ids = {item.id for item in current_user.registered_doctors}
    if doctor.id in existing_ids:
        raise HTTPException(status_code=409, detail={"msg": "Doctor already registered"})
    if len(existing_ids) >= MAX_DOCTORS:
        raise HTTPException(
            status_code=400,
            detail={
                "msg": f"You can only register up to {MAX_DOCTORS} doctors. Remove one first.",
                "limitReached": True,
            },
        )

    current_user.registered_doctors.append(doctor)
    db.commit()
    db.refresh(current_user)
    return {
        "msg": "Doctor registered successfully",
        "doctors": [doctor_summary(item) for item in current_user.registered_doctors],
    }


@app.delete("/api/home/my-doctors/{doctor_id}")
async def remove_my_doctor(
    doctor_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    matching_doctor = next((item for item in current_user.registered_doctors if item.id == doctor_id), None)
    if matching_doctor:
        current_user.registered_doctors.remove(matching_doctor)
        db.commit()
    return {"msg": "Doctor removed successfully"}


@app.patch("/api/home/my-doctors/swap")
async def swap_my_doctor(
    payload: DoctorSwapRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doctor_to_add = db.get(Doctor, payload.addId)
    if not doctor_to_add:
        raise HTTPException(status_code=404, detail={"msg": "Doctor not found"})

    retained_doctors = [doctor for doctor in current_user.registered_doctors if doctor.id != payload.removeId]
    if doctor_to_add.id not in {doctor.id for doctor in retained_doctors}:
        retained_doctors.append(doctor_to_add)
    current_user.registered_doctors = retained_doctors[:MAX_DOCTORS]
    db.commit()
    db.refresh(current_user)

    return {
        "msg": "Doctor swapped successfully",
        "doctors": [doctor_summary(doctor) for doctor in current_user.registered_doctors],
    }


@app.post("/api/home/appointments")
async def book_appointment(
    payload: AppointmentCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    reason = payload.reasonOfAppointment.strip()
    if not reason:
        raise HTTPException(
            status_code=400,
            detail={"msg": "doctorId, appointmentDate and reasonOfAppointment are required"},
        )

    appointment_date = normalize_date_only(payload.appointmentDate)
    if appointment_date is None:
        raise HTTPException(status_code=400, detail={"msg": "Invalid appointmentDate"})

    doctor = db.get(Doctor, payload.doctorId)
    if not doctor:
        raise HTTPException(status_code=404, detail={"msg": "Doctor not found"})

    conflict = (
        db.query(Appointment)
        .filter(
            Appointment.doctor_id == doctor.id,
            Appointment.appointment_date == appointment_date,
            Appointment.status != "cancelled",
        )
        .first()
    )
    if conflict:
        raise HTTPException(
            status_code=409,
            detail={"msg": "This doctor already has an active appointment on that date"},
        )

    appointment = Appointment(
        patient_id=current_user.id,
        doctor_id=doctor.id,
        doctor_name=(doctor.name or "Unknown Doctor").strip(),
        speciality=(doctor.specialization or "General Medicine").strip(),
        hospital_name=(doctor.hospital or "Unknown Hospital").strip(),
        appointment_date=appointment_date,
        reason_of_appointment=reason,
    )
    db.add(appointment)
    db.commit()
    db.refresh(appointment)

    return {"msg": "Appointment booked", "appointment": appointment_for_patient_payload(appointment)}


@app.get("/api/home/appointments")
async def get_my_appointments(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    appointments = (
        db.query(Appointment)
        .filter(Appointment.patient_id == current_user.id)
        .order_by(Appointment.appointment_date.asc())
        .all()
    )
    return [appointment_for_patient_payload(appointment) for appointment in appointments]


@app.delete("/api/home/appointments/{appointment_id}")
async def cancel_appointment(
    appointment_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    appointment = (
        db.query(Appointment)
        .filter(Appointment.id == appointment_id, Appointment.patient_id == current_user.id)
        .first()
    )
    if not appointment:
        raise HTTPException(status_code=404, detail={"msg": "Appointment not found"})

    appointment.status = "cancelled"
    if appointment.slot_id:
        slot = db.get(Slot, appointment.slot_id)
        if slot:
            slot.status = "available"
    db.commit()
    db.refresh(appointment)

    return {"msg": "Appointment cancelled", "appointment": appointment_for_patient_payload(appointment)}


@app.get("/api/doctor")
async def get_doctor_profile(current_doctor: Doctor = Depends(get_current_doctor)):
    return doctor_summary(current_doctor)


@app.patch("/api/doctor/details")
async def update_doctor_details(
    payload: DoctorDetailsRequest,
    current_doctor: Doctor = Depends(get_current_doctor),
    db: Session = Depends(get_db),
):
    parsed_age = parse_age(payload.age)
    if not payload.name.strip() or not payload.hospital.strip() or parsed_age is None:
        raise HTTPException(
            status_code=400,
            detail={"msg": "Provide valid name, hospital and age (1-120)"},
        )

    current_doctor.name = payload.name.strip()
    current_doctor.hospital = payload.hospital.strip()
    current_doctor.age = parsed_age
    db.commit()
    db.refresh(current_doctor)
    return {"msg": "User details updated successfully", "user": doctor_summary(current_doctor)}


@app.patch("/api/doctor/update")
async def update_doctor_profile(
    payload: DoctorUpdateRequest,
    current_doctor: Doctor = Depends(get_current_doctor),
    db: Session = Depends(get_db),
):
    parsed_age = parse_age(payload.age)
    if (
        not payload.name.strip()
        or not payload.hospital.strip()
        or not payload.doctorId.strip()
        or parsed_age is None
    ):
        raise HTTPException(
            status_code=400,
            detail={"msg": "Provide valid doctorId, name, hospital and age (1-120)"},
        )

    duplicate_doctor = (
        db.query(Doctor)
        .filter(
            func.lower(Doctor.doctor_id) == payload.doctorId.strip().lower(),
            Doctor.id != current_doctor.id,
        )
        .first()
    )
    if duplicate_doctor:
        raise HTTPException(status_code=400, detail={"msg": "User already exists"})

    current_doctor.doctor_id = payload.doctorId.strip()
    current_doctor.name = payload.name.strip()
    current_doctor.hospital = payload.hospital.strip()
    current_doctor.age = parsed_age
    current_doctor.specialization = payload.specialization.strip() if payload.specialization else current_doctor.specialization
    current_doctor.experience = payload.experience.strip() if payload.experience else current_doctor.experience
    current_doctor.contact = payload.contact.strip() if payload.contact else current_doctor.contact
    current_doctor.email = payload.email.strip().lower() if payload.email else current_doctor.email
    db.commit()
    db.refresh(current_doctor)
    return {"msg": "User details updated successfully", "user": doctor_summary(current_doctor)}


@app.get("/api/doctor/appointments")
async def get_doctor_appointments(current_doctor: Doctor = Depends(get_current_doctor), db: Session = Depends(get_db)):
    appointments = (
        db.query(Appointment)
        .options(selectinload(Appointment.patient))
        .filter(Appointment.doctor_id == current_doctor.id)
        .order_by(Appointment.appointment_date.asc())
        .all()
    )
    return [appointment_for_doctor_payload(appointment) for appointment in appointments]


@app.patch("/api/doctor/appointments/{appointment_id}")
async def update_appointment_status(
    appointment_id: int,
    payload: AppointmentStatusRequest,
    current_doctor: Doctor = Depends(get_current_doctor),
    db: Session = Depends(get_db),
):
    if payload.status not in {"confirmed", "cancelled"}:
        raise HTTPException(status_code=400, detail={"msg": "Invalid status"})

    appointment = (
        db.query(Appointment)
        .options(selectinload(Appointment.patient))
        .filter(Appointment.id == appointment_id, Appointment.doctor_id == current_doctor.id)
        .first()
    )
    if not appointment:
        raise HTTPException(status_code=404, detail={"msg": "Appointment not found"})
    if appointment.status != "pending":
        raise HTTPException(status_code=409, detail={"msg": "Only pending requests can be updated"})

    appointment.status = payload.status

    if appointment.slot_id:
        slot = db.get(Slot, appointment.slot_id)
        if slot:
            slot.status = "booked" if payload.status == "confirmed" else "available"

    if payload.status == "confirmed" and appointment.request_group_id:
        siblings = (
            db.query(Appointment)
            .filter(
                Appointment.request_group_id == appointment.request_group_id,
                Appointment.doctor_id == current_doctor.id,
                Appointment.patient_id == appointment.patient_id,
                Appointment.id != appointment.id,
                Appointment.status == "pending",
            )
            .all()
        )
        for sibling in siblings:
            sibling.status = "cancelled"
            if sibling.slot_id:
                sibling_slot = db.get(Slot, sibling.slot_id)
                if sibling_slot:
                    sibling_slot.status = "available"

    db.commit()
    db.refresh(appointment)
    return {"msg": f"Appointment {payload.status}", "appointment": appointment_for_doctor_payload(appointment)}


@app.get("/api/doctor/patients")
async def get_my_patients(current_doctor: Doctor = Depends(get_current_doctor), db: Session = Depends(get_db)):
    patients = (
        db.query(User)
        .join(User.registered_doctors)
        .filter(Doctor.id == current_doctor.id)
        .options(selectinload(User.appointments))
        .all()
    )

    payload = []
    for patient in patients:
        patient_appointments = [
            {
                "id": appointment.id,
                "_id": appointment.id,
                "appointmentDate": appointment.appointment_date.isoformat(),
                "status": appointment.status,
                "reasonOfAppointment": appointment.reason_of_appointment,
                "date": appointment.appointment_date.isoformat(),
                "startTime": get_start_time(appointment.slot_time),
                "reason": appointment.reason_of_appointment,
            }
            for appointment in sorted(
                [item for item in patient.appointments if item.doctor_id == current_doctor.id],
                key=lambda item: item.appointment_date,
                reverse=True,
            )
        ]
        payload.append(
            {
                "id": patient.id,
                "_id": patient.id,
                "name": patient.name,
                "age": patient.age,
                "gender": patient.gender,
                "email": patient.email,
                "phoneNumber": patient.phone_number,
                "contact": patient.phone_number,
                "appointments": patient_appointments,
            }
        )
    return payload


@app.post("/api/slots/create")
async def create_slots(
    payload: SlotCreateRequest,
    current_doctor: Doctor = Depends(get_current_doctor),
    db: Session = Depends(get_db),
):
    if payload.doctorId != current_doctor.id:
        raise HTTPException(
            status_code=403,
            detail={
                "message": "You can only create slots for your own account",
                "msg": "You can only create slots for your own account",
            },
        )
    if not payload.date.strip():
        raise HTTPException(status_code=400, detail={"message": "date is required", "msg": "date is required"})
    if not payload.times:
        raise HTTPException(status_code=400, detail={"message": "times is required", "msg": "times is required"})

    normalized_times = []
    seen = set()
    for value in payload.times:
        if isinstance(value, str):
            item = value.strip()
            if item and item not in seen:
                normalized_times.append(item)
                seen.add(item)
    if not normalized_times:
        raise HTTPException(
            status_code=400,
            detail={"message": "No valid time slots provided", "msg": "No valid time slots provided"},
        )

    existing_slots = (
        db.query(Slot)
        .filter(
            Slot.doctor_id == current_doctor.id,
            Slot.date == payload.date.strip(),
            Slot.time.in_(normalized_times),
        )
        .all()
    )
    existing_times = {slot.time for slot in existing_slots}
    new_times = [slot_time for slot_time in normalized_times if slot_time not in existing_times]

    if not new_times:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Selected slots already exist for this date",
                "msg": "Selected slots already exist for this date",
                "createdCount": 0,
                "skippedTimes": normalized_times,
            },
        )

    created_slots = []
    for slot_time in new_times:
        slot = Slot(doctor_id=current_doctor.id, date=payload.date.strip(), time=slot_time)
        db.add(slot)
        created_slots.append(slot)

    try:
        db.commit()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(status_code=409, detail={"message": "Selected slots already exist for this date", "msg": "Selected slots already exist for this date"}) from error

    for slot in created_slots:
        db.refresh(slot)

    full_success = len(new_times) == len(normalized_times)
    return {
        "message": "Slots published successfully" if full_success else "Some slots already existed and were skipped",
        "msg": "Slots published successfully" if full_success else "Some slots already existed and were skipped",
        "createdCount": len(created_slots),
        "skippedTimes": [slot_time for slot_time in normalized_times if slot_time in existing_times],
        "slots": [slot_payload(slot) for slot in created_slots],
    }


@app.get("/api/slots/doctors")
async def get_doctors_with_slots(db: Session = Depends(get_db)):
    slots = (
        db.query(Slot)
        .options(selectinload(Slot.doctor))
        .filter(Slot.status == "available")
        .order_by(Slot.date.asc(), Slot.time.asc())
        .all()
    )

    grouped: dict[int, dict] = {}
    for slot in slots:
        doctor = slot.doctor
        if doctor is None:
            continue
        if doctor.id not in grouped:
            grouped[doctor.id] = {
                "_id": doctor.id,
                "id": doctor.id,
                "name": doctor.name or "Unknown Doctor",
                "hospital": doctor.hospital or "Unknown Hospital",
                "specialization": doctor.specialization or "General",
                "availability": [],
            }
        entry = f"{slot.date} | {slot.time}"
        if entry not in grouped[doctor.id]["availability"]:
            grouped[doctor.id]["availability"].append(entry)
    return list(grouped.values())


@app.get("/api/slots/my")
async def get_my_slots_by_doctor(current_doctor: Doctor = Depends(get_current_doctor), db: Session = Depends(get_db)):
    slots = (
        db.query(Slot)
        .filter(Slot.status == "available", Slot.doctor_id == current_doctor.id)
        .order_by(Slot.date.asc(), Slot.time.asc())
        .all()
    )

    availability = []
    for slot in slots:
        entry = f"{slot.date} | {slot.time}"
        if entry not in availability:
            availability.append(entry)

    return [
        {
            "_id": current_doctor.id,
            "id": current_doctor.id,
            "name": current_doctor.name or "Unknown Doctor",
            "hospital": current_doctor.hospital or "Unknown Hospital",
            "specialization": current_doctor.specialization or "General",
            "availability": availability,
        }
    ]


@app.get("/api/slots/{doctor_id}/{slot_date}")
async def get_doctor_slots_by_date(
    doctor_id: int,
    slot_date: str,
    _auth: dict = Depends(require_auth()),
    db: Session = Depends(get_db),
):
    doctor = db.get(Doctor, doctor_id)
    if not doctor:
        raise HTTPException(status_code=400, detail={"message": "Invalid doctorId", "msg": "Invalid doctorId"})
    if not slot_date.strip():
        raise HTTPException(status_code=400, detail={"message": "date is required", "msg": "date is required"})

    slots = (
        db.query(Slot)
        .filter(
            Slot.doctor_id == doctor.id,
            Slot.date == slot_date.strip(),
            Slot.status == "available",
        )
        .order_by(Slot.time.asc())
        .all()
    )

    seen_times = set()
    unique_slots = []
    for slot in slots:
        if slot.time in seen_times:
            continue
        seen_times.add(slot.time)
        unique_slots.append(slot_payload(slot))
    return unique_slots


@app.post("/api/slots/book")
async def book_slot_appointment(
    payload: SlotBookRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    selected_ids = payload.slotIds if payload.slotIds is not None else [payload.slotId] if payload.slotId else []
    selected_ids = [slot_id for slot_id in dict.fromkeys(selected_ids) if slot_id is not None]
    if len(selected_ids) != 1:
        raise HTTPException(status_code=400, detail={"message": "Select exactly one slot", "msg": "Select exactly one slot"})

    slot = db.get(Slot, selected_ids[0])
    if not slot:
        raise HTTPException(status_code=404, detail={"message": "Slot not found", "msg": "Slot not found"})
    if slot.status != "available":
        raise HTTPException(
            status_code=409,
            detail={"message": "This slot is not available", "msg": "This slot is not available"},
        )

    appointment_date = normalize_date_only(slot.date)
    if appointment_date is None:
        raise HTTPException(status_code=500, detail={"message": "Server error", "msg": "Server error"})

    duplicate_appointment = (
        db.query(Appointment)
        .filter(
            Appointment.patient_id == current_user.id,
            Appointment.doctor_id == slot.doctor_id,
            Appointment.appointment_date == appointment_date,
            Appointment.status != "cancelled",
        )
        .first()
    )
    if duplicate_appointment:
        suffix = f" at {duplicate_appointment.slot_time}" if duplicate_appointment.slot_time else ""
        raise HTTPException(
            status_code=409,
            detail={
                "message": f"You already have an appointment with this doctor on this date{suffix}",
                "msg": "You already have an appointment with this doctor on this date",
            },
        )

    doctor = db.get(Doctor, slot.doctor_id)
    if not doctor:
        raise HTTPException(status_code=404, detail={"message": "Doctor not found", "msg": "Doctor not found"})

    slot.status = "booked"
    request_group_id = str(uuid.uuid4())
    notes = payload.patient.notes.strip() if payload.patient and payload.patient.notes else ""
    appointment = Appointment(
        patient_id=current_user.id,
        doctor_id=slot.doctor_id,
        slot_id=slot.id,
        request_group_id=request_group_id,
        slot_time=slot.time,
        doctor_name=(doctor.name or "Unknown Doctor").strip(),
        speciality=(doctor.specialization or "General Physician").strip(),
        hospital_name=(doctor.hospital or "Unknown Hospital").strip(),
        appointment_date=appointment_date,
        reason_of_appointment=notes or "Booked from available slots",
        status="confirmed",
    )
    db.add(appointment)
    db.commit()
    db.refresh(appointment)

    return {
        "message": "Appointment confirmed",
        "appointment": {"_id": appointment.id, "bookingId": request_group_id},
    }


@app.get("/api/test")
async def test_connection(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"success": True, "message": "Database connected!"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host="127.0.0.1", port=PORT, reload=True)
