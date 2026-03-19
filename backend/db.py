import os
from datetime import datetime
from pathlib import Path

from sqlalchemy import (
    Column,
    Date,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    event,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker


def load_local_env() -> None:
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


load_local_env()

DATABASE_URL = os.getenv("DATABASE_URL")
DB_SCHEMA = os.getenv("DB_SCHEMA", "appuser").strip() or "appuser"

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not configured")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


@event.listens_for(engine, "connect", insert=True)
def set_search_path(dbapi_connection, _connection_record):
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute(f'SET search_path TO "{DB_SCHEMA}"')
    finally:
        cursor.close()


registered_doctors_table = Table(
    "registered_doctors",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("doctor_id", ForeignKey("doctors.id", ondelete="CASCADE"), primary_key=True),
)


class TimestampMixin:
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)
    gender = Column(String(20), nullable=True)
    age = Column(Integer, nullable=True)
    phone_number = Column(String(10), nullable=True)

    registered_doctors = relationship(
        "Doctor",
        secondary=registered_doctors_table,
        back_populates="patients",
    )
    appointments = relationship("Appointment", back_populates="patient")
    reports = relationship("Report", back_populates="patient")


class Doctor(TimestampMixin, Base):
    __tablename__ = "doctors"

    id = Column(Integer, primary_key=True, index=True)
    doctor_id = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=True, index=True)
    hospital = Column(String(255), nullable=True, index=True)
    age = Column(Integer, nullable=True)
    password = Column(String(255), nullable=False)
    specialization = Column(String(255), nullable=True, index=True)
    experience = Column(String(255), nullable=True)
    contact = Column(String(255), nullable=True)
    email = Column(String(255), nullable=True)

    patients = relationship(
        "User",
        secondary=registered_doctors_table,
        back_populates="registered_doctors",
    )
    appointments = relationship("Appointment", back_populates="doctor")
    slots = relationship("Slot", back_populates="doctor")


class Slot(TimestampMixin, Base):
    __tablename__ = "slots"

    id = Column(Integer, primary_key=True, index=True)
    doctor_id = Column(Integer, ForeignKey("doctors.id", ondelete="CASCADE"), nullable=False, index=True)
    date = Column(String(32), nullable=False, index=True)
    time = Column(String(64), nullable=False, index=True)
    status = Column(String(20), nullable=False, default="available")

    doctor = relationship("Doctor", back_populates="slots")
    appointments = relationship("Appointment", back_populates="slot")

    __table_args__ = (
        UniqueConstraint("doctor_id", "date", "time", name="uq_slot_doctor_date_time"),
    )


class Appointment(TimestampMixin, Base):
    __tablename__ = "appointments"

    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    doctor_id = Column(Integer, ForeignKey("doctors.id", ondelete="CASCADE"), nullable=False, index=True)
    slot_id = Column(Integer, ForeignKey("slots.id", ondelete="SET NULL"), nullable=True, index=True)
    request_group_id = Column(String(255), nullable=True, index=True)
    slot_time = Column(String(64), nullable=False, default="")
    doctor_name = Column(String(255), nullable=False)
    speciality = Column(String(255), nullable=False)
    hospital_name = Column(String(255), nullable=False)
    appointment_date = Column(Date, nullable=False, index=True)
    reason_of_appointment = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, default="pending", index=True)

    patient = relationship("User", back_populates="appointments")
    doctor = relationship("Doctor", back_populates="appointments")
    slot = relationship("Slot", back_populates="appointments")


class Report(TimestampMixin, Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(String(255), unique=True, nullable=False, index=True)
    patient_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    uploaded_by = Column(String(50), nullable=False, default="patient")
    doctor_id = Column(Integer, ForeignKey("doctors.id", ondelete="SET NULL"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(50), nullable=False)
    file_size = Column(Integer, nullable=False)
    file_id = Column(String(255), unique=True, nullable=False, index=True)
    visibility = Column(String(20), nullable=False, default="private")
    original_file_name = Column(String(255), nullable=False, default="")
    mime_type = Column(String(255), nullable=False, default="")
    file_content = Column(LargeBinary, nullable=False)

    patient = relationship("User", back_populates="reports")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
