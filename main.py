from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
import socket
import asyncio
import re
from scanner import scan_target

# Конфігурація API
app = FastAPI(
    title="CloudGuard Lite API",
    description="API for Attack Surface Monitoring",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Валидація IPv4 (регулярний вираз)
ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

class ScanRequest(BaseModel):
    host: str
    
    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        # Перевірка на коректність формату IPv4
        if not ip_pattern.match(value):
            # Спроба резолвувати домен у IP-адресу (якщо є)
            try:
                resolved = socket.gethostbyname(value)
                return resolved
            except socket.gaierror:
                raise ValueError("Некоректний формат хосту. Використовуйте коректне IPv4 або коректне доменне ім'я.")
        return value

def log_event(message: str):
    print(f"[LOG] {message}")

@app.get("/")
async def read_root():
    return {"status": "active", "service": "CloudGuard Lite API"}

@app.post("/api/v1/scan")
async def run_scan(request: ScanRequest, semaphore=None):
    # Конфігурація кількості потоків (за замовчуванням 1000)
    if not semaphore:
        semaphore = asyncio.Semaphore(1000)

    try:
        target_ip = socket.gethostbyname(request.host)
    except socket.gaierror:
        raise HTTPException(
            status_code=400,
            detail="Неможливо розпізнати хост. Перевірте правильність IP/домену."
        )

    async def scan_with_semaphore():
        findings = await scan_target(target_ip)
        return findings
    
    findings = await asyncio.wait_for(scan_with_semaphore(), timeout=120.0)  # Timeout 2 хв

    # Визначаємо загальний статус безпеки хоста
    has_critical = any(f["risk_level"] == "CRITICAL" for f in findings)
    has_high = any(f["risk_level"] == "HIGH" for f in findings)

    if has_critical:
        overall_status = "CRITICAL"
    elif has_high:
        overall_status = "WARNING"
    else:
        overall_status = "OK"

    return {
        "target": request.host,
        "ip": target_ip,
        "overall_status": overall_status,
        "findings": findings
    }
