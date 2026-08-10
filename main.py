from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import socket
from scanner import scan_target

app = FastAPI(
    title="CloudGuard Lite API",
    description="API для моніторингу поверхні атак (Attack Surface Monitoring)",
    version="1.0.0"
)

# Дозволяємо фронтенду звертатися до нашого API (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    host: str

@app.get("/")
def read_root():
    return {"status": "active", "service": "CloudGuard Lite API"}

@app.post("/api/v1/scan")
async def run_scan(request: ScanRequest):
    try:
        # Резолвимо IP-адресу
        target_ip = socket.gethostbyname(request.host)
    except socket.gaierror:
        raise HTTPException(
            status_code=400,
            detail="Неможливо резолвити хост. Перевірте правильність IP/домену."
        )

    # Асинхронний виклик сканера через await
    findings = await scan_target(target_ip)

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
