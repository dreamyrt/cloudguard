import asyncio
import socket

COMMON_PORTS = {
    21: {"service": "FTP", "risk": "HIGH", "desc": "Передача файлів. Можлива передача даних у відкритому вигляді."},
    22: {"service": "SSH", "risk": "MEDIUM", "desc": "Віддалений доступ. Потрібен захист ключами або VPN."},
    23: {"service": "Telnet", "risk": "CRITICAL", "desc": "Застарілий незахищений протокол."},
    25: {"service": "SMTP", "risk": "MEDIUM", "desc": "Поштовий сервер."},
    53: {"service": "DNS", "risk": "LOW", "desc": "Служба імен."},
    80: {"service": "HTTP", "risk": "LOW", "desc": "Звичайний веб-трафік."},
    443: {"service": "HTTPS", "risk": "LOW", "desc": "Зашифрований веб-трафік."},
    445: {"service": "SMB", "risk": "CRITICAL", "desc": "Мережеві папки Windows (EternalBlue)."},
    3306: {"service": "MySQL", "risk": "HIGH", "desc": "База даних MySQL."},
    3389: {"service": "RDP", "risk": "HIGH", "desc": "Віддалений робочий стіл Windows."},
    6379: {"service": "Redis", "risk": "CRITICAL", "desc": "In-memory БД без пароля."},
    8080: {"service": "HTTP-Alt", "risk": "MEDIUM", "desc": "Альтернативний веб-порт/адмінка."},
    27017: {"service": "MongoDB", "risk": "CRITICAL", "desc": "NoSQL база даних."}
}

async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> str:
    """Зчитує банер, який сервер надсилає при підключенні."""
    try:
        # Для HTTP портів відправляємо базовий HEAD-запит
        writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
        await writer.drain()

        data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
        banner = data.decode('utf-8', errors='ignore').strip().split('\n')[0]
        return banner[:60] if banner else "No banner received"
    except Exception:
        return "No banner received"

async def check_port(ip: str, port: int, semaphore: asyncio.Semaphore) -> dict | None:
    async with semaphore:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=0.8)

            # Зчитуємо банер
            banner = await grab_banner(reader, writer)

            writer.close()
            await writer.wait_closed()

            port_info = COMMON_PORTS.get(port, {
                "service": "Unknown",
                "risk": "INFO",
                "desc": "Нестандартний або кастомний сервіс."
            })

            return {
                "port": port,
                "service": port_info["service"],
                "risk_level": port_info["risk"],
                "description": port_info["desc"],
                "banner": banner
            }
        except (asyncio.TimeoutError, OSError):
            return None

async def scan_all_ports_async(ip: str) -> list:
    semaphore = asyncio.Semaphore(1000)
    tasks = [check_port(ip, port, semaphore) for port in range(1, 65536)]
    results = await asyncio.gather(*tasks)

    open_ports = [r for r in results if r is not None]
    open_ports.sort(key=lambda x: x["port"])
    return open_ports

async def scan_target(ip: str) -> list:
    return await scan_all_ports_async(ip)
