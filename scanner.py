import asyncio
import socket

# Список стандартних портів для різних протоколів
HTTP_PORTS = {80, 443, 8080}
HTTP_USER_AGENT = b"Mozilla/5.0 (compatible; CloudGuard/1.0)\r\n\r\n"

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

async def grab_banner_http(reader, writer):
    """Зчитує банер для HTTP/HTTPS запитів (GET / або HEAD)."""
    try:
        writer.write(b"GET / HTTP/1.1\r\nHost: .\r\nConnection: close\r\n\r\n")
        await writer.drain()

        # Читаємо перші 2048 символів
        data = await asyncio.wait_for(reader.read(2048), timeout=0.5)
        
        if not data:
            return "Connection closed by server"

        response_lines = data.decode('utf-8', errors='ignore').split('\n')
        status_line = response_lines[0].strip() if response_lines else ""

        # Пошукуємо статус HTTP (наприклад, 200 OK) та першу доступну строку заголовків
        if "200" in status_line or "301" in status_line:
            return status_line[:60] if len(status_line) > 60 else status_line
        elif response_lines:
            return f"{response_lines[0].strip()}\n{response_lines[1][:50]}" if len(response_lines) > 1 else response_lines[0]
        else:
            return "HTTP response received"
    except Exception as e:
        return f"No banner received ({str(e)})"

async def grab_banner_other(reader, writer):
    """Зчитує банер для інших протоколів (FTP: 'PORT', SSH: 'SSH-2.0')."""
    try:
        # Спроба отримати будь-який відповідь
        writer.write(b"ABCDEF")  # Спробуємо коротке повідомлення
        await writer.drain()

        data = await asyncio.wait_for(reader.read(512), timeout=0.3)
        if data:
            return data.decode('utf-8', errors='ignore').strip().split('\n')[0][:40]
        else:
            return "No banner received"
    except Exception:
        return "Connection closed by server"

async def check_port(ip, port, semaphore):
    """Перевіряє відкриття порту та зчитує відповідний банер."""
    
    # Визначаємо протокол на основі порту
    is_http_port = port in HTTP_PORTS
    
    async with semaphore:
        try:
            conn = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=0.6)

            # Вибір відповідної функції для зчитування банеру
            reader, writer = conn
            banner_reader = grab_banner_http if is_http_port else grab_banner_other
            
            banner = await banner_reader(reader, writer)
            
            # Завжди закриваємо після отримання даних
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
        except asyncio.TimeoutError:
            # Якщо з'єднання не встановлено (таймаут) — це означає, що порт закрито або фільтрація фаєрволу
            return None
        except ConnectionRefusedError:
            return None
        except OSError as e:
            if "Connection refused" in str(e):
                return None
            raise

async def scan_all_ports_async(ip):
    """Запускає паралельне сканування всіх портів для заданого IP."""
    # Заборона занадто високого навантаження — обмежуємо кількість одночасних спроб до 1000
    semaphore = asyncio.Semaphore(1000)
    
    # Створюємо завдання для кожного порту з діапазону 1-65535
    tasks = [check_port(ip, port, semaphore) for port in range(1, 65536)]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Фільтруємо результати: залишаємо лише ті, що не None (отримані портами)
    open_ports = [r for r in results if r is not None and isinstance(r, dict)]
    open_ports.sort(key=lambda x: x["port"])

    return open_ports

async def scan_target(ip):
    """Головна функція для запуску сканування."""
    return await scan_all_ports_async(ip)
