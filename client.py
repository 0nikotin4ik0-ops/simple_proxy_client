import customtkinter as ctk
import json
import subprocess
import socket
import time
import threading
import winreg
import ctypes
import os
import glob
import requests
import base64
import copy
import re
from urllib.parse import urlparse, parse_qs, unquote

# ==========================================
# 1. КОНФИГУРАЦИЯ И ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
# ==========================================
CONFIGS_DIR = "configs"
XRAY_EXE = "xray.exe"
LOCAL_HTTP_PROXY = "127.0.0.1:10809" 

servers = []
current_process = None
current_server = None
is_connected = False
selected_server_var = None
app = None

SETTINGS_PATH = os.path.join("", "settings.json")

def load_settings():
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_settings(data):
    cur = load_settings()
    cur.update(data)
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(cur, f, ensure_ascii=False, indent=2)

BLACKLIST = set(load_settings().get("blacklist", []))
# ==========================================
# 2. ЧТЕНИЕ ЛОКАЛЬНЫХ КОНФИГОВ
# ==========================================
def load_servers():
    global servers
    try:
        if not os.path.exists(CONFIGS_DIR):
            os.makedirs(CONFIGS_DIR)
            update_log(f"Папка '{CONFIGS_DIR}' создана. Положите туда .json файлы.")
            app.after(0, render_server_list)
            return

        servers.clear()
        config_files = glob.glob(os.path.join(CONFIGS_DIR, "*.json"))
        
        for filepath in config_files:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                name = data.get("remarks", os.path.basename(filepath))
                address = data["outbounds"][0]["settings"]["vnext"][0]["address"]
                port = data["outbounds"][0]["settings"]["vnext"][0]["port"]
                
                servers.append({
                    'id': os.path.basename(filepath),
                    'name': name,
                    'address': address,
                    'port': int(port),
                    'filepath': filepath
                })
            except Exception as e:
                update_log(f"Ошибка чтения {os.path.basename(filepath)}: {e}")
                
        update_log(f"Загружено конфигов: {len(servers)}")
        app.after(0, render_server_list)
    except Exception as e:
        update_log(f"Ошибка загрузки: {e}")

TEMPLATE_PATH = os.path.join("", "template.json")

def parse_vless_link(link):
    try:
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        return {
            'name': unquote(parsed.fragment) or f"{parsed.hostname}:{parsed.port}",
            'address': parsed.hostname,
            'port': int(parsed.port),
            'uuid': parsed.username,
            'flow': params.get('flow', [''])[0],
            'security': params.get('security', ['tls'])[0],
            'sni': params.get('sni', [''])[0],
            'fp': params.get('fp', ['chrome'])[0],
            'pbk': params.get('pbk', [''])[0],
            'sid': params.get('sid', [''])[0],
            'type': params.get('type', ['tcp'])[0],
        }
    except Exception:
        return None

def get_template():
    # 1. Явный шаблон
    if os.path.exists(TEMPLATE_PATH):
        with open(TEMPLATE_PATH, encoding="utf-8") as f:
            return json.load(f)
    # 2. Или первый попавшийся конфиг как шаблон
    files = glob.glob(os.path.join(CONFIGS_DIR, "*.json"))
    if files:
        with open(files[0], encoding="utf-8") as f:
            return json.load(f)
    return None

def safe_filename(name, fallback):
    name = re.sub(r'[\\/:*?"<>|]', '', name).strip()
    return (name or fallback) + ".json"

def import_subscription(url):
    template = get_template()
    if template is None:
        update_log("Нет шаблона: положи template.json или хотя бы один конфиг в configs")
        return
    try:
        text = requests.get(url, timeout=15).text.strip()
    except Exception as e:
        update_log(f"Ошибка скачивания подписки: {e}")
        return

    # Base64 или plain-текст
    if not text.startswith("vless://"):
        try:
            text = base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8")
        except Exception:
            update_log("Не удалось распознать формат подписки")
            return

    count = 0
    for i, link in enumerate(text.splitlines(), 1):
        link = link.strip()
        if not link.startswith("vless://"):
            continue
        p = parse_vless_link(link)
        if not p:
            continue
        if p['name'] in BLACKLIST:
            continue
        cfg = copy.deepcopy(template)
        ob = cfg["outbounds"][0]                      # считаем первый outbound прокси-сервером
        vnext = ob["settings"]["vnext"][0]
        vnext["address"] = p["address"]
        vnext["port"] = p["port"]
        u = vnext["users"][0]
        u["id"] = p["uuid"]
        u["encryption"] = "none"
        if p["flow"]:
            u["flow"] = p["flow"]

        ss = ob["streamSettings"]
        ss["network"] = p["type"] or "tcp"
        ss["security"] = p["security"]
        rs = ss.get("realitySettings", {})
        rs.update({
            "serverName": p["sni"],
            "publicKey": p["pbk"],
            "shortId": p["sid"],
            "fingerprint": p["fp"],
        })
        ss["realitySettings"] = rs
        cfg["remarks"] = p["name"]

        with open(os.path.join(CONFIGS_DIR, safe_filename(p["name"], f"import_{i}")),
                  "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        count += 1

    update_log(f"Импортировано серверов: {count}")
    load_servers()

# ==========================================
# 3. ПРОВЕРКА ДОСТУПНОСТИ (TCP PING)
# ==========================================
def tcp_ping(server, timeout=2.0):
    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((server['address'], server['port']))
        sock.close()
        if result == 0:
            return int((time.time() - start_time) * 1000)
        return 9999
    except Exception:
        return 9999

def ping_server(server, label):
    app.after(0, lambda: label.configure(text="...", text_color="gray"))
    p = tcp_ping(server)
    
    def update_ui():
        if p < 9999:
            color = "green" if p < 300 else "orange"
            label.configure(text=f"{p} ms", text_color=color)
            server['ping'] = p
        else:
            label.configure(text="Timeout", text_color="red")
            server['ping'] = 9999
            
    app.after(0, update_ui)

def ping_all_servers():
    update_log("Начата проверка доступности...")
    for s in servers:
        if 'ping_label' in s:
            threading.Thread(target=ping_server, args=(s, s['ping_label']), daemon=True).start()
            time.sleep(0.05)

# ==========================================
# 4. УПРАВЛЕНИЕ ЯДРОМ XRAY (С ЧТЕНИЕМ ЛОГОВ)
# ==========================================
def read_xray_output(process):
    """Читает консольный вывод Xray и отправляет его в наш GUI лог"""
    try:
        for line in process.stdout:
            if line:
                update_log(f"[XRAY] {line.strip()}")
    except Exception:
        pass

def start_xray(server):
    global current_process
    # Запускаем Xray и перехватываем его stdout/stderr
    current_process = subprocess.Popen(
        [XRAY_EXE, "-c", server['filepath']], 
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding='utf-8',
        errors='ignore',
        creationflags=0x08000000 # CREATE_NO_WINDOW
    )
    # Запускаем поток, который будет читать логи Xray
    threading.Thread(target=read_xray_output, args=(current_process,), daemon=True).start()
    time.sleep(1)

def stop_xray():
    global current_process
    if current_process:
        current_process.terminate()
        current_process = None

# ==========================================
# 5. СИСТЕМНЫЙ ПРОКСИ (WINDOWS 11)
# ==========================================
def set_system_proxy(enable, server=LOCAL_HTTP_PROXY):
    try:
        INTERNET_SETTINGS = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
            0, winreg.KEY_ALL_ACCESS
        )
        if enable:
            winreg.SetValueEx(INTERNET_SETTINGS, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(INTERNET_SETTINGS, "ProxyServer", 0, winreg.REG_SZ, server)
            # ВАЖНО: Исключаем локальные адреса, чтобы Windows не проксировала саму себя
            winreg.SetValueEx(INTERNET_SETTINGS, "ProxyOverride", 0, winreg.REG_SZ, "127.*;localhost;<local>")
        else:
            winreg.SetValueEx(INTERNET_SETTINGS, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        
        winreg.CloseKey(INTERNET_SETTINGS)
        ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
        ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)
    except Exception as e:
        update_log(f"Ошибка прокси: {e}")

# ==========================================
# 6. ЛОГИКА ПОДКЛЮЧЕНИЯ
# ==========================================
def connect():
    global is_connected
    global current_server
    selected_id = selected_server_var.get()
    target_server = None
    
    if selected_id:
        for s in servers:
            if s['id'] == selected_id:
                target_server = s
                break
                
    if not target_server:
        update_log("Поиск лучшего сервера...")
        min_ping = 9999
        for s in servers:
            if 'ping' not in s:
                s['ping'] = tcp_ping(s)
            if s['ping'] < min_ping:
                min_ping = s['ping']
                target_server = s
                
    if target_server and target_server.get('ping', 9999) < 9999:
        update_log(f"Подключение к {target_server['name']}...")
        stop_xray()
        start_xray(target_server)
        set_system_proxy(True)
        is_connected = True
        current_server = target_server
        app.after(0, lambda s=target_server: selected_server_var.set(s['id']))
        update_status(f"Подключено: {target_server['name']}", "green")

    else:
        update_log("Нет доступных серверов для подключения.")

def disconnect():
    global is_connected
    stop_xray()
    set_system_proxy(False)
    is_connected = False
    current_server = None
    update_status("Отключено", "red")
    update_log("Отключено.")

def update_log(msg):
    def _update():
        log_text.configure(state="normal")
        log_text.insert("end", msg + "\n")
        log_text.see("end")
        log_text.configure(state="disabled")
    if app:
        app.after(0, _update)

def update_status(text, color):
    def _update():
        status_label.configure(text=text, text_color=color)
    if app:
        app.after(0, _update)

# ==========================================
# 6.5 АВТОПЕРЕКЛЮЧЕНИЕ
# ==========================================
auto_swap_var = None # создадим после окна

def do_switch(new_server):
    global current_server
    stop_xray()
    start_xray(new_server)
    current_server = new_server
    app.after(0, lambda s=new_server: selected_server_var.set(s['id']))
    update_status(f"Подключено: {new_server['name']}", "green")
    update_log(f"Автопереключение на {new_server['name']}")

def auto_swap_loop():
    """Фоновый наблюдатель: раз в 30 сек проверяет текущий сервер"""
    while True:
        time.sleep(30)
        if not is_connected or current_server is None:
            continue
        if auto_swap_var is None or not auto_swap_var.get():
            continue

        cur_ping = tcp_ping(current_server)
        need_switch = (cur_ping >= 9999) # текущий сервер умер

        if not need_switch:
            # Ищем ЗНАЧИТЕЛЬНО более быстрый сервер (защита от "дёргания")
            for s in servers:
                if s['id'] == current_server['id']:
                    continue
                p = tcp_ping(s)
                if p < 9999 and cur_ping > 100 and p * 2 < cur_ping:
                    update_log(f"Найден сервер вдвое быстрее: {s['name']} ({p}ms против {cur_ping}ms)")
                    need_switch = True
                    break

        if need_switch:
            update_log("Автоподбор лучшего сервера...")
            best = None
            for s in servers:
                p = tcp_ping(s)
                if p < 9999 and (best is None or p < best[1]):
                    best = (s, p)
            if best and best[0]['id'] != current_server['id']:
                app.after(0, lambda b=best[0]: do_switch(b))

# ==========================================
# 7. UI (CUSTOMTKINTER)
# ==========================================
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.geometry("500x700")
app.title("Simple VPN Client")

selected_server_var = ctk.StringVar(value="")

status_label = ctk.CTkLabel(app, text="Отключено", text_color="red", font=ctk.CTkFont(size=20, weight="bold"))
status_label.pack(pady=(20, 10))

btn_frame = ctk.CTkFrame(app, fg_color="transparent")
btn_frame.pack(pady=10)

import_frame = ctk.CTkFrame(app, fg_color="transparent")
import_frame.pack(pady=5)

sub_url_entry = ctk.CTkEntry(import_frame, width=330, placeholder_text="Ссылка на подписку")
sub_url_entry.pack(side="left", padx=(10, 5))

def thread_update():
    url = sub_url_entry.get().strip()
    if url:
        save_settings({"subscription_url": url})          # запомнили ссылку
        threading.Thread(target=import_subscription, args=(url,), daemon=True).start()
    else:
        threading.Thread(target=load_servers, daemon=True).start()

def thread_import():
    url = sub_url_entry.get().strip()
    if url:
        save_settings({"subscription_url": url})
        threading.Thread(target=import_subscription, args=(url,), daemon=True).start()

btn_import = ctk.CTkButton(import_frame, text="Импорт", width=90, command=thread_import)
btn_import.pack(side="left", padx=5)

def thread_update(): threading.Thread(target=load_servers).start()
def thread_ping_all(): threading.Thread(target=ping_all_servers).start()
def thread_connect(): threading.Thread(target=connect).start()
def thread_disconnect(): threading.Thread(target=disconnect).start()

btn_update = ctk.CTkButton(btn_frame, text="Обновить", width=100, command=thread_update)
btn_update.grid(row=0, column=0, padx=5)

btn_ping = ctk.CTkButton(btn_frame, text="Пинг всех", width=100, command=thread_ping_all)
btn_ping.grid(row=0, column=1, padx=5)

btn_connect = ctk.CTkButton(btn_frame, text="Подключиться", width=100, command=thread_connect)
btn_connect.grid(row=0, column=2, padx=5)

btn_disconnect = ctk.CTkButton(btn_frame, text="Отключить", width=100, command=thread_disconnect, fg_color="darkred", hover_color="red")
btn_disconnect.grid(row=0, column=3, padx=5)

auto_swap_var = ctk.BooleanVar(value=False)
auto_swap_check = ctk.CTkCheckBox(app, text="Автопереключение на лучший сервер", variable=auto_swap_var)
auto_swap_check.pack(pady=5)

server_list_frame = ctk.CTkScrollableFrame(app, width=460, height=350)
server_list_frame.pack(pady=10, padx=10, fill="both", expand=True)

def on_ban(server):
    BLACKLIST.add(server['name'])
    save_settings({"blacklist": sorted(BLACKLIST)})
    try:
        os.remove(server['filepath'])   # убираем уже созданный файл
    except Exception:
        pass
    if current_server and current_server['id'] == server['id']:
        disconnect()                    # если были подключены к нему
    update_log(f"Сервер {server['name']} в чёрном списке")
    load_servers()

def render_server_list():
    for widget in server_list_frame.winfo_children():
        widget.destroy()
        
    for s in servers:
        card = ctk.CTkFrame(server_list_frame)
        card.pack(fill="x", pady=2, padx=5)
        
        rb = ctk.CTkRadioButton(card, text=s['name'], variable=selected_server_var, value=s['id'])
        rb.pack(side="left", padx=10, pady=10)
        
        ping_label = ctk.CTkLabel(card, text="... ms", text_color="gray", width=80)
        ping_label.pack(side="right", padx=10)
        s['ping_label'] = ping_label
        ban_btn = ctk.CTkButton(card, text="✕", width=30,
                        fg_color="transparent",
                        command=lambda s=s: on_ban(s))
        ban_btn.pack(side="right", padx=2)

log_text = ctk.CTkTextbox(app, height=150, state="disabled")
log_text.pack(pady=10, padx=10, fill="x")

def on_closing():
    disconnect()
    app.destroy()

app.protocol("WM_DELETE_WINDOW", on_closing)

threading.Thread(target=auto_swap_loop, daemon=True).start()
settings = load_settings()
saved_url = settings.get("subscription_url", "")
if saved_url:
    sub_url_entry.insert(0, saved_url)                    # поле предзаполнено
    threading.Thread(target=import_subscription, args=(saved_url,), daemon=True).start()
else:
    threading.Thread(target=load_servers, daemon=True).start()

app.mainloop()