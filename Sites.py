from flask import Flask, request, render_template_string
import os
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
import time

app = Flask(__name__)

# Configuración de Selenium en modo headless
def configurar_selenium_headless():
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--log-level=3")
    options.add_argument("--silent")
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-infobars")
    options.add_experimental_option('excludeSwitches', ['enable-logging'])
    
    service = Service(log_output=os.devnull, service_args=['--silent', '--log-level=OFF'])
    driver = webdriver.Chrome(service=service, options=options)
    return driver

# Análisis pasivo de una URL
def analizar_url_pasivo(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        }
        response = requests.get(url, headers=headers, timeout=10)
        resultado = f"[+] {url} - Código de estado: {response.status_code}\n"
        
        cabeceras = response.headers
        resultado += detectar_seguridad_cabeceras(cabeceras)
        
        soup = BeautifulSoup(response.text, "html.parser")
        texto = response.text.lower()

        if response.status_code == 200:
            resultado += "[+] Respuesta normal (200 OK)\n"
        elif response.status_code == 403:
            resultado += "[!] Acceso denegado (403) - Posible WAF o protección\n"
        elif response.status_code == 503:
            resultado += "[!] Servicio no disponible (503) - Posible Cloudflare u otro WAF\n"

        resultado += detectar_seguridad_contenido(texto, soup)
        resultado += detectar_2fa(texto, soup)
        resultado += detectar_checkout(texto, soup)

        return resultado, tiene_seguridad(texto, soup, cabeceras), soup, texto
    except requests.exceptions.RequestException:
        return f"[-] {url} - Error de conexión\n", False, None, ""

# Análisis con Selenium
def analizar_url_selenium(url):
    resultado = f"[*] Analizando {url} con Selenium (headless)...\n"
    driver = None
    try:
        driver = configurar_selenium_headless()
        driver.get(url)
        time.sleep(3)
        texto = driver.page_source.lower()
        soup = BeautifulSoup(texto, "html.parser")
        
        resultado_2fa = detectar_2fa(texto, soup)
        resultado_checkout = detectar_checkout(texto, soup)
        
        if "[!]" in resultado_2fa or "[!]" in resultado_checkout:
            resultado += "[+] Selenium confirmó seguridad adicional:\n" + resultado_2fa + resultado_checkout
        else:
            resultado += "[+] Selenium no encontró 2FA ni checkout adicionales\n"
        
        return resultado, tiene_seguridad(texto, soup, {})
    except:
        return f"[-] {url} - Error en Selenium\n", False
    finally:
        if driver:
            driver.quit()

# Funciones auxiliares de análisis
def detectar_seguridad_cabeceras(cabeceras):
    resultado = "[*] Analizando cabeceras HTTP...\n"
    if "server" in cabeceras:
        resultado += f"[*] Servidor: {cabeceras['server']}\n"
    if "cloudflare" in cabeceras.get("server", "").lower():
        resultado += "[!] Cloudflare detectado en cabecera 'Server'\n"
    if "x-akamai" in cabeceras or "akamai" in str(cabeceras).lower():
        resultado += "[!] Akamai detectado en cabeceras\n"
    return resultado

def detectar_seguridad_contenido(texto, soup):
    resultado = "[*] Analizando contenido HTML...\n"
    if "cloudflare" in texto or "cf-" in texto:
        resultado += "[!] Cloudflare detectado en el contenido\n"
    if "recaptcha" in texto or soup.find("script", src=lambda x: x and "recaptcha" in x):
        resultado += "[!] reCAPTCHA detectado\n"
    if not any(x in texto for x in ["cloudflare", "recaptcha"]):
        resultado += "[+] No se detectaron protecciones obvias\n"
    return resultado

def detectar_2fa(texto, soup):
    resultado = "[*] Buscando indicios de 2FA...\n"
    pistas_2fa = ["two-factor", "2fa", "verification code", "enter the code", "sms", "phone"]
    if any(pista in texto for pista in pistas_2fa):
        resultado += "[!] Posible 2FA detectado\n"
    else:
        resultado += "[+] No se encontraron indicios de 2FA\n"
    return resultado

def detectar_checkout(texto, soup):
    resultado = "[*] Buscando indicios de checkout...\n"
    pistas_checkout = ["checkout", "payment", "cart", "pago", "order"]
    if any(pista in texto for pista in pistas_checkout):
        resultado += "[!] Posible checkout detectado\n"
    else:
        resultado += "[+] No se encontraron indicios de checkout\n"
    return resultado

def tiene_seguridad(texto, soup, cabeceras):
    aseguridades = ["cloudflare", "recaptcha", "two-factor", "2fa", "verification", "checkout", "payment"]
    return any(s in texto for s in aseguridades) or "cloudflare" in cabeceras.get("server", "").lower()

def es_url_valida(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except ValueError:
        return False

# Ruta principal con HTML embebido
HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analizador de URLs</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        pre { white-space: pre-wrap; }
        .segura { color: red; }
        .vulnerable { color: green; }
    </style>
</head>
<body class="bg-dark text-white">
    <div class="container mt-5">
        <h1 class="text-center">Analizador de URLs</h1>
        <p class="text-center">Echo por @Chiamaru</p>
        
        <form method="post" enctype="multipart/form-data" class="mt-4">
            <div class="mb-3">
                <label for="urls_manual" class="form-label">Pega URLs aquí (una por línea):</label>
                <textarea class="form-control" id="urls_manual" name="urls_manual" rows="3" placeholder="Ejemplo:
https://ejemplo.com
https://otro.com"></textarea>
            </div>
            <div class="mb-3">
                <label for="file" class="form-label">O sube un archivo (.txt) para más URLs:</label>
                <input type="file" class="form-control" id="file" name="file" accept=".txt">
            </div>
            <button type="submit" class="btn btn-primary w-100">Analizar</button>
        </form>
        
        {% if error %}
            <div class="alert alert-danger mt-3">{{ error }}</div>
        {% endif %}
        
        {% if resultados %}
            <div class="mt-4">
                <h3>Resultados</h3>
                <table class="table table-dark">
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Análisis</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for resultado in resultados %}
                            <tr>
                                <td class="{% if resultado.segura %}segura{% else %}vulnerable{% endif %}">
                                    {{ resultado.url }}
                                </td>
                                <td><pre>{{ resultado.resultado }}</pre></td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    resultados = []
    error = None
    
    if request.method == 'POST':
        urls = []
        
        # Opción 1: URLs pegadas manualmente
        urls_manual = request.form.get('urls_manual', '').strip()
        if urls_manual:
            urls.extend([url.strip() for url in urls_manual.splitlines() if url.strip()])
        
        # Opción 2: Archivo subido
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename:
                urls.extend([line.strip() for line in file.read().decode('utf-8').splitlines() if line.strip()])
        
        if not urls:
            error = "No se proporcionaron URLs ni archivo."
        else:
            for url in urls:
                if not es_url_valida(url):
                    resultados.append({"url": url, "resultado": "URL inválida: falta esquema (http/https)", "segura": False})
                    continue
                
                resultado_pasivo, seguridad_pasiva, soup, texto = analizar_url_pasivo(url)
                resultado_selenium = ""
                if not seguridad_pasiva or "2fa" in texto or "checkout" in texto:
                    resultado_selenium, seguridad_selenium = analizar_url_selenium(url)
                    seguridad_pasiva = seguridad_pasiva or seguridad_selenium
                
                resultado_total = resultado_pasivo + resultado_selenium
                resultados.append({"url": url, "resultado": resultado_total, "segura": seguridad_pasiva})

    return render_template_string(HTML, resultados=resultados, error=error)

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
