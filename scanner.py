import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

HEADERS_DE_SEGURANCA = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]

def extrair_dominio(url: str) -> str:
    """Extrai apenas o domínio limpo da URL."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

def verificar_cabecalhos(url: str) -> dict:
    """Retorna um dicionário com o status de cada cabeçalho de segurança."""
    resultados = {}
    try:
        resposta = requests.get(url, timeout=5)
        cabecalhos_recebidos = {k.lower(): v for k, v in resposta.headers.items()}
        for header in HEADERS_DE_SEGURANCA:
            resultados[header] = header.lower() in cabecalhos_recebidos
        return resultados
    except requests.exceptions.RequestException:
        return {}

def verificar_certificado_ssl(dominio: str) -> dict:
    """Retorna dados de expiração e dias restantes do certificado SSL/TLS."""
    contexto = ssl.create_default_context()
    try:
        with socket.create_connection((dominio, 443), timeout=5) as sock:
            with contexto.wrap_socket(sock, server_hostname=dominio) as ssock:
                certificado = ssock.getpeercert()
                formato_data = r"%b %d %H:%M:%S %Y %Z"
                data_expiracao = datetime.strptime(certificado["notAfter"], formato_data).replace(tzinfo=timezone.utc)
                agora = datetime.now(timezone.utc)
                dias_restantes = (data_expiracao - agora).days
                return {
                    "valido": True,
                    "expira_em": data_expiracao,
                    "dias_restantes": dias_restantes
                }
    except Exception as erro:
        return {
            "valido": False,
            "erro": str(erro)
        }

if __name__ == "__main__":
    print("=" * 50)
    print("      VALIDADOR DE SEGURANÇA WEB (CLI)      ")
    print("=" * 50)
    entrada = input("\nDigite o domínio ou URL para analisar (ex: github.com): ").strip()
    if not entrada:
        print("[ERRO] Nenhuma URL informada. Encerrando.")
    else:
        url_alvo = f"https://{entrada}" if not entrada.startswith(("http://", "https://")) else entrada
        
        print(f"\n[+] Analisando cabeçalhos para: {url_alvo}")
        cabecalhos = verificar_cabecalhos(url_alvo)
        for h, presente in cabecalhos.items():
            print(f"[{'OK' if presente else 'FALHA'}] {h}: {'PRESENTE' if presente else 'AUSENTE'}")
            
        dominio_alvo = extrair_dominio(url_alvo)
        print(f"\n[+] Verificando Certificado SSL/TLS para: {dominio_alvo}")
        ssl_info = verificar_certificado_ssl(dominio_alvo)
        if ssl_info.get("valido"):
            dias = ssl_info["dias_restantes"]
            print(f"  - Expira em: {ssl_info['expira_em'].strftime('%d/%m/%Y às %H:%M UTC')}")
            print(f"  - Status: {'[OK]' if dias > 15 else '[ALERTA]'} Válido por mais {dias} dias.")
        else:
            print(f"  - [ERRO] {ssl_info.get('erro')}")