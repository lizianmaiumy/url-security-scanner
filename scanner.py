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

def extrair_dominio(url):
    """Extrai apenas o domínio limpo da URL (ex: 'https://github.com/teste' -> 'github.com')."""
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

def verificar_certificado_ssl(dominio):
    print(f"\n[+] Verificando Certificado SSL/TLS para: {dominio}")
    
    contexto = ssl.create_default_context()
    
    try:
        with socket.create_connection((dominio, 443), timeout=5) as sock:
            # Envelopa o socket com a camada criptográfica TLS
            with contexto.wrap_socket(sock, server_hostname=dominio) as ssock:
                certificado = ssock.getpeercert()
                
                formato_data = r"%b %d %H:%M:%S %Y %Z"
                data_expiracao_str = certificado["notAfter"]
                data_expiracao = datetime.strptime(data_expiracao_str, formato_data).replace(tzinfo=timezone.utc)
                
                agora = datetime.now(timezone.utc)
                dias_restantes = (data_expiracao - agora).days
                
                print(f"  - Emitido para: {dominio}")
                print(f"  - Expira em: {data_expiracao.strftime('%d/%m/%Y às %H:%M UTC')}")
                
                if dias_restantes < 0:
                    print(f"  - Status: [PERIGO] Certificado EXPIRADO há {abs(dias_restantes)} dias!")
                elif dias_restantes < 15:
                    print(f"  - Status: [ALERTA] Certificado expira em breve ({dias_restantes} dias restantes)!")
                else:
                    print(f"  - Status: [OK] Válido por mais {dias_restantes} dias.")
                    
    except Exception as erro:
        print(f"  - [ERRO] Não foi possível verificar o certificado SSL: {erro}")

def verificar_cabecalhos(url):
    print(f"\n[+] Analisando cabeçalhos de segurança para: {url}")
    try:
        resposta = requests.get(url, timeout=5)
        print(f"Status HTTP: {resposta.status_code} ({resposta.reason})")
        
        cabecalhos_recebidos = resposta.headers
        print("\n--- Relatório de Cabeçalhos ---")
        for header in HEADERS_DE_SEGURANCA:
            if header in cabecalhos_recebidos:
                print(f"[OK] {header}: PRESENTE")
            else:
                print(f"[FALHA] {header}: AUSENTE")
    except requests.exceptions.RequestException as erro:
        print(f"[ERRO] Falha ao conectar ao servidor: {erro}")

if __name__ == "__main__":
    print("=" * 50)
    print("      VALIDADOR DE SEGURANÇA WEB (CLI)      ")
    print("=" * 50)
    
    entrada = input("\nDigite o domínio ou URL para analisar (ex: github.com): ").strip()
    
    if not entrada:
        print("[ERRO] Nenhuma URL informada. Encerrando.")
    else:
        if not entrada.startswith("http://") and not entrada.startswith("https://"):
            url_alvo = f"https://{entrada}"
        else:
            url_alvo = entrada
            
        verificar_cabecalhos(url_alvo)
        
        dominio_alvo = extrair_dominio(url_alvo)
        verificar_certificado_ssl(dominio_alvo)
        
        print("\n" + "=" * 50)
        print("Análise concluída com sucesso.")