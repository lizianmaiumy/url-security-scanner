import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests
import sys
import ctypes

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

console = Console()

HEADERS_DE_SEGURANCA = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]

def configurar_icone_janela():
    """Aplica o ícone da aplicação na barra de título da consola Windows."""
    if sys.platform != "win32":
        return
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if not hwnd:
            return

        h_instance = ctypes.windll.kernel32.GetModuleHandleW(None)

        IMAGE_ICON = 1
        LR_DEFAULTSIZE = 0x0040
        h_icon = ctypes.windll.user32.LoadImageW(h_instance, 1, IMAGE_ICON, 0, 0, LR_DEFAULTSIZE)

        if h_icon:
            WM_SETICON = 0x0080
            ICON_SMALL = 0
            ICON_BIG = 1
            ctypes.windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, h_icon)
            ctypes.windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, h_icon)
    except Exception:
        pass

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

def exibir_banner():
    texto_banner = "[bold cyan]WEB SECURITY & SSL/TLS VALIDATOR[/bold cyan]\n[dim]Auditoria rápida de cabeçalhos OWASP e ciclo de certificados TLS[/dim]"
    console.print(Panel(texto_banner, style="cyan", expand=False))

def exibir_tabela_cabecalhos(cabecalhos: dict):
    tabela = Table(title="Cabeçalhos de Segurança (OWASP)", show_header=True, header_style="bold magenta")
    tabela.add_column("Cabeçalho", style="dim", width=30)
    tabela.add_column("Status", justify="center")
    tabela.add_column("Diagnóstico", justify="left")

    if not cabecalhos:
        console.print("[bold red][!] Falha ao conectar ao servidor para inspecionar cabeçalhos.[/bold red]")
        return

    for header, presente in cabecalhos.items():
        if presente:
            tabela.add_row(header, "[bold green]✔ PRESENTE[/bold green]", "Mitigação ativa")
        else:
            tabela.add_row(header, "[bold red]✖ AUSENTE[/bold red]", "Vulnerável a exploração")

    console.print(tabela)

def exibir_card_ssl(ssl_info: dict, dominio: str):
    if not ssl_info.get("valido"):
        console.print(Panel(f"[bold red]Erro na inspeção SSL/TLS:[/bold red] {ssl_info.get('erro')}", title="Certificado SSL/TLS", border_style="red"))
        return

    dias = ssl_info["dias_restantes"]
    data_fmt = ssl_info["expira_em"].strftime("%d/%m/%Y às %H:%M UTC")

    if dias < 0:
        cor = "red"
        status = f"[bold red]EXPIRADO há {abs(dias)} dias[/bold red]"
    elif dias < 15:
        cor = "yellow"
        status = f"[bold yellow]ALERTA: Expira em breve ({dias} dias restantes)[/bold yellow]"
    else:
        cor = "green"
        status = f"[bold green]OK: Válido por mais {dias} dias[/bold green]"

    conteudo = f"[b]Domínio:[/b] {dominio}\n[b]Expiração:[/b] {data_fmt}\n[b]Diagnóstico:[/b] {status}"
    console.print(Panel(conteudo, title="Certificado SSL/TLS", border_style=cor))

if __name__ == "__main__":
    configurar_icone_janela()
    exibir_banner()
    
    entrada = Prompt.ask("\n[bold yellow]?[/bold yellow] Digite o domínio ou URL para analisar").strip()
    
    if not entrada:
        console.print("[red]Nenhuma URL informada. A terminar.[/red]")
    else:
        url_alvo = f"https://{entrada}" if not entrada.startswith(("http://", "https://")) else entrada
        dominio_alvo = extrair_dominio(url_alvo)

        with console.status(f"[bold green]A analisar {dominio_alvo}...[/bold green]"):
            cabecalhos = verificar_cabecalhos(url_alvo)
            ssl_info = verificar_certificado_ssl(dominio_alvo)

        console.print()
        exibir_tabela_cabecalhos(cabecalhos)
        console.print()
        exibir_card_ssl(ssl_info, dominio_alvo)

        Prompt.ask("\n[dim]Pressione Enter para fechar...[/dim]", default="")