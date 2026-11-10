from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
import requests
from scanner import extrair_dominio, verificar_cabecalhos, verificar_certificado_ssl

def test_extrair_dominio_com_https():
    url = "https://github.com/teste/repositorio"
    assert extrair_dominio(url) == "github.com"

def test_extrair_dominio_sem_esquema():
    url = "exemplo.com.br"
    assert extrair_dominio(url) == "exemplo.com.br"

def test_extrair_dominio_com_porta():
    url = "https://localhost:8080/api"
    assert extrair_dominio(url) == "localhost:8080"

@patch("scanner.requests.get")
def test_verificar_cabecalhos_presentes(mock_get):
    resposta_falsa = MagicMock()
    resposta_falsa.headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff"
    }
    mock_get.return_value = resposta_falsa

    resultados = verificar_cabecalhos("https://site-seguro.com")
    assert resultados["Strict-Transport-Security"] is True
    assert resultados["Content-Security-Policy"] is True
    assert resultados["X-Frame-Options"] is True
    assert resultados["X-Content-Type-Options"] is True

@patch("scanner.requests.get")
def test_verificar_cabecalhos_falha_conexao(mock_get):
    # Simula erro de conexão/timeout
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")
    resultados = verificar_cabecalhos("https://site-inexistente.com")
    assert resultados == {}

@patch("scanner.ssl.create_default_context")
@patch("scanner.socket.create_connection")
def test_verificar_certificado_ssl_valido(mock_socket, mock_ssl_context):
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = {
        "notAfter": "Dec 31 23:59:59 2030 GMT"
    }
    
    mock_context_instance = MagicMock()
    mock_context_instance.wrap_socket.return_value.__enter__.return_value = mock_ssock
    mock_ssl_context.return_value = mock_context_instance
    
    resultado = verificar_certificado_ssl("github.com")
    assert resultado["valido"] is True
    assert resultado["dias_restantes"] > 0