<#
.SYNOPSIS
    Verificar se o sistema está pronto para o detector

.DESCRIPTION
    Script para verificar todos os pré-requisitos
#>

Write-Host "🔍 VERIFICADOR DE SISTEMA" -ForegroundColor Cyan
Write-Host "=" * 50 + "`n"

$allGood = $true

# 1. Verificar Python
Write-Host "1. Verificando Python..." -NoNewline
try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python 3\.[8-9]|Python 3\.1[0-9]") {
        Write-Host " ✅" -ForegroundColor Green
        Write-Host "   Versão: $pythonVersion"
    }
    else {
        Write-Host " ❌" -ForegroundColor Red
        Write-Host "   Python 3.8+ necessário. Versão atual: $pythonVersion"
        $allGood = $false
    }
}
catch {
    Write-Host " ❌" -ForegroundColor Red
    Write-Host "   Erro ao verificar Python: $_"
    $allGood = $false
}