<#
.SYNOPSIS
    Verificador otimizado para detecção de malware polimórfico

.DESCRIPTION
    Script avançado para verificar todos os pré-requisitos e configurações
    específicas para detecção de malware polimórfico
#>

Write-Host "🔍 VERIFICADOR DE SISTEMA - DETECTOR DE MALWARE POLIMÓRFICO" -ForegroundColor Cyan
Write-Host "=" * 70 + "`n"

$allGood = $true
$warnings = @()
$recommendations = @()

# Função para testar conectividade
function Test-NetworkConnectivity {
    param([string]$url)
    try {
        $response = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# 1. Verificar privilégios administrativos
Write-Host "1. Verificando privilégios administrativos..." -NoNewline
if ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") {
    Write-Host " ✅" -ForegroundColor Green
    Write-Host "   Executando como Administrador"
} else {
    Write-Host " ❌" -ForegroundColor Red
    Write-Host "   ERRO: Não está executando como Administrador"
    Write-Host "   Algumas verificações serão limitadas"
    $allGood = $false
}

# 2. Verificar Python
Write-Host "`n2. Verificando Python..." -NoNewline
try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python 3\.[8-9]|Python 3\.1[0-9]") {
        Write-Host " ✅" -ForegroundColor Green
        Write-Host "   Versão: $pythonVersion"
        
        # Verificar pip
        $pipVersion = pip --version 2>&1
        Write-Host "   Pip: $pipVersion"
        
    } else {
        Write-Host " ⚠️" -ForegroundColor Yellow
        Write-Host "   Python 3.8+ recomendado. Versão atual: $pythonVersion"
        $warnings += "Versão do Python pode causar problemas de compatibilidade"
    }
} catch {
    Write-Host " ❌" -ForegroundColor Red
    Write-Host "   Erro ao verificar Python: $_"
    $allGood = $false
}

# 3. Verificar dependências Python
Write-Host "`n3. Verificando dependências Python..."
$requiredPackages = @(
    @{Name="joblib"; ImportName="joblib"},
    @{Name="psutil"; ImportName="psutil"},
    @{Name="pywin32"; ImportName="win32evtlog"},
    @{Name="scikit-learn"; ImportName="sklearn"},
    @{Name="numpy"; ImportName="numpy"},
    @{Name="pandas"; ImportName="pandas"}
)

foreach ($package in $requiredPackages) {
    Write-Host "   Verificando $($package.Name)..." -NoNewline
    try {
        $result = python -c "import $($package.ImportName); print('OK')" 2>&1
        if ($result -eq "OK") {
            Write-Host " ✅" -ForegroundColor Green
        } else {
            Write-Host " ❌" -ForegroundColor Red
            Write-Host "     Erro: $result"
            $allGood = $false
        }
    } catch {
        Write-Host " ❌" -ForegroundColor Red
        Write-Host "     Erro ao importar: $_"
        $allGood = $false
    }
}

# 4. Verificar Sysmon
Write-Host "`n4. Verificando Sysmon..."
$sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue

if ($sysmonService) {
    Write-Host "   Serviço Sysmon..." -NoNewline
    if ($sysmonService.Status -eq "Running") {
        Write-Host " ✅" -ForegroundColor Green
        Write-Host "   Nome: $($sysmonService.Name)"
        Write-Host "   Status: $($sysmonService.Status)"
        Write-Host "   Tipo de início: $($sysmonService.StartType)"
        
        # Verificar eventos Sysmon
        Write-Host "   Verificando eventos Sysmon..." -NoNewline
        try {
            $recentEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 -ErrorAction SilentlyContinue
            if ($recentEvents) {
                Write-Host " ✅" -ForegroundColor Green
                Write-Host "   Eventos recentes: $($recentEvents.Count)"
                
                # Verificar tipos de eventos específicos para malware polimórfico
                $criticalEventTypes = @(1, 3, 7, 8, 10, 11, 22, 25)
                $foundEventTypes = @()
                
                foreach ($eventType in $criticalEventTypes) {
                    $typeEvents = $recentEvents | Where-Object { $_.Id -eq $eventType }
                    if ($typeEvents) {
                        $foundEventTypes += $eventType
                    }
                }
                
                Write-Host "   Tipos de eventos críticos encontrados: $($foundEventTypes -join ', ')"
                
                if ($foundEventTypes.Count -lt 4) {
                    $warnings += "Poucos tipos de eventos críticos sendo capturados"
                    $recommendations += "Execute atividade no sistema para gerar mais eventos"
                }
                
            } else {
                Write-Host " ⚠️" -ForegroundColor Yellow
                Write-Host "   Nenhum evento recente (normal após instalação)"
            }
        } catch {
            Write-Host " ❌" -ForegroundColor Red
            Write-Host "   Erro ao acessar log: $_"
            $allGood = $false
        }
        
    } else {
        Write-Host " ❌" -ForegroundColor Red
        Write-Host "   Serviço não está rodando: $($sysmonService.Status)"
        $allGood = $false
    }
} else {
    Write-Host "   Serviço Sysmon... ❌" -ForegroundColor Red
    Write-Host "   Sysmon não está instalado"
    $allGood = $false
    $recommendations += "Execute: scripts\install_sysmon_optimized.ps1"
}

# 5. Verificar modelo de ML
Write-Host "`n5. Verificando modelo de Machine Learning..."
$modelPath = "Tentativa2\optimized_malware_detector.joblib"
Write-Host "   Verificando $modelPath..." -NoNewline

if (Test-Path $modelPath) {
    Write-Host " ✅" -ForegroundColor Green
    
    # Verificar tamanho do arquivo
    $modelSize = (Get-Item $modelPath).Length / 1MB
    Write-Host "   Tamanho: $([math]::Round($modelSize, 2)) MB"
    
    # Testar carregamento do modelo
    Write-Host "   Testando carregamento..." -NoNewline
    try {
        $loadTest = python -c "import joblib; model = joblib.load('$modelPath'); print('OK')" 2>&1
        if ($loadTest -eq "OK") {
            Write-Host " ✅" -ForegroundColor Green
        } else {
            Write-Host " ❌" -ForegroundColor Red
            Write-Host "     Erro no carregamento: $loadTest"
            $allGood = $false
        }
    } catch {
        Write-Host " ❌" -ForegroundColor Red
        Write-Host "     Erro: $_"
        $allGood = $false
    }
    
} else {
    Write-Host " ❌" -ForegroundColor Red
    Write-Host "   Modelo não encontrado em: $modelPath"
    $allGood = $false
    $recommendations += "Verifique se o modelo está na pasta Tentativa2"
}

# 6. Verificar configuração do detector
Write-Host "`n6. Verificando configuração do detector..."
$configPath = "app\config_polymorphic.json"
Write-Host "   Verificando $configPath..." -NoNewline

if (Test-Path $configPath) {
    Write-Host " ✅" -ForegroundColor Green
    
    try {
        $config = Get-Content $configPath | ConvertFrom-Json
        Write-Host "   Threshold: $($config.detection_threshold)"
        Write-Host "   Análise a cada: $($config.analysis_interval) segundos"
        Write-Host "   Eventos Sysmon: $($config.sysmon_events.Count)"
        Write-Host "   Palavras-chave IA: $($config.polymorphic_detection.ai_keywords.Count)"
        
        if ($config.detection_threshold -gt 0.7) {
            $warnings += "Threshold muito alto para modelo com 62% accuracy"
            $recommendations += "Considere threshold entre 0.4-0.6"
        }
        
    } catch {
        Write-Host " ❌" -ForegroundColor Red
        Write-Host "     Erro ao parsear JSON: $_"
        $allGood = $false
    }
    
} else {
    Write-Host " ❌" -ForegroundColor Red
    Write-Host "   Configuração não encontrada"
    $allGood = $false
    $recommendations += "Execute o detector otimizado para criar configuração"
}

# 7. Verificar conectividade de rede (para detectar comunicação IA)
Write-Host "`n7. Verificando conectividade para APIs de IA..."
$aiDomains = @("api.openai.com", "api.anthropic.com", "googleapis.com")
$connectedDomains = @()

foreach ($domain in $aiDomains) {
    Write-Host "   Testando $domain..." -NoNewline
    if (Test-NetworkConnectivity "https://$domain") {
        Write-Host " ✅" -ForegroundColor Green
        $connectedDomains += $domain
    } else {
        Write-Host " ⚠️" -ForegroundColor Yellow
    }
}

if ($connectedDomains.Count -eq 0) {
    $warnings += "Sem conectividade com APIs de IA - pode afetar detecção"
} else {
    Write-Host "   Conectividade IA: $($connectedDomains.Count)/$($aiDomains.Count) domínios"
}

# 8. Verificar recursos do sistema
Write-Host "`n8. Verificando recursos do sistema..."
$os = Get-WmiObject -Class Win32_OperatingSystem
$cpu = Get-WmiObject -Class Win32_Processor
$memory = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
$freeMemory = [math]::Round($os.FreePhysicalMemory / 1MB, 2)

Write-Host "   SO: $($os.Caption) $($os.OSArchitecture)"
Write-Host "   CPU: $($cpu.Name)"
Write-Host "   Memória Total: $memory GB"
Write-Host "   Memória Livre: $freeMemory GB"

if ($freeMemory -lt 2) {
    $warnings += "Pouca memória livre - pode afetar performance"
    $recommendations += "Feche aplicações desnecessárias"
}

# 9. Verificar espaço em disco
Write-Host "`n9. Verificando espaço em disco..."
$disk = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "C:" }
$freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
$totalSpaceGB = [math]::Round($disk.Size / 1GB, 2)

Write-Host "   Disco C: $freeSpaceGB GB livres de $totalSpaceGB GB total"

if ($freeSpaceGB -lt 5) {
    $warnings += "Pouco espaço em disco - logs podem ser afetados"
    $recommendations += "Libere espaço em disco"
}

# 10. Verificar Windows Event Log
Write-Host "`n10. Verificando Windows Event Log..."
Write-Host "    Testando acesso ao Event Log..." -NoNewline
try {
    $testEvent = Get-WinEvent -LogName "System" -MaxEvents 1 -ErrorAction Stop
    Write-Host " ✅" -ForegroundColor Green
} catch {
    Write-Host " ❌" -ForegroundColor Red
    Write-Host "     Erro: $_"
    $allGood = $false
}

# Resumo final
Write-Host "`n" + "=" * 70
Write-Host "📊 RESUMO DA VERIFICAÇÃO" -ForegroundColor Cyan
Write-Host "=" * 70

if ($allGood -and $warnings.Count -eq 0) {
    Write-Host "🎉 SISTEMA PRONTO PARA DETECÇÃO DE MALWARE POLIMÓRFICO!" -ForegroundColor Green
    Write-Host ""
    Write-Host "✅ Todos os requisitos atendidos"
    Write-Host "✅ Configuração otimizada"
    Write-Host "✅ Sysmon configurado corretamente"
    Write-Host ""
    Write-Host "🚀 Execute o detector:" -ForegroundColor Cyan
    Write-Host "   cd app"
    Write-Host "   python detection_sistem.py --model ../Tentativa2/optimized_malware_detector.joblib --config config_polymorphic.json --debug"
    
} elseif ($allGood -and $warnings.Count -gt 0) {
    Write-Host "⚠️ SISTEMA FUNCIONAL COM AVISOS" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "✅ Requisitos básicos atendidos"
    Write-Host "⚠️ $($warnings.Count) aviso(s) encontrado(s):"
    foreach ($warning in $warnings) {
        Write-Host "   • $warning" -ForegroundColor Yellow
    }
    
} else {
    Write-Host "❌ SISTEMA NÃO ESTÁ PRONTO" -ForegroundColor Red
    Write-Host ""
    Write-Host "❌ Problemas críticos encontrados"
    Write-Host "🔧 Corrija os problemas antes de executar o detector"
}

if ($recommendations.Count -gt 0) {
    Write-Host ""
    Write-Host "💡 RECOMENDAÇÕES:" -ForegroundColor Cyan
    foreach ($rec in $recommendations) {
        Write-Host "   • $rec" -ForegroundColor White
    }
}

Write-Host ""
Write-Host "📋 Para mais informações, consulte:" -ForegroundColor Gray
Write-Host "   • app\README_MELHORIAS.md"
Write-Host "   • scripts\ANALISE_SYSMON.md"
Write-Host ""

pause