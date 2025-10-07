Write-Host "🛡️ INSTALADOR OTIMIZADO DO SYSMON PARA MALWARE POLIMÓRFICO" -ForegroundColor Cyan
Write-Host "=" * 70

# Verificar privilégios de administrador
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ Este script precisa ser executado como Administrador!" -ForegroundColor Red
    Write-Host "Clique com botão direito e selecione 'Executar como Administrador'" -ForegroundColor Yellow
    pause
    exit
}

Write-Host "🎯 Configuração otimizada para detectar:" -ForegroundColor Yellow
Write-Host "   • Malware polimórfico" -ForegroundColor White
Write-Host "   • Comunicação com IA" -ForegroundColor White
Write-Host "   • Injeção de código em memória" -ForegroundColor White
Write-Host "   • Manipulação de processos" -ForegroundColor White
Write-Host ""

# Criar diretório
$sysmonPath = "C:\Sysmon"
Write-Host "📁 Criando diretório: $sysmonPath"
New-Item -Path $sysmonPath -ItemType Directory -Force | Out-Null

# Verificar se Sysmon já está instalado
$sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
if ($sysmonService) {
    Write-Host "⚠️ Sysmon já está instalado. Atualizando configuração..." -ForegroundColor Yellow
    $updateOnly = $true
} else {
    $updateOnly = $false
}

# Download Sysmon se necessário
if (-not $updateOnly) {
    Write-Host "⬇️ Baixando Sysmon..."
    try {
        $url = "https://download.sysinternals.com/files/Sysmon.zip"
        $output = "$sysmonPath\Sysmon.zip"
        
        # Progress bar for download
        $progressPreference = 'Continue'
        Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing
        Write-Host "✅ Download concluído" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Erro no download: $_" -ForegroundColor Red
        pause
        exit
    }

    # Extrair
    Write-Host "📦 Extraindo arquivos..."
    Expand-Archive -Path "$sysmonPath\Sysmon.zip" -DestinationPath $sysmonPath -Force
}

# Criar configuração otimizada para malware polimórfico
Write-Host "⚙️ Criando configuração otimizada para malware polimórfico..."
$config = @"
<?xml version="1.0" encoding="UTF-8"?>
<Sysmon schemaversion="4.90">
  <!-- 
  CONFIGURAÇÃO OTIMIZADA PARA DETECÇÃO DE MALWARE POLIMÓRFICO
  Especialmente projetada para capturar:
  - Comunicação com APIs de IA
  - Injeção de código em memória  
  - Execução dinâmica de código
  - Manipulação de processos
  -->
  
  <HashAlgorithms>md5,sha256,imphash</HashAlgorithms>
  <CheckRevocation/>
  <ArchiveDirectory>C:\Sysmon\Archive</ArchiveDirectory>
  <CopyOnDeletePE/>
  
  <EventFiltering>
    
    <!-- Event ID 1: Process Creation - Capturar TODOS os processos -->
    <ProcessCreate onmatch="exclude">
      <!-- Excluir apenas processos muito comuns e seguros -->
      <Image condition="is">C:\Windows\System32\conhost.exe</Image>
      <Image condition="is">C:\Windows\System32\dllhost.exe</Image>
      <ParentImage condition="is">C:\Windows\System32\services.exe</ParentImage>
      <ParentImage condition="is">C:\Windows\System32\lsass.exe</ParentImage>
    </ProcessCreate>
    
    <!-- Event ID 2: File creation time changed - Importante para evasão -->
    <FileCreateTime onmatch="include">
      <TargetFilename condition="end with">.exe</TargetFilename>
      <TargetFilename condition="end with">.dll</TargetFilename>
      <TargetFilename condition="end with">.sys</TargetFilename>
      <TargetFilename condition="end with">.scr</TargetFilename>
    </FileCreateTime>
    
    <!-- Event ID 3: Network Connection - CRÍTICO para comunicação IA -->
    <NetworkConnect onmatch="exclude">
      <!-- Excluir apenas conexões locais óbvias -->
      <DestinationIp condition="is">127.0.0.1</DestinationIp>
      <DestinationIp condition="is">::1</DestinationIp>
      <SourceImage condition="is">C:\Windows\System32\svchost.exe</SourceImage>
    </NetworkConnect>
    
    <!-- Event ID 5: Process Termination - Para cleanup tracking -->
    <ProcessTerminate onmatch="exclude">
      <Image condition="is">C:\Windows\System32\conhost.exe</Image>
    </ProcessTerminate>
    
    <!-- Event ID 6: Driver Loading - Crítico para rootkits -->
    <DriverLoad onmatch="exclude">
      <Signed condition="is">true</Signed>
    </DriverLoad>
    
    <!-- Event ID 7: Image/DLL Loading - Importante para injeção -->
    <ImageLoad onmatch="include">
      <!-- Capturar DLLs suspeitas e carregamento não autorizado -->
      <ImageLoaded condition="contains">temp</ImageLoaded>
      <ImageLoaded condition="contains">appdata</ImageLoaded>
      <ImageLoaded condition="end with">.dll</ImageLoaded>
      <Signed condition="is">false</Signed>
    </ImageLoad>
    
    <!-- Event ID 8: CreateRemoteThread - CRÍTICO para injeção de código -->
    <CreateRemoteThread onmatch="exclude">
      <!-- Permitir apenas algumas exceções conhecidas -->
      <SourceImage condition="is">C:\Windows\System32\wbem\WmiPrvSE.exe</SourceImage>
      <SourceImage condition="is">C:\Windows\System32\svchost.exe</SourceImage>
      <TargetImage condition="is">C:\Windows\System32\svchost.exe</TargetImage>
    </CreateRemoteThread>
    
    <!-- Event ID 9: RawAccessRead - Detecção de acesso direto ao disco -->
    <RawAccessRead onmatch="exclude">
      <Image condition="is">C:\Windows\System32\svchost.exe</Image>
      <Image condition="is">C:\Windows\System32\defrag.exe</Image>
    </RawAccessRead>
    
    <!-- Event ID 10: Process Access - Acesso a processos críticos -->
    <ProcessAccess onmatch="include">
      <!-- Monitorar acesso a processos críticos -->
      <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
      <TargetImage condition="is">C:\Windows\System32\winlogon.exe</TargetImage>
      <TargetImage condition="is">C:\Windows\System32\csrss.exe</TargetImage>
      <TargetImage condition="is">C:\Windows\System32\services.exe</TargetImage>
      <!-- Também processos do próprio detector -->
      <TargetImage condition="end with">python.exe</TargetImage>
      <TargetImage condition="end with">pythonw.exe</TargetImage>
    </ProcessAccess>
    
    <!-- Event ID 11: File Creation - Arquivos suspeitos -->
    <FileCreate onmatch="include">
      <!-- Executáveis em locais suspeitos -->
      <TargetFilename condition="contains">temp</TargetFilename>
      <TargetFilename condition="contains">appdata</TargetFilename>
      <TargetFilename condition="contains">programdata</TargetFilename>
      <TargetFilename condition="end with">.exe</TargetFilename>
      <TargetFilename condition="end with">.dll</TargetFilename>
      <TargetFilename condition="end with">.scr</TargetFilename>
      <TargetFilename condition="end with">.bat</TargetFilename>
      <TargetFilename condition="end with">.ps1</TargetFilename>
      <TargetFilename condition="end with">.vbs</TargetFilename>
      <TargetFilename condition="end with">.py</TargetFilename>
    </FileCreate>
    
    <!-- Event ID 12/13/14: Registry Events - Persistência -->
    <RegistryEvent onmatch="include">
      <!-- Chaves de inicialização -->
      <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
      <TargetObject condition="contains">CurrentVersion\RunOnce</TargetObject>
      <TargetObject condition="contains">CurrentVersion\RunServices</TargetObject>
      <TargetObject condition="contains">Winlogon</TargetObject>
      <TargetObject condition="contains">Userinit</TargetObject>
      <TargetObject condition="contains">Shell</TargetObject>
      <TargetObject condition="contains">Explorer\Run</TargetObject>
      <!-- Configurações de serviços -->
      <TargetObject condition="contains">Services\</TargetObject>
      <!-- Configurações de políticas -->
      <TargetObject condition="contains">Policies\</TargetObject>
    </RegistryEvent>
    
    <!-- Event ID 15: File Stream Creation -->
    <FileCreateStreamHash onmatch="include">
      <TargetFilename condition="end with">.exe</TargetFilename>
      <TargetFilename condition="end with">.dll</TargetFilename>
    </FileCreateStreamHash>
    
    <!-- Event ID 17/18: Named Pipes - Comunicação inter-processo -->
    <PipeEvent onmatch="exclude">
      <PipeName condition="contains">wkssvc</PipeName>
      <PipeName condition="contains">spoolss</PipeName>
      <PipeName condition="contains">srvsvc</PipeName>
    </PipeEvent>
    
    <!-- Event ID 19/20/21: WMI Events - Persistência e execução -->
    <WmiEvent onmatch="include">
      <!-- Capturar TODOS os eventos WMI - muito usado por malware -->
    </WmiEvent>
    
    <!-- Event ID 22: DNS Queries - CRÍTICO para comunicação IA -->
    <DnsQuery onmatch="include">
      <!-- Capturar consultas para domínios de IA -->
      <QueryName condition="contains">openai</QueryName>
      <QueryName condition="contains">anthropic</QueryName>
      <QueryName condition="contains">claude</QueryName>
      <QueryName condition="contains">googleapis</QueryName>
      <QueryName condition="contains">azure</QueryName>
      <QueryName condition="contains">api</QueryName>
      <QueryName condition="contains">huggingface</QueryName>
      <QueryName condition="contains">cohere</QueryName>
      <QueryName condition="contains">replicate</QueryName>
      <!-- Também domínios suspeitos gerais -->
      <QueryName condition="contains">temp</QueryName>
      <QueryName condition="contains">dyndns</QueryName>
      <QueryName condition="contains">ngrok</QueryName>
    </DnsQuery>
    
    <!-- Event ID 23: File Deletion -->
    <FileDelete onmatch="include">
      <TargetFilename condition="contains">temp</TargetFilename>
      <TargetFilename condition="end with">.exe</TargetFilename>
      <TargetFilename condition="end with">.dll</TargetFilename>
      <TargetFilename condition="end with">.log</TargetFilename>
    </FileDelete>
    
    <!-- Event ID 24: Clipboard Changes -->
    <ClipboardChange onmatch="include">
      <!-- Capturar mudanças suspeitas no clipboard -->
    </ClipboardChange>
    
    <!-- Event ID 25: Process Image Tampering -->
    <ProcessTampering onmatch="include">
      <!-- CRÍTICO - qualquer manipulação de processo -->
    </ProcessTampering>
    
    <!-- Event ID 26: File Delete Logging -->
    <FileDeleteDetected onmatch="include">
      <TargetFilename condition="end with">.exe</TargetFilename>
      <TargetFilename condition="end with">.dll</TargetFilename>
    </FileDeleteDetected>
    
    <!-- Event ID 27: File Block Executable -->
    <FileBlockExecutable onmatch="include">
      <!-- Capturar tentativas de execução bloqueadas -->
    </FileBlockExecutable>
    
    <!-- Event ID 28: File Block Shredding -->
    <FileBlockShredding onmatch="include">
      <!-- Capturar tentativas de destruição de evidência -->
    </FileBlockShredding>
    
    <!-- Event ID 29: File Executable Detected -->
    <FileExecutableDetected onmatch="include">
      <!-- Novos executáveis detectados -->
    </FileExecutableDetected>
    
  </EventFiltering>
</Sysmon>
"@

# Salvar configuração
$configPath = "$sysmonPath\sysmonconfig_polymorphic.xml"
Set-Content -Path $configPath -Value $config -Encoding UTF8
Write-Host "✅ Configuração salva em: $configPath" -ForegroundColor Green

# Instalar ou atualizar Sysmon
Write-Host "🔧 Aplicando configuração otimizada..."
try {
    if ($updateOnly) {
        # Apenas atualizar configuração
        $updateCmd = "sysmon -c `"$configPath`""
        Invoke-Expression $updateCmd
        Write-Host "✅ Configuração Sysmon atualizada!" -ForegroundColor Green
    } else {
        # Instalação completa
        $installCmd = "$sysmonPath\Sysmon64.exe -accepteula -i `"$configPath`""
        Invoke-Expression $installCmd
        Write-Host "✅ Sysmon instalado com configuração otimizada!" -ForegroundColor Green
    }
}
catch {
    Write-Host "❌ Erro na instalação/atualização: $_" -ForegroundColor Red
    pause
    exit
}

# Verificar instalação
Write-Host "`n📊 Verificando configuração..."
$service = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue

if ($service -and $service.Status -eq "Running") {
    Write-Host "✅ Serviço Sysmon está rodando!" -ForegroundColor Green
    Write-Host "   Nome do serviço: $($service.Name)" -ForegroundColor Gray
    Write-Host "   Status: $($service.Status)" -ForegroundColor Gray
    
    # Aguardar alguns eventos
    Write-Host "`n⏳ Aguardando geração de eventos..." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    
    # Verificar eventos por tipo
    Write-Host "`n🔍 Verificando tipos de eventos capturados..."
    
    $eventTypes = @(1, 2, 3, 5, 7, 8, 10, 11, 12, 13, 14, 22, 25)
    $capturedTypes = @()
    
    foreach ($eventType in $eventTypes) {
        try {
            $events = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=$eventType} -MaxEvents 1 -ErrorAction SilentlyContinue
            if ($events) {
                $capturedTypes += $eventType
            }
        } catch {}
    }
    
    if ($capturedTypes.Count -gt 0) {
        Write-Host "✅ Eventos sendo capturados:" -ForegroundColor Green
        foreach ($type in $capturedTypes) {
            $eventName = switch ($type) {
                1 { "Process Create" }
                2 { "File Time Change" }
                3 { "Network Connect" }
                5 { "Process Terminate" }
                7 { "Image Load" }
                8 { "CreateRemoteThread" }
                10 { "Process Access" }
                11 { "File Create" }
                12 { "Registry Create" }
                13 { "Registry Set" }
                14 { "Registry Rename" }
                22 { "DNS Query" }
                25 { "Process Tampering" }
                default { "Unknown" }
            }
            Write-Host "   • ID $type - $eventName" -ForegroundColor White
        }
    } else {
        Write-Host "⚠️ Nenhum evento capturado ainda (isso é normal nos primeiros minutos)" -ForegroundColor Yellow
    }
    
    # Estatísticas gerais
    try {
        $totalEvents = (Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 100 -ErrorAction SilentlyContinue).Count
        Write-Host "📈 Total de eventos recentes: $totalEvents" -ForegroundColor Cyan
    } catch {
        Write-Host "📈 Log de eventos inicializando..." -ForegroundColor Cyan
    }
    
} else {
    Write-Host "❌ Serviço não está rodando!" -ForegroundColor Red
    Write-Host "Tente executar novamente o script" -ForegroundColor Yellow
}

# Criar arquivo de backup da configuração
$backupPath = "$sysmonPath\sysmonconfig_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
Copy-Item -Path $configPath -Destination $backupPath
Write-Host "💾 Backup da configuração salvo em: $backupPath" -ForegroundColor Gray

Write-Host "`n" + "=" * 70
Write-Host "🎉 SYSMON OTIMIZADO PARA MALWARE POLIMÓRFICO!" -ForegroundColor Green
Write-Host "=" * 70

Write-Host "`n🎯 Configuração otimizada para detectar:" -ForegroundColor Yellow
Write-Host "   • Comunicação com APIs de IA (OpenAI, Anthropic, etc.)" -ForegroundColor White
Write-Host "   • Injeção de código (CreateRemoteThread)" -ForegroundColor White
Write-Host "   • Manipulação de processos" -ForegroundColor White
Write-Host "   • Execução em memória" -ForegroundColor White
Write-Host "   • DNS queries suspeitas" -ForegroundColor White
Write-Host "   • Persistência via registry" -ForegroundColor White
Write-Host "   • Criação de arquivos suspeitos" -ForegroundColor White

Write-Host "`n📋 Próximos passos:" -ForegroundColor Cyan
Write-Host "1. Execute o detector otimizado:" -ForegroundColor White
Write-Host "   cd app" -ForegroundColor Gray
Write-Host "   python detection_sistem.py --model ../Tentativa2/optimized_malware_detector.joblib --config config_polymorphic.json --debug" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Para testar o sistema:" -ForegroundColor White
Write-Host "   python test_detector.py" -ForegroundColor Gray
Write-Host ""

pause