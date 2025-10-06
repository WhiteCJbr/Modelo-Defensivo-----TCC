Write-Host "🛡️ INSTALADOR AUTOMÁTICO DO SYSMON" -ForegroundColor Cyan
Write-Host "=" * 50

# Verificar privilégios de administrador
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ Este script precisa ser executado como Administrador!" -ForegroundColor Red
    Write-Host "Clique com botão direito e selecione 'Executar como Administrador'" -ForegroundColor Yellow
    pause
    exit
}

# Criar diretório
$sysmonPath = "C:\Sysmon"
Write-Host "📁 Criando diretório: $sysmonPath"
New-Item -Path $sysmonPath -ItemType Directory -Force | Out-Null

# Download Sysmon
Write-Host "⬇️  Baixando Sysmon..."
try {
    $url = "https://download.sysinternals.com/files/Sysmon.zip"
    $output = "$sysmonPath\Sysmon.zip"
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

# Criar configuração
Write-Host "⚙️  Criando configuração..."
$config = @"
<?xml version="1.0" encoding="UTF-8"?>
<Sysmon schemaversion="4.82">
  <HashAlgorithms>md5,sha256</HashAlgorithms>
  <CheckRevocation/>
  
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="end with">exe</Image>
    </ProcessCreate>
    
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">80</DestinationPort>
      <DestinationPort condition="is">443</DestinationPort>
      <DestinationPort condition="is">4444</DestinationPort>
    </NetworkConnect>
    
    <ImageLoad onmatch="include">
      <ImageLoaded condition="end with">dll</ImageLoaded>
    </ImageLoad>
    
    <CreateRemoteThread onmatch="exclude">
      <SourceImage condition="is">C:\Windows\System32\svchost.exe</SourceImage>
    </CreateRemoteThread>
    
    <ProcessAccess onmatch="include">
      <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
    </ProcessAccess>
    
    <FileCreate onmatch="include">
      <TargetFilename condition="end with">exe</TargetFilename>
      <TargetFilename condition="end with">dll</TargetFilename>
    </FileCreate>
    
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
    </RegistryEvent>
  </EventFiltering>
</Sysmon>
"@

Set-Content -Path "$sysmonPath\sysmonconfig.xml" -Value $config -Encoding UTF8

# Instalar Sysmon
Write-Host "🔧 Instalando Sysmon..."
try {
    $installCmd = "$sysmonPath\Sysmon64.exe -accepteula -i $sysmonPath\sysmonconfig.xml"
    Invoke-Expression $installCmd
    Write-Host "✅ Sysmon instalado com sucesso!" -ForegroundColor Green
}
catch {
    Write-Host "❌ Erro na instalação: $_" -ForegroundColor Red
    pause
    exit
}

# Verificar instalação
Write-Host "`n📊 Verificando instalação..."
$service = Get-Service Sysmon64 -ErrorAction SilentlyContinue

if ($service -and $service.Status -eq "Running") {
    Write-Host "✅ Serviço Sysmon64 está rodando!" -ForegroundColor Green
    
    # Testar eventos
    Write-Host "`n🔍 Verificando eventos..."
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction SilentlyContinue
    
    if ($events) {
        Write-Host "✅ Eventos Sysmon sendo capturados!" -ForegroundColor Green
        Write-Host "   Total de eventos recentes: $($events.Count)"
    }
    else {
        Write-Host "⚠️  Nenhum evento capturado ainda (aguarde alguns segundos)" -ForegroundColor Yellow
    }
}
else {
    Write-Host "❌ Serviço não está rodando!" -ForegroundColor Red
}

Write-Host "`n" + "=" * 50
Write-Host "🎉 INSTALAÇÃO CONCLUÍDA!" -ForegroundColor Green
Write-Host "=" * 50
Write-Host "`nPróximos passos:"
Write-Host "1. Configure o detector de malware"
Write-Host "2. Execute: python sysmon_detector.py --model seu_modelo.joblib"
Write-Host ""

pause