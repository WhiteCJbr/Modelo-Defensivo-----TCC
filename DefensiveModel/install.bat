@echo off
REM SCRIPT DE INSTALAÇÃO - MODELO DEFENSIVO
REM Automatiza a instalação de dependências e configuração inicial

echo ================================================
echo MODELO DEFENSIVO - INSTALACAO AUTOMATIZADA
echo Sistema de Detecção de Malware Polimórfico
echo ================================================
echo.

REM Verificar se Python está instalado
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERRO] Python não encontrado! Instale Python 3.8+ primeiro.
    echo Download: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [OK] Python encontrado:
python --version
echo.

REM Verificar se pip está disponível
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERRO] pip não encontrado! Instale pip primeiro.
    pause
    exit /b 1
)

echo [OK] pip encontrado:
pip --version
echo.

REM Criar ambiente virtual (opcional)
set /p create_venv="Criar ambiente virtual? (y/n): "
if /i "%create_venv%"=="y" (
    echo [INFO] Criando ambiente virtual...
    python -m venv modelo_defensivo_env
    call modelo_defensivo_env\Scripts\activate
    echo [OK] Ambiente virtual criado e ativado
    echo.
)

REM Escolher tipo de instalação
echo Escolha o tipo de instalação:
echo 1. Completa (todas as dependências)
echo 2. Mínima (apenas essenciais)
echo 3. Personalizada
echo.
set /p install_type="Digite sua escolha (1-3): "

if "%install_type%"=="1" (
    echo [INFO] Instalando dependências completas...
    pip install -r requirements.txt
) else if "%install_type%"=="2" (
    echo [INFO] Instalando dependências mínimas...
    pip install -r requirements-minimal.txt
) else if "%install_type%"=="3" (
    echo [INFO] Instalação personalizada...
    echo Instalando dependências essenciais primeiro...
    pip install -r requirements-minimal.txt
    echo.
    echo Dependências opcionais disponíveis:
    echo - yara-python (detecção YARA)
    echo - pefile (análise PE)
    echo - matplotlib seaborn (visualizações)
    echo - nltk (processamento de texto)
    echo.
    set /p extra_deps="Instalar dependências opcionais? (y/n): "
    if /i "%extra_deps%"=="y" (
        pip install yara-python pefile matplotlib seaborn nltk
    )
) else (
    echo [ERRO] Opção inválida!
    pause
    exit /b 1
)

echo.
echo [INFO] Verificando instalação...
python -c "import sklearn, pandas, numpy, psutil, requests; print('[OK] Dependências principais instaladas com sucesso!')"

if %errorlevel% neq 0 (
    echo [ERRO] Falha na verificação das dependências!
    pause
    exit /b 1
)

echo.
echo ================================================
echo CONFIGURAÇÃO INICIAL
echo ================================================

REM Criar diretórios necessários
echo [INFO] Criando diretórios...
if not exist "CreatingDatabase\collected_data" mkdir "CreatingDatabase\collected_data"
if not exist "ModelTraining\trained_models" mkdir "ModelTraining\trained_models"
if not exist "RealtimeDetection\detection_logs" mkdir "RealtimeDetection\detection_logs"
echo [OK] Diretórios criados

REM Configurar Discord webhook
echo.
echo [INFO] Configuração do Discord Webhook
set /p setup_discord="Configurar Discord webhook agora? (y/n): "
if /i "%setup_discord%"=="y" (
    set /p webhook_url="Digite a URL do webhook Discord: "
    echo Atualizando configuração...
    powershell -Command "(Get-Content RealtimeDetection\detection_config.json) -replace 'YOUR_WEBHOOK_URL_HERE', '%webhook_url%' | Set-Content RealtimeDetection\detection_config.json"
    echo [OK] Discord webhook configurado
)

echo.
echo ================================================
echo INSTALAÇÃO CONCLUÍDA COM SUCESSO!
echo ================================================
echo.
echo Próximos passos:
echo 1. Coleta de dados: python CreatingDatabase/benign_api_collector.py
echo 2. Coleta malware: python CreatingDatabase/malware_api_collector.py
echo 3. Treinamento: python ModelTraining/defensive_model_trainer.py
echo 4. Detecção: python RealtimeDetection/realtime_malware_detector.py
echo.
echo Para documentação completa, consulte os arquivos README.md
echo.

if /i "%create_venv%"=="y" (
    echo IMPORTANTE: Para usar o sistema, sempre ative o ambiente virtual:
    echo modelo_defensivo_env\Scripts\activate
    echo.
)

pause