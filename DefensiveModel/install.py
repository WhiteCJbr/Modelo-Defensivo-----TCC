#!/usr/bin/env python3
"""
MODELO DEFENSIVO - SCRIPT DE INSTALAÇÃO
Automatiza a instalação de dependências e configuração inicial
Compatível com Windows, Linux e macOS
"""

import os
import sys
import subprocess
import json
from pathlib import Path

def run_command(command, check=True):
    """Executa comando e retorna resultado"""
    try:
        result = subprocess.run(command, shell=True, check=check, 
                              capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return False, "", str(e)

def check_python():
    """Verifica se Python está instalado"""
    print("🐍 Verificando Python...")
    success, stdout, stderr = run_command("python --version", check=False)
    
    if success:
        version = stdout.strip()
        print(f"✅ {version}")
        return True
    else:
        print("❌ Python não encontrado!")
        print("📥 Instale Python 3.8+ em: https://www.python.org/downloads/")
        return False

def check_pip():
    """Verifica se pip está disponível"""
    print("📦 Verificando pip...")
    success, stdout, stderr = run_command("pip --version", check=False)
    
    if success:
        version = stdout.strip()
        print(f"✅ {version}")
        return True
    else:
        print("❌ pip não encontrado!")
        return False

def create_virtual_env():
    """Cria ambiente virtual opcional"""
    print("\n🔧 AMBIENTE VIRTUAL")
    create = input("Criar ambiente virtual? (y/n): ").lower()
    
    if create == 'y':
        print("📁 Criando ambiente virtual...")
        success, _, _ = run_command("python -m venv modelo_defensivo_env")
        
        if success:
            print("✅ Ambiente virtual criado: modelo_defensivo_env/")
            
            # Instruções de ativação por plataforma
            if os.name == 'nt':  # Windows
                activate_cmd = "modelo_defensivo_env\\Scripts\\activate"
            else:  # Linux/macOS
                activate_cmd = "source modelo_defensivo_env/bin/activate"
            
            print(f"💡 Para ativar: {activate_cmd}")
            return True
        else:
            print("❌ Erro ao criar ambiente virtual")
            return False
    
    return False

def install_dependencies():
    """Instala dependências baseado na escolha do usuário"""
    print("\n📚 INSTALAÇÃO DE DEPENDÊNCIAS")
    print("1. Completa (todas as dependências)")
    print("2. Mínima (apenas essenciais)")
    print("3. Personalizada")
    
    choice = input("\nEscolha (1-3): ")
    
    if choice == "1":
        print("📥 Instalando dependências completas...")
        success, _, stderr = run_command("pip install -r requirements.txt")
        
    elif choice == "2":
        print("📥 Instalando dependências mínimas...")
        success, _, stderr = run_command("pip install -r requirements-minimal.txt")
        
    elif choice == "3":
        print("📥 Instalando dependências essenciais...")
        success, _, stderr = run_command("pip install -r requirements-minimal.txt")
        
        if success:
            print("\n🔧 Dependências opcionais disponíveis:")
            print("- yara-python (detecção YARA)")
            print("- pefile (análise PE)")
            print("- matplotlib seaborn (visualizações)")
            print("- nltk (processamento de texto)")
            
            extra = input("\nInstalar opcionais? (y/n): ").lower()
            if extra == 'y':
                extras = "yara-python pefile matplotlib seaborn nltk"
                success, _, stderr = run_command(f"pip install {extras}")
    else:
        print("❌ Opção inválida!")
        return False
    
    if success:
        print("✅ Dependências instaladas!")
        return True
    else:
        print(f"❌ Erro na instalação: {stderr}")
        return False

def verify_installation():
    """Verifica se as dependências principais foram instaladas"""
    print("\n🔍 Verificando instalação...")
    
    test_imports = [
        "sklearn", "pandas", "numpy", "psutil", "requests", "joblib"
    ]
    
    failed_imports = []
    
    for module in test_imports:
        try:
            __import__(module)
            print(f"✅ {module}")
        except ImportError:
            print(f"❌ {module}")
            failed_imports.append(module)
    
    if not failed_imports:
        print("🎉 Todas as dependências principais instaladas!")
        return True
    else:
        print(f"⚠️ Falha ao importar: {', '.join(failed_imports)}")
        return False

def create_directories():
    """Cria diretórios necessários"""
    print("\n📁 Criando diretórios...")
    
    directories = [
        "CreatingDatabase/collected_data",
        "ModelTraining/trained_models", 
        "RealtimeDetection/detection_logs"
    ]
    
    for dir_path in directories:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        print(f"✅ {dir_path}")

def configure_discord():
    """Configura Discord webhook"""
    print("\n🤖 CONFIGURAÇÃO DISCORD")
    setup = input("Configurar Discord webhook? (y/n): ").lower()
    
    if setup == 'y':
        webhook_url = input("URL do webhook Discord: ")
        
        config_path = Path("RealtimeDetection/detection_config.json")
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                
                config['discord_webhook'] = webhook_url
                
                with open(config_path, 'w') as f:
                    json.dump(config, f, indent=4)
                
                print("✅ Discord webhook configurado!")
                return True
                
            except Exception as e:
                print(f"❌ Erro ao configurar webhook: {e}")
                return False
        else:
            print("❌ Arquivo de configuração não encontrado!")
            return False
    
    return True

def main():
    """Função principal da instalação"""
    print("=" * 60)
    print("🛡️ MODELO DEFENSIVO - INSTALAÇÃO AUTOMATIZADA")
    print("Sistema de Detecção de Malware Polimórfico")
    print("=" * 60)
    
    # Verificações iniciais
    if not check_python():
        return False
    
    if not check_pip():
        return False
    
    # Ambiente virtual
    venv_created = create_virtual_env()
    
    # Instalação de dependências
    if not install_dependencies():
        return False
    
    # Verificação
    if not verify_installation():
        return False
    
    # Configuração inicial
    create_directories()
    configure_discord()
    
    # Conclusão
    print("\n" + "=" * 60)
    print("🎉 INSTALAÇÃO CONCLUÍDA COM SUCESSO!")
    print("=" * 60)
    
    print("\n📋 Próximos passos:")
    print("1. Coleta benigna: python CreatingDatabase/benign_api_collector.py")
    print("2. Coleta malware: python CreatingDatabase/malware_api_collector.py")
    print("3. Treinamento: python ModelTraining/defensive_model_trainer.py")
    print("4. Detecção: python RealtimeDetection/realtime_malware_detector.py")
    
    print("\n📚 Consulte os arquivos README.md para documentação completa")
    
    if venv_created:
        if os.name == 'nt':
            activate_cmd = "modelo_defensivo_env\\Scripts\\activate"
        else:
            activate_cmd = "source modelo_defensivo_env/bin/activate"
        
        print(f"\n⚠️ IMPORTANTE: Ative o ambiente virtual antes de usar:")
        print(f"   {activate_cmd}")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        if not success:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️ Instalação cancelada pelo usuário")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Erro inesperado: {e}")
        sys.exit(1)