"""
SCRIPT DE TESTE PARA DETECTOR DE MALWARE POLIMÓRFICO
Testa funcionalidades básicas e logging do sistema
"""

import sys
import time
import json
from pathlib import Path
from datetime import datetime

def test_model_loading():
    """Testar carregamento do modelo"""
    print("🧪 Testando carregamento do modelo...")
    
    model_path = Path("../Tentativa2/optimized_malware_detector.joblib")
    
    if not model_path.exists():
        print(f"❌ Modelo não encontrado: {model_path}")
        return False
    
    try:
        import joblib
        model_data = joblib.load(model_path)
        
        required_components = ['model', 'tfidf_vectorizer', 'feature_selector', 'pca']
        missing_components = []
        
        for component in required_components:
            if component not in model_data:
                missing_components.append(component)
        
        if missing_components:
            print(f"⚠️ Componentes faltando no modelo: {missing_components}")
        else:
            print("✅ Modelo carregado com sucesso")
            print(f"   - Tipo do modelo: {type(model_data['model']).__name__}")
            print(f"   - TF-IDF Vectorizer: {'✓' if 'tfidf_vectorizer' in model_data else '✗'}")
            print(f"   - Feature Selector: {'✓' if 'feature_selector' in model_data else '✗'}")
            print(f"   - PCA: {'✓' if 'pca' in model_data else '✗'}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro ao carregar modelo: {e}")
        return False

def test_configuration():
    """Testar carregamento de configuração"""
    print("\n🧪 Testando configuração...")
    
    config_path = Path("config_polymorphic.json")
    
    if not config_path.exists():
        print(f"⚠️ Arquivo de configuração não encontrado: {config_path}")
        return False
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        print("✅ Configuração carregada com sucesso")
        print(f"   - Threshold: {config.get('detection_threshold', 'N/A')}")
        print(f"   - Análise a cada: {config.get('analysis_interval', 'N/A')} segundos")
        print(f"   - Eventos monitorados: {len(config.get('sysmon_events', []))}")
        print(f"   - Palavras-chave IA: {len(config.get('polymorphic_detection', {}).get('ai_keywords', []))}")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro ao carregar configuração: {e}")
        return False

def test_sysmon_connection():
    """Testar conexão com Sysmon"""
    print("\n🧪 Testando conexão com Sysmon...")
    
    try:
        import win32evtlog
        
        # Tentar abrir log do Sysmon
        hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
        win32evtlog.CloseEventLog(hand)
        
        print("✅ Sysmon detectado e acessível")
        return True
        
    except Exception as e:
        print(f"❌ Erro ao conectar com Sysmon: {e}")
        print("   💡 Verifique se o Sysmon está instalado e executando")
        print("   💡 Execute como Administrador")
        return False

def test_permissions():
    """Testar permissões administrativas"""
    print("\n🧪 Testando permissões...")
    
    try:
        import ctypes
        
        if ctypes.windll.shell32.IsUserAnAdmin():
            print("✅ Executando como Administrador")
            return True
        else:
            print("⚠️ NÃO está executando como Administrador")
            print("   💡 Algumas funcionalidades podem não funcionar")
            return False
            
    except Exception as e:
        print(f"❌ Erro ao verificar permissões: {e}")
        return False

def test_dependencies():
    """Testar dependências"""
    print("\n🧪 Testando dependências...")
    
    required_modules = [
        'joblib', 'psutil', 'win32evtlog', 'win32con', 
        'win32event', 'win32api', 'logging', 'threading',
        'json', 'time', 'datetime', 'collections', 'pathlib'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"   ✅ {module}")
        except ImportError:
            print(f"   ❌ {module}")
            missing_modules.append(module)
    
    if missing_modules:
        print(f"\n❌ Módulos faltando: {missing_modules}")
        print("   💡 Instale as dependências faltando")
        return False
    else:
        print("\n✅ Todas as dependências estão disponíveis")
        return True

def test_log_directories():
    """Testar criação de diretórios de log"""
    print("\n🧪 Testando diretórios de log...")
    
    try:
        log_dir = Path("logs")
        evidence_dir = Path("evidence")
        
        log_dir.mkdir(exist_ok=True)
        evidence_dir.mkdir(exist_ok=True)
        
        # Testar escrita
        test_file = log_dir / "test.log"
        with open(test_file, 'w') as f:
            f.write(f"Teste de log - {datetime.now()}")
        
        test_file.unlink()  # Remover arquivo de teste
        
        print("✅ Diretórios de log criados e acessíveis")
        return True
        
    except Exception as e:
        print(f"❌ Erro ao criar diretórios: {e}")
        return False

def run_basic_functionality_test():
    """Teste básico de funcionalidade do detector"""
    print("\n🧪 Testando funcionalidade básica do detector...")
    
    try:
        # Importar e inicializar o detector
        sys.path.append('.')
        from detection_sistem import SysmonMalwareDetector
        
        model_path = "../Tentativa2/optimized_malware_detector.joblib"
        config_path = "config_polymorphic.json"
        
        print("   Inicializando detector...")
        detector = SysmonMalwareDetector(model_path, config_path)
        
        print("   Testando processamento de API calls...")
        # Testar processamento básico
        test_api_calls = ['CreateProcess', 'connect:suspicious.com:443', 'LoadLibrary:kernel32.dll']
        
        result = detector._predict(test_api_calls, "TEST_PID")
        
        if result:
            print(f"   ✅ Predição funcionando: {result['prediction']} (confiança: {result['confidence']:.3f})")
        else:
            print("   ⚠️ Predição retornou None")
        
        print("✅ Teste básico de funcionalidade concluído")
        return True
        
    except Exception as e:
        print(f"❌ Erro no teste de funcionalidade: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Executar todos os testes"""
    print("🔍 TESTE DO DETECTOR DE MALWARE POLIMÓRFICO")
    print("=" * 60)
    print(f"Data/Hora: {datetime.now()}")
    print("=" * 60)
    
    tests = [
        ("Dependências", test_dependencies),
        ("Permissões", test_permissions),
        ("Carregamento do Modelo", test_model_loading),
        ("Configuração", test_configuration),
        ("Conexão Sysmon", test_sysmon_connection),
        ("Diretórios de Log", test_log_directories),
        ("Funcionalidade Básica", run_basic_functionality_test)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        results[test_name] = test_func()
        time.sleep(0.5)  # Pequena pausa entre testes
    
    # Resumo dos resultados
    print("\n" + "=" * 60)
    print("📊 RESUMO DOS TESTES")
    print("=" * 60)
    
    passed = sum(results.values())
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASSOU" if result else "❌ FALHOU"
        print(f"{test_name:.<30} {status}")
    
    print("-" * 60)
    print(f"Total: {passed}/{total} testes passaram")
    
    if passed == total:
        print("\n🎉 TODOS OS TESTES PASSARAM!")
        print("O detector está pronto para uso.")
    else:
        print(f"\n⚠️ {total - passed} teste(s) falharam")
        print("Corrija os problemas antes de usar o detector.")
    
    print("\n💡 Para executar o detector:")
    print("python detection_sistem.py --model ../Tentativa2/optimized_malware_detector.joblib --config config_polymorphic.json --debug")

if __name__ == "__main__":
    main()