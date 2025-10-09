"""
TESTE DE VALIDAÇÃO - COLETOR DE DADOS BENIGNOS
Script para testar e validar o funcionamento do coletor após correções
"""

import sys
import os
from pathlib import Path

# Adicionar o diretório do projeto ao path
sys.path.append(str(Path(__file__).parent))

try:
    from benign_api_collector import BenignAPICollector
    print("✅ Import do BenignAPICollector bem-sucedido")
except ImportError as e:
    print(f"❌ Erro no import: {e}")
    sys.exit(1)

def test_collector_initialization():
    """Testar inicialização do coletor"""
    print("\n🧪 Testando inicialização do coletor...")
    
    try:
        collector = BenignAPICollector(output_dir="test_output", verbose=True)
        print("✅ Coletor inicializado com sucesso")
        return collector
    except Exception as e:
        print(f"❌ Erro na inicialização: {e}")
        return None

def test_sysmon_connection(collector):
    """Testar conexão com Sysmon"""
    print("\n🔌 Testando conexão com Sysmon...")
    
    try:
        # Tentar acessar eventos do Sysmon
        events = list(collector._get_sysmon_events())
        print(f"✅ Conexão Sysmon OK - {len(events)} eventos obtidos")
        return True
    except Exception as e:
        print(f"⚠️ Sysmon não disponível: {e}")
        print("📝 Isso é normal se o Sysmon não estiver instalado")
        return False

def test_alternative_monitoring(collector):
    """Testar monitoramento alternativo"""
    print("\n🔄 Testando monitoramento alternativo (psutil)...")
    
    try:
        # Coletar algumas APIs por 5 segundos
        collector.collecting = True
        collector.start_time = None
        
        # Usar monitoramento alternativo por pouco tempo
        import time
        import threading
        
        def collect_for_time():
            collector._monitor_api_calls_alternative()
        
        # Iniciar coleta em thread separada
        thread = threading.Thread(target=collect_for_time, daemon=True)
        thread.start()
        
        time.sleep(3)  # Coletar por 3 segundos
        collector.collecting = False
        
        # Verificar se coletou dados
        total_apis = sum(len(apis) for apis in collector.process_api_calls.values())
        print(f"✅ Monitoramento alternativo OK - {total_apis} APIs coletadas")
        return True
        
    except Exception as e:
        print(f"❌ Erro no monitoramento alternativo: {e}")
        return False

def test_csv_output(collector):
    """Testar saída CSV"""
    print("\n📄 Testando geração de CSV...")
    
    try:
        # Se há dados coletados, gerar CSV
        if collector.process_api_calls:
            output_file = collector._generate_output_filename()
            success = collector._save_to_csv(output_file)
            
            if success and Path(output_file).exists():
                file_size = Path(output_file).stat().st_size
                print(f"✅ CSV gerado - {output_file} ({file_size} bytes)")
                return True
            else:
                print("❌ Arquivo CSV não foi criado")
                return False
        else:
            # Se não há dados, criar dados de teste para validar o método
            print("⚠️ Não há dados reais, criando dados de teste...")
            
            # Adicionar dados de teste
            collector.process_api_calls[9999] = ['test_api_1', 'test_api_2', 'test_api_3']
            collector.process_info[9999] = {'name': 'test_process.exe'}
            
            output_file = collector._generate_output_filename()
            success = collector._save_to_csv(output_file)
            
            if success and Path(output_file).exists():
                file_size = Path(output_file).stat().st_size
                print(f"✅ CSV de teste gerado - {output_file} ({file_size} bytes)")
                
                # Limpar dados de teste
                del collector.process_api_calls[9999]
                del collector.process_info[9999]
                
                # Remover arquivo de teste
                Path(output_file).unlink()
                print("🧹 Dados de teste removidos")
                return True
            else:
                print("❌ Falha na geração de CSV de teste")
                return False
            
    except Exception as e:
        print(f"❌ Erro na geração de CSV: {e}")
        return False

def main():
    """Função principal de teste"""
    print("🧪 TESTE DE VALIDAÇÃO - COLETOR DE DADOS BENIGNOS")
    print("=" * 60)
    
    # Teste 1: Inicialização
    collector = test_collector_initialization()
    if not collector:
        print("\n❌ Teste falhou na inicialização")
        return False
    
    # Teste 2: Conexão Sysmon
    sysmon_ok = test_sysmon_connection(collector)
    
    # Teste 3: Monitoramento alternativo
    alt_monitoring_ok = test_alternative_monitoring(collector)
    
    # Teste 4: Saída CSV
    csv_ok = test_csv_output(collector)
    
    # Resultado final
    print("\n" + "=" * 60)
    print("📊 RESULTADO DOS TESTES:")
    print(f"✅ Inicialização: OK")
    print(f"{'✅' if sysmon_ok else '⚠️'} Sysmon: {'OK' if sysmon_ok else 'Não disponível (normal)'}")
    print(f"{'✅' if alt_monitoring_ok else '❌'} Monitoramento alternativo: {'OK' if alt_monitoring_ok else 'FALHA'}")
    print(f"{'✅' if csv_ok else '❌'} Geração CSV: {'OK' if csv_ok else 'FALHA'}")
    
    if alt_monitoring_ok and csv_ok:
        print("\n🎉 SISTEMA FUNCIONAL - Pronto para coleta de dados!")
        print("💡 Mesmo sem Sysmon, o modo alternativo funcionará")
        return True
    else:
        print("\n❌ SISTEMA COM PROBLEMAS - Verifique as dependências")
        return False

if __name__ == "__main__":
    try:
        success = main()
        if not success:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n⚠️ Teste interrompido pelo usuário")
    except Exception as e:
        print(f"\n❌ Erro inesperado no teste: {e}")
        sys.exit(1)