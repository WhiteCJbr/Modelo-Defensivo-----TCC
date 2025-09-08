"""
Script para Captura de Chamadas de API Benignas usando Sysmon
Desenvolvido para Windows 11 - Coleta dados de aplicativos comuns

Requisitos:
- Sysmon instalado e configurado
- Executar como Administrador
- Python com dependências instaladas
"""

import pandas as pd
import numpy as np
import json
import xml.etree.ElementTree as ET
import subprocess
import psutil
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path
import win32evtlog
import win32con
import win32api
import win32process
import win32security
import threading
from collections import defaultdict, Counter
import csv
import os
import sys

class BenignAPICollector:
    """
    Coletor de chamadas de API de aplicativos benignos
    """
    
    def __init__(self, output_dir="benign_data"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.api_calls = []
        self.process_info = {}
        self.collection_active = False
        
        # Aplicativos comuns para monitorar
        self.target_apps = {
            'notepad.exe': 'text_editor',
            'calc.exe': 'calculator', 
            'explorer.exe': 'file_manager',
            'chrome.exe': 'web_browser',
            'firefox.exe': 'web_browser',
            'msedge.exe': 'web_browser',
            'winword.exe': 'office_app',
            'excel.exe': 'office_app',
            'powerpnt.exe': 'office_app',
            'code.exe': 'development',
            'cmd.exe': 'system_tool',
            'powershell.exe': 'system_tool',
            'mspaint.exe': 'graphics',
            'wmplayer.exe': 'media_player',
            'spotify.exe': 'media_player'
        }
        
        # APIs comuns a monitorar
        self.target_apis = {
            'CreateFileW', 'CreateFileA', 'ReadFile', 'WriteFile', 'CloseHandle',
            'CreateProcessW', 'CreateProcessA', 'OpenProcess', 'TerminateProcess',
            'VirtualAlloc', 'VirtualFree', 'VirtualProtect', 'HeapAlloc', 'HeapFree',
            'LoadLibraryW', 'LoadLibraryA', 'GetProcAddress', 'FreeLibrary',
            'RegOpenKeyW', 'RegOpenKeyA', 'RegCreateKeyW', 'RegSetValueW', 'RegCloseKey',
            'WSAStartup', 'WSASocket', 'connect', 'send', 'recv', 'WSACleanup',
            'CreateThread', 'CreateRemoteThread', 'WaitForSingleObject',
            'CreateMutexW', 'CreateMutexA', 'CreateEventW', 'CreateEventA',
            'GetSystemInfo', 'GetVersionExW', 'GetComputerNameW', 'GetUserNameW',
            'FindFirstFileW', 'FindNextFileW', 'GetFileSize', 'SetFilePointer',
            'CreateDirectoryW', 'RemoveDirectoryW', 'CopyFileW', 'MoveFileW'
        }
        
        self._setup_logging()
        
    def _setup_logging(self):
        """Configurar logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / 'collection.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def install_sysmon_config(self):
        """Instalar configuração otimizada do Sysmon"""
        config_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Sysmon schemaversion="15.0">
    <EventFiltering>
        <!-- Process and thread activity -->
        <ProcessCreate onmatch="include">
            <Image condition="end with">notepad.exe</Image>
            <Image condition="end with">calc.exe</Image>
            <Image condition="end with">explorer.exe</Image>
            <Image condition="end with">chrome.exe</Image>
            <Image condition="end with">firefox.exe</Image>
            <Image condition="end with">msedge.exe</Image>
            <Image condition="end with">winword.exe</Image>
            <Image condition="end with">excel.exe</Image>
            <Image condition="end with">powerpnt.exe</Image>
            <Image condition="end with">code.exe</Image>
            <Image condition="end with">cmd.exe</Image>
            <Image condition="end with">powershell.exe</Image>
            <Image condition="end with">mspaint.exe</Image>
            <Image condition="end with">wmplayer.exe</Image>
            <Image condition="end with">spotify.exe</Image>
        </ProcessCreate>
        
        <!-- File creation -->
        <FileCreate onmatch="include">
            <Image condition="end with">notepad.exe</Image>
            <Image condition="end with">winword.exe</Image>
            <Image condition="end with">excel.exe</Image>
            <Image condition="end with">mspaint.exe</Image>
        </FileCreate>
        
        <!-- Network connections -->
        <NetworkConnect onmatch="include">
            <Image condition="end with">chrome.exe</Image>
            <Image condition="end with">firefox.exe</Image>
            <Image condition="end with">msedge.exe</Image>
            <Image condition="end with">spotify.exe</Image>
        </NetworkConnect>
        
        <!-- Image/DLL loads -->
        <ImageLoad onmatch="include">
            <Image condition="end with">notepad.exe</Image>
            <Image condition="end with">calc.exe</Image>
            <Image condition="end with">chrome.exe</Image>
        </ImageLoad>
        
        <!-- Registry events -->
        <RegistryEvent onmatch="include">
            <Image condition="end with">chrome.exe</Image>
            <Image condition="end with">winword.exe</Image>
            <Image condition="end with">code.exe</Image>
        </RegistryEvent>
    </EventFiltering>
</Sysmon>"""
        
        config_path = self.output_dir / "sysmon_config.xml"
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(config_xml)
            
        self.logger.info(f"Configuração Sysmon salva em: {config_path}")
        self.logger.info("Execute como Administrador:")
        self.logger.info(f"sysmon64.exe -accepteula -i \"{config_path}\"")
        
        return config_path
        
    def check_sysmon_status(self):
        """Verificar se Sysmon está instalado e rodando"""
        try:
            # Verificar serviço Sysmon
            result = subprocess.run(['sc', 'query', 'Sysmon64'], 
                                  capture_output=True, text=True)
            if 'RUNNING' in result.stdout:
                self.logger.info("✅ Sysmon está rodando")
                return True
            else:
                self.logger.warning("⚠️ Sysmon não está rodando")
                return False
        except Exception as e:
            self.logger.error(f"Erro ao verificar Sysmon: {e}")
            return False
            
    def monitor_sysmon_events(self, duration_minutes=30):
        """Monitorar eventos do Sysmon por um período"""
        if not self.check_sysmon_status():
            self.logger.error("Sysmon não está disponível!")
            return
            
        self.logger.info(f"Iniciando coleta por {duration_minutes} minutos...")
        self.collection_active = True
        
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        
        try:
            # Conectar ao log do Sysmon
            hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
            
            while datetime.now() < end_time and self.collection_active:
                try:
                    # Ler eventos recentes
                    events = win32evtlog.ReadEventLog(
                        hand,
                        win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                        0
                    )
                    
                    for event in events:
                        if event.TimeGenerated > datetime.now() - timedelta(minutes=1):
                            self._process_sysmon_event(event)
                    
                    time.sleep(2)  # Verificar a cada 2 segundos
                    
                except Exception as e:
                    self.logger.debug(f"Erro na leitura de eventos: {e}")
                    time.sleep(5)
                    
        except Exception as e:
            self.logger.error(f"Erro no monitoramento: {e}")
        finally:
            try:
                win32evtlog.CloseEventLog(hand)
            except:
                pass
                
        self.logger.info("Monitoramento concluído")
        
    def _process_sysmon_event(self, event):
        """Processar evento individual do Sysmon"""
        try:
            # Extrair dados XML do evento
            xml_data = event.StringInserts
            if not xml_data:
                return
                
            event_data = {
                'timestamp': event.TimeGenerated,
                'event_id': event.EventID,
                'process_id': None,
                'image': None,
                'api_sequence': []
            }
            
            # Processar dados baseado no tipo de evento
            if event.EventID == 1:  # Process creation
                event_data.update(self._parse_process_creation(xml_data))
            elif event.EventID == 3:  # Network connection
                event_data.update(self._parse_network_connection(xml_data))
            elif event.EventID == 7:  # Image loaded
                event_data.update(self._parse_image_load(xml_data))
            elif event.EventID == 11:  # File create
                event_data.update(self._parse_file_create(xml_data))
            elif event.EventID in [12, 13, 14]:  # Registry events
                event_data.update(self._parse_registry_event(xml_data))
                
            # Verificar se é de aplicativo alvo
            if event_data.get('image'):
                app_name = Path(event_data['image']).name.lower()
                if app_name in self.target_apps:
                    event_data['app_category'] = self.target_apps[app_name]
                    self._generate_api_sequence(event_data)
                    self.api_calls.append(event_data)
                    
        except Exception as e:
            self.logger.debug(f"Erro ao processar evento: {e}")
            
    def _parse_process_creation(self, xml_data):
        """Parse evento de criação de processo"""
        try:
            return {
                'process_id': xml_data[3] if len(xml_data) > 3 else None,
                'image': xml_data[4] if len(xml_data) > 4 else None,
                'command_line': xml_data[8] if len(xml_data) > 8 else None,
                'parent_image': xml_data[13] if len(xml_data) > 13 else None,
                'api_sequence': ['CreateProcessW', 'OpenProcess', 'GetProcAddress']
            }
        except:
            return {}
            
    def _parse_network_connection(self, xml_data):
        """Parse evento de conexão de rede"""
        try:
            return {
                'process_id': xml_data[3] if len(xml_data) > 3 else None,
                'image': xml_data[4] if len(xml_data) > 4 else None,
                'protocol': xml_data[7] if len(xml_data) > 7 else None,
                'destination_ip': xml_data[14] if len(xml_data) > 14 else None,
                'destination_port': xml_data[15] if len(xml_data) > 15 else None,
                'api_sequence': ['WSAStartup', 'WSASocket', 'connect', 'send', 'recv']
            }
        except:
            return {}
            
    def _parse_image_load(self, xml_data):
        """Parse evento de carregamento de imagem/DLL"""
        try:
            return {
                'process_id': xml_data[3] if len(xml_data) > 3 else None,
                'image': xml_data[4] if len(xml_data) > 4 else None,
                'loaded_image': xml_data[5] if len(xml_data) > 5 else None,
                'api_sequence': ['LoadLibraryW', 'GetProcAddress', 'GetModuleHandleW']
            }
        except:
            return {}
            
    def _parse_file_create(self, xml_data):
        """Parse evento de criação de arquivo"""
        try:
            return {
                'process_id': xml_data[3] if len(xml_data) > 3 else None,
                'image': xml_data[4] if len(xml_data) > 4 else None,
                'target_filename': xml_data[5] if len(xml_data) > 5 else None,
                'api_sequence': ['CreateFileW', 'WriteFile', 'SetFilePointer', 'CloseHandle']
            }
        except:
            return {}
            
    def _parse_registry_event(self, xml_data):
        """Parse evento de registro"""
        try:
            return {
                'process_id': xml_data[3] if len(xml_data) > 3 else None,
                'image': xml_data[4] if len(xml_data) > 4 else None,
                'target_object': xml_data[5] if len(xml_data) > 5 else None,
                'api_sequence': ['RegOpenKeyW', 'RegSetValueW', 'RegQueryValueW', 'RegCloseKey']
            }
        except:
            return {}
            
    def _generate_api_sequence(self, event_data):
        """Gerar sequência realística de APIs baseada no tipo de evento"""
        base_apis = ['GetModuleHandleW', 'GetProcAddress']
        
        if event_data.get('app_category') == 'text_editor':
            event_data['api_sequence'].extend([
                'CreateFileW', 'ReadFile', 'WriteFile', 'SetFilePointer', 'GetFileSize', 'CloseHandle'
            ])
        elif event_data.get('app_category') == 'web_browser':
            event_data['api_sequence'].extend([
                'WSAStartup', 'WSASocket', 'connect', 'send', 'recv', 'closesocket', 'WSACleanup'
            ])
        elif event_data.get('app_category') == 'office_app':
            event_data['api_sequence'].extend([
                'CreateFileW', 'ReadFile', 'WriteFile', 'CreateDirectoryW', 'RegOpenKeyW', 'RegSetValueW'
            ])
        elif event_data.get('app_category') == 'system_tool':
            event_data['api_sequence'].extend([
                'CreateProcessW', 'OpenProcess', 'GetSystemInfo', 'GetVersionExW', 'TerminateProcess'
            ])
            
        # Adicionar APIs base
        event_data['api_sequence'].extend(base_apis)
        
        # Remover duplicatas mantendo ordem
        seen = set()
        event_data['api_sequence'] = [x for x in event_data['api_sequence'] 
                                    if not (x in seen or seen.add(x))]
                                    
    def simulate_user_activity(self, duration_minutes=30):
        """Simular atividade de usuário com aplicativos comuns"""
        self.logger.info("Iniciando simulação de atividade do usuário...")
        
        activities = [
            {
                'app': 'notepad.exe',
                'description': 'Abrir Notepad e criar arquivo de texto',
                'duration': 60
            },
            {
                'app': 'calc.exe', 
                'description': 'Usar Calculadora',
                'duration': 30
            },
            {
                'app': 'explorer.exe',
                'description': 'Navegar em pastas',
                'duration': 45
            },
            {
                'app': 'mspaint.exe',
                'description': 'Criar imagem simples',
                'duration': 90
            }
        ]
        
        for activity in activities:
            self.logger.info(f"Executando: {activity['description']}")
            try:
                # Tentar executar aplicativo
                if activity['app'] == 'explorer.exe':
                    subprocess.Popen(['explorer', '.'])
                else:
                    subprocess.Popen([activity['app']])
                    
                time.sleep(activity['duration'])
                
            except Exception as e:
                self.logger.warning(f"Não foi possível executar {activity['app']}: {e}")
                
        self.logger.info("Simulação de atividade concluída")
        
    def save_to_csv(self):
        """Salvar dados coletados em CSV"""
        if not self.api_calls:
            self.logger.warning("Nenhum dado coletado!")
            return None
            
        # Preparar dados para CSV
        csv_data = []
        
        for call_data in self.api_calls:
            # Criar sequência de API como string
            api_sequence = ' '.join(call_data.get('api_sequence', []))
            
            csv_row = {
                'timestamp': call_data.get('timestamp', ''),
                'app_category': call_data.get('app_category', 'unknown'),
                'image': Path(call_data.get('image', '')).name if call_data.get('image') else '',
                'api_calls': api_sequence,
                'process_id': call_data.get('process_id', ''),
                'event_id': call_data.get('event_id', ''),
                'label': 'Benign'  # Importante: marcar como benigno
            }
            
            csv_data.append(csv_row)
            
        # Salvar em CSV
        output_file = self.output_dir / f"benign_api_calls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        df = pd.DataFrame(csv_data)
        df.to_csv(output_file, index=False)
        
        self.logger.info(f"✅ Dados salvos em: {output_file}")
        self.logger.info(f"📊 Total de registros: {len(csv_data)}")
        self.logger.info(f"📊 Aplicativos capturados: {df['app_category'].value_counts().to_dict()}")
        
        return output_file
        
    def generate_comprehensive_dataset(self, samples_per_category=100):
        """Gerar dataset abrangente com padrões realísticos"""
        self.logger.info("Gerando dataset abrangente de dados benignos...")
        
        synthetic_data = []
        
        # Padrões de API para diferentes categorias
        api_patterns = {
            'text_editor': [
                ['CreateFileW', 'WriteFile', 'SetFilePointer', 'CloseHandle'],
                ['CreateFileW', 'ReadFile', 'GetFileSize', 'CloseHandle'],
                ['CreateFileW', 'WriteFile', 'FlushFileBuffers', 'CloseHandle'],
                ['FindFirstFileW', 'FindNextFileW', 'FindClose'],
                ['CreateDirectoryW', 'CreateFileW', 'WriteFile', 'CloseHandle']
            ],
            'web_browser': [
                ['WSAStartup', 'WSASocket', 'connect', 'send', 'recv', 'closesocket'],
                ['InternetOpenW', 'InternetConnectW', 'HttpOpenRequestW', 'HttpSendRequestW'],
                ['CreateFileW', 'WriteFile', 'CloseHandle', 'DeleteFileW'],
                ['RegOpenKeyW', 'RegQueryValueW', 'RegCloseKey'],
                ['VirtualAlloc', 'VirtualProtect', 'VirtualFree']
            ],
            'office_app': [
                ['CreateFileW', 'ReadFile', 'WriteFile', 'SetFilePointer', 'CloseHandle'],
                ['RegOpenKeyW', 'RegSetValueW', 'RegQueryValueW', 'RegCloseKey'],
                ['CreateDirectoryW', 'CopyFileW', 'MoveFileW'],
                ['LoadLibraryW', 'GetProcAddress', 'FreeLibrary'],
                ['CreateThread', 'WaitForSingleObject', 'CloseHandle']
            ],
            'system_tool': [
                ['GetSystemInfo', 'GetVersionExW', 'GetComputerNameW'],
                ['CreateProcessW', 'OpenProcess', 'GetProcessImageFileNameW'],
                ['RegOpenKeyW', 'RegEnumKeyW', 'RegEnumValueW', 'RegCloseKey'],
                ['FindFirstFileW', 'GetFileAttributesW', 'FindClose'],
                ['CreateFileW', 'GetFileInformationByHandle', 'CloseHandle']
            ],
            'media_player': [
                ['CreateFileW', 'ReadFile', 'SetFilePointer', 'CloseHandle'],
                ['DirectSoundCreate', 'CreateSoundBuffer', 'Play'],
                ['LoadLibraryW', 'GetProcAddress', 'FreeLibrary'],
                ['CreateThread', 'SetThreadPriority', 'WaitForSingleObject'],
                ['VirtualAlloc', 'VirtualProtect', 'VirtualFree']
            ]
        }
        
        for category, patterns in api_patterns.items():
            for i in range(samples_per_category):
                # Escolher padrão aleatório
                pattern = np.random.choice(patterns)
                
                # Adicionar variação realística
                if np.random.random() > 0.7:
                    # Adicionar APIs comuns
                    common_apis = ['GetModuleHandleW', 'GetLastError', 'SetLastError']
                    pattern = pattern + [np.random.choice(common_apis)]
                
                # Criar registro
                record = {
                    'timestamp': datetime.now() - timedelta(
                        minutes=np.random.randint(0, 1440)  # Últimas 24h
                    ),
                    'app_category': category,
                    'image': f"{category}_app.exe",
                    'api_calls': ' '.join(pattern),
                    'process_id': np.random.randint(1000, 9999),
                    'event_id': np.random.choice([1, 3, 7, 11]),
                    'label': 'Benign'
                }
                
                synthetic_data.append(record)
                
        # Salvar dataset sintético
        synthetic_file = self.output_dir / f"synthetic_benign_dataset_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        df_synthetic = pd.DataFrame(synthetic_data)
        df_synthetic.to_csv(synthetic_file, index=False)
        
        self.logger.info(f"✅ Dataset sintético salvo: {synthetic_file}")
        self.logger.info(f"📊 Total de amostras sintéticas: {len(synthetic_data)}")
        
        return synthetic_file

def main():
    """Função principal"""
    print("="*60)
    print("🛡️ COLETOR DE CHAMADAS DE API BENIGNAS")
    print("="*60)
    
    collector = BenignAPICollector()
    
    print("\n1. Configurando Sysmon...")
    config_path = collector.install_sysmon_config()
    
    if not collector.check_sysmon_status():
        print(f"\n⚠️ AÇÃO NECESSÁRIA:")
        print(f"Execute como Administrador:")
        print(f"sysmon64.exe -accepteula -i \"{config_path}\"")
        print("\nApós instalar o Sysmon, execute este script novamente.")
        return
    
    print("\n2. Escolha o método de coleta:")
    print("   1 - Monitoramento em tempo real (30 min)")
    print("   2 - Gerar dataset sintético (rápido)")
    print("   3 - Ambos")
    
    choice = input("\nEscolha (1-3): ").strip()
    
    if choice in ['1', '3']:
        print("\n🔄 Iniciando monitoramento em tempo real...")
        print("💡 Dica: Use aplicativos normalmente durante a coleta")
        
        # Thread para monitoramento
        monitor_thread = threading.Thread(
            target=collector.monitor_sysmon_events,
            args=(30,)  # 30 minutos
        )
        monitor_thread.start()
        
        # Thread para simular atividade
        activity_thread = threading.Thread(
            target=collector.simulate_user_activity,
            args=(30,)
        )
        activity_thread.start()
        
        # Aguardar conclusão
        monitor_thread.join()
        activity_thread.join()
        
        # Salvar dados coletados
        real_data_file = collector.save_to_csv()
        
    if choice in ['2', '3']:
        print("\n🔄 Gerando dataset sintético...")
        synthetic_file = collector.generate_comprehensive_dataset(samples_per_category=200)
        
    print("\n✅ Coleta concluída!")
    print(f"📁 Dados salvos em: {collector.output_dir}")
    print("\n🚀 Próximo passo: Execute o notebook atualizado para treinamento")

if __name__ == "__main__":
    # Verificar se está rodando como administrador
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("⚠️ Este script precisa ser executado como Administrador!")
            print("Clique com botão direito e escolha 'Executar como administrador'")
            input("Pressione Enter para sair...")
            sys.exit(1)
    except:
        pass
        
    main()
