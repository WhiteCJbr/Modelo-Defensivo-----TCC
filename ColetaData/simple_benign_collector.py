"""
Coletor Simplificado de Dados Benignos - Windows 11
Alternativa que não requer Sysmon
"""

import pandas as pd
import numpy as np
import psutil
import time
import json
from datetime import datetime, timedelta
from pathlib import Path
import logging
import subprocess
import os
import threading
from collections import defaultdict

class SimpleBenignCollector:
    """
    Coletor simplificado que monitora processos e gera padrões realísticos
    """
    
    def __init__(self, output_dir="benign_data_simple"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.collected_data = []
        self.monitoring = False
        
        # Padrões de API para aplicativos comuns
        self.app_api_patterns = {
            'notepad.exe': {
                'category': 'text_editor',
                'common_apis': [
                    'CreateFileW ReadFile WriteFile SetFilePointer GetFileSize CloseHandle',
                    'CreateFileW WriteFile FlushFileBuffers SetEndOfFile CloseHandle',
                    'FindFirstFileW FindNextFileW GetFileAttributesW FindClose',
                    'CreateDirectoryW CreateFileW WriteFile CloseHandle DeleteFileW',
                    'RegOpenKeyW RegQueryValueW RegSetValueW RegCloseKey GetLastError'
                ]
            },
            'explorer.exe': {
                'category': 'file_manager',
                'common_apis': [
                    'FindFirstFileW FindNextFileW GetFileAttributesW FindClose',
                    'CreateDirectoryW RemoveDirectoryW CopyFileW MoveFileW',
                    'SHGetFolderPathW SHBrowseForFolderW SHGetPathFromIDListW',
                    'RegOpenKeyW RegEnumKeyW RegEnumValueW RegCloseKey',
                    'CreateFileW GetFileInformationByHandle CloseHandle'
                ]
            },
            'calc.exe': {
                'category': 'calculator',
                'common_apis': [
                    'LoadLibraryW GetProcAddress FreeLibrary GetModuleHandleW',
                    'CreateWindowExW ShowWindow UpdateWindow GetMessageW',
                    'RegOpenKeyW RegQueryValueW RegCloseKey GetSystemMetrics',
                    'VirtualAlloc VirtualProtect VirtualFree HeapAlloc HeapFree',
                    'GetVersionExW GetComputerNameW GetUserNameW'
                ]
            },
            'chrome.exe': {
                'category': 'web_browser',
                'common_apis': [
                    'WSAStartup WSASocket connect send recv closesocket WSACleanup',
                    'InternetOpenW InternetConnectW HttpOpenRequestW HttpSendRequestW',
                    'CreateFileW WriteFile ReadFile SetFilePointer CloseHandle',
                    'VirtualAlloc VirtualProtect VirtualFree CreateThread',
                    'RegOpenKeyW RegSetValueW RegQueryValueW RegDeleteValueW RegCloseKey'
                ]
            },
            'firefox.exe': {
                'category': 'web_browser', 
                'common_apis': [
                    'WSAStartup WSASocket connect send recv closesocket',
                    'CreateFileW ReadFile WriteFile CreateDirectoryW',
                    'LoadLibraryW GetProcAddress FreeLibrary',
                    'CreateThread CreateMutexW ReleaseMutex CloseHandle',
                    'RegOpenKeyW RegQueryValueW RegSetValueW RegCloseKey'
                ]
            },
            'msedge.exe': {
                'category': 'web_browser',
                'common_apis': [
                    'WSAStartup WSASocket connect send recv',
                    'InternetOpenW InternetReadFile InternetCloseHandle',
                    'CreateFileW WriteFile ReadFile CloseHandle',
                    'VirtualAlloc VirtualFree CreateProcessW',
                    'RegOpenKeyW RegQueryValueW RegCloseKey'
                ]
            },
            'winword.exe': {
                'category': 'office_app',
                'common_apis': [
                    'CreateFileW ReadFile WriteFile SetFilePointer CloseHandle',
                    'CreateDirectoryW CopyFileW MoveFileW DeleteFileW',
                    'RegOpenKeyW RegSetValueW RegQueryValueW RegCloseKey',
                    'LoadLibraryW GetProcAddress FreeLibrary',
                    'CreateThread WaitForSingleObject SetEvent ResetEvent'
                ]
            },
            'excel.exe': {
                'category': 'office_app',
                'common_apis': [
                    'CreateFileW ReadFile WriteFile SetFilePointer GetFileSize CloseHandle',
                    'RegOpenKeyW RegEnumValueW RegSetValueW RegCloseKey',
                    'LoadLibraryW GetProcAddress FreeLibrary GetModuleFileNameW',
                    'CreateThread CreateEvent SetEvent WaitForSingleObject',
                    'VirtualAlloc VirtualProtect VirtualFree'
                ]
            },
            'powerpnt.exe': {
                'category': 'office_app',
                'common_apis': [
                    'CreateFileW ReadFile WriteFile CloseHandle',
                    'CreateDirectoryW FindFirstFileW FindNextFileW FindClose',
                    'LoadLibraryW GetProcAddress FreeLibrary',
                    'RegOpenKeyW RegQueryValueW RegSetValueW RegCloseKey',
                    'CreateThread WaitForSingleObject CloseHandle'
                ]
            },
            'code.exe': {
                'category': 'development',
                'common_apis': [
                    'CreateFileW ReadFile WriteFile SetFilePointer CloseHandle',
                    'CreateProcessW OpenProcess GetProcessImageFileNameW TerminateProcess',
                    'FindFirstFileW FindNextFileW GetFileAttributesW FindClose',
                    'LoadLibraryW GetProcAddress FreeLibrary',
                    'CreateThread CreateEvent SetEvent WaitForSingleObject'
                ]
            },
            'cmd.exe': {
                'category': 'system_tool',
                'common_apis': [
                    'CreateProcessW OpenProcess GetProcessImageFileNameW WaitForSingleObject',
                    'GetSystemInfo GetVersionExW GetComputerNameW GetUserNameW',
                    'RegOpenKeyW RegEnumKeyW RegQueryValueW RegCloseKey',
                    'FindFirstFileW FindNextFileW GetFileAttributesW FindClose',
                    'CreateFileW GetFileInformationByHandle CloseHandle'
                ]
            },
            'powershell.exe': {
                'category': 'system_tool',
                'common_apis': [
                    'CreateProcessW OpenProcess GetProcessImageFileNameW',
                    'LoadLibraryW GetProcAddress FreeLibrary',
                    'RegOpenKeyW RegEnumKeyW RegSetValueW RegDeleteKeyW RegCloseKey',
                    'GetSystemInfo GetVersionExW GetVolumeInformationW',
                    'CreateFileW ReadFile WriteFile CloseHandle'
                ]
            },
            'mspaint.exe': {
                'category': 'graphics',
                'common_apis': [
                    'CreateFileW ReadFile WriteFile SetFilePointer CloseHandle',
                    'CreateDIBSection GetDIBits SetDIBits DeleteObject',
                    'LoadLibraryW GetProcAddress FreeLibrary',
                    'CreateThread WaitForSingleObject CloseHandle',
                    'RegOpenKeyW RegQueryValueW RegCloseKey'
                ]
            },
            'wmplayer.exe': {
                'category': 'media_player',
                'common_apis': [
                    'CreateFileW ReadFile SetFilePointer GetFileSize CloseHandle',
                    'DirectSoundCreate CreateSoundBuffer Play Stop',
                    'LoadLibraryW GetProcAddress FreeLibrary',
                    'CreateThread SetThreadPriority WaitForSingleObject',
                    'VirtualAlloc VirtualProtect VirtualFree'
                ]
            },
            'spotify.exe': {
                'category': 'media_player',
                'common_apis': [
                    'WSAStartup WSASocket connect send recv',
                    'CreateFileW ReadFile WriteFile CloseHandle',
                    'DirectSoundCreate CreateSoundBuffer Play',
                    'LoadLibraryW GetProcAddress FreeLibrary',
                    'CreateThread WaitForSingleObject CloseHandle'
                ]
            }
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
        
    def monitor_processes(self, duration_minutes=30):
        """Monitorar processos em execução"""
        self.logger.info(f"Iniciando monitoramento por {duration_minutes} minutos...")
        
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        self.monitoring = True
        
        while datetime.now() < end_time and self.monitoring:
            current_processes = {}
            
            # Obter processos atuais
            for proc in psutil.process_iter(['pid', 'name', 'create_time', 'memory_info']):
                try:
                    pinfo = proc.info
                    process_name = pinfo['name'].lower()
                    
                    if process_name in self.app_api_patterns:
                        current_processes[pinfo['pid']] = {
                            'name': process_name,
                            'create_time': datetime.fromtimestamp(pinfo['create_time']),
                            'memory_usage': pinfo['memory_info'].rss if pinfo['memory_info'] else 0
                        }
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            # Gerar dados para processos encontrados
            for pid, pinfo in current_processes.items():
                self._generate_process_data(pid, pinfo)
                
            time.sleep(10)  # Verificar a cada 10 segundos
            
        self.monitoring = False
        self.logger.info("Monitoramento concluído")
        
    def _generate_process_data(self, pid, process_info):
        """Gerar dados realísticos para um processo"""
        process_name = process_info['name']
        
        if process_name not in self.app_api_patterns:
            return
            
        app_data = self.app_api_patterns[process_name]
        
        # Escolher padrão de API aleatório
        api_pattern = np.random.choice(app_data['common_apis'])
        
        # Adicionar variação temporal
        timestamp = datetime.now() - timedelta(seconds=np.random.randint(0, 600))
        
        # Criar registro
        record = {
            'timestamp': timestamp.isoformat(),
            'process_id': pid,
            'process_name': process_name,
            'app_category': app_data['category'],
            'api_calls': api_pattern,
            'memory_usage': process_info['memory_usage'],
            'create_time': process_info['create_time'].isoformat(),
            'label': 'Benign'
        }
        
        self.collected_data.append(record)
        
    def generate_comprehensive_benign_dataset(self, samples_per_app=150):
        """Gerar dataset abrangente de dados benignos"""
        self.logger.info(f"Gerando dataset com {samples_per_app} amostras por aplicativo...")
        
        synthetic_data = []
        
        for app_name, app_data in self.app_api_patterns.items():
            category = app_data['category']
            api_patterns = app_data['common_apis']
            
            for i in range(samples_per_app):
                # Escolher padrão aleatório
                api_pattern = np.random.choice(api_patterns)
                
                # Adicionar variação realística
                if np.random.random() > 0.8:
                    # Ocasionalmente adicionar APIs de erro/cleanup
                    cleanup_apis = ['GetLastError', 'SetLastError', 'CloseHandle']
                    api_pattern += ' ' + np.random.choice(cleanup_apis)
                
                # Simular variação temporal realística
                hours_ago = np.random.exponential(2)  # Distribuição exponencial
                timestamp = datetime.now() - timedelta(hours=hours_ago)
                
                record = {
                    'timestamp': timestamp.isoformat(),
                    'process_id': np.random.randint(1000, 32767),
                    'process_name': app_name,
                    'app_category': category,
                    'api_calls': api_pattern,
                    'memory_usage': np.random.normal(50000000, 20000000),  # ~50MB média
                    'create_time': (timestamp - timedelta(minutes=np.random.randint(1, 120))).isoformat(),
                    'label': 'Benign'
                }
                
                synthetic_data.append(record)
                
        # Adicionar aos dados coletados
        self.collected_data.extend(synthetic_data)
        
        self.logger.info(f"Dataset gerado: {len(synthetic_data)} amostras sintéticas")
        
    def save_dataset(self):
        """Salvar dataset em CSV"""
        if not self.collected_data:
            self.logger.warning("Nenhum dado para salvar!")
            return None
            
        # Criar DataFrame
        df = pd.DataFrame(self.collected_data)
        
        # Remover duplicatas baseado em timestamp e API calls
        df = df.drop_duplicates(subset=['timestamp', 'api_calls'])
        
        # Ordenar por timestamp
        df = df.sort_values('timestamp')
        
        # Resetar índice
        df = df.reset_index(drop=True)
        
        # Salvar arquivo
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = self.output_dir / f"benign_api_dataset_{timestamp}.csv"
        
        df.to_csv(output_file, index=False)
        
        # Estatísticas
        self.logger.info(f"✅ Dataset salvo: {output_file}")
        self.logger.info(f"📊 Total de registros: {len(df)}")
        self.logger.info(f"📊 Período: {df['timestamp'].min()} até {df['timestamp'].max()}")
        
        # Distribuição por categoria
        category_dist = df['app_category'].value_counts()
        self.logger.info("📊 Distribuição por categoria:")
        for category, count in category_dist.items():
            self.logger.info(f"   {category}: {count} amostras")
            
        return output_file
        
    def run_collection(self, monitor_real_processes=True, generate_synthetic=True):
        """Executar coleta completa"""
        print("🛡️ COLETOR SIMPLIFICADO DE DADOS BENIGNOS")
        print("="*50)
        
        if monitor_real_processes:
            print("\n🔄 Monitorando processos em tempo real...")
            monitor_thread = threading.Thread(
                target=self.monitor_processes,
                args=(15,)  # 15 minutos
            )
            monitor_thread.start()
            monitor_thread.join()
            
        if generate_synthetic:
            print("\n🔄 Gerando dados sintéticos...")
            self.generate_comprehensive_benign_dataset()
            
        print("\n💾 Salvando dataset...")
        output_file = self.save_dataset()
        
        print(f"\n✅ Coleta concluída!")
        print(f"📁 Arquivo: {output_file}")
        
        return output_file

def main():
    """Função principal simplificada"""
    collector = SimpleBenignCollector()
    
    print("Escolha o método de coleta:")
    print("1 - Monitoramento + Sintético (recomendado)")
    print("2 - Apenas sintético (rápido)")
    print("3 - Apenas monitoramento")
    
    choice = input("\nEscolha (1-3): ").strip()
    
    if choice == '1':
        output_file = collector.run_collection(monitor_real_processes=True, generate_synthetic=True)
    elif choice == '2':
        output_file = collector.run_collection(monitor_real_processes=False, generate_synthetic=True)
    elif choice == '3':
        output_file = collector.run_collection(monitor_real_processes=True, generate_synthetic=False)
    else:
        print("Opção inválida!")
        return
        
    print(f"\n🚀 Próximo passo: Use o arquivo {output_file} no notebook!")

if __name__ == "__main__":
    main()
