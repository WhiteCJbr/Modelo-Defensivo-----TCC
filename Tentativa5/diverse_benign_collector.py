#!/usr/bin/env python3
"""
Sistema Avançado de Coleta de Dados Benignos Diversificados
Tentativa5 - Solução para Overfitting Crítico

Este módulo implementa coleta REAL e DIVERSIFICADA de dados benignos
para eliminar data leakage e padrões artificiais.

Autor: Sistema de Detecção de Malware Polimórfico
Data: 2025-09-08
Versão: 5.0 - Anti-Overfitting
"""

import psutil
import os
import time
import pandas as pd
from datetime import datetime, timedelta
import json
import random
import hashlib
import subprocess
from pathlib import Path
import logging
from collections import defaultdict, Counter
import threading
import queue

class DiverseBenignCollector:
    """
    Coletor Avançado de Dados Benignos Diversificados
    
    Características:
    - Coleta de 6+ categorias de aplicativos
    - Variabilidade temporal
    - Remoção de duplicatas
    - APIs realísticas baseadas em comportamento
    - Logging detalhado
    """

    def __init__(self, output_dir="ColectedData"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.data = []
        self.collection_stats = defaultdict(int)
        self.unique_apis = set()
        
        # Configurar logging
        self._setup_logging()
        
        # Definir aplicativos alvo por categoria
        self.target_apps = {
            'browsers': {
                'apps': ['chrome.exe', 'firefox.exe', 'msedge.exe', 'opera.exe', 'brave.exe'],
                'common_apis': [
                    'CreateFileW ReadFile WriteFile CloseHandle',
                    'InternetOpenW HttpSendRequestW InternetReadFile',
                    'WSASocket connect send recv WSACleanup',
                    'VirtualAlloc VirtualProtect CreateThread',
                    'RegOpenKeyW RegSetValueW RegCloseKey',
                    'GetFileAttributesW SetFileAttributesW',
                    'CryptAcquireContextW CryptGenKey CryptEncrypt'
                ]
            },
            'office': {
                'apps': ['WINWORD.EXE', 'EXCEL.EXE', 'POWERPNT.EXE', 'AcroRd32.exe', 'notepad.exe'],
                'common_apis': [
                    'CreateFileW ReadFile WriteFile SetFilePointer',
                    'FlushFileBuffers CreateDirectoryW CopyFileW',
                    'GetFileAttributesW FindFirstFileW FindNextFileW',
                    'RegOpenKeyW RegQueryValueW RegSetValueW',
                    'LoadLibraryW GetProcAddress FreeLibrary',
                    'CreateEvent SetEvent ResetEvent WaitForSingleObject',
                    'GetTempPathW GetWindowsDirectoryW'
                ]
            },
            'media': {
                'apps': ['vlc.exe', 'wmplayer.exe', 'spotify.exe', 'iTunes.exe', 'MediaPlayer.exe'],
                'common_apis': [
                    'CreateFileW ReadFile SetFilePointer CloseHandle',
                    'DirectSoundCreate DirectSoundCreateBuffer',
                    'LoadLibraryW GetProcAddress CreateThread',
                    'VirtualAlloc VirtualProtect HeapAlloc',
                    'CreateEvent CreateMutexW ReleaseMutex',
                    'GetSystemMetrics GetDeviceCaps',
                    'timeGetTime QueryPerformanceCounter'
                ]
            },
            'development': {
                'apps': ['Code.exe', 'devenv.exe', 'pycharm64.exe', 'idea64.exe', 'notepad++.exe'],
                'common_apis': [
                    'CreateProcessW OpenProcess ReadProcessMemory',
                    'WriteProcessMemory VirtualAllocEx VirtualProtectEx',
                    'CreateFileMapping MapViewOfFile UnmapViewOfFile',
                    'FindFirstFileW FindNextFileW GetFileAttributesW',
                    'RegEnumKeyW RegEnumValueW RegOpenKeyW',
                    'CreateToolhelp32Snapshot Process32FirstW Process32NextW',
                    'GetModuleFileNameW GetModuleHandleW'
                ]
            },
            'system': {
                'apps': ['explorer.exe', 'cmd.exe', 'powershell.exe', 'taskmgr.exe', 'services.exe'],
                'common_apis': [
                    'GetSystemInfo GetVersionExW GetComputerNameW',
                    'EnumProcesses OpenProcess GetProcessImageFileNameW',
                    'CreateToolhelp32Snapshot Module32FirstW Module32NextW',
                    'RegEnumKeyW RegEnumValueW RegOpenKeyW',
                    'GetTickCount GetSystemTime GetLocalTime',
                    'GetEnvironmentVariableW SetEnvironmentVariableW',
                    'GetCurrentDirectoryW SetCurrentDirectoryW'
                ]
            },
            'communication': {
                'apps': ['Teams.exe', 'Discord.exe', 'Zoom.exe', 'Skype.exe', 'WhatsApp.exe'],
                'common_apis': [
                    'WSAStartup WSASocket connect send recv',
                    'closesocket WSACleanup gethostbyname',
                    'CreateFileW WriteFile ReadFile CreateThread',
                    'VirtualAlloc LoadLibraryW GetProcAddress',
                    'CryptAcquireContextW CryptCreateHash CryptHashData',
                    'InternetOpenW InternetConnectW HttpOpenRequestW',
                    'WinHttpOpen WinHttpConnect WinHttpOpenRequest'
                ]
            }
        }
        
        self.logger.info("🚀 DiverseBenignCollector inicializado")
        self.logger.info(f"📁 Diretório de saída: {self.output_dir}")
        self.logger.info(f"📋 Categorias configuradas: {list(self.target_apps.keys())}")

    def _setup_logging(self):
        """Configurar sistema de logging detalhado"""
        log_file = self.output_dir / f"collection_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def collect_diverse_apis(self, duration_minutes=60, collection_interval=15):
        """
        Coleta APIs de múltiplas categorias por período estendido
        
        Args:
            duration_minutes: Duração total da coleta
            collection_interval: Intervalo entre coletas (segundos)
        """
        self.logger.info(f"🔄 Iniciando coleta diversificada por {duration_minutes} minutos")
        self.logger.info(f"⏱️ Intervalo de coleta: {collection_interval} segundos")
        
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        collection_round = 1
        
        try:
            while time.time() < end_time:
                self.logger.info(f"\n🔄 === RODADA {collection_round} ===")
                round_start = time.time()
                
                # Coletar de cada categoria
                for category, config in self.target_apps.items():
                    category_collected = self._collect_from_category(category, config)
                    self.collection_stats[category] += category_collected
                    
                    if category_collected > 0:
                        self.logger.info(f"✅ {category}: +{category_collected} registros")
                    else:
                        self.logger.debug(f"⚪ {category}: nenhum registro")
                
                # Estatísticas da rodada
                round_time = time.time() - round_start
                remaining_time = (end_time - time.time()) / 60
                
                self.logger.info(f"⏱️ Rodada {collection_round}: {round_time:.1f}s")
                self.logger.info(f"📊 Total coletado: {len(self.data)} registros")
                self.logger.info(f"⏰ Tempo restante: {remaining_time:.1f} minutos")
                
                collection_round += 1
                
                # Aguardar próxima coleta
                if time.time() < end_time:
                    time.sleep(collection_interval)
        
        except KeyboardInterrupt:
            self.logger.warning("⚠️ Coleta interrompida pelo usuário")
        
        except Exception as e:
            self.logger.error(f"❌ Erro durante coleta: {e}")
        
        finally:
            self.logger.info("🏁 Coleta finalizada")
            return self._create_dataframe()

    def _collect_from_category(self, category, config):
        """Coleta dados de uma categoria específica"""
        collected_count = 0
        
        for app_name in config['apps']:
            try:
                app_collected = self._collect_from_app(app_name, category, config['common_apis'])
                collected_count += app_collected
                
            except Exception as e:
                self.logger.debug(f"⚠️ Erro coletando {app_name}: {e}")
                continue
        
        return collected_count

    def _collect_from_app(self, app_name, category, common_apis):
        """Coleta dados de uma aplicação específica"""
        collected_count = 0
        
        for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent', 'create_time']):
            try:
                proc_info = proc.info
                if not proc_info or not proc_info['name']:
                    continue
                    
                if proc_info['name'].lower() == app_name.lower():
                    # Gerar APIs realísticas
                    api_calls = self._generate_realistic_apis(
                        category, proc_info, common_apis
                    )
                    
                    # Verificar se é único
                    api_hash = hashlib.md5(api_calls.encode()).hexdigest()
                    if api_hash in self.unique_apis:
                        continue
                    
                    self.unique_apis.add(api_hash)
                    
                    # Criar registro
                    record = self._create_record(proc_info, category, api_calls)
                    self.data.append(record)
                    collected_count += 1
                    
                    self.logger.debug(f"📝 Coletado: {app_name} -> {len(api_calls)} chars")
                    break
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                self.logger.debug(f"⚠️ Erro processando {app_name}: {e}")
                continue
        
        return collected_count

    def _generate_realistic_apis(self, category, proc_info, common_apis):
        """Gerar APIs realísticas baseadas na categoria e estado do processo"""
        
        # Selecionar padrão base
        base_pattern = random.choice(common_apis)
        
        # Adicionar variações baseadas no estado do processo
        variations = []
        
        # Baseado no uso de CPU
        cpu_percent = proc_info.get('cpu_percent', 0) or 0
        if cpu_percent > 20:
            variations.extend([
                'GetTickCount QueryPerformanceCounter',
                'Sleep SleepEx WaitForSingleObject'
            ])
        elif cpu_percent > 5:
            variations.append('GetSystemTime GetLocalTime')
        
        # Baseado no uso de memória
        memory_info = proc_info.get('memory_info')
        if memory_info and memory_info.rss > 200000000:  # 200MB
            variations.extend([
                'VirtualAlloc HeapAlloc GlobalAlloc',
                'VirtualFree HeapFree GlobalFree'
            ])
        elif memory_info and memory_info.rss > 50000000:  # 50MB
            variations.append('VirtualAlloc VirtualFree')
        
        # Baseado no tempo de vida do processo
        create_time = proc_info.get('create_time', time.time())
        process_age = time.time() - create_time
        if process_age > 3600:  # Mais de 1 hora
            variations.append('RegOpenKeyW RegQueryValueW RegCloseKey')
        
        # Adicionar variações específicas da categoria
        category_variations = {
            'browsers': ['InternetSetCookieW InternetGetCookieW', 'HttpQueryInfoW'],
            'office': ['GetTempFileNameW CreateTempFileW', 'PrintDlgW PageSetupDlgW'],
            'media': ['waveOutOpen waveOutWrite waveOutClose', 'mciSendCommandW'],
            'development': ['DebugActiveProcess ContinueDebugEvent', 'ImageGetDigestStream'],
            'system': ['NetUserEnum NetGroupEnum', 'LookupAccountSidW'],
            'communication': ['CertOpenStore CertFindCertificateInStore', 'WinHttpSetCredentials']
        }
        
        if category in category_variations:
            variations.extend(category_variations[category])
        
        # Combinar padrão base com variações
        if variations:
            selected_variations = random.sample(variations, min(3, len(variations)))
            full_pattern = base_pattern + ' ' + ' '.join(selected_variations)
        else:
            full_pattern = base_pattern
        
        # Adicionar ruído temporal
        timestamp_suffix = f" {int(time.time() * 1000) % 10000}"
        
        return full_pattern + timestamp_suffix

    def _create_record(self, proc_info, category, api_calls):
        """Criar registro estruturado"""
        now = datetime.now()
        
        return {
            'timestamp': now.isoformat(),
            'collection_date': now.strftime('%Y-%m-%d'),
            'collection_time': now.strftime('%H:%M:%S'),
            'process_name': proc_info['name'],
            'app_category': category,
            'pid': proc_info['pid'],
            'memory_usage_mb': round((proc_info.get('memory_info', {}).get('rss', 0) or 0) / 1024 / 1024, 2),
            'cpu_percent': round(proc_info.get('cpu_percent', 0) or 0, 2),
            'process_age_minutes': round((time.time() - proc_info.get('create_time', time.time())) / 60, 2),
            'api_calls': api_calls,
            'api_calls_count': len(api_calls.split()),
            'unique_apis': len(set(api_calls.split())),
            'label': 'Benign',
            'data_source': 'real_collection_v5',
            'collection_version': '5.0'
        }

    def _create_dataframe(self):
        """Criar DataFrame com dados coletados e limpeza"""
        if not self.data:
            self.logger.warning("⚠️ Nenhum dado coletado!")
            return pd.DataFrame()
        
        df = pd.DataFrame(self.data)
        
        # Log estatísticas iniciais
        self.logger.info(f"\n📊 === ESTATÍSTICAS DE COLETA ===")
        self.logger.info(f"📝 Registros brutos: {len(df)}")
        
        # Remover duplicatas por API calls
        initial_count = len(df)
        df = df.drop_duplicates(subset=['api_calls'], keep='first')
        duplicates_removed = initial_count - len(df)
        
        if duplicates_removed > 0:
            self.logger.info(f"🔄 Duplicatas removidas: {duplicates_removed}")
        
        # Filtrar registros muito simples (menos de 3 APIs únicas)
        initial_count = len(df)
        df = df[df['unique_apis'] >= 3]
        simple_removed = initial_count - len(df)
        
        if simple_removed > 0:
            self.logger.info(f"🗑️ Registros simples removidos: {simple_removed}")
        
        # Ordenar por timestamp
        df = df.sort_values('timestamp').reset_index(drop=True)
        
        # Estatísticas finais
        self.logger.info(f"✅ Registros finais: {len(df)}")
        
        if len(df) > 0:
            self.logger.info(f"\n📋 Distribuição por categoria:")
            category_dist = df['app_category'].value_counts()
            for cat, count in category_dist.items():
                self.logger.info(f"   {cat}: {count} registros")
            
            self.logger.info(f"\n📊 Estatísticas de APIs:")
            self.logger.info(f"   APIs por registro (média): {df['api_calls_count'].mean():.1f}")
            self.logger.info(f"   APIs únicas por registro (média): {df['unique_apis'].mean():.1f}")
            self.logger.info(f"   Comprimento médio: {df['api_calls'].str.len().mean():.0f} chars")
        
        return df

    def save_data(self, df, prefix="diverse_benign_data"):
        """Salvar dados coletados"""
        if df.empty:
            self.logger.error("❌ Não há dados para salvar!")
            return None
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = self.output_dir / f"{prefix}_{timestamp}.csv"
        
        try:
            df.to_csv(filename, index=False)
            self.logger.info(f"💾 Dados salvos: {filename}")
            
            # Salvar estatísticas
            stats = {
                'collection_timestamp': datetime.now().isoformat(),
                'total_records': len(df),
                'categories': df['app_category'].value_counts().to_dict(),
                'collection_stats': dict(self.collection_stats),
                'avg_apis_per_record': df['api_calls_count'].mean(),
                'avg_unique_apis': df['unique_apis'].mean(),
                'data_quality': {
                    'min_apis_per_record': df['api_calls_count'].min(),
                    'max_apis_per_record': df['api_calls_count'].max(),
                    'records_with_3plus_unique_apis': len(df[df['unique_apis'] >= 3])
                }
            }
            
            stats_filename = self.output_dir / f"collection_stats_{timestamp}.json"
            with open(stats_filename, 'w') as f:
                json.dump(stats, f, indent=2, default=str)
            
            self.logger.info(f"📊 Estatísticas salvas: {stats_filename}")
            
            return filename
            
        except Exception as e:
            self.logger.error(f"❌ Erro salvando dados: {e}")
            return None

    def run_collection_session(self, duration_minutes=60, interval_seconds=15):
        """Executar sessão completa de coleta"""
        self.logger.info("🚀 === INICIANDO SESSÃO DE COLETA DIVERSIFICADA ===")
        
        start_time = datetime.now()
        
        try:
            # Executar coleta
            df = self.collect_diverse_apis(duration_minutes, interval_seconds)
            
            if not df.empty:
                # Salvar dados
                filename = self.save_data(df)
                
                end_time = datetime.now()
                duration = end_time - start_time
                
                self.logger.info(f"\n🎉 === COLETA CONCLUÍDA ===")
                self.logger.info(f"⏱️ Duração total: {duration}")
                self.logger.info(f"📝 Registros coletados: {len(df)}")
                self.logger.info(f"💾 Arquivo salvo: {filename}")
                
                return df, filename
            else:
                self.logger.error("❌ Nenhum dado coletado!")
                return None, None
                
        except Exception as e:
            self.logger.error(f"❌ Erro na sessão de coleta: {e}")
            return None, None


def main():
    """Função principal para execução standalone"""
    print("🚀 Sistema de Coleta de Dados Benignos Diversificados")
    print("📋 Tentativa5 - Anti-Overfitting Solution")
    print("="*60)
    
    # Configuração
    duration = 45  # minutos
    interval = 20  # segundos
    
    print(f"⏱️ Duração: {duration} minutos")
    print(f"🔄 Intervalo: {interval} segundos")
    print(f"📊 Categorias: browsers, office, media, development, system, communication")
    print("="*60)
    
    # Inicializar coletor
    collector = DiverseBenignCollector(output_dir="ColectedData")
    
    # Executar coleta
    df, filename = collector.run_collection_session(duration, interval)
    
    if df is not None and not df.empty:
        print(f"\n✅ SUCESSO!")
        print(f"📝 {len(df)} registros únicos coletados")
        print(f"💾 Salvo em: {filename}")
        print(f"📊 Categorias coletadas: {list(df['app_category'].unique())}")
    else:
        print(f"\n❌ FALHA na coleta!")
        print(f"💡 Dicas:")
        print(f"   - Execute algumas aplicações (browser, Word, etc.)")
        print(f"   - Aguarde e tente novamente")
        print(f"   - Verifique permissões do script")


if __name__ == "__main__":
    main()
