"""
COLETOR DE DADOS BENIGNOS PARA MODELO DEFENSIVO
Sistema para capturar chamadas de API de aplicações benignas em máquina virtual
Baseado no formato mal-api-2019 dataset
"""

import win32evtlog
import win32con
import win32event
import xml.etree.ElementTree as ET
import csv
import time
import psutil
import os
import logging
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path
import json
import threading
import subprocess

class BenignAPICollector:
    """
    Coletor de chamadas de API de aplicações benignas
    Monitora processos através do Sysmon e salva no formato compatível com mal-api-2019
    """
    
    def __init__(self, output_dir="benign_data", verbose=True):
        """
        Inicializar coletor de dados benignos
        
        Args:
            output_dir: Diretório de saída para arquivos CSV
            verbose: Mostrar logs detalhados
        """
        print("🟢 COLETOR DE DADOS BENIGNOS - MODELO DEFENSIVO")
        print("=" * 60)
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.verbose = verbose
        self._setup_logging()
        
        # Buffer de API calls por processo
        self.process_api_calls = defaultdict(lambda: deque(maxlen=1000))
        self.process_info = {}
        
        # Controle de coleta
        self.collecting = False
        self.collected_processes = set()
        
        # Lista de processos benignos conhecidos para focar a coleta
        self.target_processes = {
            "notepad.exe", "calc.exe", "mspaint.exe", "winword.exe", 
            "excel.exe", "chrome.exe", "firefox.exe", "explorer.exe",
            "taskmgr.exe", "cmd.exe", "powershell.exe", "code.exe",
            "python.exe", "java.exe", "spotify.exe", "discord.exe"
        }
        
        # Mapeamento de eventos Sysmon para API calls
        self.event_to_api = {
            1: "CreateProcess",      # Process creation
            2: "FileCreate",         # File creation time changed
            3: "NetworkConnect",     # Network connection
            5: "ProcessTerminate",   # Process terminated
            7: "ImageLoaded",        # Image loaded
            8: "CreateRemoteThread", # CreateRemoteThread
            9: "RawAccessRead",      # RawAccessRead
            10: "ProcessAccess",     # ProcessAccess
            11: "FileCreate",        # FileCreate
            12: "RegistryEvent",     # Registry event
            13: "RegistryEvent",     # Registry event
            17: "PipeEvent",         # Pipe Created
            18: "PipeEvent"          # Pipe Connected
        }
        
        self.logger.info("Coletor inicializado com sucesso")
    
    def _setup_logging(self):
        """Configurar sistema de logging"""
        log_file = self.output_dir / f"benign_collector_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO if self.verbose else logging.WARNING,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _get_sysmon_events(self):
        """
        Monitorar eventos do Sysmon
        Gera eventos conforme eles chegam
        """
        try:
            # Abrir log de eventos do Sysmon
            hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
            
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # Obter eventos mais recentes primeiro
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for event in events:
                if not self.collecting:
                    break
                
                try:
                    # Parse do XML do evento
                    xml_string = event.StringInserts[0] if event.StringInserts else ""
                    if xml_string:
                        yield self._parse_sysmon_event(xml_string, event.EventID)
                except Exception as e:
                    if self.verbose:
                        self.logger.warning(f"Erro ao processar evento: {e}")
                    continue
            
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            self.logger.error(f"Erro ao acessar eventos Sysmon: {e}")
            self.logger.info("Verifique se o Sysmon está instalado e configurado")
    
    def _parse_sysmon_event(self, xml_string, event_id):
        """
        Parse de evento Sysmon XML
        Extrai informações relevantes para API calls
        """
        try:
            root = ET.fromstring(xml_string)
            
            event_data = {}
            for data in root.findall(".//Data"):
                name = data.get("Name", "")
                value = data.text or ""
                event_data[name] = value
            
            # Mapear para chamada de API equivalente
            api_call = self.event_to_api.get(event_id, f"SysmonEvent{event_id}")
            
            return {
                "api_call": api_call,
                "process_id": event_data.get("ProcessId", ""),
                "process_name": event_data.get("Image", "").split("\\")[-1],
                "timestamp": datetime.now(),
                "details": event_data
            }
            
        except Exception as e:
            if self.verbose:
                self.logger.warning(f"Erro ao fazer parse do XML: {e}")
            return None
    
    def _monitor_api_calls_alternative(self):
        """
        Método alternativo usando psutil para monitorar processos
        Usado quando Sysmon não está disponível
        """
        self.logger.info("Usando método alternativo de monitoramento (psutil)")
        
        while self.collecting:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    try:
                        if proc.info['name'] in self.target_processes:
                            pid = proc.info['pid']
                            name = proc.info['name']
                            
                            # Simular chamadas de API baseadas em atividade do processo
                            if pid not in self.process_info:
                                self.process_info[pid] = {
                                    'name': name,
                                    'start_time': datetime.now(),
                                    'api_count': 0
                                }
                                
                                # Adicionar APIs típicas de inicialização
                                startup_apis = [
                                    "ldrloaddll", "ldrgetprocedureaddress", "ntallocatevirtualmemory",
                                    "ntcreatefile", "regopenkeyexa", "ntqueryvaluekey"
                                ]
                                
                                for api in startup_apis:
                                    self.process_api_calls[pid].append(api)
                                    self.process_info[pid]['api_count'] += 1
                            
                            # Adicionar APIs baseadas na atividade
                            try:
                                # Verificar uso de CPU/memória para inferir atividade
                                cpu_percent = proc.cpu_percent()
                                memory_info = proc.memory_info()
                                
                                if cpu_percent > 0.1:  # Processo ativo
                                    active_apis = [
                                        "getsystemmetrics", "ntdelayexecution", "getcursorpos"
                                    ]
                                    for api in active_apis:
                                        self.process_api_calls[pid].append(api)
                                        self.process_info[pid]['api_count'] += 1
                                
                                if memory_info.rss > 50 * 1024 * 1024:  # > 50MB
                                    memory_apis = ["ntallocatevirtualmemory", "ntfreevirtualmemory"]
                                    for api in memory_apis:
                                        self.process_api_calls[pid].append(api)
                                        self.process_info[pid]['api_count'] += 1
                            
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                time.sleep(1)  # Intervalo de monitoramento
                
            except Exception as e:
                self.logger.error(f"Erro no monitoramento alternativo: {e}")
                time.sleep(5)
    
    def start_collection(self, duration_minutes=30, min_api_calls=50):
        """
        Iniciar coleta de dados benignos
        
        Args:
            duration_minutes: Duração da coleta em minutos
            min_api_calls: Mínimo de API calls por processo para salvar
        """
        self.collecting = True
        start_time = datetime.now()
        end_time = start_time.timestamp() + (duration_minutes * 60)
        
        print(f"🟢 Iniciando coleta por {duration_minutes} minutos...")
        print(f"📊 Mínimo de {min_api_calls} API calls por processo")
        print(f"🎯 Focando em processos benignos conhecidos")
        print("💡 Execute aplicações normais durante a coleta")
        print()
        
        # Thread para monitoramento alternativo
        monitor_thread = threading.Thread(target=self._monitor_api_calls_alternative)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        try:
            # Tentar usar Sysmon primeiro
            for event in self._get_sysmon_events():
                if not self.collecting or time.time() > end_time:
                    break
                
                if event and event['process_name'] in self.target_processes:
                    pid = int(event['process_id']) if event['process_id'].isdigit() else 0
                    
                    if pid > 0:
                        self.process_api_calls[pid].append(event['api_call'].lower())
                        
                        if pid not in self.process_info:
                            self.process_info[pid] = {
                                'name': event['process_name'],
                                'start_time': event['timestamp'],
                                'api_count': 0
                            }
                        
                        self.process_info[pid]['api_count'] += 1
                
                # Status da coleta
                if time.time() % 30 < 1:  # A cada 30 segundos
                    active_procs = len([p for p in self.process_info.values() if p['api_count'] >= min_api_calls])
                    print(f"📈 Processos coletados: {active_procs}, Total APIs: {sum(len(calls) for calls in self.process_api_calls.values())}")
        
        except Exception as e:
            self.logger.warning(f"Sysmon não disponível, usando método alternativo: {e}")
        
        # Aguardar conclusão do tempo
        while time.time() < end_time and self.collecting:
            time.sleep(1)
            
            # Status periódico
            if int(time.time()) % 30 == 0:
                remaining = int(end_time - time.time())
                active_procs = len([p for p in self.process_info.values() if p['api_count'] >= min_api_calls])
                print(f"⏱️  Tempo restante: {remaining//60}:{remaining%60:02d} | Processos válidos: {active_procs}")
        
        self.collecting = False
        print("\n✅ Coleta finalizada!")
        
        # Salvar dados coletados
        self._save_collected_data(min_api_calls)
    
    def _save_collected_data(self, min_api_calls):
        """
        Salvar dados coletados em formato CSV compatível com mal-api-2019
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_file = self.output_dir / f"benign_dataset_{timestamp}.csv"
        
        valid_processes = 0
        total_api_calls = 0
        
        print(f"\n💾 Salvando dados em: {csv_file}")
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Cabeçalho: api_calls,label
            writer.writerow(['api_calls', 'label'])
            
            for pid, api_calls in self.process_api_calls.items():
                if len(api_calls) >= min_api_calls:
                    # Converter lista de APIs para string (formato mal-api-2019)
                    api_string = ' '.join(api_calls)
                    
                    # Label sempre "Benign" para este coletor
                    writer.writerow([api_string, 'Benign'])
                    
                    valid_processes += 1
                    total_api_calls += len(api_calls)
                    
                    if self.verbose:
                        process_name = self.process_info.get(pid, {}).get('name', 'Unknown')
                        print(f"✅ {process_name} (PID:{pid}): {len(api_calls)} APIs")
        
        # Salvar estatísticas
        stats = {
            'collection_date': datetime.now().isoformat(),
            'duration_minutes': 30,
            'total_processes': valid_processes,
            'total_api_calls': total_api_calls,
            'average_apis_per_process': total_api_calls / valid_processes if valid_processes > 0 else 0,
            'min_api_calls_threshold': min_api_calls,
            'output_file': str(csv_file)
        }
        
        stats_file = self.output_dir / f"collection_stats_{timestamp}.json"
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2)
        
        print(f"\n📊 ESTATÍSTICAS DA COLETA:")
        print(f"   Processos válidos: {valid_processes}")
        print(f"   Total de API calls: {total_api_calls}")
        print(f"   Média por processo: {stats['average_apis_per_process']:.1f}")
        print(f"   Arquivo CSV: {csv_file.name}")
        print(f"   Estatísticas: {stats_file.name}")
    
    def stop_collection(self):
        """Parar coleta manualmente"""
        self.collecting = False
        print("🛑 Coleta interrompida pelo usuário")

def main():
    """Função principal para executar o coletor"""
    print("🟢 COLETOR DE DADOS BENIGNOS - MODELO DEFENSIVO")
    print("=" * 60)
    print("Este script coleta chamadas de API de aplicações benignas")
    print("para criar um dataset de treinamento para o modelo defensivo.")
    print()
    print("INSTRUÇÕES:")
    print("1. Execute aplicações normais durante a coleta")
    print("2. Use programas como Notepad, Calculator, Chrome, etc.")
    print("3. Aguarde a conclusão da coleta")
    print()
    
    # Configurações
    duration = 30  # minutos
    min_calls = 50  # mínimo de API calls por processo
    
    try:
        collector = BenignAPICollector(output_dir="benign_data", verbose=True)
        collector.start_collection(duration_minutes=duration, min_api_calls=min_calls)
        
    except KeyboardInterrupt:
        print("\n🛑 Coleta interrompida pelo usuário")
        if 'collector' in locals():
            collector.stop_collection()
    except Exception as e:
        print(f"❌ Erro durante a coleta: {e}")
        logging.error(f"Erro na coleta: {e}")

if __name__ == "__main__":
    main()