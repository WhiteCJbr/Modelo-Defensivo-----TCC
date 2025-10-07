"""
DETECTOR DE MALWARE INTEGRADO COM SYSMON
Sistema completo de detecção em tempo real usando eventos do Sysmon
"""

import joblib
import time
import json
import win32evtlog
import win32con
import win32event
import win32api
import psutil
import logging
import threading
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict, deque
from pathlib import Path

class SysmonMalwareDetector:
    """
    Detector de malware integrado com Sysmon
    Monitora eventos em tempo real e detecta comportamentos maliciosos
    """
    
    def __init__(self, model_path, config_path=None):
        """
        Inicializar detector com Sysmon
        
        Args:
            model_path: Caminho para modelo treinado (.joblib)
            config_path: Caminho para configuração (opcional)
        """
        print("🛡️ DETECTOR DE MALWARE COM INTEGRAÇÃO SYSMON")
        print("=" * 60)
        
        # Configurar logging
        self._setup_logging()
        
        # Carregar modelo
        self.logger.info(f"Carregando modelo: {model_path}")
        self._load_model(model_path)
        
        # Carregar configurações
        self.config = self._load_config(config_path)
        
        # Buffers para API calls por processo
        self.process_api_calls = defaultdict(lambda: deque(maxlen=500))  # Aumentado para malware polimórfico
        self.process_info = {}
        
        # Histórico de detecções
        self.detections = deque(maxlen=1000)
        
        # Controle de execução
        self.running = False
        self.sysmon_handle = None
        
        # Cache para melhor performance
        self.process_cache = {}
        self.last_cleanup = datetime.now()
        
        # Padrões específicos para malware polimórfico
        self.polymorphic_indicators = {
            'memory_operations': ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread'],
            'ai_communication': ['connect:openai', 'connect:api', 'HttpSendRequest'],
            'code_injection': ['SetWindowsHookEx', 'NtMapViewOfSection', 'RtlCreateUserThread'],
            'obfuscation': ['CryptEncrypt', 'CryptDecrypt', 'Base64', 'XOR'],
            'persistence': ['RegSetValue', 'CreateService', 'SetWindowsHookEx']
        }
        
        # Contadores para padrões específicos
        self.pattern_counters = defaultdict(lambda: defaultdict(int))
        
        # Estatísticas avançadas
        self.stats = {
            'events_processed': 0,
            'processes_monitored': 0,
            'malware_detected': 0,
            'quarantined': 0,
            'false_positives': 0,
            'polymorphic_detected': 0,
            'memory_injections': 0,
            'ai_communications': 0,
            'start_time': None,
            'events_per_second': 0,
            'last_event_time': datetime.now()
        }
        
        # Mapeamento de Event IDs do Sysmon (ampliado para malware polimórfico)
        self.event_handlers = {
            1: self._handle_process_create,        # Process Creation
            2: self._handle_file_time_change,      # File creation time changed
            3: self._handle_network_connect,       # Network connection
            4: self._handle_sysmon_state,          # Sysmon service state change
            5: self._handle_process_terminate,     # Process terminated
            6: self._handle_driver_load,           # Driver loaded
            7: self._handle_image_load,            # Image loaded
            8: self._handle_create_remote_thread,  # CreateRemoteThread
            9: self._handle_raw_access_read,       # RawAccessRead
            10: self._handle_process_access,       # ProcessAccess
            11: self._handle_file_create,          # FileCreate
            12: self._handle_registry_event,       # RegistryEvent (Object create and delete)
            13: self._handle_registry_event,       # RegistryEvent (Value Set)
            14: self._handle_registry_event,       # RegistryEvent (Key and Value Rename)
            15: self._handle_file_stream_create,   # FileCreateStreamHash
            16: self._handle_sysmon_config,        # Sysmon config change
            17: self._handle_pipe_create,          # Pipe Created
            18: self._handle_pipe_connect,         # Pipe Connected
            19: self._handle_wmi_event,            # WmiEvent (WmiEventFilter activity)
            20: self._handle_wmi_event,            # WmiEvent (WmiEventConsumer activity)
            21: self._handle_wmi_event,            # WmiEvent (WmiEventConsumerToFilter activity)
            22: self._handle_dns_query,            # DNSEvent (DNS query)
            23: self._handle_file_delete,          # FileDelete (File Delete archived)
            24: self._handle_clipboard_change,     # ClipboardChange (New content in clipboard)
            25: self._handle_process_tampering,    # ProcessTampering (Process image change)
            26: self._handle_file_delete_log,      # FileDeleteDetected (File Delete logged)
            27: self._handle_file_block,           # FileBlockExecutable
            28: self._handle_file_block_shredding, # FileBlockShredding
            29: self._handle_file_executable       # FileExecutableDetected
        }
        
        self.logger.info("✅ Detector inicializado com sucesso\n")
    
    def _setup_logging(self):
        """Configurar sistema de logging avançado"""
        
        # Criar diretório de logs se não existir
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Configurar formatação detalhada
        detailed_format = '%(asctime)s [%(levelname)8s] [%(name)s:%(lineno)d] %(message)s'
        
        # Configurar handler para arquivo principal
        main_handler = logging.FileHandler(
            log_dir / 'sysmon_detector.log', 
            encoding='utf-8'
        )
        main_handler.setLevel(logging.INFO)
        main_handler.setFormatter(logging.Formatter(detailed_format))
        
        # Handler para debugging detalhado
        debug_handler = logging.FileHandler(
            log_dir / 'sysmon_debug.log', 
            encoding='utf-8'
        )
        debug_handler.setLevel(logging.DEBUG)
        debug_handler.setFormatter(logging.Formatter(detailed_format))
        
        # Handler para eventos críticos
        critical_handler = logging.FileHandler(
            log_dir / 'sysmon_critical.log', 
            encoding='utf-8'
        )
        critical_handler.setLevel(logging.CRITICAL)
        critical_handler.setFormatter(logging.Formatter(detailed_format))
        
        # Handler para console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        
        # Configurar logger principal
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(main_handler)
        self.logger.addHandler(debug_handler)
        self.logger.addHandler(critical_handler)
        self.logger.addHandler(console_handler)
        
        # Logger específico para eventos
        self.event_logger = logging.getLogger(f"{__name__}.events")
        self.event_logger.setLevel(logging.DEBUG)
        event_handler = logging.FileHandler(
            log_dir / 'sysmon_events.log', 
            encoding='utf-8'
        )
        event_handler.setFormatter(logging.Formatter(detailed_format))
        self.event_logger.addHandler(event_handler)
        
        # Logger para análise ML
        self.ml_logger = logging.getLogger(f"{__name__}.ml")
        self.ml_logger.setLevel(logging.DEBUG)
        ml_handler = logging.FileHandler(
            log_dir / 'sysmon_ml_analysis.log', 
            encoding='utf-8'
        )
        ml_handler.setFormatter(logging.Formatter(detailed_format))
        self.ml_logger.addHandler(ml_handler)
    
    def _load_model(self, model_path):
        """Carregar modelo treinado"""
        try:
            model_data = joblib.load(model_path)
            
            self.model = model_data['model']
            self.tfidf_vectorizer = model_data.get('tfidf_vectorizer')
            self.pca = model_data.get('pca')
            self.scaler = model_data.get('scaler')
            self.label_encoder = model_data.get('label_encoder')
            self.feature_selector = model_data.get('feature_selector')
            
            self.logger.info("✓ Modelo carregado com sucesso")
            
        except Exception as e:
            self.logger.error(f"❌ Erro ao carregar modelo: {e}")
            raise
    
    def _load_config(self, config_path):
        """Carregar configurações otimizadas para malware polimórfico"""
        default_config = {
            'detection_threshold': 0.5,  # Reduzido devido à baixa accuracy do modelo
            'analysis_interval': 5,      # Análise mais frequente
            'min_api_calls': 3,          # Reduzido para capturar atividade rápida
            'quarantine_enabled': True,
            'save_evidence': True,
            'alert_webhook': None,
            'verbose_logging': True,
            
            # Eventos específicos para malware polimórfico
            'sysmon_events': [1, 2, 3, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 25, 26, 27, 29],
            
            # Configurações para detecção polimórfica
            'polymorphic_detection': {
                'memory_threshold': 3,      # Operações de memória suspeitas
                'network_threshold': 2,     # Conexões suspeitas
                'injection_threshold': 1,   # Tolerância zero para injeção
                'ai_keywords': ['openai', 'anthropic', 'claude', 'gpt', 'api', 'chat', 'generate'],
                'obfuscation_threshold': 2
            },
            
            # Processos na whitelist
            'whitelist_processes': [
                'svchost.exe', 'System', 'smss.exe', 'csrss.exe', 
                'wininit.exe', 'services.exe', 'lsass.exe', 'winlogon.exe',
                'dwm.exe', 'explorer.exe', 'conhost.exe'
            ],
            
            # Processos críticos do sistema (acesso a eles é altamente suspeito)
            'critical_processes': [
                'lsass.exe', 'winlogon.exe', 'csrss.exe', 'services.exe',
                'smss.exe', 'wininit.exe'
            ],
            
            # Extensões de arquivo suspeitas
            'suspicious_extensions': [
                '.exe', '.dll', '.scr', '.bat', '.ps1', '.vbs', '.com',
                '.pif', '.cmd', '.msi', '.jar', '.hta'
            ],
            
            # Diretórios suspeitos para criação de arquivos
            'suspicious_directories': [
                'temp', 'tmp', 'appdata\\local\\temp', 'windows\\temp',
                'programdata', 'users\\public'
            ]
        }
        
        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
                self.logger.info(f"✓ Configuração carregada de: {config_path}")
            except Exception as e:
                self.logger.warning(f"Erro ao carregar config: {e}")
        
        # Log das configurações importantes
        self.logger.info(f"✓ Threshold de detecção: {default_config['detection_threshold']}")
        self.logger.info(f"✓ Eventos monitorados: {len(default_config['sysmon_events'])}")
        self.logger.info(f"✓ Detecção polimórfica: {default_config.get('polymorphic_detection', {}).get('memory_threshold', 'N/A')}")
        
        return default_config
    
    def start(self):
        """Iniciar monitoramento com Sysmon"""
        self.logger.info("🚀 INICIANDO MONITORAMENTO COM SYSMON")
        self.logger.info("=" * 60)
        
        # Verificar se Sysmon está instalado
        if not self._check_sysmon():
            self.logger.error("❌ Sysmon não está instalado ou não está executando")
            self.logger.error("Execute o instalador do Sysmon primeiro")
            return
        
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        # Thread para monitorar eventos do Sysmon
        monitor_thread = threading.Thread(target=self._monitor_sysmon_events, daemon=True)
        monitor_thread.start()
        
        # Thread para análise periódica
        analysis_thread = threading.Thread(target=self._periodic_analysis, daemon=True)
        analysis_thread.start()
        
        self.logger.info("✓ Threads de monitoramento iniciadas")
        self.logger.info(f"✓ Threshold de detecção: {self.config['detection_threshold']}")
        self.logger.info(f"✓ Quarentena: {'Habilitada' if self.config['quarantine_enabled'] else 'Desabilitada'}")
        self.logger.info("\n⏳ Monitorando eventos... (Pressione Ctrl+C para parar)\n")
        
        try:
            # Loop principal
            while self.running:
                time.sleep(1)
                
                # Imprimir status a cada 60 segundos
                if int(time.time()) % 60 == 0:
                    self._print_status()
                    
        except KeyboardInterrupt:
            self.logger.info("\n⚠️ Interrupção do usuário detectada")
        finally:
            self.stop()
    
    def stop(self):
        """Parar monitoramento"""
        self.logger.info("🛑 Parando detector...")
        self.running = False
        
        if self.sysmon_handle:
            try:
                win32evtlog.CloseEventLog(self.sysmon_handle)
            except:
                pass
        
        self._print_final_statistics()
        self.logger.info("✅ Detector parado com sucesso")
    
    def _check_sysmon(self):
        """Verificar se Sysmon está instalado e executando"""
        try:
            # Tentar abrir log do Sysmon
            hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
            win32evtlog.CloseEventLog(hand)
            
            self.logger.info("✓ Sysmon detectado e operacional")
            return True
            
        except Exception as e:
            self.logger.error(f"Erro ao verificar Sysmon: {e}")
            return False
    
    def _monitor_sysmon_events(self):
        """Thread otimizada para monitorar eventos do Sysmon em tempo real"""
        try:
            # Abrir log do Sysmon
            self.sysmon_handle = win32evtlog.OpenEventLog(
                None, 
                "Microsoft-Windows-Sysmon/Operational"
            )
            
            # Configurar para ler eventos mais recentes
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            self.logger.info("✓ Conectado ao log do Sysmon")
            self.event_logger.info("Iniciando captura de eventos Sysmon")
            
            # Controle de performance
            events_batch = []
            last_batch_time = time.time()
            batch_size = 50  # Processar em lotes para melhor performance
            
            while self.running:
                try:
                    # Ler eventos
                    events = win32evtlog.ReadEventLog(
                        self.sysmon_handle,
                        flags,
                        0
                    )
                    
                    if events:
                        current_time = time.time()
                        
                        for event in events:
                            if not self.running:
                                break
                            
                            events_batch.append(event)
                            
                            # Processar em lotes ou quando batch fica cheio
                            if (len(events_batch) >= batch_size or 
                                current_time - last_batch_time > 1.0):
                                
                                self._process_event_batch(events_batch)
                                events_batch.clear()
                                last_batch_time = current_time
                        
                        # Atualizar estatísticas de performance
                        self.stats['events_per_second'] = len(events) / max(0.1, current_time - time.time())
                        self.stats['last_event_time'] = datetime.now()
                    else:
                        # Sem eventos, processar batch restante se houver
                        if events_batch:
                            self._process_event_batch(events_batch)
                            events_batch.clear()
                    
                    # Delay adaptativo baseado na carga de eventos
                    if len(events_batch) > batch_size * 0.8:
                        time.sleep(0.05)  # Muitos eventos, delay menor
                    else:
                        time.sleep(0.1)   # Poucos eventos, delay maior
                    
                except Exception as e:
                    if self.running:
                        self.logger.debug(f"Erro ao ler eventos: {e}")
                        time.sleep(1)
            
        except Exception as e:
            self.logger.error(f"Erro no monitoramento Sysmon: {e}")
            
    def _process_event_batch(self, events_batch):
        """Processar lote de eventos para melhor performance"""
        for event in events_batch:
            try:
                self._process_sysmon_event(event)
                self.stats['events_processed'] += 1
            except Exception as e:
                self.event_logger.debug(f"Erro ao processar evento em lote: {e}")
    
    def _process_sysmon_event(self, event):
        """Processar evento individual do Sysmon com logging detalhado"""
        try:
            event_id = event.EventID & 0xFFFF  # Remover bits de severidade
            
            # Log detalhado do evento
            self.event_logger.debug(f"Processando evento ID {event_id} de {event.ComputerName}")
            
            # Verificar se é um evento que monitoramos
            if event_id not in self.config['sysmon_events']:
                self.event_logger.debug(f"Evento ID {event_id} não está na lista de monitoramento")
                return
            
            # Extrair dados do evento
            event_data = self._parse_event_xml(event)
            
            if not event_data:
                self.event_logger.debug(f"Falha ao parsear evento ID {event_id}")
                return
            
            # Log do evento parseado
            self.event_logger.debug(f"Evento parseado: {event_data}")
            
            # Chamar handler apropriado
            handler = self.event_handlers.get(event_id)
            if handler:
                handler(event_data)
                self.event_logger.debug(f"Handler executado para evento ID {event_id}")
            else:
                self.event_logger.warning(f"Handler não encontrado para evento ID {event_id}")
            
        except Exception as e:
            self.event_logger.error(f"Erro ao processar evento: {e}")
            self.logger.debug(f"Erro ao processar evento: {e}")
    
    def _parse_event_xml(self, event):
        """Parser de evento do Sysmon (extração de dados XML)"""
        try:
            # Converter para XML
            xml_data = event.StringInserts
            
            if not xml_data:
                return None
            
            # Criar dicionário com dados do evento
            event_dict = {
                'EventID': event.EventID & 0xFFFF,
                'TimeCreated': event.TimeGenerated,
                'Computer': event.ComputerName
            }
            
            # Adicionar campos específicos baseados no Event ID
            if len(xml_data) > 0:
                event_id = event_dict['EventID']
                
                if event_id == 1:  # Process Create
                    event_dict.update({
                        'ProcessId': xml_data[3] if len(xml_data) > 3 else None,
                        'Image': xml_data[4] if len(xml_data) > 4 else None,
                        'CommandLine': xml_data[10] if len(xml_data) > 10 else None,
                        'ParentImage': xml_data[13] if len(xml_data) > 13 else None
                    })
                    
                elif event_id == 3:  # Network Connect
                    event_dict.update({
                        'ProcessId': xml_data[3] if len(xml_data) > 3 else None,
                        'Image': xml_data[4] if len(xml_data) > 4 else None,
                        'DestinationIp': xml_data[14] if len(xml_data) > 14 else None,
                        'DestinationPort': xml_data[16] if len(xml_data) > 16 else None
                    })
                    
                elif event_id == 7:  # Image Load
                    event_dict.update({
                        'ProcessId': xml_data[3] if len(xml_data) > 3 else None,
                        'Image': xml_data[4] if len(xml_data) > 4 else None,
                        'ImageLoaded': xml_data[5] if len(xml_data) > 5 else None
                    })
                    
                elif event_id == 8:  # CreateRemoteThread
                    event_dict.update({
                        'SourceProcessId': xml_data[3] if len(xml_data) > 3 else None,
                        'TargetProcessId': xml_data[6] if len(xml_data) > 6 else None,
                        'SourceImage': xml_data[4] if len(xml_data) > 4 else None
                    })
                    
                elif event_id == 10:  # Process Access
                    event_dict.update({
                        'SourceProcessId': xml_data[3] if len(xml_data) > 3 else None,
                        'TargetProcessId': xml_data[6] if len(xml_data) > 6 else None,
                        'SourceImage': xml_data[4] if len(xml_data) > 4 else None,
                        'TargetImage': xml_data[7] if len(xml_data) > 7 else None
                    })
                    
                elif event_id == 11:  # File Create
                    event_dict.update({
                        'ProcessId': xml_data[3] if len(xml_data) > 3 else None,
                        'Image': xml_data[4] if len(xml_data) > 4 else None,
                        'TargetFilename': xml_data[5] if len(xml_data) > 5 else None
                    })
            
            return event_dict
            
        except Exception as e:
            self.logger.debug(f"Erro ao parsear XML: {e}")
            return None
    
    def _handle_process_create(self, event_data):
        """Handler otimizado para Event ID 1: Process Creation"""
        pid = event_data.get('ProcessId')
        image = event_data.get('Image', '')
        cmdline = event_data.get('CommandLine', '')
        
        if not pid:
            self.event_logger.warning("Evento Process Create sem PID")
            return
        
        # Verificar whitelist
        process_name = Path(image).name.lower() if image else ''
        if process_name in [p.lower() for p in self.config['whitelist_processes']]:
            self.event_logger.debug(f"Processo {process_name} está na whitelist - ignorando")
            return
        
        # Log detalhado do processo criado
        self.event_logger.info(f"Novo processo: {process_name} (PID: {pid})")
        self.event_logger.debug(f"Comando: {cmdline}")
        
        # Adicionar à lista de processos monitorados
        self.process_info[pid] = {
            'image': image,
            'cmdline': cmdline,
            'parent': event_data.get('ParentImage', ''),
            'first_seen': datetime.now(),
            'process_name': process_name,
            'suspicious_score': 0
        }
        
        # Registrar API call
        self.process_api_calls[pid].append('CreateProcess')
        
        # Verificações específicas para malware polimórfico
        self._check_polymorphic_indicators(pid, 'process_create', {
            'image': image,
            'cmdline': cmdline,
            'process_name': process_name
        })
        
        self.stats['processes_monitored'] += 1
        self.event_logger.debug(f"Processo {pid} adicionado ao monitoramento")
    
    def _handle_network_connect(self, event_data):
        """Handler otimizado para Event ID 3: Network Connection"""
        pid = event_data.get('ProcessId')
        dest_ip = event_data.get('DestinationIp', '')
        dest_port = event_data.get('DestinationPort', '')
        dest_hostname = event_data.get('DestinationHostname', '')
        
        if not pid:
            return
        
        # Log conexão de rede
        self.event_logger.info(f"Conexão de rede PID {pid}: {dest_ip}:{dest_port} ({dest_hostname})")
        
        # Registrar API call detalhada
        if dest_hostname:
            api_call = f"connect:{dest_hostname}:{dest_port}"
        elif dest_ip:
            api_call = f"connect:{dest_ip}:{dest_port}"
        else:
            api_call = "connect"
        
        self.process_api_calls[pid].append(api_call)
        
        # Verificar indicadores de comunicação com IA
        self._check_ai_communication(pid, dest_hostname, dest_ip, dest_port)
        
        # Verificar padrões polimórficos
        self._check_polymorphic_indicators(pid, 'network', {
            'destination': dest_hostname or dest_ip,
            'port': dest_port,
            'api_call': api_call
        })
    
    def _handle_create_remote_thread(self, event_data):
        """Handler crítico para Event ID 8: CreateRemoteThread (Injeção de código)"""
        source_pid = event_data.get('SourceProcessId')
        target_pid = event_data.get('TargetProcessId')
        source_image = event_data.get('SourceImage', '')
        
        # Log crítico para injeção de código
        self.logger.critical(f"🚨 INJEÇÃO DE CÓDIGO DETECTADA!")
        self.logger.critical(f"Processo origem: {source_image} (PID: {source_pid})")
        self.logger.critical(f"Processo destino: PID {target_pid}")
        
        if source_pid:
            self.process_api_calls[source_pid].append('CreateRemoteThread')
            
            # Marcar como altamente suspeito
            if source_pid in self.process_info:
                self.process_info[source_pid]['suspicious_score'] += 50
            
            # Incrementar contador de injeções
            self.stats['memory_injections'] += 1
            
            # Verificar imediatamente - injeção é comportamento crítico
            self.logger.warning(f"Analisando processo {source_pid} imediatamente devido à injeção")
            self._analyze_process(source_pid)
            
            # Padrão polimórfico crítico
            self._check_polymorphic_indicators(source_pid, 'injection', {
                'target_pid': target_pid,
                'source_image': source_image
            })
    
    def _handle_process_access(self, event_data):
        """Handler para Event ID 10: Process Access"""
        source_pid = event_data.get('SourceProcessId')
        target_image = event_data.get('TargetImage', '')
        access_mask = event_data.get('GrantedAccess', '')
        
        if not source_pid:
            return
        
        target_name = Path(target_image).name.lower() if target_image else ''
        
        # Log acesso a processo
        self.event_logger.debug(f"Acesso a processo: PID {source_pid} -> {target_name} (Access: {access_mask})")
        
        # Verificar acesso a processos críticos
        if target_name in [p.lower() for p in self.config['critical_processes']]:
            self.logger.warning(f"⚠️ Acesso a processo crítico: {target_name}")
            self.process_api_calls[source_pid].append(f"OpenProcess:{target_name}")
            
            # Marcar como suspeito
            if source_pid in self.process_info:
                self.process_info[source_pid]['suspicious_score'] += 30
            
            # Analisar imediatamente
            self._analyze_process(source_pid)
        else:
            self.process_api_calls[source_pid].append('OpenProcess')
    
    def _handle_file_create(self, event_data):
        """Handler para Event ID 11: File Create"""
        pid = event_data.get('ProcessId')
        filename = event_data.get('TargetFilename', '')
        
        if not pid or not filename:
            return
        
        file_path = Path(filename)
        file_ext = file_path.suffix.lower()
        file_dir = str(file_path.parent).lower()
        
        # Log criação de arquivo
        self.event_logger.debug(f"Arquivo criado por PID {pid}: {filename}")
        
        # Verificar extensões suspeitas
        if file_ext in self.config['suspicious_extensions']:
            self.logger.warning(f"⚠️ Arquivo suspeito criado: {filename}")
            self.process_api_calls[pid].append(f"CreateFile:{file_ext}")
            
            # Marcar como suspeito
            if pid in self.process_info:
                self.process_info[pid]['suspicious_score'] += 20
        else:
            self.process_api_calls[pid].append('CreateFile')
        
        # Verificar diretórios suspeitos
        for sus_dir in self.config['suspicious_directories']:
            if sus_dir.lower() in file_dir:
                self.logger.warning(f"⚠️ Arquivo criado em diretório suspeito: {file_dir}")
                if pid in self.process_info:
                    self.process_info[pid]['suspicious_score'] += 15
                break
    
    def _handle_registry_event(self, event_data):
        """Handler para Event IDs 12/13/14: Registry Events"""
        pid = event_data.get('ProcessId')
        target_object = event_data.get('TargetObject', '')
        
        if pid:
            self.process_api_calls[pid].append('RegSetValue')
            
            # Verificar chaves de persistência
            persistence_keys = [
                'run', 'runonce', 'services', 'currentversion\\run',
                'currentversion\\runonce', 'winlogon', 'userinit'
            ]
            
            if any(key in target_object.lower() for key in persistence_keys):
                self.logger.warning(f"⚠️ Modificação de registro de persistência: {target_object}")
                if pid in self.process_info:
                    self.process_info[pid]['suspicious_score'] += 25
    
    # Novos handlers para eventos adicionais
    def _handle_image_load(self, event_data):
        """Handler para Event ID 7: Image/DLL Load"""
        pid = event_data.get('ProcessId')
        image_loaded = event_data.get('ImageLoaded', '')
        
        if pid and image_loaded:
            dll_name = Path(image_loaded).name.lower()
            self.process_api_calls[pid].append(f"LoadLibrary:{dll_name}")
            
            # Verificar DLLs suspeitas
            suspicious_dlls = ['ntdll.dll', 'kernel32.dll', 'advapi32.dll', 'user32.dll']
            if dll_name in suspicious_dlls:
                self.event_logger.debug(f"DLL crítica carregada: {dll_name}")
    
    def _handle_file_time_change(self, event_data):
        """Handler para Event ID 2: File creation time changed"""
        pid = event_data.get('ProcessId')
        if pid:
            self.process_api_calls[pid].append('SetFileTime')
            self.event_logger.debug(f"Modificação de timestamp por PID {pid}")
    
    def _handle_process_terminate(self, event_data):
        """Handler para Event ID 5: Process terminated"""
        pid = event_data.get('ProcessId')
        if pid:
            self.event_logger.info(f"Processo terminado: PID {pid}")
            # Limpar dados do processo
            if pid in self.process_api_calls:
                del self.process_api_calls[pid]
            if pid in self.process_info:
                del self.process_info[pid]
    
    def _handle_driver_load(self, event_data):
        """Handler para Event ID 6: Driver loaded"""
        image_loaded = event_data.get('ImageLoaded', '')
        if image_loaded:
            self.logger.warning(f"⚠️ Driver carregado: {image_loaded}")
    
    def _handle_raw_access_read(self, event_data):
        """Handler para Event ID 9: RawAccessRead"""
        pid = event_data.get('ProcessId')
        if pid:
            self.process_api_calls[pid].append('RawDiskAccess')
            self.logger.warning(f"⚠️ Acesso direto ao disco por PID {pid}")
    
    def _handle_file_stream_create(self, event_data):
        """Handler para Event ID 15: FileCreateStreamHash"""
        pid = event_data.get('ProcessId')
        if pid:
            self.process_api_calls[pid].append('CreateFileStream')
    
    def _handle_pipe_create(self, event_data):
        """Handler para Event ID 17: Pipe Created"""
        pid = event_data.get('ProcessId')
        pipe_name = event_data.get('PipeName', '')
        if pid:
            self.process_api_calls[pid].append(f"CreatePipe:{pipe_name}")
    
    def _handle_pipe_connect(self, event_data):
        """Handler para Event ID 18: Pipe Connected"""
        pid = event_data.get('ProcessId')
        if pid:
            self.process_api_calls[pid].append('ConnectPipe')
    
    def _handle_wmi_event(self, event_data):
        """Handler para Event IDs 19/20/21: WMI Events"""
        pid = event_data.get('ProcessId')
        if pid:
            self.process_api_calls[pid].append('WMIEvent')
            self.logger.warning(f"⚠️ Evento WMI por PID {pid}")
    
    def _handle_dns_query(self, event_data):
        """Handler para Event ID 22: DNS Query"""
        pid = event_data.get('ProcessId')
        query_name = event_data.get('QueryName', '')
        if pid:
            self.process_api_calls[pid].append(f"DNSQuery:{query_name}")
            
            # Verificar consultas suspeitas para IA
            self._check_ai_communication(pid, query_name, '', '')
    
    def _handle_file_delete(self, event_data):
        """Handler para Event ID 23: File Delete"""
        pid = event_data.get('ProcessId')
        if pid:
            self.process_api_calls[pid].append('DeleteFile')
    
    def _handle_clipboard_change(self, event_data):
        """Handler para Event ID 24: Clipboard Change"""
        pid = event_data.get('ProcessId')
        if pid:
            self.process_api_calls[pid].append('ClipboardAccess')
    
    def _handle_process_tampering(self, event_data):
        """Handler para Event ID 25: Process Tampering"""
        pid = event_data.get('ProcessId')
        if pid:
            self.logger.critical(f"🚨 MANIPULAÇÃO DE PROCESSO DETECTADA: PID {pid}")
            self.process_api_calls[pid].append('ProcessTampering')
            if pid in self.process_info:
                self.process_info[pid]['suspicious_score'] += 50
    
    def _handle_file_delete_log(self, event_data):
        """Handler para Event ID 26: File Delete Logged"""
        pid = event_data.get('ProcessId')
        if pid:
            self.process_api_calls[pid].append('FileDeleteLogged')
    
    def _handle_file_block(self, event_data):
        """Handler para Event ID 27: File Block Executable"""
        pid = event_data.get('ProcessId')
        if pid:
            self.logger.warning(f"⚠️ Execução de arquivo bloqueada: PID {pid}")
            self.process_api_calls[pid].append('FileBlocked')
    
    def _handle_file_block_shredding(self, event_data):
        """Handler para Event ID 28: File Block Shredding"""
        pid = event_data.get('ProcessId')
        if pid:
            self.process_api_calls[pid].append('FileShredding')
    
    def _handle_file_executable(self, event_data):
        """Handler para Event ID 29: File Executable Detected"""
        pid = event_data.get('ProcessId')
        if pid:
            self.process_api_calls[pid].append('ExecutableDetected')
    
    # Handlers para eventos não implementados
    def _handle_sysmon_state(self, event_data):
        """Handler para Event ID 4: Sysmon service state change"""
        pass
    
    def _handle_sysmon_config(self, event_data):
        """Handler para Event ID 16: Sysmon config change"""
        pass
    
    def _check_polymorphic_indicators(self, pid, event_type, event_details):
        """Verificar indicadores específicos de malware polimórfico"""
        try:
            if pid not in self.pattern_counters:
                self.pattern_counters[pid] = defaultdict(int)
            
            polymorphic_detected = False
            
            # Verificar padrões baseados no tipo de evento
            if event_type == 'injection':
                self.pattern_counters[pid]['injection'] += 1
                if self.pattern_counters[pid]['injection'] >= self.config['polymorphic_detection']['injection_threshold']:
                    self.logger.critical(f"🚨 PADRÃO POLIMÓRFICO: Injeção de código detectada - PID {pid}")
                    polymorphic_detected = True
            
            elif event_type == 'network':
                self.pattern_counters[pid]['network'] += 1
                destination = event_details.get('destination', '').lower()
                
                # Verificar comunicação com serviços de IA
                ai_keywords = self.config['polymorphic_detection']['ai_keywords']
                if any(keyword in destination for keyword in ai_keywords):
                    self.pattern_counters[pid]['ai_communication'] += 1
                    self.stats['ai_communications'] += 1
                    self.logger.warning(f"⚠️ COMUNICAÇÃO COM IA DETECTADA: {destination} - PID {pid}")
                    polymorphic_detected = True
            
            elif event_type == 'process_create':
                cmdline = event_details.get('cmdline', '').lower()
                
                # Verificar comandos suspeitos para polimorfismo
                suspicious_commands = ['powershell', 'cmd', 'wscript', 'cscript', 'regsvr32', 'rundll32']
                if any(cmd in cmdline for cmd in suspicious_commands):
                    self.pattern_counters[pid]['suspicious_commands'] += 1
            
            # Se detectado comportamento polimórfico, marcar para análise imediata
            if polymorphic_detected:
                self.stats['polymorphic_detected'] += 1
                if pid in self.process_info:
                    self.process_info[pid]['suspicious_score'] += 40
                self._analyze_process(pid)
                
        except Exception as e:
            self.logger.debug(f"Erro ao verificar indicadores polimórficos: {e}")
    
    def _check_ai_communication(self, pid, hostname, ip, port):
        """Verificar comunicação específica com serviços de IA"""
        try:
            # Verificar hostname
            if hostname:
                hostname_lower = hostname.lower()
                ai_domains = [
                    'openai.com', 'api.openai.com', 'chat.openai.com',
                    'anthropic.com', 'api.anthropic.com',
                    'googleapis.com', 'api.google.com',
                    'azure.com', 'api.azure.com',
                    'huggingface.co', 'api.huggingface.co'
                ]
                
                for domain in ai_domains:
                    if domain in hostname_lower:
                        self.logger.critical(f"🚨 COMUNICAÇÃO COM IA CONFIRMADA: {hostname} - PID {pid}")
                        self.stats['ai_communications'] += 1
                        
                        if pid in self.process_info:
                            self.process_info[pid]['suspicious_score'] += 60
                            
                        # Analisar imediatamente
                        self._analyze_process(pid)
                        break
            
            # Verificar portas comuns de APIs
            if port in ['80', '443', '8080', '8443']:
                self.pattern_counters[pid]['api_calls'] += 1
                
        except Exception as e:
            self.logger.debug(f"Erro ao verificar comunicação IA: {e}")
    
    def _calculate_threat_score(self, pid, api_calls):
        """Calcular score de ameaça baseado em comportamentos específicos"""
        threat_score = 0
        
        try:
            # Score baseado no processo
            if pid in self.process_info:
                threat_score += self.process_info[pid].get('suspicious_score', 0)
            
            # Score baseado em padrões de API calls
            api_string = ' '.join(api_calls).lower()
            
            # Padrões específicos de malware polimórfico
            polymorphic_patterns = {
                'memory_operations': ['virtualalloc', 'writeprocessmemory', 'createremotethread'],
                'injection_patterns': ['createremotethread', 'setwindowshook', 'ntmapviewofsection'],
                'ai_communication': ['connect:api', 'connect:openai', 'httpsendrequest'],
                'obfuscation': ['cryptencrypt', 'cryptdecrypt', 'base64'],
                'persistence': ['regsetvalue', 'createservice', 'setwindowshook']
            }
            
            for pattern_name, patterns in polymorphic_patterns.items():
                pattern_count = sum(1 for pattern in patterns if pattern in api_string)
                if pattern_count > 0:
                    threat_score += pattern_count * 15
                    self.ml_logger.info(f"Padrão {pattern_name} detectado {pattern_count} vezes - PID {pid}")
            
            # Bonus por combinação de padrões (comportamento polimórfico típico)
            if ('createremotethread' in api_string and 
                'connect:' in api_string and 
                len(api_calls) > 10):
                threat_score += 50
                self.ml_logger.warning(f"Combinação polimórfica detectada - PID {pid}")
            
            return min(threat_score, 100)  # Cap em 100
            
        except Exception as e:
            self.ml_logger.error(f"Erro ao calcular threat score: {e}")
            return 0
    def _periodic_analysis(self):
        """Thread otimizada para análise periódica de processos"""
        while self.running:
            try:
                self.ml_logger.debug("Iniciando análise periódica")
                analyzed_count = 0
                
                # Analisar todos os processos com dados suficientes
                for pid in list(self.process_api_calls.keys()):
                    api_calls = list(self.process_api_calls[pid])
                    
                    if len(api_calls) >= self.config['min_api_calls']:
                        self.ml_logger.debug(f"Analisando processo {pid} com {len(api_calls)} API calls")
                        self._analyze_process(pid)
                        analyzed_count += 1
                
                # Limpar processos antigos periodicamente
                current_time = datetime.now()
                if (current_time - self.last_cleanup).seconds > 300:  # 5 minutos
                    self._cleanup_old_processes()
                    self.last_cleanup = current_time
                
                self.ml_logger.debug(f"Análise periódica concluída: {analyzed_count} processos analisados")
                time.sleep(self.config['analysis_interval'])
                
            except Exception as e:
                self.logger.debug(f"Erro na análise periódica: {e}")
                time.sleep(5)  # Esperar mais em caso de erro
    
    def _analyze_process(self, pid):
        """Analisar um processo específico com detecção aprimorada"""
        try:
            api_calls = list(self.process_api_calls[pid])
            
            if len(api_calls) < self.config['min_api_calls']:
                self.ml_logger.debug(f"Processo {pid} tem apenas {len(api_calls)} API calls - pulando análise")
                return
            
            self.ml_logger.info(f"Analisando processo {pid} com {len(api_calls)} API calls")
            
            # Calcular threat score customizado
            threat_score = self._calculate_threat_score(pid, api_calls)
            
            # Fazer predição do modelo ML
            ml_result = self._predict(api_calls, pid)
            
            # Combinar resultados
            if ml_result:
                # Ajustar confiança baseado no threat score
                adjusted_confidence = (ml_result['confidence'] + (threat_score / 100)) / 2
                ml_result['threat_score'] = threat_score
                ml_result['adjusted_confidence'] = adjusted_confidence
                
                # Decisão final considerando ambos os fatores
                is_malware = (adjusted_confidence > self.config['detection_threshold'] or 
                             threat_score > 70 or
                             (ml_result['confidence'] > 0.4 and threat_score > 50))
                
                ml_result['is_malware'] = is_malware
                
                self.ml_logger.info(f"Análise PID {pid}: ML={ml_result['confidence']:.3f}, "
                                  f"Threat={threat_score}, Adjusted={adjusted_confidence:.3f}, "
                                  f"Malware={is_malware}")
                
                if is_malware:
                    self._handle_malware_detection(pid, ml_result)
                else:
                    self.ml_logger.debug(f"Processo {pid} considerado benigno")
            
            # Limpar buffer após análise (mas manter um histórico mínimo)
            if len(api_calls) > 100:
                # Manter últimas 50 API calls para contexto
                self.process_api_calls[pid] = deque(api_calls[-50:], maxlen=500)
            
        except Exception as e:
            self.logger.error(f"Erro ao analisar processo {pid}: {e}")
            self.ml_logger.error(f"Erro na análise do processo {pid}: {e}")
    
    def _predict(self, api_calls, pid):
        """Fazer predição otimizada sobre API calls"""
        try:
            # Converter para string
            api_sequence = ' '.join(api_calls)
            
            self.ml_logger.debug(f"Predição para PID {pid}: {api_sequence[:100]}...")
            
            # Pré-processar
            X_processed = self._preprocess_sample(api_sequence)
            
            # Predição
            prediction = self.model.predict([X_processed])[0]
            probabilities = self.model.predict_proba([X_processed])[0]
            
            # Label original
            if self.label_encoder:
                predicted_label = self.label_encoder.inverse_transform([prediction])[0]
            else:
                predicted_label = str(prediction)
            
            confidence = max(probabilities)
            
            self.ml_logger.debug(f"Predição PID {pid}: {predicted_label} (confiança: {confidence:.3f})")
            
            return {
                'pid': pid,
                'prediction': predicted_label,
                'confidence': confidence,
                'probabilities': probabilities.tolist(),
                'api_calls': api_calls,
                'timestamp': datetime.now()
            }
            
        except Exception as e:
            self.ml_logger.error(f"Erro na predição para PID {pid}: {e}")
            return None
    
    def _preprocess_sample(self, api_sequence):
        """Pré-processar amostra"""
        # TF-IDF
        if self.tfidf_vectorizer:
            X = self.tfidf_vectorizer.transform([api_sequence]).toarray()
        else:
            X = [[len(api_sequence.split())]]
        
        # Feature selection
        if self.feature_selector:
            X = self.feature_selector.transform(X)
        
        # PCA
        if self.pca:
            X = self.pca.transform(X)
        
        return X[0]
    
    def _handle_malware_detection(self, pid, result):
        """Lidar com detecção de malware aprimorada"""
        self.stats['malware_detected'] += 1
        self.detections.append(result)
        
        # Log crítico detalhado
        self.logger.critical("=" * 80)
        self.logger.critical("🚨 MALWARE DETECTADO!")
        self.logger.critical("=" * 80)
        self.logger.critical(f"PID: {pid}")
        self.logger.critical(f"Tipo: {result['prediction']}")
        self.logger.critical(f"Confiança ML: {result['confidence']:.3f}")
        
        if 'threat_score' in result:
            self.logger.critical(f"Threat Score: {result['threat_score']}")
            self.logger.critical(f"Confiança Ajustada: {result['adjusted_confidence']:.3f}")
        
        # Informações detalhadas do processo
        if pid in self.process_info:
            info = self.process_info[pid]
            self.logger.critical(f"Processo: {info.get('process_name', 'N/A')}")
            self.logger.critical(f"Imagem: {info.get('image', 'N/A')}")
            self.logger.critical(f"Linha de Comando: {info.get('cmdline', 'N/A')[:100]}...")
            self.logger.critical(f"Processo Pai: {info.get('parent', 'N/A')}")
            self.logger.critical(f"Score Suspeito: {info.get('suspicious_score', 0)}")
            self.logger.critical(f"Primeiro Visto: {info.get('first_seen', 'N/A')}")
        
        # Estatísticas de padrões polimórficos
        if pid in self.pattern_counters:
            patterns = dict(self.pattern_counters[pid])
            if patterns:
                self.logger.critical(f"Padrões Polimórficos: {patterns}")
        
        # API Calls detectadas (primeiras 15 para evitar logs muito longos)
        api_calls_summary = result['api_calls'][:15]
        self.logger.critical(f"API Calls: {', '.join(api_calls_summary)}")
        if len(result['api_calls']) > 15:
            self.logger.critical(f"... e mais {len(result['api_calls']) - 15} calls")
        
        self.logger.critical("=" * 80 + "\n")
        
        # Log no arquivo específico de detecções
        self.event_logger.critical(f"MALWARE DETECTADO - PID: {pid}, Tipo: {result['prediction']}, "
                                 f"Confiança: {result['confidence']:.3f}")
        
        # Salvar evidências detalhadas
        if self.config['save_evidence']:
            self._save_evidence(pid, result)
        
        # Quarentena
        if self.config['quarantine_enabled']:
            self._quarantine_process(pid)
        
        # Webhook
        if self.config.get('alert_webhook'):
            self._send_webhook_alert(result)
    
    def _cleanup_old_processes(self):
        """Limpar dados de processos otimizada"""
        cleanup_count = 0
        current_time = datetime.now()
        
        for pid in list(self.process_api_calls.keys()):
            try:
                # Verificar se processo ainda existe
                psutil.Process(int(pid))
                
                # Verificar se processo é muito antigo (mais de 1 hora sem atividade)
                if pid in self.process_info:
                    first_seen = self.process_info[pid].get('first_seen', current_time)
                    if (current_time - first_seen).seconds > 3600:  # 1 hora
                        self.event_logger.debug(f"Removendo processo antigo: {pid}")
                        if pid in self.process_api_calls:
                            del self.process_api_calls[pid]
                        if pid in self.process_info:
                            del self.process_info[pid]
                        if pid in self.pattern_counters:
                            del self.pattern_counters[pid]
                        cleanup_count += 1
                        
            except psutil.NoSuchProcess:
                # Processo não existe mais, limpar
                self.event_logger.debug(f"Removendo processo inexistente: {pid}")
                if pid in self.process_api_calls:
                    del self.process_api_calls[pid]
                if pid in self.process_info:
                    del self.process_info[pid]
                if pid in self.pattern_counters:
                    del self.pattern_counters[pid]
                cleanup_count += 1
        
        if cleanup_count > 0:
            self.logger.debug(f"Limpeza concluída: {cleanup_count} processos removidos")
    
    def _print_status(self):
        """Imprimir status detalhado atual"""
        if not self.stats.get('start_time'):
            return
            
        uptime = datetime.now() - self.stats['start_time']
        current_processes = len(self.process_api_calls)
        
        self.logger.info("=" * 60)
        self.logger.info("📊 STATUS DO DETECTOR")
        self.logger.info("=" * 60)
        self.logger.info(f"⏱️  Uptime: {uptime}")
        self.logger.info(f"📈 Eventos/segundo: {self.stats.get('events_per_second', 0):.1f}")
        self.logger.info(f"📊 Eventos processados: {self.stats['events_processed']}")
        self.logger.info(f"👁️  Processos monitorados: {current_processes}")
        self.logger.info(f"🛡️  Total processos vistos: {self.stats['processes_monitored']}")
        self.logger.info(f"🚨 Malware detectado: {self.stats['malware_detected']}")
        self.logger.info(f"🔒 Processos em quarentena: {self.stats['quarantined']}")
        self.logger.info(f"🧬 Comportamento polimórfico: {self.stats['polymorphic_detected']}")
        self.logger.info(f"💬 Comunicações IA: {self.stats['ai_communications']}")
        self.logger.info(f"💉 Injeções de memória: {self.stats['memory_injections']}")
        self.logger.info(f"📅 Última atividade: {self.stats.get('last_event_time', 'N/A')}")
        self.logger.info("=" * 60 + "\n")
    
    def _print_final_statistics(self):
        """Imprimir estatísticas finais detalhadas"""
        if not self.stats.get('start_time'):
            return
            
        uptime = datetime.now() - self.stats['start_time']
        
        self.logger.info("\n" + "=" * 80)
        self.logger.info("📊 ESTATÍSTICAS FINAIS DO DETECTOR")
        self.logger.info("=" * 80)
        self.logger.info(f"⏱️  Tempo de execução: {uptime}")
        self.logger.info(f"📊 Total de eventos processados: {self.stats['events_processed']}")
        self.logger.info(f"👁️  Processos monitorados: {self.stats['processes_monitored']}")
        self.logger.info(f"🚨 Malware detectado: {self.stats['malware_detected']}")
        self.logger.info(f"🔒 Processos em quarentena: {self.stats['quarantined']}")
        self.logger.info(f"❌ Falsos positivos: {self.stats['false_positives']}")
        self.logger.info(f"🧬 Comportamento polimórfico: {self.stats['polymorphic_detected']}")
        self.logger.info(f"💬 Comunicações com IA: {self.stats['ai_communications']}")
        self.logger.info(f"💉 Injeções de memória: {self.stats['memory_injections']}")
        
        if self.stats['events_processed'] > 0 and uptime.total_seconds() > 0:
            events_per_second = self.stats['events_processed'] / uptime.total_seconds()
            self.logger.info(f"📈 Taxa média de eventos: {events_per_second:.2f}/segundo")
        
        if self.stats['processes_monitored'] > 0:
            detection_rate = (self.stats['malware_detected'] / self.stats['processes_monitored']) * 100
            self.logger.info(f"🎯 Taxa de detecção: {detection_rate:.2f}%")
        
        self.logger.info("=" * 80)
        self.logger.info("🏁 DETECTOR FINALIZADO")
        self.logger.info("=" * 80 + "\n")


def main():
    """Função principal otimizada"""
    import argparse
    import ctypes
    
    parser = argparse.ArgumentParser(
        description='Detector de Malware Integrado com Sysmon - Versão Otimizada para Malware Polimórfico',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python detection_sistem.py --model ../Tentativa2/optimized_malware_detector.joblib
  python detection_sistem.py --model ../Tentativa2/optimized_malware_detector.joblib --config config.json
  python detection_sistem.py --model ../Tentativa2/optimized_malware_detector.joblib --threshold 0.5 --no-quarantine
  python detection_sistem.py --model ../Tentativa2/optimized_malware_detector.joblib --debug --verbose
  
Configurações específicas para malware polimórfico:
  - Threshold padrão reduzido para 0.5 devido à complexidade do malware
  - Análise mais frequente (5 segundos)
  - Detecção específica de comunicação com IA
  - Monitoramento de injeção de código em tempo real
        """
    )
    
    parser.add_argument('--model', required=True, 
                       help='Caminho para o modelo treinado (.joblib)')
    parser.add_argument('--config', 
                       help='Caminho para arquivo de configuração (.json)')
    parser.add_argument('--threshold', type=float, default=0.5,
                       help='Threshold de detecção (0-1, padrão: 0.5)')
    parser.add_argument('--no-quarantine', action='store_true',
                       help='Desabilitar quarentena automática')
    parser.add_argument('--debug', action='store_true',
                       help='Habilitar modo debug com logs detalhados')
    parser.add_argument('--verbose', action='store_true',
                       help='Habilitar logs verbosos')
    parser.add_argument('--test-mode', action='store_true',
                       help='Modo de teste - não termina processos')
    
    args = parser.parse_args()
    
    try:
        print("🛡️ DETECTOR DE MALWARE POLIMÓRFICO - VERSÃO OTIMIZADA")
        print("=" * 70)
        print(f"📁 Modelo: {args.model}")
        print(f"🎯 Threshold: {args.threshold}")
        print(f"🔍 Debug: {'Habilitado' if args.debug else 'Desabilitado'}")
        print(f"📝 Verbose: {'Habilitado' if args.verbose else 'Desabilitado'}")
        print("=" * 70)
        
        # Verificar se está executando como administrador
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠️ AVISO: Execute como Administrador para melhor funcionalidade")
            print("Alguns recursos podem não funcionar corretamente\n")
        
        # Verificar se o modelo existe
        if not Path(args.model).exists():
            print(f"❌ ERRO: Modelo não encontrado: {args.model}")
            print("Verifique o caminho do arquivo")
            return
        
        # Inicializar detector
        print("🚀 Inicializando detector...")
        detector = SysmonMalwareDetector(args.model, args.config)
        
        # Aplicar configurações da linha de comando
        detector.config['detection_threshold'] = args.threshold
        
        if args.no_quarantine or args.test_mode:
            detector.config['quarantine_enabled'] = False
            print("⚠️ Quarentena desabilitada")
        
        if args.debug:
            detector.config['verbose_logging'] = True
            # Configurar logging para debug
            import logging
            logging.getLogger().setLevel(logging.DEBUG)
            print("🔍 Modo debug habilitado")
        
        if args.verbose:
            detector.config['verbose_logging'] = True
            print("📝 Logs verbosos habilitados")
        
        if args.test_mode:
            print("🧪 Modo de teste habilitado - processos não serão terminados")
        
        print("\n✅ Configuração concluída")
        print("📋 Configurações aplicadas:")
        print(f"   - Threshold: {detector.config['detection_threshold']}")
        print(f"   - Quarentena: {'Habilitada' if detector.config['quarantine_enabled'] else 'Desabilitada'}")
        print(f"   - Eventos monitorados: {len(detector.config['sysmon_events'])}")
        print(f"   - Análise a cada: {detector.config['analysis_interval']} segundos")
        print(f"   - Mín. API calls: {detector.config['min_api_calls']}")
        
        # Iniciar monitoramento
        print("\n🎯 Iniciando monitoramento...")
        detector.start()
        
    except FileNotFoundError:
        print(f"❌ ERRO: Arquivo não encontrado: {args.model}")
        print("Verifique o caminho do arquivo")
    except KeyboardInterrupt:
        print("\n⚠️ Interrupção do usuário")
    except Exception as e:
        print(f"❌ ERRO CRÍTICO: {e}")
        import traceback
        traceback.print_exc()
        
        # Log adicional para debugging
        try:
            error_log = Path("logs") / "error.log"
            error_log.parent.mkdir(exist_ok=True)
            with open(error_log, 'a', encoding='utf-8') as f:
                f.write(f"\n{datetime.now()}: {e}\n")
                f.write(traceback.format_exc())
                f.write("\n" + "="*50 + "\n")
        except:
            pass


if __name__ == "__main__":
    main()