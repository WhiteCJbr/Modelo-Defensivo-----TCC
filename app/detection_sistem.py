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
        self.process_api_calls = defaultdict(lambda: deque(maxlen=200))
        self.process_info = {}
        
        # Histórico de detecções
        self.detections = deque(maxlen=1000)
        
        # Controle de execução
        self.running = False
        self.sysmon_handle = None
        
        # Estatísticas
        self.stats = {
            'events_processed': 0,
            'processes_monitored': 0,
            'malware_detected': 0,
            'quarantined': 0,
            'start_time': None
        }
        
        # Mapeamento de Event IDs do Sysmon
        self.event_handlers = {
            1: self._handle_process_create,
            3: self._handle_network_connect,
            7: self._handle_image_load,
            8: self._handle_create_remote_thread,
            10: self._handle_process_access,
            11: self._handle_file_create,
            12: self._handle_registry_event,
            13: self._handle_registry_event,
            14: self._handle_registry_event
        }
        
        self.logger.info("✅ Detector inicializado com sucesso\n")
    
    def _setup_logging(self):
        """Configurar sistema de logging"""
        log_format = '%(asctime)s [%(levelname)s] %(message)s'
        
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.FileHandler('sysmon_detector.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
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
        """Carregar configurações"""
        default_config = {
            'detection_threshold': 0.7,
            'analysis_interval': 10,
            'min_api_calls': 5,
            'quarantine_enabled': True,
            'save_evidence': True,
            'alert_webhook': None,
            'sysmon_events': [1, 3, 7, 8, 10, 11, 12, 13, 14],
            'whitelist_processes': [
                'svchost.exe',
                'System',
                'smss.exe',
                'csrss.exe',
                'wininit.exe',
                'services.exe'
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
        """Thread para monitorar eventos do Sysmon em tempo real"""
        try:
            # Abrir log do Sysmon
            self.sysmon_handle = win32evtlog.OpenEventLog(
                None, 
                "Microsoft-Windows-Sysmon/Operational"
            )
            
            # Configurar para ler eventos mais recentes
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            self.logger.info("✓ Conectado ao log do Sysmon")
            
            while self.running:
                try:
                    # Ler eventos
                    events = win32evtlog.ReadEventLog(
                        self.sysmon_handle,
                        flags,
                        0
                    )
                    
                    if events:
                        for event in events:
                            if not self.running:
                                break
                            
                            self._process_sysmon_event(event)
                            self.stats['events_processed'] += 1
                    
                    # Pequeno delay para não sobrecarregar CPU
                    time.sleep(0.1)
                    
                except Exception as e:
                    if self.running:
                        self.logger.debug(f"Erro ao ler eventos: {e}")
                        time.sleep(1)
            
        except Exception as e:
            self.logger.error(f"Erro no monitoramento Sysmon: {e}")
    
    def _process_sysmon_event(self, event):
        """Processar evento individual do Sysmon"""
        try:
            event_id = event.EventID & 0xFFFF  # Remover bits de severidade
            
            # Verificar se é um evento que monitoramos
            if event_id not in self.config['sysmon_events']:
                return
            
            # Extrair dados do evento
            event_data = self._parse_event_xml(event)
            
            if not event_data:
                return
            
            # Chamar handler apropriado
            handler = self.event_handlers.get(event_id)
            if handler:
                handler(event_data)
            
        except Exception as e:
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
        """Handler para Event ID 1: Process Creation"""
        pid = event_data.get('ProcessId')
        image = event_data.get('Image', '')
        
        if not pid:
            return
        
        # Verificar whitelist
        process_name = Path(image).name if image else ''
        if process_name in self.config['whitelist_processes']:
            return
        
        # Adicionar à lista de processos monitorados
        self.process_info[pid] = {
            'image': image,
            'cmdline': event_data.get('CommandLine', ''),
            'parent': event_data.get('ParentImage', ''),
            'first_seen': datetime.now()
        }
        
        # Registrar API call
        self.process_api_calls[pid].append('CreateProcess')
        
        self.stats['processes_monitored'] += 1
    
    def _handle_network_connect(self, event_data):
        """Handler para Event ID 3: Network Connection"""
        pid = event_data.get('ProcessId')
        dest_ip = event_data.get('DestinationIp')
        dest_port = event_data.get('DestinationPort')
        
        if pid:
            api_call = f"connect:{dest_ip}:{dest_port}" if dest_ip else "connect"
            self.process_api_calls[pid].append(api_call)
    
    def _handle_image_load(self, event_data):
        """Handler para Event ID 7: Image/DLL Load"""
        pid = event_data.get('ProcessId')
        image_loaded = event_data.get('ImageLoaded', '')
        
        if pid:
            dll_name = Path(image_loaded).name if image_loaded else 'unknown'
            self.process_api_calls[pid].append(f"LoadLibrary:{dll_name}")
    
    def _handle_create_remote_thread(self, event_data):
        """Handler para Event ID 8: CreateRemoteThread"""
        source_pid = event_data.get('SourceProcessId')
        target_pid = event_data.get('TargetProcessId')
        
        if source_pid:
            self.process_api_calls[source_pid].append('CreateRemoteThread')
        
        # API call muito suspeita, analisar imediatamente
        if source_pid and len(self.process_api_calls[source_pid]) >= 3:
            self._analyze_process(source_pid)
    
    def _handle_process_access(self, event_data):
        """Handler para Event ID 10: Process Access"""
        source_pid = event_data.get('SourceProcessId')
        target_image = event_data.get('TargetImage', '')
        
        if source_pid:
            # Acesso a processos críticos é suspeito
            critical_processes = ['lsass.exe', 'winlogon.exe', 'csrss.exe']
            target_name = Path(target_image).name if target_image else ''
            
            if target_name in critical_processes:
                self.process_api_calls[source_pid].append(f"OpenProcess:{target_name}")
                # Analisar imediatamente
                self._analyze_process(source_pid)
            else:
                self.process_api_calls[source_pid].append('OpenProcess')
    
    def _handle_file_create(self, event_data):
        """Handler para Event ID 11: File Create"""
        pid = event_data.get('ProcessId')
        filename = event_data.get('TargetFilename', '')
        
        if pid:
            # Verificar extensões suspeitas
            suspicious_extensions = ['.exe', '.dll', '.scr', '.bat', '.ps1', '.vbs']
            if any(filename.lower().endswith(ext) for ext in suspicious_extensions):
                self.process_api_calls[pid].append(f"CreateFile:{Path(filename).suffix}")
            else:
                self.process_api_calls[pid].append('CreateFile')
    
    def _handle_registry_event(self, event_data):
        """Handler para Event IDs 12/13/14: Registry Events"""
        pid = event_data.get('ProcessId')
        
        if pid:
            self.process_api_calls[pid].append('RegSetValue')
    
    def _periodic_analysis(self):
        """Thread para análise periódica de processos"""
        while self.running:
            try:
                # Analisar todos os processos com dados suficientes
                for pid in list(self.process_api_calls.keys()):
                    if len(self.process_api_calls[pid]) >= self.config['min_api_calls']:
                        self._analyze_process(pid)
                
                # Limpar processos antigos
                self._cleanup_old_processes()
                
                time.sleep(self.config['analysis_interval'])
                
            except Exception as e:
                self.logger.debug(f"Erro na análise periódica: {e}")
    
    def _analyze_process(self, pid):
        """Analisar um processo específico"""
        try:
            api_calls = list(self.process_api_calls[pid])
            
            if len(api_calls) < self.config['min_api_calls']:
                return
            
            # Fazer predição
            result = self._predict(api_calls, pid)
            
            if result and result['is_malware']:
                self._handle_malware_detection(pid, result)
            
            # Limpar buffer após análise
            self.process_api_calls[pid].clear()
            
        except Exception as e:
            self.logger.debug(f"Erro ao analisar processo {pid}: {e}")
    
    def _predict(self, api_calls, pid):
        """Fazer predição sobre API calls"""
        try:
            # Converter para string
            api_sequence = ' '.join(api_calls)
            
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
            is_malware = (confidence > self.config['detection_threshold'] and 
                         predicted_label.lower() != 'benign')
            
            return {
                'pid': pid,
                'prediction': predicted_label,
                'confidence': confidence,
                'is_malware': is_malware,
                'api_calls': api_calls,
                'timestamp': datetime.now()
            }
            
        except Exception as e:
            self.logger.debug(f"Erro na predição: {e}")
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
        """Lidar com detecção de malware"""
        self.stats['malware_detected'] += 1
        self.detections.append(result)
        
        # Log crítico
        self.logger.critical("=" * 60)
        self.logger.critical("🚨 MALWARE DETECTADO!")
        self.logger.critical(f"PID: {pid}")
        self.logger.critical(f"Tipo: {result['prediction']}")
        self.logger.critical(f"Confiança: {result['confidence']:.3f}")
        
        # Informações do processo
        if pid in self.process_info:
            info = self.process_info[pid]
            self.logger.critical(f"Imagem: {info.get('image', 'N/A')}")
            self.logger.critical(f"Linha de Comando: {info.get('cmdline', 'N/A')}")
        
        # API Calls detectadas
        self.logger.critical(f"API Calls: {', '.join(result['api_calls'][:10])}")
        self.logger.critical("=" * 60 + "\n")
        
        # Salvar evidências
        if self.config['save_evidence']:
            self._save_evidence(pid, result)
        
        # Quarentena
        if self.config['quarantine_enabled']:
            self._quarantine_process(pid)
        
        # Webhook
        if self.config.get('alert_webhook'):
            self._send_webhook_alert(result)
    
    def _quarantine_process(self, pid):
        """Terminar processo malicioso"""
        try:
            proc = psutil.Process(int(pid))
            proc_name = proc.name()
            
            self.logger.warning(f"⚠️ Terminando processo: {proc_name} (PID: {pid})")
            
            proc.terminate()
            proc.wait(timeout=5)
            
            self.stats['quarantined'] += 1
            self.logger.info(f"✅ Processo terminado com sucesso\n")
            
        except psutil.TimeoutExpired:
            try:
                proc.kill()
                self.logger.warning(f"⚠️ Processo foi forçado a terminar\n")
            except:
                pass
        except Exception as e:
            self.logger.error(f"❌ Erro ao terminar processo: {e}\n")
    
    def _save_evidence(self, pid, result):
        """Salvar evidências"""
        evidence_dir = Path("evidence")
        evidence_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = evidence_dir / f"detection_{pid}_{timestamp}.json"
        
        try:
            evidence = {
                'detection': {
                    'pid': pid,
                    'prediction': result['prediction'],
                    'confidence': result['confidence'],
                    'timestamp': str(result['timestamp'])
                },
                'process_info': self.process_info.get(pid, {}),
                'api_calls': result['api_calls'],
                'system_time': str(datetime.now())
            }
            
            # Serializar com formatação
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(evidence, f, indent=2, default=str, ensure_ascii=False)
            
            self.logger.info(f"📁 Evidência salva: {filename}\n")
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar evidência: {e}")
    
    def _send_webhook_alert(self, result):
        """Enviar alerta via webhook"""
        try:
            import requests
            
            payload = {
                'type': 'malware_detection',
                'severity': 'critical',
                'prediction': result['prediction'],
                'confidence': result['confidence'],
                'pid': result['pid'],
                'timestamp': str(result['timestamp'])
            }
            
            response = requests.post(
                self.config['alert_webhook'],
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                self.logger.info("✅ Alerta enviado via webhook")
                
        except Exception as e:
            self.logger.debug(f"Erro ao enviar webhook: {e}")
    
    def _cleanup_old_processes(self):
        """Limpar dados de processos que não existem mais"""
        for pid in list(self.process_api_calls.keys()):
            try:
                psutil.Process(int(pid))
            except psutil.NoSuchProcess:
                # Processo não existe mais, limpar
                if pid in self.process_api_calls:
                    del self.process_api_calls[pid]
                if pid in self.process_info:
                    del self.process_info[pid]
    
    def _print_status(self):
        """Imprimir status atual"""
        uptime = datetime.now() - self.stats['start_time']
        
        self.logger.info(f"📊 STATUS - Uptime: {uptime}")
        self.logger.info(f"   Eventos: {self.stats['events_processed']} | "
                        f"Processos: {self.stats['processes_monitored']} | "
                        f"Malware: {self.stats['malware_detected']} | "
                        f"Quarentena: {self.stats['quarantined']}\n")
    
    def _print_final_statistics(self):
        """Imprimir estatísticas finais"""
        uptime = datetime.now() - self.stats['start_time']
        
        self.logger.info("\n" + "=" * 60)
        self.logger.info("📊 ESTATÍSTICAS FINAIS")
        self.logger.info("=" * 60)
        self.logger.info(f"Tempo de execução: {uptime}")
        self.logger.info(f"Eventos processados: {self.stats['events_processed']}")
        self.logger.info(f"Processos monitorados: {self.stats['processes_monitored']}")
        self.logger.info(f"Malware detectado: {self.stats['malware_detected']}")
        self.logger.info(f"Processos em quarentena: {self.stats['quarantined']}")
        self.logger.info("=" * 60 + "\n")


def main():
    """Função principal"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Detector de Malware Integrado com Sysmon',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python sysmon_detector.py --model model.joblib
  python sysmon_detector.py --model model.joblib --config config.json
  python sysmon_detector.py --model model.joblib --threshold 0.8 --no-quarantine
        """
    )
    
    parser.add_argument('--model', required=True, 
                       help='Caminho para o modelo treinado (.joblib)')
    parser.add_argument('--config', 
                       help='Caminho para arquivo de configuração (.json)')
    parser.add_argument('--threshold', type=float, 
                       help='Threshold de detecção (0-1)')
    parser.add_argument('--no-quarantine', action='store_true',
                       help='Desabilitar quarentena automática')
    
    args = parser.parse_args()
    
    try:
        # Verificar se está executando como administrador
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠️ AVISO: Execute como Administrador para melhor funcionalidade")
            print("Alguns recursos podem não funcionar corretamente\n")
        
        # Inicializar detector
        detector = SysmonMalwareDetector(args.model, args.config)
        
        # Aplicar configurações da linha de comando
        if args.threshold:
            detector.config['detection_threshold'] = args.threshold
        
        if args.no_quarantine:
            detector.config['quarantine_enabled'] = False
        
        # Iniciar monitoramento
        detector.start()
        
    except FileNotFoundError:
        print(f"❌ ERRO: Modelo não encontrado: {args.model}")
        print("Verifique o caminho do arquivo")
    except Exception as e:
        print(f"❌ ERRO: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()