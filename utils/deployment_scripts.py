# ========================================
# SCRIPTS DE DEPLOYMENT E CONFIGURAÇÃO
# ========================================

import os
import sys
import subprocess
import json
import requests
import zipfile
from pathlib import Path

class SystemDeployment:
    """
    Sistema de deployment automatizado para o detector de malware
    """
    
    def __init__(self):
        self.base_path = Path.cwd()
        self.config = {
            "sysmon_url": "https://download.sysinternals.com/files/Sysmon.zip",
            "sysmon_config_url": "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",
            "malapi_dataset_url": "https://github.com/ocatak/malware_api_class/raw/main/data/malapi2019.csv"
        }
    
    def full_deployment(self):
        """Deployment completo do sistema"""
        
        print("🚀 INICIANDO DEPLOYMENT COMPLETO")
        print("=" * 50)
        
        steps = [
            ("Verificando privilégios administrativos", self._check_admin_privileges),
            ("Instalando dependências Python", self._install_python_dependencies),
            ("Baixando e configurando Sysmon", self._setup_sysmon),
            ("Baixando dataset MALAPI2019", self._download_dataset),
            ("Configurando serviço Windows", self._setup_windows_service),
            ("Criando scripts de controle", self._create_control_scripts),
            ("Configurando logging", self._setup_logging),
            ("Executando testes finais", self._final_tests)
        ]
        
        for step_name, step_func in steps:
            print(f"\n📋 {step_name}...")
            try:
                step_func()
                print(f"✅ {step_name}: CONCLUÍDO")
            except Exception as e:
                print(f"❌ {step_name}: FALHOU - {e}")
                return False
        
        print("\n🎉 DEPLOYMENT CONCLUÍDO COM SUCESSO!")
        print("🛡️  O sistema está pronto para detectar malware polimórfico")
        
        return True
    
    def _check_admin_privileges(self):
        """Verificar privilégios administrativos"""
        import ctypes
        
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise PermissionError("Execute como administrador para instalar o Sysmon")
        
        print("✓ Privilégios administrativos confirmados")
    
    def _install_python_dependencies(self):
        """Instalar dependências Python"""
        
        requirements = [
            "pandas>=1.3.0",
            "numpy>=1.21.0", 
            "scikit-learn>=1.0.0",
            "xgboost>=1.5.0",
            "shap>=0.40.0",
            "psutil>=5.8.0",
            "pywin32>=227",
            "matplotlib>=3.3.0",
            "seaborn>=0.11.0",
            "joblib>=1.1.0",
            "requests>=2.25.0"
        ]
        
        for requirement in requirements:
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", requirement], 
                             check=True, capture_output=True)
                print(f"✓ Instalado: {requirement}")
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Falha ao instalar {requirement}: {e}")
    
    def _setup_sysmon(self):
        """Baixar e configurar Sysmon"""
        
        sysmon_dir = self.base_path / "sysmon"
        sysmon_dir.mkdir(exist_ok=True)
        
        # Baixar Sysmon
        sysmon_zip = sysmon_dir / "Sysmon.zip"
        
        print("Baixando Sysmon...")
        response = requests.get(self.config["sysmon_url"])
        response.raise_for_status()
        
        with open(sysmon_zip, 'wb') as f:
            f.write(response.content)
        
        # Extrair Sysmon
        with zipfile.ZipFile(sysmon_zip, 'r') as zip_ref:
            zip_ref.extractall(sysmon_dir)
        
        # Baixar configuração
        config_file = sysmon_dir / "sysmonconfig.xml"
        
        print("Baixando configuração do Sysmon...")
        response = requests.get(self.config["sysmon_config_url"])
        response.raise_for_status()
        
        with open(config_file, 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        # Instalar Sysmon
        sysmon_exe = sysmon_dir / "Sysmon64.exe"
        
        print("Instalando Sysmon...")
        subprocess.run([
            str(sysmon_exe), 
            "-accepteula", 
            "-i", 
            str(config_file)
        ], check=True)
        
        print("✓ Sysmon instalado e configurado")
    
    def _download_dataset(self):
        """Baixar dataset MALAPI2019"""
        
        dataset_file = self.base_path / "malapi2019.csv"
        
        if dataset_file.exists():
            print("✓ Dataset já existe")
            return
        
        print("Baixando dataset MALAPI2019...")
        response = requests.get(self.config["malapi_dataset_url"])
        response.raise_for_status()
        
        with open(dataset_file, 'wb') as f:
            f.write(response.content)
        
        print("✓ Dataset baixado")
    
    def _setup_windows_service(self):
        """Configurar como serviço do Windows"""
        
        service_script = self.base_path / "malware_service.py"
        
        service_code = '''
import win32serviceutil
import win32service
import win32event
import logging
import sys
import os

# Adicionar diretório atual ao path
sys.path.insert(0, os.path.dirname(__file__))

from malware_detection_system import MalwareDetectionSystem

class MalwareDetectionService(win32serviceutil.ServiceFramework):
    _svc_name_ = "MalwarePolymorphicDetector"
    _svc_display_name_ = "Detector de Malware Polimórfico"
    _svc_description_ = "Serviço de detecção em tempo real de malware polimórfico controlado por LLM"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.detector = None
        
        # Configurar logging
        logging.basicConfig(
            filename='C:/malware_detector_service.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.detector:
            self.detector.stop_realtime_monitoring()
        win32event.SetEvent(self.hWaitStop)
        
    def SvcDoRun(self):
        try:
            # Inicializar detector
            self.detector = MalwareDetectionSystem()
            self.detector.load_model("production_model.joblib")
            
            # Iniciar monitoramento
            self.detector.start_realtime_monitoring()
            
            logging.info("Serviço de detecção iniciado")
            
            # Aguardar sinal de parada
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
            
        except Exception as e:
            logging.error(f"Erro no serviço: {e}")
            
        logging.info("Serviço de detecção parado")

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(MalwareDetectionService)
'''
        
        with open(service_script, 'w') as f:
            f.write(service_code)
        
        print("✓ Script de serviço criado")
        print("  Para instalar: python malware_service.py install")
        print("  Para iniciar: python malware_service.py start")
    
    def _create_control_scripts(self):
        """Criar scripts de controle"""
        
        # Script de início
        start_script = self.base_path / "start_detector.bat"
        
        start_content = '''@echo off
echo Iniciando Detector de Malware Polimórfico...
python malware_service.py start
echo Serviço iniciado!
pause
'''
        
        with open(start_script, 'w') as f:
            f.write(start_content)
        
        # Script de parada
        stop_script = self.base_path / "stop_detector.bat"
        
        stop_content = '''@echo off
echo Parando Detector de Malware Polimórfico...
python malware_service.py stop
echo Serviço parado!
pause
'''
        
        with open(stop_script, 'w') as f:
            f.write(stop_content)
        
        # Script de status
        status_script = self.base_path / "status_detector.bat"
        
        status_content = '''@echo off
echo Status do Detector de Malware Polimórfico:
python malware_service.py status
pause
'''
        
        with open(status_script, 'w') as f:
            f.write(status_content)
        
        print("✓ Scripts de controle criados")
    
    def _setup_logging(self):
        """Configurar sistema de logging"""
        
        log_dir = self.base_path / "logs"
        log_dir.mkdir(exist_ok=True)
        
        log_config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "detailed": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                },
                "simple": {
                    "format": "%(levelname)s - %(message)s"
                }
            },
            "handlers": {
                "file": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "filename": str(log_dir / "malware_detector.log"),
                    "maxBytes": 10485760,  # 10MB
                    "backupCount": 5,
                    "formatter": "detailed"
                },
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "simple"
                }
            },
            "loggers": {
                "malware_detector": {
                    "handlers": ["file", "console"],
                    "level": "INFO",
                    "propagate": False
                }
            },
            "root": {
                "level": "INFO",
                "handlers": ["file"]
            }
        }
        
        config_file = self.base_path / "logging_config.json"
        with open(config_file, 'w') as f:
            json.dump(log_config, f, indent=2)
        
        print("✓ Sistema de logging configurado")
    
    def _final_tests(self):
        """Testes finais do sistema"""
        
        # Teste 1: Verificar se Sysmon está rodando
        result = subprocess.run(
            ['sc', 'query', 'Sysmon64'],
            capture_output=True,
            text=True
        )
        
        if "RUNNING" not in result.stdout:
            raise RuntimeError("Sysmon não está executando")
        
        # Teste 2: Verificar arquivos essenciais
        essential_files = [
            "malapi2019.csv",
            "malware_service.py",
            "start_detector.bat",
            "stop_detector.bat"
        ]
        
        for file in essential_files:
            if not (self.base_path / file).exists():
                raise FileNotFoundError(f"Arquivo essencial não encontrado: {file}")
        
        print("✓ Todos os testes passaram")


# ========================================
# CONFIGURAÇÕES AVANÇADAS DE SYSMON
# ========================================

class SysmonConfiguration:
    """
    Configurações avançadas do Sysmon para detecção de malware polimórfico
    """
    
    def __init__(self):
        self.config_template = self._get_sysmon_config_template()
    
    def _get_sysmon_config_template(self):
        """Template de configuração otimizada para malware polimórfico"""
        
        return '''<?xml version="1.0" encoding="UTF-8"?>
<Sysmon schemaversion="4.82">
  <!-- Configuração otimizada para detecção de malware polimórfico controlado por LLM -->
  <HashAlgorithms>md5,sha256</HashAlgorithms>
  <CheckRevocation/>
  
  <EventFiltering>
    <!-- Event ID 1: Process Creation -->
    <ProcessCreate onmatch="include">
      <!-- Executáveis suspeitos -->
      <Image condition="end with">exe</Image>
      <Image condition="end with">scr</Image>
      <Image condition="end with">com</Image>
      <Image condition="end with">pif</Image>
      
      <!-- Processos com argumentos suspeitos -->
      <CommandLine condition="contains">powershell</CommandLine>
      <CommandLine condition="contains">cmd.exe</CommandLine>
      <CommandLine condition="contains">wscript</CommandLine>
      <CommandLine condition="contains">cscript</CommandLine>
      
      <!-- Processos iniciados de locais suspeitos -->
      <Image condition="begin with">C:\Users\</Image>
      <Image condition="begin with">C:\Temp\</Image>
      <Image condition="begin with">C:\Windows\Temp\</Image>
      
      <!-- Indicadores de malware polimórfico -->
      <CommandLine condition="contains">base64</CommandLine>
      <CommandLine condition="contains">invoke</CommandLine>
      <CommandLine condition="contains">downloadstring</CommandLine>
      <CommandLine condition="contains">iex</CommandLine>
    </ProcessCreate>
    
    <!-- Event ID 3: Network Connection -->
    <NetworkConnect onmatch="include">
      <!-- Conexões HTTP/HTTPS suspeitas -->
      <DestinationPort condition="is">80</DestinationPort>
      <DestinationPort condition="is">443</DestinationPort>
      <DestinationPort condition="is">8080</DestinationPort>
      <DestinationPort condition="is">8443</DestinationPort>
      
      <!-- Conexões para IPs suspeitos (exemplo) -->
      <DestinationIp condition="begin with">192.168.</DestinationIp>
      <DestinationIp condition="begin with">10.</DestinationIp>
      
      <!-- Protocolos comuns de C2 -->
      <DestinationPort condition="is">53</DestinationPort>  <!-- DNS -->
      <DestinationPort condition="is">25</DestinationPort>  <!-- SMTP -->
    </NetworkConnect>
    
    <!-- Event ID 7: Image/DLL Load -->
    <ImageLoad onmatch="include">
      <!-- DLLs suspeitas -->
      <ImageLoaded condition="end with">dll</ImageLoaded>
      <ImageLoaded condition="contains">inject</ImageLoaded>
      <ImageLoaded condition="contains">hook</ImageLoaded>
      
      <!-- Carregamento de DLLs de locais suspeitos -->
      <ImageLoaded condition="begin with">C:\Users\</ImageLoaded>
      <ImageLoaded condition="begin with">C:\Temp\</ImageLoaded>
    </ImageLoad>
    
    <!-- Event ID 8: CreateRemoteThread -->
    <CreateRemoteThread onmatch="exclude">
      <!-- Excluir processos conhecidos e seguros -->
      <SourceImage condition="is">C:\Windows\System32\svchost.exe</SourceImage>
      <SourceImage condition="is">C:\Windows\System32\wininit.exe</SourceImage>
    </CreateRemoteThread>
    
    <!-- Event ID 10: Process Access -->
    <ProcessAccess onmatch="include">
      <!-- Acesso suspeito a processos críticos -->
      <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
      <TargetImage condition="is">C:\Windows\System32\winlogon.exe</TargetImage>
      <TargetImage condition="is">C:\Windows\System32\csrss.exe</TargetImage>
    </ProcessAccess>
    
    <!-- Event ID 11: File Create -->
    <FileCreate onmatch="include">
      <!-- Criação de arquivos em locais suspeitos -->
      <TargetFilename condition="begin with">C:\Users\</TargetFilename>
      <TargetFilename condition="begin with">C:\Temp\</TargetFilename>
      <TargetFilename condition="begin with">C:\Windows\Temp\</TargetFilename>
      
      <!-- Extensões suspeitas -->
      <TargetFilename condition="end with">exe</TargetFilename>
      <TargetFilename condition="end with">dll</TargetFilename>
      <TargetFilename condition="end with">scr</TargetFilename>
      <TargetFilename condition="end with">bat</TargetFilename>
      <TargetFilename condition="end with">ps1</TargetFilename>
    </FileCreate>
    
    <!-- Event ID 12/13/14: Registry Events -->
    <RegistryEvent onmatch="include">
      <!-- Chaves de persistência -->
      <TargetObject condition="contains">\\CurrentVersion\\Run</TargetObject>
      <TargetObject condition="contains">\\CurrentVersion\\RunOnce</TargetObject>
      <TargetObject condition="contains">\\CurrentVersion\\Winlogon</TargetObject>
      
      <!-- Chaves de configuração suspeitas -->
      <TargetObject condition="contains">\\Policies\\System</TargetObject>
      <TargetObject condition="contains">\\Windows\\CurrentVersion\\Explorer</TargetObject>
    </RegistryEvent>
    
    <!-- Event ID 15: File Create Stream Hash -->
    <FileCreateStreamHash onmatch="include">
      <TargetFilename condition="end with">exe</TargetFilename>
      <TargetFilename condition="end with">dll</TargetFilename>
      <TargetFilename condition="end with">ps1</TargetFilename>
    </FileCreateStreamHash>
    
  </EventFiltering>
</Sysmon>'''
    
    def create_optimized_config(self, output_path="sysmonconfig-optimized.xml"):
        """Criar configuração otimizada do Sysmon"""
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(self.config_template)
        
        print(f"✓ Configuração otimizada criada: {output_path}")
        return output_path
    
    def update_sysmon_config(self, config_path):
        """Atualizar configuração do Sysmon"""
        
        try:
            # Parar Sysmon
            subprocess.run(['sc', 'stop', 'Sysmon64'], check=True)
            
            # Atualizar configuração
            subprocess.run([
                'sysmon64.exe', 
                '-c', 
                config_path
            ], check=True)
            
            # Reiniciar Sysmon
            subprocess.run(['sc', 'start', 'Sysmon64'], check=True)
            
            print("✓ Configuração do Sysmon atualizada")
            
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Falha ao atualizar Sysmon: {e}")


# ========================================
# MONITOR DE PERFORMANCE EM TEMPO REAL
# ========================================

class PerformanceMonitor:
    """
    Monitor de performance em tempo real do sistema de detecção
    """
    
    def __init__(self, detector):
        self.detector = detector
        self.metrics_history = []
        self.alert_thresholds = {
            'cpu_usage': 80,      # %
            'memory_usage': 85,   # %
            'detection_latency': 5,  # segundos
            'false_positive_rate': 0.1  # 10%
        }
        
    def start_monitoring(self, interval=60):
        """Iniciar monitoramento de performance"""
        
        import threading
        
        def monitor_loop():
            while self.detector.monitoring_active:
                try:
                    metrics = self._collect_metrics()
                    self._analyze_metrics(metrics)
                    self.metrics_history.append(metrics)
                    
                    # Manter apenas últimas 1440 medições (24h em intervalos de 1min)
                    if len(self.metrics_history) > 1440:
                        self.metrics_history.pop(0)
                    
                    time.sleep(interval)
                    
                except Exception as e:
                    print(f"Erro no monitoramento de performance: {e}")
        
        monitor_thread = threading.Thread(target=monitor_loop)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        print("🔍 Monitor de performance iniciado")
    
    def _collect_metrics(self):
        """Coletar métricas do sistema"""
        
        import time
        import psutil
        
        # Métricas do sistema
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk_io = psutil.disk_io_counters()
        
        # Métricas do detector
        detector_metrics = self.detector.get_performance_metrics()
        
        # Métricas de processos Python
        current_process = psutil.Process()
        
        metrics = {
            'timestamp': time.time(),
            'system': {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available_gb': memory.available / (1024**3),
                'disk_read_mb': disk_io.read_bytes / (1024**2) if disk_io else 0,
                'disk_write_mb': disk_io.write_bytes / (1024**2) if disk_io else 0
            },
            'detector_process': {
                'cpu_percent': current_process.cpu_percent(),
                'memory_mb': current_process.memory_info().rss / (1024**2),
                'threads': current_process.num_threads()
            },
            'detection': detector_metrics
        }
        
        return metrics
    
    def _analyze_metrics(self, metrics):
        """Analisar métricas e gerar alertas"""
        
        # Verificar thresholds
        alerts = []
        
        if metrics['system']['cpu_percent'] > self.alert_thresholds['cpu_usage']:
            alerts.append(f"🚨 CPU alta: {metrics['system']['cpu_percent']:.1f}%")
        
        if metrics['system']['memory_percent'] > self.alert_thresholds['memory_usage']:
            alerts.append(f"🚨 Memória alta: {metrics['system']['memory_percent']:.1f}%")
        
        if metrics['detector_process']['memory_mb'] > 1024:  # > 1GB
            alerts.append(f"🚨 Processo detector usando {metrics['detector_process']['memory_mb']:.0f}MB")
        
        # Verificar taxa de falsos positivos
        detection_metrics = metrics['detection']
        total_detections = (detection_metrics.get('true_positives', 0) + 
                          detection_metrics.get('false_positives', 0))
        
        if total_detections > 10:  # Mínimo de detecções para calcular taxa
            fp_rate = detection_metrics.get('false_positives', 0) / total_detections
            if fp_rate > self.alert_thresholds['false_positive_rate']:
                alerts.append(f"🚨 Taxa alta de falsos positivos: {fp_rate:.1%}")
        
        # Imprimir alertas
        for alert in alerts:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {alert}")
    
    def get_performance_report(self, hours=24):
        """Gerar relatório de performance"""
        
        if not self.metrics_history:
            return "Nenhum dado de performance disponível"
        
        # Filtrar últimas N horas
        cutoff_time = time.time() - (hours * 3600)
        recent_metrics = [m for m in self.metrics_history if m['timestamp'] >= cutoff_time]
        
        if not recent_metrics:
            return f"Nenhum dado dos últimas {hours} horas"
        
        # Calcular estatísticas
        cpu_values = [m['system']['cpu_percent'] for m in recent_metrics]
        memory_values = [m['system']['memory_percent'] for m in recent_metrics]
        detector_memory = [m['detector_process']['memory_mb'] for m in recent_metrics]
        
        report = f"""
📊 RELATÓRIO DE PERFORMANCE ({hours}h)
{'='*50}

🖥️  SISTEMA:
   CPU Média: {np.mean(cpu_values):.1f}%
   CPU Máxima: {np.max(cpu_values):.1f}%
   Memória Média: {np.mean(memory_values):.1f}%
   Memória Máxima: {np.max(memory_values):.1f}%

🔍 DETECTOR:
   Memória Média: {np.mean(detector_memory):.0f}MB
   Memória Máxima: {np.max(detector_memory):.0f}MB
   
🛡️  DETECÇÕES:
   Total de medições: {len(recent_metrics)}
   Período analisado: {hours}h
"""
        
        # Adicionar métricas de detecção se disponível
        if recent_metrics[-1]['detection']:
            det_metrics = recent_metrics[-1]['detection']
            report += f"""
   Verdadeiros Positivos: {det_metrics.get('true_positives', 0)}
   Falsos Positivos: {det_metrics.get('false_positives', 0)}
   Verdadeiros Negativos: {det_metrics.get('true_negatives', 0)}
   Falsos Negativos: {det_metrics.get('false_negatives', 0)}
"""
        
        return report


# ========================================
# INTERFACE DE LINHA DE COMANDO
# ========================================

class CLIInterface:
    """
    Interface de linha de comando para o sistema
    """
    
    def __init__(self):
        self.commands = {
            'deploy': self._deploy_command,
            'train': self._train_command,
            'start': self._start_command,
            'stop': self._stop_command,
            'status': self._status_command,
            'test': self._test_command,
            'report': self._report_command,
            'config': self._config_command,
            'help': self._help_command
        }
    
    def run(self, args):
        """Executar comando CLI"""
        
        if not args or args[0] not in self.commands:
            self._help_command()
            return
        
        command = args[0]
        command_args = args[1:] if len(args) > 1 else []
        
        try:
            self.commands[command](command_args)
        except Exception as e:
            print(f"❌ Erro ao executar comando '{command}': {e}")
    
    def _deploy_command(self, args):
        """Comando de deployment"""
        print("🚀 Iniciando deployment do sistema...")
        
        deployer = SystemDeployment()
        success = deployer.full_deployment()
        
        if success:
            print("✅ Sistema deployado com sucesso!")
            print("Use 'python cli.py start' para iniciar o detector")
        else:
            print("❌ Falha no deployment")
    
    def _train_command(self, args):
        """Comando de treinamento"""
        dataset_path = args[0] if args else "malapi2019.csv"
        
        print(f"🎯 Treinando modelo com dataset: {dataset_path}")
        
        from malware_detection_system import MalwareDetectionPipeline
        
        pipeline = MalwareDetectionPipeline()
        pipeline.run_complete_pipeline(dataset_path)
        
        print("✅ Treinamento concluído!")
    
    def _start_command(self, args):
        """Comando para iniciar o detector"""
        print("🛡️  Iniciando detector de malware...")
        
        try:
            from malware_detection_system import MalwareDetectionSystem
            
            detector = MalwareDetectionSystem()
            
            # Carregar modelo se existir
            model_path = "production_model.joblib"
            if Path(model_path).exists():
                detector.load_model(model_path)
            else:
                print("❌ Modelo não encontrado. Execute 'train' primeiro.")
                return
            
            # Iniciar monitoramento
            detector.start_realtime_monitoring()
            
            # Iniciar monitor de performance
            performance_monitor = PerformanceMonitor(detector)
            performance_monitor.start_monitoring()
            
            print("✅ Detector iniciado com sucesso!")
            print("Pressione Ctrl+C para parar")
            
            try:
                while True:
                    time.sleep(60)
                    metrics = detector.get_performance_metrics()
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] TP: {metrics.get('true_positives', 0)}, FP: {metrics.get('false_positives', 0)}")
            except KeyboardInterrupt:
                detector.stop_realtime_monitoring()
                print("\n🛑 Detector parado")
                
        except ImportError:
            print("❌ Sistema não está instalado. Execute 'deploy' primeiro.")
    
    def _stop_command(self, args):
        """Comando para parar o detector"""
        print("🛑 Parando detector de malware...")
        
        # Em implementação real, enviaria sinal para parar o serviço
        subprocess.run(['python', 'malware_service.py', 'stop'])
        
        print("✅ Detector parado")
    
    def _status_command(self, args):
        """Comando de status"""
        print("📊 Status do sistema:")
        
        # Verificar se Sysmon está rodando
        result = subprocess.run(['sc', 'query', 'Sysmon64'], 
                              capture_output=True, text=True)
        
        if "RUNNING" in result.stdout:
            print("✅ Sysmon: Executando")
        else:
            print("❌ Sysmon: Parado")
        
        # Verificar arquivos essenciais
        essential_files = [
            "production_model.joblib",
            "malapi2019.csv", 
            "malware_service.py"
        ]
        
        for file in essential_files:
            if Path(file).exists():
                print(f"✅ {file}: Presente")
            else:
                print(f"❌ {file}: Ausente")
    
    def _test_command(self, args):
        """Comando de teste"""
        print("🧪 Executando testes do sistema...")
        
        tests_passed = 0
        total_tests = 3
        
        # Teste 1: Importações
        try:
            from malware_detection_system import MalwareDetectionSystem
            print("✅ Teste 1: Importações OK")
            tests_passed += 1
        except ImportError as e:
            print(f"❌ Teste 1: Importações FALHOU - {e}")
        
        # Teste 2: Modelo
        try:
            if Path("production_model.joblib").exists():
                detector = MalwareDetectionSystem()
                detector.load_model("production_model.joblib")
                print("✅ Teste 2: Carregamento do modelo OK")
                tests_passed += 1
            else:
                print("❌ Teste 2: Modelo não encontrado")
        except Exception as e:
            print(f"❌ Teste 2: Carregamento do modelo FALHOU - {e}")
        
        # Teste 3: Sysmon
        try:
            result = subprocess.run(['sc', 'query', 'Sysmon64'], 
                                  capture_output=True, text=True)
            if "RUNNING" in result.stdout:
                print("✅ Teste 3: Sysmon OK")
                tests_passed += 1
            else:
                print("❌ Teste 3: Sysmon não está executando")
        except Exception as e:
            print(f"❌ Teste 3: Sysmon FALHOU - {e}")
        
        print(f"\n📋 Resultados: {tests_passed}/{total_tests} testes passaram")
    
    def _report_command(self, args):
        """Comando de relatório"""
        hours = int(args[0]) if args else 24
        
        print(f"📊 Gerando relatório das últimas {hours} horas...")
        
        # Em implementação real, carregaria métricas salvas
        print("Relatório de performance indisponível (detector não está executando)")
    
    def _config_command(self, args):
        """Comando de configuração"""
        print("⚙️  Configurações do sistema:")
        
        config_file = "deployment_config.json"
        if Path(config_file).exists():
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            print(json.dumps(config, indent=2))
        else:
            print("Arquivo de configuração não encontrado")
    
    def _help_command(self, args=None):
        """Comando de ajuda"""
        print("""
🛡️  DETECTOR DE MALWARE POLIMÓRFICO - AJUDA

COMANDOS DISPONÍVEIS:

  deploy    - Fazer deployment completo do sistema
  train     - Treinar modelo com dataset
  start     - Iniciar detector em tempo real  
  stop      - Parar detector
  status    - Verificar status do sistema
  test      - Executar testes do sistema
  report    - Gerar relatório de performance
  config    - Mostrar configurações
  help      - Mostrar esta ajuda

EXEMPLOS:
  python cli.py deploy
  python cli.py train malapi2019.csv
  python cli.py start
  python cli.py report 24
""")


# Script principal CLI
if __name__ == "__main__":
    import sys
    
    cli = CLIInterface()
    cli.run(sys.argv[1:])