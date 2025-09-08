# 🛡️ Sistema de Detecção de Malware Polimórfico Controlado por LLM

## Guia Completo de Instalação, Configuração e Uso

### 📋 Visão Geral

Este sistema implementa um detector avançado de malware polimórfico controlado por LLM utilizando:

- **Random Forest** otimizado com ensemble learning
- **Análise comportamental** em tempo real via Sysmon
- **TF-IDF** para análise de padrões de API calls
- **SHAP** para interpretabilidade das decisões
- **Detecção em tempo real** com baixa latência

---

## 🚀 Instalação Rápida

### Pré-requisitos

- **Windows 10/11** (Administrator privileges required)
- **Python 3.8+** 
- **8GB RAM** mínimo (16GB recomendado)
- **5GB** espaço livre em disco

### Instalação Automatizada

1. **Clone ou baixe os arquivos do sistema**
```bash
# Se usando git
git clone <repository-url>
cd malware-detector

# Ou baixe os arquivos manualmente
```

2. **Execute o deployment automatizado** (como Administrator)
```bash
python deployment_scripts.py
# OU use a CLI
python cli.py deploy
```

3. **O sistema irá automaticamente:**
   - Instalar dependências Python
   - Baixar e configurar Sysmon
   - Baixar dataset MALAPI2019
   - Configurar serviço Windows
   - Criar scripts de controle

---

## 🎯 Treinamento do Modelo

### Treinamento Básico

```bash
python cli.py train
```

### Treinamento Personalizado

```python
from malware_detection_system import MalwareDetectionPipeline

# Inicializar pipeline
pipeline = MalwareDetectionPipeline()

# Executar pipeline completo
pipeline.run_complete_pipeline(
    dataset_path="malapi2019.csv",
    target_column="class"
)
```

### Pipeline de Treinamento Detalhado

O sistema executa as seguintes etapas automaticamente:

1. **Análise Exploratória**
   - Verificação de balanceamento de classes
   - Análise de valores ausentes
   - Estatísticas descritivas

2. **Pré-processamento**
   - Aplicação de TF-IDF para API calls
   - Seleção de características via Mutual Information
   - PCA para redução de dimensionalidade (se necessário)

3. **Treinamento**
   - Random Forest + XGBoost ensemble
   - Validação cruzada estratificada
   - Otimização de hiperparâmetros

4. **Validação**
   - Métricas especializadas para malware
   - Análise de interpretabilidade com SHAP
   - Testes contra amostras adversariais

---

## 🔄 Uso do Sistema

### Iniciar Detector

```bash
# Via CLI
python cli.py start

# Via serviço Windows
python malware_service.py start

# Via scripts batch
start_detector.bat
```

### Monitoramento em Tempo Real

O sistema monitora automaticamente:

- **Eventos do Sysmon** (Process creation, Network connections, DLL loading)
- **Comportamento de processos** via psutil
- **Padrões de API calls** em tempo real
- **Indicadores de evasão** específicos de malware polimórfico

### Interface de Monitoramento

```python
# Exemplo de uso programático
from malware_detection_system import MalwareDetectionSystem

detector = MalwareDetectionSystem()
detector.load_model("production_model.joblib")
detector.start_realtime_monitoring()

# O sistema imprime alertas automaticamente:
# [10:30:15] 🚨 MALWARE DETECTADO: Trojan (confiança: 0.892)
```

---

## ⚙️ Configurações Avançadas

### Arquivo de Configuração Principal

```json
{
  "random_forest": {
    "n_estimators": 300,
    "max_depth": null,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "criterion": "gini"
  },
  "detection_threshold": 0.7,
  "temporal_window": 60,
  "quarantine_enabled": true,
  "log_level": "INFO"
}
```

### Configuração do Sysmon

O sistema utiliza uma configuração otimizada do Sysmon para capturar:

**Eventos Monitorados:**
- **Event ID 1**: Process Creation
- **Event ID 3**: Network Connections  
- **Event ID 7**: Image/DLL Loading
- **Event ID 8**: CreateRemoteThread
- **Event ID 10**: Process Access
- **Event ID 11**: File Creation
- **Event ID 12/13/14**: Registry Events

**Filtros Específicos para Malware Polimórfico:**
- Processos com argumentos PowerShell suspeitos
- Conexões de rede para portas comuns de C2
- Carregamento de DLLs de locais não-confiáveis
- Modificações em chaves de persistência do Registry

### Personalização de Thresholds

```python
# Ajustar limiar de detecção
detector.detection_threshold = 0.8  # Mais restritivo

# Configurar janela temporal
detector.temporal_window = 30  # 30 segundos

# Personalizar alertas
detector.alert_thresholds = {
    'cpu_usage': 70,
    'memory_usage': 80,
    'detection_latency': 3
}
```

---

## 📊 Métricas e Monitoramento

### Métricas de Performance

O sistema coleta automaticamente:

**Métricas de Detecção:**
- True Positives / False Positives
- True Negatives / False Negatives  
- Precision, Recall, F1-Score
- AUC-ROC para múltiplas classes
- Tempo médio de detecção

**Métricas de Sistema:**
- Uso de CPU e Memória
- I/O de Disco e Rede
- Latência de processamento
- Taxa de eventos processados/segundo

### Relatórios Automáticos

```bash
# Relatório das últimas 24 horas
python cli.py report 24

# Status atual do sistema
python cli.py status
```

### Dashboard de Monitoramento

```python
# Obter métricas em tempo real
metrics = detector.get_performance_metrics()

print(f"Detecções hoje: {metrics['true_positives']}")
print(f"Taxa de FP: {metrics.get('false_positive_rate', 0):.2%}")
print(f"Tempo médio de detecção: {metrics.get('avg_detection_time', 0):.2f}s")
```

---

## 🔍 Interpretabilidade e Explicações

### Análise SHAP

O sistema utiliza SHAP para explicar predições:

```python
# Explicar uma detecção específica
explanation = detector.explain_prediction(sample_data)

# Visualizar importância das características
shap.summary_plot(explanation.values, sample_data)
```

### Características Mais Importantes

O modelo identifica automaticamente:

1. **API Calls mais discriminativas** (ex: CreateRemoteThread, WriteProcessMemory)
2. **Padrões de sequência temporal** de chamadas
3. **Indicadores comportamentais** específicos
4. **Características de evasão** típicas de LLM-controlled malware

### Insights de Detecção

```python
# Obter características mais importantes
feature_importance = detector.model.named_steps['rf'].feature_importances_

# Identificar APIs críticas
critical_apis = detector.get_critical_api_patterns()
```

---

## 🧪 Testes e Validação

### Testes Automatizados

```bash
# Executar suite completa de testes
python cli.py test

# Testes específicos
python -m pytest tests/ -v
```

### Validação com Malware Real

**⚠️ ATENÇÃO: Execute apenas em ambiente isolado/VM**

```python
# Teste com amostra suspeita (em VM)
result = detector.predict_realtime(suspicious_api_calls)

if result['is_malware']:
    print(f"Malware detectado: {result['prediction']}")
    print(f"Confiança: {result['confidence']:.3f}")
    print(f"Família provável: {result['predicted_label']}")
```

### Métricas de Validação

- **Accuracy**: >95% em dataset de teste
- **Precision**: >90% para reduzir falsos positivos  
- **Recall**: >95% para não perder malware real
- **F1-Score**: >92% balanceando precision/recall
- **AUC**: >0.98 para classificação multiclasse

---

## 🚨 Resposta a Incidentes

### Ações Automáticas

Quando malware é detectado:

1. **Log detalhado** da detecção
2. **Quarentena automática** do processo (se habilitado)
3. **Alerta no console** e arquivo de log
4. **Coleta de evidências** (API calls, contexto do processo)
5. **Notificação** para sistema de SIEM (se configurado)

### Resposta Manual

```python
# Analisar detecção específica
detection_details = detector.get_detection_details(process_id)

# Coletar evidências adicionais
evidence = detector.collect_evidence(process_id)

# Quarentena manual
detector.quarantine_process(process_id)
```

### Integração com SIEM

```python
# Configurar webhook para SIEM
detector.configure_siem_integration({
    'webhook_url': 'https://siem.company.com/webhook',
    'auth_token': 'your_token_here',
    'severity_threshold': 0.8
})
```

---

## 🔧 Troubleshooting

### Problemas Comuns

**1. Sysmon não está capturando eventos**
```bash
# Verificar status
sc query Sysmon64

# Reiniciar com configuração
sysmon64 -c sysmonconfig-optimized.xml
```

**2. Alto consumo de memória**
```python
# Ajustar buffer de API calls
detector.api_calls_buffer_size = 1000  # Reduzir de 5000

# Aumentar intervalo de limpeza
detector.cleanup_interval = 30  # 30 segundos
```

**3. Muitos falsos positivos**
```python
# Aumentar threshold de detecção
detector.detection_threshold = 0.8

# Retreinar com mais dados negativos
pipeline.retrain_with_additional_data(benign_samples)
```

**4. Latência alta de detecção**
```python
# Reduzir janela temporal
detector.temporal_window = 30

# Otimizar seleção de características
detector.config['feature_selection']['k_best'] = 1000
```

### Logs e Debugging

```bash
# Logs principais
tail -f logs/malware_detector.log

# Logs do Sysmon
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Select -First 10

# Debug mode
python malware_detection_system.py --debug
```

---

## 📈 Otimização de Performance

### Configurações para Produção

```json
{
  "performance_optimizations": {
    "batch_processing": true,
    "batch_size": 100,
    "parallel_processing": true,
    "memory_limit_mb": 2048,
    "cpu_cores": 4
  }
}
```

### Tuning de Hiperparâmetros

```python
# Grid search automático
from deployment_scripts import MalwareDetectionPipeline

pipeline = MalwareDetectionPipeline()
optimized_model = pipeline._hyperparameter_optimization(X_train, y_train)
```

### Monitoramento de Resources

```python
# Monitor de performance
performance_monitor = PerformanceMonitor(detector)
performance_monitor.start_monitoring(interval=30)

# Relatório de performance
report = performance_monitor.get_performance_report(hours=24)
print(report)
```

---

## 🔄 Atualizações e Manutenção

### Retreinamento Periódico

```python
# Retreinamento automático semanal
from datetime import datetime, timedelta

def weekly_retrain():
    if datetime.now().weekday() == 0:  # Segunda-feira
        # Coletar novos dados
        new_data = collector.collect_weekly_data()
        
        # Retreinar modelo
        pipeline = MalwareDetectionPipeline()
        pipeline.incremental_training(new_data)
        
        # Validar e deploy
        if pipeline.validate_new_model():
            pipeline.deploy_updated_model()
```

### Atualizações de Configuração

```bash
# Atualizar configuração do Sysmon
python deployment_scripts.py update_sysmon

# Atualizar regras de detecção
python cli.py update_rules
```

### Backup e Recovery

```python
# Backup automático do modelo
detector.backup_model(f"backup_model_{datetime.now().strftime('%Y%m%d')}.joblib")

# Restore de backup
detector.restore_from_backup("backup_model_20250101.joblib")
```

---

## 📚 Dados Adicionais Recomendados

### Coleta de Dados Complementares

Para melhorar a precisão do modelo, recomenda-se coletar:

**1. Dados de Comportamento de Rede:**
```python
# Padrões de tráfego DNS
dns_patterns = collect_dns_queries()

# Análise de certificados SSL
ssl_patterns = analyze_ssl_certificates()

# Detecção de DGA (Domain Generation Algorithms)
dga_indicators = detect_dga_patterns()
```

**2. Análise de Memória:**
```python
# Dumps de memória de processos suspeitos
memory_dumps = collect_memory_dumps()

# Detecção de injection techniques
injection_indicators = analyze_memory_injection()
```

**3. Dados de Sistema de Arquivos:**
```python
# Monitoramento de alterações de arquivos
file_changes = monitor_file_system_changes()

# Análise de entropy de arquivos
entropy_analysis = analyze_file_entropy()
```

**4. Indicadores de Sandbox Evasion:**
```python
# Detecção de técnicas anti-VM
anti_vm_indicators = detect_anti_vm_techniques()

# Análise de timing attacks
timing_analysis = analyze_execution_timing()
```

### Scripts de Coleta Automática

```python
# Executar coleta de dados complementares
collector = AdditionalDataCollector()
additional_data = collector.collect_all_data(duration_minutes=60)

# Integrar com dataset principal
enhanced_dataset = integrate_additional_data(base_dataset, additional_data)
```

---

## 🚀 Próximos Passos e Melhorias

### Roadmap de Desenvolvimento

**Fase 1 - Otimização Atual:**
- [ ] Fine-tuning de hiperparâmetros
- [ ] Redução de falsos positivos
- [ ] Otimização de performance

**Fase 2 - Expansão:**
- [ ] Suporte para Linux/macOS
- [ ] Integração com Deep Learning
- [ ] API REST para integração

**Fase 3 - Inteligência Avançada:**
- [ ] Federated Learning
- [ ] Attention mechanisms
- [ ] Zero-day detection enhancement

### Contribuições e Feedback

Para reportar bugs ou sugerir melhorias:

1. Abra uma issue no repositório
2. Inclua logs relevantes
3. Descreva o comportamento esperado vs. atual
4. Teste em ambiente isolado

---

## 📞 Suporte e Documentação

### Recursos Adicionais

- **Documentação técnica**: `/docs/technical_reference.md`
- **API Reference**: `/docs/api_reference.md`
- **Troubleshooting Guide**: `/docs/troubleshooting.md`
- **Performance Tuning**: `/docs/performance_guide.md`

### Contato e Suporte

Para questões técnicas específicas:

- Crie uma issue detalhada no repositório
- Inclua versões do sistema e Python
- Anexe logs relevantes (sem informações sensíveis)
- Descreva passos para reproduzir o problema

---

## ⚖️ Considerações Éticas e Legais

### Uso Responsável

Este sistema deve ser usado exclusivamente para:

- **Defesa legítima** de sistemas próprios
- **Pesquisa acadêmica** em ambientes controlados  
- **Testes de penetração** com autorização explícita

### Limitações de Responsabilidade

- Sistema destinado apenas para ambientes Windows
- Requer configuração adequada para produção
- Performance pode variar conforme hardware
- Falsos positivos são possíveis e devem ser validados

### Compliance e Auditoria

- Logs detalhados para auditoria
- Explicabilidade das decisões via SHAP
- Rastreabilidade completa de detecções
- Conformidade com regulamentações de segurança

---

*📝 Este documento serve como guia completo para instalação, configuração e uso do Sistema de Detecção de Malware Polimórfico Controlado por LLM. Para informações técnicas detalhadas, consulte a documentação complementar.*