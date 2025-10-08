# MODELO DEFENSIVO - GUIA DE INSTALAÇÃO E USO

## 🚀 Instalação Rápida

### Opção 1: Script Automático (Recomendado)
```bash
# Windows
install.bat

# Multiplataforma (Windows/Linux/macOS)
python install.py
```

### Opção 2: Manual
```bash
# Instalação completa
pip install -r requirements.txt

# OU instalação mínima
pip install -r requirements-minimal.txt
```

## 📋 Dependências Principais

### Essenciais
- **scikit-learn**: Modelo Random Forest e TF-IDF
- **pandas**: Manipulação de dados CSV
- **numpy**: Operações numéricas
- **psutil**: Monitoramento de processos
- **requests**: Alertas Discord
- **joblib**: Persistência de modelos

### Opcionais
- **yara-python**: Regras YARA para detecção
- **pefile**: Análise de executáveis PE
- **matplotlib/seaborn**: Visualizações
- **nltk**: Processamento de texto

## 🔧 Configuração

### 1. Discord Webhook
Edite `RealtimeDetection/detection_config.json`:
```json
{
    "discord_webhook": "https://discord.com/api/webhooks/YOUR_URL_HERE"
}
```

### 2. Parâmetros de Detecção
```json
{
    "detection_threshold": 0.7,     // Sensibilidade (0.5-0.9)
    "analysis_interval": 5,         // Intervalo análise (segundos)
    "min_api_calls": 50,           // APIs mínimas para análise
    "auto_terminate": false        // Auto-kill malware
}
```

## 📊 Estrutura de Dados

### CSV de Entrada (compatível mal-api-2019)
```csv
Process,API,Label
notepad.exe,ldrloaddll ntcreatefile regopenkeyexa,Benign
malware.exe,setwindowshookexa createremotethread,Spyware
```

### Modelo Treinado
- `defensive_model_polymorphic.joblib`: Random Forest
- `defensive_model_polymorphic_vectorizer.joblib`: TF-IDF
- `defensive_model_polymorphic_encoder.joblib`: Labels

## 🏃 Execução

### Sequência Completa
```bash
# 1. Coleta dados benignos
cd CreatingDatabase
python benign_api_collector.py

# 2. Coleta dados malware (com malwaretcc.exe rodando)
python malware_api_collector.py

# 3. Treina modelo
cd ../ModelTraining
python defensive_model_trainer.py

# 4. Detecção em tempo real
cd ../RealtimeDetection
python realtime_malware_detector.py
```

## 🔍 Troubleshooting

### Erro: "Import joblib could not be resolved"
```bash
pip install joblib scikit-learn
```

### Erro: "Import psutil could not be resolved"
```bash
pip install psutil
```

### Erro: "pywin32 not found"
```bash
pip install pywin32
# Após instalação, execute:
python Scripts/pywin32_postinstall.py -install
```

### Discord não recebe alertas
1. Verifique URL do webhook
2. Teste conectividade: `curl -X POST webhook_url`
3. Verifique logs em `detection_logs/`

## 🛡️ Segurança

### Ambiente Virtual (Recomendado)
```bash
python -m venv modelo_defensivo_env

# Windows
modelo_defensivo_env\Scripts\activate

# Linux/macOS
source modelo_defensivo_env/bin/activate
```

### Permissões Windows
Execute como Administrador para:
- Acesso completo aos logs de eventos
- Monitoramento de todos os processos
- Ações de quarentena/terminação

## 📈 Performance

### Recursos Mínimos
- **RAM**: 2GB disponível
- **CPU**: 2 cores (multi-threading)
- **Disco**: 500MB para logs e modelos

### Otimizações
- Ajuste `max_concurrent_analysis` conforme CPU
- Use `detection_threshold` alto para reduzir falsos positivos
- Configure `whitelist_processes` para ignorar apps conhecidos

## 🔧 Customização

### Adicionar APIs Personalizadas
Edite os coletores para incluir APIs específicas:
```python
custom_apis = ['custom_api_1', 'custom_api_2']
```

### Modificar Modelo
Ajuste parâmetros em `defensive_model_trainer.py`:
```python
RandomForestClassifier(
    n_estimators=200,      # Mais árvores = mais precisão
    max_depth=30,          # Maior profundidade
    min_samples_split=3    # Menor divisão
)
```

## 📚 Documentação Adicional

- `CreatingDatabase/README.md`: Coleta de dados
- `ModelTraining/README.md`: Treinamento do modelo  
- `RealtimeDetection/README.md`: Detecção em tempo real
- `README.md`: Visão geral do sistema