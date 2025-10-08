# Detecção em Tempo Real - Modelo Defensivo

## Objetivo
Esta pasta contém o sistema de detecção de malware em tempo real que utiliza o modelo Random Forest treinado para identificar ameaças polimórficas através de chamadas de API.

## Implementação Realizada

### realtime_malware_detector.py
**Sistema completo de detecção em tempo real**

#### Funcionalidades Principais

##### 1. Monitoramento Contínuo
- **Processo monitoring**: Monitora todos os processos ativos no sistema
- **API call capture**: Captura chamadas de API em tempo real
- **Behavioral analysis**: Analisa comportamento suspeito
- **Resource monitoring**: Monitora uso de CPU e memória

##### 2. Sistema de Detecção
- **Modelo Random Forest**: Utiliza o modelo treinado para classificação
- **TF-IDF vectorization**: Transforma APIs em vetores para o modelo
- **Confidence scoring**: Calcula confiança da predição
- **Threshold filtering**: Aplica limiar configurável para reduzir falsos positivos

##### 3. Sistema de Alertas
- **Discord integration**: Envia alertas via webhook do Discord
- **Rich notifications**: Alertas detalhados com informações completas
- **Real-time logging**: Log completo das atividades de detecção
- **Statistics tracking**: Estatísticas de detecção e performance

#### Características Técnicas

##### Arquitetura Multi-threaded
- **Main thread**: Coordenação geral e interface
- **Monitor thread**: Monitoramento de processos
- **Analysis thread**: Análise de APIs coletadas
- **Alert thread**: Envio de alertas assíncronos

##### Sistema de Configuração
- **JSON config**: Configurações flexíveis via arquivo JSON
- **Runtime parameters**: Ajustes de threshold, intervalos, etc.
- **Whitelist management**: Lista de processos confiáveis
- **Response actions**: Configuração de ações automáticas

##### Coleta de APIs Inteligente
- **Process filtering**: Filtra processos suspeitos automaticamente
- **API simulation**: Simula coleta de APIs (para ambiente de demonstração)
- **Behavioral scoring**: Pontua atividades suspeitas
- **Buffer management**: Gerencia buffers de APIs por processo

## Arquivos

### realtime_malware_detector.py
Sistema principal de detecção com as seguintes classes:

#### RealtimeMalwareDetector
- `__init__()`: Inicialização do detector
- `_setup_logging()`: Configuração do sistema de logs
- `_load_model_components()`: Carregamento do modelo treinado
- `_monitor_system_processes()`: Monitoramento de processos
- `_analyze_collected_apis()`: Análise usando o modelo ML
- `_handle_malware_detection()`: Tratamento de detecções
- `_send_discord_alert()`: Envio de alertas Discord
- `start_monitoring()`: Início do monitoramento
- `stop_monitoring()`: Parada do monitoramento

### detection_config.json
Arquivo de configuração com parâmetros:

```json
{
    "detection_threshold": 0.7,        // Limiar de confiança
    "analysis_interval": 5,            // Intervalo de análise (segundos)
    "min_api_calls": 50,              // Mínimo de APIs para análise
    "discord_webhook": "URL_WEBHOOK",  // URL do webhook Discord
    "whitelist_processes": [...],      // Lista de processos confiáveis
    "quarantine_detected": false,      // Auto-quarentena
    "auto_terminate": false            // Auto-terminação
}
```

## Como Usar

### 1. Configuração Inicial
1. Configure o webhook do Discord no `detection_config.json`
2. Ajuste os parâmetros de detecção conforme necessário
3. Certifique-se que o modelo foi treinado (pasta ModelTraining)

### 2. Execução
```bash
python realtime_malware_detector.py
```

### 3. Monitoramento
O sistema exibirá:
- Status de carregamento do modelo
- Configurações ativas
- Estatísticas em tempo real
- Alertas de detecção

### 4. Parada
- Pressione `Ctrl+C` para parar o monitoramento
- O sistema gerará estatísticas finais

## Funcionalidades Avançadas

### Sistema de Alertas Discord
- **Rich embeds**: Alertas visuais com informações detalhadas
- **Process information**: Nome, PID, caminho do executável
- **Malware classification**: Tipo de malware detectado
- **Confidence level**: Nível de confiança da detecção
- **API patterns**: Principais APIs utilizadas pelo processo

### Logs Detalhados
- **Detection logs**: Pasta `detection_logs/` com logs timestamped
- **Process tracking**: Rastreamento completo de processos
- **Error handling**: Tratamento robusto de erros
- **Performance metrics**: Métricas de performance do sistema

### Ações de Resposta
- **Quarantine**: Isolamento de processos maliciosos
- **Termination**: Terminação automática de ameaças
- **Logging**: Registro detalhado de todas as ações
- **Statistics**: Estatísticas de detecção e resposta

## Integração com o Sistema

### Entrada
- **Modelo treinado**: `../ModelTraining/trained_models/`
- **Configurações**: `detection_config.json`
- **Dados em tempo real**: APIs capturadas do sistema

### Saída
- **Alertas Discord**: Notificações em tempo real
- **Logs de detecção**: Arquivos de log detalhados
- **Relatórios**: Estatísticas de performance
- **Ações de resposta**: Quarentena/terminação conforme configurado

## Tecnologias Utilizadas
- **Random Forest**: Modelo de machine learning para classificação
- **TF-IDF**: Vetorização de sequências de API
- **psutil**: Monitoramento de processos do sistema
- **threading**: Processamento assíncrono
- **Discord API**: Sistema de alertas em tempo real
- **JSON**: Configuração flexível