# Modelo Defensivo - Sistema de Detecção de Malware Polimórfico

## Visão Geral
Sistema completo de detecção de malware polimórfico para TCC, implementando coleta de dados, treinamento de modelo Random Forest e detecção em tempo real com alertas via Discord.

## Estrutura do Projeto

### CreatingDatabase/
**Coleta de dados para treinamento**
- `benign_api_collector.py`: Coleta APIs de aplicações legítimas (rotuladas como "Benign")
- `malware_api_collector.py`: Coleta APIs do malwaretcc.exe (rotuladas como "Spyware")

### ModelTraining/  
**Treinamento do modelo defensivo**
- `defensive_model_trainer.py`: Sistema de treinamento Random Forest com TF-IDF
- `trained_models/`: Modelos treinados, vectorizers e encoders

### RealtimeDetection/
**Detecção em tempo real**
- `realtime_malware_detector.py`: Sistema de monitoramento e detecção em tempo real
- `detection_config.json`: Configurações do detector
- `detection_logs/`: Logs das atividades de detecção

## Metodologia Implementada

### 1. Coleta de Dados
- **Fontes múltiplas**: Aplicações benignas + malware específico + dataset mal-api-2019
- **Rotulação específica**: "Benign" vs "Spyware" 
- **Formato unificado**: CSV compatível para treinamento

### 2. Treinamento do Modelo
- **Random Forest**: 100 estimadores para robustez
- **TF-IDF**: Vetorização com n-gramas (1,2) e 5000 features
- **Validação cruzada**: 5-fold cross-validation
- **Anti-polimórfico**: Captura padrões sequenciais de APIs

### 3. Detecção em Tempo Real
- **Monitoramento contínuo**: Todos os processos do sistema
- **Análise comportamental**: Scoring de atividades suspeitas
- **Alertas Discord**: Notificações instantâneas com detalhes
- **Threading**: Processamento assíncrono para performance

## Tecnologias Principais
- **Machine Learning**: Random Forest + TF-IDF
- **Monitoramento**: psutil + System Events
- **Alertas**: Discord Webhooks
- **Persistência**: joblib para modelos
- **Configuração**: JSON para flexibilidade

## Fluxo de Execução

### Fase 1: Coleta
1. Execute `benign_api_collector.py` para coletar dados benignos
2. Execute `malware_api_collector.py` com malwaretcc.exe em execução
3. Dados salvos em CSV compatível com mal-api-2019

### Fase 2: Treinamento  
1. Execute `defensive_model_trainer.py`
2. Sistema unifica todos os datasets disponíveis
3. Treina modelo Random Forest otimizado
4. Salva modelo, vectorizer e encoder

### Fase 3: Detecção
1. Configure Discord webhook em `detection_config.json`
2. Execute `realtime_malware_detector.py`
3. Sistema monitora continuamente e alerta sobre ameaças

## Características Defensivas

### Anti-Evasão
- **Múltiplas features**: TF-IDF captura padrões complexos
- **N-gramas**: Detecta sequências características de malware
- **Ensemble learning**: Random Forest reduz falsos negativos

### Performance
- **Threading**: Monitoramento não-bloqueante
- **Buffers otimizados**: Gestão eficiente de memória
- **Modelos leves**: Carregamento e inferência rápidos

### Alertas Inteligentes
- **Threshold configurável**: Reduz falsos positivos
- **Rich information**: Alertas com contexto completo
- **Logging detalhado**: Auditoria completa das detecções

## Resultados Esperados
- **Detecção de spyware**: Foco específico em malware polimórfico tipo spyware
- **Baixo falso positivo**: Threshold otimizado e whitelist de processos
- **Tempo real**: Detecção em segundos após execução
- **Alertas acionáveis**: Informações suficientes para resposta

## Conclusão
Sistema completo que atende aos requisitos do TCC:
✅ Script de coleta de APIs benignas em CSV  
✅ Script de coleta de APIs do malware rotuladas como Spyware
✅ Ferramenta de detecção em tempo real com alertas Discord
✅ Modelo Random Forest treinado com dados unificados
✅ Documentação completa de implementação