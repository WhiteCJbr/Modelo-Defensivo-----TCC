# Detector de Malware Polimórfico - Versão Otimizada

## 📋 Resumo das Melhorias Implementadas

Este sistema foi otimizado especificamente para detectar malware polimórfico que se comunica com IA para gerar novos códigos e executá-los em memória.

### 🚀 Principais Melhorias

#### 1. **Sistema de Logging Avançado**
- **Múltiplos arquivos de log** especializados:
  - `sysmon_detector.log` - Log principal
  - `sysmon_debug.log` - Debugging detalhado
  - `sysmon_critical.log` - Apenas detecções críticas
  - `sysmon_events.log` - Todos os eventos capturados
  - `sysmon_ml_analysis.log` - Análises do modelo ML
- **Logging estruturado** com níveis apropriados
- **Formatação detalhada** com timestamps e localização do código

#### 2. **Detecção Específica para Malware Polimórfico**
- **Detecção de comunicação com IA**:
  - Monitora conexões para OpenAI, Anthropic, Google AI, etc.
  - Identifica consultas DNS suspeitas
  - Palavras-chave específicas de APIs de IA
- **Detecção de injeção de código**:
  - Monitoramento em tempo real de `CreateRemoteThread`
  - Detecção de manipulação de processos
  - Análise imediata após injeção detectada
- **Padrões polimórficos**:
  - Operações de memória suspeitas
  - Combinações de comportamentos
  - Pontuação de ameaça customizada

#### 3. **Performance Otimizada**
- **Processamento em lotes** de eventos
- **Cache de processos** para melhor eficiência
- **Análise adaptativa** baseada na carga
- **Limpeza periódica** de dados antigos
- **Delay adaptativo** baseado na atividade

#### 4. **Monitoramento Expandido**
- **29 tipos de eventos Sysmon** (vs 9 originais):
  - Process creation/termination
  - Network connections
  - File operations
  - Registry changes
  - Memory operations
  - WMI events
  - DNS queries
  - Pipe operations
  - Driver loading
- **Handlers específicos** para cada tipo de evento
- **Análise contextual** de comportamentos

#### 5. **Configuração Otimizada**
- **Threshold reduzido** (0.5) devido à complexidade do malware
- **Análise mais frequente** (3-5 segundos)
- **Mínimo de API calls reduzido** (3) para detecção rápida
- **Configuração específica** para malware polimórfico

### 📊 Estatísticas Avançadas

O sistema agora rastreia:
- Taxa de eventos por segundo
- Detecções polimórficas específicas
- Comunicações com IA
- Injeções de memória
- Score de ameaça customizado
- Falsos positivos

### 🔧 Uso do Sistema

#### Instalação das Dependências
```bash
pip install joblib psutil pywin32 scikit-learn
```

#### Uso Básico
```bash
# Uso padrão
python detection_sistem.py --model ../Tentativa2/optimized_malware_detector.joblib

# Com configuração otimizada
python detection_sistem.py --model ../Tentativa2/optimized_malware_detector.joblib --config config_polymorphic.json

# Modo debug para desenvolvimento
python detection_sistem.py --model ../Tentativa2/optimized_malware_detector.joblib --debug --verbose

# Modo de teste (sem quarentena)
python detection_sistem.py --model ../Tentativa2/optimized_malware_detector.joblib --test-mode
```

#### Teste do Sistema
```bash
# Executar testes de funcionalidade
python test_detector.py
```

### 🎯 Configurações Específicas para Malware Polimórfico

O arquivo `config_polymorphic.json` contém:

```json
{
  "detection_threshold": 0.45,
  "analysis_interval": 3,
  "min_api_calls": 3,
  "polymorphic_detection": {
    "memory_threshold": 2,
    "network_threshold": 3,
    "injection_threshold": 1,
    "ai_keywords": ["openai", "anthropic", "claude", "gpt", "api", ...]
  }
}
```

### 🚨 Indicadores de Malware Polimórfico

O sistema detecta especificamente:

1. **Comunicação com IA**:
   - Conexões para APIs de IA conhecidas
   - Padrões de requisições HTTP/HTTPS
   - DNS queries suspeitas

2. **Injeção de Código**:
   - `CreateRemoteThread` em processos críticos
   - Manipulação de memória
   - Hooks de sistema

3. **Comportamentos Polimórficos**:
   - Execução em memória
   - Operações de criptografia/descriptografia
   - Modificações de timestamps

4. **Persistência**:
   - Modificações no registry
   - Criação de serviços
   - Hooks de sistema

### 📈 Melhorias de Detecção

- **Score de ameaça híbrido**: Combina ML + regras específicas
- **Análise contextual**: Considera padrões de comportamento
- **Detecção proativa**: Análise imediata para comportamentos críticos
- **Redução de falsos positivos**: Whitelist expandida e análise contextual

### 🔍 Debugging e Monitoramento

- **Logs verbosos** para acompanhar cada evento
- **Estatísticas em tempo real** a cada minuto
- **Evidências salvas** automaticamente
- **Relatórios detalhados** de detecções

### ⚠️ Requisitos

- **Windows** com Sysmon instalado
- **Privilégios administrativos**
- **Python 3.7+**
- **Modelo treinado** da Tentativa2

### 📝 Arquivos de Log

Todos os logs são salvos na pasta `logs/`:
- Acompanhe `sysmon_detector.log` para visão geral
- Use `sysmon_debug.log` para troubleshooting
- Monitore `sysmon_critical.log` para detecções
- Analise `sysmon_ml_analysis.log` para comportamento do modelo

### 🎯 Otimizações Específicas para o TCC

1. **Threshold ajustado** para o modelo da Tentativa2 (62% accuracy)
2. **Detecção específica** para malware que usa IA
3. **Logging detalhado** para análise posterior
4. **Configuração flexível** para diferentes cenários de teste
5. **Modo de teste** para desenvolvimento seguro

Este sistema agora está otimizado para capturar efetivamente o malware polimórfico desenvolvido para o TCC, com logging detalhado para análise e debugging durante os testes.