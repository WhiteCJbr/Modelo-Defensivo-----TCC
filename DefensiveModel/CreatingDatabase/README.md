# Coleta de Dados - Modelo Defensivo

## Objetivo
Esta pasta contém os scripts responsáveis pela coleta de dados para treinamento do modelo defensivo de detecção de malware polimórfico.

## Implementação Realizada

### benign_api_collector.py
**Script para captura de chamadas de API de aplicações benignas**

- **Funcionalidade**: Monitora aplicações legítimas executando no sistema e captura suas chamadas de API
- **Método de coleta**: Utiliza Sysmon (System Monitor) e eventos do Windows para capturar APIs em tempo real
- **Formato de saída**: CSV compatível com o dataset mal-api-2019
- **Rotulação**: Todos os dados coletados são rotulados como "Benign"

**Características principais**:
- Integração com logs do Sysmon para captura precisa de APIs
- Fallback para monitoramento via psutil quando Sysmon não está disponível
- Filtragem automática de processos do sistema
- Coleta de metadados como nome do processo, PID, caminho do executável
- Salvamento automático em CSV com timestamp

### malware_api_collector.py
**Script para captura de chamadas de API de malware específico**

- **Funcionalidade**: Monitora especificamente a execução do malwaretcc.exe e captura suas APIs
- **Método de coleta**: Monitoramento direcionado com análise comportamental
- **Formato de saída**: CSV compatível com o dataset mal-api-2019
- **Rotulação**: Todos os dados coletados são rotulados como "Spyware"

**Características principais**:
- Detecção automática da execução do malwaretcc.exe
- Monitoramento de processos filhos do malware
- Análise comportamental para scoring de atividades suspeitas
- Captura de APIs relacionadas a keylogging, network activity, file operations
- Sistema de pontuação para identificar comportamentos mais suspeitos

## Como Usar

### 1. Coleta de Dados Benignos
```bash
python benign_api_collector.py
```

### 2. Coleta de Dados de Malware
```bash
python malware_api_collector.py
```

## Dependências
- psutil: Monitoramento de processos
- win32evtlog: Acesso aos logs de eventos do Windows
- pandas: Manipulação de dados
- pathlib: Manipulação de caminhos de arquivos

## Saída
Os arquivos CSV gerados seguem o formato:
- **Process**: Nome do processo
- **API**: Sequência de chamadas de API capturadas
- **Label**: Rótulo (Benign ou Spyware)

## Integração
Os dados coletados são utilizados pelo sistema de treinamento localizado na pasta ModelTraining para treinar o modelo Random Forest de detecção de malware polimórfico.