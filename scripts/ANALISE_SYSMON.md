# 🔍 Análise da Configuração Atual do Sysmon

## ❌ Problemas Identificados na Configuração Atual

### 1. **Configuração XML Inadequada**
- **Schema version desatualizada** (4.82 vs atual 4.90+)
- **Filtragem muito restritiva** - perde eventos críticos
- **Faltam eventos específicos** para malware polimórfico
- **Não monitora comunicações com IA**

### 2. **Eventos Limitados**
A configuração atual monitora apenas:
- Process Create (básico)
- Network Connect (só portas 80, 443, 4444)
- Image Load (só DLLs)
- CreateRemoteThread (excluindo svchost)
- Process Access (só lsass)
- File Create (só exe/dll)
- Registry (só CurrentVersion\Run)

### 3. **Configuração Inadequada para Malware Polimórfico**
- **Não detecta injeção de código** avançada
- **Não monitora operações de memória**
- **Não captura DNS queries** para comunicação IA
- **Não monitora WMI events**
- **Não detecta manipulação de processos**

## 🚨 Problemas Críticos da Configuração Original

### Network Connect - Muito Restritivo
```xml
<NetworkConnect onmatch="include">
  <DestinationPort condition="is">80</DestinationPort>
  <DestinationPort condition="is">443</DestinationPort>
  <DestinationPort condition="is">4444</DestinationPort>
</NetworkConnect>
```
**Problema:** Só captura 3 portas específicas. APIs de IA usam HTTPS (443) mas também outras portas.

### CreateRemoteThread - Excludindo Demais
```xml
<CreateRemoteThread onmatch="exclude">
  <SourceImage condition="is">C:\Windows\System32\svchost.exe</SourceImage>
</CreateRemoteThread>
```
**Problema:** Exclui svchost, mas malware pode se fazer passar por svchost ou usar outros processos.

### Faltam Eventos Críticos
A configuração original **NÃO** monitora:
- **Event ID 22 (DNS Query)** - crítico para comunicação IA
- **Event ID 25 (Process Tampering)** - manipulação de processos
- **Event ID 2 (File Time Change)** - evasão temporal
- **Event ID 9 (Raw Access Read)** - acesso direto ao disco
- **Event IDs 19-21 (WMI Events)** - persistência avançada

## ✅ Configuração Otimizada Criada

### Melhorias Implementadas

#### 1. **Monitoramento Expandido - 29 Tipos de Eventos**
- Process creation/termination (1, 5)
- File operations (2, 11, 15, 23, 26, 27, 29)
- Network & DNS (3, 22)
- Memory operations (7, 8, 9, 25)
- Process access (10)
- Registry events (12, 13, 14)
- Pipes & WMI (17, 18, 19, 20, 21)
- Driver loading (6)
- Clipboard changes (24)

#### 2. **Detecção Específica para Comunicação IA**
```xml
<DnsQuery onmatch="include">
  <QueryName condition="contains">openai</QueryName>
  <QueryName condition="contains">anthropic</QueryName>
  <QueryName condition="contains">claude</QueryName>
  <QueryName condition="contains">googleapis</QueryName>
  <!-- ... outros domínios IA -->
</DnsQuery>
```

#### 3. **Monitoramento Crítico de Injeção**
```xml
<CreateRemoteThread onmatch="exclude">
  <!-- Apenas exceções muito específicas -->
  <SourceImage condition="is">C:\Windows\System32\wbem\WmiPrvSE.exe</SourceImage>
  <SourceImage condition="is">C:\Windows\System32\svchost.exe</SourceImage>
  <TargetImage condition="is">C:\Windows\System32\svchost.exe</TargetImage>
</CreateRemoteThread>
```

#### 4. **Detecção de Manipulação de Processos**
```xml
<ProcessTampering onmatch="include">
  <!-- CRÍTICO - qualquer manipulação de processo -->
</ProcessTampering>
```

#### 5. **Network Monitoring Abrangente**
```xml
<NetworkConnect onmatch="exclude">
  <!-- Excluir apenas conexões locais óbvias -->
  <DestinationIp condition="is">127.0.0.1</DestinationIp>
  <DestinationIp condition="is">::1</DestinationIp>
  <SourceImage condition="is">C:\Windows\System32\svchost.exe</SourceImage>
</NetworkConnect>
```

## 📊 Comparação: Original vs Otimizada

| Aspecto | Original | Otimizada |
|---------|----------|-----------|
| Eventos monitorados | 7 tipos | 29 tipos |
| DNS queries | ❌ Não | ✅ Sim (específico IA) |
| Process tampering | ❌ Não | ✅ Sim |
| CreateRemoteThread | Muito restritivo | Balanceado |
| Network monitoring | 3 portas apenas | Todas (exceto locais) |
| File operations | Básico | Avançado |
| WMI events | ❌ Não | ✅ Sim |
| Schema version | 4.82 (antiga) | 4.90 (atual) |

## 🎯 Benefícios da Nova Configuração

### Para Malware Polimórfico
1. **Detecta comunicação com IA** via DNS e network
2. **Monitora injeção de código** em tempo real
3. **Captura manipulação de processos** (Event 25)
4. **Rastreia execução em memória** (Events 7, 8, 9)

### Para Análise Forense
1. **Logs mais abrangentes** para investigação
2. **Timestamps preservados** (Event 2)
3. **Evidências de persistência** (WMI events)
4. **Rastro completo de atividade**

## 🚀 Como Aplicar

### 1. **Instalar Nova Configuração**
```powershell
# Execute como Administrador
.\scripts\install_sysmon_optimized.ps1
```

### 2. **Verificar Sistema**
```powershell
.\scripts\check_system_optimized.ps1
```

### 3. **Executar Detector**
```powershell
cd app
python detection_sistem.py --model ../Tentativa2/optimized_malware_detector.joblib --config config_polymorphic.json --debug
```

## ⚠️ Considerações Importantes

### Performance
- **Mais eventos = mais processamento**
- Monitor CPU usage durante testes
- Ajuste filtragem se necessário

### Storage
- **Logs maiores** devido a mais eventos
- Configure rotação de logs
- Monitore espaço em disco

### Tuning
- **Ajuste filtragem** baseado no ambiente
- **Whitelist processos** específicos se necessário
- **Monitor false positives**

A nova configuração está **especificamente otimizada** para capturar o comportamento do malware polimórfico desenvolvido para o TCC, fornecendo visibilidade completa das atividades suspeitas.