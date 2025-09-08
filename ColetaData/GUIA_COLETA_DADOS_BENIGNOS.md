# Guia de Coleta de Dados Benignos Reais para Detecção de Malware

## 📋 Visão Geral

Este guia explica como coletar dados benignos reais do seu sistema Windows 11 para melhorar o modelo de detecção de malware keylogger polimórfico.

## 🎯 Objetivos

- Coletar chamadas de API de aplicativos legítimos
- Criar dataset de dados benignos realísticos
- Melhorar as métricas do modelo de ML (target: >75% accuracy)

## 🛠️ Métodos Disponíveis

### Método 1: Coletor Simplificado (Recomendado)
**Arquivo**: `simple_benign_collector.py`
- ✅ Não requer instalação adicional
- ✅ Funciona sem privilégios administrativos
- ✅ Gera padrões realísticos baseados em processos observados
- ✅ Rápido e fácil de usar

### Método 2: Coletor Completo com Sysmon
**Arquivo**: `benign_data_collector.py`
- ✅ Coleta mais detalhada
- ✅ Dados reais do sistema
- ⚠️ Requer Sysmon instalado
- ⚠️ Requer privilégios administrativos

## 🚀 Instruções de Uso

### Para o Coletor Simplificado:

1. **Execute o script**:
   ```bash
   python simple_benign_collector.py
   ```

2. **Escolha o modo**:
   - **Opção 1**: Monitoramento + Sintético (recomendado)
   - **Opção 2**: Apenas sintético (rápido)
   - **Opção 3**: Apenas monitoramento

3. **Durante a coleta** (se escolheu monitoramento):
   - Use aplicativos normalmente (Notepad, Calculator, Chrome, etc.)
   - O script coletará automaticamente por 15 minutos

### Para o Coletor Completo:

1. **Instalar Sysmon** (como Administrador):
   ```bash
   # Baixar Sysmon do Microsoft Sysinternals
   # https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
   
   # Executar o script para gerar configuração
   python benign_data_collector.py
   
   # Instalar Sysmon com a configuração gerada
   sysmon64.exe -accepteula -i "benign_data\sysmon_config.xml"
   ```

2. **Executar coleta**:
   ```bash
   python benign_data_collector.py
   ```

## 📊 Aplicativos Monitorados

O sistema coleta dados dos seguintes aplicativos:

### 📝 Editores de Texto
- `notepad.exe` - Bloco de Notas
- `winword.exe` - Microsoft Word
- `code.exe` - Visual Studio Code

### 🌐 Navegadores
- `chrome.exe` - Google Chrome
- `firefox.exe` - Mozilla Firefox
- `msedge.exe` - Microsoft Edge

### 📊 Office
- `excel.exe` - Microsoft Excel
- `powerpnt.exe` - Microsoft PowerPoint

### 🛠️ Ferramentas do Sistema
- `explorer.exe` - Windows Explorer
- `cmd.exe` - Prompt de Comando
- `powershell.exe` - PowerShell

### 🎨 Multimedia
- `mspaint.exe` - Paint
- `wmplayer.exe` - Windows Media Player
- `spotify.exe` - Spotify

### 🧮 Outros
- `calc.exe` - Calculadora

## 📁 Arquivos Gerados

### Coletor Simplificado:
- `benign_data_simple/benign_api_dataset_YYYYMMDD_HHMMSS.csv`
- `benign_data_simple/collection.log`

### Coletor Completo:
- `benign_data/benign_api_calls_YYYYMMDD_HHMMSS.csv`
- `benign_data/synthetic_benign_dataset_YYYYMMDD_HHMMSS.csv`
- `benign_data/sysmon_config.xml`
- `benign_data/collection.log`

## 📋 Formato dos Dados

Os arquivos CSV gerados contêm:

| Coluna | Descrição |
|--------|-----------|
| `timestamp` | Data/hora da coleta |
| `process_name` | Nome do processo |
| `app_category` | Categoria do aplicativo |
| `api_calls` | Sequência de chamadas de API |
| `process_id` | ID do processo |
| `memory_usage` | Uso de memória |
| `label` | "Benign" (marcador de classe) |

## 🔄 Integração com o Notebook

1. **Upload do arquivo**:
   - Faça upload do arquivo CSV gerado para o Google Drive
   - Coloque na pasta do projeto

2. **Configurar o notebook**:
   ```python
   USE_REAL_BENIGN_DATA = True
   benign_data_filename = '/content/drive/MyDrive/IFSP/benign_api_dataset_YYYYMMDD_HHMMSS.csv'
   ```

3. **Executar treinamento**:
   - Execute o notebook atualizado
   - Compare os resultados com versões anteriores

## 📈 Melhorias Esperadas

Com dados benignos reais, esperamos:

- **Accuracy**: >75% (vs 62.8% anterior)
- **AUC**: >0.80 (vs 0.66 anterior)
- **Precision/Recall**: Mais balanceados
- **Generalização**: Melhor performance em dados novos

## 🔍 Solução de Problemas

### Erro: "Import não encontrado"
```bash
pip install pandas numpy psutil
```

### Erro: "Sysmon não encontrado"
- Use o coletor simplificado como alternativa
- Ou instale Sysmon seguindo as instruções oficiais

### Poucos dados coletados
- Execute o coletor por mais tempo
- Use mais aplicativos durante a coleta
- Combine dados reais com sintéticos

### Dados inconsistentes
- Verifique o formato do CSV
- Confirme que a coluna `api_calls` existe
- Valide se `label` está marcado como "Benign"

## 📞 Próximos Passos

1. **Execute um dos coletores**
2. **Faça upload do arquivo gerado**
3. **Configure o notebook**
4. **Execute o treinamento**
5. **Compare os resultados**
6. **Documente as melhorias**

## 🛡️ Considerações de Segurança

- Os coletores apenas observam processos existentes
- Não modificam sistema ou arquivos
- Dados coletados são apenas para fins acadêmicos
- Execute apenas em sistema de teste/desenvolvimento

## 📚 Referências

- [Microsoft Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Windows API Documentation](https://docs.microsoft.com/en-us/windows/win32/api/)
- [MALAPI 2019 Dataset](https://github.com/farshadsafavi/MALAPI-2019)

---

**Desenvolvido para**: TCC - Modelo Defensivo contra Malware Polimórfico  
**Versão**: 2.0  
**Data**: Setembro 2025
