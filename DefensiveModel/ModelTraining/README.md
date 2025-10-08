# Treinamento do Modelo - Modelo Defensivo

## Objetivo
Esta pasta contém o sistema de treinamento do modelo Random Forest para detecção de malware polimórfico baseado em chamadas de API.

## Implementação Realizada

### defensive_model_trainer.py
**Sistema completo de treinamento do modelo defensivo**

O sistema realiza as seguintes etapas:

#### 1. Unificação de Datasets
- **Dados benignos**: Coleta dados dos scripts da pasta CreatingDatabase
- **Dados de malware coletados**: Utiliza os dados do malwaretcc.exe capturados
- **Dataset mal-api-2019**: Integra especificamente as amostras classificadas como "Spyware"
- **Balanceamento**: Garante distribuição equilibrada entre classes

#### 2. Preparação dos Dados
- **Limpeza**: Remove duplicatas e dados inconsistentes
- **Filtragem**: Seleciona apenas amostras de qualidade
- **Normalização**: Padroniza o formato das APIs
- **Validação**: Verifica integridade dos dados

#### 3. Engenharia de Features
- **TF-IDF Vectorization**: Transforma sequências de API em vetores numéricos
- **Parâmetros otimizados**:
  - max_features=5000: Vocabulário de 5000 APIs mais frequentes
  - ngram_range=(1,2): Uni-gramas e bi-gramas para capturar padrões
  - stop_words removal: Remove APIs muito comuns
  - min_df e max_df: Filtra APIs muito raras ou muito frequentes

#### 4. Treinamento do Modelo
- **Algoritmo**: Random Forest Classifier
- **Parâmetros otimizados**:
  - n_estimators=100: 100 árvores para robustez
  - max_depth=20: Profundidade controlada para evitar overfitting
  - min_samples_split=5: Mínimo de amostras para divisão
  - min_samples_leaf=2: Mínimo de amostras por folha
  - random_state=42: Reprodutibilidade

#### 5. Validação e Avaliação
- **Cross-validation**: Validação cruzada com 5 folds
- **Métricas calculadas**:
  - Acurácia geral
  - Precisão por classe
  - Recall por classe
  - F1-score por classe
  - Matriz de confusão
  - ROC-AUC score

#### 6. Persistência do Modelo
- **Modelo treinado**: Salvo como .joblib para carregamento rápido
- **Vectorizer**: TF-IDF vectorizer salvo separadamente
- **Label encoder**: Encoder de rótulos salvo
- **Relatório de treinamento**: JSON com métricas e configurações

## Arquivos Gerados

### trained_models/
- `defensive_model_polymorphic.joblib`: Modelo Random Forest treinado
- `defensive_model_polymorphic_vectorizer.joblib`: TF-IDF vectorizer
- `defensive_model_polymorphic_encoder.joblib`: Label encoder
- `training_report_polymorphic.json`: Relatório completo de treinamento

## Como Usar

### Treinamento Completo
```bash
python defensive_model_trainer.py
```

### Configurações Principais
O sistema automaticamente:
1. Localiza e carrega todos os dados disponíveis
2. Unifica os datasets
3. Treina o modelo com parâmetros otimizados
4. Salva todos os componentes necessários
5. Gera relatório detalhado

## Metodologia Implementada

### Estratégia Anti-Polimórfica
- **N-gramas**: Captura padrões sequenciais de APIs
- **TF-IDF**: Pondera importância relativa das APIs
- **Ensemble learning**: Random Forest para robustez
- **Feature selection**: Seleção inteligente de características

### Prevenção de Overfitting
- **Validação cruzada**: Teste em múltiplas divisões dos dados
- **Regularização**: Parâmetros de profundidade controlados
- **Amostragem balanceada**: Evita bias por desbalanceamento

### Otimização para Detecção em Tempo Real
- **Modelo leve**: Tamanho otimizado para carregamento rápido
- **Vetorização eficiente**: TF-IDF com vocabulário limitado
- **Predição rápida**: Random Forest permite inferência rápida

## Integração
O modelo treinado é utilizado pelo sistema de detecção em tempo real localizado na pasta RealtimeDetection para identificar malware polimórfico durante a execução.