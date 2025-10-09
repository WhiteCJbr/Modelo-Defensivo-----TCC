"""
UNIFICADOR DE DADOS E TREINAMENTO DO MODELO DEFENSIVO
Sistema para unificar dados benignos, malware coletado e mal-api-2019
Treina modelo Random Forest para detecção de malware polimórfico
"""

import pandas as pd
import numpy as np
import joblib
import logging
from pathlib import Path
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder
# import matplotlib.pyplot as plt  # Opcional
# import seaborn as sns             # Opcional
import json

class DefensiveModelTrainer:
    """
    Treinador do modelo defensivo para detecção de malware polimórfico
    Unifica dados de múltiplas fontes e treina Random Forest otimizado
    """
    
    def __init__(self, output_dir="trained_models", verbose=True):
        """
        Inicializar treinador do modelo defensivo
        
        Args:
            output_dir: Diretório para salvar modelos treinados
            verbose: Logs detalhados
        """
        print("🛡️ TREINADOR DO MODELO DEFENSIVO - RANDOM FOREST")
        print("=" * 60)
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.verbose = verbose
        self._setup_logging()
        
        # Componentes do modelo
        self.vectorizer = None
        self.model = None
        self.label_encoder = None
        
        # Dados unificados
        self.unified_data = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        
        # Métricas de treinamento
        self.training_metrics = {}
        
        self.logger.info("Treinador do modelo defensivo inicializado")
    
    def _setup_logging(self):
        """Configurar sistema de logging"""
        log_file = self.output_dir / f"training_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO if self.verbose else logging.WARNING,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_mal_api_2019(self, data_file, labels_file):
        """
        Carregar dados do mal-api-2019 (somente Spyware)
        
        Args:
            data_file: Arquivo all_analysis_data.txt
            labels_file: Arquivo labels.csv
        """
        print("📁 Carregando dados mal-api-2019...")
        
        try:
            # Carregar labels
            labels_df = pd.read_csv(labels_file, header=None, names=['label'])
            
            # Filtrar apenas Spyware
            spyware_indices = labels_df[labels_df['label'] == 'Spyware'].index.tolist()
            self.logger.info(f"Encontrados {len(spyware_indices)} samples de Spyware no mal-api-2019")
            
            # Carregar dados de API calls
            with open(data_file, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.readlines()
            
            # Extrair apenas linhas correspondentes ao Spyware
            spyware_data = []
            for idx in spyware_indices:
                if idx < len(all_lines):
                    api_calls = all_lines[idx].strip()
                    if api_calls:  # Ignorar linhas vazias
                        spyware_data.append({
                            'api_calls': api_calls,
                            'label': 'Spyware'
                        })
            
            mal_api_df = pd.DataFrame(spyware_data)
            
            print(f"✅ Carregados {len(mal_api_df)} samples de Spyware do mal-api-2019")
            self.logger.info(f"Dados mal-api-2019 carregados: {len(mal_api_df)} amostras")
            
            return mal_api_df
            
        except Exception as e:
            self.logger.error(f"Erro ao carregar mal-api-2019: {e}")
            print(f"❌ Erro ao carregar mal-api-2019: {e}")
            return pd.DataFrame()
    
    def load_collected_data(self, benign_dir="benign_data", malware_dir="malware_data"):
        """
        Carregar dados coletados (benignos e malware)
        
        Args:
            benign_dir: Diretório com dados benignos
            malware_dir: Diretório com dados de malware
        """
        print("📁 Carregando dados coletados...")
        
        collected_data = []
        
        # Carregar dados benignos
        benign_path = Path(benign_dir)
        if benign_path.exists():
            benign_files = list(benign_path.glob("benign_dataset_*.csv"))
            for file in benign_files:
                try:
                    df = pd.read_csv(file)
                    collected_data.append(df)
                    print(f"✅ Benignos: {len(df)} samples de {file.name}")
                except Exception as e:
                    self.logger.warning(f"Erro ao carregar {file}: {e}")
        
        # Carregar dados de malware
        malware_path = Path(malware_dir)
        if malware_path.exists():
            malware_files = list(malware_path.glob("spyware_dataset_*.csv"))
            for file in malware_files:
                try:
                    df = pd.read_csv(file)
                    collected_data.append(df)
                    print(f"✅ Malware: {len(df)} samples de {file.name}")
                except Exception as e:
                    self.logger.warning(f"Erro ao carregar {file}: {e}")
        
        if collected_data:
            combined_df = pd.concat(collected_data, ignore_index=True)
            print(f"✅ Total coletado: {len(combined_df)} samples")
            return combined_df
        else:
            print("⚠️ Nenhum dado coletado encontrado")
            return pd.DataFrame()
    
    def unify_datasets(self, mal_api_data, collected_data):
        """
        Unificar todos os datasets
        
        Args:
            mal_api_data: DataFrame do mal-api-2019
            collected_data: DataFrame dos dados coletados
        """
        print("\n🔄 Unificando datasets...")
        
        datasets = []
        
        if not mal_api_data.empty:
            datasets.append(mal_api_data)
            print(f"   - mal-api-2019: {len(mal_api_data)} samples")
        
        if not collected_data.empty:
            datasets.append(collected_data)
            print(f"   - Dados coletados: {len(collected_data)} samples")
        
        if not datasets:
            raise ValueError("Nenhum dataset disponível para unificação")
        
        # Unificar todos os dados
        self.unified_data = pd.concat(datasets, ignore_index=True)
        
        # Limpar dados
        self.unified_data = self.unified_data.dropna()
        self.unified_data = self.unified_data[self.unified_data['api_calls'].str.len() > 0]
        
        # Estatísticas
        label_counts = self.unified_data['label'].value_counts()
        
        print(f"\n📊 DATASET UNIFICADO:")
        print(f"   Total de samples: {len(self.unified_data)}")
        for label, count in label_counts.items():
            percentage = (count / len(self.unified_data)) * 100
            print(f"   - {label}: {count} ({percentage:.1f}%)")
        
        self.logger.info(f"Dataset unificado criado com {len(self.unified_data)} amostras")
        return self.unified_data
    
    def _balance_dataset(self):
        """
        Balancear dataset para reduzir overfitting por desbalanceamento
        """
        from sklearn.utils import resample
        
        print("\n⚖️ Aplicando balanceamento de dados...")
        
        # Separar classes
        df_majority = self.unified_data[self.unified_data['label'] == 'Spyware']
        df_minority = self.unified_data[self.unified_data['label'] == 'Benign']
        
        print(f"   Antes: Spyware={len(df_majority)}, Benign={len(df_minority)}")
        
        # Estratégia de balanceamento híbrida
        # 1. Undersample da classe majoritária (Spyware)
        # 2. Upsample da classe minoritária (Benign) se necessário
        
        # Definir tamanho alvo (40-60% da classe majoritária)
        target_size = min(max(len(df_minority) * 3, 100), len(df_majority) // 2)
        
        # Undersample Spyware
        df_majority_sampled = resample(
            df_majority, 
            replace=False, 
            n_samples=target_size,
            random_state=42
        )
        
        # Upsample Benign se necessário
        if len(df_minority) < target_size // 3:  # Se muito desbalanceado
            df_minority_sampled = resample(
                df_minority,
                replace=True,
                n_samples=min(target_size // 2, len(df_minority) * 3),
                random_state=42
            )
        else:
            df_minority_sampled = df_minority
        
        # Recombinar dados balanceados
        self.unified_data = pd.concat([df_majority_sampled, df_minority_sampled], ignore_index=True)
        self.unified_data = self.unified_data.sample(frac=1, random_state=42).reset_index(drop=True)
        
        print(f"   Depois: Spyware={len(df_majority_sampled)}, Benign={len(df_minority_sampled)}")
        print(f"   📊 Total balanceado: {len(self.unified_data)} samples")
    
    def prepare_features(self, max_features=2000):
        """
        Preparar features usando TF-IDF com técnicas anti-overfitting
        
        Args:
            max_features: Máximo número de features (reduzido para evitar overfitting)
        """
        print(f"\n🔧 Preparando features (TF-IDF, max_features={max_features})...")
        
        if self.unified_data is None:
            raise ValueError("Dados não unificados. Execute unify_datasets() primeiro.")
        
        # Aplicar balanceamento primeiro
        self._balance_dataset()
        
        # Preparar TF-IDF Vectorizer com parâmetros mais conservadores
        self.vectorizer = TfidfVectorizer(
            max_features=max_features,  # Reduzido de 5000 para 2000
            lowercase=True,
            token_pattern=r'\b\w+\b',
            stop_words=None,  # Não remover stop words para API calls
            ngram_range=(1, 2),  # Unigrams e bigrams
            min_df=3,  # Aumentado de 2 para 3 (ignora termos muito raros)
            max_df=0.85  # Reduzido de 0.95 para 0.85 (ignora termos muito frequentes)
        )
        
        # Transformar API calls em features
        X = self.vectorizer.fit_transform(self.unified_data['api_calls'])
        
        # Preparar labels
        self.label_encoder = LabelEncoder()
        y = self.label_encoder.fit_transform(self.unified_data['label'])
        
        print(f"✅ Features preparadas: {X.shape[0]} samples, {X.shape[1]} features")
        print(f"✅ Labels: {list(self.label_encoder.classes_)}")
        
        # Split train/test com test set maior para validação mais robusta
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y  # Aumentado de 0.2 para 0.3
        )
        
        print(f"📊 Train set: {self.X_train.shape[0]} samples")
        print(f"📊 Test set: {self.X_test.shape[0]} samples")
        
        # Verificar distribuição final
        train_counts = np.bincount(self.y_train)
        test_counts = np.bincount(self.y_test)
        
        for i, label in enumerate(self.label_encoder.classes_):
            train_pct = (train_counts[i] / len(self.y_train)) * 100
            test_pct = (test_counts[i] / len(self.y_test)) * 100
            print(f"   {label}: Train {train_counts[i]} ({train_pct:.1f}%), Test {test_counts[i]} ({test_pct:.1f}%)")
        
        return self.X_train, self.X_test, self.y_train, self.y_test
    
    def train_model(self, n_estimators=100, max_depth=10, min_samples_split=10, min_samples_leaf=5):
        """
        Treinar modelo Random Forest com parâmetros anti-overfitting
        
        Args:
            n_estimators: Número de árvores (reduzido)
            max_depth: Profundidade máxima (reduzida)
            min_samples_split: Mínimo de samples para split (aumentado)
            min_samples_leaf: Mínimo de samples por folha (aumentado)
        """
        print(f"\n🤖 Treinando Random Forest...")
        print(f"   Parâmetros anti-overfitting:")
        print(f"   - n_estimators={n_estimators} (reduzido)")
        print(f"   - max_depth={max_depth} (limitado)")
        print(f"   - min_samples_split={min_samples_split} (aumentado)")
        print(f"   - min_samples_leaf={min_samples_leaf} (aumentado)")
        
        if self.X_train is None:
            raise ValueError("Features não preparadas. Execute prepare_features() primeiro.")
        
        # Configurar Random Forest com parâmetros conservadores
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,          # Reduzido de 200 para 100
            max_depth=max_depth,                # Reduzido de 20 para 10
            min_samples_split=min_samples_split, # Aumentado de 5 para 10
            min_samples_leaf=min_samples_leaf,   # Aumentado de 2 para 5
            max_features='sqrt',                 # Usar sqrt das features
            bootstrap=True,
            oob_score=True,
            class_weight='balanced',             # Balanceamento automático
            random_state=42,
            n_jobs=-1
        )
        
        # Treinar modelo
        start_time = datetime.now()
        self.model.fit(self.X_train, self.y_train)
        training_time = (datetime.now() - start_time).total_seconds()
        
        print(f"✅ Modelo treinado em {training_time:.2f} segundos")
        print(f"📊 OOB Score: {self.model.oob_score_:.4f}")
        
        # Avaliar modelo
        self._evaluate_model()
        
        return self.model
    
    def _evaluate_model(self):
        """Avaliar performance do modelo com detecção de overfitting"""
        print(f"\n📈 Avaliando modelo...")
        
        # Predições
        y_pred_train = self.model.predict(self.X_train)
        y_pred_test = self.model.predict(self.X_test)
        
        # Métricas básicas
        train_accuracy = accuracy_score(self.y_train, y_pred_train)
        test_accuracy = accuracy_score(self.y_test, y_pred_test)
        
        print(f"🎯 Acurácia Train: {train_accuracy:.4f}")
        print(f"🎯 Acurácia Test: {test_accuracy:.4f}")
        
        # Detecção de overfitting
        overfitting_gap = train_accuracy - test_accuracy
        print(f"⚠️ Gap Train-Test: {overfitting_gap:.4f}")
        
        if overfitting_gap > 0.05:
            print(f"🚨 POSSÍVEL OVERFITTING DETECTADO! Gap = {overfitting_gap:.4f}")
            print("   Sugestões:")
            print("   - Reduzir max_depth")
            print("   - Aumentar min_samples_split/min_samples_leaf")
            print("   - Coletar mais dados benignos")
            print("   - Reduzir max_features do TF-IDF")
        elif overfitting_gap < -0.05:
            print(f"⚠️ POSSÍVEL UNDERFITTING! Gap = {overfitting_gap:.4f}")
            print("   Sugestões:")
            print("   - Aumentar max_depth")
            print("   - Reduzir min_samples_split/min_samples_leaf")
            print("   - Aumentar max_features do TF-IDF")
        else:
            print(f"✅ Modelo balanceado (Gap = {overfitting_gap:.4f})")
        
        # Cross-validation mais robusta
        cv_scores = cross_val_score(
            self.model, self.X_train, self.y_train,
            cv=StratifiedKFold(n_splits=10, shuffle=True, random_state=42),  # Aumentado para 10 folds
            scoring='accuracy'
        )
        
        print(f"🔄 CV Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
        
        # Verificar variabilidade do CV
        if cv_scores.std() > 0.1:
            print(f"⚠️ ALTA VARIABILIDADE NO CV! Std = {cv_scores.std():.4f}")
            print("   Possível instabilidade do modelo")
        
        # Relatório detalhado
        print(f"\n📋 Relatório de Classificação (Test Set):")
        report = classification_report(
            self.y_test, y_pred_test,
            target_names=self.label_encoder.classes_,
            output_dict=True
        )
        
        for label in self.label_encoder.classes_:
            metrics = report[label]
            print(f"   {label}:")
            print(f"     Precision: {metrics['precision']:.4f}")
            print(f"     Recall: {metrics['recall']:.4f}")
            print(f"     F1-score: {metrics['f1-score']:.4f}")
        
        # Salvar métricas expandidas
        self.training_metrics = {
            'train_accuracy': train_accuracy,
            'test_accuracy': test_accuracy,
            'overfitting_gap': overfitting_gap,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'oob_score': self.model.oob_score_,
            'classification_report': report,
            'feature_count': self.X_train.shape[1],
            'training_samples': self.X_train.shape[0],
            'test_samples': self.X_test.shape[0]
        }
    
    def save_model(self, model_name=None):
        """
        Salvar modelo treinado e componentes
        
        Args:
            model_name: Nome personalizado do modelo
        """
        if model_name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            model_name = f"defensive_model_{timestamp}"
        
        print(f"\n💾 Salvando modelo: {model_name}")
        
        # Salvar modelo Random Forest
        model_file = self.output_dir / f"{model_name}.joblib"
        joblib.dump(self.model, model_file)
        
        # Salvar vectorizer
        vectorizer_file = self.output_dir / f"{model_name}_vectorizer.joblib"
        joblib.dump(self.vectorizer, vectorizer_file)
        
        # Salvar label encoder
        encoder_file = self.output_dir / f"{model_name}_encoder.joblib"
        joblib.dump(self.label_encoder, encoder_file)
        
        # Salvar informações do treinamento
        info = {
            'model_name': model_name,
            'training_date': datetime.now().isoformat(),
            'model_type': 'RandomForestClassifier',
            'model_file': str(model_file),
            'vectorizer_file': str(vectorizer_file),
            'encoder_file': str(encoder_file),
            'classes': list(self.label_encoder.classes_),
            'metrics': self.training_metrics,
            'dataset_info': {
                'total_samples': len(self.unified_data),
                'label_distribution': self.unified_data['label'].value_counts().to_dict()
            }
        }
        
        info_file = self.output_dir / f"{model_name}_info.json"
        with open(info_file, 'w') as f:
            json.dump(info, f, indent=2)
        
        print(f"✅ Arquivos salvos:")
        print(f"   - Modelo: {model_file.name}")
        print(f"   - Vectorizer: {vectorizer_file.name}")
        print(f"   - Encoder: {encoder_file.name}")
        print(f"   - Info: {info_file.name}")
        
        return model_file, info_file

def main():
    """Função principal para treinar o modelo defensivo"""
    print("🛡️ TREINAMENTO DO MODELO DEFENSIVO - RANDOM FOREST")
    print("=" * 60)
    print("Sistema para unificar dados e treinar modelo de detecção")
    print("de malware polimórfico usando Random Forest otimizado.")
    print()
    
    # Caminhos dos dados
    mal_api_data_file = "..\\..\\mal-api-2019\\all_analysis_data.txt"
    mal_api_labels_file = "..\\..\\mal-api-2019\\labels.csv"
    benign_data_dir = "benign_data"
    malware_data_dir = "malware_data"
    
    try:
        # Inicializar treinador
        trainer = DefensiveModelTrainer(output_dir="trained_models", verbose=True)
        
        # Carregar dados mal-api-2019
        print("1️⃣ Carregando mal-api-2019...")
        mal_api_data = trainer.load_mal_api_2019(mal_api_data_file, mal_api_labels_file)
        
        # Carregar dados coletados
        print("\n2️⃣ Carregando dados coletados...")
        collected_data = trainer.load_collected_data(benign_data_dir, malware_data_dir)
        
        # Unificar datasets
        print("\n3️⃣ Unificando datasets...")
        unified_data = trainer.unify_datasets(mal_api_data, collected_data)
        
        # Preparar features
        print("\n4️⃣ Preparando features...")
        trainer.prepare_features(max_features=5000)
        
        # Treinar modelo
        print("\n5️⃣ Treinando modelo...")
        model = trainer.train_model(n_estimators=200, max_depth=20)
        
        # Salvar modelo
        print("\n6️⃣ Salvando modelo...")
        model_file, info_file = trainer.save_model("defensive_model_polymorphic")
        
        print(f"\n🎉 TREINAMENTO CONCLUÍDO!")
        print(f"📁 Modelo salvo: {model_file}")
        print(f"📊 Acurácia Test: {trainer.training_metrics['test_accuracy']:.4f}")
        print(f"🔄 CV Accuracy: {trainer.training_metrics['cv_mean']:.4f}")
        
    except Exception as e:
        print(f"❌ Erro durante o treinamento: {e}")
        logging.error(f"Erro no treinamento: {e}")

if __name__ == "__main__":
    main()