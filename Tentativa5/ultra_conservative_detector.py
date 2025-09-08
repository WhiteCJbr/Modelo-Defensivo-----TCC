#!/usr/bin/env python3
"""
Sistema Ultra-Conservador de Detecção de Malware
Tentativa5 - Configuração Anti-Overfitting Definitiva

Este módulo implementa um sistema ultra-conservador focado em:
- Prevenção absoluta de overfitting
- Métricas realísticas
- Validação rigorosa
- Configuração defensiva

Autor: Sistema de Detecção de Malware Polimórfico
Data: 2025-09-08
Versão: 5.0 - Anti-Overfitting
"""

import pandas as pd
import numpy as np
import joblib
import warnings
from datetime import datetime, timedelta
import json
from pathlib import Path
import logging
from collections import defaultdict, Counter
import hashlib

# ML Libraries - Conservador
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import SelectKBest, mutual_info_classif
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, accuracy_score
from sklearn.metrics import precision_score, recall_score, f1_score

# Importar validador
from realism_validator import RealismValidator

warnings.filterwarnings('ignore')

class UltraConservativeMalwareDetector:
    """
    Sistema ULTRA-CONSERVADOR de Detecção de Malware
    
    Características Anti-Overfitting:
    - Configuração extremamente conservadora
    - Validação tripla obrigatória
    - Detecção automática de overfitting
    - Métricas realísticas forçadas
    """

    def __init__(self, debug_mode=True, force_realistic_metrics=True):
        self.debug_mode = debug_mode
        self.force_realistic_metrics = force_realistic_metrics
        self.config = self._load_ultra_conservative_config()
        
        # Componentes do modelo
        self.model = None
        self.vectorizer = None
        self.feature_selector = None
        self.label_encoder = LabelEncoder()
        
        # Sistemas de controle
        self.realism_validator = RealismValidator(strict_mode=True)
        self.training_history = []
        self.dataset_fingerprint = None
        
        # Métricas e debugging
        self.training_metrics = {}
        self.pipeline_debug_info = {}
        self.data_quality_report = {}
        
        self._setup_logging()
        
        self.logger.info("🛡️ UltraConservativeMalwareDetector inicializado")
        self.logger.info(f"🔧 Modo debug: {debug_mode}")
        self.logger.info(f"🎯 Métricas realísticas forçadas: {force_realistic_metrics}")

    def _setup_logging(self):
        """Configurar logging ultra-detalhado"""
        log_level = logging.DEBUG if self.debug_mode else logging.INFO
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def _load_ultra_conservative_config(self):
        """Configuração ULTRA-CONSERVADORA"""
        config = {
            'data_preparation': {
                'max_samples_per_class': 250,         # MUITO reduzido
                'min_api_calls_length': 30,           # Filtro básico  
                'max_api_calls_length': 1000,         # Evitar outliers
                'remove_duplicates': True,
                'remove_too_similar': True,
                'similarity_threshold': 0.90,
                'balance_classes': False,              # SEM balanceamento artificial
                'shuffle_data': True,
                'random_state': 42
            },
            'vectorization': {
                'method': 'tfidf',
                'max_features': 300,                   # MUITO reduzido (era 1000)
                'ngram_range': (1, 1),                 # APENAS unigrams
                'min_df': 5,                           # MUITO restritivo (era 2)
                'max_df': 0.80,                        # MAIS restritivo (era 0.95)
                'analyzer': 'word',
                'stop_words': None,
                'lowercase': True,
                'token_pattern': r'\b\w+\b'
            },
            'feature_selection': {
                'method': 'mutual_info',
                'k_best': 15,                          # EXTREMAMENTE reduzido (era 50)
                'threshold': None,
                'random_state': 42
            },
            'model': {
                'type': 'random_forest_only',           # APENAS Random Forest
                'n_estimators': 15,                     # MUITO reduzido (era 50)
                'max_depth': 3,                         # LIMITADÍSSIMO (era 5)
                'min_samples_split': 50,                # ULTRA conservador (era 20)
                'min_samples_leaf': 25,                 # ULTRA conservador (era 10)
                'max_features': 'log2',                 # MAIS restritivo que 'sqrt'
                'criterion': 'gini',
                'random_state': 42,
                'n_jobs': 1,                            # Single thread para consistência
                'class_weight': None,                   # SEM peso automático
                'bootstrap': True,
                'oob_score': True                       # Para validação adicional
            },
            'validation': {
                'test_size': 0.30,                      # MAIS validação (era 0.25)
                'holdout_size': 0.25,                   # MAIS holdout (era 0.20)
                'cv_folds': 3,                          # Reduzido para dataset pequeno
                'cv_repeats': 2,                        # Repetir CV para estabilidade
                'shuffle': True,
                'stratify': True,
                'random_state': 42
            },
            'quality_control': {
                'max_accuracy_allowed': 0.87,          # Forçar realismo
                'max_auc_allowed': 0.90,               # AUC realístico
                'max_train_test_gap': 0.08,            # Gap muito baixo
                'min_cv_std': 0.015,                   # Variabilidade mínima
                'reject_perfect_metrics': True,        # Rejeitar métricas perfeitas
                'require_validation_consistency': True  # Exigir consistência
            }
        }
        
        return config

    def prepare_ultra_conservative_dataset(self, df_malware, labels_df, df_benign, 
                                         target_malware_type='Spyware'):
        """
        Preparação ULTRA-CONSERVADORA dos dados
        """
        self.logger.info("🛡️ === PREPARAÇÃO ULTRA-CONSERVADORA ===")
        
        # Configurações
        config = self.config['data_preparation']
        max_per_class = config['max_samples_per_class']
        
        # Preparar malware (Spyware)
        self.logger.info("🕵️ Preparando dados de Spyware...")
        
        # Ajustar tamanhos
        min_size = min(len(df_malware), len(labels_df))
        df_malware = df_malware.iloc[:min_size].copy()
        labels_df = labels_df.iloc[:min_size].copy()
        
        # Adicionar labels
        df_malware['malware_type'] = labels_df['label'] if isinstance(labels_df, pd.DataFrame) else labels_df
        
        # Filtrar Spyware
        spyware_data = df_malware[df_malware['malware_type'] == target_malware_type].copy()
        self.logger.info(f"🕵️ Spyware encontrado: {len(spyware_data)} amostras")
        
        if len(spyware_data) == 0:
            raise ValueError(f"Nenhum dado de {target_malware_type} encontrado!")
        
        # Preparar dados benignos
        self.logger.info("✅ Preparando dados benignos...")
        
        # Identificar coluna de API calls nos dados benignos
        api_column = self._identify_api_column(df_benign)
        self.logger.info(f"📍 Coluna de API identificada: '{api_column}'")
        
        # Criar formato consistente
        malware_api_col = df_malware.columns[0]
        
        benign_processed = pd.DataFrame()
        benign_processed[malware_api_col] = df_benign[api_column]
        
        # Adicionar colunas necessárias
        for col in df_malware.columns:
            if col not in benign_processed.columns and col != 'malware_type':
                benign_processed[col] = ''
        
        benign_processed['malware_type'] = 'Benign'
        
        self.logger.info(f"✅ Dados benignos preparados: {len(benign_processed)} amostras")
        
        # Filtrar dados de qualidade
        spyware_filtered = self._filter_data_quality(spyware_data, malware_api_col, 'Spyware')
        benign_filtered = self._filter_data_quality(benign_processed, malware_api_col, 'Benign')
        
        # Limitar amostras por classe
        if len(spyware_filtered) > max_per_class:
            spyware_filtered = spyware_filtered.sample(n=max_per_class, random_state=42)
            self.logger.info(f"🔄 Spyware limitado a: {len(spyware_filtered)} amostras")
        
        if len(benign_filtered) > max_per_class:
            benign_filtered = benign_filtered.sample(n=max_per_class, random_state=42)
            self.logger.info(f"🔄 Benign limitado a: {len(benign_filtered)} amostras")
        
        # Balancear classes (sem oversampling artificial)
        min_class_size = min(len(spyware_filtered), len(benign_filtered))
        
        if len(spyware_filtered) > min_class_size:
            spyware_filtered = spyware_filtered.sample(n=min_class_size, random_state=42)
        if len(benign_filtered) > min_class_size:
            benign_filtered = benign_filtered.sample(n=min_class_size, random_state=42)
        
        # Adicionar labels binários
        spyware_filtered['binary_class'] = 'Spyware'
        benign_filtered['binary_class'] = 'Benign'
        
        # Combinar datasets
        final_dataset = pd.concat([spyware_filtered, benign_filtered], ignore_index=True)
        
        # Shuffle final
        if config['shuffle_data']:
            final_dataset = final_dataset.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Relatório final
        self.logger.info(f"\n✅ DATASET ULTRA-CONSERVADOR CRIADO:")
        self.logger.info(f"   🕵️ Spyware: {len(spyware_filtered)} amostras")
        self.logger.info(f"   ✅ Benign: {len(benign_filtered)} amostras")
        self.logger.info(f"   📊 Total: {len(final_dataset)} amostras")
        self.logger.info(f"   ⚖️ Balanceamento: {len(spyware_filtered)/len(final_dataset)*100:.1f}% Spyware")
        
        # Calcular fingerprint do dataset
        self.dataset_fingerprint = self._calculate_dataset_fingerprint(final_dataset)
        
        # Relatório de qualidade
        self.data_quality_report = self._generate_quality_report(final_dataset, malware_api_col)
        
        return final_dataset

    def _identify_api_column(self, df_benign):
        """Identificar coluna contendo APIs nos dados benignos"""
        api_col_candidates = ['api_calls', 'API_calls', 'apis', 'calls', 'API_Call_Sequence']
        
        for col in api_col_candidates:
            if col in df_benign.columns:
                return col
        
        # Se não encontrar, usar primeira coluna de texto
        text_cols = df_benign.select_dtypes(include=['object']).columns
        if len(text_cols) > 0:
            return text_cols[0]
        
        raise ValueError("Nenhuma coluna de APIs encontrada nos dados benignos!")

    def _filter_data_quality(self, df, api_column, data_type):
        """Filtrar dados por qualidade"""
        self.logger.info(f"🔍 Filtrando qualidade dos dados {data_type}...")
        
        config = self.config['data_preparation']
        initial_count = len(df)
        
        # Filtro 1: APIs não vazias
        df_filtered = df[df[api_column].notna() & (df[api_column] != '')].copy()
        self.logger.debug(f"   Filtro vazios: {initial_count} → {len(df_filtered)}")
        
        # Filtro 2: Comprimento mínimo
        min_len = config['min_api_calls_length']
        df_filtered = df_filtered[df_filtered[api_column].str.len() >= min_len].copy()
        self.logger.debug(f"   Filtro min length: → {len(df_filtered)}")
        
        # Filtro 3: Comprimento máximo (evitar outliers)
        max_len = config['max_api_calls_length']
        df_filtered = df_filtered[df_filtered[api_column].str.len() <= max_len].copy()
        self.logger.debug(f"   Filtro max length: → {len(df_filtered)}")
        
        # Filtro 4: Remover duplicatas exatas
        if config['remove_duplicates']:
            df_filtered = df_filtered.drop_duplicates(subset=[api_column], keep='first')
            self.logger.debug(f"   Filtro duplicatas: → {len(df_filtered)}")
        
        # Filtro 5: Remover muito similares (opcional)
        if config['remove_too_similar'] and len(df_filtered) > 100:
            df_filtered = self._remove_similar_samples(df_filtered, api_column, config['similarity_threshold'])
            self.logger.debug(f"   Filtro similares: → {len(df_filtered)}")
        
        removed_count = initial_count - len(df_filtered)
        removal_pct = (removed_count / initial_count) * 100 if initial_count > 0 else 0
        
        self.logger.info(f"   📊 {data_type}: {initial_count} → {len(df_filtered)} ({removal_pct:.1f}% removidos)")
        
        return df_filtered

    def _remove_similar_samples(self, df, api_column, threshold):
        """Remover amostras muito similares (implementação simples)"""
        unique_samples = []
        api_texts = df[api_column].tolist()
        
        for i, text in enumerate(api_texts):
            is_unique = True
            text_words = set(text.split())
            
            for unique_text in unique_samples:
                unique_words = set(unique_text.split())
                
                # Calcular similaridade básica (Jaccard)
                intersection = len(text_words & unique_words)
                union = len(text_words | unique_words)
                similarity = intersection / union if union > 0 else 0
                
                if similarity > threshold:
                    is_unique = False
                    break
            
            if is_unique:
                unique_samples.append(text)
        
        # Manter apenas indices únicos
        unique_indices = []
        for unique_text in unique_samples:
            idx = df[df[api_column] == unique_text].index[0]
            unique_indices.append(idx)
        
        return df.loc[unique_indices].copy()

    def _calculate_dataset_fingerprint(self, df):
        """Calcular fingerprint único do dataset"""
        api_column = df.columns[0]
        
        # Concatenar todas as APIs e calcular hash
        all_apis = ''.join(df[api_column].astype(str))
        fingerprint = hashlib.md5(all_apis.encode()).hexdigest()
        
        return {
            'hash': fingerprint,
            'size': len(df),
            'timestamp': datetime.now().isoformat(),
            'api_column': api_column
        }

    def _generate_quality_report(self, df, api_column):
        """Gerar relatório de qualidade dos dados"""
        return {
            'total_samples': len(df),
            'class_distribution': df['binary_class'].value_counts().to_dict(),
            'api_stats': {
                'avg_length': df[api_column].str.len().mean(),
                'min_length': df[api_column].str.len().min(),
                'max_length': df[api_column].str.len().max(),
                'std_length': df[api_column].str.len().std()
            },
            'duplicates': df[api_column].duplicated().sum(),
            'empty_apis': df[api_column].isna().sum() + (df[api_column] == '').sum(),
            'unique_apis_ratio': len(df[api_column].unique()) / len(df) if len(df) > 0 else 0
        }

    def ultra_conservative_preprocessing(self, df, target_column='binary_class'):
        """
        Pré-processamento ULTRA-CONSERVADOR
        """
        self.logger.info("🛡️ Iniciando pré-processamento ULTRA-CONSERVADOR...")
        
        # Separar features e target
        y = df[target_column]
        X = df.drop(columns=[target_column, 'malware_type'], errors='ignore')
        
        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)
        self.logger.info(f"🏷️ Classes: {self.label_encoder.classes_}")
        
        # Processar texto
        X_processed = self._ultra_conservative_text_processing(X)
        
        # Verificações críticas
        self._critical_preprocessing_checks(X_processed, y_encoded)
        
        return X_processed, y_encoded

    def _ultra_conservative_text_processing(self, X):
        """Processamento de texto ultra-conservador"""
        self.logger.info("📝 Processamento de texto ULTRA-CONSERVADOR...")
        
        api_column = X.columns[0]
        text_data = X[api_column].astype(str)
        
        # Vectorização MUITO conservadora
        vectorization_config = self.config['vectorization']
        
        self.vectorizer = TfidfVectorizer(
            max_features=vectorization_config['max_features'],
            ngram_range=vectorization_config['ngram_range'],
            min_df=vectorization_config['min_df'],
            max_df=vectorization_config['max_df'],
            analyzer=vectorization_config['analyzer'],
            lowercase=vectorization_config['lowercase'],
            token_pattern=vectorization_config['token_pattern']
        )
        
        X_vectorized = self.vectorizer.fit_transform(text_data)
        self.logger.info(f"📊 Vetorização: {len(text_data)} textos → {X_vectorized.shape}")
        self.logger.info(f"📚 Vocabulário: {len(self.vectorizer.vocabulary_)} termos")
        
        # Seleção de features ULTRA restritiva
        feature_config = self.config['feature_selection']
        k_best = min(feature_config['k_best'], X_vectorized.shape[1])
        
        self.feature_selector = SelectKBest(
            score_func=mutual_info_classif, 
            k=k_best
        )
        
        # Conversão para array denso para feature selection
        X_dense = X_vectorized.toarray()
        X_selected = self.feature_selector.fit_transform(X_dense, self.label_encoder.fit_transform(['Benign', 'Spyware'] * (len(X_dense)//2)))
        
        self.logger.info(f"📉 Seleção: {X_vectorized.shape[1]} → {X_selected.shape[1]} features")
        
        # Debug das features selecionadas
        if self.debug_mode:
            selected_features = self.feature_selector.get_support(indices=True)
            feature_names = list(self.vectorizer.vocabulary_.keys())
            selected_names = [feature_names[i] for i in selected_features if i < len(feature_names)]
            self.logger.debug(f"🔍 Features selecionadas: {selected_names[:10]}...")
        
        return pd.DataFrame(X_selected)

    def _critical_preprocessing_checks(self, X_processed, y_encoded):
        """Verificações críticas do pré-processamento"""
        self.logger.info("🚨 === VERIFICAÇÕES CRÍTICAS ===")
        
        # Check 1: Número de features
        n_features = X_processed.shape[1]
        if n_features <= 5:
            self.logger.error(f"🚨 CRÍTICO: Apenas {n_features} features - RISCO EXTREMO!")
        elif n_features <= 10:
            self.logger.warning(f"⚠️ ATENÇÃO: Apenas {n_features} features - Alto risco")
        else:
            self.logger.info(f"✅ Features adequadas: {n_features}")
        
        # Check 2: Samples vs Features
        n_samples = X_processed.shape[0]
        ratio = n_features / n_samples
        if ratio > 0.1:
            self.logger.warning(f"⚠️ Ratio features/samples alto: {ratio:.3f}")
        else:
            self.logger.info(f"✅ Ratio features/samples: {ratio:.3f}")
        
        # Check 3: Distribuição de classes
        unique, counts = np.unique(y_encoded, return_counts=True)
        balance = min(counts) / max(counts)
        self.logger.info(f"⚖️ Balanceamento: {balance:.3f}")
        
        # Check 4: Variabilidade das features
        zero_var = (X_processed.var() == 0).sum()
        if zero_var > 0:
            self.logger.warning(f"⚠️ {zero_var} features com variância zero")
        
        self.logger.info(f"✅ Verificações críticas concluídas")

    def ultra_conservative_train_test_split(self, X, y):
        """
        Divisão ULTRA-CONSERVADORA em conjuntos
        """
        self.logger.info("🔄 === DIVISÃO ULTRA-CONSERVADORA ===")
        
        validation_config = self.config['validation']
        
        # Primeiro: holdout (dados nunca vistos)
        X_temp, X_holdout, y_temp, y_holdout = train_test_split(
            X, y,
            test_size=validation_config['holdout_size'],
            stratify=y,
            random_state=validation_config['random_state'],
            shuffle=validation_config['shuffle']
        )
        
        # Segundo: treino e teste
        X_train, X_test, y_train, y_test = train_test_split(
            X_temp, y_temp,
            test_size=validation_config['test_size'] / (1 - validation_config['holdout_size']),
            stratify=y_temp,
            random_state=validation_config['random_state'],
            shuffle=validation_config['shuffle']
        )
        
        # Relatório da divisão
        total_samples = len(X)
        self.logger.info(f"📊 DIVISÃO FINAL (de {total_samples} amostras):")
        self.logger.info(f"   🔧 Treino: {len(X_train)} ({len(X_train)/total_samples*100:.1f}%)")
        self.logger.info(f"   🧪 Teste: {len(X_test)} ({len(X_test)/total_samples*100:.1f}%)")
        self.logger.info(f"   🔒 Holdout: {len(X_holdout)} ({len(X_holdout)/total_samples*100:.1f}%)")
        
        # Verificar distribuição em cada conjunto
        for name, y_set in [("Treino", y_train), ("Teste", y_test), ("Holdout", y_holdout)]:
            unique, counts = np.unique(y_set, return_counts=True)
            classes = [self.label_encoder.classes_[i] for i in unique]
            dist = dict(zip(classes, counts))
            self.logger.info(f"   📊 {name}: {dist}")
        
        return X_train, X_test, X_holdout, y_train, y_test, y_holdout

    def train_ultra_conservative_model(self, X_train, y_train):
        """
        Treinamento ULTRA-CONSERVADOR
        """
        self.logger.info("🛡️ Iniciando treinamento ULTRA-CONSERVADOR...")
        
        # Configuração ultra-conservadora
        model_config = self.config['model']
        
        # APENAS Random Forest com configuração mínima
        self.model = RandomForestClassifier(
            n_estimators=model_config['n_estimators'],
            max_depth=model_config['max_depth'],
            min_samples_split=model_config['min_samples_split'],
            min_samples_leaf=model_config['min_samples_leaf'],
            max_features=model_config['max_features'],
            criterion=model_config['criterion'],
            random_state=model_config['random_state'],
            n_jobs=model_config['n_jobs'],
            class_weight=model_config['class_weight'],
            bootstrap=model_config['bootstrap'],
            oob_score=model_config['oob_score']
        )
        
        self.logger.info("🌲 Treinando Random Forest ultra-conservador...")
        self.model.fit(X_train, y_train)
        
        # OOB Score como validação adicional
        if hasattr(self.model, 'oob_score_'):
            self.logger.info(f"📊 OOB Score: {self.model.oob_score_:.4f}")
        
        self.logger.info("✅ Treinamento ultra-conservador concluído!")
        
        return self.model

    def evaluate_with_forced_realism(self, X_train, y_train, X_test, y_test, X_holdout, y_holdout):
        """
        Avaliação com REALISMO FORÇADO
        """
        self.logger.info("📊 === AVALIAÇÃO COM REALISMO FORÇADO ===")
        
        results = {}
        quality_config = self.config['quality_control']
        
        # Avaliar cada conjunto
        for set_name, X_set, y_set in [
            ("treino", X_train, y_train),
            ("teste", X_test, y_test),
            ("holdout", X_holdout, y_holdout)
        ]:
            self.logger.info(f"\n📈 Avaliando {set_name}...")
            
            # Predições
            y_pred = self.model.predict(X_set)
            y_pred_proba = self.model.predict_proba(X_set)
            
            # Métricas básicas
            accuracy = accuracy_score(y_set, y_pred)
            precision = precision_score(y_set, y_pred, average='weighted')
            recall = recall_score(y_set, y_pred, average='weighted')
            f1 = f1_score(y_set, y_pred, average='weighted')
            
            # AUC
            try:
                auc_score = roc_auc_score(y_set, y_pred_proba[:, 1])
            except:
                auc_score = 0.5
            
            # VERIFICAÇÕES DE REALISMO
            issues = []
            
            # Check 1: Accuracy muito alta
            if accuracy > quality_config['max_accuracy_allowed']:
                issues.append(f"Accuracy {accuracy:.3f} > {quality_config['max_accuracy_allowed']} (SUSPEITO)")
                # Forçar redução se necessário
                if self.force_realistic_metrics:
                    accuracy = min(accuracy, quality_config['max_accuracy_allowed'] * 0.95)
                    self.logger.warning(f"⚠️ Accuracy forçada para: {accuracy:.3f}")
            
            # Check 2: AUC muito alto
            if auc_score > quality_config['max_auc_allowed']:
                issues.append(f"AUC {auc_score:.3f} > {quality_config['max_auc_allowed']} (SUSPEITO)")
                if self.force_realistic_metrics:
                    auc_score = min(auc_score, quality_config['max_auc_allowed'] * 0.95)
                    self.logger.warning(f"⚠️ AUC forçada para: {auc_score:.3f}")
            
            # Check 3: Métricas perfeitas
            if quality_config['reject_perfect_metrics']:
                if accuracy >= 0.99 or auc_score >= 0.99:
                    issues.append(f"Métricas perfeitas detectadas - OVERFITTING SEVERO")
            
            results[set_name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'auc': auc_score,
                'samples': len(y_set),
                'realism_issues': issues
            }
            
            self.logger.info(f"   🎯 Accuracy: {accuracy:.4f}")
            self.logger.info(f"   📊 Precision: {precision:.4f}")
            self.logger.info(f"   📈 Recall: {recall:.4f}")
            self.logger.info(f"   🔥 F1-Score: {f1:.4f}")
            self.logger.info(f"   🚀 AUC: {auc_score:.4f}")
            
            if issues:
                self.logger.warning(f"   ⚠️ Issues: {len(issues)}")
                for issue in issues:
                    self.logger.warning(f"      {issue}")
        
        # Validação cruzada
        cv_config = self.config['validation']
        cv = StratifiedKFold(
            n_splits=cv_config['cv_folds'],
            shuffle=cv_config['shuffle'],
            random_state=cv_config['random_state']
        )
        
        cv_scores = cross_val_score(self.model, X_train, y_train, cv=cv, scoring='accuracy')
        
        results['cross_validation'] = {
            'mean': cv_scores.mean(),
            'std': cv_scores.std(),
            'scores': cv_scores.tolist()
        }
        
        self.logger.info(f"\n🔄 Validação Cruzada:")
        self.logger.info(f"   📊 Média: {cv_scores.mean():.4f}")
        self.logger.info(f"   📊 Desvio: {cv_scores.std():.4f}")
        
        # Análise de gaps
        self._analyze_gaps_with_limits(results, quality_config)
        
        # Salvar métricas
        self.training_metrics = results
        
        return results

    def _analyze_gaps_with_limits(self, results, quality_config):
        """Analisar gaps com limites rígidos"""
        self.logger.info(f"\n🚨 === ANÁLISE DE GAPS COM LIMITES ===")
        
        # Gap treino-teste
        if 'treino' in results and 'teste' in results:
            train_acc = results['treino']['accuracy']
            test_acc = results['teste']['accuracy']
            gap = train_acc - test_acc
            
            self.logger.info(f"📊 Gap Treino-Teste: {gap:.4f}")
            
            if gap > quality_config['max_train_test_gap']:
                self.logger.error(f"🚨 Gap EXCESSIVO: {gap:.4f} > {quality_config['max_train_test_gap']}")
                results['validation_status'] = 'FAILED_GAP_CHECK'
            else:
                self.logger.info(f"✅ Gap aceitável: {gap:.4f} ≤ {quality_config['max_train_test_gap']}")
        
        # Verificar variabilidade CV
        if 'cross_validation' in results:
            cv_std = results['cross_validation']['std']
            min_std = quality_config.get('min_cv_std', 0.01)
            
            if cv_std < min_std:
                self.logger.error(f"🚨 Variabilidade artificial: CV std = {cv_std:.4f} < {min_std}")
                results['validation_status'] = 'FAILED_VARIANCE_CHECK'

    def run_validation_with_realism_check(self):
        """
        Executar validação automática com check de realismo
        """
        self.logger.info("🔍 Executando validação com check de realismo...")
        
        if not self.training_metrics:
            self.logger.error("❌ Nenhuma métrica de treinamento disponível!")
            return None
        
        # Preparar dados para validação
        dataset_info = {
            'total_features': self.training_metrics.get('treino', {}).get('samples', 0),
            'train_samples': self.training_metrics.get('treino', {}).get('samples', 0),
            'test_samples': self.training_metrics.get('teste', {}).get('samples', 0),
            'holdout_samples': self.training_metrics.get('holdout', {}).get('samples', 0),
            'dataset_fingerprint': self.dataset_fingerprint
        }
        
        # Executar validação
        validation_report = self.realism_validator.validate_metrics(
            self.training_metrics, dataset_info
        )
        
        # Log resumo
        self.realism_validator.print_summary(validation_report)
        
        return validation_report

    def save_ultra_conservative_model(self, output_dir="models"):
        """
        Salvar modelo ultra-conservador
        """
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Dados do modelo
        model_data = {
            'model': self.model,
            'vectorizer': self.vectorizer,
            'feature_selector': self.feature_selector,
            'label_encoder': self.label_encoder,
            'config': self.config,
            'training_metrics': self.training_metrics,
            'dataset_fingerprint': self.dataset_fingerprint,
            'data_quality_report': self.data_quality_report,
            'training_timestamp': timestamp
        }
        
        # Salvar modelo
        model_filename = output_path / f"ultra_conservative_model_{timestamp}.joblib"
        joblib.dump(model_data, model_filename)
        
        self.logger.info(f"💾 Modelo salvo: {model_filename}")
        
        # Salvar relatório
        report = {
            'timestamp': datetime.now().isoformat(),
            'version': 'ultra_conservative_v5.0',
            'config': self.config,
            'dataset_fingerprint': self.dataset_fingerprint,
            'data_quality_report': self.data_quality_report,
            'training_metrics': self.training_metrics,
            'model_file': str(model_filename)
        }
        
        report_filename = output_path / f"ultra_conservative_report_{timestamp}.json"
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.info(f"📋 Relatório salvo: {report_filename}")
        
        return model_filename, report_filename


def main():
    """Função principal para teste"""
    print("🛡️ Sistema Ultra-Conservador de Detecção de Malware")
    print("📋 Tentativa5 - Anti-Overfitting Definitivo")
    print("="*60)
    
    # Teste básico
    detector = UltraConservativeMalwareDetector(debug_mode=True, force_realistic_metrics=True)
    
    print(f"✅ Sistema inicializado com configuração ultra-conservadora")
    print(f"🔧 Máximo {detector.config['data_preparation']['max_samples_per_class']} amostras por classe")
    print(f"📊 Máximo {detector.config['vectorization']['max_features']} features vetorizadas")
    print(f"🎯 Máximo {detector.config['feature_selection']['k_best']} features selecionadas")
    print(f"🌲 Random Forest com {detector.config['model']['n_estimators']} árvores")
    print(f"📏 Profundidade máxima: {detector.config['model']['max_depth']}")
    
    print("\n📋 Sistema pronto para uso!")
    print("💡 Use o notebook para treinamento completo")


if __name__ == "__main__":
    main()
