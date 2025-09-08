#!/usr/bin/env python3
"""
Validador de Realismo para Métricas de ML
Tentativa5 - Detecção Automática de Overfitting

Este módulo detecta automaticamente overfitting e métricas irrealísticas
em modelos de detecção de malware.

Autor: Sistema de Detecção de Malware Polimórfico  
Data: 2025-09-08
Versão: 5.0 - Anti-Overfitting
"""

import numpy as np
import pandas as pd
import json
from datetime import datetime
from pathlib import Path
import logging
from typing import Dict, List, Tuple, Any
import warnings

class RealismValidator:
    """
    Validador Avançado de Realismo das Métricas
    
    Detecta automaticamente:
    - Overfitting severo
    - Métricas impossíveis
    - Data leakage
    - Configurações inadequadas
    """
    
    def __init__(self, strict_mode=True):
        self.strict_mode = strict_mode
        
        # Ranges realísticos baseados na literatura
        self.realistic_ranges = {
            'accuracy': {
                'acceptable': (0.60, 0.85),
                'good': (0.70, 0.80),
                'suspicious': (0.90, 1.0),
                'impossible': (0.99, 1.0)
            },
            'precision': {
                'acceptable': (0.55, 0.85),
                'good': (0.65, 0.80),
                'suspicious': (0.90, 1.0),
                'impossible': (0.98, 1.0)
            },
            'recall': {
                'acceptable': (0.55, 0.85),
                'good': (0.65, 0.80),
                'suspicious': (0.90, 1.0),
                'impossible': (0.98, 1.0)
            },
            'f1_score': {
                'acceptable': (0.55, 0.85),
                'good': (0.65, 0.80),
                'suspicious': (0.90, 1.0),
                'impossible': (0.98, 1.0)
            },
            'auc': {
                'acceptable': (0.60, 0.90),
                'good': (0.70, 0.85),
                'suspicious': (0.95, 1.0),
                'impossible': (0.99, 1.0)  # AUC = 1.0 é impossível
            }
        }
        
        # Thresholds para detecção de problemas
        self.problem_thresholds = {
            'overfitting': {
                'train_test_gap_warning': 0.10,
                'train_test_gap_critical': 0.15,
                'train_holdout_gap_warning': 0.12,
                'train_holdout_gap_critical': 0.20
            },
            'stability': {
                'cv_std_too_low': 0.01,      # Variabilidade artificialmente baixa
                'cv_std_too_high': 0.15,     # Modelo instável
                'cv_mean_too_high': 0.90     # CV média suspeita
            },
            'dataset': {
                'min_samples_per_class': 100,
                'min_total_samples': 500,
                'max_features_ratio': 0.1,   # Features/samples
                'min_unique_samples_ratio': 0.95
            }
        }
        
        # Configurar logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Configurar sistema de logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def validate_metrics(self, metrics: Dict, dataset_info: Dict = None) -> Dict:
        """
        Validação completa das métricas
        
        Args:
            metrics: Dicionário com métricas do modelo
            dataset_info: Informações sobre o dataset
            
        Returns:
            Relatório completo de validação
        """
        self.logger.info("🔍 Iniciando validação de realismo das métricas...")
        
        validation_report = {
            'timestamp': datetime.now().isoformat(),
            'validation_version': '5.0',
            'strict_mode': self.strict_mode,
            'overall_status': 'UNKNOWN',
            'issues': {
                'critical': [],
                'warnings': [],
                'info': []
            },
            'metrics_analysis': {},
            'overfitting_analysis': {},
            'stability_analysis': {},
            'dataset_analysis': {},
            'recommendations': [],
            'scores': {
                'realism_score': 0.0,
                'reliability_score': 0.0,
                'production_readiness': 0.0
            }
        }
        
        try:
            # Análise 1: Métricas individuais
            self._analyze_individual_metrics(metrics, validation_report)
            
            # Análise 2: Overfitting
            self._analyze_overfitting(metrics, validation_report)
            
            # Análise 3: Estabilidade
            self._analyze_stability(metrics, validation_report)
            
            # Análise 4: Dataset (se disponível)
            if dataset_info:
                self._analyze_dataset(dataset_info, validation_report)
            
            # Análise 5: Pontuação final
            self._calculate_scores(validation_report)
            
            # Análise 6: Status geral
            self._determine_overall_status(validation_report)
            
            # Análise 7: Recomendações
            self._generate_recommendations(validation_report)
            
            self.logger.info(f"✅ Validação concluída: {validation_report['overall_status']}")
            
        except Exception as e:
            self.logger.error(f"❌ Erro na validação: {e}")
            validation_report['issues']['critical'].append(f"Erro interno: {e}")
            validation_report['overall_status'] = 'ERROR'
        
        return validation_report

    def _analyze_individual_metrics(self, metrics: Dict, report: Dict):
        """Analisar métricas individuais"""
        self.logger.info("📊 Analisando métricas individuais...")
        
        report['metrics_analysis'] = {
            'sets_analyzed': [],
            'metric_issues': {},
            'impossible_metrics': [],
            'suspicious_metrics': [],
            'good_metrics': []
        }
        
        # Analisar cada conjunto (treino, teste, holdout)
        for set_name in ['treino', 'teste', 'holdout']:
            if set_name not in metrics:
                continue
                
            report['metrics_analysis']['sets_analyzed'].append(set_name)
            set_metrics = metrics[set_name]
            
            # Verificar cada métrica
            for metric_name, value in set_metrics.items():
                if metric_name in self.realistic_ranges:
                    issue = self._check_metric_realism(metric_name, value, set_name)
                    
                    if issue:
                        metric_key = f"{set_name}_{metric_name}"
                        report['metrics_analysis']['metric_issues'][metric_key] = issue
                        
                        if issue['severity'] == 'CRITICAL':
                            report['issues']['critical'].append(issue['message'])
                            report['metrics_analysis']['impossible_metrics'].append(metric_key)
                        elif issue['severity'] == 'WARNING':
                            report['issues']['warnings'].append(issue['message'])
                            report['metrics_analysis']['suspicious_metrics'].append(metric_key)
                    else:
                        report['metrics_analysis']['good_metrics'].append(f"{set_name}_{metric_name}")

    def _check_metric_realism(self, metric_name: str, value: float, set_name: str) -> Dict:
        """Verificar realismo de uma métrica específica"""
        ranges = self.realistic_ranges[metric_name]
        
        # Verificar se é impossível
        if ranges['impossible'][0] <= value <= ranges['impossible'][1]:
            return {
                'severity': 'CRITICAL',
                'category': 'impossible_metric',
                'message': f"🚨 {metric_name} em {set_name}: {value:.4f} é IMPOSSÍVEL na prática",
                'value': value,
                'expected_range': ranges['acceptable'],
                'recommendation': f"Revisar modelo - {metric_name}={value:.3f} indica overfitting severo"
            }
        
        # Verificar se é suspeito
        if ranges['suspicious'][0] <= value <= ranges['suspicious'][1]:
            return {
                'severity': 'WARNING',
                'category': 'suspicious_metric',
                'message': f"⚠️ {metric_name} em {set_name}: {value:.4f} é SUSPEITO",
                'value': value,
                'expected_range': ranges['good'],
                'recommendation': f"Investigar - {metric_name}={value:.3f} pode indicar overfitting"
            }
        
        # Verificar se está abaixo do aceitável
        if value < ranges['acceptable'][0]:
            return {
                'severity': 'WARNING',
                'category': 'low_performance',
                'message': f"⚠️ {metric_name} em {set_name}: {value:.4f} abaixo do esperado",
                'value': value,
                'expected_range': ranges['acceptable'],
                'recommendation': f"Melhorar modelo - {metric_name}={value:.3f} está baixo"
            }
        
        return None

    def _analyze_overfitting(self, metrics: Dict, report: Dict):
        """Analisar sinais de overfitting"""
        self.logger.info("🔍 Analisando overfitting...")
        
        report['overfitting_analysis'] = {
            'gaps': {},
            'overfitting_detected': False,
            'overfitting_severity': 'NONE',
            'gap_analysis': {}
        }
        
        # Calcular gaps
        if 'treino' in metrics and 'teste' in metrics:
            train_acc = metrics['treino'].get('accuracy', 0)
            test_acc = metrics['teste'].get('accuracy', 0)
            train_test_gap = train_acc - test_acc
            
            report['overfitting_analysis']['gaps']['train_test'] = train_test_gap
            
            # Avaliar gap treino-teste
            if train_test_gap > self.problem_thresholds['overfitting']['train_test_gap_critical']:
                report['overfitting_analysis']['overfitting_detected'] = True
                report['overfitting_analysis']['overfitting_severity'] = 'CRITICAL'
                report['issues']['critical'].append(
                    f"🚨 Overfitting CRÍTICO: gap treino-teste = {train_test_gap:.4f} > {self.problem_thresholds['overfitting']['train_test_gap_critical']}"
                )
            elif train_test_gap > self.problem_thresholds['overfitting']['train_test_gap_warning']:
                report['overfitting_analysis']['overfitting_detected'] = True
                report['overfitting_analysis']['overfitting_severity'] = 'WARNING'
                report['issues']['warnings'].append(
                    f"⚠️ Possível overfitting: gap treino-teste = {train_test_gap:.4f} > {self.problem_thresholds['overfitting']['train_test_gap_warning']}"
                )
        
        # Gap treino-holdout
        if 'treino' in metrics and 'holdout' in metrics:
            train_acc = metrics['treino'].get('accuracy', 0)
            holdout_acc = metrics['holdout'].get('accuracy', 0)
            train_holdout_gap = train_acc - holdout_acc
            
            report['overfitting_analysis']['gaps']['train_holdout'] = train_holdout_gap
            
            if train_holdout_gap > self.problem_thresholds['overfitting']['train_holdout_gap_critical']:
                report['overfitting_analysis']['overfitting_detected'] = True
                if report['overfitting_analysis']['overfitting_severity'] != 'CRITICAL':
                    report['overfitting_analysis']['overfitting_severity'] = 'CRITICAL'
                report['issues']['critical'].append(
                    f"🚨 Overfitting CRÍTICO: gap treino-holdout = {train_holdout_gap:.4f}"
                )
            elif train_holdout_gap > self.problem_thresholds['overfitting']['train_holdout_gap_warning']:
                report['overfitting_analysis']['overfitting_detected'] = True
                if report['overfitting_analysis']['overfitting_severity'] == 'NONE':
                    report['overfitting_analysis']['overfitting_severity'] = 'WARNING'
                report['issues']['warnings'].append(
                    f"⚠️ Possível overfitting: gap treino-holdout = {train_holdout_gap:.4f}"
                )
        
        # Verificação especial: métricas perfeitas em múltiplos conjuntos
        perfect_metrics_count = 0
        for set_name in ['treino', 'teste', 'holdout']:
            if set_name in metrics:
                set_metrics = metrics[set_name]
                if (set_metrics.get('accuracy', 0) > 0.99 or 
                    set_metrics.get('auc', 0) > 0.99):
                    perfect_metrics_count += 1
        
        if perfect_metrics_count >= 2:
            report['overfitting_analysis']['overfitting_detected'] = True
            report['overfitting_analysis']['overfitting_severity'] = 'CRITICAL'
            report['issues']['critical'].append(
                f"🚨 OVERFITTING MASCARADO: métricas perfeitas em {perfect_metrics_count} conjuntos"
            )

    def _analyze_stability(self, metrics: Dict, report: Dict):
        """Analisar estabilidade do modelo"""
        self.logger.info("📈 Analisando estabilidade...")
        
        report['stability_analysis'] = {
            'cv_available': False,
            'stability_issues': [],
            'stability_score': 0.0
        }
        
        if 'cross_validation' in metrics:
            report['stability_analysis']['cv_available'] = True
            cv_data = metrics['cross_validation']
            
            cv_mean = cv_data.get('mean', 0)
            cv_std = cv_data.get('std', 0)
            cv_scores = cv_data.get('scores', [])
            
            # Verificar variabilidade artificialmente baixa
            if cv_std < self.problem_thresholds['stability']['cv_std_too_low']:
                report['issues']['critical'].append(
                    f"🚨 Variabilidade artificial: CV std = {cv_std:.4f} < {self.problem_thresholds['stability']['cv_std_too_low']}"
                )
                report['stability_analysis']['stability_issues'].append('artificial_low_variance')
            
            # Verificar instabilidade
            elif cv_std > self.problem_thresholds['stability']['cv_std_too_high']:
                report['issues']['warnings'].append(
                    f"⚠️ Modelo instável: CV std = {cv_std:.4f} > {self.problem_thresholds['stability']['cv_std_too_high']}"
                )
                report['stability_analysis']['stability_issues'].append('high_variance')
            
            # Verificar média suspeita
            if cv_mean > self.problem_thresholds['stability']['cv_mean_too_high']:
                report['issues']['warnings'].append(
                    f"⚠️ CV média suspeita: {cv_mean:.4f} > {self.problem_thresholds['stability']['cv_mean_too_high']}"
                )
                report['stability_analysis']['stability_issues'].append('suspicious_cv_mean')
            
            # Calcular score de estabilidade
            if len(report['stability_analysis']['stability_issues']) == 0:
                if 0.02 <= cv_std <= 0.08:  # Range ideal
                    report['stability_analysis']['stability_score'] = 1.0
                else:
                    report['stability_analysis']['stability_score'] = 0.7
            else:
                report['stability_analysis']['stability_score'] = 0.3

    def _analyze_dataset(self, dataset_info: Dict, report: Dict):
        """Analisar características do dataset"""
        self.logger.info("📋 Analisando dataset...")
        
        report['dataset_analysis'] = {
            'size_issues': [],
            'quality_issues': [],
            'recommendations': []
        }
        
        # Verificar tamanho do dataset
        total_samples = sum([
            dataset_info.get('train_samples', 0),
            dataset_info.get('test_samples', 0),
            dataset_info.get('holdout_samples', 0)
        ])
        
        if total_samples < self.problem_thresholds['dataset']['min_total_samples']:
            report['issues']['warnings'].append(
                f"⚠️ Dataset pequeno: {total_samples} < {self.problem_thresholds['dataset']['min_total_samples']} amostras"
            )
            report['dataset_analysis']['size_issues'].append('dataset_too_small')
        
        # Verificar proporção features/amostras
        total_features = dataset_info.get('total_features', 0)
        if total_features > 0 and total_samples > 0:
            features_ratio = total_features / total_samples
            if features_ratio > self.problem_thresholds['dataset']['max_features_ratio']:
                report['issues']['warnings'].append(
                    f"⚠️ Muitas features: {total_features} features / {total_samples} amostras = {features_ratio:.3f}"
                )
                report['dataset_analysis']['quality_issues'].append('too_many_features')

    def _calculate_scores(self, report: Dict):
        """Calcular pontuações finais"""
        scores = report['scores']
        
        # Score de realismo (baseado em issues críticos)
        critical_count = len(report['issues']['critical'])
        warning_count = len(report['issues']['warnings'])
        
        if critical_count == 0:
            if warning_count == 0:
                scores['realism_score'] = 1.0
            elif warning_count <= 2:
                scores['realism_score'] = 0.8
            else:
                scores['realism_score'] = 0.6
        else:
            scores['realism_score'] = max(0.0, 0.4 - (critical_count * 0.1))
        
        # Score de confiabilidade (baseado em estabilidade)
        stability_score = report.get('stability_analysis', {}).get('stability_score', 0.5)
        overfitting_detected = report.get('overfitting_analysis', {}).get('overfitting_detected', False)
        
        if overfitting_detected:
            scores['reliability_score'] = min(0.3, stability_score)
        else:
            scores['reliability_score'] = stability_score
        
        # Score de prontidão para produção
        scores['production_readiness'] = min(scores['realism_score'], scores['reliability_score'])

    def _determine_overall_status(self, report: Dict):
        """Determinar status geral"""
        critical_count = len(report['issues']['critical'])
        warning_count = len(report['issues']['warnings'])
        production_score = report['scores']['production_readiness']
        
        if critical_count > 0:
            if critical_count >= 3:
                report['overall_status'] = 'CRITICAL_FAILURE'
            else:
                report['overall_status'] = 'NEEDS_MAJOR_FIXES'
        elif warning_count > 5:
            report['overall_status'] = 'NEEDS_IMPROVEMENTS'
        elif production_score >= 0.8:
            report['overall_status'] = 'PRODUCTION_READY'
        elif production_score >= 0.6:
            report['overall_status'] = 'ACCEPTABLE'
        else:
            report['overall_status'] = 'NEEDS_WORK'

    def _generate_recommendations(self, report: Dict):
        """Gerar recomendações específicas"""
        recommendations = report['recommendations']
        
        # Baseado no status geral
        overall_status = report['overall_status']
        
        if overall_status == 'CRITICAL_FAILURE':
            recommendations.extend([
                "🚨 REFORMULAR COMPLETAMENTE o modelo",
                "🚨 COLETAR NOVOS DADOS com maior diversidade",
                "🚨 REVISAR pipeline de pré-processamento",
                "🚨 APLICAR configuração ultra-conservadora"
            ])
        
        elif overall_status == 'NEEDS_MAJOR_FIXES':
            recommendations.extend([
                "⚠️ Reduzir drasticamente a complexidade do modelo",
                "⚠️ Aumentar o dataset de treinamento",
                "⚠️ Aplicar mais regularização",
                "⚠️ Revisar seleção de features"
            ])
        
        # Baseado em issues específicos
        if 'artificial_low_variance' in report.get('stability_analysis', {}).get('stability_issues', []):
            recommendations.append("🔧 Aumentar variabilidade dos dados de treino")
        
        if report.get('overfitting_analysis', {}).get('overfitting_detected', False):
            recommendations.extend([
                "🔧 Implementar early stopping",
                "🔧 Reduzir número de features",
                "🔧 Usar validação holdout rigorosa"
            ])
        
        # Sempre incluir monitoramento
        if overall_status not in ['CRITICAL_FAILURE', 'NEEDS_MAJOR_FIXES']:
            recommendations.append("📊 Implementar monitoramento contínuo em produção")

    def save_report(self, report: Dict, output_path: str = None):
        """Salvar relatório de validação"""
        if output_path is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f"validation_report_{timestamp}.json"
        
        try:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            self.logger.info(f"📋 Relatório salvo: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"❌ Erro salvando relatório: {e}")
            return None

    def print_summary(self, report: Dict):
        """Imprimir resumo da validação"""
        print("\n" + "="*60)
        print("🔍 RELATÓRIO DE VALIDAÇÃO DE REALISMO")
        print("="*60)
        
        # Status geral
        status = report['overall_status']
        status_colors = {
            'PRODUCTION_READY': '🟢',
            'ACCEPTABLE': '🟡', 
            'NEEDS_WORK': '🟠',
            'NEEDS_IMPROVEMENTS': '🔴',
            'NEEDS_MAJOR_FIXES': '🚨',
            'CRITICAL_FAILURE': '💀'
        }
        
        print(f"\n📊 STATUS GERAL: {status_colors.get(status, '❓')} {status}")
        
        # Pontuações
        scores = report['scores']
        print(f"\n📈 PONTUAÇÕES:")
        print(f"   🎯 Realismo: {scores['realism_score']:.2f}/1.00")
        print(f"   🛡️ Confiabilidade: {scores['reliability_score']:.2f}/1.00")
        print(f"   🚀 Prontidão: {scores['production_readiness']:.2f}/1.00")
        
        # Issues críticos
        if report['issues']['critical']:
            print(f"\n🚨 ISSUES CRÍTICOS ({len(report['issues']['critical'])}):")
            for issue in report['issues']['critical']:
                print(f"   {issue}")
        
        # Warnings
        if report['issues']['warnings']:
            print(f"\n⚠️ WARNINGS ({len(report['issues']['warnings'])}):")
            for warning in report['issues']['warnings'][:5]:  # Mostrar só os primeiros 5
                print(f"   {warning}")
            if len(report['issues']['warnings']) > 5:
                print(f"   ... e mais {len(report['issues']['warnings']) - 5} warnings")
        
        # Recomendações principais
        if report['recommendations']:
            print(f"\n💡 RECOMENDAÇÕES PRINCIPAIS:")
            for rec in report['recommendations'][:3]:  # Top 3
                print(f"   {rec}")
        
        print("="*60)


def validate_current_model(metrics_file: str, dataset_info: Dict = None) -> Dict:
    """
    Função auxiliar para validar modelo atual
    
    Args:
        metrics_file: Caminho para arquivo JSON com métricas
        dataset_info: Informações do dataset (opcional)
    
    Returns:
        Relatório de validação
    """
    try:
        with open(metrics_file, 'r') as f:
            data = json.load(f)
        
        metrics = data.get('metrics', {})
        if dataset_info is None:
            dataset_info = data.get('dataset_info', {})
        
        validator = RealismValidator(strict_mode=True)
        report = validator.validate_metrics(metrics, dataset_info)
        
        return report
        
    except Exception as e:
        print(f"❌ Erro validando modelo: {e}")
        return None


if __name__ == "__main__":
    # Teste com métricas do modelo V4
    test_metrics = {
        'treino': {'accuracy': 0.9977, 'precision': 0.9977, 'recall': 0.9977, 'f1_score': 0.9977, 'auc': 1.0},
        'teste': {'accuracy': 0.995, 'precision': 0.995, 'recall': 0.995, 'f1_score': 0.995, 'auc': 1.0},
        'holdout': {'accuracy': 0.99375, 'precision': 0.9938, 'recall': 0.99375, 'f1_score': 0.9937, 'auc': 1.0},
        'cross_validation': {'mean': 0.9955, 'std': 0.0056, 'scores': [1.0, 1.0, 0.9886, 1.0, 0.9886]}
    }
    
    test_dataset = {
        'train_samples': 440,
        'test_samples': 200,
        'holdout_samples': 160,
        'total_features': 50
    }
    
    print("🧪 Testando validador com métricas do modelo V4...")
    
    validator = RealismValidator(strict_mode=True)
    report = validator.validate_metrics(test_metrics, test_dataset)
    validator.print_summary(report)
    
    # Salvar relatório
    output_file = validator.save_report(report, "v4_validation_report.json")
    print(f"\n💾 Relatório detalhado salvo: {output_file}")
