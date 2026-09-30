"""Measured classification metrics and explicitly heuristic fit diagnostics."""
import numpy as np
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, log_loss, roc_auc_score

from ml.evaluation.metrics import LABELS


def probability_metrics(actual, probabilities):
    actual = np.asarray(actual, dtype=int)
    probabilities = np.asarray(probabilities, dtype=float)
    if probabilities.shape != (len(actual), len(LABELS)) or not len(actual):
        raise ValueError('Expected one four-class probability row per email')
    if not np.isfinite(probabilities).all() or (probabilities < 0).any():
        raise ValueError('Invalid probabilities')
    if not np.allclose(probabilities.sum(axis=1), 1, atol=1e-5):
        raise ValueError('Class probabilities must sum to one')
    if not np.isin(actual, np.arange(len(LABELS))).all():
        raise ValueError('Unexpected class label')
    probabilities = probabilities / probabilities.sum(axis=1, keepdims=True)
    predicted = probabilities.argmax(axis=1)
    report = classification_report(actual, predicted, labels=list(range(len(LABELS))),
                                   target_names=LABELS, output_dict=True, zero_division=0)
    auc = {name: (float(roc_auc_score(actual == i, probabilities[:, i]))
                  if 0 < (actual == i).sum() < len(actual) else None)
           for i, name in enumerate(LABELS)}
    return {'count': len(actual), 'accuracy': float(accuracy_score(actual, predicted)),
            'precision_macro': report['macro avg']['precision'],
            'recall_macro': report['macro avg']['recall'], 'f1_macro': report['macro avg']['f1-score'],
            'log_loss': float(log_loss(actual, probabilities, labels=list(range(len(LABELS))))),
            'auc_macro_ovr': float(np.mean(list(auc.values()))) if all(v is not None for v in auc.values()) else None,
            'auc_per_class_ovr': auc, 'report': report,
            'confusion_matrix': confusion_matrix(actual, predicted, labels=list(range(len(LABELS)))).tolist()}


def fit_assessment(train, validation, gap_threshold=.05, adequate_f1=.80):
    """Use validation, never test results, for this configurable screening rule."""
    gap = train['f1_macro'] - validation['f1_macro']
    if train['f1_macro'] >= adequate_f1 and gap >= gap_threshold:
        status = 'Overfitting indication'
    elif train['f1_macro'] < adequate_f1 and validation['f1_macro'] < adequate_f1:
        status = 'Underfitting indication'
    elif train['f1_macro'] >= adequate_f1 and validation['f1_macro'] >= adequate_f1 and abs(gap) < gap_threshold:
        status = 'Good/Normal Fit indication'
    else:
        status = 'Inconclusive'
    return {'status': status, 'basis': 'Current saved checkpoint; train versus validation macro-F1',
            'train_minus_validation_f1': gap,
            'thresholds': {'gap': gap_threshold, 'adequate_macro_f1': adequate_f1},
            'limitation': 'Heuristic screening, not proof of fit or real-world generalization. '
                          'Thresholds are declared policy choices, not measured model values. '
                          'Missing epoch curves cannot be reconstructed from one saved checkpoint.'}


def history_rows(history):
    """Preserve missing observations as null; never fabricate epoch measurements."""
    return [{'epoch': row['epoch'], 'training_loss_sum': row.get('training_loss_sum'),
             'training_log_loss': row.get('training', {}).get('log_loss'),
             'validation_log_loss': row.get('validation', {}).get('log_loss'),
             'training_accuracy': row.get('training', {}).get('accuracy'),
             'validation_accuracy': row.get('validation', {}).get('accuracy'),
             'training_macro_f1': row.get('training', {}).get('report', {}).get('macro avg', {}).get('f1-score'),
             'validation_macro_f1': row.get('validation', {}).get('report', {}).get('macro avg', {}).get('f1-score')}
            for row in history]
