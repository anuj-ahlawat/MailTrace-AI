"""Small deterministic test inputs validate metrics, never populate user reports."""
import numpy as np
import pytest

from ml.evaluation.fit_metrics import fit_assessment, history_rows, probability_metrics


def test_perfect_predictions_keep_all_four_classes_and_probability_auc():
    labels = [0, 1, 2, 3]
    probabilities = np.full((4, 4), .01)
    probabilities[np.arange(4), labels] = .97
    result = probability_metrics(labels, probabilities)
    assert result['accuracy'] == result['f1_macro'] == result['auc_macro_ovr'] == 1
    assert result['log_loss'] == pytest.approx(-np.log(.97))
    assert sum(map(sum, result['confusion_matrix'])) == 4


def test_absent_classes_have_unavailable_auc_not_zero_or_fabricated_macro():
    result = probability_metrics([0, 0], [[.7, .1, .1, .1], [.4, .2, .2, .2]])
    assert result['auc_macro_ovr'] is None
    assert all(value is None for value in result['auc_per_class_ovr'].values())


@pytest.mark.parametrize('probabilities', [[[.5, .5]], [[1, 1, 1, 1]], [[float('nan'), 0, 0, 0]], [[-1, 1, 1, 0]]])
def test_invalid_probabilities_are_rejected(probabilities):
    with pytest.raises(ValueError):
        probability_metrics([0], probabilities)


def test_legacy_history_does_not_reconstruct_missing_epoch_values():
    row = history_rows([{'epoch': 1, 'training_loss_sum': 100,
                        'validation': {'accuracy': .9, 'report': {'macro avg': {'f1-score': .8}}}}])[0]
    assert row['training_accuracy'] is None
    assert row['training_log_loss'] is None
    assert row['validation_log_loss'] is None
    assert row['validation_accuracy'] == .9
    assert row['training_loss_sum'] == 100


@pytest.mark.parametrize(('train', 'validation', 'expected'), [
    (.95, .93, 'Good/Normal Fit indication'), (.96, .83, 'Overfitting indication'),
    (.6, .5, 'Underfitting indication'), (.79, .9, 'Inconclusive'),
])
def test_fit_diagnosis_is_declared_validation_only_heuristic(train, validation, expected):
    result = fit_assessment({'f1_macro': train}, {'f1_macro': validation})
    assert result['status'] == expected
    assert result['thresholds'] == {'gap': .05, 'adequate_macro_f1': .8}
