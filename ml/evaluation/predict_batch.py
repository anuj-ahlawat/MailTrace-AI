"""Offline probability evaluation, preserving production chunk aggregation."""
import re
import numpy as np
from backend.detection.inference import LABELS


def predict_many(service, texts, batch_size=64):
    if not len(texts):
        return np.empty((0, len(LABELS)))
    if service.status != 'Available':
        raise ValueError('Model unavailable')
    kind = service.metadata['model_type']
    if kind == 'tfidf_logistic':
        return service.model.predict_proba(texts)
    if kind == 'ensemble':
        return sum(weight * predict_many(member, texts, batch_size)
                   for weight, member in zip(service.ensemble_weights, service.members))
    if kind == 'transformer':
        outputs = [service.predict(text, explain=False)['probabilities'] for text in texts]
        return np.asarray([[output[label] for label in LABELS] for output in outputs])
    import torch
    length=int(service.metadata.get('configuration',{}).get('max_length',512))
    sums = np.zeros((len(texts), 4)); counts = np.zeros(len(texts)); chunks = []; owners = []

    def flush():
        if not chunks:
            return
        with torch.no_grad():
            values = service.model(torch.tensor(chunks)).softmax(-1).cpu().numpy()
        np.add.at(sums, owners, values); np.add.at(counts, owners, 1)
        chunks.clear(); owners.clear()

    for index, text in enumerate(texts):
        ids = [service.vocab.get(w, 1) for w in re.findall(r'\w+', text.lower())]
        for start in range(0, max(1, len(ids)), length):
            chunks.append((ids[start:start + length] + [0] * length)[:length]); owners.append(index)
            if len(chunks) >= batch_size:
                flush()
    flush()
    return sums / counts[:, None]
