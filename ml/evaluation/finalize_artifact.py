"""Measure a validation-selected artifact on the fixed test split exactly once."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import numpy as np
import torch
from backend.config import DATASETS_DIR
from backend.detection.inference import MLService, LABELS
from ml.evaluation.fit_metrics import probability_metrics
from ml.evaluation.predict_batch import predict_many
from ml.training.train_ensemble import measured_member_predictions


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--artifact',type=Path,required=True)
    ap.add_argument('--data',type=Path,default=DATASETS_DIR/'splits')
    args=ap.parse_args();torch.set_num_threads(2)
    path=args.artifact/'metadata.json';metadata=json.loads(path.read_text())
    if metadata.get('test') is not None:
        raise ValueError('This artifact already has a final test report')
    manifest=json.loads((args.data/'manifest.json').read_text())
    if metadata['dataset_version']!=manifest['dataset_version']:raise ValueError('Dataset mismatch')
    rows=[json.loads(line) for line in (args.data/'test.jsonl').open()]
    service=MLService(args.artifact)
    if service.status!='Available':raise ValueError('Artifact cannot be loaded')
    if metadata['model_type']=='ensemble':
        values=[]
        for member,loaded in zip(metadata['members'],service.members):
            source=Path(member['source'])
            # Cached predictions may be reused only if their source artifact is
            # byte-identical to the immutable bundled member.
            matches=all((source/name).exists() and hashlib.sha256((source/name).read_bytes()).hexdigest()==digest
                        for name,digest in member['artifact_sha256'].items())
            p=measured_member_predictions(source,'test',rows,loaded.metadata) if matches else None
            if p is None:p=predict_many(loaded,[r['model_text'] for r in rows])
            values.append(p)
        probabilities=sum(m['weight']*p for m,p in zip(metadata['members'],values))
    else:
        probabilities=predict_many(service,[r['model_text'] for r in rows])
    # Exercise the actual public inference path, including long chunked inputs.
    indices=sorted(set([0,len(rows)//2,len(rows)-1,max(range(len(rows)),key=lambda i:len(rows[i]['model_text']))]))
    for index in indices:
        actual=service.predict(rows[index]['model_text'],explain=False)['probabilities']
        np.testing.assert_allclose(probabilities[index],[actual[label] for label in LABELS],atol=1e-6)
    metadata['test']=probability_metrics([r['label_id'] for r in rows],probabilities)
    metadata['test_evaluation']={'selection_locked_before_test':True,'sha256':hashlib.sha256((args.data/'test.jsonl').read_bytes()).hexdigest(),
                                 'purpose':'Final report only; not used for model or fit selection'}
    with (args.artifact/'test_predictions.csv').open('w',newline='') as stream:
        writer=csv.writer(stream);writer.writerow(['content_id','true_label','predicted_label',*['p_'+label for label in LABELS]])
        for row,p in zip(rows,probabilities):writer.writerow([row['id'],row['label'],LABELS[int(np.argmax(p))],*map(float,p)])
    path.write_text(json.dumps(metadata,indent=2))
    print(json.dumps({'artifact':str(args.artifact),'test_accuracy':metadata['test']['accuracy'],'test_macro_f1':metadata['test']['f1_macro']},indent=2))


if __name__=='__main__':main()
