"""Train and select a TF-IDF/logistic baseline using validation macro F1 only."""
import argparse,json,time,hashlib
from pathlib import Path
import joblib
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report,confusion_matrix,accuracy_score
import sklearn

LABELS=['BENIGN','PHISHING','BEC','SPAM']
def metrics(y,p):
    return {'accuracy':accuracy_score(y,p),'report':classification_report(y,p,labels=list(range(4)),target_names=LABELS,output_dict=True,zero_division=0),
            'confusion_matrix':confusion_matrix(y,p,labels=list(range(4))).tolist()}
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--data',default='ml/artifacts/dataset');ap.add_argument('--out',default='ml/artifacts/production');args=ap.parse_args()
    root=Path(args.data);out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    splits={s:[json.loads(line) for line in (root/(s+'.jsonl')).open()] for s in ['train','validation','test']}
    for a,b in [('train','validation'),('train','test'),('validation','test')]:
        assert not ({r['group_id'] for r in splits[a]} & {r['group_id'] for r in splits[b]}),'Group leakage'
        assert not ({r['content_hash'] for r in splits[a]} & {r['content_hash'] for r in splits[b]}),'Exact leakage'
    X={s:[r['model_text'] for r in rows] for s,rows in splits.items()};y={s:[r['label_id'] for r in rows] for s,rows in splits.items()}
    start=time.monotonic();candidates=[];best=None;best_f1=-1
    for c in [.5,2,8]:
        model=Pipeline([('tfidf',TfidfVectorizer(max_features=60000,ngram_range=(1,2),min_df=2,sublinear_tf=True)),
            ('classifier',LogisticRegression(C=c,class_weight='balanced',max_iter=600,random_state=42))])
        model.fit(X['train'],y['train']);m=metrics(y['validation'],model.predict(X['validation']));f1=m['report']['macro avg']['f1-score']
        candidates.append({'C':c,'validation':m});print('C',c,'validation_macro_f1',f1,flush=True)
        if f1>best_f1:best=model;best_f1=f1
    test=metrics(y['test'],best.predict(X['test']))
    joblib.dump(best,out/'model.joblib')
    manifest=json.loads((root/'manifest.json').read_text())
    metadata={'model_type':'tfidf_logistic','label_mapping':dict(enumerate(LABELS)), 'dataset_version':manifest['dataset_version'],
        'selection':'Best validation macro-F1 among baseline C candidates; cross-family selection is recorded by select_model.py',
        'validation_macro_f1':best_f1,
        'validation_candidates':candidates,'test':test,'training_seconds':time.monotonic()-start,'sklearn_version':sklearn.__version__,
        'model_sha256':hashlib.sha256((out/'model.joblib').read_bytes()).hexdigest(),'dataset_manifest':manifest,
        'limitations':manifest['limitations'],'configuration':{'C':best['classifier'].C,'max_features':60000,'ngram_range':[1,2]}}
    (out/'metadata.json').write_text(json.dumps(metadata,indent=2)); print(json.dumps(test,indent=2))
if __name__=='__main__':main()
