"""CNN/BiLSTM or pretrained transformer training, shared fixed grouped splits."""
import argparse,csv,json,random,re,time
from collections import Counter
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from backend.config import DATASETS_DIR
import numpy as np
import torch
from torch import nn
from backend.detection.networks import CNN, BiLSTM
from ml.evaluation.metrics import LABELS
from ml.evaluation.fit_metrics import probability_metrics, history_rows

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--model',choices=['cnn','bilstm','transformer'],required=True)
    ap.add_argument('--pretrained',default='distilbert/distilbert-base-uncased');ap.add_argument('--epochs',type=int,default=5)
    ap.add_argument('--data',default=str(DATASETS_DIR / 'splits'));ap.add_argument('--out',required=True);ap.add_argument('--batch-size',type=int,default=16)
    ap.add_argument('--embedding-dim',type=int,default=128);ap.add_argument('--hidden',type=int,default=96)
    ap.add_argument('--dropout',type=float,default=.35);ap.add_argument('--word-dropout',type=float,default=0)
    ap.add_argument('--weight-decay',type=float,default=.01);ap.add_argument('--label-smoothing',type=float,default=0)
    ap.add_argument('--learning-rate',type=float);ap.add_argument('--vocab-size',type=int,default=30000)
    ap.add_argument('--patience',type=int,default=2);ap.add_argument('--threads',type=int,default=4)
    ap.add_argument('--max-length',type=int,default=512)
    ap.add_argument('--skip-test',action='store_true',help='Keep test data untouched during candidate tuning')
    args=ap.parse_args()
    if min(args.epochs,args.batch_size,args.embedding_dim,args.hidden,args.vocab_size,args.patience,args.threads)<1:ap.error('Counts must be positive')
    if not all(0<=v<1 for v in (args.dropout,args.word_dropout,args.label_smoothing)):ap.error('Dropout/smoothing must be in [0,1)')
    if not 8<=args.max_length<=512:ap.error('Max length must be between 8 and 512')
    random.seed(42);np.random.seed(42);torch.manual_seed(42);torch.set_num_threads(args.threads)
    root=Path(args.data);out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    split_names=['train','validation']+([] if args.skip_test else ['test'])
    splits={s:[json.loads(l) for l in (root/(s+'.jsonl')).open()] for s in split_names}
    for a,b in [('train','validation')]+([] if args.skip_test else [('train','test'),('validation','test')]):
        assert not ({r['group_id'] for r in splits[a]} & {r['group_id'] for r in splits[b]})
    if args.model=='transformer':
        from transformers import AutoTokenizer,AutoModelForSequenceClassification
        tokenizer=AutoTokenizer.from_pretrained(args.pretrained)
        model=AutoModelForSequenceClassification.from_pretrained(args.pretrained,num_labels=4,ignore_mismatched_sizes=True)
        def encode(text):
            ids=tokenizer.encode(text,add_special_tokens=False)
            chunks=[ids[i:i+args.max_length-2] for i in range(0,max(1,len(ids)),args.max_length-2)]
            return [tokenizer.prepare_for_model(c,max_length=args.max_length,padding='max_length',truncation=True,return_tensors='pt') for c in chunks]
    else:
        tokens=Counter(t for row in splits['train'] for t in re.findall(r'\w+',row['model_text'].lower()))
        vocab={word:i+2 for i,(word,_) in enumerate(tokens.most_common(args.vocab_size))}
        architecture={'embedding_dim':args.embedding_dim,'hidden':args.hidden,'dropout':args.dropout}
        (out/'vocab.json').write_text(json.dumps(vocab));model=(CNN if args.model=='cnn' else BiLSTM)(len(vocab)+2,**architecture)
        def encode(text):
            ids=[vocab.get(w,1) for w in re.findall(r'\w+',text.lower())]
            return [torch.tensor((ids[i:i+args.max_length]+[0]*args.max_length)[:args.max_length]) for i in range(0,max(1,len(ids)),args.max_length)]
    device=torch.device('cuda' if torch.cuda.is_available() else 'cpu');model.to(device)
    counts=Counter(r['label_id'] for r in splits['train']);weights=torch.tensor([len(splits['train'])/(4*counts[i]) for i in range(4)],device=device)
    loss_fn=nn.CrossEntropyLoss(weight=weights,label_smoothing=args.label_smoothing)
    optimizer=torch.optim.AdamW(model.parameters(),lr=args.learning_rate or (2e-5 if args.model=='transformer' else 1e-3),weight_decay=args.weight_decay)
    encoded={id(row):encode(row['model_text']) for rows in splits.values() for row in rows}
    print('Encoded splits', {s:len(rows) for s,rows in splits.items()}, flush=True)
    def logits(chunks):
        if args.model=='transformer':
            return model(**{k:torch.cat([c[k].reshape(1,-1) for c in chunks]).to(device) for k in chunks[0]}).logits
        return model(torch.stack(chunks).to(device))
    def predict_probabilities(rows):
        if args.model!='transformer':
            model.eval();sums=np.zeros((len(rows),4));counts=np.zeros(len(rows));chunks=[];owners=[]
            def flush():
                if not chunks:return
                with torch.no_grad():values=logits(chunks).softmax(-1).cpu().numpy()
                np.add.at(sums,owners,values);np.add.at(counts,owners,1)
                chunks.clear();owners.clear()
            for index,row in enumerate(rows):
                for chunk in encoded[id(row)]:
                    chunks.append(chunk);owners.append(index)
                    if len(chunks)>=args.batch_size:flush()
            flush()
            return sums/counts[:,None]
        model.eval();pred=[]
        with torch.no_grad():
            for row in rows:
                chunks=encoded[id(row)];probs=[]
                for i in range(0,len(chunks),args.batch_size):probs.append(logits(chunks[i:i+args.batch_size]).softmax(-1).cpu())
                pred.append(torch.cat(probs).mean(0).numpy())
        return pred
    def evaluate(rows):
        return probability_metrics([r['label_id'] for r in rows], predict_probabilities(rows))
    best=-1;best_epoch=None;history=[];start=time.monotonic();stale=0
    for epoch in range(args.epochs):
        model.train();order=list(splits['train']);random.shuffle(order);total=0
        # Sample one chunk per email per epoch so long messages do not dominate training.
        for i in range(0,len(order),args.batch_size):
            batch=order[i:i+args.batch_size];x=[random.choice(encoded[id(r)]) for r in batch]
            if args.model!='transformer' and args.word_dropout:
                x=[torch.where((chunk!=0)&(torch.rand(chunk.shape)<args.word_dropout),1,chunk) for chunk in x]
            y=torch.tensor([r['label_id'] for r in batch],device=device);optimizer.zero_grad()
            loss=loss_fn(logits(x),y);loss.backward();nn.utils.clip_grad_norm_(model.parameters(),1);optimizer.step();total+=float(loss.detach())
            if (i//args.batch_size+1)%100==0:print(args.model,'epoch',epoch+1,'training_emails',min(i+args.batch_size,len(order)),'/',len(order),flush=True)
        # Comparable per-email measurements at the same frozen epoch state.
        # Keep the historical weighted optimizer loss sum as a separate field.
        training=evaluate(splits['train']);result=evaluate(splits['validation'])
        history.append({'epoch':epoch+1,'training_loss_sum':total,'training':training,'validation':result})
        (out/'training_history.json').write_text(json.dumps({'epochs':history,
            'loss_definition':'Mean unweighted per-email log loss of averaged chunk probabilities in eval mode; optimizer loss sum is separate.'},indent=2))
        flat=history_rows(history)
        with (out/'training_history.csv').open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=list(flat[0]));writer.writeheader();writer.writerows(flat)
        score=result['report']['macro avg']['f1-score']
        print(args.model,'epoch',epoch+1,'train_f1',training['f1_macro'],'validation_f1',score,'seconds',round(time.monotonic()-start),flush=True)
        if score>best:
            best=score;best_epoch=epoch+1;stale=0
            if args.model=='transformer':model.save_pretrained(out);tokenizer.save_pretrained(out)
            else:torch.save(model.state_dict(),out/'weights.pt')
        else:stale+=1
        if stale>=args.patience:
            print('Early stopping: validation macro-F1 did not improve',flush=True);break
    if args.model=='transformer':
        from transformers import AutoModelForSequenceClassification
        model=AutoModelForSequenceClassification.from_pretrained(out).to(device)
    else:model.load_state_dict(torch.load(out/'weights.pt',map_location=device,weights_only=True))
    manifest=json.loads((root/'manifest.json').read_text())
    # Save best-checkpoint probabilities for reproducible downstream evaluation
    # and ensemble fitting without repeating expensive neural inference.
    best_predictions={split:predict_probabilities(rows) for split,rows in splits.items()}
    for split,probabilities in best_predictions.items():
        with (out/(split+'_predictions.csv')).open('w',newline='') as stream:
            writer=csv.writer(stream);writer.writerow(['content_id','true_label','predicted_label',*['p_'+label for label in LABELS]])
            for row,p in zip(splits[split],probabilities):
                writer.writerow([row.get('id',row['group_id']),LABELS[row['label_id']],LABELS[int(np.argmax(p))],*map(float,p)])
    metadata={'model_type':args.model,'label_mapping':dict(enumerate(LABELS)),'dataset_version':manifest['dataset_version'],
        'history':history,'history_schema_version':2,'best_epoch':best_epoch,'validation_macro_f1':best,
        'train':probability_metrics([r['label_id'] for r in splits['train']],best_predictions['train']),
        'validation':probability_metrics([r['label_id'] for r in splits['validation']],best_predictions['validation']),
        'test':None if args.skip_test else probability_metrics([r['label_id'] for r in splits['test']],best_predictions['test']),
        'training_seconds':time.monotonic()-start,'dataset_manifest':manifest,'limitations':manifest['limitations'],
        'configuration':{'max_length':args.max_length,'pretrained':args.pretrained if args.model=='transformer' else None,'seed':42,
                         'batch_size':args.batch_size,'epochs':args.epochs,
                         'architecture':architecture if args.model!='transformer' else {},
                         'word_dropout':args.word_dropout,'weight_decay':args.weight_decay,'label_smoothing':args.label_smoothing,
                         'learning_rate':optimizer.param_groups[0]['lr'],'vocab_size':args.vocab_size,'patience':args.patience,
                         'history_loss':'Unweighted per-email log loss in eval mode; training_loss_sum is the weighted optimizer objective.'}}
    (out/'metadata.json').write_text(json.dumps(metadata,indent=2))
if __name__=='__main__':main()
