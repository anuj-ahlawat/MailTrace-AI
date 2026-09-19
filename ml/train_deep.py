"""CNN/BiLSTM or pretrained transformer training, shared fixed grouped splits."""
import argparse,json,random,re,time
from collections import Counter
from pathlib import Path
import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader,TensorDataset
from models.networks import CNN,BiLSTM
from train import metrics,LABELS

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--model',choices=['cnn','bilstm','transformer'],required=True)
    ap.add_argument('--pretrained',default='distilbert/distilbert-base-uncased');ap.add_argument('--epochs',type=int,default=5)
    ap.add_argument('--data',default='ml/artifacts/dataset');ap.add_argument('--out',required=True);ap.add_argument('--batch-size',type=int,default=16)
    args=ap.parse_args();random.seed(42);np.random.seed(42);torch.manual_seed(42);torch.set_num_threads(4)
    root=Path(args.data);out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    splits={s:[json.loads(l) for l in (root/(s+'.jsonl')).open()] for s in ['train','validation','test']}
    for a,b in [('train','validation'),('train','test'),('validation','test')]:
        assert not ({r['group_id'] for r in splits[a]} & {r['group_id'] for r in splits[b]})
    if args.model=='transformer':
        from transformers import AutoTokenizer,AutoModelForSequenceClassification
        tokenizer=AutoTokenizer.from_pretrained(args.pretrained)
        model=AutoModelForSequenceClassification.from_pretrained(args.pretrained,num_labels=4,ignore_mismatched_sizes=True)
        def encode(text):
            ids=tokenizer.encode(text,add_special_tokens=False)
            chunks=[ids[i:i+510] for i in range(0,max(1,len(ids)),510)]
            return [tokenizer.prepare_for_model(c,max_length=512,padding='max_length',truncation=True,return_tensors='pt') for c in chunks]
    else:
        tokens=Counter(t for row in splits['train'] for t in re.findall(r'\w+',row['model_text'].lower()))
        vocab={word:i+2 for i,(word,_) in enumerate(tokens.most_common(30000))}
        (out/'vocab.json').write_text(json.dumps(vocab));model=(CNN if args.model=='cnn' else BiLSTM)(len(vocab)+2)
        def encode(text):
            ids=[vocab.get(w,1) for w in re.findall(r'\w+',text.lower())]
            return [torch.tensor((ids[i:i+512]+[0]*512)[:512]) for i in range(0,max(1,len(ids)),512)]
    device=torch.device('cuda' if torch.cuda.is_available() else 'cpu');model.to(device)
    counts=Counter(r['label_id'] for r in splits['train']);weights=torch.tensor([len(splits['train'])/(4*counts[i]) for i in range(4)],device=device)
    loss_fn=nn.CrossEntropyLoss(weight=weights);optimizer=torch.optim.AdamW(model.parameters(),lr=2e-5 if args.model=='transformer' else 1e-3)
    def logits(chunks):
        if args.model=='transformer':
            return model(**{k:torch.cat([c[k].reshape(1,-1) for c in chunks]).to(device) for k in chunks[0]}).logits
        return model(torch.stack(chunks).to(device))
    def predict(rows):
        model.eval();pred=[]
        with torch.no_grad():
            for row in rows:
                chunks=encode(row['model_text']);probs=[]
                for i in range(0,len(chunks),args.batch_size):probs.append(logits(chunks[i:i+args.batch_size]).softmax(-1).cpu())
                pred.append(int(torch.cat(probs).mean(0).argmax()))
        return pred
    best=-1;history=[];start=time.monotonic()
    for epoch in range(args.epochs):
        model.train();order=list(splits['train']);random.shuffle(order);total=0
        # Sample one chunk per email per epoch so long messages do not dominate training.
        for i in range(0,len(order),args.batch_size):
            batch=order[i:i+args.batch_size];x=[random.choice(encode(r['model_text'])) for r in batch]
            y=torch.tensor([r['label_id'] for r in batch],device=device);optimizer.zero_grad()
            loss=loss_fn(logits(x),y);loss.backward();nn.utils.clip_grad_norm_(model.parameters(),1);optimizer.step();total+=float(loss.detach())
        result=metrics([r['label_id'] for r in splits['validation']],predict(splits['validation']))
        history.append({'epoch':epoch+1,'training_loss_sum':total,'validation':result});score=result['report']['macro avg']['f1-score']
        print(args.model,epoch+1,score,flush=True)
        if score>best:
            best=score
            if args.model=='transformer':model.save_pretrained(out);tokenizer.save_pretrained(out)
            else:torch.save(model.state_dict(),out/'weights.pt')
    if args.model=='transformer':
        from transformers import AutoModelForSequenceClassification
        model=AutoModelForSequenceClassification.from_pretrained(out).to(device)
    else:model.load_state_dict(torch.load(out/'weights.pt',map_location=device,weights_only=True))
    manifest=json.loads((root/'manifest.json').read_text())
    metadata={'model_type':args.model,'label_mapping':dict(enumerate(LABELS)),'dataset_version':manifest['dataset_version'],
        'history':history,'validation_macro_f1':best,'test':metrics([r['label_id'] for r in splits['test']],predict(splits['test'])),
        'training_seconds':time.monotonic()-start,'dataset_manifest':manifest,'limitations':manifest['limitations'],
        'configuration':{'max_length':512,'pretrained':args.pretrained if args.model=='transformer' else None,'seed':42}}
    (out/'metadata.json').write_text(json.dumps(metadata,indent=2))
if __name__=='__main__':main()
