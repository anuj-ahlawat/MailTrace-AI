"""Trainable four-class text networks (no pretrained claims)."""
import torch
from torch import nn

class CNN(nn.Module):
    def __init__(self,vocab_size,embedding_dim=128,hidden=96):
        super().__init__(); self.embedding=nn.Embedding(vocab_size,embedding_dim,padding_idx=0)
        self.convs=nn.ModuleList([nn.Conv1d(embedding_dim,hidden,k) for k in [3,4,5]])
        self.output=nn.Sequential(nn.Dropout(.35),nn.Linear(hidden*3,4))
    def forward(self,tokens):
        embedded=self.embedding(tokens).transpose(1,2)
        features=torch.cat([torch.relu(conv(embedded)).amax(dim=2) for conv in self.convs],dim=1)
        return self.output(features)

class BiLSTM(nn.Module):
    def __init__(self,vocab_size,embedding_dim=128,hidden=96):
        super().__init__();self.embedding=nn.Embedding(vocab_size,embedding_dim,padding_idx=0)
        self.lstm=nn.LSTM(embedding_dim,hidden,batch_first=True,bidirectional=True)
        self.output=nn.Sequential(nn.Dropout(.35),nn.Linear(hidden*2,4))
    def forward(self,tokens):
        lengths=(tokens!=0).sum(1).clamp(min=1).cpu()
        packed=nn.utils.rnn.pack_padded_sequence(self.embedding(tokens),lengths,batch_first=True,enforce_sorted=False)
        _,(hidden,_)=self.lstm(packed)
        return self.output(torch.cat([hidden[-2],hidden[-1]],dim=1))
