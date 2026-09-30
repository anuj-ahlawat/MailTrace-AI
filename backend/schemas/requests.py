"""Requests."""
from typing import Literal
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from backend.database.store import DEFAULTS
from backend.intelligence.providers import CORE_PROVIDERS

class Input(BaseModel):
    model_config=ConfigDict(extra='forbid')


class Login(Input):
    email:EmailStr
    password:str=Field(min_length=1,max_length=1024)


class NewUser(Input):
    email:EmailStr
    name:str=Field(min_length=1,max_length=120)
    password:str=Field(min_length=12,max_length=128)
    role:Literal['ANALYST','SENIOR_ANALYST','ADMINISTRATOR']='ANALYST'


class UserUpdate(Input):
    name:str|None=Field(default=None,min_length=1,max_length=120)
    role:Literal['ANALYST','SENIOR_ANALYST','ADMINISTRATOR']|None=None
    status:Literal['active','inactive']|None=None


class RawEmail(Input):
    raw_email:str=Field(min_length=20,max_length=10_000_000)


class PasswordChange(Input):
    current_password:str=Field(min_length=1,max_length=1024)
    new_password:str=Field(min_length=12,max_length=128)


class CaseCreate(Input):
    title:str=Field(min_length=1,max_length=250)
    description:str=Field(default='',max_length=20000)
    email_ids:list[str]=Field(default_factory=list,max_length=100)


class CaseUpdate(Input):
    title:str|None=Field(default=None,min_length=1,max_length=250)
    description:str|None=Field(default=None,max_length=20000)
    status:Literal['OPEN','IN_PROGRESS','ESCALATED','RESOLVED','CLOSED']|None=None
    assigned_to:str|None=None


class Note(Input):
    content:str=Field(min_length=1,max_length=20000)


class LinkEvidence(Input):
    evidence_id:str


class LinkEmail(Input):
    email_id:str


class Indicator(Input):
    type:Literal['ip','domain','url','hash']
    value:str=Field(min_length=1,max_length=4096)


class ReportCreate(Input):
    case_id:str
    title:str=Field(default='Forensic Investigation Report',min_length=1,max_length=250)


class AlertUpdate(Input):
    status:Literal['OPEN','ACKNOWLEDGED','RESOLVED']


class ProviderKey(Input):
    api_key:str=Field(min_length=1,max_length=4096)


class SystemUpdate(Input):
    max_upload_mb:int=Field(default=10,ge=1,le=25)
    csv_row_limit:int=Field(default=500,ge=1,le=1000)
    alert_threshold:int=Field(default=60,ge=1,le=100)
    mask_sensitive:bool=False
    retention_enabled:bool=False
    analysis_retention_days:int=Field(default=365,ge=1,le=36500)
    evidence_retention_days:int=Field(default=730,ge=1,le=36500)
    audit_retention_days:int=Field(default=1095,ge=30,le=36500)
    risk_weights:dict[str,float]=Field(default_factory=lambda:DEFAULTS['risk_weights'].copy())
    risk_thresholds:list[int]=Field(default_factory=lambda:[30,60,80],min_length=3,max_length=3)
    enabled_providers:list[Literal['virustotal','abuseipdb','urlscan','greynoise','geoip','ipinfo']]=Field(default_factory=lambda:list(CORE_PROVIDERS))
    dns_enabled:bool=False
    automatic_enrichment:bool=False
    rdap_enabled:bool=False
    model_name:Literal['production','baseline','cnn','bilstm','transformer','ensemble']='production'


class CampaignCreate(Input):
    title:str=Field(min_length=1,max_length=250)
    email_ids:list[str]=Field(min_length=2,max_length=100)
    reason:str=Field(min_length=10,max_length=5000)
