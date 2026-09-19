"""Intelligence lookup routes — domain, IP, URL."""
from fastapi import APIRouter, Depends, Request
from app.core.security import require_analyst
from app.intelligence.providers import get_intel_provider, LiveIPGeolocation
from app.services.audit import log_event

router = APIRouter(prefix="/intel", tags=["Threat Intelligence"])


@router.get("/domain/{domain}")
async def get_domain_intel(
    domain: str,
    request: Request,
    current_user: dict = Depends(require_analyst),
):
    provider = get_intel_provider()
    result = await provider.lookup_domain(domain)
    await log_event("IOC viewed", user=current_user, request=request,
                    resource="domain_intel", resource_id=domain)
    return result


@router.get("/ip/{ip}")
async def get_ip_intel(
    ip: str,
    request: Request,
    current_user: dict = Depends(require_analyst),
):
    # Try live geolocation first
    provider = get_intel_provider()
    result = await provider.lookup_ip(ip)
    geo = await LiveIPGeolocation.lookup(ip)
    if geo:
        result.update({
            "country": geo.get("country", result.get("country")),
            "city": geo.get("city", result.get("city")),
            "region": geo.get("region", result.get("region")),
            "asn": geo.get("asn", result.get("asn")),
            "isp": geo.get("isp", result.get("isp")),
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
        })
    await log_event("IOC viewed", user=current_user, request=request,
                    resource="ip_intel", resource_id=ip)
    return result


@router.post("/url")
async def get_url_intel(
    url: str,
    request: Request,
    current_user: dict = Depends(require_analyst),
):
    provider = get_intel_provider()
    result = await provider.lookup_url(url)
    await log_event("IOC viewed", user=current_user, request=request,
                    resource="url_intel", resource_id=url[:100])
    return result


@router.get("/iocs")
async def list_iocs(
    skip: int = 0, limit: int = 50,
    ioc_type: str = None,
    current_user: dict = Depends(require_analyst),
):
    from app.core.database import get_db
    db = get_db()
    query = {}
    if ioc_type:
        query["type"] = ioc_type
    cursor = db.iocs.find(query).sort("last_seen", -1).skip(skip).limit(limit)
    docs = await cursor.to_list(length=limit)
    for d in docs:
        d["id"] = str(d.pop("_id", ""))
        for k, v in d.items():
            if hasattr(v, 'isoformat'):
                d[k] = v.isoformat()
    return docs
