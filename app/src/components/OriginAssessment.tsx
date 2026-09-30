type Indicator = { kind: string; basis: string; source: string; field: string; value: unknown; ip: string };
type Origin = {
  score?: number; level?: string; candidate_ip?: string | null; interpretation?: string;
  supporting_evidence?: string[]; conflicting_evidence?: string[]; limitations?: string[];
  infrastructure_indicators?: Indicator[];
  disclaimer?: string;
  probable_origin?: { ip?: string; country?: string; region?: string; city?: string; latitude?: number; longitude?: number; asn?: number | string; organization?: string; network_owner?: string; network_cidr?: string; network_type?: string; infrastructure_type?: string; is_vpn?: boolean | null; is_proxy?: boolean | null; is_tor?: boolean | null; mail_cloud_provider?: string; data_source?: string; field_sources?: Record<string,string>; rdap_cross_check?: {status?: string} };
};
export const ORIGIN_DISCLAIMER = "Location is inferred from email relay infrastructure and IP intelligence. It represents an approximate network origin, not the sender's exact physical location. VPNs, proxies, Tor, NAT, cloud infrastructure, and email providers may obscure the true origin.";
type Attribution = { assessment?: string; findings?: { kind: string; status: string; reason: string }[]; next_steps?: string[] };

export default function OriginAssessment({ origin, attribution }: { origin?: Origin; attribution?: Attribution }) {
  const p=origin?.probable_origin;
  const flag=(v?: boolean | null)=>v===true?'Yes (reported)':v===false?'No (reported)':'Unknown / not supplied by provider';
  const fields: [string, unknown][]=[['IP Address',p?.ip || origin?.candidate_ip],['Country',p?.country],['Region',p?.region],['City',p?.city],['Coordinates',p?.latitude!=null&&p?.longitude!=null?`${p.latitude}, ${p.longitude}`:null],['ASN',p?.asn],['Organization / ISP',p?.organization],['Network Owner',p?.network_owner],['Network CIDR / range',p?.network_cidr],['Network Type',p?.network_type || p?.infrastructure_type],['VPN',flag(p?.is_vpn)],['Proxy',flag(p?.is_proxy)],['Tor',flag(p?.is_tor)],['Mail/Cloud Provider',p?.mail_cloud_provider],['Data Source',p?.data_source],['RDAP cross-check',p?.rdap_cross_check?.status]];
  return <>
    <h3>Probable Network Origin</h3>
    <div className="soc-table-wrap"><table><tbody>{fields.map(([label,value])=><tr key={label}><th scope="row">{label}</th><td>{value==null?'Unknown / unavailable':String(value)}</td></tr>)}</tbody></table></div>
    <p className="soc-note">{origin?.disclaimer || ORIGIN_DISCLAIMER}</p>
    {p?.mail_cloud_provider&&<p className="soc-note">Provider association is inferred from network organization records. This relay does not establish the mailbox user’s physical location.</p>}
    {p?.field_sources&&<details><summary>Field-level data sources</summary><ul>{Object.entries(p.field_sources).map(([field,source])=><li key={field}>{field}: {source}</li>)}</ul></details>}
    <div className="soc-banner"><strong>Origin confidence: {origin?.score === undefined ? 'Not Available' : `${origin.score}/100 · ${origin.level}`}</strong><span>Candidate relay: {origin?.candidate_ip || 'Not established'}</span></div>
    <p className="soc-note">{origin?.interpretation || 'Re-analyze this email to compute the current candidate infrastructure assessment.'}</p>
    <div className="soc-grid-2">
      <div><h3>Supporting observations</h3>{origin?.supporting_evidence?.length ? <ul>{origin.supporting_evidence.map((x,i)=><li key={i}>{x}</li>)}</ul> : <p>No supporting observations recorded.</p>}</div>
      <div><h3>Conflicts and limits</h3><ul>{[...(origin?.conflicting_evidence || []), ...(origin?.limitations || [])].map((x,i)=><li key={i}>{x}</li>)}</ul></div>
    </div>
    {!!origin?.infrastructure_indicators?.length && <><h3>Infrastructure indicators</h3><div className="soc-table-wrap"><table><thead><tr><th>Characteristic</th><th>Basis</th><th>Source</th><th>Observed field</th></tr></thead><tbody>{origin.infrastructure_indicators.map((i,n)=><tr key={n}><td>{i.kind}</td><td>{i.basis}</td><td>{i.source}</td><td>{i.field}: {String(i.value)}</td></tr>)}</tbody></table></div></>}
    <h3>Attribution support</h3><p className="soc-note">{attribution?.assessment || 'No attribution assessment recorded. A relay IP does not identify a person.'}</p>
    {attribution?.findings?.map((finding,i)=><p key={i}><strong>{finding.kind} · {finding.status}</strong><br/>{finding.reason}</p>)}
    {!!attribution?.next_steps?.length && <ul>{attribution.next_steps.map(x=><li key={x}>{x}</li>)}</ul>}
  </>;
}
