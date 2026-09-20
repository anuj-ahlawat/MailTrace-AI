type Contribution = { category: string; maximum_points: number; points: number };
type Assessment = { reported_result?: string; local_verification?: { status?: string } };
type Analysis = {
  contributions?: Contribution[]; formula?: string; risk_version?: string;
  weighted_score?: number; risk_score?: number; interpretation?: string;
  omitted_enrichment_indicators?: number;
  model_review?: { reason: string; limitation: string; minimum_score: number } | null;
  ml?: { status?: string; label?: string; confidence?: number; probabilities?: Record<string, number> };
  forensics?: {
    authentication?: Record<string, Assessment>; urls?: unknown[]; attachments?: unknown[];
    received_chain?: unknown[]; sender?: string;
  };
  intelligence?: { providers?: { provider: string; status: string }[] }[];
};
const labels: Record<string, string> = { ai: 'AI model', url: 'URL', correlated_evidence: 'Correlation adjustment', model_review: 'Model review adjustment' };
const number = (value: number) => value.toLocaleString('en-US', { maximumFractionDigits: 2 });

function assessment(category: string, a: Analysis): string {
  const f = a.forensics;
  if (category === 'ai') return a.ml?.status === 'Available' ? 'Model evaluated' : 'Model unavailable';
  if (category === 'authentication') {
    const auth = f?.authentication;
    const verified = auth?.dkim?.local_verification?.status;
    if (verified === 'PASS' || verified === 'FAIL') return `DKIM verified: ${verified}; SPF may remain unverified`;
    const reported = Object.values(auth || {}).some(v => v.reported_result && v.reported_result !== 'Unknown');
    return reported ? 'Header-reported results only; not independently verified' : 'Authentication verification unavailable';
  }
  if (category === 'intelligence') {
    // Only these providers contribute reputation points. GeoIP is not a safety check.
    const reports = (a.intelligence || []).flatMap(i => i.providers || []).filter(p => ['virustotal', 'abuseipdb', 'greynoise'].includes(p.provider));
    const available = reports.filter(p => p.status === 'Available').length;
    const states = [...new Set(reports.filter(p => p.status !== 'Available').map(p => p.status))];
    const omitted = a.omitted_enrichment_indicators ? `; ${a.omitted_enrichment_indicators} indicators not checked` : '';
    if (!available) return `No reputation results${states.length ? ` (${states.join(', ')})` : ''}${omitted}`;
    return `${available} reputation reports available${states.length ? `; other lookups: ${states.join(', ')}` : ''}${omitted}`;
  }
  if (category === 'attachment') return !f?.attachments ? 'Attachment evidence unavailable' : f.attachments.length ? 'Local file-type checks only; no malware scan' : 'Not applicable: no attachments';
  if (category === 'url') return !f?.urls ? 'URL evidence unavailable' : f.urls.length ? 'Local URL checks; strongest URL only' : 'Not applicable: no URLs';
  if (category === 'headers') return f?.received_chain?.length ? 'Relay timestamp checks evaluated' : 'No relay headers to check';
  if (category === 'sender_identity') return f?.sender ? 'Local sender checks evaluated' : 'Sender evidence unavailable';
  if (category === 'correlated_evidence') return 'Points added to reach the matched rule minimum';
  if (category === 'model_review') return 'Review policy adjustment; not additional forensic evidence';
  return 'Assessment details unavailable';
}

export default function RiskBreakdown({ analysis: a }: { analysis: Analysis }) {
  const contributions = a.contributions || [];
  const ai = contributions.find(c => c.category === 'ai');
  const probabilities = a.ml?.probabilities;
  const weighted = a.weighted_score;
  const adjustment = contributions.find(c => c.category === 'correlated_evidence')?.points || 0;
  const modelAdjustment = contributions.find(c => c.category === 'model_review')?.points || 0;
  return <>
    <p className="soc-note">{a.formula}</p>
    {weighted !== undefined && <p className="soc-note">Scoring version {a.risk_version || 'unknown'} · weighted evidence {number(weighted)}/100{a.risk_score !== undefined && <> · final risk {number(a.risk_score)}/100 (rounded{adjustment + modelAdjustment > 0 ? ` after adding ${[adjustment > 0 ? `${number(adjustment)} correlation points` : '', modelAdjustment > 0 ? `${number(modelAdjustment)} model review points` : ''].filter(Boolean).join(' and ')}` : ''})</>}</p>}
    {a.model_review && <p className="soc-note"><strong>{a.model_review.reason}.</strong> Minimum review score: {a.model_review.minimum_score}/100. {a.model_review.limitation}.</p>}
    <p className="soc-note">Each bar shows points earned out of that category’s maximum. Zero points do not mean a check passed; see the assessment below each category.</p>
    {contributions.map(c => {
      const label = labels[c.category] || c.category.replaceAll('_', ' ');
      return <div className="soc-contribution" key={c.category}>
        <span>{label}<small>{c.maximum_points > 0 ? assessment(c.category, a) : 'Disabled by scoring settings'}</small></span>
        {c.maximum_points > 0 ? <meter min={0} max={c.maximum_points} value={c.points} aria-label={`${label} risk contribution`} /> : <span aria-label={`${label} scoring disabled`}>—</span>}
        <strong>{number(c.points)} / {number(c.maximum_points)}</strong>
      </div>;
    })}
    {a.ml?.status === 'Available' && probabilities && ai && <details className="soc-risk-explanation">
      <summary>How the model contributes to risk</summary>
      <p>The model predicts {a.ml.label}{a.ml.confidence !== undefined ? ` with ${number(a.ml.confidence * 100)}% class probability` : ''}. Class probability is separate from the email’s risk score.</p>
      <p>AI points = category weight × [P(phishing) + P(BEC) + 0.4 × P(spam)]. The policy gives spam less weight than phishing or BEC.</p>
      <p>{number(ai.maximum_points)} × [{number((probabilities.PHISHING || 0) * 100)}% + {number((probabilities.BEC || 0) * 100)}% + 0.4 × {number((probabilities.SPAM || 0) * 100)}%] = {number(ai.points)} points. Calculation uses unrounded probabilities.</p>
    </details>}
    <p className="soc-note">{a.interpretation}</p>
  </>;
}
