import React from "react";
import { Lock, Server, FileSearch, ArrowRightLeft, Fingerprint, Radar, Globe } from "lucide-react";

function Field({ label, value }) {
  return (
    <div className="flex justify-between text-xs py-1 border-b border-slate-800/60 last:border-0 gap-3">
      <span className="text-slate-500 shrink-0">{label}</span>
      <span className="text-slate-300 text-right break-all">{value === null || value === undefined || value === "" ? "—" : String(value)}</span>
    </div>
  );
}

function Section({ icon: Icon, title, available, children, badge }) {
  return (
    <div className="bg-slate-950/50 rounded-lg p-3">
      <div className="flex items-center justify-between mb-1.5">
        <div className="flex items-center gap-1.5 text-slate-300">
          <Icon className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-xs font-semibold">{title}</span>
        </div>
        {badge}
      </div>
      {available ? children : <p className="text-xs text-slate-600 italic">Not available (no network / lookup failed / dependency not installed)</p>}
    </div>
  );
}

function Pill({ ok, textOk = "OK", textBad = "Flagged" }) {
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-medium ${ok ? "bg-risk-low/15 text-risk-low" : "bg-risk-critical/15 text-risk-critical"}`}>
      {ok ? textOk : textBad}
    </span>
  );
}

export default function DomainIntelligencePanel({ intel, brand, threat }) {
  const { domain = {}, ssl = {}, dns = {}, whois = {}, http = {} } = intel || {};

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900 p-5 md:col-span-2 space-y-3">
      <h3 className="font-semibold text-sm mb-1">Domain Intelligence</h3>
      <div className="grid sm:grid-cols-2 gap-3">
        <Section icon={Globe} title="Domain Existence" available={domain.available}
          badge={domain.available && <Pill ok={domain.exists} textOk="Exists" textBad="Not found" />}>
          <Field label="Resolves" value={domain.exists ? "Yes" : "No"} />
        </Section>

        <Section icon={Lock} title="SSL Certificate" available={ssl.available}
          badge={ssl.available && <Pill ok={ssl.valid && !ssl.is_expired && !ssl.is_self_signed} />}>
          <Field label="Exists" value={ssl.exists ? "Yes" : "No"} />
          <Field label="Subject" value={ssl.subject} />
          <Field label="Issuer" value={ssl.issuer} />
          <Field label="Issued" value={ssl.issued_on?.slice(0, 10)} />
          <Field label="Expires" value={ssl.expires_on?.slice(0, 10)} />
          <Field label="Valid" value={ssl.valid ? "Yes" : "No"} />
          <Field label="Hostname matches cert" value={ssl.hostname_matches_certificate ? "Yes" : "No"} />
          <Field label="Self-signed" value={ssl.is_self_signed ? "Yes" : "No"} />
        </Section>

        <Section icon={FileSearch} title="WHOIS" available={whois.available}
          badge={whois.available && <Pill ok={!whois.is_recently_registered} textOk="Established" textBad="New domain" />}>
          <Field label="Registrar" value={whois.registrar} />
          <Field label="Created" value={whois.creation_date?.slice(0, 10)} />
          <Field label="Expires" value={whois.expiration_date?.slice(0, 10)} />
          <Field label="Last updated" value={whois.last_updated?.slice(0, 10)} />
          <Field label="Domain age (days)" value={whois.domain_age_days} />
          <Field label="Registrant country" value={whois.registrant_country} />
        </Section>

        <Section icon={Server} title="DNS" available={dns.available}
          badge={dns.available && <Pill ok={dns.resolves} textOk="Resolves" textBad="No records" />}>
          <Field label="A records" value={(dns.a_records || []).join(", ")} />
          <Field label="CNAME" value={(dns.cname_records || []).join(", ")} />
          <Field label="MX records" value={(dns.mx_records || []).length} />
          <Field label="Nameservers" value={(dns.nameservers || []).join(", ")} />
        </Section>

        <Section icon={ArrowRightLeft} title="HTTP / Redirects" available={http.available}
          badge={http.available && <Pill ok={http.responds && !http.suspicious_redirect} />}>
          <Field label="Responds" value={http.responds ? "Yes" : "No"} />
          <Field label="Status code" value={http.status_code} />
          <Field label="Redirect count" value={http.redirect_count} />
          <Field label="Final URL" value={http.final_url} />
          <Field label="HTTPS enforced" value={http.https_enforced ? "Yes" : "No"} />
        </Section>

        <Section icon={Fingerprint} title="Brand Similarity" available={brand?.available}
          badge={brand?.available && <Pill ok={!brand.is_impersonation_suspected} textOk="No match" textBad="Lookalike" />}>
          <Field label="Closest brand" value={brand?.closest_brand} />
          <Field label="Similarity" value={brand?.similarity != null ? `${brand.similarity}%` : null} />
          <Field label="Impersonation suspected" value={brand?.is_impersonation_suspected ? "Yes" : "No"} />
        </Section>
      </div>

      <div className="bg-slate-950/50 rounded-lg p-3">
        <div className="flex items-center gap-1.5 mb-1.5 text-slate-300">
          <Radar className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-xs font-semibold">Threat Intelligence</span>
        </div>
        {threat?.any_provider_configured ? (
          <>
            <Field label="Flagged malicious" value={threat.is_flagged_malicious ? "Yes" : "No"} />
            {threat.providers.filter((p) => p.configured).map((p) => (
              <Field key={p.provider} label={p.provider} value={p.is_malicious ? "Malicious" : "Clean"} />
            ))}
          </>
        ) : (
          <p className="text-xs text-slate-600 italic">
            No provider configured (Google Safe Browsing / VirusTotal / PhishTank / OpenPhish). Add an API key as an
            environment variable to enable — no code changes required.
          </p>
        )}
      </div>
    </div>
  );
}
