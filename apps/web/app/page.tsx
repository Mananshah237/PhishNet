'use client';

import React, { useEffect, useMemo, useState } from 'react';

type EmailListItem = {
  id: string;
  source: string;
  subject?: string | null;
  from_addr?: string | null;
  created_at: string;
};

type EmailDetail = {
  id: string;
  source?: string;
  created_at?: string;
  headers?: { subject?: string | null; from?: string | null };
  body?: { text?: string };
  links?: { defanged?: string[] };
  analysis?: any;
};

type Detection = { label: string; risk_score: number; reasons: string[] };

type Rewrite = { safe_subject?: string | null; safe_body: string; used_llm: boolean };

function apiBase() {
  return process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:8000';
}

function Badge({ text, bg }: { text: string; bg: string }) {
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: 999,
        background: bg,
        color: 'white',
        fontSize: 12,
        fontWeight: 600
      }}
    >
      {text}
    </span>
  );
}

export default function Home() {
  const base = useMemo(() => apiBase(), []);

  const [health, setHealth] = useState<any>(null);
  const [emails, setEmails] = useState<EmailListItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<EmailDetail | null>(null);

  const [detecting, setDetecting] = useState(false);
  const [detection, setDetection] = useState<Detection | null>(null);

  const [rewriting, setRewriting] = useState(false);
  const [rewrite, setRewrite] = useState<Rewrite | null>(null);
  const [useLlm, setUseLlm] = useState(false);

  const [busyMsg, setBusyMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function refreshHealth() {
    const res = await fetch(`${base}/health`, { cache: 'no-store' });
    setHealth(await res.json());
  }

  async function refreshEmails(selectFirst = false) {
    const res = await fetch(`${base}/emails`, { cache: 'no-store' });
    const data = (await res.json()) as EmailListItem[];
    setEmails(data);
    if (selectFirst && data.length && !selectedId) {
      setSelectedId(data[0].id);
    }
  }

  async function loadEmail(id: string) {
    setError(null);
    setBusyMsg('Loading email…');
    try {
      const res = await fetch(`${base}/emails/${id}`, { cache: 'no-store' });
      const d = (await res.json()) as EmailDetail;
      setDetail(d);
      setDetection(d?.analysis?.detection ?? null);
      setRewrite(d?.analysis?.rewrite ?? null);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusyMsg(null);
    }
  }

  async function uploadEml(file: File) {
    setError(null);
    setBusyMsg('Uploading .eml…');
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await fetch(`${base}/ingest/upload-eml`, { method: 'POST', body: fd });
      if (!res.ok) throw new Error(`Upload failed: ${res.status}`);
      const data = await res.json();
      const id = data.email_id as string;
      await refreshEmails(false);
      setSelectedId(id);
      await loadEmail(id);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusyMsg(null);
    }
  }

  async function runDetect() {
    if (!selectedId) return;
    setDetecting(true);
    setError(null);
    try {
      const res = await fetch(`${base}/emails/${selectedId}/detect`, { method: 'POST' });
      if (!res.ok) throw new Error(`Detect failed: ${res.status}`);
      const d = (await res.json()) as Detection;
      setDetection(d);
      await loadEmail(selectedId);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setDetecting(false);
    }
  }

  async function runRewrite() {
    if (!selectedId) return;
    setRewriting(true);
    setError(null);
    try {
      const qs = new URLSearchParams({ use_llm: useLlm ? 'true' : 'false' });
      const res = await fetch(`${base}/emails/${selectedId}/rewrite?${qs.toString()}`, { method: 'POST' });
      if (!res.ok) throw new Error(`Rewrite failed: ${res.status}`);
      const d = (await res.json()) as Rewrite;
      setRewrite(d);
      await loadEmail(selectedId);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setRewriting(false);
    }
  }

  function riskBadge() {
    const score = detection?.risk_score;
    if (score === undefined || score === null) return null;
    if (score >= 70) return <Badge text={`HIGH (${score})`} bg="#b91c1c" />;
    if (score >= 40) return <Badge text={`MED (${score})`} bg="#b45309" />;
    if (score >= 20) return <Badge text={`LOW (${score})`} bg="#1d4ed8" />;
    return <Badge text={`MIN (${score})`} bg="#065f46" />;
  }

  useEffect(() => {
    (async () => {
      try {
        await refreshHealth();
        await refreshEmails(true);
      } catch {
        // ignore; rendered error covers it
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (selectedId) loadEmail(selectedId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  return (
    <main style={{ maxWidth: 1200 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between' }}>
        <div>
          <h1 style={{ marginBottom: 4 }}>PhishNet</h1>
          <div style={{ color: '#444' }}>MVP demo UI — upload .eml → detect → rewrite (no raw HTML to client).</div>
        </div>
        <div style={{ fontSize: 12, color: '#666' }}>
          API: <code>{base}</code> {health?.ok ? <Badge text="OK" bg="#065f46" /> : null}
        </div>
      </div>

      <section
        style={{
          marginTop: 16,
          padding: 12,
          border: '1px solid #e5e7eb',
          borderRadius: 12,
          background: '#fafafa'
        }}
      >
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <label style={{ display: 'inline-flex', gap: 8, alignItems: 'center' }}>
            <strong>Upload .eml</strong>
            <input
              type="file"
              accept=".eml,message/rfc822"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) uploadEml(f);
              }}
            />
          </label>

          <button
            onClick={() => refreshEmails(false)}
            style={{ padding: '8px 10px', borderRadius: 10, border: '1px solid #ddd', background: 'white' }}
          >
            Refresh list
          </button>

          <div style={{ flex: 1 }} />

          {busyMsg ? <span style={{ color: '#444' }}>{busyMsg}</span> : null}
          {error ? <span style={{ color: '#b91c1c' }}>{error}</span> : null}
        </div>
      </section>

      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 16, marginTop: 16 }}>
        {/* Left: list */}
        <aside
          style={{
            border: '1px solid #e5e7eb',
            borderRadius: 12,
            overflow: 'hidden'
          }}
        >
          <div style={{ padding: 12, borderBottom: '1px solid #e5e7eb', background: '#fff' }}>
            <strong>Emails</strong> <span style={{ color: '#666' }}>({emails.length})</span>
          </div>
          <div style={{ maxHeight: 520, overflow: 'auto', background: '#fff' }}>
            {emails.length === 0 ? (
              <div style={{ padding: 12, color: '#666' }}>Upload an .eml to get started.</div>
            ) : (
              emails.map((e) => (
                <button
                  key={e.id}
                  onClick={() => setSelectedId(e.id)}
                  style={{
                    display: 'block',
                    width: '100%',
                    textAlign: 'left',
                    padding: 12,
                    border: 'none',
                    borderBottom: '1px solid #f3f4f6',
                    background: e.id === selectedId ? '#eef2ff' : 'white',
                    cursor: 'pointer'
                  }}
                >
                  <div style={{ fontWeight: 600, marginBottom: 4, fontSize: 13 }}>{e.subject || '(no subject)'}</div>
                  <div style={{ color: '#555', fontSize: 12, marginBottom: 6 }}>{e.from_addr || '(unknown sender)'}</div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: 11, color: '#777' }}>
                    <span>{e.source}</span>
                    <span>{new Date(e.created_at).toLocaleString()}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </aside>

        {/* Right: viewer */}
        <section
          style={{
            border: '1px solid #e5e7eb',
            borderRadius: 12,
            padding: 12,
            background: '#fff'
          }}
        >
          {!detail ? (
            <div style={{ color: '#666' }}>Select an email to view.</div>
          ) : (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
                <div>
                  <div style={{ fontSize: 18, fontWeight: 800 }}>{detail.headers?.subject || '(no subject)'}</div>
                  <div style={{ color: '#555', marginTop: 4 }}>From: {detail.headers?.from || '(unknown)'}</div>
                </div>
                <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>{riskBadge()}</div>
              </div>

              <div style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap', alignItems: 'center' }}>
                <button
                  onClick={runDetect}
                  disabled={detecting}
                  style={{
                    padding: '8px 10px',
                    borderRadius: 10,
                    border: '1px solid #ddd',
                    background: detecting ? '#f3f4f6' : 'white',
                    cursor: detecting ? 'not-allowed' : 'pointer'
                  }}
                >
                  {detecting ? 'Detecting…' : 'Run detection'}
                </button>

                <label style={{ display: 'inline-flex', gap: 8, alignItems: 'center', color: '#333' }}>
                  <input type="checkbox" checked={useLlm} onChange={(e) => setUseLlm(e.target.checked)} />
                  Use LLM (optional)
                </label>

                <button
                  onClick={runRewrite}
                  disabled={rewriting}
                  style={{
                    padding: '8px 10px',
                    borderRadius: 10,
                    border: '1px solid #ddd',
                    background: rewriting ? '#f3f4f6' : 'white',
                    cursor: rewriting ? 'not-allowed' : 'pointer'
                  }}
                >
                  {rewriting ? 'Rewriting…' : 'Generate safe rewrite'}
                </button>

                <div style={{ flex: 1 }} />

                <div style={{ fontSize: 12, color: '#666' }}>
                  Email ID: <code>{detail.id}</code>
                </div>
              </div>

              {detection ? (
                <div
                  style={{
                    marginTop: 12,
                    padding: 10,
                    borderRadius: 12,
                    border: '1px solid #e5e7eb',
                    background: '#f9fafb'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <strong>Detection</strong>
                    <span style={{ color: '#444' }}>{detection.label}</span>
                  </div>
                  <ul style={{ marginTop: 8, marginBottom: 0, color: '#333' }}>
                    {detection.reasons?.length ? (
                      detection.reasons.map((r, idx) => <li key={idx}>{r}</li>)
                    ) : (
                      <li>No reasons returned.</li>
                    )}
                  </ul>
                </div>
              ) : null}

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12 }}>
                <div style={{ border: '1px solid #e5e7eb', borderRadius: 12, overflow: 'hidden' }}>
                  <div style={{ padding: 10, borderBottom: '1px solid #e5e7eb', background: '#fff' }}>
                    <strong>Original (text-only, safe)</strong>
                  </div>
                  <pre
                    style={{
                      margin: 0,
                      padding: 10,
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                      maxHeight: 340,
                      overflow: 'auto',
                      background: '#fff'
                    }}
                  >
                    {detail.body?.text || ''}
                  </pre>

                  {detail.links?.defanged?.length ? (
                    <div style={{ padding: 10, borderTop: '1px solid #e5e7eb', background: '#fff' }}>
                      <div style={{ fontWeight: 700, marginBottom: 6 }}>Defanged links</div>
                      <ul style={{ margin: 0, paddingLeft: 18, color: '#333' }}>
                        {detail.links.defanged.map((u: string, idx: number) => (
                          <li key={idx}>
                            <code>{u}</code>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </div>

                <div style={{ border: '1px solid #e5e7eb', borderRadius: 12, overflow: 'hidden' }}>
                  <div style={{ padding: 10, borderBottom: '1px solid #e5e7eb', background: '#fff' }}>
                    <strong>Safe rewrite</strong>{' '}
                    <span style={{ color: '#666', fontSize: 12 }}>
                      {rewrite ? `(used_llm: ${rewrite.used_llm ? 'yes' : 'no'})` : ''}
                    </span>
                  </div>
                  <pre
                    style={{
                      margin: 0,
                      padding: 10,
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                      maxHeight: 520,
                      overflow: 'auto',
                      background: '#fff'
                    }}
                  >
                    {rewrite?.safe_body || 'Click “Generate safe rewrite”'}
                  </pre>
                </div>
              </div>

              <div style={{ marginTop: 14, paddingTop: 10, borderTop: '1px solid #e5e7eb', color: '#666' }}>
                <strong>Open Safely</strong> (screenshots + IOCs) is next — we’ll wire the runner + artifacts API after the
                viewer is stable.
              </div>
            </>
          )}
        </section>
      </div>
    </main>
  );
}
