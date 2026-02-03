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

  const [openSafely, setOpenSafely] = useState<{
    open: boolean;
    loading: boolean;
    jobId?: string;
    desktopUrl?: string;
    mobileUrl?: string;
    iocsUrl?: string;
  }>({ open: false, loading: false });

  async function refreshHealth() {
    const res = await fetch(`${base}/health`, { cache: 'no-store' });
    setHealth(await res.json());
  }

  async function refreshEmails(selectFirst = false) {
    const res = await fetch(`${base}/emails`, { cache: 'no-store' });
    if (!res.ok) throw new Error(`Failed to load emails: ${res.status}`);
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

      // Demo-friendly: automatically analyze right after upload.
      setBusyMsg('Analyzing…');
      await refreshEmails(false);
      setSelectedId(id);
      await loadEmail(id);

      // Auto-run detection + rewrite so users don't wonder why nothing happened.
      await fetch(`${base}/emails/${id}/detect`, { method: 'POST' });
      const qs = new URLSearchParams({ use_llm: useLlm ? 'true' : 'false' });
      await fetch(`${base}/emails/${id}/rewrite?${qs.toString()}`, { method: 'POST' });
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

  async function runOpenSafely(linkIndex: number, allowTargetOrigin: boolean) {
    if (!selectedId) return;
    setError(null);
    setOpenSafely({ open: true, loading: true });
    try {
      const res = await fetch(`${base}/emails/${selectedId}/open-safely`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ link_index: linkIndex, allow_target_origin: allowTargetOrigin })
      });
      if (!res.ok) throw new Error(`Open Safely failed: ${res.status}`);
      const data = await res.json();

      // ADS path: API may return just job_id, or job_id + artifacts for convenience.
      let desktop = data?.artifacts?.desktop;
      let mobile = data?.artifacts?.mobile;
      let iocs = data?.artifacts?.iocs;

      if (!desktop || !mobile) {
        // Fetch artifact list from ADS endpoint.
        const aRes = await fetch(`${base}/open-safely/artifacts/${data.job_id}`, { cache: 'no-store' });
        if (aRes.ok) {
          const aData = await aRes.json();
          const list = (aData?.artifacts || []) as Array<{ name: string; url: string }>;
          const find = (n: string) => list.find((x) => x.name === n)?.url;
          desktop = find('desktop.png');
          mobile = find('mobile.png');
          iocs = find('iocs.json');
        }
      }

      setOpenSafely({
        open: true,
        loading: false,
        jobId: data.job_id,
        desktopUrl: desktop ? `${base}${desktop}` : undefined,
        mobileUrl: mobile ? `${base}${mobile}` : undefined,
        iocsUrl: iocs ? `${base}${iocs}` : undefined
      });
    } catch (e: any) {
      setError(String(e));
      setOpenSafely({ open: true, loading: false });
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
    <main style={{ maxWidth: 1280, margin: '0 auto' }}>
      <div
        style={{
          border: '1px solid rgba(255,255,255,0.12)',
          borderRadius: 18,
          padding: 16,
          background: 'linear-gradient(135deg, rgba(99,102,241,0.16), rgba(236,72,153,0.10))',
          boxShadow: '0 18px 60px rgba(0,0,0,0.35)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 12 }}>
          <div>
            <h1 style={{ margin: 0, fontSize: 34, letterSpacing: -0.5 }}>
              PhishNet 
              <span style={{ fontSize: 18, opacity: 0.9 }}>🛡️🎣</span>
            </h1>
            <div style={{ color: 'rgba(229,231,235,0.85)', marginTop: 6 }}>
              Upload a suspicious email → get a risk score + safe rewrite → (next) Open Safely screenshots.
            </div>
          </div>
          <div style={{ fontSize: 12, color: 'rgba(229,231,235,0.85)' }}>
            API: <code style={{ color: '#fff' }}>{base}</code> {health?.ok ? <Badge text="OK" bg="#16a34a" /> : null}
          </div>
        </div>
      </div>

      <section
        style={{
          marginTop: 16,
          padding: 14,
          border: '1px solid rgba(255,255,255,0.14)',
          borderRadius: 18,
          background: 'rgba(255,255,255,0.06)',
          backdropFilter: 'blur(10px)'
        }}
      >
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <label style={{ display: 'inline-flex', gap: 10, alignItems: 'center' }}>
            <strong style={{ fontSize: 14 }}>Upload .eml ✉️</strong>
            <input
              type="file"
              accept=".eml,message/rfc822"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) uploadEml(f);
              }}
            />
          </label>

          <label style={{ display: 'inline-flex', gap: 8, alignItems: 'center', color: 'rgba(229,231,235,0.9)' }}>
            <input type="checkbox" checked={useLlm} onChange={(e) => setUseLlm(e.target.checked)} />
            Use LLM rewrite (optional) ✨
          </label>

          <button
            onClick={() => {
              setError(null);
              refreshEmails(false).catch((e) => setError(String(e)));
            }}
            style={{
              padding: '9px 12px',
              borderRadius: 12,
              border: '1px solid rgba(255,255,255,0.18)',
              background: 'rgba(0,0,0,0.25)',
              color: '#fff',
              cursor: 'pointer'
            }}
          >
            Refresh list ↻
          </button>

          <div style={{ flex: 1 }} />

          {busyMsg ? <span style={{ color: 'rgba(229,231,235,0.9)' }}>{busyMsg}</span> : null}
          {error ? <span style={{ color: '#fca5a5' }}>{error}</span> : null}
        </div>
      </section>

      <div style={{ display: 'grid', gridTemplateColumns: '340px 1fr', gap: 16, marginTop: 16 }}>
        {/* Left: list */}
        <aside
          style={{
            border: '1px solid rgba(255,255,255,0.14)',
            borderRadius: 18,
            overflow: 'hidden',
            background: 'rgba(255,255,255,0.06)',
            backdropFilter: 'blur(10px)'
          }}
        >
          <div
            style={{
              padding: 12,
              borderBottom: '1px solid rgba(255,255,255,0.12)',
              background: 'rgba(0,0,0,0.18)',
              color: '#fff'
            }}
          >
            <strong>Emails</strong> <span style={{ color: 'rgba(229,231,235,0.75)' }}>({emails.length})</span>
          </div>
          <div style={{ maxHeight: 560, overflow: 'auto' }}>
            {emails.length === 0 ? (
              <div style={{ padding: 12, color: 'rgba(229,231,235,0.8)' }}>Upload an .eml to get started ✉️</div>
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
                    borderBottom: '1px solid rgba(255,255,255,0.08)',
                    background:
                      e.id === selectedId
                        ? 'linear-gradient(135deg, rgba(99,102,241,0.35), rgba(236,72,153,0.22))'
                        : 'transparent',
                    color: '#fff',
                    cursor: 'pointer'
                  }}
                >
                  <div style={{ fontWeight: 800, marginBottom: 4, fontSize: 13 }}>{e.subject || '(no subject)'}</div>
                  <div style={{ color: 'rgba(229,231,235,0.85)', fontSize: 12, marginBottom: 6 }}>
                    {e.from_addr || '(unknown sender)'}
                  </div>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      gap: 8,
                      fontSize: 11,
                      color: 'rgba(229,231,235,0.7)'
                    }}
                  >
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
            border: '1px solid rgba(255,255,255,0.14)',
            borderRadius: 18,
            padding: 14,
            background: 'rgba(255,255,255,0.06)',
            backdropFilter: 'blur(10px)'
          }}
        >
          {!detail ? (
            <div style={{ color: '#666' }}>Select an email to view.</div>
          ) : (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
                <div>
                  <div style={{ fontSize: 20, fontWeight: 900, color: '#fff' }}>
                    {detail.headers?.subject || '(no subject)'}
                  </div>
                  <div style={{ color: 'rgba(229,231,235,0.85)', marginTop: 6 }}>From: {detail.headers?.from || '(unknown)'}</div>
                </div>
                <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>{riskBadge()}</div>
              </div>

              <div style={{ display: 'flex', gap: 8, marginTop: 12, flexWrap: 'wrap', alignItems: 'center' }}>
                <button
                  onClick={runDetect}
                  disabled={detecting}
                  style={{
                    padding: '9px 12px',
                    borderRadius: 12,
                    border: '1px solid rgba(255,255,255,0.18)',
                    background: detecting ? 'rgba(255,255,255,0.12)' : 'rgba(0,0,0,0.25)',
                    color: '#fff',
                    cursor: detecting ? 'not-allowed' : 'pointer'
                  }}
                >
                  {detecting ? 'Detecting…' : 'Run detection 🧠'}
                </button>

                <button
                  onClick={runRewrite}
                  disabled={rewriting}
                  style={{
                    padding: '9px 12px',
                    borderRadius: 12,
                    border: '1px solid rgba(255,255,255,0.18)',
                    background: rewriting
                      ? 'rgba(255,255,255,0.12)'
                      : 'linear-gradient(135deg, rgba(99,102,241,0.45), rgba(236,72,153,0.35))',
                    color: '#fff',
                    cursor: rewriting ? 'not-allowed' : 'pointer'
                  }}
                >
                  {rewriting ? 'Rewriting…' : 'Generate safe rewrite ✍️'}
                </button>

                <div style={{ flex: 1 }} />

                <div style={{ fontSize: 12, color: 'rgba(229,231,235,0.75)' }}>
                  Email ID: <code style={{ color: '#fff' }}>{detail.id}</code>
                </div>
              </div>

              {detection ? (
                <div
                  style={{
                    marginTop: 12,
                    padding: 12,
                    borderRadius: 16,
                    border: '1px solid rgba(255,255,255,0.14)',
                    background: 'rgba(0,0,0,0.22)'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <strong style={{ color: '#fff' }}>Detection 🕵️</strong>
                    <span style={{ color: 'rgba(229,231,235,0.9)' }}>{detection.label}</span>
                  </div>
                  <ul style={{ marginTop: 10, marginBottom: 0, color: 'rgba(243,244,246,0.95)' }}>
                    {detection.reasons?.length ? (
                      detection.reasons.map((r, idx) => <li key={idx}>{r}</li>)
                    ) : (
                      <li>No reasons returned.</li>
                    )}
                  </ul>
                </div>
              ) : null}

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12 }}>
                <div
                  style={{
                    border: '1px solid rgba(255,255,255,0.14)',
                    borderRadius: 16,
                    overflow: 'hidden',
                    background: 'rgba(0,0,0,0.20)'
                  }}
                >
                  <div style={{ padding: 10, borderBottom: '1px solid rgba(255,255,255,0.12)', color: '#fff' }}>
                    <strong>Original (text-only, safe) 🧾</strong>
                  </div>
                  <pre
                    style={{
                      margin: 0,
                      padding: 12,
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                      maxHeight: 340,
                      overflow: 'auto',
                      color: 'rgba(243,244,246,0.95)'
                    }}
                  >
                    {detail.body?.text || ''}
                  </pre>

                  {detail.links?.defanged?.length ? (
                    <div style={{ padding: 12, borderTop: '1px solid rgba(255,255,255,0.12)' }}>
                      <div style={{ fontWeight: 900, marginBottom: 10, color: '#fff' }}>Defanged links 🔗</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                        {detail.links.defanged.map((u: string, idx: number) => (
                          <div key={idx} style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                            <code style={{ color: '#e5e7eb' }}>{u}</code>
                            <button
                              onClick={() => runOpenSafely(idx, false)}
                              style={{
                                padding: '8px 10px',
                                borderRadius: 12,
                                border: '1px solid rgba(255,255,255,0.16)',
                                background: 'rgba(0,0,0,0.25)',
                                color: '#fff',
                                cursor: 'pointer'
                              }}
                            >
                              Open Safely 👀 (no network)
                            </button>
                            <button
                              onClick={() => runOpenSafely(idx, true)}
                              style={{
                                padding: '8px 10px',
                                borderRadius: 12,
                                border: '1px solid rgba(255,255,255,0.16)',
                                background: 'linear-gradient(135deg, rgba(99,102,241,0.45), rgba(236,72,153,0.35))',
                                color: '#fff',
                                cursor: 'pointer'
                              }}
                            >
                              Open Safely ✨ (allow target origin)
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>

                <div
                  style={{
                    border: '1px solid rgba(255,255,255,0.14)',
                    borderRadius: 16,
                    overflow: 'hidden',
                    background: 'rgba(0,0,0,0.20)'
                  }}
                >
                  <div style={{ padding: 10, borderBottom: '1px solid rgba(255,255,255,0.12)', color: '#fff' }}>
                    <strong>Safe rewrite 🧼</strong>{' '}
                    <span style={{ color: 'rgba(229,231,235,0.75)', fontSize: 12 }}>
                      {rewrite ? `(used_llm: ${rewrite.used_llm ? 'yes' : 'no'})` : ''}
                    </span>
                  </div>
                  <pre
                    style={{
                      margin: 0,
                      padding: 12,
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                      maxHeight: 520,
                      overflow: 'auto',
                      color: 'rgba(243,244,246,0.95)'
                    }}
                  >
                    {rewrite?.safe_body || 'Upload an email to auto-generate a safe rewrite.'}
                  </pre>
                </div>
              </div>

              {/* Open Safely modal */}
              {openSafely.open ? (
                <div
                  onClick={() => setOpenSafely({ open: false, loading: false })}
                  style={{
                    position: 'fixed',
                    inset: 0,
                    background: 'rgba(0,0,0,0.6)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    padding: 16,
                    zIndex: 50
                  }}
                >
                  <div
                    onClick={(e) => e.stopPropagation()}
                    style={{
                      width: 'min(1100px, 96vw)',
                      maxHeight: '90vh',
                      overflow: 'auto',
                      borderRadius: 18,
                      border: '1px solid rgba(255,255,255,0.14)',
                      background: 'rgba(15,23,42,0.92)',
                      padding: 14
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
                      <div style={{ color: '#fff', fontWeight: 900, fontSize: 16 }}>Open Safely Preview 👀</div>
                      <button
                        onClick={() => setOpenSafely({ open: false, loading: false })}
                        style={{
                          padding: '8px 10px',
                          borderRadius: 12,
                          border: '1px solid rgba(255,255,255,0.16)',
                          background: 'rgba(0,0,0,0.25)',
                          color: '#fff',
                          cursor: 'pointer'
                        }}
                      >
                        Close ✖
                      </button>
                    </div>

                    {openSafely.loading ? (
                      <div style={{ marginTop: 12, color: 'rgba(229,231,235,0.85)' }}>
                        Rendering in sandbox… (screenshots only)
                      </div>
                    ) : null}

                    {!openSafely.loading && openSafely.desktopUrl ? (
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12 }}>
                        <div>
                          <div style={{ color: 'rgba(229,231,235,0.85)', marginBottom: 8 }}>Desktop 📸</div>
                          <img src={openSafely.desktopUrl} alt="desktop" style={{ width: '100%', borderRadius: 12 }} />
                        </div>
                        <div>
                          <div style={{ color: 'rgba(229,231,235,0.85)', marginBottom: 8 }}>Mobile 📱</div>
                          <img src={openSafely.mobileUrl} alt="mobile" style={{ width: '100%', borderRadius: 12 }} />
                        </div>
                      </div>
                    ) : null}

                    {!openSafely.loading && openSafely.iocsUrl ? (
                      <div style={{ marginTop: 12 }}>
                        <div style={{ color: 'rgba(229,231,235,0.85)', marginBottom: 8 }}>IOCs 🧬</div>
                        <pre
                          style={{
                            margin: 0,
                            padding: 12,
                            borderRadius: 12,
                            border: '1px solid rgba(255,255,255,0.12)',
                            background: 'rgba(0,0,0,0.25)',
                            color: 'rgba(243,244,246,0.95)',
                            overflow: 'auto'
                          }}
                        >
                          (Open in new tab: {openSafely.iocsUrl})
                        </pre>
                      </div>
                    ) : null}
                  </div>
                </div>
              ) : null}
            </>
          )}
        </section>
      </div>
    </main>
  );
}
