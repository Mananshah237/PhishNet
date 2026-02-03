export default async function Home() {
  let health: any = null;
  try {
    const base = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:8000';
    const res = await fetch(`${base}/health`, { cache: 'no-store' });
    health = await res.json();
  } catch (e) {
    health = { ok: false, error: String(e) };
  }

  return (
    <main>
      <h1>PhishNet</h1>
      <p>Local MVP scaffold.</p>
      <pre>{JSON.stringify(health, null, 2)}</pre>
    </main>
  );
}
