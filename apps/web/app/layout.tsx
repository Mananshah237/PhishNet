export const metadata = {
  title: 'PhishNet',
  description: 'Safe phishing analysis + Open Safely preview'
};

export default function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          minHeight: '100vh',
          fontFamily:
            "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, 'Apple Color Emoji', 'Segoe UI Emoji', 'Noto Color Emoji'",
          background:
            'radial-gradient(900px 500px at 10% 10%, rgba(99,102,241,0.25), transparent 60%), radial-gradient(900px 500px at 90% 20%, rgba(236,72,153,0.22), transparent 60%), radial-gradient(900px 500px at 60% 90%, rgba(34,197,94,0.18), transparent 60%), #0b1020',
          color: '#e5e7eb'
        }}
      >
        <div style={{ padding: 20 }}>{children}</div>
      </body>
    </html>
  );
}
