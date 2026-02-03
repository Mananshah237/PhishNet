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
      <body style={{ fontFamily: 'system-ui, sans-serif', margin: 24 }}>
        {children}
      </body>
    </html>
  );
}
