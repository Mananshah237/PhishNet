/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    const apiUrl = process.env.INTERNAL_API_URL || 'http://localhost:8000';
    return [
      {
        source: '/api-proxy/:path*',
        destination: `${apiUrl}/:path*`,
      },
    ];
  },
};

export default nextConfig;
