import type { NextConfig } from "next";

const apiBase =
  process.env.CAIAE_API_BASE_URL ??
  "http://localhost:4000";

const nextConfig: NextConfig = {
  async rewrites() {
    return [
      {
        source: "/engine-api/:path*",
        destination: `${apiBase}/:path*`,
      },
    ];
  },
};

export default nextConfig;
