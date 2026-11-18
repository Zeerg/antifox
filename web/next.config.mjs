/** @type {import('next').NextConfig} */

// Static export: `NEXT_EXPORT=1 next build` emits a pure static dir at web/out,
// droppable straight into an nginx web root. Dev (next dev) leaves it unset, keeping the /api proxy and HMR.
const isExport = process.env.NEXT_EXPORT === "1";
// Vercel demo: whole site runs on mocks — no backend, no /api proxy needed.
const isMock = process.env.NEXT_PUBLIC_MOCK === "1";

const nextConfig = {
  reactCompiler: true,
  // Allow dev assets (HMR) to be reached from LAN IPs; adjust as needed.
  // In dev, permit any IPv4 origin to reach /_next/* and HMR (unaffected by LAN IP churn).
  // Note: Next forbids a bare "*" for security — use segment wildcards; "*.*.*.*" matches any IPv4.
  allowedDevOrigins: ["*.*.*.*"],
  compiler: {
    removeConsole: process.env.NODE_ENV === "production",
  },
  ...(isExport
    ? {
        // Pure static export: no Node runtime; images unoptimized; every route emits <route>/index.html.
        output: "export",
        images: { unoptimized: true },
        trailingSlash: true,
      }
    : isMock
      ? {
          // Vercel mock demo: no backend — no /api proxy needed.
          images: { unoptimized: true },
        }
      : {
          // Dev: reverse-proxy /api/* to the Go backend (default :8787, override with AUTOPENTEST_API).
          async rewrites() {
            const backend = process.env.AUTOPENTEST_API ?? "http://localhost:8787";
            return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
          },
        }),
};

export default nextConfig;
