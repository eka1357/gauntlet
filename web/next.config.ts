import type { NextConfig } from "next";

const isStatic = process.env.NEXT_PUBLIC_STATIC_DATA === "true";

const nextConfig: NextConfig = {
  devIndicators: false,
  ...(isStatic
    ? {
        output: "export",
        trailingSlash: true,
        images: {
          unoptimized: true,
        },
      }
    : {}),
};

export default nextConfig;
