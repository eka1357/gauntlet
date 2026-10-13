import type { Metadata } from "next";
import { Bricolage_Grotesque, IBM_Plex_Sans, IBM_Plex_Mono } from "next/font/google";
import { AppShell } from "@/components/AppShell";
import "./globals.css";

const bricolageGrotesque = Bricolage_Grotesque({
  variable: "--font-bricolage",
  subsets: ["latin"],
  display: "swap",
});

const ibmPlexSans = IBM_Plex_Sans({
  variable: "--font-ibm-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  display: "swap",
});

const ibmPlexMono = IBM_Plex_Mono({
  variable: "--font-ibm-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  display: "swap",
});

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_APP_URL || "https://gauntlet.dev"),
  title: {
    default: "Gauntlet — AI Agent Hardening & Verification",
    template: "%s | Gauntlet",
  },
  description: "Test instrument for hardening AI agents against prompt injection and tool misuse.",
  openGraph: {
    title: "Gauntlet — AI Agent Hardening & Verification",
    description: "Test instrument for hardening AI agents against prompt injection and tool misuse.",
    images: [
      {
        url: "/og.png",
        width: 1200,
        height: 630,
        alt: "Gauntlet AI Agent Hardening and Verification",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Gauntlet — AI Agent Hardening & Verification",
    description: "Test instrument for hardening AI agents against prompt injection and tool misuse.",
    images: ["/og.png"],
  },
  icons: {
    icon: "/icon.svg",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${bricolageGrotesque.variable} ${ibmPlexSans.variable} ${ibmPlexMono.variable} h-full antialiased`}
    >
      <body className="min-h-full bg-[var(--range-paper)] text-[var(--ink)] font-sans">
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
