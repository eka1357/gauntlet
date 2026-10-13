import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Verification Report",
  description: "Formal verification report with methodology, attack surface breakdown, and cryptographic hashes.",
};

export default function ReportLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
