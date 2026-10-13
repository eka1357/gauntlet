import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Results & Evidence",
  description: "Empirical verification results, metrics breakdown, and cost accounting across hardening runs.",
};

export default function ResultsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
