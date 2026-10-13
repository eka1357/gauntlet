import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Policy Specification",
  description: "Policy-as-code defense rules, syntax validation, and canary leakage inspection.",
};

export default function PolicyLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
