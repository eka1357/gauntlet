import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Live Evaluation",
  description: "Interactive evaluation of target agent against prompt-injection attacks with strict cost caps.",
};

export default function LiveLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
