import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Workspace & The Range",
  description: "235 attack replay grid across unhardened and hardened policy conditions.",
};

export default function WorkspaceLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
