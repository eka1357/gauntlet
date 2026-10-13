import Link from "next/link";

export default function NotFound() {
  return (
    <div className="max-w-xl mx-auto py-16 text-center space-y-6">
      <div className="font-mono text-xs uppercase tracking-wider text-[var(--ink-muted)]">
        404 error
      </div>
      <h1 className="font-display font-bold text-3xl sm:text-4xl text-[var(--ink)]">
        Page not found
      </h1>
      <p className="font-sans text-sm text-[var(--ink-muted)] leading-relaxed">
        The page you are looking for does not exist, has been removed, or is not available in this build.
      </p>
      <div className="pt-2">
        <Link
          href="/"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-[var(--radius-sm)] bg-[var(--ink)] text-[var(--panel)] font-sans text-xs font-semibold hover:opacity-90 focus-visible:outline-2 focus-visible:outline-[var(--ink)]"
        >
          ← Return to the Range
        </Link>
      </div>
    </div>
  );
}
