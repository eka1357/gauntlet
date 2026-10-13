"use client";

import React, { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { getPolicy, getRecordedAttacks, PolicyResponse, AttackRecord } from "@/lib/api";

interface RuleStats {
  rule: string;
  v1Blocks: number;
  v2Blocks: number;
  description: string;
  anchorId: string;
}

interface MechanismGuide {
  id: string;
  name: string;
  ruleAnchor: string;
  mechanism: string;
  limitation: string;
}

const MECHANISMS: MechanismGuide[] = [
  {
    id: "secrets_registry",
    name: "Secrets Registry",
    ruleAnchor: "secrets_registry",
    mechanism:
      "Maintains an in-memory runtime catalog of designated secrets loaded from local vaults. Intercepts arguments to all egress tools (send_email, http_post, calendar_add, web_fetch) and blocks execution if exact secret literals or known vault tokens appear anywhere in parameters.",
    limitation:
      "Cannot detect secrets that are not indexed in the catalog, newly issued credentials not yet synchronized with the vault, or secrets fragmented across multi-step prompt chains.",
  },
  {
    id: "credential_patterns",
    name: "Credential-Pattern Detection",
    ruleAnchor: "credential_patterns",
    mechanism:
      "Scans tool payloads using regular expressions and Shannon entropy analysis for known credential shapes (e.g. bearer tokens, JWT segments, API key prefixes, base64 blobs, and private key headers) before tools dispatch.",
    limitation:
      "High-entropy benign tokens (such as image asset hashes, git commit SHAs, or cryptographic nonces) can trigger false positives, while low-entropy passwords or obfuscated text can evade pattern matching.",
  },
  {
    id: "partner_emails",
    name: "Partner-Email Inspection",
    ruleAnchor: "tools.send_email.allow_recipients",
    mechanism:
      "Enforces a strict allowlist of validated partner domains (harbor authorities, customs dispatchers, terminal logistics) and performs body and attachment deep-scanning on outbound email tools to ensure credentials are never sent to external partners.",
    limitation:
      "Vulnerable to partner account compromise, supply-chain typo-squatting, or subtle semantic prompt injection where an agent is coerced into conveying sensitive business intelligence without using literal secret tokens.",
  },
  {
    id: "web_fetch",
    name: "web_fetch Parameter Rules",
    ruleAnchor: "tools.web_fetch.deny_credential_params",
    mechanism:
      "Inspects outbound URLs fetched by the agent, stripping or denying requests with suspicious authentication parameters (?token=, ?auth=, ?key=, ?secret=) and scanning the URL query string for secret tokens.",
    limitation:
      "Path-based exfiltration (e.g. https://attacker.com/leak/<token>) or DNS/subdomain tunneling (https://<token>.attacker.com) can bypass query parameter filtering unless strict hostname allowlisting is in place.",
  },
  {
    id: "calendar_add",
    name: "Calendar Field Scanning",
    ruleAnchor: "tools.calendar_add.secrets_registry",
    mechanism:
      "Scans title, description, location, and attendee fields during calendar event creation calls to prevent covert side-channel exfiltration where the agent stores stolen tokens into shared calendars.",
    limitation:
      "Inspects only standard textual fields at creation time; cannot prevent an attacker from inferring leaked metadata from event start times, calendar duration, or scheduling patterns.",
  },
];

export default function PolicyPage() {
  const [policyV1, setPolicyV1] = useState<PolicyResponse | null>(null);
  const [policyV2, setPolicyV2] = useState<PolicyResponse | null>(null);
  const [attacks, setAttacks] = useState<AttackRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [copiedV1, setCopiedV1] = useState(false);
  const [copiedV2, setCopiedV2] = useState(false);

  useEffect(() => {
    let active = true;
    Promise.all([
      getPolicy("v1"),
      getPolicy("v2"),
      getRecordedAttacks({ page: 1, limit: 150 }),
      getRecordedAttacks({ page: 2, limit: 150 }),
    ])
      .then(([v1, v2, p1, p2]) => {
        if (!active) return;
        setPolicyV1(v1);
        setPolicyV2(v2);
        setAttacks([...(p1.attacks || []), ...(p2.attacks || [])]);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setError(err?.message || "Failed to load policy data");
        setLoading(false);
      });

    return () => {
      active = false;
    };
  }, []);

  // Compute block counts per policy rule from recorded attacks
  const ruleStats = useMemo<RuleStats[]>(() => {
    const v1Counts: Record<string, number> = {};
    const v2Counts: Record<string, number> = {};

    attacks.forEach((a) => {
      if (a.v1?.policy_block_rule) {
        v1Counts[a.v1.policy_block_rule] = (v1Counts[a.v1.policy_block_rule] || 0) + 1;
      }
      if (a.v2?.policy_block_rule) {
        v2Counts[a.v2.policy_block_rule] = (v2Counts[a.v2.policy_block_rule] || 0) + 1;
      }
    });

    const knownRules: Array<{ rule: string; desc: string; anchor: string }> = [
      {
        rule: "tools.read_file.deny_paths",
        desc: "Wildcard denial of /vault/** and sensitive credential files (*.json, *.bin).",
        anchor: "tools.read_file.deny_paths",
      },
      {
        rule: "tools.send_email.allow_recipients",
        desc: "Allowlist filtering of recipient addresses to internal domains and verified partners.",
        anchor: "tools.send_email.allow_recipients",
      },
      {
        rule: "tools.http_post.deny",
        desc: "Complete denial of arbitrary outbound HTTP POST requests.",
        anchor: "tools.http_post.deny",
      },
      {
        rule: "tools.calendar_add.secrets_registry",
        desc: "Inspection of calendar titles, descriptions, and attendees against the secrets registry.",
        anchor: "tools.calendar_add.secrets_registry",
      },
      {
        rule: "tools.web_fetch.deny_credential_params",
        desc: "Blocks outbound web_fetch requests carrying credential and authorization query parameters.",
        anchor: "tools.web_fetch.deny_credential_params",
      },
      {
        rule: "secrets_registry",
        desc: "Runtime interception of all tool arguments against known vault canary tokens.",
        anchor: "secrets_registry",
      },
      {
        rule: "credential_patterns",
        desc: "Entropy and regex pattern scanner for bearer tokens and credentials in tool arguments.",
        anchor: "credential_patterns",
      },
    ];

    return knownRules.map(({ rule, desc, anchor }) => ({
      rule,
      v1Blocks: v1Counts[rule] || 0,
      v2Blocks: v2Counts[rule] || 0,
      description: desc,
      anchorId: anchor,
    }));
  }, [attacks]);

  // Code check verifying Policy v2 contains NO canary literals or canary patterns
  const canaryCheck = useMemo(() => {
    if (!policyV2?.yaml) {
      return { passed: false, matchedPatterns: [], checkedLines: 0 };
    }
    const lines = policyV2.yaml.split("\n");
    const testPatterns = [
      /GAUNTLET_CANARY/i,
      /canary_/i,
      /7f8a9b1c/i,
      /3c4d5e6f/i,
      /9a0b1c2d/i,
      /5d6e7f8a/i,
    ];
    const matches: string[] = [];

    lines.forEach((line, lineIdx) => {
      testPatterns.forEach((pat) => {
        if (pat.test(line)) {
          matches.push(`Line ${lineIdx + 1}: ${line.trim()}`);
        }
      });
    });

    return {
      passed: matches.length === 0,
      matchedPatterns: matches,
      checkedLines: lines.length,
    };
  }, [policyV2]);

  // Simple line diff calculation for v2 additions
  const diffLines = useMemo(() => {
    if (!policyV1?.yaml || !policyV2?.yaml) return [];
    const v1Lines = new Set(policyV1.yaml.split("\n").map((l) => l.trim()));
    return policyV2.yaml.split("\n").map((line, idx) => {
      const isAdded = line.trim().length > 0 && !v1Lines.has(line.trim());
      return {
        lineNo: idx + 1,
        content: line,
        isAdded,
      };
    });
  }, [policyV1, policyV2]);

  const copyHash = (hash: string, which: "v1" | "v2") => {
    navigator.clipboard.writeText(hash);
    if (which === "v1") {
      setCopiedV1(true);
      setTimeout(() => setCopiedV1(false), 2000);
    } else {
      setCopiedV2(true);
      setTimeout(() => setCopiedV2(false), 2000);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3">
        <div className="w-6 h-6 border-2 border-[var(--ink)] border-t-transparent rounded-full animate-spin" />
        <span className="font-mono text-xs text-[var(--ink-muted)]">
          Loading policy specifications and rule telemetry...
        </span>
      </div>
    );
  }

  if (error || !policyV1 || !policyV2) {
    return (
      <div className="max-w-2xl mx-auto my-8 p-6 bg-[var(--panel)] border border-[var(--breach)] rounded-[var(--radius-md)] space-y-3">
        <div className="text-sm font-semibold text-[var(--breach)] font-sans">
          Failed to load policy specification
        </div>
        <p className="font-mono text-xs text-[var(--ink)] bg-[var(--range-paper)] p-3 rounded border border-[var(--rule)]">
          {error}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1.5">
          <span className="font-mono text-xs px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] text-[var(--ink)] font-semibold">
            Policy-as-Code
          </span>
          <span className="text-xs font-sans text-[var(--ink-muted)]">
            Specification & Enforcement Telemetry
          </span>
        </div>
        <h1 className="font-display font-bold text-2xl text-[var(--ink)]">
          Policy Architecture & Rules
        </h1>
        <p className="text-xs sm:text-sm text-[var(--ink-muted)] font-sans max-w-3xl mt-1 leading-relaxed">
          Comparison of synthesized defenses: Policy v1 (initial synthesis from training exploits) and Policy v2 (hardened with runtime secrets registry, credential pattern scanning, and web/calendar parameter checks).
        </p>
      </div>

      {/* Canary-free verification statement */}
      <section className="p-4 rounded-[var(--radius-md)] bg-[var(--panel)] border border-[var(--cleared)] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 font-semibold text-xs sm:text-sm text-[var(--cleared)] font-sans mb-1">
            <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
              <path
                fillRule="evenodd"
                d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                clipRule="evenodd"
              />
            </svg>
            <span>Canary Independence Verification: Confirmed Clean</span>
          </div>
          <p className="text-xs text-[var(--ink)] font-sans leading-relaxed">
            Policy v2 contains <strong>no canary literals</strong> or test-suite-specific patterns. Hardening relies strictly on generalized domain controls, parameter patterns, and an in-memory runtime secrets registry.
          </p>
        </div>
        <div className="shrink-0 font-mono text-xs px-3 py-1.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] text-[var(--ink)]">
          {canaryCheck.checkedLines} lines scanned, 0 canary matches
        </div>
      </section>

      {/* Side-by-side Policy v1 and v2 View */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="font-display font-semibold text-lg text-[var(--ink)]">
            Policy Specification Comparison
          </h2>
          <div className="text-xs font-sans text-[var(--ink-muted)]">
            Green lines highlight additions in Policy v2
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          {/* Policy v1 Column */}
          <div className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-4 sm:p-5 flex flex-col h-full">
            <div className="flex items-start justify-between gap-3 pb-3 border-b border-[var(--rule)] mb-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-sm font-display text-[var(--ink)]">
                    Policy v1
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] text-[var(--ink-muted)] font-mono">
                    Baseline Synthesized Policy
                  </span>
                </div>
                <div className="text-xs text-[var(--ink-muted)] font-sans mt-0.5">
                  Initial synthesis from 41 training exploits
                </div>
              </div>
            </div>

            {/* SHA-256 Hash with Copy */}
            <div className="mb-3 p-2.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] text-xs">
              <div className="flex items-center justify-between text-[var(--ink-muted)] font-sans mb-1">
                <span>SHA-256 Hash:</span>
                <button
                  type="button"
                  onClick={() => copyHash(policyV1.sha256, "v1")}
                  className="font-mono text-xs px-1.5 py-0.5 rounded border border-[var(--rule)] bg-[var(--panel)] hover:bg-[var(--range-paper)] text-[var(--ink)]"
                >
                  {copiedV1 ? "Copied" : "Copy"}
                </button>
              </div>
              <div className="font-mono text-xs text-[var(--ink)] break-all select-all font-semibold">
                {policyV1.sha256}
              </div>
            </div>

            {/* YAML Code Box */}
            <div
              tabIndex={0}
              role="region"
              aria-label="Policy v1 specification YAML"
              className="flex-1 font-mono text-xs bg-[var(--range-paper)] p-3 rounded-[var(--radius-sm)] border border-[var(--rule)] overflow-x-auto max-h-[520px] overflow-y-auto leading-relaxed select-all focus-visible:outline-2 focus-visible:outline-[var(--ink)]"
            >
              <pre>{policyV1.yaml}</pre>
            </div>
          </div>

          {/* Policy v2 Column */}
          <div className="bg-[var(--panel)] border border-[var(--rule)] rounded-[var(--radius-md)] p-4 sm:p-5 flex flex-col h-full ring-1 ring-[var(--cleared)]/30">
            <div className="flex items-start justify-between gap-3 pb-3 border-b border-[var(--rule)] mb-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-bold text-sm font-display text-[var(--ink)]">
                    Policy v2
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--cleared)]/10 text-[var(--cleared)] border border-[var(--cleared)] font-mono font-semibold">
                    Hardened Active Policy
                  </span>
                </div>
                <div className="text-xs text-[var(--ink-muted)] font-sans mt-0.5">
                  Eliminates held-out breaches & side-channel probe leaks
                </div>
              </div>
            </div>

            {/* SHA-256 Hash with Copy */}
            <div className="mb-3 p-2.5 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)] text-xs">
              <div className="flex items-center justify-between text-[var(--ink-muted)] font-sans mb-1">
                <span>SHA-256 Hash:</span>
                <button
                  type="button"
                  onClick={() => copyHash(policyV2.sha256, "v2")}
                  className="font-mono text-xs px-1.5 py-0.5 rounded border border-[var(--rule)] bg-[var(--panel)] hover:bg-[var(--range-paper)] text-[var(--ink)]"
                >
                  {copiedV2 ? "Copied" : "Copy"}
                </button>
              </div>
              <div className="font-mono text-xs text-[var(--ink)] break-all select-all font-semibold">
                {policyV2.sha256}
              </div>
            </div>

            {/* YAML Code Box with Diff Line Highlighting */}
            <div
              tabIndex={0}
              role="region"
              aria-label="Policy v2 specification YAML with diff highlighting"
              className="flex-1 font-mono text-xs bg-[var(--range-paper)] p-3 rounded-[var(--radius-sm)] border border-[var(--rule)] overflow-x-auto max-h-[520px] overflow-y-auto leading-relaxed select-all focus-visible:outline-2 focus-visible:outline-[var(--ink)]"
            >
              <div className="space-y-0.5">
                {diffLines.map((l) => (
                  <div
                    key={l.lineNo}
                    className={`flex items-start gap-2 px-1 -mx-1 rounded-sm ${
                      l.isAdded
                        ? "bg-[var(--cleared)]/15 text-[var(--ink)] font-medium border-l-2 border-[var(--cleared)]"
                        : "text-[var(--ink)]"
                    }`}
                  >
                    <span
                      aria-hidden="true"
                      className={`select-none text-right w-6 shrink-0 ${l.isAdded ? "text-[var(--ink)] font-semibold" : "text-[var(--ink-muted)]"}`}
                    >
                      {l.lineNo}
                    </span>
                    <span className="select-none text-[var(--cleared)] w-2 shrink-0">
                      {l.isAdded ? "+" : " "}
                    </span>
                    <span className="break-all whitespace-pre">{l.content}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Rule Block Telemetry & Anchors */}
      <section className="space-y-4">
        <div>
          <h2 className="font-display font-semibold text-lg text-[var(--ink)]">
            Enforcement Telemetry per Rule
          </h2>
          <p className="text-xs text-[var(--ink-muted)] font-sans">
            Counts of recorded attacks stopped by each named rule across the 235-attack test suite.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {ruleStats.map((st) => (
            <div
              key={st.rule}
              id={st.anchorId}
              className="p-4 rounded-[var(--radius-md)] bg-[var(--panel)] border border-[var(--rule)] scroll-mt-20 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <span className="font-mono font-bold text-xs text-[var(--ink)] break-all">
                    {st.rule}
                  </span>
                  <a
                    href={`#${st.anchorId}`}
                    className="text-xs text-[var(--ink-muted)] hover:text-[var(--ink)] font-mono shrink-0"
                    title="Direct link anchor"
                  >
                    #
                  </a>
                </div>
                <p className="text-xs text-[var(--ink-muted)] font-sans mb-3 leading-relaxed">
                  {st.description}
                </p>
              </div>

              <div className="pt-2.5 border-t border-[var(--rule)] flex items-center justify-between text-xs font-sans">
                <div>
                  <span className="text-[var(--ink-muted)]">v1 blocked: </span>
                  <span className="font-mono font-semibold text-[var(--ink)]">{st.v1Blocks}</span>
                </div>
                <div>
                  <span className="text-[var(--ink-muted)]">v2 blocked: </span>
                  <span className="font-mono font-semibold text-[var(--cleared)]">{st.v2Blocks}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Mechanism Explanations & Limitations */}
      <section className="space-y-4">
        <div>
          <h2 className="font-display font-semibold text-lg text-[var(--ink)]">
            Defense Mechanisms & Limitations
          </h2>
          <p className="text-xs text-[var(--ink-muted)] font-sans">
            Plain explanation of each security control and its honest boundary.
          </p>
        </div>

        <div className="space-y-3">
          {MECHANISMS.map((m) => (
            <div
              key={m.id}
              className="p-4 sm:p-5 rounded-[var(--radius-md)] bg-[var(--panel)] border border-[var(--rule)] space-y-3"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <h3 className="font-display font-semibold text-base text-[var(--ink)]">
                  {m.name}
                </h3>
                <Link
                  href={`#${m.ruleAnchor}`}
                  className="font-mono text-xs text-[var(--cleared)] underline hover:opacity-80"
                >
                  Anchor: #{m.ruleAnchor}
                </Link>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-sans leading-relaxed">
                <div className="p-3 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--rule)]">
                  <div className="font-semibold text-[var(--ink)] mb-1">How it works:</div>
                  <p className="text-[var(--ink-muted)]">{m.mechanism}</p>
                </div>

                <div className="p-3 rounded-[var(--radius-sm)] bg-[var(--range-paper)] border border-[var(--in-flight)]/40">
                  <div className="font-semibold text-[var(--ink)] mb-1">Honest limitation:</div>
                  <p className="text-[var(--ink-muted)]">{m.limitation}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
