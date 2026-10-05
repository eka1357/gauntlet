# PRODUCT.md — Gauntlet

## One line
Gauntlet attacks your AI agent until it breaks, fixes it, and proves the fix.

## The problem
Teams can build capable agents quickly, but agent projects stall at security review. Reviewers want evidence that an agent cannot be talked into leaking data or misusing tools. Today that evidence is a manual red-team exercise, or a scanner that lists problems and stops there.

## Who it is for
- AI engineers about to ship an agent that reads email, web pages or documents and can call tools.
- Security and platform reviewers who need reproducible evidence, not opinions.

## What it does (the loop)
1. **Recon.** Ultra reads the agent's tools and prompt and writes a threat plan. Tavily pulls current injection techniques, with citations.
2. **Attack.** A swarm of Nano workers generates and evolves attack payloads across channels (email, web page, document, tool arguments, image). Successful attacks are mutated for the next generation.
3. **Detect.** A deterministic oracle flags a breach: a canary secret leaves through a tool call, or a forbidden action executes. Each breach keeps a full trace.
4. **Triage.** Breaches are clustered by root cause with a minimal reproduction each.
5. **Fix.** Ultra writes a policy (egress allowlist, argument rules, approval gates, untrusted-content handling) and the fix is applied to the agent.
6. **Verify.** Old exploits, fresh held-out attacks and a benign task suite are re-run. The report shows breach rate before and after, and task success before and after.
7. **Ship.** Output is a hardening report, the policy file, and the exploit corpus as regression tests (and a pull request on the demo repo).

## Why it is different
- Closed loop: it fixes and re-tests, not just scans.
- Utility is measured. A fix that breaks the agent does not count.
- Breach detection is deterministic and reproducible.
- Model tiering is deliberate: cheap Nano swarm, Ultra for judgment, Omni for vision. Cost per run is shown live.

## Non-goals
Not a general vulnerability scanner, not a runtime firewall, not a compliance certificate. It tests agents the user owns, in a sandbox, with fake data.

## Demo script (under 3:00, no copyrighted music)
- 0:00-0:15 Problem line on screen: "Agents don't stall on capability. They stall on security review."
- 0:15-0:40 The demo Inbox Assistant summarises mail. One poisoned email arrives. The assistant sends a canary secret to an outside address. Show the audit log.
- 0:40-1:30 Launch Gauntlet. The Range fills: attacks fly, squares turn red as breaches are found, generation by generation. Cost meter and time visible.
- 1:30-1:50 Findings: clusters by root cause, open one trace.
- 1:50-2:30 Defender writes the policy. Verify runs. Before/after wipe: breach rate and task success, both real numbers.
- 2:30-2:50 Image attack: a hidden instruction in an invoice image is caught.
- 2:50-3:00 Repo, license, PR with regression tests. Close.

## Judging map
- Technological Implementation: tiered Nemotron routing, parallel Serverless Jobs, structured outputs, cost metering.
- Design: one coherent workspace, the Range visual, report page.
- Potential Impact: the security-review gate, measurable before/after.
- Quality of the Idea: adversarial self-play that patches and verifies, with a utility check.

## Safety statement (put in README)
Gauntlet only tests agents you own, in a sandbox with fake tools and data. Payloads are prompt-injection text. No real exploit code, no real credentials, no outbound network from the sandbox.
