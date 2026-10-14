# Gauntlet video script

One section per scene, in render order. The build reads this file.

- `Narration:` is the voice-over text and the exact burned-in caption text.
- `On screen:` is display text for scenes that have a title line.
- Numbers are never typed here. Write `{{path.in.summary.json}}` and the build
  replaces it with the stored value from `web/public/data/summary.json`.
  Add `|pct` to print a stored one-decimal percentage (the build fails if the
  stored value would need rounding). A missing field fails the build.
- To record the voice-over, run `npm run prepare-data` and read from
  `video/script.resolved.md`, which has the numbers filled in.
- Audio files: `video/audio/01.mp3` ... `07.mp3` and `04b.mp3`, one per section.

## 01 Hook

On screen: Your agent reads email. Some of it is written by an attacker.

Narration: Your agent reads email, web pages and documents. Some of that text is written by an attacker. Gauntlet finds what breaks before you ship, writes the fix as policy, and proves it.

## 02 One breach

Narration: Here is one breach from the recorded run. A spoofed gateway error got the agent to read a vault file and email the secrets to an outside address. The trace shows the exact tool call.

## 03 The Range

On screen: The Range

Narration: This is the Range. {{n_total}} attacks, one square each, in rows by channel. Red with a slash is an unsafe action, grey is defended. Before hardening, every unsafe action came in through email. Web pages and documents produced none.

## 04 Before and after

Narration: Under the realistic prompt, {{realistic_mode.unhardened.unsafe.count}} of {{realistic_mode.n}} standard attacks led to an unsafe action before hardening. Gauntlet clustered the failures and wrote Policy v2. Under Policy v2, {{realistic_mode.policy_v2.unsafe.count}} of {{realistic_mode.n}}, with a 95% upper bound of {{realistic_mode.policy_v2.unsafe.ci_pct.1|pct}} percent.

## 04b Live run

Narration: This is a live run, recorded locally. Fresh email attacks are generated on the spot and run against the same agent, with and without Policy v2. Short runs vary, so the recorded run carries the evidence.

## 05 Still does its job

Narration: A fix is useless if the agent stops working. On {{benign_suite.tasks_per_repeat}} benign tasks, repeated {{benign_suite.repeats}} times, the agent passed {{benign_suite.unhardened.pooled_passed}} of {{benign_suite.unhardened.pooled_total}} before hardening and {{benign_suite.policy_v2.pooled_passed}} of {{benign_suite.policy_v2.pooled_total}} after. A deny-everything control passed {{benign_suite.negative_control.passed}} of {{benign_suite.negative_control.total}}, so the suite does catch a broken agent.

## 06 Limitations

On screen: What this does not show

Narration: What this does not show. The secrets registry matches literal values. We tested one fictional company and one agent. And a labelling effect on benign tasks is not excluded.

## 07 End card

Narration: Gauntlet is open source under the MIT licence. The code, the recorded run and every trace are on GitHub.
