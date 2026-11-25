# Tuning notes

Detections in this lab are written to be **honest about false positives** rather
than tuned into silence. In a real SOC every allowlist below would be a Splunk
lookup owned and version-controlled by the team, not an inline `NOT (...)` in a
search. They are inline here so the whole lab is one folder you can read
top-to-bottom, and calling that shortcut out is part of the point.

## The allowlist-as-lookup pattern

Where a rule has an inline exclusion (e.g. the LSASS rule's list of legitimate
readers, or the `known_admin_tooling` macro), production would replace it with:

```
| lookup allowed_lsass_readers SourceImage OUTPUT is_allowed
| where isnull(is_allowed)
```

backed by a CSV lookup the SOC maintains. The advantages you should be able to
articulate: changes are auditable, they don't require editing detection logic,
and the same allowlist can be shared across many rules.

## Per-rule baselining priority

| Rule | FP volume | How to tune |
|------|-----------|-------------|
| Office spawning shell | ~none | Allowlist benign business macros by document hash |
| Shadow copy deletion | ~none | Allowlist backup product by signed path |
| LSASS access | high w/ EDR | Allowlist EDR/AV binaries — mandatory if you add EDR |
| Encoded PowerShell | real | Baseline a week; tune by ParentImage, not content |
| Run key persistence | high | Only usable with a known-good Image+Details baseline |
| Scheduled task | moderate | Filter SYSTEM + logon-trigger + user-writable path |
| Failed logon burst | mundane | Set threshold from measured baseline, not the lab's 10 |
| Discovery burst | low | Tune out scripted inventory sources by ParentImage |

## Thresholds are lab values

`failures >= 10`, `distinct_tools >= 5`, `total_risk >= 120` are starting points,
not truths. The correct value comes from measuring your own environment's normal
and setting the threshold above it. "How did you choose that number?" is a
question an interviewer will ask, and "I measured the baseline and set it at the
95th percentile" is the answer that lands.
