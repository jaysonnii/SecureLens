// Joins analysis.score_breakdown (points + reason) to analysis.findings
// (severity, evidence, recommendation, ...) by finding_type <-> type.
// Nothing in the API enforces that pairing beyond both lists being built
// together server-side, so this treats it as data to verify, not a
// convention to trust: a breakdown entry with no matching finding is
// reported back in `orphaned` instead of silently dropped.
export function joinFindings(findings, scoreBreakdown) {
  const findingByType = new Map(
    (findings ?? []).map((finding) => [finding.type, finding])
  );

  const items = [];
  const orphaned = [];

  for (const entry of scoreBreakdown ?? []) {
    const finding = findingByType.get(entry.finding_type);

    if (!finding) {
      orphaned.push(entry);
      continue;
    }

    items.push({
      id: entry.finding_type,
      points: entry.points,
      reason: entry.reason,
      type: finding.type,
      severity: finding.severity,
      mitreAttack: finding.mitre_attack ?? null,
      count: finding.count,
      evidence: finding.evidence ?? [],
      recommendation: finding.recommendation,
    });
  }

  return { items, orphaned };
}
