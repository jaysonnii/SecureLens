// Builds the timeline's placed-event list from joined finding items.
//
// Evidence timestamps are opportunistic (see analyzer.py's
// _parse_leading_timestamp): most evidence lines won't have one, and a
// timeline that silently plotted only the parseable subset would imply
// completeness it doesn't have. So this always reports how many of the
// total events could be placed, and the caller renders nothing at all
// once there are fewer than two placed points - one point can't show a
// window, and a lone tick reads as false precision.
export function buildTimeline(items) {
  const all = [];

  for (const item of items) {
    for (const entry of item.evidence ?? []) {
      all.push({
        findingId: item.id,
        severity: item.severity,
        lineNumber: entry.line_number,
        timestamp: entry.timestamp ?? null,
      });
    }
  }

  const totalCount = all.length;
  const placed = all.filter((event) => event.timestamp);
  const placedCount = placed.length;

  if (placedCount < 2) {
    return {
      events: [],
      placedCount,
      totalCount,
      hasAssumedTimezone: false,
      windowStart: null,
      windowEnd: null,
    };
  }

  const times = placed.map((event) => Date.parse(event.timestamp.utc));
  const windowStart = Math.min(...times);
  const windowEnd = Math.max(...times);
  const span = windowEnd - windowStart || 1;

  const events = placed.map((event, i) => ({
    ...event,
    percent: ((times[i] - windowStart) / span) * 100,
  }));

  const hasAssumedTimezone = placed.some(
    (event) => event.timestamp.timezone_assumed
  );

  return {
    events,
    placedCount,
    totalCount,
    hasAssumedTimezone,
    windowStart,
    windowEnd,
  };
}
