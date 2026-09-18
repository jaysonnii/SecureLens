import { describe, expect, it } from "vitest";
import { buildTimeline } from "./timeline";

function item(id, severity, evidence) {
  return { id, severity, evidence };
}

describe("buildTimeline", () => {
  it("places every event when all evidence has a timestamp", () => {
    const items = [
      item("A", "High", [
        {
          line_number: 1,
          timestamp: {
            original: "2026-01-01T00:00:00Z",
            utc: "2026-01-01T00:00:00Z",
            timezone_assumed: false,
          },
        },
      ]),
      item("B", "Medium", [
        {
          line_number: 2,
          timestamp: {
            original: "2026-01-01T00:05:00Z",
            utc: "2026-01-01T00:05:00Z",
            timezone_assumed: false,
          },
        },
      ]),
    ];

    const timeline = buildTimeline(items);

    expect(timeline.placedCount).toBe(2);
    expect(timeline.totalCount).toBe(2);
    expect(timeline.events).toHaveLength(2);
    expect(timeline.hasAssumedTimezone).toBe(false);
    expect(timeline.events[0].percent).toBe(0);
    expect(timeline.events[1].percent).toBe(100);
  });

  it("reports a partial placement when some evidence has no timestamp", () => {
    const items = [
      item("A", "High", [
        {
          line_number: 1,
          timestamp: {
            original: "2026-01-01T00:00:00Z",
            utc: "2026-01-01T00:00:00Z",
            timezone_assumed: false,
          },
        },
        { line_number: 2, timestamp: null },
      ]),
      item("B", "Medium", [
        {
          line_number: 3,
          timestamp: {
            original: "2026-01-01T00:05:00Z",
            utc: "2026-01-01T00:05:00Z",
            timezone_assumed: false,
          },
        },
      ]),
    ];

    const timeline = buildTimeline(items);

    expect(timeline.totalCount).toBe(3);
    expect(timeline.placedCount).toBe(2);
    expect(timeline.events).toHaveLength(2);
  });

  it("refuses to render a timeline (fewer than two placed points) when every evidence timestamp is null", () => {
    const items = [
      item("A", "High", [
        { line_number: 1, timestamp: null },
        { line_number: 2, timestamp: null },
      ]),
    ];

    const timeline = buildTimeline(items);

    expect(timeline.totalCount).toBe(2);
    expect(timeline.placedCount).toBe(0);
    expect(timeline.events).toHaveLength(0);
  });

  it("refuses to render a timeline with exactly one placed point", () => {
    const items = [
      item("A", "High", [
        {
          line_number: 1,
          timestamp: {
            original: "2026-01-01T00:00:00Z",
            utc: "2026-01-01T00:00:00Z",
            timezone_assumed: false,
          },
        },
        { line_number: 2, timestamp: null },
      ]),
    ];

    const timeline = buildTimeline(items);

    expect(timeline.placedCount).toBe(1);
    expect(timeline.events).toHaveLength(0);
  });

  it("flags when any placed event had its timezone assumed", () => {
    const items = [
      item("A", "High", [
        {
          line_number: 1,
          timestamp: {
            original: "2026-01-01T00:00:00",
            utc: "2026-01-01T00:00:00Z",
            timezone_assumed: true,
          },
        },
      ]),
      item("B", "Medium", [
        {
          line_number: 2,
          timestamp: {
            original: "2026-01-01T00:05:00Z",
            utc: "2026-01-01T00:05:00Z",
            timezone_assumed: false,
          },
        },
      ]),
    ];

    const timeline = buildTimeline(items);

    expect(timeline.hasAssumedTimezone).toBe(true);
  });
});
