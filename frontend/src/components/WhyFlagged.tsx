import type { Detection, FlagCriteria, Incident, RiskComponent } from "../api";
import { STAGE_COLOR, human, pct } from "./ui";

const COMPONENT_COLOR: Record<string, string> = {
  A: "#a78bfa", P: "#fb923c", C: "#38bdf8", S: "#f43f5e", T: "#facc15", D: "#34d399",
};
const LEVEL_TEXT: Record<string, string> = {
  CRITICAL: "text-rose-300", HIGH: "text-orange-300", MEDIUM: "text-amber-300", LOW: "text-sky-300", MINIMAL: "text-slate-300",
};
const KILL_CHAIN = Object.keys(STAGE_COLOR).filter((s) => s !== "NORMAL");

type Criteria = FlagCriteria;

/** One check a detection was put through: the measured value, the cut-off, and whether it tripped. */
interface Check { label: string; value: number; threshold: number; hit: boolean }

export function detectionChecks(d: Detection, c: Criteria): Check[] {
  if (d.kind === "rule") {
    return [{ label: d.rule === "GUARDDUTY_FINDING" ? "GuardDuty finding severity" : `Rule ${human((d.rule ?? "").replace(/^RULE_/, ""))} severity`,
      value: d.score, threshold: d.rule === "GUARDDUTY_FINDING" ? 0 : c.rule_severity_threshold, hit: true }];
  }
  return [
    { label: "XGBoost attack probability", value: d.attack_probability, threshold: c.attack_probability_threshold,
      hit: d.attack_probability >= c.attack_probability_threshold },
    { label: "Isolation Forest anomaly", value: d.anomaly_score, threshold: c.anomaly_threshold,
      hit: d.anomaly_score >= c.anomaly_threshold },
  ];
}

/** Short one-line reason for tables (e.g. "attack p 0.97 ≥ 0.50"). */
export function triggerSummary(d: Detection, c: Criteria | null): string {
  if (d.kind === "rule") return d.rule === "GUARDDUTY_FINDING" ? `GuardDuty severity ${d.score.toFixed(2)}` : `${human((d.rule ?? "").replace(/^RULE_/, ""))} rule`;
  const at = c?.attack_probability_threshold ?? 0.5;
  const an = c?.anomaly_threshold ?? 0.995;
  const parts = [];
  if (d.attack_probability >= at) parts.push(`attack p ${d.attack_probability.toFixed(2)} ≥ ${at}`);
  if (d.anomaly_score >= an) parts.push(`anomaly ${d.anomaly_score.toFixed(3)} ≥ ${an}`);
  return parts.join(" · ") || "below thresholds";
}

/** Percent that never rounds up to a claim of certainty (0.9996 → ">99.9%"). */
const share = (v: number) => (v >= 0.999 ? ">99.9%" : pct(v, 1));

function meaning(comp: RiskComponent, inc: Incident): string {
  const v = comp.value;
  switch (comp.name) {
    case "anomaly":
      return v > 0 ? `More unusual than ${share(v)} of the normal activity windows the model was calibrated on` : "Activity looks like normal behaviour";
    case "attack_probability":
      return inc.explanation.predicted_class
        ? `XGBoost puts the attack probability at ${share(v)}, most likely ${human(inc.explanation.predicted_class)}`
        : `Detection confidence ${share(v)}`;
    case "correlation": {
      const best = inc.links.reduce((m, l) => Math.max(m, l.score), 0);
      return inc.alert_count > 1
        ? `${inc.alert_count} detections linked across layers (strongest link ${best.toFixed(2)}, needs ≥ ${inc.flag_criteria.correlation_threshold})`
        : "Single detection: nothing else linked to it";
    }
    case "sequence_severity": {
      const reached = inc.sequence.map((s) => s.stage).filter((s) => KILL_CHAIN.includes(s))
        .sort((a, b) => KILL_CHAIN.indexOf(b) - KILL_CHAIN.indexOf(a))[0];
      return reached ? `HMM shows the attack got as far as ${human(reached)}` : "No attack stage decoded";
    }
    case "threat_intel":
      return v > 0 ? `GuardDuty raised a finding (severity ${pct(v)})` : "No GuardDuty finding involved";
    case "resource_sensitivity":
      return v >= 0.8 ? "Touched highly sensitive resources (e.g. IAM, customer data)" : v > 0 ? "Touched moderately sensitive resources" : "No sensitive resources involved";
    default:
      return comp.description;
  }
}

export default function WhyFlagged({ inc }: { inc: Incident }) {
  const c = inc.flag_criteria;
  const { risk } = inc;
  const levels = [...c.risk_levels].sort((a, b) => a.min - b.min);
  const floor = levels.filter((l) => risk.score >= l.min).pop();
  const next = levels.find((l) => l.min > risk.score);
  const ranked = [...risk.components].sort((a, b) => b.contribution - a.contribution);
  const triggers = [...inc.detections].sort((a, b) => b.score - a.score).slice(0, 5);
  const fired = inc.detections.length;

  return (
    <div className="space-y-5">
      {/* Verdict */}
      <p className="text-sm leading-relaxed">
        Rated <b className={LEVEL_TEXT[risk.level]}>{risk.level}</b> with <b>{risk.score.toFixed(1)} / 100</b>
        {floor && <> ({(risk.score - floor.min).toFixed(1)} points above the {floor.level} cut-off of {floor.min}{next ? `, ${(next.min - risk.score).toFixed(1)} short of ${next.level}` : ""})</>}.
        {" "}{fired} detection{fired === 1 ? "" : "s"} tripped a threshold, and the score is driven mostly by{" "}
        {ranked.slice(0, 2).map((r) => human(r.name).toLowerCase()).join(" and ")}.
      </p>

      {/* 1. What tripped */}
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">1 · What tripped the alarm</h3>
        <div className="space-y-2">
          {triggers.map((d) => (
            <div key={d.detection_id} className="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
              <div className="mb-1.5 flex flex-wrap items-baseline justify-between gap-2 text-xs">
                <span><span className="mono text-slate-200">{d.entity}</span> <span className="text-slate-500">→</span> {human(d.predicted_class)}</span>
                <span className="text-slate-500">{d.kind === "model" ? "ML window" : "deterministic rule"}</span>
              </div>
              {detectionChecks(d, c).map((k) => (
                <div key={k.label} className={`flex items-center gap-2 text-xs ${k.hit ? "" : "opacity-50"}`}>
                  <span className={`w-4 text-center ${k.hit ? "text-rose-400" : "text-slate-500"}`}>{k.hit ? "✓" : "–"}</span>
                  <span className="w-52 shrink-0 text-slate-300">{k.label}</span>
                  <div className="relative h-1.5 flex-1 rounded bg-slate-800">
                    <div className="h-1.5 rounded" style={{ width: `${Math.min(1, k.value) * 100}%`, background: k.hit ? "#f43f5e" : "#475569" }} />
                    {k.threshold > 0 && <div className="absolute -top-1 h-3.5 w-px bg-slate-200" style={{ left: `${k.threshold * 100}%` }} title={`threshold ${k.threshold}`} />}
                  </div>
                  <span className="w-28 shrink-0 text-right tabular-nums text-slate-400">
                    {k.value.toFixed(k.threshold > 0.99 ? 3 : 2)} {k.threshold > 0 ? (k.hit ? "≥" : "<") + " " + k.threshold : ""}
                  </span>
                </div>
              ))}
            </div>
          ))}
          {fired > triggers.length && <p className="text-xs text-slate-500">…and {fired - triggers.length} more in the correlated detections table below.</p>}
        </div>
      </div>

      {/* 2. How the score adds up */}
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">2 · How the risk score adds up</h3>
        <div className="relative">
          <div className="flex h-6 overflow-hidden rounded bg-slate-800">
            {ranked.filter((r) => r.contribution > 0).map((r) => (
              <div key={r.symbol} className="flex items-center justify-center text-[10px] font-semibold text-slate-950"
                   style={{ width: `${r.contribution}%`, background: COMPONENT_COLOR[r.symbol] }} title={`${human(r.name)}: ${r.contribution.toFixed(1)} pts`}>
                {r.contribution >= 4 ? r.symbol : ""}
              </div>
            ))}
          </div>
          {levels.filter((l) => l.min > 0).map((l) => (
            <div key={l.level} className="absolute top-0 h-6 border-l border-dashed border-slate-300/60" style={{ left: `${l.min}%` }} />
          ))}
          <div className="relative mt-1 h-4 text-[10px] text-slate-500">
            {levels.map((l, i) => {
              const end = levels[i + 1]?.min ?? 100;
              return <span key={l.level} className="absolute text-center" style={{ left: `${l.min}%`, width: `${end - l.min}%` }}>{l.level}</span>;
            })}
          </div>
        </div>

        <table className="mt-2 w-full text-xs">
          <thead>
            <tr><th className="th">Factor</th><th className="th">Measured</th><th className="th">× weight</th><th className="th text-right">Points</th><th className="th">What it means here</th></tr>
          </thead>
          <tbody>
            {ranked.map((r) => (
              <tr key={r.symbol} className="border-t border-slate-800">
                <td className="td whitespace-nowrap">
                  <span className="mr-1.5 inline-block h-2.5 w-2.5 rounded-sm align-middle" style={{ background: COMPONENT_COLOR[r.symbol] }} />
                  <b>{r.symbol}</b> {human(r.name)}
                </td>
                <td className="td tabular-nums">{r.value.toFixed(2)}</td>
                <td className="td tabular-nums text-slate-400">× {r.weight.toFixed(2)}</td>
                <td className="td text-right tabular-nums font-semibold">{r.contribution.toFixed(1)}</td>
                <td className="td text-slate-300">{meaning(r, inc)}</td>
              </tr>
            ))}
            <tr className="border-t border-slate-700">
              <td className="td font-semibold" colSpan={3}>Total = 100 × Σ(value × weight)</td>
              <td className="td text-right tabular-nums font-semibold">{risk.score.toFixed(1)}</td>
              <td className={`td font-semibold ${LEVEL_TEXT[risk.level]}`}>{risk.level}</td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* 3. Evidence from the model */}
      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">3 · Behaviour that pushed the model (SHAP)</h3>
        {inc.explanation.reasons.length ? (
          <ul className="list-disc space-y-1 pl-4 text-sm">{inc.explanation.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
        ) : (
          <p className="text-sm text-slate-500">Raised by deterministic rules only, so there is no ML window to explain.</p>
        )}
        <p className="mt-2 text-xs text-slate-500">Full SHAP chart, LIME and counterfactuals are on the Explainability tab.</p>
      </div>
    </div>
  );
}
