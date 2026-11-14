import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { get } from "../api";
import { ErrorBox, Loading, Section, Stat, fmtTime, human, useApi } from "../components/ui";

/* eslint-disable @typescript-eslint/no-explicit-any */
type AnyRecord = Record<string, any>;
const tooltipStyle = { background: "#0f172a", border: "1px solid #334155", borderRadius: 8, fontSize: 12 };

function Table({ rows, columns }: { rows: AnyRecord[]; columns: [string, string][] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead><tr>{columns.map(([, t]) => <th key={t} className="th">{t}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => (
          <tr key={i} className="border-t border-slate-800">
            {columns.map(([k]) => <td key={k} className="td">{typeof r[k] === "number" ? (Number.isInteger(r[k]) ? r[k] : r[k].toFixed(3)) : r[k] ?? "—"}</td>)}
          </tr>))}
        </tbody>
      </table>
    </div>
  );
}

export default function Models() {
  const model = useApi(() => get<AnyRecord>("/api/models"));
  const exp = useApi(() => get<AnyRecord>("/api/experiments"));

  if (model.error) return <ErrorBox error={model.error} />;
  if (!model.data) return <Loading />;
  const m = model.data;
  const v = m.validation;
  const importance = (m.global_importance ?? []).slice(0, 15).map((g: AnyRecord) => ({ ...g, name: g.description || g.feature }));

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold">Models & research</h1>
        <p className="text-sm text-slate-400">Model <span className="mono">{m.version}</span> trained {fmtTime(m.trained_at)} on {m.training.data}.</p>
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Training events" value={m.training.events.toLocaleString()} />
        <Stat label="Training windows" value={m.training.windows.toLocaleString()} />
        <Stat label="Attack scenarios" value={m.training.scenarios} />
        <Stat label="XGBoost macro-F1 (val)" value={v.xgboost.macro_f1} />
        <Stat label="XGBoost attack F1 (val)" value={v.xgboost.binary.f1} />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Section title="Hybrid detection architecture">
          <ul className="space-y-2 text-sm text-slate-300">
            <li><b>Isolation Forest</b>: unsupervised; trained on normal windows only; score = ECDF vs. held-out normal activity. Catches the unknown.</li>
            <li><b>XGBoost</b>: supervised 8-class classifier (gradient-boosted trees) for attack type; explained with SHAP.</li>
            <li><b>Random Forest</b>: baseline classifier for comparison.</li>
            <li><b>Hidden Markov Model</b>: {m.models.hmm.states.length} kill-chain states × {m.models.hmm.observations.length} observation symbols, decoded with Viterbi per incident.</li>
            <li><b>Rules</b>: logging/detection tampering and GuardDuty findings never depend on a model.</li>
          </ul>
        </Section>
        <Section title="Global feature importance (mean |SHAP|)">
          <div className="h-80">
            <ResponsiveContainer>
              <BarChart data={importance} layout="vertical" margin={{ left: 10 }}>
                <XAxis type="number" tick={{ fill: "#64748b", fontSize: 11 }} />
                <YAxis type="category" dataKey="name" width={250} tick={{ fill: "#cbd5e1", fontSize: 11 }} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "#1e293b" }} />
                <Bar dataKey="mean_abs_shap" fill="#38bdf8" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Section>
      </div>

      {exp.error ? (
        <Section title="Experiments"><p className="text-sm text-slate-500">No experiment report yet. Run <span className="mono">python -m app.cli experiments</span>.</p></Section>
      ) : exp.data && (
        <div className="space-y-4">
          <div className="rounded-lg border border-amber-400/30 bg-amber-400/10 p-3 text-sm text-amber-100">
            Experiment report from {fmtTime(exp.data.generated_at)}. All data is synthetic (CloudShield simulator). Models are evaluated on organisations never seen in training.
          </div>
          <Section title="E1 · Detection models (window level, held-out organisation)">
            <Table rows={exp.data.e1_model_comparison.models} columns={[["model", "Model"], ["precision", "Precision"], ["recall", "Recall"], ["f1", "F1"], ["roc_auc", "ROC-AUC"], ["pr_auc", "PR-AUC"], ["macro_f1", "Macro-F1"], ["latency_ms_per_1k", "ms / 1k windows"]]} />
          </Section>
          <div className="grid gap-4 xl:grid-cols-2">
            <Section title="Per-class F1">
              <Table rows={Object.entries(exp.data.e1_model_comparison.per_class_f1).map(([k, val]) => ({ class: human(k), ...(val as AnyRecord) }))}
                columns={[["class", "Class"], ["support", "Windows"], ["xgboost", "XGBoost"], ["random_forest", "Random Forest"]]} />
            </Section>
            <Section title="E3 · Explainability">
              <ul className="space-y-1 text-sm">
                <li>{exp.data.e3_explainability.ms_per_explanation} ms per SHAP explanation</li>
                <li>Removing top-{exp.data.e3_explainability.deletion_k} SHAP features drops class probability by <b>{exp.data.e3_explainability.mean_probability_drop_top_shap}</b> vs {exp.data.e3_explainability.mean_probability_drop_random} for random features ({exp.data.e3_explainability.faithfulness_ratio}× more faithful)</li>
                <li>Local top-5 ∩ global top-10 overlap: {exp.data.e3_explainability.local_global_top5_overlap}</li>
              </ul>
              <h3 className="mt-4 text-sm font-semibold">E4 · Forensics</h3>
              <ul className="space-y-1 text-sm">
                <li>Timeline completeness {exp.data.e4_forensics.mean_completeness} · entity recall {exp.data.e4_forensics.mean_entity_recall} · top-3 node hit {exp.data.e4_forensics.top3_node_hit_rate}</li>
                <li>HMM stage accuracy {exp.data.e4_forensics.stage_decoding.hmm_attack_stage_accuracy} vs static rules {exp.data.e4_forensics.stage_decoding.rule_attack_stage_accuracy}</li>
              </ul>
              <h3 className="mt-4 text-sm font-semibold">E5 · Risk</h3>
              <ul className="space-y-1 text-sm">
                <li>Risk ROC-AUC (attack vs benign incidents): <b>{exp.data.e5_risk_and_response.risk_auc_attack_vs_benign}</b></li>
                <li>Benign HIGH/CRITICAL incidents per day: {exp.data.e5_risk_and_response.benign_high_or_critical_per_day}</li>
              </ul>
            </Section>
          </div>
          <Section title="E2 · Correlation ablation">
            <Table rows={exp.data.e2_correlation.methods} columns={[["method", "Method"], ["incidents", "Incidents"], ["alert_reduction", "Alert reduction"], ["pairwise_precision", "Pair P"], ["pairwise_recall", "Pair R"], ["pairwise_f1", "Pair F1"], ["fragments_per_scenario", "Incidents / scenario"], ["false_alert_contamination", "Contamination"]]} />
          </Section>
          <Section title="Detection by scenario type (test) and under stealth (E6)">
            <div className="grid gap-4 xl:grid-cols-2">
              <Table rows={exp.data.per_kind} columns={[["kind", "Scenario"], ["scenarios", "n"], ["detected", "Detected"], ["high_or_critical", "HIGH+"], ["mean_completeness", "Completeness"]]} />
              <Table rows={exp.data.e6_robustness.per_kind} columns={[["kind", "Stealthy scenario"], ["scenarios", "n"], ["detected", "Detected"], ["high_or_critical", "HIGH+"], ["mean_completeness", "Completeness"]]} />
            </div>
          </Section>
        </div>
      )}
    </div>
  );
}
