import { NavLink, Route, Routes } from "react-router-dom";
import { useAnalyst } from "./components/ui";
import Overview from "./pages/Overview";
import Events from "./pages/Events";
import Detections from "./pages/Detections";
import Incidents from "./pages/Incidents";
import IncidentDetail from "./pages/IncidentDetail";
import Response from "./pages/Response";
import Models from "./pages/Models";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/events", label: "Live events" },
  { to: "/detections", label: "Detections" },
  { to: "/incidents", label: "Incidents" },
  { to: "/response", label: "Response" },
  { to: "/models", label: "Models & research" },
];

export default function App() {
  const [analyst, setAnalyst] = useAnalyst();
  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-20 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
        <div className="mx-auto flex max-w-[1500px] flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
          <div className="flex items-center gap-2">
            <svg viewBox="0 0 24 24" className="h-6 w-6 text-sky-400" fill="none" stroke="currentColor" strokeWidth={2}>
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <span className="text-lg font-semibold tracking-tight">CloudShield</span>
            <span className="hidden text-xs text-slate-500 md:inline">cross-layer cloud attack detection & forensics</span>
          </div>
          <nav className="flex flex-1 flex-wrap gap-1">
            {NAV.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                end={n.end}
                className={({ isActive }) =>
                  `rounded-md px-3 py-1.5 text-sm ${isActive ? "bg-slate-800 text-white" : "text-slate-400 hover:text-slate-200"}`
                }
              >
                {n.label}
              </NavLink>
            ))}
          </nav>
          <label className="flex items-center gap-2 text-xs text-slate-400">
            Analyst
            <input className="input w-32 py-1" value={analyst} onChange={(e) => setAnalyst(e.target.value)} />
          </label>
        </div>
      </header>
      <main className="mx-auto max-w-[1500px] px-4 py-6">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/events" element={<Events />} />
          <Route path="/detections" element={<Detections />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/response" element={<Response />} />
          <Route path="/models" element={<Models />} />
        </Routes>
      </main>
    </div>
  );
}
