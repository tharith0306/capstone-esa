import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { UNAUTHORIZED_EVENT, get, getToken, logout, type SessionUser } from "./api";
import { Loading, UserContext } from "./components/ui";
import Admin from "./pages/Admin";
import Cloud from "./pages/Cloud";
import Detections from "./pages/Detections";
import Events from "./pages/Events";
import IncidentDetail from "./pages/IncidentDetail";
import Incidents from "./pages/Incidents";
import Login from "./pages/Login";
import Models from "./pages/Models";
import Overview from "./pages/Overview";
import Response from "./pages/Response";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/events", label: "Live events" },
  { to: "/detections", label: "Detections" },
  { to: "/incidents", label: "Incidents" },
  { to: "/response", label: "Response" },
  { to: "/cloud", label: "Cloud" },
  { to: "/models", label: "Models & research" },
];

export default function App() {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [checking, setChecking] = useState(!!getToken());

  useEffect(() => {
    if (getToken()) {
      get<SessionUser>("/api/auth/me").then(setUser).catch(() => setUser(null)).finally(() => setChecking(false));
    }
    const onUnauthorized = () => setUser(null);
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  if (checking) return <Loading />;
  if (!user) return <Login onLogin={setUser} />;

  return (
    <UserContext.Provider value={user}>
      <div className="min-h-screen">
        <header className="sticky top-0 z-20 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
          <div className="mx-auto flex max-w-[1500px] flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
            <div className="flex items-center gap-2">
              <svg viewBox="0 0 24 24" className="h-6 w-6 text-sky-400" fill="none" stroke="currentColor" strokeWidth={2}>
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              <span className="text-lg font-semibold tracking-tight">CloudShield</span>
            </div>
            <nav className="flex flex-1 flex-wrap gap-1">
              {[...NAV, ...(user.role === "admin" ? [{ to: "/admin", label: "Users", end: false }] : [])].map((n) => (
                <NavLink key={n.to} to={n.to} end={n.end}
                  className={({ isActive }) => `rounded-md px-3 py-1.5 text-sm ${isActive ? "bg-slate-800 text-white" : "text-slate-400 hover:text-slate-200"}`}>
                  {n.label}
                </NavLink>
              ))}
            </nav>
            <div className="flex items-center gap-3 text-sm">
              <span className="text-slate-300">{user.username} <span className="text-xs text-slate-500">({user.role})</span></span>
              <button className="btn-ghost py-1 text-xs" onClick={() => logout().finally(() => setUser(null))}>Sign out</button>
            </div>
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
            <Route path="/cloud" element={<Cloud />} />
            <Route path="/models" element={<Models />} />
            <Route path="/admin" element={<Admin />} />
          </Routes>
        </main>
      </div>
    </UserContext.Provider>
  );
}
