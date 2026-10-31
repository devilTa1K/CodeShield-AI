import { useEffect, useState } from "react";
import Home from "./pages/Home";
import Scan from "./pages/Scan";

type Tab = "review" | "scan";

function currentTab(): Tab {
  return window.location.hash === "#scan" ? "scan" : "review";
}

export default function App() {
  const [tab, setTab] = useState<Tab>(currentTab);

  useEffect(() => {
    const onHash = () => setTab(currentTab());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const link = (active: boolean) =>
    `border-b-2 px-3 py-2 text-sm font-medium transition ${
      active ? "border-accent-400 text-ink-100" : "border-transparent text-ink-400 hover:text-ink-100"
    }`;

  return (
    <>
      <nav aria-label="Modes" className="border-b border-ink-700/80 bg-ink-900/60">
        <div className="mx-auto flex max-w-7xl gap-1 px-4 sm:px-6">
          <a href="#review" className={link(tab === "review")} aria-current={tab === "review" ? "page" : undefined}>
            Code review
          </a>
          <a href="#scan" className={link(tab === "scan")} aria-current={tab === "scan" ? "page" : undefined}>
            Project scan
          </a>
        </div>
      </nav>
      {tab === "scan" ? <Scan /> : <Home />}
    </>
  );
}
