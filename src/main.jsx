import React, { lazy, Suspense, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import AgentConsole from './AgentConsole.jsx';
import SkillInstall from './SkillInstall.jsx';
import DeviceApproval from './DeviceApproval.jsx';
import CompanyCallMetrics from './CompanyCallMetrics.jsx';
import CommandPalette from './CommandPalette.jsx';
import { navigateSearchResult } from './command-search.js';
import { resolveProductRoute } from './product-routing.js';
import './style.css';
import './offense-theme.css';
import './product-design.css';

const LegacyWorkspace = lazy(() => import('./LegacyWorkspace.jsx'));
function Product() {
  const currentRoute = () => resolveProductRoute(location.pathname, location.hash, location.search);
  const [route, setRoute] = useState(currentRoute);
  const [isOperator, setIsOperator] = useState(false);
  useEffect(() => {
    const sync = () => setRoute(currentRoute());
    window.addEventListener('popstate', sync);
    window.addEventListener('hashchange', sync);
    return () => { window.removeEventListener('popstate', sync); window.removeEventListener('hashchange', sync); };
  }, []);
  function navigate(href) {
    if (!navigateSearchResult(href, { isOperator }) || new URL(href, location.origin).searchParams.has('tool')) return;
    requestAnimationFrame(() => {
      const heading = document.querySelector('main h1');
      if (!heading?.getClientRects().length) return;
      heading.tabIndex = -1;
      heading.focus({ preventScroll: true });
    });
  }
  let page;
  if (route.surface === 'device') page = <DeviceApproval/>;
  else if (route.surface === 'metrics') page = <CompanyCallMetrics onOperatorAccess={setIsOperator}/>;
  else if (route.surface === 'skill') page = <SkillInstall/>;
  else if (route.surface === 'legacy') page = <Suspense fallback={<div className="loading" role="status">Opening V1 workspace…</div>}><LegacyWorkspace onOperatorAccess={setIsOperator}/></Suspense>;
  else page = <AgentConsole initialSection={route.section} onOperatorAccess={setIsOperator}/>;
  return <>{page}<CommandPalette isOperator={isOperator} disabled={route.surface === 'device'} onNavigate={navigate}/></>;
}
createRoot(document.getElementById('root')).render(<Product/>);
