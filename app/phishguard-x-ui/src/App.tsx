import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import MainLayout from './layouts/MainLayout';
import Dashboard from './pages/Dashboard';
import ThreatAnalysis from './pages/ThreatAnalysis';
import ThreatGraph from './pages/ThreatGraph';
import ModelInsights from './pages/ModelInsights';
import Investigations from './pages/Investigations';
import ThreatIntelligence from './pages/ThreatIntelligence';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<MainLayout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="analyze" element={<ThreatAnalysis />} />
          <Route path="graph" element={<ThreatGraph />} />
          <Route path="insights" element={<ModelInsights />} />
          <Route path="investigations" element={<Investigations />} />
          <Route path="intelligence" element={<ThreatIntelligence />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
