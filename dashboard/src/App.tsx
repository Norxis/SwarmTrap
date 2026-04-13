import React, { Suspense, Component, type ReactNode } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ToastProvider } from "./lib/toast";
import { AppLayout } from "./components/AppLayout";
import { PageLoading } from "./components/LoadingSkeleton";

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: 40, color: "#f85149", fontFamily: "monospace", background: "#0d1117", minHeight: "100vh" }}>
          <h1>Dashboard Crash</h1>
          <pre style={{ whiteSpace: "pre-wrap", color: "#e6edf3" }}>{this.state.error.message}</pre>
          <pre style={{ whiteSpace: "pre-wrap", color: "#8b949e", fontSize: 12 }}>{this.state.error.stack}</pre>
        </div>
      );
    }
    return this.props.children;
  }
}

/* ---- lazy pages (code-split) ---- */
const GodHome = React.lazy(() => import("./pages/GodHome"));
const IpDetail = React.lazy(() => import("./pages/IpDetail"));
const Verdicts = React.lazy(() => import("./pages/Verdicts"));
const Services = React.lazy(() => import("./pages/Services"));
const Training = React.lazy(() => import("./pages/Training"));
const AttackMap = React.lazy(() => import("./pages/AttackMap"));

/* ---- query client ---- */
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
});

export default function App() {
  return (
    <ErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <BrowserRouter basename="/dashboard">
          <Routes>
            <Route element={<AppLayout />}>
              <Route index element={<Suspense fallback={<PageLoading />}><GodHome /></Suspense>} />
              <Route path="ip/*" element={<Suspense fallback={<PageLoading />}><IpDetail /></Suspense>} />
              <Route path="verdicts" element={<Suspense fallback={<PageLoading />}><Verdicts /></Suspense>} />
              <Route path="services" element={<Suspense fallback={<PageLoading />}><Services /></Suspense>} />
              <Route path="training" element={<Suspense fallback={<PageLoading />}><Training /></Suspense>} />
              <Route path="map" element={<Suspense fallback={<PageLoading />}><AttackMap /></Suspense>} />
            </Route>
          </Routes>
        </BrowserRouter>
      </ToastProvider>
    </QueryClientProvider>
    </ErrorBoundary>
  );
}
