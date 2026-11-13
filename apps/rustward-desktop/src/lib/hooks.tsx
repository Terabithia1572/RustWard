import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { Api, toApiError, type ApiError } from "../api/client";
import type { AuthStatusView } from "../api/types";

const ApiContext = createContext<Api | null>(null);
const AuthContext = createContext<AuthStatusView | null>(null);

export function AuthProvider({ auth, children }: { auth: AuthStatusView | null; children: ReactNode }) {
  return <AuthContext.Provider value={auth}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthStatusView | null {
  return useContext(AuthContext);
}

export function ApiProvider({ api, children }: { api: Api; children: ReactNode }) {
  return <ApiContext.Provider value={api}>{children}</ApiContext.Provider>;
}

export function useApi(): Api {
  const api = useContext(ApiContext);
  if (!api) throw new Error("useApi outside ApiProvider");
  return api;
}

export interface Resource<T> {
  data: T | undefined;
  error: ApiError | undefined;
  loading: boolean;
  reload: () => void;
}

/** Load data from the backend; reloads when `key` changes. */
export function useResource<T>(load: (api: Api) => Promise<T>, key: string): Resource<T> {
  const api = useApi();
  const [state, setState] = useState<{ data?: T; error?: ApiError; loading: boolean }>({ loading: true });
  const [tick, setTick] = useState(0);
  const loader = useRef(load);
  loader.current = load;
  useEffect(() => {
    let alive = true;
    setState((s) => ({ ...s, loading: true }));
    loader
      .current(api)
      .then((data) => alive && setState({ data, loading: false }))
      .catch((e: unknown) => alive && setState({ error: toApiError(e), loading: false }));
    return () => {
      alive = false;
    };
  }, [api, key, tick]);
  const reload = useCallback(() => setTick((n) => n + 1), []);
  return { data: state.data, error: state.error, loading: state.loading, reload };
}

/** Run a mutation with busy/error state. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (e) {
      setError(toApiError(e));
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, setError, run };
}
