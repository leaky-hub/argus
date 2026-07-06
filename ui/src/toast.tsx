import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";

// Toast notifications + a promise-based confirm dialog, replacing the native
// window.alert / window.confirm. Drafted by the local qwen bridge; reviewed and
// corrected here (dark mode uses the app's class-based `dark:` convention, not
// an OS media query; deduplicated the ToastItem name).

export interface ToastOptions {
  kind: "success" | "error" | "info";
  message: string;
  ttlMs?: number;
}

interface ToastRecord extends ToastOptions {
  id: number;
}

interface ConfirmOptions {
  title: string;
  message?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
}

const ToastContext = createContext<{ toast: (opts: ToastOptions) => void } | null>(null);
const ConfirmContext = createContext<{ confirm: (opts: ConfirmOptions) => Promise<boolean> } | null>(null);

let toastIdCounter = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastRecord[]>([]);

  const addToast = useCallback((opts: ToastOptions) => {
    const id = ++toastIdCounter;
    setToasts((prev) => [...prev, { ...opts, id }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), opts.ttlMs ?? 4000);
  }, []);

  const removeToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toast: addToast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
        {toasts.map((t) => (
          <Toast key={t.id} item={t} onDismiss={removeToast} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

const TOAST_COLORS: Record<ToastOptions["kind"], string> = {
  success: "bg-emerald-50 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200",
  error: "bg-red-50 text-red-800 dark:bg-red-900/40 dark:text-red-200",
  info: "bg-blue-50 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200",
};

function Toast({ item, onDismiss }: { item: ToastRecord; onDismiss: (id: number) => void }) {
  return (
    <div
      role="status"
      className={`flex max-w-sm items-center justify-between gap-3 rounded-lg px-4 py-2 text-sm shadow-lg ring-1 ring-black/5 ${TOAST_COLORS[item.kind]}`}
    >
      <span className="break-words">{item.message}</span>
      <button
        onClick={() => onDismiss(item.id)}
        aria-label="Dismiss"
        className="font-bold text-current opacity-60 hover:opacity-100"
      >
        ×
      </button>
    </div>
  );
}

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [dialog, setDialog] = useState<{ opts: ConfirmOptions; resolve: (v: boolean) => void } | null>(null);

  const confirm = useCallback(
    (opts: ConfirmOptions): Promise<boolean> => new Promise((resolve) => setDialog({ opts, resolve })),
    [],
  );

  const close = useCallback(
    (result: boolean) => {
      setDialog((d) => {
        d?.resolve(result);
        return null;
      });
    },
    [],
  );

  useEffect(() => {
    if (!dialog) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") close(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [dialog, close]);

  return (
    <ConfirmContext.Provider value={{ confirm }}>
      {children}
      {dialog && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
          onClick={(e) => {
            if (e.target === e.currentTarget) close(false);
          }}
        >
          <div className="w-full max-w-md rounded-xl bg-white p-5 shadow-xl dark:bg-gray-900">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">{dialog.opts.title}</h3>
            {dialog.opts.message && (
              <p className="mt-2 mb-5 text-sm text-gray-600 dark:text-gray-300">{dialog.opts.message}</p>
            )}
            <div className="mt-5 flex justify-end gap-3">
              <button
                onClick={() => close(false)}
                className="rounded px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-800"
              >
                {dialog.opts.cancelLabel ?? "Cancel"}
              </button>
              <button
                ref={(el) => el?.focus()}
                onClick={() => close(true)}
                className={`rounded px-4 py-2 text-sm font-medium text-white ${
                  dialog.opts.danger ? "bg-red-600 hover:bg-red-700" : "bg-accent-600 hover:bg-accent-700"
                }`}
              >
                {dialog.opts.confirmLabel ?? "Confirm"}
              </button>
            </div>
          </div>
        </div>
      )}
    </ConfirmContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx.toast;
}

export function useConfirm() {
  const ctx = useContext(ConfirmContext);
  if (!ctx) throw new Error("useConfirm must be used within ConfirmProvider");
  return ctx.confirm;
}

export function AppProviders({ children }: { children: ReactNode }) {
  return (
    <ToastProvider>
      <ConfirmProvider>{children}</ConfirmProvider>
    </ToastProvider>
  );
}
