import { ReactNode, useEffect, useRef } from "react";

// SidePane is a right-anchored detail panel, in the Datadog style: it slides
// over the right portion of the view while the list on the left stays visible
// and interactive, so you can click or key through rows and the pane follows.
// Escape closes it. There is no blocking backdrop, on purpose — the list keeps
// working underneath.
export function SidePane({
  open,
  onClose,
  title,
  children,
  actions,
  onPrev,
  onNext,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
  // Prev/next move through the underlying list without closing the pane.
  // undefined hides the control; null renders it disabled (at either end).
  onPrev?: (() => void) | null;
  onNext?: (() => void) | null;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      ref={ref}
      role="dialog"
      aria-modal="false"
      aria-label="Details"
      className="fixed right-0 top-0 z-40 flex h-full w-full max-w-2xl flex-col border-l border-gray-200 bg-white shadow-float motion-safe:animate-[slideInRight_180ms_ease-out] dark:border-gray-800 dark:bg-gray-900"
    >
      <div className="flex items-center gap-2 border-b border-gray-200 px-4 py-2.5 dark:border-gray-800">
        <div className="min-w-0 flex-1">{title}</div>
        {onPrev !== undefined && onNext !== undefined && (
          <div className="flex shrink-0 items-center">
            <button
              onClick={onPrev ?? undefined}
              disabled={!onPrev}
              aria-label="Previous item"
              title="Previous"
              className="rounded-md p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-700 disabled:opacity-30 disabled:hover:bg-transparent dark:hover:bg-gray-800 dark:hover:text-gray-200"
            >
              <svg width="16" height="16" viewBox="0 0 20 20" fill="none" aria-hidden="true">
                <path d="M12 5l-5 5 5 5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>
            <button
              onClick={onNext ?? undefined}
              disabled={!onNext}
              aria-label="Next item"
              title="Next"
              className="rounded-md p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-700 disabled:opacity-30 disabled:hover:bg-transparent dark:hover:bg-gray-800 dark:hover:text-gray-200"
            >
              <svg width="16" height="16" viewBox="0 0 20 20" fill="none" aria-hidden="true">
                <path d="M8 5l5 5-5 5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>
          </div>
        )}
        {actions}
        <button
          onClick={onClose}
          aria-label="Close panel"
          title="Close (Esc)"
          className="shrink-0 rounded-md p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-700 dark:hover:bg-gray-800 dark:hover:text-gray-200"
        >
          <svg width="16" height="16" viewBox="0 0 20 20" fill="none" aria-hidden="true">
            <path d="M6 6l8 8M14 6l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
          </svg>
        </button>
      </div>
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">{children}</div>
    </div>
  );
}
