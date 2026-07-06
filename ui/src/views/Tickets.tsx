import { useCallback, useEffect, useMemo, useState } from "react";
import { opsApi, TicketView, TicketDetail, TicketStatus, TicketPriority, Severity, ApiError } from "../api";
import { Panel, SeverityBadge, EmptyState } from "../components";
import { Loading } from "../components";
import { useToast, useConfirm } from "../toast";
import { fmtTime } from "../theme";

const STATUS_LABEL: Record<TicketStatus, string> = {
  open: "Open",
  "in-progress": "In progress",
  blocked: "Blocked",
  done: "Done",
};
// Workflow status: a neutral chip with a colored dot (severity stays the one
// saturated channel).
const STATUS_DOT: Record<TicketStatus, string> = {
  open: "#6b7386",
  "in-progress": "#2f74c0",
  blocked: "#c98a10",
  done: "#1f8a4c",
};
const PRIORITIES: TicketPriority[] = ["urgent", "high", "medium", "low"];
const STATUSES: TicketStatus[] = ["open", "in-progress", "blocked", "done"];

const selectClass =
  "rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-800";

function StatusChip({ status }: { status: TicketStatus }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded bg-gray-100 px-1.5 py-0.5 text-[11px] font-medium text-gray-600 dark:bg-gray-800 dark:text-gray-300">
      <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: STATUS_DOT[status] }} />
      {STATUS_LABEL[status]}
    </span>
  );
}

function PriorityTag({ priority }: { priority: TicketPriority }) {
  const strong = priority === "urgent" || priority === "high";
  return (
    <span className={`text-[11px] font-semibold uppercase tracking-wide ${strong ? "text-gray-700 dark:text-gray-200" : "text-gray-400"}`}>
      {priority}
    </span>
  );
}

export function Tickets({ canEdit, canDelete }: { canEdit: boolean; canDelete: boolean }) {
  const [tickets, setTickets] = useState<TicketView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<TicketDetail | null>(null);
  const [creating, setCreating] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const toast = useToast();
  const confirm = useConfirm();

  const load = useCallback(() => {
    opsApi
      .tickets(statusFilter === "all" ? undefined : { status: statusFilter })
      .then((r) => setTickets(r.tickets))
      .catch((e) => setError(e instanceof ApiError ? e.message : String(e)));
  }, [statusFilter]);

  useEffect(() => {
    load();
  }, [load, reloadKey]);

  // Keep a selection; default to the first ticket.
  const selected = useMemo(
    () => tickets?.find((t) => t.id === selectedId) ?? tickets?.[0] ?? null,
    [tickets, selectedId],
  );

  useEffect(() => {
    if (!selected) {
      setDetail(null);
      return;
    }
    let live = true;
    opsApi.ticket(selected.id).then((d) => live && setDetail(d)).catch(() => live && setDetail(null));
    return () => {
      live = false;
    };
  }, [selected, reloadKey]);

  const refresh = () => setReloadKey((k) => k + 1);

  const patch = async (patch: Parameters<typeof opsApi.updateTicket>[1]) => {
    if (!selected) return;
    try {
      await opsApi.updateTicket(selected.id, patch);
      toast({ kind: "success", message: "Ticket updated." });
      refresh();
    } catch (e) {
      toast({ kind: "error", message: e instanceof ApiError ? e.message : String(e) });
    }
  };

  const addComment = async (body: string) => {
    if (!selected || !body.trim()) return;
    try {
      await opsApi.ticketComment(selected.id, body);
      refresh();
    } catch (e) {
      toast({ kind: "error", message: e instanceof ApiError ? e.message : String(e) });
    }
  };

  const closeFixed = async () => {
    if (!selected) return;
    const ok = await confirm({
      title: "Close and mark findings fixed?",
      message: "This marks the ticket done and sets every linked finding's disposition to “fixed”, which clears them from the gate until a re-scan confirms.",
      confirmLabel: "Close as done",
    });
    if (!ok) return;
    try {
      const r = await opsApi.ticketCloseFixed(selected.id);
      toast({ kind: "success", message: `Closed. ${r.markedFixed} finding(s) marked fixed.` });
      refresh();
    } catch (e) {
      toast({ kind: "error", message: e instanceof ApiError ? e.message : String(e) });
    }
  };

  const remove = async () => {
    if (!selected) return;
    const ok = await confirm({
      title: "Delete this ticket?",
      message: "The ticket, its links, and its timeline are removed. Findings and their dispositions are untouched.",
      confirmLabel: "Delete",
      danger: true,
    });
    if (!ok) return;
    try {
      await opsApi.deleteTicket(selected.id);
      toast({ kind: "success", message: "Ticket deleted." });
      setSelectedId(null);
      refresh();
    } catch (e) {
      toast({ kind: "error", message: e instanceof ApiError ? e.message : String(e) });
    }
  };

  if (error) return <div className="m-4 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800 dark:border-red-900 dark:bg-red-950 dark:text-red-300">{error}</div>;
  if (tickets === null) return <Loading what="tickets" />;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
      <div className="lg:col-span-3">
        <Panel
          title={`Tickets (${tickets.length})`}
          right={
            <div className="flex items-center gap-2">
              <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className={selectClass}>
                <option value="all">all statuses</option>
                {STATUSES.map((s) => (
                  <option key={s} value={s}>{STATUS_LABEL[s]}</option>
                ))}
              </select>
              {canEdit && (
                <button onClick={() => setCreating(true)} className="rounded-md bg-accent-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-accent-700">
                  New ticket
                </button>
              )}
            </div>
          }
        >
          {creating && (
            <CreateForm
              onClose={() => setCreating(false)}
              onCreated={(id) => {
                setCreating(false);
                setSelectedId(id);
                refresh();
              }}
            />
          )}
          {tickets.length === 0 && !creating ? (
            <EmptyState title="No tickets yet" hint={canEdit ? "Create one here, or from a selection in the Findings view, to start tracking work." : "An operator can open a ticket to start tracking work on findings."} />
          ) : (
            <div className="divide-y divide-gray-100 dark:divide-gray-800">
              {tickets.map((t) => (
                <button
                  key={t.id}
                  onClick={() => setSelectedId(t.id)}
                  className={`flex w-full items-center gap-3 px-1 py-2 text-left ${selected?.id === t.id ? "bg-accent-100 dark:bg-accent-500/10" : "hover:bg-gray-50 dark:hover:bg-gray-800/50"}`}
                >
                  <span className="w-16 shrink-0"><PriorityTag priority={t.priority} /></span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{t.title}</span>
                    <span className="font-mono text-[11px] text-gray-400">{t.id} · {t.linkCount} finding{t.linkCount === 1 ? "" : "s"}</span>
                  </span>
                  {t.rollup.max && <SeverityBadge severity={t.rollup.max as Severity} />}
                  <StatusChip status={t.status} />
                </button>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <div className="min-w-0 lg:col-span-2">
        {selected && detail ? (
          <Detail
            key={detail.id}
            detail={detail}
            canEdit={canEdit}
            canDelete={canDelete}
            onPatch={patch}
            onComment={addComment}
            onCloseFixed={closeFixed}
            onDelete={remove}
          />
        ) : (
          <Panel title="Ticket">
            <p className="py-10 text-center text-sm text-gray-500">Select a ticket to see its findings and timeline.</p>
          </Panel>
        )}
      </div>
    </div>
  );
}

function CreateForm({ onClose, onCreated }: { onClose: () => void; onCreated: (id: string) => void }) {
  const [title, setTitle] = useState("");
  const [priority, setPriority] = useState<TicketPriority>("medium");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  const submit = async () => {
    if (!title.trim()) return;
    setBusy(true);
    try {
      const t = await opsApi.createTicket({ title, priority, description });
      onCreated(t.id);
    } catch (e) {
      toast({ kind: "error", message: e instanceof ApiError ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mb-3 rounded-lg border border-gray-200 bg-gray-50 p-3 dark:border-gray-800 dark:bg-gray-800/40">
      <input
        autoFocus
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && submit()}
        placeholder="Ticket title"
        className="w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-900"
      />
      <textarea
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        placeholder="Description (optional)"
        rows={2}
        className="mt-2 w-full rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-900"
      />
      <div className="mt-2 flex items-center gap-2">
        <select value={priority} onChange={(e) => setPriority(e.target.value as TicketPriority)} className={selectClass}>
          {PRIORITIES.map((p) => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
        <span className="ml-auto flex gap-2">
          <button onClick={onClose} className="rounded-md border border-gray-300 px-2.5 py-1 text-xs dark:border-gray-700">Cancel</button>
          <button onClick={submit} disabled={busy || !title.trim()} className="rounded-md bg-accent-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-accent-700 disabled:opacity-50">
            Create
          </button>
        </span>
      </div>
    </div>
  );
}

function Detail({
  detail,
  canEdit,
  canDelete,
  onPatch,
  onComment,
  onCloseFixed,
  onDelete,
}: {
  detail: TicketDetail;
  canEdit: boolean;
  canDelete: boolean;
  onPatch: (p: Parameters<typeof opsApi.updateTicket>[1]) => void;
  onComment: (body: string) => void;
  onCloseFixed: () => void;
  onDelete: () => void;
}) {
  const [comment, setComment] = useState("");
  return (
    <Panel
      title={detail.id}
      right={canDelete ? <button onClick={onDelete} className="text-xs text-gray-400 hover:text-red-600 dark:hover:text-red-400">Delete</button> : undefined}
    >
      <h3 className="text-base font-semibold leading-tight">{detail.title}</h3>
      {detail.description && <p className="mt-1 whitespace-pre-wrap text-sm text-gray-600 dark:text-gray-300">{detail.description}</p>}

      <div className="mt-3 flex flex-wrap items-center gap-2">
        {canEdit ? (
          <>
            <select value={detail.status} onChange={(e) => onPatch({ status: e.target.value as TicketStatus })} className={selectClass}>
              {STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
            </select>
            <select value={detail.priority} onChange={(e) => onPatch({ priority: e.target.value as TicketPriority })} className={selectClass}>
              {PRIORITIES.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </>
        ) : (
          <>
            <StatusChip status={detail.status} />
            <PriorityTag priority={detail.priority} />
          </>
        )}
        {detail.rollup.max && (
          <span className="inline-flex items-center gap-1 text-xs text-gray-500">
            rollup <SeverityBadge severity={detail.rollup.max as Severity} />
          </span>
        )}
      </div>

      <div className="mt-4 border-t border-gray-200 pt-3 dark:border-gray-800">
        <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">Linked findings ({detail.links.length})</div>
        {detail.links.length === 0 ? (
          <p className="mt-1 text-xs text-gray-500">No findings linked. Select findings in the Findings view and use “Create ticket” or link them there.</p>
        ) : (
          <ul className="mt-2 space-y-1">
            {detail.links.map((l) => (
              <li key={l.findingId} className="truncate font-mono text-[11px] text-gray-500 dark:text-gray-400">{l.findingId}{l.targetId ? ` · ${l.targetId}` : ""}</li>
            ))}
          </ul>
        )}
        {canEdit && detail.status !== "done" && detail.links.length > 0 && (
          <button onClick={onCloseFixed} className="mt-2 rounded-md border border-gray-300 px-2.5 py-1 text-xs font-medium hover:bg-gray-100 dark:border-gray-700 dark:hover:bg-gray-800">
            Close as done · mark {detail.links.length} fixed
          </button>
        )}
      </div>

      <div className="mt-4 border-t border-gray-200 pt-3 dark:border-gray-800">
        <div className="text-[11px] font-semibold uppercase tracking-wide text-gray-400">Timeline</div>
        <ul className="mt-2 space-y-2">
          {detail.comments.length === 0 && <li className="text-xs text-gray-500">No activity yet.</li>}
          {detail.comments.map((c) => (
            <li key={c.id} className="text-xs">
              <span className={c.kind === "event" ? "text-gray-400" : "text-gray-700 dark:text-gray-200"}>
                {c.kind === "event" ? "• " : ""}
                {c.body}
              </span>
              <span className="ml-1 text-gray-400">— {c.author || "system"}, {fmtTime(c.createdAt)}</span>
            </li>
          ))}
        </ul>
        {canEdit && (
          <div className="mt-2 flex gap-2">
            <input
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  onComment(comment);
                  setComment("");
                }
              }}
              placeholder="Add a comment…"
              className="min-w-0 flex-1 rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-800"
            />
            <button
              onClick={() => {
                onComment(comment);
                setComment("");
              }}
              disabled={!comment.trim()}
              className="rounded-md bg-accent-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-accent-700 disabled:opacity-50"
            >
              Send
            </button>
          </div>
        )}
      </div>

      <p className="mt-4 text-[11px] text-gray-400">
        Created {fmtTime(detail.createdAt)}{detail.createdBy ? ` by ${detail.createdBy}` : ""} · updated {fmtTime(detail.updatedAt)}
      </p>
    </Panel>
  );
}
