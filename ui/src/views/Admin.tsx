import { useEffect, useState } from "react";
import { opsApi, UserInfo, Target, AuditEntry, ApiError, KNOWN_SCANNERS, PROFILES } from "../api";
import { Panel, Loading, ErrorNote, EmptyState } from "../components";
import { fmtTime } from "../theme";

export function Admin({ selfUsername }: { selfUsername: string }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [users, setUsers] = useState<UserInfo[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);

  // Per-section errors
  const [userError, setUserError] = useState<string | null>(null);
  const [targetError, setTargetError] = useState<string | null>(null);

  // Controlled add-forms (never read back through the DOM).
  const [newUser, setNewUser] = useState({ username: "", password: "", role: "viewer" });
  const [newTarget, setNewTarget] = useState({ name: "", path: "", profile: "" });
  const [newTargetScanners, setNewTargetScanners] = useState<Set<string>>(new Set());

  useEffect(() => {
    reload(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Mutations call reload() without the full-page loading flash.
  async function reload(initial = false) {
    if (initial) setLoading(true);
    setError(null);
    try {
      const [uRes, tRes, aRes] = await Promise.all([
        opsApi.users(),
        opsApi.targets(),
        opsApi.audit(200),
      ]);
      setUsers(uRes.users);
      setTargets(tRes.targets);
      setAudit(aRes.entries);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("Failed to load admin data");
      }
    } finally {
      setLoading(false);
    }
  }

  if (loading) return <Loading what="admin data" />;
  if (error) return <ErrorNote error={error} />;

  return (
    <div className="space-y-6">
      {/* Section 1: Users */}
      <Panel title="Users">
        {userError && <div className="mb-3 text-xs text-red-600 dark:text-red-400">{userError}</div>}
        <div className="scroll-thin overflow-x-auto">
        <table className="w-full min-w-[600px] text-left text-sm">
          <thead className="text-xs uppercase text-gray-500">
            <tr>
              <th className="py-2 pr-3">Username</th>
              <th className="py-2 pr-3">Role</th>
              <th className="py-2 pr-3">Created</th>
              <th className="py-2 pr-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <UserRow
                key={u.id}
                user={u}
                selfUsername={selfUsername}
                onRoleChange={(role) => handleUserRoleChange(u.id, role)}
                onPasswordReset={(pw) => handleUserPasswordReset(u.id, pw)}
                onRemove={() => handleUserRemove(u.id, u.username)}
              />
            ))}
          </tbody>
        </table>
        </div>
        <div className="mt-4 grid gap-2 md:grid-cols-4">
          <input
            type="text"
            placeholder="Username"
            autoComplete="off"
            value={newUser.username}
            onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
            className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
          />
          <input
            type="password"
            placeholder="Password (min 8)"
            autoComplete="new-password"
            value={newUser.password}
            onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
            className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
          />
          <select
            value={newUser.role}
            onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
            className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
          >
            <option value="viewer">viewer</option>
            <option value="operator">operator</option>
            <option value="admin">admin</option>
          </select>
          <button
            onClick={handleAddUser}
            disabled={!newUser.username || !newUser.password}
            className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            Add user
          </button>
        </div>
      </Panel>

      {/* Section 2: Targets */}
      <Panel title="Targets">
        {targetError && <div className="mb-3 text-xs text-red-600 dark:text-red-400">{targetError}</div>}
        <div className="scroll-thin overflow-x-auto">
        <table className="w-full min-w-[600px] text-left text-sm">
          <thead className="text-xs uppercase text-gray-500">
            <tr>
              <th className="py-2 pr-3">Name</th>
              <th className="py-2 pr-3">Path</th>
              <th className="py-2 pr-3">Scanners</th>
              <th className="py-2 pr-3">Profile</th>
              <th className="py-2 pr-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.id} className="border-t border-gray-100 dark:border-gray-800">
                <td className="py-2 pr-3 font-medium">{t.name}</td>
                <td className="py-2 pr-3 font-mono text-xs text-gray-600 dark:text-gray-400">{t.path}</td>
                <td className="py-2 pr-3 text-xs">
                  {t.scanners && t.scanners.length > 0 ? t.scanners.join(", ") : "all"}
                </td>
                <td className="py-2 pr-3 text-xs">{t.profile || "standard"}</td>
                <td className="py-2 pr-3">
                  <button
                    onClick={() => handleRemoveTarget(t.id)}
                    className="text-xs text-red-600 hover:underline dark:text-red-400"
                  >
                    remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
        <div className="mt-4 space-y-2">
          <div className="grid gap-2 md:grid-cols-3">
            <input
              type="text"
              placeholder="Name"
              value={newTarget.name}
              onChange={(e) => setNewTarget({ ...newTarget, name: e.target.value })}
              className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
            />
            <input
              type="text"
              placeholder="/abs/path/to/repo"
              value={newTarget.path}
              onChange={(e) => setNewTarget({ ...newTarget, path: e.target.value })}
              className="rounded-md border border-gray-300 bg-white px-2 py-1.5 font-mono text-sm dark:border-gray-700 dark:bg-gray-800"
            />
            <select
              value={newTarget.profile}
              onChange={(e) => setNewTarget({ ...newTarget, profile: e.target.value })}
              className="rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm dark:border-gray-700 dark:bg-gray-800"
            >
              <option value="">standard (default)</option>
              {PROFILES.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </div>
          <div className="flex flex-wrap gap-4">
            {KNOWN_SCANNERS.map((s) => (
              <label key={s} className="flex items-center gap-1 text-sm">
                <input
                  type="checkbox"
                  checked={newTargetScanners.has(s)}
                  onChange={() =>
                    setNewTargetScanners((prev) => {
                      const next = new Set(prev);
                      if (next.has(s)) next.delete(s);
                      else next.add(s);
                      return next;
                    })
                  }
                  className="rounded border-gray-300 dark:border-gray-700"
                />
                <span>{s}</span>
              </label>
            ))}
            <span className="text-xs text-gray-500 dark:text-gray-400">none checked = all allowed</span>
          </div>
          <button
            onClick={handleAddTarget}
            disabled={!newTarget.name || !newTarget.path}
            className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
          >
            Register target
          </button>
        </div>
        <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
          Paths are validated server-side: absolute, existing directory, never /.
        </p>
      </Panel>

      {/* Section 3: Audit */}
      <Panel title="Audit log" right={<span className="text-xs text-gray-500 dark:text-gray-400">{audit.length} entries</span>}>
        {audit.length === 0 ? (
          <EmptyState title="No audit entries" hint="Logins, user/target changes and scan launches land here." />
        ) : (
          <div className="scroll-thin overflow-x-auto">
        <table className="w-full min-w-[600px] text-left text-sm">
            <thead className="text-xs uppercase text-gray-500">
              <tr>
                <th className="py-2 pr-3">Time</th>
                <th className="py-2 pr-3">Event</th>
                <th className="py-2 pr-3">Actor</th>
                <th className="py-2 pr-3">Details</th>
              </tr>
            </thead>
            <tbody>
              {[...audit].reverse().map((entry, idx) => (
                <tr key={idx} className="border-t border-gray-100 dark:border-gray-800">
                  <td className="py-2 pr-3 text-xs">{fmtTime(entry.time)}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{entry.event}</td>
                  <td className="py-2 pr-3 text-xs">{entry.actor || "-"}</td>
                  <td className="py-2 pr-3">
                    {entry.details ? (
                      <span className="font-mono text-[11px] text-gray-500">
                        {Object.entries(entry.details)
                          .map(([k, v]) => `${k}=${v}`)
                          .join(" ")}
                      </span>
                    ) : (
                      "-"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        )}
      </Panel>
    </div>
  );

  // --- Handlers ---

  async function handleUserRoleChange(userId: string, newRole: string) {
    setUserError(null);
    try {
      await opsApi.updateUserRole(userId, newRole);
      await reload();
    } catch (err) {
      setUserError(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function handleUserPasswordReset(userId: string, password: string) {
    setUserError(null);
    try {
      await opsApi.updateUserPassword(userId, password);
      await reload();
    } catch (err) {
      setUserError(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function handleUserRemove(userId: string, username: string) {
    if (!window.confirm(`Remove ${username}?`)) return;
    setUserError(null);
    try {
      await opsApi.deleteUser(userId);
      await reload();
    } catch (err) {
      setUserError(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function handleAddUser() {
    if (!newUser.username || !newUser.password) return;
    setUserError(null);
    try {
      await opsApi.createUser(newUser.username, newUser.password, newUser.role);
      setNewUser({ username: "", password: "", role: "viewer" });
      await reload();
    } catch (err) {
      setUserError(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function handleAddTarget() {
    if (!newTarget.name || !newTarget.path) return;
    setTargetError(null);
    try {
      const selected = Array.from(newTargetScanners);
      await opsApi.createTarget({
        name: newTarget.name,
        path: newTarget.path,
        scanners: selected.length > 0 ? selected : undefined,
        profile: newTarget.profile || undefined,
      });
      setNewTarget({ name: "", path: "", profile: "" });
      setNewTargetScanners(new Set());
      await reload();
    } catch (err) {
      setTargetError(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function handleRemoveTarget(targetId: string) {
    if (!window.confirm("Remove this target?")) return;
    setTargetError(null);
    try {
      await opsApi.deleteTarget(targetId);
      await reload();
    } catch (err) {
      setTargetError(err instanceof ApiError ? err.message : String(err));
    }
  }
}

function UserRow({
  user,
  selfUsername,
  onRoleChange,
  onPasswordReset,
  onRemove,
}: {
  user: UserInfo;
  selfUsername: string;
  onRoleChange: (role: string) => void;
  onPasswordReset: (pw: string) => void;
  onRemove: () => void;
}) {
  const [showPwInput, setShowPwInput] = useState(false);
  const [pwValue, setPwValue] = useState("");

  const isSelf = user.username === selfUsername;

  return (
    <tr className="border-t border-gray-100 dark:border-gray-800">
      <td className="py-2 pr-3 font-medium">{user.username}</td>
      <td className="py-2 pr-3">
        <select
          value={user.role}
          onChange={(e) => onRoleChange(e.target.value)}
          disabled={isSelf}
          className="rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-800"
        >
          <option value="viewer">viewer</option>
          <option value="operator">operator</option>
          <option value="admin">admin</option>
        </select>
      </td>
      <td className="py-2 pr-3 text-xs text-gray-500">{fmtTime(user.createdAt)}</td>
      <td className="py-2 pr-3">
        <div className="flex gap-2">
          {isSelf ? (
            <span className="text-xs text-gray-400">self</span>
          ) : (
            <>
              <button
                onClick={() => setShowPwInput(!showPwInput)}
                className="text-xs text-blue-600 hover:underline dark:text-blue-400"
              >
                reset password
              </button>
              <button
                onClick={onRemove}
                className="text-xs text-red-600 hover:underline dark:text-red-400"
              >
                remove
              </button>
            </>
          )}
        </div>
        {showPwInput && (
          <div className="mt-1 flex gap-2">
            <input
              type="password"
              placeholder="new password (min 8)"
              value={pwValue}
              onChange={(e) => setPwValue(e.target.value)}
              className="rounded-md border border-gray-300 bg-white px-2 py-1 text-xs dark:border-gray-700 dark:bg-gray-800"
            />
            <button
              onClick={() => {
                if (pwValue) onPasswordReset(pwValue);
                setShowPwInput(false);
                setPwValue("");
              }}
              className="rounded bg-blue-600 px-2 py-1 text-xs text-white hover:bg-blue-700"
            >
              confirm
            </button>
          </div>
        )}
      </td>
    </tr>
  );
}
