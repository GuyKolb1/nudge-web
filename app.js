// Nudge web: end-to-end encrypted notes synced through the hidden Nudge folder in Google Drive.
// Same vault + file format as the Android app (see app/.../sync in the nudge repo).
import * as C from "./crypto.js";

const CLIENT_ID = "268823083504-eeb2eh2mndmllongm0hsc13hshc2l30n.apps.googleusercontent.com";
const SCOPE = "https://www.googleapis.com/auth/drive.appdata";
const DEVICE = "web";
const API = "https://www.googleapis.com";
const DAY = 86400000;

const $ = (id) => document.getElementById(id);
const state = {
  token: null, tokenExp: 0, tokenClient: null,
  key: null,               // AES CryptoKey, memory only (asked again in each browser session)
  notes: new Map(),        // uid -> note
  ownFileId: null,
  dirty: false,
  tab: "upcoming",
  pendingAt: null, pendingLabel: null,
  vault: null,             // { id, json } or null if none yet
};

// ---------- Google auth ----------
function initGoogle() {
  return new Promise((resolve) => {
    const ready = () => {
      state.tokenClient = google.accounts.oauth2.initTokenClient({ client_id: CLIENT_ID, scope: SCOPE, callback: () => {} });
      resolve();
    };
    if (window.google?.accounts?.oauth2) ready();
    else window.addEventListener("load", () => {
      const t = setInterval(() => { if (window.google?.accounts?.oauth2) { clearInterval(t); ready(); } }, 50);
    });
  });
}

function getToken() {
  if (state.token && Date.now() < state.tokenExp - 60000) return Promise.resolve(state.token);
  return new Promise((resolve, reject) => {
    state.tokenClient.callback = (r) => {
      if (r.error) return reject(new Error(r.error_description || r.error));
      state.token = r.access_token;
      state.tokenExp = Date.now() + r.expires_in * 1000;
      resolve(state.token);
    };
    state.tokenClient.error_callback = (e) => reject(new Error(e.message || e.type || "Sign-in cancelled"));
    state.tokenClient.requestAccessToken({ prompt: "" });
  });
}

// ---------- Drive (appDataFolder only) ----------
async function drive(path, opts = {}, retry = true) {
  const token = await getToken();
  const res = await fetch(API + path, { ...opts, headers: { ...(opts.headers || {}), Authorization: `Bearer ${token}` } });
  if (res.status === 401 && retry) { state.token = null; return drive(path, opts, false); }
  if (!res.ok) throw new Error(`Google Drive error ${res.status}`);
  return res;
}
const listFiles = async () =>
  (await (await drive("/drive/v3/files?spaces=appDataFolder&pageSize=100&fields=files(id,name,modifiedTime)")).json()).files || [];
const seenVersions = new Map(); // file id -> modifiedTime already merged
const download = async (id) => (await drive(`/drive/v3/files/${id}?alt=media`)).text();
async function createFile(name, content) {
  const boundary = "nudge" + Date.now();
  const meta = JSON.stringify({ name, parents: ["appDataFolder"] });
  const body = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${meta}\r\n` +
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${content}\r\n--${boundary}--\r\n`;
  const res = await drive("/upload/drive/v3/files?uploadType=multipart&fields=id", {
    method: "POST", headers: { "Content-Type": `multipart/related; boundary=${boundary}` }, body,
  });
  return (await res.json()).id;
}
const updateFile = (id, content) => drive(`/upload/drive/v3/files/${id}?uploadType=media`, {
  method: "PATCH", headers: { "Content-Type": "application/json; charset=UTF-8" }, body: content,
});

// ---------- Vault ----------
async function loadVaultInfo() {
  const files = await listFiles();
  const v = files.find((f) => f.name === "vault.json");
  state.vault = v ? { id: v.id, json: JSON.parse(await download(v.id)) } : null;
}

async function unlock(passphrase) {
  if (state.vault) {
    const { salt, iter, check } = state.vault.json;
    const key = await C.deriveKey(passphrase, C.unb64(salt), iter || C.ITERATIONS);
    let ok = false;
    try { ok = (await C.decrypt(key, check)) === C.CHECK_TEXT; } catch { ok = false; }
    if (!ok) throw new Error("That passphrase doesn't match your vault.");
    state.key = key;
  } else {
    const salt = C.newSalt();
    const key = await C.deriveKey(passphrase, salt);
    const vault = { v: 1, kdf: "PBKDF2-SHA256", iter: C.ITERATIONS, salt: C.b64(salt), check: await C.encrypt(key, C.CHECK_TEXT) };
    await createFile("vault.json", JSON.stringify(vault));
    state.key = key;
  }
}

// ---------- Sync ----------
function mergeOne(n) {
  const cur = state.notes.get(n.uid);
  if (!cur || n.updatedAt > cur.updatedAt) state.notes.set(n.uid, n);
}

let syncing = false;
async function sync() {
  if (!state.key || syncing) return;
  syncing = true; setStatus("Syncing…");
  try {
    const files = await listFiles();
    for (const f of files.filter((f) => f.name.endsWith(".enc"))) {
      if (f.name === `${DEVICE}.enc`) state.ownFileId = f.id;
      if (f.modifiedTime && seenVersions.get(f.id) === f.modifiedTime) continue; // unchanged since last check
      const payload = JSON.parse(await C.decrypt(state.key, await download(f.id)));
      payload.notes.forEach(mergeOne);
      seenVersions.set(f.id, f.modifiedTime);
    }
    if (state.dirty || !state.ownFileId) await writeOwn();
    setStatus(`Up to date · ${fmtTime(Date.now())}`);
  } catch (e) {
    setStatus("Sync problem: " + e.message, true);
  } finally {
    syncing = false; render();
    if (state.dirty) setTimeout(sync, 300); // a change arrived while syncing
  }
}

async function writeOwn() {
  const cutoff = Date.now() - 30 * DAY;
  for (const [uid, n] of state.notes) if (n.deleted && n.updatedAt < cutoff) state.notes.delete(uid);
  const payload = JSON.stringify({ v: 1, device: DEVICE, writtenAt: Date.now(), notes: [...state.notes.values()] });
  const enc = await C.encrypt(state.key, payload);
  if (state.ownFileId) await updateFile(state.ownFileId, enc);
  else state.ownFileId = await createFile(`${DEVICE}.enc`, enc);
  state.dirty = false;
}

let saveTimer = null;
function changed() {
  state.dirty = true;
  render();
  clearTimeout(saveTimer);
  saveTimer = setTimeout(sync, 600);
}

function upsert(uid, patch) {
  const n = state.notes.get(uid);
  state.notes.set(uid, { ...n, ...patch, updatedAt: Date.now() });
  changed();
}

// ---------- Time helpers (same rules as the phone) ----------
const pad = (n) => String(n).padStart(2, "0");
const fmtTime = (ms) => { const d = new Date(ms); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; };
const dayName = (d) => d.toLocaleDateString("en-GB", { weekday: "short" });
const startOfDay = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();

function describe(ms) {
  const d = new Date(ms), now = new Date();
  const days = Math.round((startOfDay(d) - startOfDay(now)) / DAY);
  const t = fmtTime(ms);
  if (days === 0) return `today ${t}`;
  if (days === 1) return `tomorrow, ${dayName(d)} ${t}`;
  if (days === -1) return `yesterday ${t}`;
  if (days > 1 && days < 7) return `${dayName(d)} ${t}`;
  return `${d.toLocaleDateString("en-GB", { weekday: "short", day: "numeric", month: "short" })}, ${t}`;
}

function quickOptions() {
  const now = new Date(), n = now.getTime(), h = now.getHours();
  const at = (dayOffset, hour) => new Date(now.getFullYear(), now.getMonth(), now.getDate() + dayOffset, hour, 0).getTime();
  const early = h < 5, late = h >= 20;
  const morning = { label: early ? "This morning" : "Tomorrow morning", at: at(early ? 0 : 1, 8) };
  const list = [];
  if (late) list.push(morning);
  list.push({ label: "In 15 min", at: n + 15 * 60000 }, { label: "In 1 hour", at: n + 3600000 }, { label: "In 3 hours", at: n + 3 * 3600000 });
  if (at(0, 19) - n >= 30 * 60000) list.push({ label: "This evening", at: at(0, 19) });
  if (!late) list.push(morning);
  list.push({ label: "Tomorrow same time", at: n + DAY });
  return list;
}

function chipButtons(onPick, selectedLabel) {
  const frag = document.createDocumentFragment();
  for (const o of quickOptions()) {
    const b = document.createElement("button");
    b.className = "chip"; b.textContent = o.label;
    b.setAttribute("aria-pressed", String(o.label === selectedLabel));
    b.onclick = () => onPick(o.label, o.at);
    frag.append(b);
  }
  const pick = document.createElement("button");
  pick.className = "chip"; pick.textContent = "Pick…";
  pick.setAttribute("aria-pressed", String(selectedLabel === "Pick…"));
  pick.onclick = () => onPick("Pick…", null);
  frag.append(pick);
  return frag;
}

// ---------- UI ----------
function show(view) {
  for (const v of ["viewSignin", "viewUnlock", "viewApp"]) $(v).hidden = v !== view;
  $("lockBtn").hidden = view !== "viewApp";
}
function setStatus(text, isError = false) {
  $("status").textContent = text;
  $("status").style.color = isError ? "var(--accent)" : "";
}

function renderCapture() {
  const chips = $("chips");
  chips.replaceChildren(chipButtons((label, at) => {
    if (state.pendingLabel === label) { state.pendingLabel = null; state.pendingAt = null; $("pickWrap").hidden = true; }
    else if (label === "Pick…") { state.pendingLabel = label; $("pickWrap").hidden = false; $("pickInput").focus(); }
    else { state.pendingLabel = label; state.pendingAt = at; $("pickWrap").hidden = true; }
    renderCapture();
  }, state.pendingLabel));
  $("whenLine").hidden = !state.pendingAt;
  if (state.pendingAt) $("whenLine").textContent = `Reminds you ${describe(state.pendingAt)}`;
  $("saveBtn").disabled = !$("noteText").value.trim();
}

function visibleNotes() {
  const q = $("search").value.trim().toLowerCase();
  let all = [...state.notes.values()].filter((n) => !n.deleted);
  if (q) all = all.filter((n) => n.text.toLowerCase().includes(q));
  const upcoming = all.filter((n) => !n.done && n.remindAt != null).sort((a, b) => a.remindAt - b.remindAt);
  const inbox = all.filter((n) => !n.done && n.remindAt == null).sort((a, b) => b.createdAt - a.createdAt);
  const done = all.filter((n) => n.done).sort((a, b) => (b.doneAt || 0) - (a.doneAt || 0));
  return { upcoming, inbox, done };
}

function render() {
  if ($("viewApp").hidden) return;
  const groups = visibleNotes();
  document.querySelectorAll(".tabs button").forEach((b) => {
    const t = b.dataset.tab;
    b.setAttribute("aria-selected", String(t === state.tab));
    const span = b.querySelector("span");
    if (span) span.textContent = groups[t].length;
  });
  const list = $("list");
  const items = groups[state.tab];
  list.replaceChildren(...items.map(renderItem));
  $("empty").hidden = items.length > 0;
  $("empty").textContent = { upcoming: "Nothing scheduled.", inbox: "Inbox zero.", done: "No completed notes yet." }[state.tab];
}

function renderItem(n) {
  const li = $("itemTpl").content.firstElementChild.cloneNode(true);
  if (n.done) li.classList.add("done");
  const text = li.querySelector(".text");
  text.textContent = n.text;
  const meta = li.querySelector(".meta");
  if (n.done) meta.textContent = n.doneAt ? `Done ${describe(n.doneAt)}` : "Done";
  else if (n.remindAt != null) {
    const overdue = n.remindAt < Date.now();
    meta.textContent = (overdue ? "Overdue · " : "") + describe(n.remindAt);
    if (overdue) meta.classList.add("overdue");
  } else meta.textContent = `Added ${describe(n.createdAt)}`;

  const check = li.querySelector(".check");
  check.setAttribute("aria-label", n.done ? "Restore" : "Mark done");
  check.onclick = () => upsert(n.uid, n.done ? { done: false, doneAt: null } : { done: true, doneAt: Date.now() });

  li.querySelector(".act-delete").onclick = () => {
    if (confirm("Delete this note everywhere?")) upsert(n.uid, { deleted: true, text: "" });
  };

  li.querySelector(".act-edit").onclick = (e) => {
    const editing = text.isContentEditable;
    if (editing) {
      const value = text.innerText.trim();
      text.contentEditable = "false"; e.target.textContent = "Edit";
      if (value && value !== n.text) upsert(n.uid, { text: value });
    } else {
      text.contentEditable = "true"; e.target.textContent = "Done editing"; text.focus();
    }
  };

  li.querySelector(".act-remind").onclick = () => {
    const body = li.querySelector(".body");
    const existing = body.querySelector(".popover");
    if (existing) { existing.remove(); return; }
    const pop = document.createElement("div");
    pop.className = "popover";
    pop.append(chipButtons((label, at) => {
      if (label === "Pick…") {
        const input = document.createElement("input");
        input.type = "datetime-local";
        input.onchange = () => input.value && upsert(n.uid, { remindAt: new Date(input.value).getTime(), done: false, doneAt: null });
        pop.replaceChildren(input); input.focus();
      } else upsert(n.uid, { remindAt: at, done: false, doneAt: null });
    }));
    if (n.remindAt != null) {
      const clear = document.createElement("button");
      clear.className = "chip"; clear.textContent = "No reminder";
      clear.onclick = () => upsert(n.uid, { remindAt: null });
      pop.append(clear);
    }
    body.append(pop);
  };
  return li;
}

function saveNote() {
  const text = $("noteText").value.trim();
  if (!text) return;
  const now = Date.now();
  const uid = crypto.randomUUID();
  state.notes.set(uid, { uid, text, createdAt: now, remindAt: state.pendingAt, done: false, doneAt: null, updatedAt: now, deleted: false });
  $("noteText").value = "";
  state.pendingAt = null; state.pendingLabel = null; $("pickWrap").hidden = true;
  state.tab = state.notes.get(uid).remindAt != null ? "upcoming" : "inbox";
  renderCapture();
  changed();
  $("noteText").focus();
}

// ---------- Wiring ----------
async function afterSignIn() {
  setStatus("Checking your Drive…");
  await loadVaultInfo();
  setStatus("");
  const create = !state.vault;
  $("unlockTitle").textContent = create ? "Create your passphrase" : "Enter your passphrase";
  $("unlockHint").textContent = create
    ? "No Nudge vault found yet. Create a passphrase (at least 8 characters). You'll use the same one on your phone. If you forget it, synced notes can't be recovered."
    : "The passphrase you created in Nudge.";
  $("confirmWrap").hidden = !create;
  $("pass2").required = create;
  $("unlockBtn").textContent = create ? "Create vault" : "Unlock";
  show("viewUnlock");
  $("pass").focus();
}

async function main() {
  show("viewSignin");
  await initGoogle();

  $("signinBtn").onclick = async () => {
    $("signinError").textContent = "";
    try { await getToken(); await afterSignIn(); }
    catch (e) { $("signinError").textContent = e.message; }
  };

  $("unlockForm").onsubmit = async (e) => {
    e.preventDefault();
    $("unlockError").textContent = "";
    const pass = $("pass").value;
    if (!$("confirmWrap").hidden && pass !== $("pass2").value) { $("unlockError").textContent = "The two passphrases don't match."; return; }
    $("unlockBtn").disabled = true; $("unlockBtn").textContent = "Unlocking…";
    try {
      await unlock(pass);
      $("pass").value = ""; $("pass2").value = "";
      show("viewApp"); renderCapture(); render();
      $("noteText").focus();
      await sync();
    } catch (err) {
      $("unlockError").textContent = err.message;
    } finally {
      $("unlockBtn").disabled = false; $("unlockBtn").textContent = state.vault ? "Unlock" : "Create vault";
    }
  };

  $("noteText").addEventListener("input", renderCapture);
  $("noteText").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey && !e.isComposing) { e.preventDefault(); saveNote(); }
  });
  $("saveBtn").onclick = saveNote;
  $("pickInput").onchange = () => {
    if ($("pickInput").value) { state.pendingAt = new Date($("pickInput").value).getTime(); renderCapture(); }
  };
  document.querySelectorAll(".tabs button").forEach((b) => (b.onclick = () => { state.tab = b.dataset.tab; render(); }));
  $("search").addEventListener("input", render);
  $("lockBtn").onclick = () => location.reload(); // key lives in memory only
  $("status").onclick = () => { if (state.key) { state.token = null; sync(); } }; // click to reconnect/retry

  // Check for phone changes every 15s while the tab is visible, every 2 min in the background.
  let lastCheck = 0;
  setInterval(() => {
    if (!state.key) return;
    const every = document.hidden ? 120000 : 15000;
    if (Date.now() - lastCheck >= every) { lastCheck = Date.now(); sync(); }
  }, 5000);
  window.addEventListener("focus", () => { if (state.key) { lastCheck = Date.now(); sync(); } });
  document.addEventListener("visibilitychange", () => { if (!document.hidden && state.key) sync(); });
  setInterval(() => { if (state.key) render(); }, 30000); // keep "overdue" and times fresh
}

main();
