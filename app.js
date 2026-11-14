// GetSheetDone web: end-to-end encrypted notes synced through the hidden GetSheetDone folder in Google Drive.
// Same vault + file format as the Android app (see app/.../sync in the nudge repo).
import * as C from "./crypto.js";

const CLIENT_ID = "268823083504-eeb2eh2mndmllongm0hsc13hshc2l30n.apps.googleusercontent.com";
// One permission only: GetSheetDone's own hidden folder in the user's Drive. Works for any Google account.
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
  tab: "inbox",
  tags: new Map(),         // uid -> { uid, name, color, order, updatedAt, deleted }
  filter: new Set(),       // tag uids picked in the filter row (any of them)
  tagPopFor: null,         // uid of the note whose tag picker is open
  pendingAt: null, pendingLabel: null,
  vault: null,             // { id, json } or null if none yet
  pendingAtts: [],         // attachments added in the capture box before Save: { meta, busy }
  blobIds: new Map(),      // attUid -> Drive file id
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
/** Every file in the hidden app folder (follows pages: attachments make the list long). */
async function listFiles() {
  const out = [];
  let page = "";
  do {
    const q = "/drive/v3/files?spaces=appDataFolder&pageSize=1000&fields=nextPageToken,files(id,name,modifiedTime)" +
      (page ? "&pageToken=" + encodeURIComponent(page) : "");
    const json = await (await drive(q)).json();
    out.push(...(json.files || []));
    page = json.nextPageToken || "";
  } while (page);
  state.blobIds = new Map(out.filter((f) => f.name.startsWith("att-")).map((f) => [f.name.slice(4, -4), f.id]));
  return out;
}
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
async function createBinary(name, bytes) {
  const boundary = "nudge" + Date.now();
  const meta = JSON.stringify({ name, parents: ["appDataFolder"] });
  const body = new Blob([
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${meta}\r\n--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n`,
    bytes,
    `\r\n--${boundary}--\r\n`,
  ]);
  const res = await drive("/upload/drive/v3/files?uploadType=multipart&fields=id", {
    method: "POST", headers: { "Content-Type": `multipart/related; boundary=${boundary}` }, body,
  });
  return (await res.json()).id;
}
const downloadBytes = async (id) => new Uint8Array(await (await drive(`/drive/v3/files/${id}?alt=media`)).arrayBuffer());
async function deleteFile(id) {
  try { await drive(`/drive/v3/files/${id}`, { method: "DELETE" }); } catch { /* already gone */ }
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
  if (!cur) state.notes.set(n.uid, n);
  else if (n.updatedAt > cur.updatedAt) state.notes.set(n.uid, { ...n, attachments: unionAtts(cur.attachments, n.attachments) });
  else cur.attachments = unionAtts(cur.attachments, n.attachments); // never lose a file added on the other device
}

/** Merge attachment lists by attUid; a deletion on either side wins. */
function unionAtts(a = [], b = []) {
  const map = new Map();
  for (const x of [...(a || []), ...(b || [])]) {
    const prev = map.get(x.attUid);
    map.set(x.attUid, prev ? { ...prev, deleted: prev.deleted || x.deleted } : x);
  }
  return [...map.values()];
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
      (payload.tags || []).forEach(mergeTag);
      seenVersions.set(f.id, f.modifiedTime);
    }
    if (state.dirty || !state.ownFileId) await writeOwn();
    setStatus(`Up to date · ${fmtTime(Date.now())}`);
  } catch (e) {
    setStatus("Sync problem: " + e.message, true);
  } finally {
    syncing = false; render();
    $("syncBtn").disabled = false; $("syncBtn").textContent = "Sync";
    if (state.dirty) setTimeout(sync, 300); // a change arrived while syncing
  }
}

async function writeOwn() {
  const cutoff = Date.now() - 30 * DAY;
  for (const [uid, n] of state.notes) if (n.deleted && n.updatedAt < cutoff) state.notes.delete(uid);
  for (const [uid, t] of state.tags) if (t.deleted && t.updatedAt < cutoff) state.tags.delete(uid);
  const payload = JSON.stringify({ v: 1, device: DEVICE, writtenAt: Date.now(), notes: [...state.notes.values()], tags: [...state.tags.values()] });
  const enc = await C.encrypt(state.key, payload);
  if (state.ownFileId) await updateFile(state.ownFileId, enc);
  else state.ownFileId = await createFile(`${DEVICE}.enc`, enc);
  state.dirty = false;
}

/** The Sync button: a full two-way sync right now (re-reads every device file, then writes ours). */
function syncNow() {
  if (!state.key || syncing) return;
  $("syncBtn").disabled = true; $("syncBtn").textContent = "Syncing…";
  seenVersions.clear();    // re-read the phone's file even if it looks unchanged
  state.dirty = true;      // and write ours
  sync();
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

// ---------- Tags (same model as the phone: last-writer-wins per tag, deletes are tombstones) ----------
const PALETTE = ["#0E6B5C", "#C2410C", "#1D4ED8", "#7C3AED", "#B45309", "#BE185D", "#15803D", "#475569"];
const HASHTAG = /(?:^|(?<=\s))#(\p{L}[\p{L}\p{N}_-]*)/gmu;

function mergeTag(t) {
  if (!t || !t.uid) return;
  const cur = state.tags.get(t.uid);
  if (cur && (t.updatedAt || 0) <= cur.updatedAt) return;
  state.tags.set(t.uid, {
    uid: t.uid, name: t.name || "", color: t.color || PALETTE[7], updatedAt: t.updatedAt || 0, deleted: !!t.deleted,
    order: t.order ?? cur?.order ?? 0, // an older phone build sends no order: keep ours
  });
}
/** Tags in the order the user chose (then by name). */
const activeTags = () => [...state.tags.values()].filter((t) => !t.deleted)
  .sort((a, b) => (a.order - b.order) || a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
const noteTagIds = (n) => (Array.isArray(n.tags) ? n.tags : []);
const noteTags = (n) => { const ids = noteTagIds(n); return activeTags().filter((t) => ids.includes(t.uid)); };

function putTag(uid, patch) {
  state.tags.set(uid, { ...state.tags.get(uid), ...patch, updatedAt: Date.now() });
  changed();
}
/** Finds a tag by name (any case) or creates it at the end of the order. Returns its uid. */
function findOrCreateTag(name) {
  const clean = name.trim().replace(/^#/, "").trim();
  if (!clean) return null;
  const all = activeTags();
  const existing = all.find((t) => t.name.toLowerCase() === clean.toLowerCase());
  if (existing) return existing.uid;
  const uid = crypto.randomUUID();
  state.tags.set(uid, {
    uid, name: clean, color: PALETTE[all.length % PALETTE.length], updatedAt: Date.now(), deleted: false,
    order: all.reduce((m, t) => Math.max(m, t.order), -1) + 1,
  });
  state.dirty = true;
  return uid;
}
function moveTag(uid, delta) {
  const list = activeTags();
  const i = list.findIndex((t) => t.uid === uid), j = i + delta;
  if (i < 0 || j < 0 || j >= list.length) return;
  list.splice(j, 0, list.splice(i, 1)[0]);
  const now = Date.now();
  list.forEach((t, idx) => { if (t.order !== idx) state.tags.set(t.uid, { ...t, order: idx, updatedAt: now }); });
  changed();
}
function toggleNoteTag(uid, tagUid) {
  const ids = noteTagIds(state.notes.get(uid));
  upsert(uid, { tags: ids.includes(tagUid) ? ids.filter((x) => x !== tagUid) : [...ids, tagUid] });
}
function tagPill(t, { selected = null, small = false, onClick = null } = {}) {
  const el = document.createElement(onClick ? "button" : "span");
  el.className = "tag" + (small ? " small" : "");
  el.style.setProperty("--c", t.color);
  el.textContent = t.name; el.dir = "auto";
  if (selected !== null) el.setAttribute("aria-pressed", String(selected));
  if (onClick) { el.type = "button"; el.onclick = onClick; }
  return el;
}

/** Filter row above the list. Click to filter, click again to clear. More than one = any of them. */
function renderFilter() {
  const tags = activeTags();
  for (const uid of state.filter) if (!tags.some((t) => t.uid === uid)) state.filter.delete(uid); // deleted tag drops out
  const row = $("tagFilter");
  const kids = tags.map((t) => tagPill(t, { selected: state.filter.has(t.uid), onClick: () => {
    state.filter.has(t.uid) ? state.filter.delete(t.uid) : state.filter.add(t.uid); render();
  } }));
  if (state.filter.size) {
    const clear = document.createElement("button");
    clear.className = "chip"; clear.textContent = "Clear";
    clear.onclick = () => { state.filter.clear(); render(); };
    kids.unshift(clear);
  }
  const manage = document.createElement("button");
  manage.className = "ghost"; manage.textContent = tags.length ? "Edit tags" : "Add tags";
  manage.onclick = () => { renderTagDialog(); $("tagDialog").showModal(); };
  row.replaceChildren(...kids, manage);
}

/** Manage tags: order (arrows), rename, color, delete, add. */
function renderTagDialog() {
  const tags = activeTags();
  $("tagList").replaceChildren(...tags.map((t, i) => {
    const li = document.createElement("li");
    const dot = document.createElement("button");
    dot.className = "dot"; dot.style.background = t.color; dot.title = "Change color";
    dot.onclick = () => putTag(t.uid, { color: PALETTE[(PALETTE.indexOf(t.color.toUpperCase()) + 1) % PALETTE.length] });
    const name = document.createElement("input");
    name.value = t.name; name.dir = "auto"; name.setAttribute("aria-label", "Tag name");
    name.onchange = () => {
      const v = name.value.trim().replace(/^#/, "").trim();
      const taken = tags.some((x) => x.uid !== t.uid && x.name.toLowerCase() === v.toLowerCase());
      if (!v || taken) { name.value = t.name; if (taken) setStatus("A tag with that name already exists", true); return; }
      if (v !== t.name) putTag(t.uid, { name: v });
    };
    const btn = (label, title, onClick, disabled = false) => {
      const b = document.createElement("button");
      b.className = "ghost"; b.textContent = label; b.title = title; b.disabled = disabled; b.onclick = onClick;
      return b;
    };
    li.append(dot, name,
      btn("↑", "Move up", () => moveTag(t.uid, -1), i === 0),
      btn("↓", "Move down", () => moveTag(t.uid, 1), i === tags.length - 1),
      btn("✕", "Delete tag", () => {
        if (confirm(`Delete "${t.name}"? It is removed from every task. The tasks themselves stay.`)) putTag(t.uid, { deleted: true });
      }));
    return li;
  }));
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
  $("syncBtn").hidden = view !== "viewApp";
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
  $("saveBtn").disabled = !$("noteText").value.trim() && !state.pendingAtts.length;
}

function visibleNotes() {
  const q = $("search").value.trim().toLowerCase();
  let all = [...state.notes.values()].filter((n) => !n.deleted);
  if (q) all = all.filter((n) => n.text.toLowerCase().includes(q));
  if (state.filter.size) all = all.filter((n) => noteTagIds(n).some((id) => state.filter.has(id)));
  // Inbox = every open note, scheduled or not (same as the phone). Starred first, then newest first.
  const inbox = all.filter((n) => !n.done).sort((a, b) => (!!b.isStarred - !!a.isStarred) || (b.createdAt - a.createdAt));
  const done = all.filter((n) => n.done).sort((a, b) => (b.doneAt || 0) - (a.doneAt || 0));
  return { inbox, done };
}

function render() {
  if ($("viewApp").hidden) return;
  renderFilter();
  if ($("tagDialog").open) renderTagDialog();
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
  $("empty").textContent = state.filter.size ? "No tasks with these tags here."
    : { inbox: "Inbox zero.", done: "No completed notes yet." }[state.tab];
}

function renderItem(n) {
  const li = $("itemTpl").content.firstElementChild.cloneNode(true);
  if (n.done) li.classList.add("done");
  const text = li.querySelector(".text");
  text.textContent = n.text || activeAtts(n).map((a) => a.name).join(", ");
  const meta = li.querySelector(".meta");
  if (n.done) meta.textContent = n.doneAt ? `Done ${describe(n.doneAt)}` : "Done";
  else if (n.remindAt != null) {
    const overdue = n.remindAt < Date.now();
    meta.textContent = (overdue ? "Overdue · " : "") + describe(n.remindAt);
    if (overdue) meta.classList.add("overdue");
  } else meta.textContent = `Added ${describe(n.createdAt)}`;

  li.querySelector(".notetags").replaceChildren(...noteTags(n).map((t) => tagPill(t, { small: true })));
  const star = li.querySelector(".act-star");
  star.textContent = n.isStarred ? "★" : "☆";
  star.classList.toggle("on", !!n.isStarred);
  star.setAttribute("aria-label", n.isStarred ? "Unstar" : "Star");
  star.onclick = () => upsert(n.uid, { isStarred: !n.isStarred });

  // Tag picker for this note: toggle existing tags or type a new one. Stays open while you pick.
  li.querySelector(".act-tags").onclick = () => { state.tagPopFor = state.tagPopFor === n.uid ? null : n.uid; render(); };
  if (state.tagPopFor === n.uid) {
    const pop = document.createElement("div");
    pop.className = "tagpop";
    const ids = noteTagIds(n);
    pop.append(...activeTags().map((t) => tagPill(t, { selected: ids.includes(t.uid), onClick: () => toggleNoteTag(n.uid, t.uid) })));
    const input = document.createElement("input");
    input.type = "search"; input.placeholder = "New tag, then Enter"; input.dir = "auto";
    input.onkeydown = (e) => {
      if (e.key !== "Enter") return;
      const id = findOrCreateTag(input.value);
      if (id && !ids.includes(id)) toggleNoteTag(n.uid, id);
    };
    const close = document.createElement("button");
    close.className = "ghost"; close.textContent = "Close";
    close.onclick = () => { state.tagPopFor = null; render(); };
    pop.append(input, close);
    li.querySelector(".body").append(pop);
  }

  renderAtts(li.querySelector(".atts"), activeAtts(n), (att) => removeAttachment(n.uid, att));
  const fileIn = document.createElement("input");
  fileIn.type = "file"; fileIn.multiple = true; fileIn.hidden = true;
  fileIn.onchange = () => { attachTo(n.uid, [...fileIn.files]); fileIn.value = ""; };
  li.append(fileIn);
  li.querySelector(".act-attach").onclick = () => fileIn.click();
  makeDropZone(li, (files) => attachTo(n.uid, files));

  const check = li.querySelector(".check");
  check.setAttribute("aria-label", n.done ? "Restore" : "Mark done");
  check.onclick = () => upsert(n.uid, n.done ? { done: false, doneAt: null } : { done: true, doneAt: Date.now() });

  li.querySelector(".act-delete").onclick = () => {
    if (!confirm("Delete this note everywhere?")) return;
    for (const a of activeAtts(n)) { const id = state.blobIds?.get(a.attUid); if (id) deleteFile(id); }
    upsert(n.uid, { deleted: true, text: "", attachments: (n.attachments || []).map((a) => ({ ...a, deleted: true })) });
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
  // #word in the text becomes a tag and leaves the text (same as the phone).
  const raw = $("noteText").value.trim();
  const names = [...raw.matchAll(HASHTAG)].map((m) => m[1]);
  const stripped = raw.replace(HASHTAG, "").split("\n").map((l) => l.replace(/ {2,}/g, " ").trimEnd()).join("\n").trim();
  const useTags = names.length > 0 && (stripped.length > 0 || state.pendingAtts.length > 0); // only #tags: keep as text
  const text = useTags ? stripped : raw;
  const tags = useTags ? [...new Set(names.map(findOrCreateTag).filter(Boolean))] : [];
  if (state.pendingAtts.some((p) => p.busy)) { setStatus("Still uploading attachments…"); return; }
  const atts = state.pendingAtts.map((p) => p.meta);
  if (!text && !atts.length) return;
  const now = Date.now();
  const uid = crypto.randomUUID();
  state.notes.set(uid, { uid, text, createdAt: now, remindAt: state.pendingAt, done: false, doneAt: null, updatedAt: now, deleted: false, attachments: atts, tags });
  state.pendingAtts = [];
  renderPending();
  $("noteText").value = "";
  state.pendingAt = null; state.pendingLabel = null; $("pickWrap").hidden = true;
  state.tab = "inbox";
  renderCapture();
  changed();
  $("noteText").focus();
}

// ---------- Attachments ----------
// Each file is its own Drive file att-<attUid>.bin: 12-byte IV + AES-GCM ciphertext (same vault key as notes).
// Google sees only a random id and ciphertext. Name, type and size live inside the encrypted note.
const MAX_FILE = 10 * 1024 * 1024;
const PHOTO_MAX_PX = 2048;
const activeAtts = (n) => (n.attachments || []).filter((a) => !a.deleted);
const urlCache = new Map(); // attUid -> object URL (decrypted, memory only)

/** Photos: resized to 2048 px JPEG (drops location data). Other files: up to 10 MB as they are. */
async function prepareFile(file) {
  const isPhoto = file.type.startsWith("image/") && !["image/gif", "image/svg+xml"].includes(file.type);
  if (isPhoto) {
    try {
      const bmp = await createImageBitmap(file, { imageOrientation: "from-image" });
      const scale = Math.min(1, PHOTO_MAX_PX / Math.max(bmp.width, bmp.height));
      const canvas = document.createElement("canvas");
      canvas.width = Math.max(1, Math.round(bmp.width * scale));
      canvas.height = Math.max(1, Math.round(bmp.height * scale));
      canvas.getContext("2d").drawImage(bmp, 0, 0, canvas.width, canvas.height);
      const blob = await new Promise((r) => canvas.toBlob(r, "image/jpeg", 0.85));
      const base = (file.name || "photo").replace(/\.[^.]+$/, "") || "photo";
      return { name: base + ".jpg", mime: "image/jpeg", bytes: new Uint8Array(await blob.arrayBuffer()) };
    } catch { /* not decodable: treat as a normal file */ }
  }
  if (file.size > MAX_FILE) throw new Error(`${file.name}: file too large (max 10 MB)`);
  return { name: file.name || "file", mime: file.type || "application/octet-stream", bytes: new Uint8Array(await file.arrayBuffer()) };
}

/** Encrypts + uploads the blob first, then returns the metadata (so the phone never sees a missing file). */
async function uploadFile(file) {
  const f = await prepareFile(file);
  const attUid = crypto.randomUUID();
  const id = await createBinary(`att-${attUid}.bin`, await C.encryptBytes(state.key, f.bytes));
  state.blobIds.set(attUid, id);
  urlCache.set(attUid, URL.createObjectURL(new Blob([f.bytes], { type: f.mime })));
  return { attUid, name: f.name, mime: f.mime, size: f.bytes.length, sha256: await C.sha256Hex(f.bytes), addedAt: Date.now(), deleted: false };
}

async function attachTo(uid, files) {
  for (const file of files) {
    try {
      setStatus(`Uploading ${file.name}…`);
      const meta = await uploadFile(file);
      const n = state.notes.get(uid);
      upsert(uid, { attachments: [...(n.attachments || []), meta] });
      setStatus("Attached " + meta.name);
    } catch (e) { setStatus(e.message, true); }
  }
}

function addPending(files) {
  for (const file of files) {
    const p = { meta: { attUid: "", name: file.name, mime: file.type }, busy: true };
    state.pendingAtts.push(p);
    renderPending();
    uploadFile(file).then((meta) => { p.meta = meta; p.busy = false; })
      .catch((e) => { state.pendingAtts = state.pendingAtts.filter((x) => x !== p); setStatus(e.message, true); })
      .finally(() => { renderPending(); renderCapture(); });
  }
  renderCapture();
}

function renderPending() {
  renderAtts($("pendingAtts"), state.pendingAtts.map((p) => ({ ...p.meta, busy: p.busy })), (att) => {
    const id = state.blobIds.get(att.attUid);
    if (id) deleteFile(id);
    state.pendingAtts = state.pendingAtts.filter((p) => p.meta.attUid !== att.attUid);
    renderPending(); renderCapture();
  });
}

function removeAttachment(uid, att) {
  const n = state.notes.get(uid);
  const id = state.blobIds.get(att.attUid);
  if (id) deleteFile(id);
  upsert(uid, { attachments: (n.attachments || []).map((a) => (a.attUid === att.attUid ? { ...a, deleted: true } : a)) });
}

/** Decrypted copy of one attachment, kept in memory for this session. Null if not uploaded yet. */
async function attachmentUrl(att) {
  if (urlCache.has(att.attUid)) return urlCache.get(att.attUid);
  let id = state.blobIds.get(att.attUid);
  if (!id) { await listFiles(); id = state.blobIds.get(att.attUid); }
  if (!id) return null;
  const bytes = await C.decryptBytes(state.key, await downloadBytes(id));
  const url = URL.createObjectURL(new Blob([bytes], { type: att.mime }));
  urlCache.set(att.attUid, url);
  return url;
}

async function openAttachment(att) {
  try {
    if (!urlCache.has(att.attUid)) setStatus(`Opening ${att.name}…`);
    const url = await attachmentUrl(att);
    if (!url) { setStatus(`${att.name} hasn't finished uploading from the phone yet.`, true); return; }
    setStatus("");
    if (att.mime.startsWith("image/")) {
      const box = document.createElement("div");
      box.className = "lightbox";
      const img = document.createElement("img");
      img.src = url; img.alt = att.name;
      box.append(img);
      box.onclick = () => box.remove();
      document.addEventListener("keydown", function esc(e) { if (e.key === "Escape") { box.remove(); document.removeEventListener("keydown", esc); } });
      document.body.append(box);
    } else {
      const a = document.createElement("a");
      a.href = url; a.download = att.name;
      document.body.append(a); a.click(); a.remove();
    }
  } catch (e) { setStatus("Couldn't open " + att.name + ": " + e.message, true); }
}

/** Chips for a list of attachments. Photos get a thumbnail once opened or uploaded here. */
function renderAtts(container, atts, onRemove) {
  container.replaceChildren(...atts.map((att) => {
    const chip = document.createElement("span");
    chip.setAttribute("role", "button"); chip.tabIndex = 0;
    chip.className = "att" + (att.busy ? " busy" : "");
    chip.title = att.busy ? "Uploading…" : `${att.name} · ${fmtSize(att.size)}`;
    const cached = urlCache.get(att.attUid);
    if (att.mime?.startsWith("image/") && cached) {
      chip.classList.add("photo");
      const img = document.createElement("img"); img.src = cached; img.alt = att.name;
      chip.append(img);
    } else {
      if (att.mime?.startsWith("image/") && !att.busy) loadThumb(att);
      const label = document.createElement("span");
      label.textContent = (att.mime?.startsWith("image/") ? "🖼 " : "📎 ") + (att.busy ? "Uploading " : "") + att.name;
      chip.append(label);
    }
    chip.onclick = () => !att.busy && openAttachment(att).then(() => render());
    if (!att.busy) {
      const x = document.createElement("button");
      x.className = "x"; x.textContent = "✕"; x.title = "Remove";
      x.onclick = (e) => { e.stopPropagation(); if (confirm(`Remove ${att.name}?`)) onRemove(att); };
      chip.append(x);
    }
    return chip;
  }));
}

const thumbLoading = new Set();
/** Fetch + decrypt a photo in the background, then redraw so its thumbnail shows. */
function loadThumb(att) {
  if (thumbLoading.has(att.attUid) || att.size > 4 * 1048576) return;
  thumbLoading.add(att.attUid);
  attachmentUrl(att).then((url) => { if (url) render(); }).catch(() => {}).finally(() => {
    // Not uploaded yet: allow another try on a later redraw (after the next sync).
    setTimeout(() => thumbLoading.delete(att.attUid), 30000);
  });
}

const fmtSize = (b) => (b == null ? "" : b < 1024 ? `${b} B` : b < 1048576 ? `${Math.round(b / 1024)} KB` : `${(b / 1048576).toFixed(1)} MB`);

function makeDropZone(el, onFiles) {
  let depth = 0;
  el.addEventListener("dragenter", (e) => { if (e.dataTransfer?.types?.includes("Files")) { depth++; el.classList.add("dropping"); e.preventDefault(); } });
  el.addEventListener("dragover", (e) => { if (e.dataTransfer?.types?.includes("Files")) e.preventDefault(); });
  el.addEventListener("dragleave", () => { if (--depth <= 0) { depth = 0; el.classList.remove("dropping"); } });
  el.addEventListener("drop", (e) => {
    depth = 0; el.classList.remove("dropping");
    const files = [...(e.dataTransfer?.files || [])];
    if (files.length) { e.preventDefault(); e.stopPropagation(); onFiles(files); }
  });
}

// ---------- Wiring ----------
async function afterSignIn() {
  setStatus("Checking your Drive…");
  await loadVaultInfo();
  setStatus("");
  const create = !state.vault;
  $("unlockTitle").textContent = create ? "Create your passphrase" : "Enter your passphrase";
  $("unlockHint").textContent = create
    ? "No GetSheetDone vault found yet. Create a passphrase (at least 8 characters). You'll use the same one on your phone. If you forget it, synced notes can't be recovered."
    : "The passphrase you created in GetSheetDone.";
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
  $("attachBtn").onclick = () => $("fileInput").click();
  $("fileInput").onchange = () => { addPending([...$("fileInput").files]); $("fileInput").value = ""; };
  makeDropZone(document.querySelector(".capture"), addPending);
  // A file dropped outside a note or the capture box must not make the browser open it.
  window.addEventListener("dragover", (e) => e.preventDefault());
  window.addEventListener("drop", (e) => e.preventDefault());
  $("noteText").addEventListener("paste", (e) => {
    const files = [...(e.clipboardData?.files || [])];
    if (files.length) { e.preventDefault(); addPending(files); }
  });
  $("pickInput").onchange = () => {
    if ($("pickInput").value) { state.pendingAt = new Date($("pickInput").value).getTime(); renderCapture(); }
  };
  document.querySelectorAll(".tabs button").forEach((b) => (b.onclick = () => { state.tab = b.dataset.tab; render(); }));
  $("search").addEventListener("input", render);
  $("lockBtn").onclick = () => location.reload(); // key lives in memory only
  $("tagDialogClose").onclick = () => $("tagDialog").close();
  $("tagAddForm").onsubmit = (e) => {
    e.preventDefault();
    if (findOrCreateTag($("tagAddInput").value)) changed();
    $("tagAddInput").value = "";
  };
  $("syncBtn").onclick = syncNow;
  $("status").onclick = syncNow; // the status text works as a second Sync button

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
