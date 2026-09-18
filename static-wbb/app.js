// Public WBB page : phase banner, entry table, ballot digest search (V14).
"use strict";

const $ = (id) => document.getElementById(id);

function setError(message) {
  const el = $("error");
  if (message) {
    el.textContent = message;
    el.classList.remove("hidden");
  } else {
    el.classList.add("hidden");
  }
}

async function api(path) {
  setError(null);
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  return response.json();
}

async function refreshPhase() {
  try {
    const result = await api("/api/phase");
    $("phase").textContent = result.phase;
  } catch (e) {
    setError(`Failed to load phase: ${e.message}`);
  }
}

let cachedEntries = [];
let validators = [];
let autoRefresh = null;

// Validators (demo): independent parties that rebuild the log's Merkle
// tree, check it against the signed checkpoint and BLS-sign every leaf they
// verified. Each row shows a semaphore: red = no validator signature yet,
// yellow = some, green = every registered validator signed.
function semaphore(row) {
  const total = row.validators_total || 0;
  const signed = (row.validations || []).length;
  const state = signed === 0 ? "red" : signed < total ? "yellow" : "green";
  const cell = document.createElement("td");
  const dot = document.createElement("span");
  dot.className = `sem sem-${state}`;
  dot.title =
    signed === 0
      ? "no validator has signed this entry yet"
      : `signed by ${row.validations.join(", ")}`;
  cell.appendChild(dot);
  cell.appendChild(document.createTextNode(` ${signed}/${total}`));
  return cell;
}

async function refreshValidators() {
  try {
    const result = await api("/api/validators");
    validators = result.validators || [];
    const legend = $("validators-legend");
    if (validators.length === 0) {
      legend.classList.add("hidden");
      if (autoRefresh) clearInterval(autoRefresh);
      autoRefresh = null;
      return;
    }
    legend.classList.remove("hidden");
    $("validators-list").textContent = validators.join(", ");
    // Validations land one by one: keep the table live while they do.
    if (!autoRefresh) autoRefresh = setInterval(refreshEntries, 2000);
  } catch (e) {
    setError(`Failed to load validators: ${e.message}`);
  }
}

// WBB timestamps are Unix milliseconds when the cluster runs on the wall
// clock: shown in the viewer's local time, with the exact UTC instant as a
// tooltip. On the reproducible logical clock they are small tick counters,
// shown as-is.
function isUnixMillis(ts) {
  return typeof ts === "number" && ts >= 1e12;
}

function formatTimestamp(ts) {
  if (!isUnixMillis(ts)) {
    return String(ts);
  }
  return new Date(ts).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  });
}

function timestampCell(ts) {
  const td = document.createElement("td");
  td.textContent = formatTimestamp(ts);
  if (isUnixMillis(ts)) {
    td.title = `${new Date(ts).toISOString()} (${ts} ms)`;
  }
  return td;
}

async function refreshEntries() {
  try {
    cachedEntries = await api("/api/entries");
    const tbody = $("entries").querySelector("tbody");
    tbody.innerHTML = "";
    const showValidators = cachedEntries.some((r) => (r.validators_total || 0) > 0);
    $("entries").classList.toggle("no-validators", !showValidators);
    for (const row of cachedEntries) {
      const tr = document.createElement("tr");
      for (const value of [
        row.leaf_index,
        row.phase,
        row.role,
        row.entry_type,
        (row.entity_ids || []).join(", "),
      ]) {
        const td = document.createElement("td");
        td.textContent = value;
        tr.appendChild(td);
      }
      tr.appendChild(timestampCell(row.timestamp));
      tr.appendChild(semaphore(row));
      tbody.appendChild(tr);
    }
    renderResults();
  } catch (e) {
    setError(`Failed to load entries: ${e.message}`);
  }
}

// V15: results view - counts from the tally_result entry + links to the
// tally entries themselves.
function renderResults() {
  const container = $("results");
  const result = cachedEntries.find((r) => r.entry_type === "tally_result");
  if (!result || !result.payload) {
    container.textContent = "No tally published yet.";
    return;
  }
  const proofs = cachedEntries.filter((r) =>
    ["tally_result", "tally_proof"].includes(r.entry_type),
  );
  const { blank, si, no } = result.payload;
  container.innerHTML =
    `<p><strong>Si: ${si}</strong> - <strong>No: ${no}</strong> - blank: ${blank}</p>` +
    `<p>Published in log ${proofs
      .map((r) => `entry #${r.leaf_index} (${r.entry_type})`)
      .join(", ")} - co-signed by the tabulation tellers and verifiable with <code>referendum-auditor</code>.</p>`;
}

// The published proof carries the value the voter chose to open, after
// casting, at each level, decoded by the ballot box (Sec. 3.8.5 1(b)). The
// voter compares it with the control value their app showed.
function describeOpened(opened) {
  if (!opened) return "n/a";
  const one = (level) => {
    const slot = level ? Object.keys(level)[0] : null;
    if (!slot) return "n/a";
    const name = slot === "Code" ? "control code" : "control sum";
    return `${name} ${String(level[slot]).padStart(2, "0")}`;
  };
  return `list level: ${one(opened.l1)}, candidate level: ${one(opened.l2)}`;
}

function renderSearch(digest) {
  const container = $("search-result");
  container.innerHTML = "";
  const matches = cachedEntries.filter(
    (row) => row.payload && row.payload.digest === digest,
  );
  if (matches.length === 0) {
    container.textContent =
      "No entry found for this digest. If you just cast your ballot, refresh and retry.";
    return;
  }
  const digests = matches.filter((r) => r.entry_type === "ballot_digest");
  const cai = matches.filter((r) => r.entry_type === "cast_intended_proof");
  const bbIds = [...new Set(digests.map((r) => r.payload.receipt?.bb_id))].sort();

  const summary = document.createElement("p");
  const noBot = bbIds.length >= 2;
  summary.innerHTML =
    `Published by ballot box(es) <strong>${bbIds.join(", ")}</strong> - ` +
    (noBot
      ? "[OK] accepted by at least 2 ballot boxes, as required for it to be counted."
      : "[!] published by fewer than 2 ballot boxes: this ballot would be discarded at tally.") +
    (cai.length > 0
      ? ` [OK] cast-as-intended disclosure published by BB ${cai
          .map((r) => r.payload.bb_id)
          .sort()
          .join(", ")} (confirmed at ${formatTimestamp(cai[0].payload.confirmed_at_ms)}; opened control values - ${describeOpened(cai[0].payload.opened)}). Compare them with the numbers your Vote App showed. Only confirmed ballots are counted.`
      : " [!] No cast-as-intended disclosure yet - an unconfirmed ballot is NOT counted at tally.");
  container.appendChild(summary);

  for (const row of digests) {
    const p = document.createElement("p");
    p.innerHTML = `BB ${row.payload.receipt.bb_id}: emoji receipt <code>${(row.payload.emoji || []).join(" ")}</code>, received at ${formatTimestamp(row.payload.receipt.received_at_unix_ms)}`;
    container.appendChild(p);
  }
}

$("btn-search").addEventListener("click", async () => {
  await refreshEntries();
  renderSearch($("digest-input").value.trim());
});
$("btn-refresh").addEventListener("click", refreshEntries);

refreshPhase();
refreshEntries();
refreshValidators();
