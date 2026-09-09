// Public WBB page (M6): phase banner, entry table, ballot digest search (V14).
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

async function refreshEntries() {
  try {
    cachedEntries = await api("/api/entries");
    const tbody = $("entries").querySelector("tbody");
    tbody.innerHTML = "";
    for (const row of cachedEntries) {
      const tr = document.createElement("tr");
      for (const value of [
        row.leaf_index,
        row.phase,
        row.role,
        row.entry_type,
        (row.entity_ids || []).join(", "),
        row.timestamp,
      ]) {
        const td = document.createElement("td");
        td.textContent = value;
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    renderResults();
  } catch (e) {
    setError(`Failed to load entries: ${e.message}`);
  }
}

// V15: results view — counts from the tally_result entry + links to the
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
    `<p><strong>Sì: ${si}</strong> · <strong>No: ${no}</strong> · blank: ${blank}</p>` +
    `<p>Published in log ${proofs
      .map((r) => `entry #${r.leaf_index} (${r.entry_type})`)
      .join(", ")} — co-signed by the tabulation tellers and verifiable with <code>referendum-auditor</code>.</p>`;
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
    `Published by ballot box(es) <strong>${bbIds.join(", ")}</strong> — ` +
    (noBot
      ? "✔ accepted by at least 2 ballot boxes (no ⊥)."
      : "⚠ fewer than 2 ballot boxes published this digest (⊥).") +
    (cai.length > 0
      ? ` ✔ cast-as-intended proof published (confirmed at ${cai[0].payload.confirmed_at_ms}).`
      : " No cast-as-intended proof yet.");
  container.appendChild(summary);

  for (const row of digests) {
    const p = document.createElement("p");
    p.innerHTML = `BB ${row.payload.receipt.bb_id}: emoji receipt <code>${(row.payload.emoji || []).join(" ")}</code>, logical time ${row.payload.receipt.received_at_unix_ms}`;
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
