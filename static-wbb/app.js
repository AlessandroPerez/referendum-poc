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
  // Only a result the tabulation tellers really co-signed counts as the
  // published outcome; the server decides that, from the signers.
  const results = cachedEntries.filter(
    (r) => r.entry_type === "tally_result" && r.tally_result_signed,
  );
  const disagree =
    results.length > 1 &&
    results.some(
      (r) => JSON.stringify(r.payload) !== JSON.stringify(results[0].payload),
    );
  if (disagree) {
    container.textContent =
      "[!] The bulletin board carries more than one signed result, and they disagree. Report it.";
    return;
  }
  const result = results[0];
  if (!result || !result.payload) {
    container.textContent = "No tally published yet.";
    return;
  }
  const proofs = cachedEntries.filter((r) =>
    ["tally_result", "tally_proof"].includes(r.entry_type),
  );
  const { blank, si, no } = result.payload;
  container.textContent = "";
  const counts = document.createElement("p");
  const strong = (text) => {
    const el = document.createElement("strong");
    el.textContent = text;
    return el;
  };
  // The published fields keep their names (`si`, `no`); the page names the
  // options as the ballot does.
  counts.append(
    strong(`Blank: ${Number(blank)}`),
    " - ",
    strong(`Approve: ${Number(si)}`),
    " - ",
    strong(`Reject: ${Number(no)}`),
  );
  const where = document.createElement("p");
  where.textContent = `Published in log ${proofs
    .map((r) => `entry #${r.leaf_index} (${r.entry_type})`)
    .join(", ")} - co-signed by the tabulation tellers and verifiable with referendum-auditor.`;
  container.append(counts, where);
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

// Everything here comes from entries written by election authorities: it is
// put on the page as TEXT only, and what an entry counts for is decided by
// the server (`ballot_box`: typed decoding + the ballot box's own signature).
//
// The view is compact: what every ballot box agrees on (the emoji, the values
// a confirmation states) is shown ONCE, and a small table per box carries only
// what differs between them - the entry and its two timestamps. Any
// disagreement is still flagged, and then every box's own value is listed:
// one box must never be able to show one value here and have another audited.
function renderSearch(digest) {
  const container = $("search-result");
  container.textContent = "";
  const about = (r) => r.ballot_box && r.ballot_box.digest === digest;
  const valid = cachedEntries.filter((r) => about(r) && r.ballot_box.status === "valid");
  const ignored = cachedEntries.filter((r) => about(r) && r.ballot_box.status === "ignored");
  if (valid.length === 0 && ignored.length === 0) {
    container.textContent =
      "No entry found for this digest. If you just cast your ballot, refresh and retry.";
    return;
  }
  const digests = valid.filter((r) => r.entry_type === "ballot_digest");
  const cai = valid.filter((r) => r.entry_type === "cast_intended_proof");
  const bbIds = [...new Set(digests.map((r) => r.ballot_box.bb_id))].sort();
  const confirming = [...new Set(cai.map((r) => r.ballot_box.bb_id))].sort();
  const line = (text, cls) => {
    const p = document.createElement("p");
    if (cls) p.className = cls;
    p.textContent = text;
    container.appendChild(p);
    return p;
  };
  const code = (values) => {
    const el = document.createElement("code");
    el.textContent = Array.isArray(values) ? values.join(" ") : String(values ?? "");
    return el;
  };
  const boxes = (ids) => (ids.length ? ids.map((id) => `BB ${id}`).join(", ") : "none");

  // Status: who published the digest, who published a confirmation. Counted
  // = digest published by at least one box AND a confirmation published by at
  // least one (the tally's rule); whether the confirmation's disclosure really
  // opens THIS ballot is settled only at the tally.
  if (cai.length > 0 && bbIds.length > 0) {
    line(
      `[OK] Published by ${boxes(bbIds)}; confirmed by ${boxes(confirming)}.` +
        (bbIds.length < 2
          ? " [!] Only one ballot box published it - casting again is safer."
          : ""),
    );
  } else if (cai.length > 0) {
    line(
      `[!] Confirmed by ${boxes(confirming)} but no ballot box published this ballot's digest: it is NOT counted as it stands.`,
    );
  } else {
    line(
      `Published by ${boxes(bbIds)}. [!] Not confirmed yet - an unconfirmed ballot is NOT counted at tally.` +
        (bbIds.length < 2 ? " Only one ballot box published it - casting again is safer." : ""),
    );
  }

  // What the boxes agree on, once.
  const looks = new Set(
    digests.map((r) => JSON.stringify([r.payload.emoji, r.payload.public_pin_emoji])),
  );
  if (digests.length > 0 && looks.size === 1) {
    const p = line("");
    p.append("Emoji receipt ", code(digests[0].payload.emoji), "  public PIN emoji ",
      code(digests[0].payload.public_pin_emoji),
      digests.length > 1 ? `  (same at ${boxes(bbIds)})` : "");
  }
  const openedTexts = new Set(cai.map((r) => describeOpened(r.payload.opened)));
  const disclosures = new Set(cai.map((r) => JSON.stringify(r.payload.disclosure ?? null)));
  if (cai.length > 0 && openedTexts.size === 1 && disclosures.size === 1) {
    line(
      `Values the confirmation${cai.length > 1 ? "s" : ""} state${cai.length > 1 ? "" : "s"}: ${[...openedTexts][0]}` +
        (cai.length > 1 ? ` (same at ${boxes(confirming)})` : "") +
        ". Compare them with the numbers your Vote App showed.",
    );
  }

  // Per box, only what differs: the entries and their two timestamps.
  const table = document.createElement("table");
  table.className = "compact";
  const head = table.createTHead().insertRow();
  for (const h of ["Box", "Entry", "Kind", "On the board", "Box says"]) {
    const th = document.createElement("th");
    th.textContent = h;
    head.appendChild(th);
  }
  const body = table.createTBody();
  const rows = [
    ...digests.map((r) => [r, "published", r.payload.receipt.received_at_unix_ms, "received"]),
    ...cai.map((r) => [r, "confirmed", r.payload.confirmed_at_ms, "confirmed"]),
  ].sort((a, b) => a[0].ballot_box.bb_id - b[0].ballot_box.bb_id || a[0].leaf_index - b[0].leaf_index);
  for (const [row, kind, boxTime, boxVerb] of rows) {
    const tr = body.insertRow();
    for (const value of [`BB ${row.ballot_box.bb_id}`, row.leaf_index, kind]) {
      const td = tr.insertCell();
      td.textContent = value;
    }
    tr.appendChild(timestampCell(row.timestamp));
    const said = timestampCell(boxTime);
    said.textContent = `${boxVerb} ${said.textContent}`;
    tr.appendChild(said);
  }
  if (rows.length > 0) {
    const wrap = document.createElement("div");
    wrap.className = "table-wrap";
    wrap.appendChild(table);
    container.appendChild(wrap);
  }

  // Disagreements: flagged, with every box's own value.
  if (looks.size > 1) {
    line("[!] The ballot boxes DISAGREE on the emoji of this ballot. Report it - the audit names the box.", "warn");
    for (const row of digests) {
      const p = line("", "warn");
      p.append(`BB ${row.ballot_box.bb_id}: emoji receipt `, code(row.payload.emoji),
        "  public PIN emoji ", code(row.payload.public_pin_emoji));
    }
  }
  if (cai.length > 0 && (openedTexts.size > 1 || disclosures.size > 1)) {
    line(
      disclosures.size > 1
        ? `[!] ${cai.length} confirmations state this digest and ${disclosures.size} of them carry different disclosures. A disclosure is tied to a ballot only at the tally, which names any box that stated a digest its disclosure does not open. Report it.`
        : "[!] The published confirmations state DIFFERENT values for the same disclosure: at least one ballot box published something the others did not. Report it - the audit names the box.",
      "warn",
    );
    for (const row of cai) {
      line(`BB ${row.ballot_box.bb_id} (entry ${row.leaf_index}) states: ${describeOpened(row.payload.opened)}`, "warn");
    }
  }
  const perBox = new Map();
  for (const row of cai) perBox.set(row.ballot_box.bb_id, (perBox.get(row.ballot_box.bb_id) || 0) + 1);
  if ([...perBox.values()].some((n) => n > 1)) {
    line("[!] A ballot box published more than one confirmation for this ballot: check every row above.", "warn");
  }
  for (const row of ignored) {
    const signer = (row.entity_ids || []).join(", ") || "no verifiable signer";
    line(`[!] Entry ${row.leaf_index} (${row.entry_type}, ${signer}) is ignored: ${row.ballot_box.reason}. Report it - the audit names the box.`, "warn");
  }
  if (cai.length > 0) {
    line(
      "Whether a disclosure really opens this ballot is settled at the tally, which discards it if it does not; only a voter's last valid ballot counts.",
      "hint",
    );
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
