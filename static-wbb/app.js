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
  counts.append(strong(`Si: ${Number(si)}`), " - ", strong(`No: ${Number(no)}`), ` - blank: ${Number(blank)}`);
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

  const summary = document.createElement("p");
  const noBot = bbIds.length >= 2;
  summary.textContent =
    `Published by ballot box(es) ${bbIds.join(", ") || "none"} - ` +
    (noBot
      ? "[OK] accepted by at least 2 ballot boxes (acceptance alone does not make it count - see below)."
      : "[!] published by only one ballot box: the other box has failed or never received it. The ballot still counts once confirmed, but casting again is safer.") +
    (cai.length > 0
      ? " Cast-as-intended disclosures are listed below: compare EVERY line with the numbers your Vote App showed."
      : " [!] No cast-as-intended disclosure yet - an unconfirmed ballot is NOT counted at tally.");
  container.appendChild(summary);

  // Every confirmation is shown, never just one: a ballot box must not be
  // able to show one value here and have another one audited.
  //
  // Two different claims are made by each line, and this page can check only
  // one of them. The values a box STATES it opened are what it printed; what
  // its DISCLOSURE really opens can only be settled against the released
  // ballot, at the tally. So the disclosures are compared here - two
  // different disclosures for one ballot are a report-it - and the stated
  // values are never called correct.
  const openedTexts = new Set();
  const disclosures = new Set();
  const perBox = new Map();
  for (const row of cai) {
    const opened = describeOpened(row.payload.opened);
    openedTexts.add(opened);
    disclosures.add(JSON.stringify(row.payload.disclosure ?? null));
    perBox.set(row.ballot_box.bb_id, (perBox.get(row.ballot_box.bb_id) || 0) + 1);
    const p = document.createElement("p");
    p.textContent = `BB ${row.ballot_box.bb_id} (entry ${row.leaf_index}): published on the board at ${formatTimestamp(row.timestamp)} (the box says the voter confirmed at ${formatTimestamp(row.payload.confirmed_at_ms)}); states it opened - ${opened}`;
    container.appendChild(p);
  }
  if (cai.length > 0) {
    const p = document.createElement("p");
    // What this page can check is what the entries SAY; what they actually
    // open is settled against the released ballots at the tally. So it
    // reports the disagreement and never predicts the auditor's verdict.
    // The digest an entry STATES is the publisher's to choose, so entries
    // gathered here may be about another ballot altogether: a dishonest box
    // can file another voter's genuine disclosure under this digest. Whether
    // a disclosure opens THIS ballot is settled only at the tally, so the
    // page reports the divergence and does not pronounce on the vote.
    if (disclosures.size > 1) {
      p.textContent =
        `[!] ${cai.length} confirmations state this digest and ${disclosures.size} of them carry different disclosures. A disclosure is tied to a ballot only at the tally, which names any box that stated a digest its disclosure does not open. Report it, and compare the values below with the numbers your Vote App showed.`;
    } else if (openedTexts.size > 1) {
      p.textContent =
        "[!] The published confirmations state DIFFERENT values for the same disclosure, so at least one ballot box has published something the others did not. Report it: the tally judges each disclosure against the released ballot, and the audit names the box.";
    } else if ([...perBox.values()].some((n) => n > 1)) {
      p.textContent =
        "[!] A ballot box published more than one confirmation for this ballot: check every line above.";
    } else {
      p.textContent = `${cai.length} confirmation(s), all STATING the same values and carrying the same disclosure. Compare the values with the numbers your Vote App showed; whether the disclosure really opens THIS ballot is settled at the tally.`;
    }
    container.appendChild(p);
  }

  // The same for what the ballot boxes say the ballot looks like.
  const looks = new Set(
    digests.map((r) => JSON.stringify([r.payload.emoji, r.payload.public_pin_emoji])),
  );
  if (looks.size > 1) {
    const p = document.createElement("p");
    p.textContent =
      "[!] The ballot boxes DISAGREE on the emoji of this ballot. Report it - the audit names the box.";
    container.appendChild(p);
  }

  // Counted = digest published by at least one ballot box AND a confirmation
  // published by at least one (the tally's rule; one honest box suffices).
  // Whether the confirmation is VALID is checked at tally against the
  // released ballot - the auditor names a box whose confirmation is not.
  if (cai.length > 0) {
    const confirming = [...perBox.keys()].sort();
    const p = document.createElement("p");
    p.textContent =
      bbIds.length > 0
        ? `[OK] Published by ballot box(es) ${bbIds.join(", ")} and a cast-as-intended disclosure is published by ${confirming.join(", ")}. Whether that disclosure really opens this ballot is settled at the tally, which discards the ballot if it does not - and only a voter's last valid ballot counts. Only the voter's own app can tell you now.`
        : `[!] A disclosure is published by ${confirming.join(", ")} but no ballot box published this ballot's digest: it is NOT counted as it stands.`;
    container.appendChild(p);
  }

  for (const row of ignored) {
    const p = document.createElement("p");
    const signer = (row.entity_ids || []).join(", ") || "no verifiable signer";
    p.textContent = `[!] Entry ${row.leaf_index} (${row.entry_type}, ${signer}) is ignored: ${row.ballot_box.reason}. Report it - the audit names the box.`;
    container.appendChild(p);
  }

  for (const row of digests) {
    const p = document.createElement("p");
    const code = (values) => {
      const el = document.createElement("code");
      el.textContent = (values || []).join(" ");
      return el;
    };
    p.append(
      `BB ${row.ballot_box.bb_id}: emoji receipt `,
      code(row.payload.emoji),
      " public PIN emoji ",
      code(row.payload.public_pin_emoji),
      ` published on the board at ${formatTimestamp(row.timestamp)} (the box says it received it at ${formatTimestamp(row.payload.receipt.received_at_unix_ms)})`,
    );
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
