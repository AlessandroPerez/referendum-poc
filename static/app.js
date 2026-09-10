// Vote App SPA: login -> enroll -> status poll -> PIN retrieve -> PIN verify.
"use strict";

const $ = (id) => document.getElementById(id);
const show = (el) => el.classList.remove("hidden");
const hide = (el) => el.classList.add("hidden");

function setError(message) {
  const el = $("error");
  if (message) {
    el.textContent = message;
    show(el);
  } else {
    hide(el);
  }
}

async function api(path, body) {
  setError(null);
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `HTTP ${response.status}`);
  }
  return payload;
}

let fiscalId = null;

$("btn-login").addEventListener("click", async () => {
  try {
    fiscalId = $("fiscal-id").value.trim();
    const result = await api("/api/login", { fiscal_id: fiscalId });
    $("vid-label").textContent = result.vid;
    show($("screen-enroll"));
  } catch (e) {
    setError(`Login failed: ${e.message}`);
  }
});

$("btn-enroll").addEventListener("click", async () => {
  try {
    const result = await api("/api/enroll", { fiscal_id: fiscalId });
    $("passphrase").textContent = result.passphrase;
    $("passphrase-input").value = result.passphrase;
    show($("passphrase-box"));
    show($("screen-status"));
  } catch (e) {
    setError(`Enrollment failed: ${e.message}`);
  }
});

$("btn-status").addEventListener("click", async () => {
  try {
    const passphrase = $("passphrase-input").value.trim();
    const result = await api("/api/status", { passphrase });
    if (result.pin_set) {
      $("status-label").textContent = "PIN already retrieved.";
      show($("btn-retrieve"));
    } else if (result.pin_ready) {
      $("status-label").textContent =
        "Enough registration tellers have notified - the PIN is ready.";
      show($("btn-retrieve"));
    } else {
      $("status-label").textContent = "PIN not ready yet - try again shortly.";
    }
  } catch (e) {
    setError(`Status check failed: ${e.message}`);
  }
});

$("btn-retrieve").addEventListener("click", async () => {
  try {
    const passphrase = $("passphrase-input").value.trim();
    const result = await api("/api/pin/retrieve", { passphrase });
    $("pin").textContent = String(result.pin).padStart(8, "0");
    show($("screen-pin"));
  } catch (e) {
    setError(`PIN retrieval failed: ${e.message}`);
  }
});

$("btn-verify").addEventListener("click", async () => {
  try {
    const passphrase = $("passphrase-input").value.trim();
    const pin = parseInt($("pin-input").value, 10);
    const result = await api("/api/pin/verify", { passphrase, pin });
    $("verify-label").textContent = result.valid
      ? "[OK] PIN is valid."
      : "[X] PIN is NOT valid.";
  } catch (e) {
    setError(`Verification failed: ${e.message}`);
  }
});

// -- Voting: build -> cast -> publication check -> CAI confirm ----------

async function refreshPhase() {
  try {
    const response = await fetch("/api/election");
    if (response.ok) {
      const info = await response.json();
      $("phase-label").textContent = info.phase;
    }
  } catch (_) {
    /* phase banner is best-effort */
  }
}
refreshPhase();

$("btn-vote").addEventListener("click", async () => {
  try {
    const passphrase = $("passphrase-input").value.trim();
    const result = await api("/api/vote", {
      passphrase,
      option: $("vote-option").value,
      pin: parseInt($("vote-pin").value, 10),
    });
    $("ballot-digest").textContent = result.digest;
    $("ballot-emoji").textContent = (result.emoji || []).join(" ");
    show($("ballot-box"));
  } catch (e) {
    setError(`Vote failed: ${e.message}`);
  }
});

$("btn-cast").addEventListener("click", async () => {
  try {
    const passphrase = $("passphrase-input").value.trim();
    const result = await api("/api/cast", { passphrase });
    $("cast-label").textContent =
      `Cast to ${result.receipts.length} ballot box(es).`;
    show($("btn-status"));
    show($("btn-confirm"));
  } catch (e) {
    setError(`Cast failed: ${e.message}`);
  }
});

$("btn-status").addEventListener("click", async () => {
  try {
    const passphrase = $("passphrase-input").value.trim();
    const result = await api("/api/ballot/status", { passphrase });
    $("cast-label").textContent = result.no_bot
      ? `[OK] Published by ballot boxes ${result.published_bb_ids.join(", ")} (no bot).`
      : `[!] Published by ${result.published_bb_ids.length} ballot box(es) - fewer than 2 (bot).`;
  } catch (e) {
    setError(`Status check failed: ${e.message}`);
  }
});

$("btn-confirm").addEventListener("click", async () => {
  try {
    const passphrase = $("passphrase-input").value.trim();
    const result = await api("/api/confirm", { passphrase });
    $("cast-label").textContent =
      `[OK] Cast-as-intended proof published (confirmed at ${result.confirmed_at_ms}).`;
  } catch (e) {
    setError(`Confirmation failed: ${e.message}`);
  }
});

// -- PIN & credential management -------------------------------------

$("btn-ruse").addEventListener("click", async () => {
  try {
    const passphrase = $("passphrase-input").value.trim();
    const result = await api("/api/pin/ruse", { passphrase });
    const el = $("ruse-pin");
    el.textContent = String(result.ruse_pin).padStart(8, "0");
    show(el);
    $("manage-label").textContent =
      "Ruse PIN issued - it verifies like the real one, but its ballots are discarded at tally.";
  } catch (e) {
    setError(`Ruse PIN failed: ${e.message}`);
  }
});

$("btn-resend").addEventListener("click", async () => {
  try {
    const passphrase = $("passphrase-input").value.trim();
    const result = await api("/api/pin/resend", { passphrase });
    $("manage-label").textContent = `PIN re-delivered: ${String(result.pin).padStart(8, "0")}`;
  } catch (e) {
    setError(`PIN re-send failed: ${e.message}`);
  }
});

$("btn-revoke").addEventListener("click", async () => {
  try {
    const passphrase = $("passphrase-input").value.trim();
    const result = await api("/api/revoke", { passphrase });
    $("manage-label").textContent =
      `Credential revoked - new pseudonymous id ${result.vid}. Check status, then retrieve your new PIN.`;
  } catch (e) {
    setError(`Revocation failed: ${e.message}`);
  }
});

$("btn-recover").addEventListener("click", async () => {
  try {
    const result = await api("/api/device/recover", {
      fiscal_id: $("recover-fiscal").value.trim(),
      passphrase: $("recover-passphrase").value.trim(),
    });
    $("passphrase-input").value = $("recover-passphrase").value.trim();
    $("manage-label").textContent =
      `Recovered voter ${result.vid} (PIN ${result.pin_set ? "restored" : "not yet retrieved"}).`;
  } catch (e) {
    setError(`Recovery failed: ${e.message}`);
  }
});

$("btn-trusted").addEventListener("click", async () => {
  try {
    const passphrase = $("passphrase-input").value.trim();
    const split = (value) => value.split(",").map((s) => s.trim()).filter(Boolean);
    const result = await api("/api/settings/trusted", {
      passphrase,
      rts: split($("trusted-rts").value),
      bbs: split($("trusted-bbs").value),
    });
    $("manage-label").textContent =
      `Trusted: RTs ${result.rts.join(", ")} - BBs ${result.bbs.join(", ")}.`;
  } catch (e) {
    setError(`Trusted-authority update failed: ${e.message}`);
  }
});
