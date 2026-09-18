// Vote App SPA. Three client-side routes, each a stack of full-height
// screens that are revealed (and scrolled to) as the voter progresses:
//   /enrollment  login -> enroll -> PIN status -> PIN -> verify
//   /voting      build ballot -> cast -> check publication + confirm
//   /management  ruse PIN, re-send, revoke, trusted authorities, recovery
"use strict";

const $ = (id) => document.getElementById(id);
const show = (el) => el.classList.remove("hidden");
const hide = (el) => el.classList.add("hidden");

// -- Errors (toast) --------------------------------------------------------

let errorTimer = null;
function setError(message) {
  const el = $("error");
  clearTimeout(errorTimer);
  if (message) {
    el.textContent = message;
    show(el);
    errorTimer = setTimeout(() => hide(el), 8000);
  } else {
    hide(el);
  }
}
$("error").addEventListener("click", () => setError(null));

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

// -- Screens -----------------------------------------------------------------

// Reveal a screen and jump to it, like moving to the next app screen.
function advanceTo(id) {
  const screen = $(id);
  show(screen);
  // An instant jump, like an app switching view - no animated scrolling.
  requestAnimationFrame(() => screen.scrollIntoView({ behavior: "instant", block: "start" }));
}

function formatTime(ms) {
  if (typeof ms !== "number" || ms < 1e12) return String(ms);
  return new Date(ms).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
}

// -- Passphrase session --------------------------------------------------
// The passphrase gates every call after enrollment. It is kept for this
// browser tab only (sessionStorage), so moving between sections or
// reloading does not ask for it again; closing the tab forgets it.

const PASSPHRASE_KEY = "voteapp.passphrase";

function getPassphrase() {
  try {
    return sessionStorage.getItem(PASSPHRASE_KEY) || "";
  } catch (_) {
    return getPassphrase.memory || "";
  }
}

function setPassphrase(value) {
  getPassphrase.memory = value;
  try {
    sessionStorage.setItem(PASSPHRASE_KEY, value);
  } catch (_) {
    /* storage unavailable: keep it in memory only */
  }
  $("passphrase-input").value = value;
  applyLock();
}

// Voting and management need the passphrase: without one they show an
// unlock screen and hide everything marked `locked`.
function applyLock() {
  const unlocked = getPassphrase() !== "";
  document.querySelectorAll(".screen.unlock").forEach((el) => el.classList.toggle("hidden", unlocked));
  document.querySelectorAll(".screen.locked").forEach((el) => el.classList.toggle("hidden", !unlocked));
  if (unlocked) loadTrusted();
}

document.querySelectorAll(".btn-unlock").forEach((button) => {
  button.addEventListener("click", async () => {
    const input = button.parentElement.querySelector(".unlock-input");
    const passphrase = input.value.trim();
    try {
      await api("/api/status", { passphrase });
      input.value = "";
      setPassphrase(passphrase);
      $("scroller").scrollTo({ top: 0 });
    } catch (e) {
      setError(`Unlock failed: ${e.message}`);
    }
  });
});

// -- Routing -----------------------------------------------------------------

const ROUTES = {
  enrollment: "Enrollment",
  voting: "Voting",
  management: "Management",
};

function routeFromPath(pathname) {
  const name = pathname.replace(/^\/+|\/+$/g, "");
  if (name === "menagement") return "management";
  return Object.hasOwn(ROUTES, name) ? name : "enrollment";
}

function navigate(route, { push = true } = {}) {
  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("hidden", view.dataset.route !== route);
  });
  document.querySelectorAll(".menu-item").forEach((item) => {
    item.classList.toggle("active", item.dataset.route === route);
  });
  closeMenu();
  $("route-title").textContent = ROUTES[route];
  document.title = `${ROUTES[route]} - Vote App`;
  const path = `/${route}`;
  if (location.pathname !== path) {
    history[push ? "pushState" : "replaceState"]({}, "", path);
  }
  $("scroller").scrollTo({ top: 0, behavior: "instant" });
  if (route === "voting") refreshPhase();
}

// Section menu (top right): toggles on its button, closes on selection,
// on a click anywhere else and on Escape.
function closeMenu() {
  hide($("menu"));
  $("btn-menu").setAttribute("aria-expanded", "false");
}

$("btn-menu").addEventListener("click", (event) => {
  event.stopPropagation();
  const open = $("menu").classList.toggle("hidden") === false;
  $("btn-menu").setAttribute("aria-expanded", String(open));
});
document.addEventListener("click", (event) => {
  if (!$("menu").contains(event.target)) closeMenu();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeMenu();
});

document.querySelectorAll("a[data-route]").forEach((link) => {
  link.addEventListener("click", (event) => {
    event.preventDefault();
    navigate(link.dataset.route);
  });
});
window.addEventListener("popstate", () => navigate(routeFromPath(location.pathname), { push: false }));

// -- Enrollment ----------------------------------------------------------------

let fiscalId = null;

$("btn-login").addEventListener("click", async () => {
  try {
    fiscalId = $("fiscal-id").value.trim();
    const result = await api("/api/login", { fiscal_id: fiscalId });
    $("vid-label").textContent = result.vid;
    advanceTo("screen-enroll");
  } catch (e) {
    setError(`Login failed: ${e.message}`);
  }
});

$("btn-enroll").addEventListener("click", async () => {
  try {
    const result = await api("/api/enroll", { fiscal_id: fiscalId });
    $("passphrase").textContent = result.passphrase;
    setPassphrase(result.passphrase);
    hide($("btn-enroll"));
    show($("passphrase-box"));
  } catch (e) {
    setError(`Enrollment failed: ${e.message}`);
  }
});

$("btn-enroll-next").addEventListener("click", () => advanceTo("screen-status"));

$("btn-status").addEventListener("click", async () => {
  try {
    const passphrase = $("passphrase-input").value.trim();
    const result = await api("/api/status", { passphrase });
    setPassphrase(passphrase);
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
    const result = await api("/api/pin/retrieve", { passphrase: getPassphrase() });
    $("pin").textContent = String(result.pin).padStart(8, "0");
    advanceTo("screen-pin");
  } catch (e) {
    setError(`PIN retrieval failed: ${e.message}`);
  }
});

$("btn-pin-next").addEventListener("click", () => advanceTo("screen-verify"));

$("btn-verify").addEventListener("click", async () => {
  try {
    const pin = parseInt($("pin-input").value, 10);
    const result = await api("/api/pin/verify", { passphrase: getPassphrase(), pin });
    $("verify-label").textContent = result.valid
      ? "[OK] PIN is valid. You are ready to vote."
      : "[X] PIN is NOT valid.";
    $("link-to-voting").classList.toggle("hidden", !result.valid);
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

$("btn-vote").addEventListener("click", async () => {
  try {
    const result = await api("/api/vote", {
      passphrase: getPassphrase(),
      option: $("vote-option").value,
      pin: parseInt($("vote-pin").value, 10),
    });
    $("ballot-digest").textContent = result.digest;
    $("ballot-emoji").textContent = (result.emoji || []).join(" ");
    $("cast-label").textContent = "";
    $("publication-label").textContent = "";
    $("confirm-label").textContent = "";
    $("control-check").textContent = "";
    hide($("control-box"));
    setCaiChoice(null);
    hide($("screen-check"));
    advanceTo("screen-cast");
  } catch (e) {
    setError(`Vote failed: ${e.message}`);
  }
});

$("btn-cast").addEventListener("click", async () => {
  try {
    const result = await api("/api/cast", { passphrase: getPassphrase() });
    $("cast-label").textContent = `Cast to ${result.receipts.length} ballot box(es).`;
    await showControlValues();
    advanceTo("screen-check");
  } catch (e) {
    setError(`Cast failed: ${e.message}`);
  }
});

$("btn-publication").addEventListener("click", async () => {
  try {
    const result = await api("/api/ballot/status", { passphrase: getPassphrase() });
    $("publication-label").textContent = result.no_bot
      ? `[OK] Published by ballot boxes ${result.published_bb_ids.join(", ")}: enough for your ballot to be counted once you confirm it.`
      : `[!] Published by only ${result.published_bb_ids.length} ballot box(es). At least 2 are required, otherwise the ballot is discarded at tally - try casting again.`;
  } catch (e) {
    setError(`Publication check failed: ${e.message}`);
  }
});

// Control values (Sec. 3.8.4 step 9): available only after the cast. The sum
// is the code plus the index of the chosen option, modulo 100.
const OPTION_INDEX = { blank: 0, approve: 1, reject: 2 };

async function showControlValues() {
  const pad = (n) => String(n).padStart(2, "0");
  try {
    const values = await api("/api/cai/values", { passphrase: getPassphrase() });
    $("control-code").textContent = pad(values.l1_code);
    $("control-sum").textContent = pad(values.l1_sum);
    const index = (values.l1_sum + 100 - values.l1_code) % 100;
    const option = $("vote-option");
    const expected = OPTION_INDEX[option.value];
    const label = option.options[option.selectedIndex].textContent;
    $("control-check").textContent =
      index === expected
        ? `Check: sum - code = ${index}, the number of "${label}".`
        : `[!] sum - code = ${index}, but "${label}" is number ${expected}. Do NOT confirm this ballot.`;
    document.querySelectorAll(".control-value").forEach((el) => el.classList.remove("opened"));
    show($("control-box"));
  } catch (e) {
    setError(`Control values unavailable: ${e.message}`);
  }
}

// Cast-as-intended choice (Sec. 3.8.4 steps 9-11): made only on this
// screen, i.e. after the ballot has been cast. "Toss a coin" draws it from
// the browser's CSPRNG. The candidate-level value is trivial in a
// referendum, so its coin is always tossed here.
function coin() {
  const byte = new Uint8Array(1);
  crypto.getRandomValues(byte);
  return (byte[0] & 1) === 0 ? "code" : "sum";
}

let caiChoice = null;
function setCaiChoice(slot) {
  caiChoice = slot;
  document.querySelectorAll("#cai-choice .seg[role=radio]").forEach((seg) => {
    seg.setAttribute("aria-checked", String(seg.dataset.slot === slot));
  });
  $("btn-confirm").disabled = slot === null;
}

document.querySelectorAll("#cai-choice .seg").forEach((seg) => {
  seg.addEventListener("click", () => {
    setCaiChoice(seg.dataset.slot === "toss" ? coin() : seg.dataset.slot);
  });
});

$("btn-confirm").addEventListener("click", async () => {
  try {
    const result = await api("/api/confirm", {
      passphrase: getPassphrase(),
      l1: caiChoice,
      l2: coin(),
    });
    const value = String(result.l1_value).padStart(2, "0");
    $(result.l1 === "code" ? "control-code" : "control-sum").parentElement.classList.add("opened");
    $("confirm-label").textContent =
      `[OK] Control ${result.l1} ${value} opened and published (confirmed ${formatTime(result.confirmed_at_ms)}). Your ballot will be counted. Later, look your ballot up on the public bulletin board: it must show this same number.`;
  } catch (e) {
    setError(`Confirmation failed: ${e.message}`);
  }
});

// -- Management ---------------------------------------------------------------

$("btn-ruse").addEventListener("click", async () => {
  try {
    const result = await api("/api/pin/ruse", { passphrase: getPassphrase() });
    const el = $("ruse-pin");
    el.textContent = String(result.ruse_pin).padStart(8, "0");
    show(el);
    $("pin-tools-label").textContent =
      "Ruse PIN issued - it verifies like the real one, but its ballots are discarded at tally.";
  } catch (e) {
    setError(`Ruse PIN failed: ${e.message}`);
  }
});

$("btn-resend").addEventListener("click", async () => {
  try {
    const result = await api("/api/pin/resend", { passphrase: getPassphrase() });
    $("pin-tools-label").textContent = `PIN re-delivered: ${String(result.pin).padStart(8, "0")}`;
  } catch (e) {
    setError(`PIN re-send failed: ${e.message}`);
  }
});

$("btn-revoke").addEventListener("click", async () => {
  const sure = window.confirm(
    "Revoke your credential? Every ballot cast with it becomes void and you get a new id and PIN.",
  );
  if (!sure) return;
  try {
    const result = await api("/api/revoke", { passphrase: getPassphrase() });
    $("revoke-label").textContent =
      `Credential revoked - new pseudonymous id ${result.vid}. Open Enrollment, check the PIN status, then retrieve your new PIN.`;
    show($("screen-status"));
  } catch (e) {
    setError(`Revocation failed: ${e.message}`);
  }
});

let trustedLoaded = false;
async function loadTrusted() {
  if (trustedLoaded) return;
  trustedLoaded = true;
  try {
    const result = await api("/api/settings/trusted/show", { passphrase: getPassphrase() });
    $("trusted-rts").value = (result.rts || []).join(",");
    $("trusted-bbs").value = (result.bbs || []).join(",");
  } catch (_) {
    trustedLoaded = false; /* prefill is best-effort */
    setError(null);
  }
}

$("btn-trusted").addEventListener("click", async () => {
  try {
    const split = (value) => value.split(",").map((s) => s.trim()).filter(Boolean);
    const result = await api("/api/settings/trusted", {
      passphrase: getPassphrase(),
      rts: split($("trusted-rts").value),
      bbs: split($("trusted-bbs").value),
    });
    $("trusted-label").textContent =
      `Trusted: RTs ${result.rts.join(", ")} - BBs ${result.bbs.join(", ")}.`;
  } catch (e) {
    setError(`Trusted-authority update failed: ${e.message}`);
  }
});

$("btn-recover").addEventListener("click", async () => {
  try {
    const passphrase = $("recover-passphrase").value.trim();
    const result = await api("/api/device/recover", {
      fiscal_id: $("recover-fiscal").value.trim(),
      passphrase,
    });
    $("recover-passphrase").value = "";
    $("recover-label").textContent =
      `Recovered voter ${result.vid} (PIN ${result.pin_set ? "restored" : "not yet retrieved"}).`;
    setPassphrase(passphrase);
  } catch (e) {
    setError(`Recovery failed: ${e.message}`);
  }
});

// -- Start ---------------------------------------------------------------------

$("passphrase-input").value = getPassphrase();
applyLock();
navigate(routeFromPath(location.pathname), { push: false });
