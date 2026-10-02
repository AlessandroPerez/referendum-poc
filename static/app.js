// Vote App SPA. Three client-side routes, each a stack of full-height
// screens that are revealed (and scrolled to) as the voter progresses:
//   /enrollment  login -> enroll -> PIN status -> PIN -> verify
//   /voting      build ballot -> cast -> check publication + confirm
//   /management  ruse PIN, re-send, revoke, trusted authorities, recovery
"use strict";

const $ = (id) => document.getElementById(id);
const show = (el) => el.classList.remove("hidden");
const hide = (el) => el.classList.add("hidden");

// Tap-to-copy: the PIN and the ballot digest (Sec. 3.8.4 step 8 has the
// voter copy H(B)) go to the clipboard when tapped; the value flashes blue
// and a toast says what was copied.
function toast(message) {
  let el = document.getElementById("toast");
  if (!el) {
    el = document.createElement("div");
    el.id = "toast";
    el.setAttribute("role", "status");
    document.body.appendChild(el);
  }
  el.textContent = message;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.remove(), 1800);
}

async function copyValue(el) {
  const text = (el.textContent || "").trim();
  if (!text || text === "--") return;
  try {
    await navigator.clipboard.writeText(text);
    el.classList.add("flash");
    setTimeout(() => el.classList.remove("flash"), 600);
    toast(`${el.dataset.copyName || "Value"} copied to the clipboard`);
  } catch (e) {
    setError("Copy failed - select the value and copy it by hand.");
  }
}

document.addEventListener("click", (event) => {
  const el = event.target.closest(".copy-on-click");
  if (el) copyValue(el);
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const el = event.target.closest && event.target.closest(".copy-on-click");
  if (el) {
    event.preventDefault();
    copyValue(el);
  }
});

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

// The PIN the voter last typed to build a ballot. Every screen that works on
// a held ballot names it, so the app asks about the ballot THAT PIN built and
// no other - which is what makes the decoy of Sec. 3.7.3 a complete story and
// keeps a PIN nobody used away from somebody else's ballot. Kept in memory
// only: it is never stored and never leaves the device.
let ballotPin = null;

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
    // Enrolled, but the PIN request did not go through: the passphrase is
    // still the voter's, and a re-send asks again.
    if (result.warning) setError(result.warning);
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
    } else if (result.pin_request_open === false) {
      $("status-label").textContent =
        "No PIN request is open for this credential - use \"Re-send my PIN\" under PIN tools.";
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
    $("pin").textContent = String(result.pin).padStart(5, "0");
    $("pin-emoji").textContent = (result.private_pin_emoji || []).join(" ");
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
    // Shown either way: it says WHICH PIN the app processed.
    $("verify-emoji").textContent = (result.private_pin_emoji || []).join(" ");
    show($("verify-emoji"));
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
    if (!$("vote-option").value) {
      setError("Choose an option first.");
      return;
    }
    const pin = parseInt($("vote-pin").value, 10);
    const result = await api("/api/vote", {
      passphrase: getPassphrase(),
      option: $("vote-option").value,
      pin,
    });
    ballotPin = pin;
    $("ballot-digest").textContent = result.digest;
    $("ballot-emoji").textContent = (result.emoji || []).join(" ");
    $("ballot-private-emoji").textContent = (result.private_pin_emoji || []).join(" ");
    $("ballot-public-emoji").textContent = (result.public_pin_emoji || []).join(" ");
    $("cast-label").textContent = result.awaiting_confirmation
      ? `[!] Ballot ${result.awaiting_confirmation} is already cast and still unconfirmed. It is the one the check-and-confirm screen acts on, and it does NOT count until you confirm it.`
      : "";
    $("publication-label").textContent = "";
    $("confirm-label").textContent = "";
    $("control-check").textContent = "";
    hide($("control-box"));
    controlValuesShown = false;
    controlValuesDigest = null;
    setCaiChoice(null);
    hide($("screen-check"));
    advanceTo("screen-cast");
  } catch (e) {
    setError(`Vote failed: ${e.message}`);
  }
});

$("btn-cast").addEventListener("click", async () => {
  try {
    // The ballot on screen, by its digest: never another one this PIN holds.
    const result = await api("/api/cast", {
      passphrase: getPassphrase(),
      pin: ballotPin,
      digest: $("ballot-digest").textContent || undefined,
    });
    const refused =
      result.refused_bb_ids && result.refused_bb_ids.length
        ? ` [!] Ballot box(es) ${result.refused_bb_ids.join(", ")} did not accept it. What counts is what the bulletin board shows: check the publication below.`
        : "";
    $("cast-label").textContent = `Cast to ${result.receipts.length} ballot box(es).${refused}`;
    await showControlValues();
    advanceTo("screen-check");
  } catch (e) {
    setError(`Cast failed: ${e.message}`);
  }
});

$("btn-publication").addEventListener("click", async () => {
  try {
    const result = await api("/api/ballot/status", {
      passphrase: getPassphrase(),
      pin: ballotPin,
    });
    // Once the electoral roll has published the list the tally is built from,
    // a voter whose identifier is missing from it would otherwise never find
    // out: their ballot is dropped at the last filter with nothing to see.
    if (result.on_eligible_list === false) {
      $("publication-label").textContent =
        "[!] The electoral roll's published list of eligible voters does NOT include you: your ballot cannot be counted. Report this.";
      return;
    }
    const oneBoxOnly = result.no_bot
      ? ""
      : ` [!] Only ${result.published_bb_ids.length} ballot box published it - casting again is safer.`;
    $("publication-label").textContent = result.will_be_counted
      ? `[OK] Published by ballot box(es) ${result.published_bb_ids.join(", ")}, confirmed by ${result.confirmed_bb_ids.join(", ")}: counted unless you vote again.${oneBoxOnly}`
      : result.published_bb_ids.length > 0 && result.confirmed_bb_ids.length > 0
      ? `[!] Published and confirmed, but the board does not show the confirmation this app sealed: NOT counted - confirm again and report it.${oneBoxOnly}`
      : result.published_bb_ids.length > 0
      ? `[OK] Published by ballot box(es) ${result.published_bb_ids.join(", ")}: counted once you confirm.${oneBoxOnly}`
      : `[!] No ballot box has published your ballot: NOT counted - cast again.`;
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
    const values = await api("/api/cai/values", {
      passphrase: getPassphrase(),
      pin: ballotPin,
    });
    controlValuesDigest = values.digest;
    // More than one ballot of this PIN may be cast and waiting: each still
    // has to be confirmed or it is dropped at tally, so say so rather than
    // let the older ones go unnoticed.
    const waiting = (values.awaiting_confirmation || []).filter((d) => d !== values.digest);
    if (waiting.length) {
      setError(
        `[!] ${waiting.length} earlier ballot(s) of this PIN are also cast and unconfirmed: ${waiting.join(", ")}. Only your most recent ballot counts: confirm this one, and the earlier ones are replaced by it.`,
      );
    }
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
    controlValuesShown = true;
  } catch (e) {
    // Sec. 3.8.4 step 9 is the voter's check that the ballot says what they
    // chose. Confirming without it opens a control value of a ballot nobody
    // has checked, so the screen refuses to go on rather than letting the
    // voter past a step they never made.
    controlValuesShown = false;
    controlValuesDigest = null;
    hide($("control-box"));
    $("control-check").textContent =
      "[!] The control values could not be shown, so the check of step 9 cannot be made. Do NOT confirm: try this screen again.";
    setError(`Control values unavailable: ${e.message}`);
  }
  refreshConfirmButton();
}

// Cast-as-intended choices (Sec. 3.8.4 steps 9-11): made only on this screen,
// i.e. after the ballot has been cast, and made by THE VOTER - step 10 has V
// "perform the two random selections, preferably tossing a coin twice". The
// app draws nothing here: a choice this device could predict is a choice it
// could have worked around when it sealed the ballot.
let caiChoice = null;
// A referendum has one candidate per option, so both candidate-level values
// are always equal and no choice is made there: the app opens a fixed slot
// (Sec. 3.11).
const CAI_L2_FIXED = "code";
// The ballot the control values on the screen belong to.
let controlValuesDigest = null;
// Set only when the control values of THIS ballot are on the screen.
let controlValuesShown = false;

function refreshConfirmButton() {
  $("btn-confirm").disabled = caiChoice === null || !controlValuesShown;
}

function setCaiChoice(slot) {
  caiChoice = slot;
  document.querySelectorAll("#control-box .control-value[role=radio]").forEach((value) => {
    value.setAttribute("aria-checked", String(value.dataset.slot === slot));
  });
  refreshConfirmButton();
}

// The voter picks which value is opened by tapping it (Sec. 3.8.4 step 10).
document.querySelectorAll("#control-box .control-value[role=radio]").forEach((value) => {
  value.addEventListener("click", () => setCaiChoice(value.dataset.slot));
  value.addEventListener("keydown", (event) => {
    if (event.key === " " || event.key === "Enter") {
      event.preventDefault();
      setCaiChoice(value.dataset.slot);
    }
  });
});

$("btn-confirm").addEventListener("click", async () => {
  try {
    const result = await api("/api/confirm", {
      passphrase: getPassphrase(),
      pin: ballotPin,
      // The ballot whose control values this screen showed (Sec. 3.8.4 steps
      // 9-11): the app refuses to open a value of any other.
      digest: controlValuesDigest,
      l1: caiChoice,
      l2: CAI_L2_FIXED,
    });
    const value = String(result.l1_value).padStart(2, "0");
    // The opened value shows as OPENED from here on; the choice is made and
    // the values stop acting as a selector.
    setCaiChoice(null);
    $(result.l1 === "code" ? "control-code" : "control-sum").parentElement.classList.add("opened");
    const liars =
      result.lying_boxes && result.lying_boxes.length
        ? ` [!] Ballot box(es) ${result.lying_boxes.join(", ")} published values this app did not seal. Report them - the board carries the evidence.`
        : "";
    const silent =
      result.silent_boxes && result.silent_boxes.length
        ? ` [!] Ballot box(es) ${result.silent_boxes.join(", ")} did not answer.`
        : "";
    // A refusal is not silence: no retry changes it. One box refusing while
    // another publishes still counts the ballot, but the voter is the only
    // one who can react in time - casting again is the remedy.
    const refused =
      result.refused_boxes && result.refused_boxes.length
        ? ` [!] Ballot box(es) ${result.refused_boxes
            .map((r) => `${r.bb_id} (${r.reason})`)
            .join(", ")} refused this confirmation. Report it; if your ballot is not counted, vote and cast again.`
        : "";
    $("confirm-label").textContent =
      (result.will_be_counted
        ? `[OK] ${result.l1} ${value} published by ballot box(es) ${result.counting_bb_ids.join(", ")} at ${formatTime(result.confirmed_at_ms)} (this device's clock - if that is not now, distrust this device). Your ballot counts unless you vote again; the public board must show this same number.`
        : `[!] ${result.l1} ${value} opened, but the board shows no confirmation: NOT counted - confirm again and report it.`) +
      liars +
      silent +
      refused;
  } catch (e) {
    setError(`Confirmation failed: ${e.message}`);
  }
});

// -- Management ---------------------------------------------------------------

$("btn-ruse").addEventListener("click", async () => {
  try {
    // Sec. 3.7.3 step 3 has the VOTER type the ruse PIN. An empty box means
    // "draw one for me"; a value means "arm this one", so a decoy already
    // given to someone can be armed again on this or another device.
    const current = $("ruse-current-pin").value.trim();
    if (!/^[0-9]{1,5}$/.test(current)) {
      setError("Type the PIN this app holds: arming a decoy is your own request to make.");
      return;
    }
    const chosen = $("ruse-pin-input").value.trim();
    const body = { passphrase: getPassphrase(), pin: Number(current) };
    if (chosen !== "") {
      const value = Number(chosen);
      if (!/^[0-9]{1,5}$/.test(chosen) || !Number.isInteger(value)) {
        setError("A ruse PIN is up to 5 digits.");
        return;
      }
      body.ruse_pin = value;
    }
    const result = await api("/api/pin/ruse", body);
    const el = $("ruse-pin");
    el.textContent = String(result.ruse_pin).padStart(5, "0");
    show(el);
    $("ruse-emoji").textContent = (result.private_pin_emoji || []).join(" ");
    show($("ruse-emoji"));
    $("pin-tools-label").textContent =
      "Ruse PIN issued - it verifies like the real one, but its ballots are discarded at tally.";
  } catch (e) {
    setError(`Ruse PIN failed: ${e.message}`);
  }
});

$("btn-resend").addEventListener("click", async () => {
  // A re-send is a new PIN request: the tellers answer only after their
  // waiting period, so this takes a few seconds. One request at a time.
  const button = $("btn-resend");
  // Sec. 3.7.2 step 4: while the PIN is being re-sent the voting, PIN
  // management and verification functions are disabled - the device is
  // holding its write lock for the tellers' waiting period, and a tap on
  // another screen would only queue behind it in silence.
  const blocked = ["btn-vote", "btn-cast", "btn-confirm", "btn-publication", "btn-ruse", "btn-revoke", "btn-verify", "btn-recover"]
    .map((id) => document.getElementById(id))
    .filter(Boolean);
  const wasDisabled = blocked.map((el) => el.disabled);
  button.disabled = true;
  blocked.forEach((el) => (el.disabled = true));
  $("pin-tools-label").textContent =
    "Asking the registration tellers again - this takes a few seconds. Voting and PIN screens are paused until it finishes.";
  try {
    const result = await api("/api/pin/resend", { passphrase: getPassphrase() });
    $("pin-tools-label").textContent = `PIN re-delivered: ${String(result.pin).padStart(5, "0")}. Any decoy is disarmed - arm it again if you need it.`;
  } catch (e) {
    $("pin-tools-label").textContent = "";
    setError(`PIN re-send failed: ${e.message}. Try again in a few seconds.`);
  } finally {
    button.disabled = false;
    blocked.forEach((el, i) => (el.disabled = wasDisabled[i]));
    refreshConfirmButton();
  }
});

$("btn-revoke").addEventListener("click", async () => {
  const sure = window.confirm(
    "Revoke your credential? Every ballot cast with it becomes void and you get a new id and PIN.",
  );
  if (!sure) return;
  // One revocation at a time: each one spends a spare identifier (Sec.
  // 3.7.5, n_ACC - n_V in all), and a second tap while the first is still
  // waiting on the tellers would revoke the NEW credential too.
  const button = $("btn-revoke");
  button.disabled = true;
  $("revoke-label").textContent = "Revoking - this takes a few seconds. Do not tap again.";
  try {
    const result = await api("/api/revoke", { passphrase: getPassphrase() });
    $("revoke-label").textContent =
      `Credential revoked - new pseudonymous id ${result.vid}. Open Enrollment, check the PIN status, then retrieve your new PIN.`;
    show($("screen-status"));
  } catch (e) {
    $("revoke-label").textContent = "";
    setError(e.message.includes("revoked") ? e.message : `Revocation failed: ${e.message}`);
  } finally {
    button.disabled = false;
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
