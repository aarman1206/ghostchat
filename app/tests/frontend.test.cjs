"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../src/main.js"), "utf8");
const markup = fs.readFileSync(path.join(__dirname, "../src/index.html"), "utf8");

class Element {
  constructor() {
    this.children = [];
    this.events = new Map();
    this.dataset = {};
    this.attributes = new Map();
    this.value = "";
    this.hidden = false;
    this.disabled = false;
    this._text = "";
    const classes = new Set();
    this.classList = {
      add: (...names) => names.forEach((name) => classes.add(name)),
      remove: (...names) => names.forEach((name) => classes.delete(name)),
      toggle: (name, enabled) => enabled ? classes.add(name) : classes.delete(name),
    };
  }
  set textContent(value) { this.children = []; this._text = String(value); }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(" "); }
  append(...children) { this.children.push(...children); }
  appendChild(child) { this.children.push(child); return child; }
  addEventListener(name, handler) { this.events.set(name, handler); }
  setAttribute(name, value) { this.attributes.set(name, value); }
  querySelector() { return this.label ||= new Element(); }
  focus() {}
  async fire(name) { return this.events.get(name)?.({ preventDefault() {} }); }
  requestSubmit() { return this.fire("submit"); }
}

function snapshot(sessionId = "a".repeat(32), overrides = {}) {
  return {
    session_id: sessionId,
    room_name: "Quiet room",
    invite_code: "aabb",
    owner_id: `p-${"a".repeat(64)}`,
    state: "active",
    epoch: 1,
    participants: [{ id: `p-${"a".repeat(64)}`, display_name: "Alice", is_self: true, state: "online" }],
    messages: [],
    transport: "tor-onion-service",
    tor_state: "connected",
    connection_state: "connected",
    encryption_active: true,
    ...overrides,
  };
}

async function load({ desktop = true, broken = false, listenFailure = false, status = { status: "ready", transport: "tor-onion-service" }, handler } = {}) {
  const elements = new Map(Array.from(markup.matchAll(/id="([^"]+)"/g), (match) => [match[1], new Element()]));
  for (const match of markup.matchAll(/<[^>]+\bid="([^"]+)"[^>]*>/g)) {
    elements.get(match[1]).hidden = /\bhidden\b/.test(match[0]);
  }
  const screens = ["home", "onboarding", "create", "join", "room", "chat", "settings", "privacy", "security", "about"].map((name) => {
    const element = elements.get(`screen-${name}`);
    element.dataset.screen = name;
    return element;
  });
  const goButtons = Array.from(markup.matchAll(/<button\b[^>]*>/g), ([tag]) => {
    const destination = tag.match(/\bdata-go="([^"]+)"/);
    if (!destination) return null;
    const element = new Element();
    element.dataset.go = destination[1];
    const historyMode = tag.match(/\bdata-history="([^"]+)"/);
    if (historyMode) element.dataset.history = historyMode[1];
    return element;
  }).filter(Boolean);
  const events = new Map();
  const windowEvents = new Map();
  const calls = [];
  const historyEntries = [{ state: { ghostChatScreen: "home" }, url: "#home" }];
  let historyIndex = 0;
  let statusTimer;
  const document = {
    querySelector: (selector) => elements.get(selector.slice(1)),
    querySelectorAll: (selector) => selector === "[data-screen]" ? screens : selector === "[data-go]" ? goButtons : [],
    createElement: () => new Element(),
    documentElement: { dataset: {} },
  };
  const window = {
    location: { protocol: desktop ? "tauri:" : "http:", hostname: desktop ? "localhost" : "localhost" },
    crypto: { randomUUID: () => "abcdefgh-1234" },
    setTimeout: () => 1,
    clearTimeout() {},
    setInterval: (handler) => { statusTimer = handler; return 1; },
    clearInterval() {},
    matchMedia: () => ({ matches: false }),
    addEventListener: (name, handler) => {
      const listeners = windowEvents.get(name) || [];
      listeners.push(handler);
      windowEvents.set(name, listeners);
    },
    dispatchEvent: (event) => {
      for (const handler of windowEvents.get(event.type) || []) handler(event);
    },
    history: {
      pushState: (state, _title, url) => {
        historyEntries.splice(historyIndex + 1);
        historyEntries.push({ state, url });
        historyIndex = historyEntries.length - 1;
      },
      replaceState: (state, _title, url) => {
        historyEntries[historyIndex] = { state, url };
      },
      back: () => {
        if (historyIndex === 0) return;
        historyIndex -= 1;
        window.dispatchEvent({ type: "popstate", state: historyEntries[historyIndex].state });
      },
    },
    confirm: () => true,
  };
  if (desktop && !broken) {
    window.__TAURI__ = {
      core: { invoke: async (command, args) => {
        calls.push({ command, args });
        if (command === "app_status") return status;
        return handler ? handler(command, args) : snapshot();
      } },
      event: { listen: async (name, handler) => {
        if (listenFailure) throw new Error("event IPC failure");
        events.set(name, handler);
        return () => events.delete(name);
      } },
      app: {
        onBackButtonPress: async (handler) => {
          window.backHandler = handler;
          return { unregister: () => { window.backHandler = undefined; } };
        },
        exit: async (code) => { window.exitCode = code; },
      },
    };
  }
  // All interactions exercise the application through DOM/history handlers
  // and its Tauri event boundary. Persistent storage and logging remain traps.
  const forbidden = new Proxy({}, { get() { throw new Error("unexpected persistent or console access"); } });
  window.localStorage = forbidden;
  window.sessionStorage = forbidden;
  vm.runInNewContext(source, { window, document, navigator: {}, TextEncoder, console: forbidden });
  for (let index = 0; index < 40; index++) await Promise.resolve();
  return {
    elements, calls,
    tick: () => statusTimer?.(),
    back: (payload = {}) => {
      if (historyIndex > 0) window.history.back();
      else window.backHandler?.({ ...payload, canGoBack: false });
    },
    go: async (screen) => {
      const button = goButtons.find((item) => item.dataset.go === screen);
      if (button) await button.fire("click");
    },
    exitCode: () => window.exitCode,
    emit: (name, payload) => events.get(`ghostchat://${name}`)?.({ payload }),
    create: async () => {
      elements.get("create-name").value = "Alice";
      await elements.get("create-form").fire("submit");
    },
    join: async () => {
      elements.get("join-name").value = "Bob";
      elements.get("invite-code").value = "aabb";
      await elements.get("join-form").fire("submit");
    },
  };
}

test("desktop IPC failure never creates a simulated room", async () => {
  const ui = await load({ broken: true });
  await ui.create();
  assert.equal(ui.elements.get("screen-room").hidden, true);
  assert.equal(ui.elements.get("create-submit").disabled, true);
  assert.equal(ui.elements.get("preview-banner").hidden, true);
  assert.match(ui.elements.get("notice-text").textContent, /getting ready/i);
});

test("failed desktop event registration and unavailable Tor keep room actions locked", async () => {
  for (const options of [{ listenFailure: true }, { status: { status: "unavailable", transport: "tor-only" } }]) {
    const ui = await load(options);
    await ui.create();
    assert.equal(ui.elements.get("create-submit").disabled, true);
    assert.equal(ui.calls.filter((call) => call.command === "create_room").length, 0);
    assert.equal(ui.elements.get("preview-banner").hidden, true);
  }
});

test("a stopped Android Tor runtime lets the first room action start it", async () => {
  const ui = await load({ status: { status: "stopped", transport: "tor-only" } });
  assert.equal(ui.elements.get("create-submit").disabled, false, `${ui.elements.get("runtime-label").textContent}; ${ui.elements.get("notice-text").textContent}; calls=${ui.calls.map((call) => call.command).join(",")}`);
  await ui.create();
  assert.equal(ui.calls.filter((call) => call.command === "create_room").length, 1);
  assert.equal(ui.elements.get("create-submit").querySelector(".button-label").textContent, "Create room");
});

test("Android Back returns through chat and room before leaving the app", async () => {
  const ui = await load();
  await ui.create();
  await ui.elements.get("room-enter-chat").fire("click");
  assert.equal(ui.elements.get("screen-chat").hidden, false);
  await ui.back();
  assert.equal(ui.elements.get("screen-room").hidden, false);
  await ui.back();
  assert.equal(ui.elements.get("screen-home").hidden, false);
  await ui.back();
  assert.equal(ui.exitCode(), 0);
});

test("Android WebView Back returns from privacy notes through settings", async () => {
  const ui = await load();
  await ui.go("settings");
  await ui.go("privacy");
  assert.equal(ui.elements.get("screen-privacy").hidden, false);
  await ui.back();
  assert.equal(ui.elements.get("screen-settings").hidden, false);
  await ui.back();
  assert.equal(ui.elements.get("screen-home").hidden, false);
});

test("ordinary browser preview stays explicitly unencrypted with sending locked", async () => {
  const ui = await load({ desktop: false });
  await ui.create();
  await ui.elements.get("room-enter-chat").fire("click");
  assert.match(ui.elements.get("runtime-label").textContent, /preview/i);
  assert.match(ui.elements.get("chat-state-label").textContent, /not encrypted/i);
  assert.equal(ui.elements.get("message-input").disabled, true);
  assert.equal(ui.elements.get("send-submit").disabled, true);
});

test("stale or unscoped events cannot mutate a new room and plaintext is bounded", async () => {
  const room = snapshot("b".repeat(32), {
    messages: Array.from({ length: 700 }, (_, index) => ({ id: `old-${index}`, body: `message ${index}` })),
  });
  const ui = await load({ handler: () => room });
  await ui.create();
  assert.equal(ui.elements.get("message-list").children.length, 500);
  ui.emit("session-state", { session_id: "a".repeat(32), payload: { state: "closed" } });
  ui.emit("session-state", { state: "closed" });
  ui.emit("message", { session_id: "a".repeat(32), payload: { id: "stale", body: "stale plaintext" } });
  assert.equal(ui.elements.get("screen-room").hidden, false);
  assert.doesNotMatch(ui.elements.get("message-list").textContent, /stale plaintext/);
  for (let index = 0; index < 700; index++) {
    ui.emit("message", { session_id: room.session_id, payload: { id: `new-${index}`, body: `live ${index}` } });
  }
  assert.equal(ui.elements.get("message-list").children.length, 500);
  assert.match(ui.elements.get("message-list").textContent, /live 699/);
  await ui.create();
  assert.equal(ui.calls.filter((call) => call.command === "create_room").length, 1);
  ui.emit("session-state", { session_id: room.session_id, payload: { session_id: room.session_id, state: "closed" } });
  assert.equal(ui.elements.get("message-list").children.length, 0);
  assert.equal(ui.elements.get("room-participants-list").children.length, 0);
  assert.equal(ui.elements.get("room-code").textContent, "");
  assert.equal(ui.elements.get("screen-home").hidden, false);
});

test("join remains locked until the room owner approves the request", async () => {
  const pending = snapshot("b".repeat(32), {
    state: "connecting", epoch: 0, encryption_active: false, connection_state: "connecting",
    participants: [{ id: `p-${"b".repeat(64)}`, display_name: "Bob", is_self: true, state: "joining" }],
  });
  const ui = await load({ handler: () => pending });
  await ui.join();
  assert.equal(ui.elements.get("room-enter-chat").disabled, true);
  assert.equal(ui.elements.get("room-shutdown").textContent, "Leave room");
  assert.match(ui.elements.get("room-enter-chat").label.textContent, /Securing room/i);
  ui.emit("session-state", { session_id: pending.session_id, payload: { ...pending, epoch: 1 } });
  assert.equal(ui.elements.get("room-enter-chat").disabled, true);
  assert.match(ui.elements.get("room-enter-chat").label.textContent, /room owner/i);
  ui.emit("session-state", { session_id: pending.session_id, payload: { ...pending, state: "active", encryption_active: true, connection_state: "connected" } });
  assert.equal(ui.elements.get("room-enter-chat").disabled, false);
});

test("pending sends are single-flight and failed delivery is shown as unknown", async () => {
  let rejectSend;
  const ui = await load({ handler: (command) => command === "send_message" ? new Promise((_, reject) => { rejectSend = reject; }) : snapshot() });
  await ui.create();
  ui.elements.get("message-input").value = "private draft";
  const sending = ui.elements.get("message-form").fire("submit");
  await ui.elements.get("message-form").fire("submit");
  assert.equal(ui.calls.filter((call) => call.command === "send_message").length, 1);
  assert.equal(ui.elements.get("send-submit").disabled, true);
  assert.match(ui.elements.get("composer-state").textContent, /Sending/);
  rejectSend(new Error("timeout"));
  await sending;
  assert.match(ui.elements.get("composer-state").textContent, /unknown/i);
  assert.equal(ui.elements.get("message-input").value, "private draft");
  assert.equal(ui.elements.get("send-submit").disabled, false);
});

test("queued messages remain delivery-unconfirmed and peer disconnect does not end the room", async () => {
  const room = snapshot(undefined, {
    participants: [...snapshot().participants, { id: `p-${"b".repeat(64)}`, display_name: "Bob", state: "online" }],
  });
  const ui = await load({ handler: (command, args) => command === "send_message"
    ? { message: { id: "queued", sender_id: room.owner_id, body: args.body }, snapshot: { ...room, messages: [{ id: "queued", sender_id: room.owner_id, body: args.body }] } }
    : room });
  await ui.create();
  ui.elements.get("message-input").value = "queued body";
  await ui.elements.get("message-form").fire("submit");
  assert.match(ui.elements.get("message-list").textContent, /Delivery unconfirmed/);
  assert.match(ui.elements.get("composer-state").textContent, /queued/);
  ui.emit("participant-left", { session_id: room.session_id, payload: { id: `p-${"b".repeat(64)}`, display_name: "Bob", state: "offline" } });
  assert.equal(ui.elements.get("screen-room").hidden, false);
  assert.match(ui.elements.get("message-list").textContent, /queued body/);
  assert.match(ui.elements.get("room-participants-list").textContent, /offline/);
  ui.emit("session-state", { session_id: room.session_id, payload: { ...room, connection_state: "disconnected", state: "closed" } });
  assert.equal(ui.elements.get("screen-home").hidden, false);
  assert.equal(ui.elements.get("message-list").textContent, "");
});

test("Tor status loss locks an existing room without showing a connected send state", async () => {
  const status = { status: "ready", transport: "tor-onion-service" };
  const ui = await load({ status });
  await ui.create();
  assert.equal(ui.elements.get("send-submit").disabled, false);
  status.status = "unavailable";
  await ui.tick();
  assert.equal(ui.elements.get("send-submit").disabled, true);
  assert.match(ui.elements.get("chat-state-label").textContent, /unavailable/i);
  assert.equal(ui.elements.get("room-tor-state").textContent, "Unavailable");
});

test("a late snapshot response cannot revive an old room", async () => {
  let current;
  let creations = 0;
  let reads = 0;
  let resolveOldSnapshot;
  const ui = await load({ handler: (command) => {
    if (command === "create_room") current = snapshot((creations++ ? "b" : "a").repeat(32));
    if (command === "get_session_snapshot" && ++reads === 2) {
      return new Promise((resolve) => { resolveOldSnapshot = resolve; });
    }
    return current;
  } });
  await ui.create();
  const old = current;
  const opening = ui.elements.get("room-enter-chat").fire("click");
  ui.emit("session-state", { session_id: old.session_id, payload: { state: "closed" } });
  await ui.create();
  resolveOldSnapshot({ ...old, room_name: "Stale room", messages: [{ id: "old", body: "old plaintext" }] });
  await opening;
  assert.doesNotMatch(ui.elements.get("room-title").textContent, /Stale/);
  assert.doesNotMatch(ui.elements.get("message-list").textContent, /old plaintext/);
  assert.equal(ui.elements.get("screen-room").hidden, false);
});

test("capacity and invalid-invitation errors have actionable private-safe labels", async () => {
  const ui = await load();
  await ui.create();
  ui.emit("error", { session_id: snapshot().session_id, message: "The room is full." });
  assert.match(ui.elements.get("notice-text").textContent, /three participants/);
  ui.emit("error", { session_id: snapshot().session_id, message: "invitation authentication failed" });
  assert.match(ui.elements.get("notice-text").textContent, /invitation is invalid/);
  ui.elements.get("message-input").value = "first\nsecond";
  await ui.elements.get("message-form").fire("submit");
  assert.match(ui.elements.get("notice-text").textContent, /line breaks/);
  assert.equal(ui.calls.filter((call) => call.command === "send_message").length, 0);
});

test("onboarding, settings, theme and product information stay frontend-only", async () => {
  const ui = await load();
  await ui.elements.get("home-onboarding").fire("click");
  assert.equal(ui.elements.get("screen-onboarding").hidden, false);
  assert.match(markup, /invite is verified and the room owner confirms the join/i);

  await ui.elements.get("settings-button").fire("click");
  assert.equal(ui.elements.get("screen-settings").hidden, false);
  await ui.elements.get("theme-light").fire("click");
  assert.equal(ui.elements.get("theme-light").attributes.get("aria-pressed"), "true");
  assert.match(ui.elements.get("theme-status").textContent, /Light theme selected/);
  assert.equal(ui.calls.filter((call) => call.command === "settings").length, 0);

  await ui.elements.get("help-button").fire("click");
  assert.equal(ui.elements.get("screen-about").hidden, false);
  assert.match(markup, /not been independently audited or certified/);
});

test("form validation exposes an inline accessible error and clears when corrected", async () => {
  const ui = await load();
  await ui.elements.get("create-form").fire("submit");
  assert.equal(ui.elements.get("create-name-error").hidden, false);
  assert.match(ui.elements.get("create-name-error").textContent, /display name/);
  assert.equal(ui.elements.get("create-name").attributes.get("aria-invalid"), "true");
  await ui.elements.get("create-name").fire("input");
  assert.equal(ui.elements.get("create-name-error").hidden, true);
  assert.equal(ui.elements.get("create-name").attributes.get("aria-invalid"), "false");
});
