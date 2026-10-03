(() => {
  "use strict";

  const tauri = window.__TAURI__;
  const invoke = typeof tauri?.core?.invoke === "function"
    ? tauri.core.invoke.bind(tauri.core)
    : null;
  const listen = typeof tauri?.event?.listen === "function"
    ? tauri.event.listen.bind(tauri.event)
    : null;
  const desktopContext = Boolean(
    tauri
      || window.__TAURI_INTERNALS__
      || window.location.protocol === "tauri:"
      || window.location.hostname === "tauri.localhost",
  );
  const bridgeReady = Boolean(invoke && listen);
  const MAX_SESSION_ITEMS = 500;

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => Array.from(document.querySelectorAll(selector));

  const elements = {
    runtimeChip: $("#runtime-chip"),
    runtimeDot: $("#runtime-dot"),
    runtimeLabel: $("#runtime-label"),
    previewBanner: $("#preview-banner"),
    notice: $("#notice"),
    noticeMark: $("#notice-mark"),
    noticeText: $("#notice-text"),
    noticeDismiss: $("#notice-dismiss"),
    createForm: $("#create-form"),
    createSubmit: $("#create-submit"),
    createName: $("#create-name"),
    createRoomName: $("#create-room-name"),
    joinForm: $("#join-form"),
    joinSubmit: $("#join-submit"),
    joinName: $("#join-name"),
    inviteCode: $("#invite-code"),
    roomBackAction: $("#room-back-action"),
    roomTitle: $("#room-title"),
    roomWelcomeName: $("#room-welcome-name"),
    roomWelcomeCopy: $("#room-welcome-copy"),
    roomCode: $("#room-code"),
    copyInvite: $("#copy-invite"),
    roomParticipantCount: $("#room-participant-count"),
    roomParticipantsList: $("#room-participants-list"),
    roomEmptyParticipants: $("#room-empty-participants"),
    roomSessionState: $("#room-session-state"),
    roomEpoch: $("#room-epoch"),
    roomTransport: $("#room-transport"),
    roomConnectionState: $("#room-connection-state"),
    roomTorState: $("#room-tor-state"),
    roomEncryptionState: $("#room-encryption-state"),
    roomAdvanceEpoch: $("#room-advance-epoch"),
    roomShutdown: $("#room-shutdown"),
    roomEnterChat: $("#room-enter-chat"),
    chatBackRoom: $("#chat-back-room"),
    chatTitle: $("#chat-title"),
    chatStateDot: $("#chat-state-dot"),
    chatStateLabel: $("#chat-state-label"),
    chatEpochLabel: $("#chat-epoch-label"),
    chatRoomDetails: $("#chat-room-details"),
    chatShutdown: $("#chat-shutdown"),
    chatParticipantCount: $("#chat-participant-count"),
    chatParticipantsList: $("#chat-participants-list"),
    chatEmptyParticipants: $("#chat-empty-participants"),
    chatInviteCode: $("#chat-invite-code"),
    messageList: $("#message-list"),
    messageListHint: $("#message-list-hint"),
    emptyMessages: $("#empty-messages"),
    messageForm: $("#message-form"),
    messageInput: $("#message-input"),
    sendSubmit: $("#send-submit"),
    composer: $("#message-form"),
    composerState: $("#composer-state"),
    sidebarRoomCard: $("#sidebar-room-card"),
    sidebarRoomName: $("#sidebar-room-name"),
    sidebarRoomDot: $("#sidebar-room-dot"),
    sidebarRoomState: $("#sidebar-room-state"),
  };

  const app = {
    screen: "home",
    runtime: bridgeReady ? "tauri" : desktopContext ? "unavailable" : "browser",
    transport: bridgeReady ? "tor-only" : desktopContext ? "unavailable" : "browser-preview",
    room: null,
    participants: [],
    messages: [],
    displayName: "",
    sessionState: "preparing",
    epoch: null,
    selfParticipantId: "",
    isCreator: false,
    coreState: bridgeReady ? "checking" : desktopContext ? "unavailable" : "preview",
    sendPending: false,
    lastSendState: "idle",
    sessionGeneration: 0,
    newRoomPending: false,
    eventsReady: false,
    returnToChat: false,
    noticeTimer: null,
    listeners: [],
    statusCheckInFlight: false,
    statusTimer: null,
  };

  function text(value, fallback = "") {
    if (value === null || value === undefined) return fallback;
    if (typeof value === "string") return value;
    if (typeof value === "number" || typeof value === "boolean") return String(value);
    return fallback;
  }

  function numberOrNull(value) {
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value))) return Number(value);
    return null;
  }

  function boundedItems(value, map = (item) => item) {
    return Array.isArray(value) ? value.slice(-MAX_SESSION_ITEMS).map(map) : [];
  }

  function unwrap(value) {
    if (typeof value !== "string") return value || {};
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === "object" ? parsed : { value };
    } catch {
      return { value };
    }
  }

  function firstValue(source, keys, fallback = "") {
    if (!source || typeof source !== "object") return fallback;
    for (const key of keys) {
      const value = source[key];
      if (value !== undefined && value !== null && value !== "") return value;
    }
    return fallback;
  }

  function setText(element, value, fallback = "") {
    if (element) element.textContent = text(value, fallback);
  }

  function setBusy(button, busy) {
    if (!button) return;
    button.disabled = busy;
    button.classList.toggle("is-busy", busy);
    button.setAttribute("aria-busy", busy ? "true" : "false");
  }

  function setNotice(kind, message) {
    if (!elements.notice || !elements.noticeText) return;
    window.clearTimeout(app.noticeTimer);
    elements.notice.dataset.tone = kind;
    elements.noticeMark.textContent = kind === "error" ? "!" : kind === "success" ? "✓" : "i";
    elements.noticeText.textContent = message;
    elements.notice.hidden = false;
    if (kind !== "error") {
      app.noticeTimer = window.setTimeout(() => {
        elements.notice.hidden = true;
      }, 6200);
    }
  }

  function clearNotice() {
    window.clearTimeout(app.noticeTimer);
    if (elements.notice) elements.notice.hidden = true;
  }

  function humanizeError(error, fallback) {
    const raw = text(error?.message || error?.error || error, "").toLowerCase();
    if (raw.includes("room is full") || raw.includes("participant limit")) {
      return "This room already has three participants. Ask the owner to free a place before joining.";
    }
    if (raw.includes("closed") || raw.includes("shutdown") || raw.includes("ended")) {
      return "This session has already ended. Start or join a new room.";
    }
    if (raw.includes("invitation") && (raw.includes("invalid") || raw.includes("authentication") || raw.includes("unsupported"))) {
      return "That invitation is invalid or belongs to an incompatible build. Ask the owner for a new code.";
    }
    if (raw.includes("unknown command") || raw.includes("not found") || raw.includes("unrecognized")) {
      return "This GhostChat build does not expose that room action yet.";
    }
    if (raw.includes("permission") || raw.includes("access denied")) {
      return "GhostChat could not access the local session. Check app permissions and try again.";
    }
    if (raw.includes("timeout") || raw.includes("timed out")) {
      return "The session took too long to respond. Check the room and try again.";
    }
    if (raw.includes("unknown") && raw.includes("deliver")) {
      return "Delivery status is unknown. Check the room before sending again to avoid a duplicate.";
    }
    if (raw.includes("ipc") || raw.includes("desktop context") || raw.includes("core unavailable")) {
      return "GhostChat's desktop connection is unavailable. Restart the app before using room actions.";
    }
    if (raw.includes("welcome") || raw.includes("connecting") || raw.includes("bootstrap")) {
      return "The secure room is still connecting through Tor. Wait for the Welcome or start a fresh join.";
    }
    if (raw.includes("tor") || raw.includes("onion")) {
      return "Tor is unavailable or not bootstrapped. Start Tor and refresh its status before trying again.";
    }
    if (raw.includes("invite") || raw.includes("code") || raw.includes("room")) {
      return "That room could not be reached. Check the invite code and try again.";
    }
    return fallback;
  }

  function setRuntimeStatus(kind, label) {
    elements.runtimeChip.classList.remove("is-ready", "is-browser", "is-connecting", "is-error");
    elements.runtimeDot.classList.remove("is-ready", "is-browser", "is-connecting", "is-error");
    elements.runtimeChip.classList.add(`is-${kind}`);
    elements.runtimeDot.classList.add(`is-${kind}`);
    setText(elements.runtimeLabel, label);
  }

  function showScreen(screen) {
    const next = ["home", "create", "join", "room", "chat"].includes(screen) ? screen : "home";
    app.screen = next;
    $$('[data-screen]').forEach((section) => {
      section.hidden = section.dataset.screen !== next;
    });
    $$('[data-go]').forEach((button) => {
      button.classList.toggle("is-active", button.dataset.go === next || (next === "room" && button.dataset.go === "home"));
    });
    if (next === "room") renderRoom();
    if (next === "chat") renderChat();
    if (next === "create") window.setTimeout(() => elements.createName?.focus(), 0);
    if (next === "join") window.setTimeout(() => elements.joinName?.focus(), 0);
  }

  function normaliseParticipant(value, index = 0) {
    if (typeof value === "string") {
      return { id: value, name: value, online: true, self: false };
    }
    const item = value && typeof value === "object" ? value : {};
    const id = text(firstValue(item, ["id", "participant_id", "user_id", "client_id"], `participant-${index + 1}`), `participant-${index + 1}`);
    const name = text(firstValue(item, ["display_name", "name", "username", "identity"], "Guest"), "Guest").trim() || "Guest";
    const state = text(firstValue(item, ["state", "status", "presence"], "online"), "online").toLowerCase();
    return {
      id,
      name,
      state,
      online: ["online", "active", "connected"].includes(state),
      self: item.self === true || item.is_self === true,
    };
  }

  function normaliseMessage(value, index = 0) {
    if (typeof value === "string") {
      return { id: `message-${index + 1}`, body: value, sender: "Guest", senderId: "", mine: false, system: false, time: "" };
    }
    const item = value && typeof value === "object" ? value : {};
    const senderObject = item.sender && typeof item.sender === "object" ? item.sender : {};
    const sender = text(firstValue(item, ["sender_name", "display_name", "author", "from"], firstValue(senderObject, ["display_name", "name"], "Guest")), "Guest").trim() || "Guest";
    const senderId = text(firstValue(item, ["sender_id", "participant_id", "author_id"], firstValue(senderObject, ["id", "participant_id"], "")), "");
    const body = text(firstValue(item, ["body", "content", "message", "text"], ""), "");
    const timestamp = firstValue(item, ["timestamp", "sent_at", "created_at", "time"], "");
    const date = timestamp ? new Date(timestamp) : null;
    const formattedTime = date && !Number.isNaN(date.getTime())
      ? date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })
      : text(timestamp, "");
    return {
      id: text(firstValue(item, ["id", "message_id"], `message-${index + 1}`), `message-${index + 1}`),
      body,
      sender,
      senderId,
      mine: item.mine === true || item.is_self === true,
      system: item.system === true || item.kind === "system",
      time: formattedTime,
    };
  }

  function makePreviewCode() {
    if (window.crypto?.randomUUID) return `PREVIEW-${window.crypto.randomUUID().slice(0, 8).toUpperCase()}`;
    return `PREVIEW-${Math.random().toString(36).slice(2, 10).toUpperCase()}`;
  }

  function roomFromResponse(result, defaults = {}) {
    const raw = unwrap(result);
    const source = raw.room && typeof raw.room === "object"
      ? raw.room
      : raw.session && typeof raw.session === "object"
        ? raw.session
        : raw;
    const roomName = text(firstValue(source, ["room_name", "name", "title"], defaults.roomName || "GhostChat room"), defaults.roomName || "GhostChat room").trim() || "GhostChat room";
    const inviteCode = text(firstValue(source, ["invite_code", "room_code", "code", "invite", "join_code"], defaults.inviteCode || ""), defaults.inviteCode || "").trim();
    const sessionId = text(firstValue(source, ["session_id", "sessionId", "id"], defaults.sessionId || ""), defaults.sessionId || "").trim();
    const hasParticipants = Array.isArray(source.participants);
    const hasMessages = Array.isArray(source.messages);
    const participants = hasParticipants
      ? boundedItems(source.participants, normaliseParticipant)
      : [];
    const messages = hasMessages
      ? boundedItems(source.messages, normaliseMessage).filter((message) => message.body || message.system)
      : [];
    const rawEncryptionActive = firstValue(source, ["encryption_active", "encryptionActive", "encrypted"], undefined);
    const hasEncryptionActive = rawEncryptionActive !== undefined;
    const encryptionActive = hasEncryptionActive ? rawEncryptionActive : defaults.encryptionActive;
    return {
      roomName,
      inviteCode,
      sessionId,
      participants,
      messages,
      state: text(firstValue(source, ["state", "session_state", "status"], defaults.state || "preparing"), defaults.state || "preparing"),
      epoch: numberOrNull(firstValue(source, ["epoch", "session_epoch"], defaults.epoch)),
      ownerId: text(firstValue(source, ["owner_id", "ownerId", "creator_id", "creatorId"], defaults.ownerId || ""), defaults.ownerId || ""),
      transport: text(firstValue(source, ["transport", "transport_state"], defaults.transport || ""), defaults.transport || ""),
      torState: text(firstValue(source, ["tor_state", "torState"], defaults.torState || ""), defaults.torState || ""),
      connectionState: text(firstValue(source, ["connection_state", "connectionState", "network_state"], defaults.connectionState || ""), defaults.connectionState || ""),
      encryptionActive: encryptionActive === true || encryptionActive === "true",
      hasEncryptionActive,
      hasParticipants,
      hasMessages,
    };
  }

  function sessionEvent(value) {
    const raw = unwrap(value);
    const payload = raw.payload && typeof raw.payload === "object" ? raw.payload : raw;
    const sessionId = text(firstValue(raw, ["session_id", "sessionId"], firstValue(payload, ["session_id", "sessionId"], "")), "");
    return { sessionId, payload };
  }

  function isCurrentSession(sessionId) {
    return Boolean(app.room && sessionId && sessionId === app.room.sessionId);
  }

  function applySessionPayload(result, defaults = {}) {
    const payload = unwrap(result);
    const room = roomFromResponse(payload, defaults);
    if (!room.sessionId) return;
    if (app.room && app.room.sessionId !== room.sessionId) return;
    if (isTerminalRoom(room)) {
      const currentSessionId = app.room?.sessionId || "";
      if (!currentSessionId || currentSessionId === room.sessionId) {
        resetRoom("This session has ended. Start or join a fresh room.");
      }
      return;
    }
    if (!app.room) {
      app.room = room;
    } else {
      app.room = {
        ...app.room,
        ...room,
        participants: room.hasParticipants ? room.participants : app.room.participants,
        messages: room.hasMessages ? room.messages : app.room.messages,
        encryptionActive: room.hasEncryptionActive ? room.encryptionActive : app.room.encryptionActive,
      };
    }
    if (!app.room.inviteCode && defaults.inviteCode) app.room.inviteCode = defaults.inviteCode;
    if (!app.room.roomName && defaults.roomName) app.room.roomName = defaults.roomName;
    app.sessionState = room.state || app.sessionState;
    app.epoch = room.epoch === null ? app.epoch : room.epoch;
    if (room.hasParticipants) app.participants = room.participants;
    if (room.hasMessages) app.messages = room.messages;
    app.room.participants = app.participants;
    app.room.messages = app.messages;
    const self = app.participants.find((participant) => participant.self);
    app.selfParticipantId = self?.id || "";
    app.isCreator = Boolean(app.room.ownerId && app.selfParticipantId && app.room.ownerId === app.selfParticipantId);
    if (!app.participants.length && app.displayName && app.runtime === "browser" && !desktopContext && !isSessionClosed()) {
      app.participants = [normaliseParticipant({ id: "self", display_name: app.displayName, self: true })];
      app.selfParticipantId = "self";
    }
    renderRoom();
    renderChat();
  }

  function participantInitials(name) {
    const parts = name.trim().split(/\s+/).filter(Boolean);
    if (!parts.length) return "?";
    return parts.slice(0, 2).map((part) => part[0]).join("").toUpperCase();
  }

  function participantRow(participant) {
    const li = document.createElement("li");
    li.className = "participant-row";

    const avatar = document.createElement("span");
    avatar.className = "participant-avatar";
    avatar.setAttribute("aria-hidden", "true");
    avatar.textContent = participantInitials(participant.name);

    const identity = document.createElement("span");
    identity.className = "participant-identity";

    const name = document.createElement("span");
    name.className = "participant-name";
    name.textContent = participant.name;
    identity.appendChild(name);

    if (participant.self) {
      const tag = document.createElement("span");
      tag.className = "participant-tag";
      tag.textContent = "You";
      identity.appendChild(tag);
    }

    const meta = document.createElement("span");
    meta.className = "participant-meta";
    const dot = document.createElement("span");
    dot.className = `presence-dot ${participant.online ? "is-online" : "is-away"}`;
    dot.setAttribute("aria-hidden", "true");
    meta.appendChild(dot);
    const state = document.createElement("span");
    state.textContent = participant.online ? "online" : ["joining", "pending", "waiting"].includes(participant.state) ? "pending" : "offline";
    meta.appendChild(state);

    li.append(avatar, identity, meta);
    if (isCreator() && !participant.self && participant.online && app.room && !isSessionClosed()) {
      const remove = document.createElement("button");
      remove.className = "participant-remove";
      remove.type = "button";
      remove.textContent = "Remove";
      remove.setAttribute("aria-label", `Remove ${participant.name} from the room`);
      remove.addEventListener("click", () => removeParticipant(participant));
      li.appendChild(remove);
    }
    return li;
  }

  function renderParticipantList(list, empty, count) {
    if (!list) return;
    list.textContent = "";
    app.participants.forEach((participant) => list.appendChild(participantRow(participant)));
    const hasParticipants = app.participants.length > 0;
    if (empty) empty.hidden = hasParticipants;
    if (count) count.textContent = String(app.participants.length);
  }

  function sessionLabel(state) {
    const value = text(state, "preparing").trim().toLowerCase();
    if (isTerminalState(value)) return "Ended";
    if (["active", "ready", "connected", "established", "running"].includes(value)) return "Active";
    if (["error", "failed"].some((word) => value.includes(word))) return "Needs attention";
    if (["confirmation", "pending-confirmation", "awaiting"].some((word) => value.includes(word))) return "Awaiting confirmation";
    if (["joining", "connecting", "preparing", "waiting"].some((word) => value.includes(word))) return "Connecting";
    return text(state, "Preparing");
  }

  function isTerminalState(value) {
    return ["closed", "ended", "shutdown", "stopped", "disconnected"]
      .includes(text(value, "").trim().toLowerCase());
  }

  function isSessionClosed() {
    return isTerminalState(app.sessionState);
  }

  function isActiveSession() {
    return text(app.sessionState, "").trim().toLowerCase() === "active";
  }

  function isTerminalRoom(room) {
    if (!room || typeof room !== "object") return false;
    return [room.state, room.connectionState, room.torState].some(isTerminalState);
  }

  function isCreator() {
    if (typeof app.isCreator === "boolean") return app.isCreator;
    return Boolean(app.room?.ownerId && app.selfParticipantId && app.room.ownerId === app.selfParticipantId);
  }

  function chatReady() {
    return Boolean(app.runtime === "tauri" && app.eventsReady && app.coreState === "ready" && app.room && !isTerminalRoom(app.room) && app.room.encryptionActive === true && isActiveSession());
  }

  function waitingForConfirmation() {
    return Boolean(app.room && !isActiveSession() && (
      app.room.encryptionActive || (!isCreator() && (app.epoch ?? 0) > 0) || /confirmation/.test(app.room.connectionState)
    ));
  }

  function waitingLabel() {
    if (app.runtime === "unavailable") return "Desktop connection unavailable";
    if (app.coreState === "unavailable") return "Tor unavailable";
    if (["checking", "connecting", "waiting"].includes(app.coreState)) return "Waiting for Tor";
    return waitingForConfirmation() ? "Awaiting creator confirmation" : "Waiting for Welcome";
  }

  function updateRoomStartAvailability() {
    const allowed = !app.newRoomPending && (app.runtime === "browser" || (
      app.runtime === "tauri" && app.eventsReady && app.coreState === "ready"
    ));
    elements.createSubmit.disabled = !allowed;
    elements.joinSubmit.disabled = !allowed;
    elements.createSubmit.setAttribute("aria-busy", app.newRoomPending ? "true" : "false");
    elements.joinSubmit.setAttribute("aria-busy", app.newRoomPending ? "true" : "false");
  }

  function canStartRoom() {
    if (app.newRoomPending) return false;
    if (app.room) {
      showScreen("room");
      setNotice("info", "Leave or end the current room before starting another.");
      return false;
    }
    if (app.runtime === "unavailable" || (app.runtime === "tauri" && (!app.eventsReady || app.coreState !== "ready"))) {
      setNotice("error", "The desktop core and Tor must be ready before starting a room.");
      return false;
    }
    return true;
  }

  function roomCanOpenChat() {
    if (!app.room || isSessionClosed()) return false;
    return (app.runtime === "browser" && !desktopContext) || chatReady();
  }

  function setRoomActionLabels() {
    const owner = isCreator();
    setText(elements.roomShutdown, owner ? "End session" : "Leave room");
    setText(elements.chatShutdown, owner ? "End session" : "Leave room");
    if (elements.roomEnterChat) {
      const label = elements.roomEnterChat.querySelector(".button-label");
      const canOpenChat = roomCanOpenChat();
      setText(label, app.runtime === "browser" && !desktopContext ? "Open preview" : canOpenChat ? "Open chat" : waitingLabel());
      elements.roomEnterChat.disabled = !canOpenChat;
      elements.roomEnterChat.title = app.runtime === "browser" && !desktopContext
        ? "Open the local preview; messages remain disabled"
        : canOpenChat
          ? "Open the encrypted chat"
          : "Chat unlocks after the authenticated Welcome and creator confirmation";
    }
    if (elements.roomAdvanceEpoch) {
      elements.roomAdvanceEpoch.hidden = !owner;
      elements.roomAdvanceEpoch.disabled = !owner || !chatReady();
    }
  }

  function renderRoom() {
    if (!app.room) return;
    const roomName = app.room.roomName || "GhostChat room";
    const code = app.room.inviteCode || "Invite unavailable";
    const closed = isSessionClosed();
    const preview = app.runtime === "browser" && !desktopContext;
    const torUnavailable = app.coreState === "unavailable" && !preview;
    setText(elements.roomTitle, roomName);
    setText(elements.roomWelcomeName, roomName);
    setText(elements.roomCode, code);
    setText(elements.roomSessionState, preview ? "Preview" : torUnavailable ? "Paused" : sessionLabel(app.sessionState));
    setText(elements.roomEpoch, app.epoch === null ? "—" : app.epoch);
    setText(elements.roomTransport, app.room.transport || app.transport || (app.runtime === "tauri" ? "Tor" : preview ? "Browser preview" : "Unavailable"));
    setText(elements.roomConnectionState, app.room.connectionState || sessionLabel(app.sessionState));
    setText(elements.roomTorState, preview ? "Preview" : torUnavailable ? "Unavailable" : app.room.torState || "Checking");
    setText(elements.roomEncryptionState, closed
      ? "Ended"
      : preview
        ? "Not encrypted in preview"
        : torUnavailable
          ? "Unavailable"
        : chatReady()
          ? "Active"
          : waitingForConfirmation() ? "Welcome verified · confirmation pending" : "MLS Welcome pending");
    setText(elements.roomWelcomeCopy, closed
      ? "This session has ended. Start or join a fresh room to continue."
      : torUnavailable
        ? "Tor is unavailable. Start Tor and refresh its status before trying again."
      : preview
        ? "This is a local browser preview. The room is simulated for interface exploration; preview messages are not encrypted or sent anywhere."
      : app.transport === "local-development"
        ? "Local development transport is enabled explicitly. This host-only room never connects to other devices."
      : chatReady()
        ? isCreator() ? "Room keys are ready. Share the invite privately; each join is activated after authenticated confirmation." : "The Welcome is verified and creator confirmation received. Encrypted chat is ready."
        : waitingForConfirmation() ? "The Welcome is verified. Chat remains locked until the creator confirms this join."
        : "The room is connecting through Tor. Chat unlocks after the authenticated Welcome and creator confirmation.");
    renderParticipantList(elements.roomParticipantsList, elements.roomEmptyParticipants, elements.roomParticipantCount);
    elements.roomBackAction.textContent = app.returnToChat ? "← Back to chat" : "← Back to rooms";
    setRoomActionLabels();
    elements.sidebarRoomCard.hidden = false;
    setText(elements.sidebarRoomName, roomName);
    setText(elements.sidebarRoomState, preview ? "Preview" : chatReady() ? sessionLabel(app.sessionState) : waitingLabel());
    elements.sidebarRoomDot.className = `presence-dot ${chatReady() ? "is-online" : "is-away"}`;
  }

  function renderMessageList() {
    if (!elements.messageList) return;
    elements.messageList.textContent = "";
    const messages = app.messages.filter((message) => message.body || message.system);
    elements.emptyMessages.hidden = messages.length > 0;
    elements.messageList.hidden = messages.length === 0;
    messages.forEach((message) => {
      const mine = message.mine || Boolean(message.senderId && message.senderId === app.selfParticipantId);
      const item = document.createElement("li");
      item.className = "message-row";
      if (mine) item.classList.add("is-mine");
      if (message.system) item.classList.add("is-system");

      const meta = document.createElement("div");
      meta.className = "message-meta";
      const sender = document.createElement("span");
      sender.className = "message-sender";
      sender.textContent = message.system ? "GhostChat" : mine ? "You" : message.sender;
      meta.appendChild(sender);
      if (message.time) {
        const timestamp = document.createElement("time");
        timestamp.textContent = message.time;
        meta.appendChild(timestamp);
      }
      if (mine && !message.system) {
        const delivery = document.createElement("span");
        delivery.textContent = "Delivery unconfirmed";
        meta.appendChild(delivery);
      }

      const bubble = document.createElement("div");
      bubble.className = "message-bubble";
      bubble.textContent = message.body;
      item.append(meta, bubble);
      elements.messageList.appendChild(item);
    });
    if (messages.length) elements.messageList.scrollTop = elements.messageList.scrollHeight;
  }

  function appendMessage(message) {
    if (message.id && app.messages.some((item) => item.id === message.id)) return;
    app.messages = [...app.messages, message].slice(-MAX_SESSION_ITEMS);
    if (app.room) app.room.messages = app.messages;
  }

  function renderChat() {
    if (!app.room) return;
    const roomName = app.room.roomName || "GhostChat room";
    const closed = isSessionClosed();
    const preview = app.runtime === "browser" && !desktopContext;
    const torUnavailable = app.coreState === "unavailable" && !preview;
    const ready = chatReady();
    setText(elements.chatTitle, roomName);
    setText(elements.chatStateLabel, closed
      ? "Session ended"
      : torUnavailable
        ? "Tor unavailable"
      : preview
        ? "Browser preview · not encrypted"
        : ready
          ? "Encrypted session active"
          : waitingLabel());
    setText(elements.chatEpochLabel, `Epoch ${app.epoch === null ? "—" : app.epoch}`);
    setText(elements.chatInviteCode, app.room.inviteCode || "Invite unavailable");
    renderParticipantList(elements.chatParticipantsList, elements.chatEmptyParticipants, elements.chatParticipantCount);
    elements.chatStateDot.className = `status-dot ${closed || torUnavailable ? "is-error" : ready ? app.runtime === "tauri" ? "is-ready" : "is-browser" : "is-connecting"}`;
    if (elements.messageListHint) {
      elements.messageListHint.classList.toggle("is-waiting", !ready);
      setText(elements.messageListHint, closed
        ? "Session ended · messages cleared"
        : torUnavailable
          ? "Tor is unavailable · messages locked"
        : preview
          ? "Preview only · messages are not encrypted"
          : ready
            ? "Encrypted for this session"
            : waitingLabel());
    }
    if (elements.composerState) {
      elements.composerState.classList.toggle("is-waiting", !ready);
      setText(elements.composerState, closed
        ? "Session ended. Start a fresh room."
        : torUnavailable
          ? "Tor is unavailable. Start Tor before sending messages."
        : app.sendPending
          ? "Sending… delivery status may be unknown if the connection closes."
        : app.lastSendState === "unknown"
          ? "Delivery is unknown. Check the room before sending again."
        : app.lastSendState === "queued"
          ? "Message encrypted and queued · peer delivery unconfirmed."
        : preview
          ? "Preview mode: message sending is disabled."
          : ready
            ? "Messages are held for this session; close it when you are finished."
            : "Chat unlocks after the Welcome and creator confirmation.");
    }
    elements.composer?.classList.toggle("is-locked", !ready);
    elements.messageInput.disabled = !ready || app.sendPending;
    elements.sendSubmit.disabled = !ready || app.sendPending;
    elements.sendSubmit.setAttribute("aria-busy", app.sendPending ? "true" : "false");
    setRoomActionLabels();
    renderMessageList();
  }

  function validateDisplayName(value) {
    const name = value.trim();
    if (!name) return "Choose a display name before continuing.";
    if ([...name].length > 32 || new TextEncoder().encode(value).length > 128) return "Display names must be 32 characters or fewer.";
    if ([...name].some((character) => /\p{Cc}/u.test(character))) return "Display names cannot contain control characters.";
    return "";
  }

  function validateRoomName(value) {
    const name = value.trim();
    if (!name) return "";
    if ([...name].length > 48 || new TextEncoder().encode(value).length > 192) return "Room names must be 48 characters or fewer.";
    if ([...name].some((character) => /\p{Cc}/u.test(character))) return "Room names cannot contain control characters.";
    return "";
  }

  function validateInviteCode(value) {
    const code = value.trim();
    if (!code) return "Paste an invite code before joining.";
    if (new TextEncoder().encode(value).length > 16 * 1024) return "Invite codes must be 16 KiB or smaller.";
    if (code.length % 2 !== 0 || !/^[a-f0-9]+$/i.test(code)) return "Invite codes must contain hexadecimal pairs.";
    return "";
  }

  function sessionArgs(extra = {}) {
    if (!app.room?.sessionId) return { ...extra };
    return { ...extra, session_id: app.room.sessionId };
  }

  function previewSession({ name, roomName, inviteCode }) {
    app.displayName = name;
    app.room = {
      roomName: roomName || "Quiet room",
      inviteCode: inviteCode || makePreviewCode(),
      sessionId: "preview-session",
      state: "active",
      epoch: 1,
      ownerId: "self",
      transport: "browser-preview",
      torState: "disabled",
      connectionState: "ready",
      encryptionActive: false,
      participants: [normaliseParticipant({ id: "self", display_name: name, self: true })],
      messages: [],
    };
    app.participants = app.room.participants;
    app.messages = [];
    app.selfParticipantId = "self";
    app.isCreator = true;
    app.sessionState = "active";
    app.epoch = 1;
    app.returnToChat = false;
    renderRoom();
    showScreen("room");
    setNotice("info", "Browser preview: this room is simulated locally and will not connect to other devices.");
  }

  async function createRoom(event) {
    event.preventDefault();
    if (!canStartRoom()) return;
    const name = elements.createName.value.trim();
    const roomName = elements.createRoomName.value.trim();
    const validation = validateDisplayName(name);
    if (validation) {
      setNotice("error", validation);
      elements.createName.focus();
      return;
    }
    const roomValidation = validateRoomName(roomName);
    if (roomValidation) {
      setNotice("error", roomValidation);
      elements.createRoomName.focus();
      return;
    }
    setBusy(elements.createSubmit, true);
    app.newRoomPending = true;
    updateRoomStartAvailability();
    clearNotice();
    try {
      if (!invoke) {
        if (desktopContext) throw new Error("desktop IPC unavailable");
        previewSession({ name, roomName });
        return;
      }
      app.displayName = name;
      const args = { display_name: name };
      if (roomName) args.room_name = roomName;
      const result = await invoke("create_room", args);
      app.room = null;
      app.participants = [];
      app.messages = [];
      applySessionPayload(result, { roomName: roomName || "GhostChat room", state: "connecting" });
      if (!app.room) throw new Error("desktop session snapshot unavailable");
      app.returnToChat = false;
      showScreen("room");
      setNotice("success", "Room created. Share the invite code with your group.");
      await refreshSnapshot(true);
    } catch (error) {
      app.room = null;
      app.participants = [];
      app.messages = [];
      app.selfParticipantId = "";
      app.isCreator = false;
      setNotice("error", humanizeError(error, "GhostChat could not create the room. Check the core connection and try again."));
    } finally {
      app.newRoomPending = false;
      setBusy(elements.createSubmit, false);
      updateRoomStartAvailability();
    }
  }

  async function joinRoom(event) {
    event.preventDefault();
    if (!canStartRoom()) return;
    const name = elements.joinName.value.trim();
    const inviteCode = elements.inviteCode.value.trim();
    const nameValidation = validateDisplayName(name);
    if (nameValidation) {
      setNotice("error", nameValidation);
      elements.joinName.focus();
      return;
    }
    const inviteValidation = validateInviteCode(inviteCode);
    if (inviteValidation) {
      setNotice("error", inviteValidation);
      elements.inviteCode.focus();
      return;
    }
    setBusy(elements.joinSubmit, true);
    app.newRoomPending = true;
    updateRoomStartAvailability();
    clearNotice();
    try {
      if (!invoke) {
        if (desktopContext) throw new Error("desktop IPC unavailable");
        previewSession({ name, roomName: "Joined room", inviteCode });
        return;
      }
      app.displayName = name;
      const result = await invoke("join_room", { display_name: name, invite_code: inviteCode });
      app.room = null;
      app.participants = [];
      app.messages = [];
      applySessionPayload(result, { roomName: "Joined room", inviteCode, state: "connecting" });
      if (!app.room) throw new Error("desktop session snapshot unavailable");
      app.returnToChat = false;
      showScreen("room");
      setNotice("info", "Join started. Chat unlocks after the authenticated Welcome and creator confirmation.");
      await refreshSnapshot(true);
    } catch (error) {
      // A failed Welcome is terminal for this join attempt. Keep no client
      // snapshot around that could be mistaken for a reconnectable MLS state.
      app.room = null;
      app.participants = [];
      app.messages = [];
      app.selfParticipantId = "";
      app.isCreator = false;
      setNotice("error", humanizeError(error, "GhostChat could not join that room. Check the invite code and try again."));
    } finally {
      app.newRoomPending = false;
      setBusy(elements.joinSubmit, false);
      updateRoomStartAvailability();
    }
  }

  async function refreshSnapshot(silent = false) {
    if (!invoke || !app.room) return;
    const requestedSessionId = app.room.sessionId;
    try {
      const result = await invoke("get_session_snapshot", sessionArgs());
      if (!app.room || app.room.sessionId !== requestedSessionId) return;
      applySessionPayload(result, { roomName: app.room.roomName, inviteCode: app.room.inviteCode, state: app.sessionState, epoch: app.epoch });
    } catch (error) {
      const raw = text(error?.message || error, "").toLowerCase();
      if (isCurrentSession(requestedSessionId) && (raw.includes("no active ghostchat session") || raw.includes("does not match the active room"))) {
        resetRoom("This session has ended. Start or join a fresh room.");
        return;
      }
      if (!silent) setNotice("error", humanizeError(error, "Live session details are temporarily unavailable."));
    }
  }

  async function sendMessage(event) {
    event.preventDefault();
    if (app.sendPending) return;
    if (!chatReady()) {
      setNotice(
        "info",
        app.runtime === "browser"
          ? "Browser preview messages are disabled because the preview is not encrypted."
          : "Chat is locked until the authenticated MLS Welcome is ready. Start a fresh join if this room cannot connect.",
      );
      return;
    }
    const body = elements.messageInput.value.trim();
    if (!body) {
      elements.messageInput.focus();
      return;
    }
    if ([...body].length > 4000 || new TextEncoder().encode(body).length > 16000) {
      setNotice("error", "Messages must be 4,000 characters or fewer.");
      return;
    }
    if (/\p{Cc}/u.test(body)) {
      setNotice("error", "Messages cannot contain control characters or line breaks.");
      return;
    }
    setBusy(elements.sendSubmit, true);
    app.sendPending = true;
    app.lastSendState = "pending";
    renderChat();
    const requestedSessionId = app.room?.sessionId;
    const generation = app.sessionGeneration;
    try {
      const result = await invoke("send_message", sessionArgs({ body }));
      if (!app.room || app.room.sessionId !== requestedSessionId) return;
      const payload = unwrap(result);
      if (payload.snapshot && typeof payload.snapshot === "object") {
        applySessionPayload(payload.snapshot);
      } else {
        const message = payload.message && typeof payload.message === "object" ? payload.message : payload;
        const normalised = normaliseMessage({ ...message, body: firstValue(message, ["body", "content", "message", "text"], body), sender_name: firstValue(message, ["sender_name", "display_name"], app.displayName), mine: true }, app.messages.length);
        if (normalised.body) appendMessage(normalised);
      }
      if (generation !== app.sessionGeneration || !isCurrentSession(requestedSessionId)) return;
      app.lastSendState = "queued";
      elements.messageInput.value = "";
      renderMessageList();
    } catch (error) {
      if (generation !== app.sessionGeneration || !isCurrentSession(requestedSessionId)) return;
      app.lastSendState = "unknown";
      setNotice("error", "The send did not complete. Delivery is unknown; check the room before sending again to avoid a duplicate.");
    } finally {
      if (generation === app.sessionGeneration) {
        app.sendPending = false;
        setBusy(elements.sendSubmit, false);
        renderChat();
      }
    }
  }

  function clearSession() {
    app.sessionGeneration += 1;
    app.room = null;
    app.participants = [];
    app.messages = [];
    app.displayName = "";
    app.sessionState = "preparing";
    app.epoch = null;
    app.selfParticipantId = "";
    app.isCreator = false;
    app.sendPending = false;
    app.lastSendState = "idle";
    app.returnToChat = false;
    elements.sidebarRoomCard.hidden = true;
    elements.messageInput.value = "";
    elements.messageList.textContent = "";
    elements.roomParticipantsList.textContent = "";
    elements.chatParticipantsList.textContent = "";
    [elements.roomCode, elements.chatInviteCode, elements.roomTitle, elements.chatTitle,
      elements.roomWelcomeName, elements.sidebarRoomName].forEach((element) => setText(element, ""));
    [elements.createName, elements.createRoomName, elements.joinName, elements.inviteCode].forEach((element) => {
      element.value = "";
    });
    setText(elements.roomParticipantCount, "0");
    setText(elements.chatParticipantCount, "0");
    elements.messageInput.disabled = true;
    setBusy(elements.sendSubmit, false);
    elements.sendSubmit.disabled = true;
  }

  function resetRoom(message) {
    clearSession();
    showScreen("home");
    if (message) setNotice("error", message);
  }

  async function removeParticipant(participant) {
    if (!invoke || !app.room || !isCreator() || !participant?.id) return;
    if (!window.confirm(`Remove ${participant.name} from this room?`)) return;
    const requestedSessionId = app.room.sessionId;
    try {
      const result = await invoke("remove_participant", sessionArgs({ participant_id: participant.id }));
      if (!app.room || app.room.sessionId !== requestedSessionId) return;
      applySessionPayload(result);
      setNotice("success", `${participant.name} was removed from the room.`);
    } catch (error) {
      setNotice("error", humanizeError(error, "GhostChat could not remove that participant."));
    }
  }

  async function advanceEpoch() {
    if (!app.room || !isCreator() || isSessionClosed()) return;
    if (!invoke) {
      app.epoch = (app.epoch ?? 0) + 1;
      app.room.epoch = app.epoch;
      renderRoom();
      renderChat();
      setNotice("info", `Browser preview: simulated MLS epoch ${app.epoch}.`);
      return;
    }
    setBusy(elements.roomAdvanceEpoch, true);
    const requestedSessionId = app.room.sessionId;
    try {
      const result = await invoke("advance_epoch", sessionArgs());
      if (!app.room || app.room.sessionId !== requestedSessionId) return;
      applySessionPayload(result);
      setNotice("success", `MLS epoch advanced to ${app.epoch}.`);
    } catch (error) {
      setNotice("error", humanizeError(error, "GhostChat could not rotate the room keys."));
    } finally {
      setBusy(elements.roomAdvanceEpoch, false);
      setRoomActionLabels();
    }
  }

  async function shutdownSession() {
    if (!app.room) {
      showScreen("home");
      return;
    }
    const owner = isCreator();
    const confirmed = window.confirm(owner
      ? "End this GhostChat session? Everyone will leave and the room will close."
      : "Leave this GhostChat room? You will need a fresh invite to join again.");
    if (!confirmed) return;
    setBusy(elements.roomShutdown, true);
    setBusy(elements.chatShutdown, true);
    const requestedSessionId = app.room.sessionId;
    try {
      if (invoke) await invoke(owner ? "shutdown_session" : "leave_session", sessionArgs());
      if (app.room && app.room.sessionId !== requestedSessionId) return;
      clearSession();
      showScreen("home");
      setNotice("success", owner ? "Session ended. Room data was cleared from this app view." : "You left the room. Join again with a fresh invite when ready.");
    } catch (error) {
      setNotice("error", humanizeError(error, "GhostChat could not end the session. Try again."));
      if (isCurrentSession(requestedSessionId)) await refreshSnapshot(true);
    } finally {
      setBusy(elements.roomShutdown, false);
      setBusy(elements.chatShutdown, false);
    }
  }

  async function copyInvite() {
    const code = app.room?.inviteCode || "";
    if (!code || code === "Invite unavailable") {
      setNotice("error", "There is no invite code to copy yet.");
      return;
    }
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(code);
        setNotice("success", "Invite copied. Clipboard may retain this bearer invite; clear it after sharing.");
      } else {
        setNotice("info", "Copy is unavailable in this preview. Select the invite code manually.");
      }
    } catch {
      setNotice("info", "Copy is unavailable here. Select the invite code manually.");
    }
  }

  function handleMessageEvent(payload) {
    if (!app.room || isSessionClosed()) return;
    const event = sessionEvent(payload?.payload ?? payload);
    if (!isCurrentSession(event.sessionId)) return;
    const raw = event.payload;
    const messageValue = raw.message && typeof raw.message === "object" ? raw.message : raw;
    const message = normaliseMessage(messageValue, app.messages.length);
    if (!message.body && !message.system) return;
    appendMessage(message);
    renderMessageList();
  }

  function handleParticipantEvent(payload, joined) {
    if (!app.room || isSessionClosed()) return;
    const event = sessionEvent(payload?.payload ?? payload);
    if (!isCurrentSession(event.sessionId)) return;
    const raw = event.payload;
    const value = raw.participant && typeof raw.participant === "object" ? raw.participant : raw;
    const participant = normaliseParticipant(value, app.participants.length);
    const existing = app.participants.findIndex((item) => item.id === participant.id);
    if (joined) {
      if (existing >= 0) app.participants[existing] = { ...app.participants[existing], ...participant, online: true };
      else app.participants = [...app.participants, participant].slice(-MAX_SESSION_ITEMS);
      setNotice("info", `${participant.name} joined the room.`);
    } else {
      if (existing >= 0) app.participants[existing] = { ...app.participants[existing], online: false };
      setNotice("info", `${participant.name} left the room.`);
    }
    app.room.participants = app.participants;
    renderRoom();
    renderChat();
  }

  function handleSessionStateEvent(payload) {
    const event = sessionEvent(payload?.payload ?? payload);
    if (!isCurrentSession(event.sessionId)) return;
    const raw = event.payload;
    const snapshot = raw.snapshot || raw.session || raw.room || (raw.session_id ? raw : null);
    const snapshotId = text(firstValue(snapshot, ["session_id", "sessionId"], ""), "");
    if (snapshotId && snapshotId !== event.sessionId) return;
    const state = text(firstValue(raw, ["state", "session_state", "status"], raw.value || ""), "");
    if (state) app.sessionState = state;
    const epoch = numberOrNull(firstValue(raw, ["epoch", "session_epoch"], null));
    if (epoch !== null) app.epoch = epoch;
    if (snapshot && typeof snapshot === "object") applySessionPayload(snapshot);
    if (!app.room) return;
    if (isSessionClosed() || isTerminalRoom(app.room)) {
      resetRoom("This session has ended. Start or join a fresh room.");
      return;
    }
    renderRoom();
    renderChat();
  }

  function handleErrorEvent(payload) {
    const raw = unwrap(payload?.payload ?? payload);
    const sessionId = text(firstValue(raw, ["session_id", "sessionId"], ""), "");
    if (!isCurrentSession(sessionId)) return;
    setNotice("error", humanizeError(raw, "The GhostChat session reported an error. Try again or start a new room."));
  }

  async function subscribeToEvents() {
    if (!listen) {
      if (desktopContext) throw new Error("desktop event IPC unavailable");
      return;
    }
    const subscriptions = [
      ["ghostchat://message", handleMessageEvent],
      ["ghostchat://participant-joined", (payload) => handleParticipantEvent(payload, true)],
      ["ghostchat://participant-left", (payload) => handleParticipantEvent(payload, false)],
      ["ghostchat://session-state", handleSessionStateEvent],
      ["ghostchat://error", handleErrorEvent],
    ];
    for (const [eventName, handler] of subscriptions) {
      try {
        const unlisten = await listen(eventName, handler);
        if (typeof unlisten !== "function") throw new Error("desktop event IPC unavailable");
        app.listeners.push(unlisten);
      } catch {
        app.runtime = "unavailable";
        throw new Error("desktop event IPC unavailable");
      }
    }
    app.eventsReady = true;
  }

  function bindNavigation() {
    $$('[data-go]').forEach((button) => {
      button.addEventListener("click", () => {
        clearNotice();
        showScreen(button.dataset.go);
      });
    });
    $("#home-create").addEventListener("click", () => showScreen("create"));
    $("#home-join").addEventListener("click", () => showScreen("join"));
    elements.roomBackAction.addEventListener("click", () => {
      if (app.returnToChat) {
        app.returnToChat = false;
        showScreen("chat");
      } else {
        showScreen("home");
      }
    });
    elements.roomEnterChat.addEventListener("click", async () => {
      if (!roomCanOpenChat()) {
        setNotice("info", "Chat unlocks after the authenticated MLS Welcome is ready. No stale session will be reused.");
        return;
      }
      app.returnToChat = false;
      showScreen("chat");
      await refreshSnapshot(false);
      elements.messageInput.focus();
    });
    elements.chatBackRoom.addEventListener("click", () => {
      app.returnToChat = true;
      showScreen("room");
    });
    elements.chatRoomDetails.addEventListener("click", () => {
      app.returnToChat = true;
      showScreen("room");
    });
  }

  function bindForms() {
    elements.createForm.addEventListener("submit", createRoom);
    elements.joinForm.addEventListener("submit", joinRoom);
    elements.messageForm.addEventListener("submit", sendMessage);
    elements.messageInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        elements.messageForm.requestSubmit();
      }
    });
  }

  function bindActions() {
    elements.copyInvite.addEventListener("click", copyInvite);
    elements.roomAdvanceEpoch.addEventListener("click", advanceEpoch);
    elements.roomShutdown.addEventListener("click", shutdownSession);
    elements.chatShutdown.addEventListener("click", shutdownSession);
    elements.noticeDismiss.addEventListener("click", clearNotice);
    $("#help-button").addEventListener("click", () => {
      setNotice("info", "GhostChat rooms are temporary MLS sessions. Use an invite code to keep a room private.");
    });
  }

  async function checkCoreStatus() {
    if (app.statusCheckInFlight) return;
    app.statusCheckInFlight = true;
    if (!bridgeReady) {
      if (desktopContext) {
        app.runtime = "unavailable";
        app.transport = "unavailable";
        app.coreState = "unavailable";
        setRuntimeStatus("error", "Desktop connection unavailable");
        elements.previewBanner.hidden = true;
        setNotice("error", "GhostChat could not connect its desktop core. Restart the app before using room actions.");
      } else {
        app.runtime = "browser";
        app.transport = "browser-preview";
        app.coreState = "preview";
        setRuntimeStatus("browser", "Browser preview");
        elements.previewBanner.hidden = false;
      }
      app.statusCheckInFlight = false;
      updateRoomStartAvailability();
      return;
    }
    elements.previewBanner.hidden = true;
    try {
      const result = await invoke("app_status");
      const status = unwrap(result);
      const value = text(firstValue(status, ["status", "state"], typeof result === "string" ? result : "unavailable"), "unavailable").toLowerCase();
      const transport = text(firstValue(status, ["transport"], "tor-only"), "tor-only").toLowerCase();
      app.transport = transport;
      app.coreState = value;
      const progress = numberOrNull(firstValue(status, ["bootstrap_progress", "bootstrapProgress"], null));
      if (transport === "local-development" || value === "ready") {
        setRuntimeStatus("ready", transport === "local-development" ? "Local development" : "Tor ready");
      } else if (value === "connecting" || value === "waiting") {
        setRuntimeStatus("connecting", progress === null ? "Tor connecting" : `Tor connecting · ${progress}%`);
      } else {
        setRuntimeStatus("error", "Tor unavailable");
      }
    } catch {
      app.transport = "tor-only";
      app.coreState = "unavailable";
      setRuntimeStatus("error", "Core unavailable");
      setNotice("error", "GhostChat could not reach the local core. Room actions may be unavailable.");
    } finally {
      app.statusCheckInFlight = false;
      updateRoomStartAvailability();
      renderRoom();
      renderChat();
    }
  }

  async function init() {
    bindNavigation();
    bindForms();
    bindActions();
    showScreen("home");
    updateRoomStartAvailability();
    await subscribeToEvents();
    await checkCoreStatus();
    app.statusTimer = window.setInterval(() => checkCoreStatus(), 15_000);
    window.addEventListener("beforeunload", () => {
      app.listeners.splice(0).forEach((unlisten) => {
        try {
          const result = unlisten();
          if (result && typeof result.catch === "function") result.catch(() => {});
        } catch {
          // The window is already closing; there is no user action to recover.
        }
      });
      window.clearInterval(app.statusTimer);
    }, { once: true });
  }

  init().catch(() => {
    app.runtime = "unavailable";
    app.coreState = "unavailable";
    updateRoomStartAvailability();
    setRuntimeStatus("error", "UI unavailable");
    setNotice("error", "GhostChat could not finish loading. Reload the window and try again.");
  });
})();
