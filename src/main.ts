import { Config } from './config.js';
import type { PeerContact, ChannelSession, MessageData } from './types.js';
import {
  concatBytes,
  decodeBase64URL,
  randomUUID,
  encodeBase64URL,
} from './crypto.js';
import { DB, Settings } from './storage.js';
import { formatEnvelope, parseEnvelope, parseHeader } from './codec.js';
import {
  calculateFingerprint,
  getLocalFingerprint,
  getLocalIdentity,
  serializeIdentityPublic,
} from './identity.js';
import {
  CreateInit,
  EncryptMessage,
  ProcessInit,
  ProcessResp,
  DecryptMessage,
} from './ratchet.js';

const State = {
  currentContactFp: undefined as string | undefined,
  showArchived: false,
  searchQuery: '',
};

const UI = {
  $: <T extends HTMLElement>(id: string): T => {
    const el = document.getElementById(id) ?? document.querySelector(id);
    if (!el) throw new Error(`Element #${id} not found in DOM`);
    return el as T;
  },
  toastTimer: undefined as number | undefined,
  showToast: (msg: string, duration = 3500) => {
    const t = UI.$('toast');
    UI.$('toast-msg').textContent = msg;
    t.classList.remove('opacity-0', 'pointer-events-none');
    t.classList.add('opacity-100');
    clearTimeout(UI.toastTimer);
    UI.toastTimer = setTimeout(() => {
      t.classList.remove('opacity-100');
      t.classList.add('opacity-0', 'pointer-events-none');
    }, duration);
  },
  showModal: (containerHtml: string) => {
    UI.$('modal-container').innerHTML = containerHtml;
    UI.$('modal-overlay').classList.remove('hidden');
    UI.$('modal-overlay').classList.add('flex');
  },
  closeModal: () => {
    UI.$('modal-overlay').classList.remove('flex');
    UI.$('modal-overlay').classList.add('hidden');
  },
};

const escapeHtml = (str: string): string =>
  str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

const closePeerDropdown = () => UI.$('peer-dropdown').classList.add('hidden');

function resetChatView(updateHash = true) {
  delete State.currentContactFp;

  if (updateHash && location.hash)
    history.replaceState(null, '', location.pathname + location.search);

  UI.$('chat-view').classList.add('hidden');
  UI.$('chat-view').classList.remove('flex');
  UI.$('sidebar-view').classList.remove('max-md:hidden');
  UI.$('chat-messages').replaceChildren();
  UI.$('chat-title').textContent = 'Select a Peer';
  UI.$('chat-status-text').textContent = 'Idle';
  UI.$('chat-status-dot').className = 'w-2 h-2 rounded-full bg-slate-500';
  UI.$('chat-input-area').classList.add('hidden');
  UI.$('empty-state').classList.remove('hidden');
}

async function handleOutgoing(packetBase64: string, bundleBase64?: string) {
  try {
    await navigator.clipboard.writeText(
      formatEnvelope(decodeBase64URL(bundleBase64 ?? packetBase64)),
    );
    UI.showToast(
      `Encrypted ${typeof bundleBase64 !== 'undefined' ? 'Bundle' : 'Packet'} Copied`,
    );
  } catch (err) {
    UI.showToast('Clipboard Access Denied');
    console.error('[Clipboard] Write error:', err);
  }
}

async function renderSidebar() {
  const local = await getLocalIdentity();
  UI.$('my-fingerprint').textContent = calculateFingerprint(
    serializeIdentityPublic(local),
  );

  let contacts = await DB.getAll<PeerContact>('contacts');
  if (!State.showArchived) contacts = contacts.filter((c) => !c.archived);

  const msgs = await DB.getAll<MessageData>('messages');
  const sessions = await DB.getAll<ChannelSession>('sessions');
  const frag = document.createDocumentFragment();

  for (const c of contacts) {
    const div = document.createElement('div');
    const isActive = c.fingerprint === State.currentContactFp;
    div.className = `min-h-11 p-3 rounded-lg cursor-pointer text-sm border transition-all duration-150 flex flex-col justify-center gap-1 ${
      isActive
        ? 'bg-indigo-900/40 border-indigo-500/50 text-indigo-100 shadow-sm'
        : 'bg-slate-900/80 border-slate-800 text-slate-300 hover:bg-slate-800/80 hover:border-slate-700'
    }`;

    let unreadCount = 0;
    if (!isActive) {
      const session = sessions.find((s) => s.contactFp === c.fingerprint);
      if (session)
        unreadCount = msgs.filter(
          (m) =>
            m.conversationId === session.conversationID &&
            !m.isMe &&
            m.timestamp > c.lastReadTimestamp,
        ).length;
    }

    const topRow = document.createElement('div');
    topRow.className = 'flex justify-between items-center gap-2';

    const nameSpan = document.createElement('span');
    nameSpan.className = 'font-medium truncate flex-1';
    nameSpan.textContent = c.name;
    topRow.appendChild(nameSpan);

    if (unreadCount > 0) {
      const badge = document.createElement('span');
      badge.className =
        'bg-emerald-500 text-slate-950 text-[10px] font-bold px-1.5 py-0.5 rounded-full shrink-0 shadow-sm';
      badge.textContent = unreadCount.toString();
      topRow.appendChild(badge);
    }

    const botRow = document.createElement('div');
    botRow.className =
      'flex justify-between items-center text-[10px] text-slate-500 font-mono';

    const fpSpan = document.createElement('span');
    fpSpan.textContent = c.fingerprint.substring(0, 8);
    botRow.appendChild(fpSpan);

    if (c.archived) {
      const archSpan = document.createElement('span');
      archSpan.className = 'text-amber-400 font-sans';
      archSpan.textContent = '(Archived)';
      botRow.appendChild(archSpan);
    }

    div.appendChild(topRow);
    div.appendChild(botRow);

    div.onclick = () => selectContact(c.fingerprint);
    div.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      showPeerMetadata(c.fingerprint);
    });

    frag.appendChild(div);
  }
  UI.$('contacts-list').replaceChildren(frag);
}

async function selectContact(fp: string, isNavigatingHistory = false) {
  const contact = await DB.get<PeerContact>('contacts', fp);
  if (!contact) {
    resetChatView(true);
    return;
  }

  if (!isNavigatingHistory) {
    const targetHash = `#${fp}`;
    if (location.hash !== targetHash)
      if (State.currentContactFp) history.replaceState(null, '', targetHash);
      else history.pushState(null, '', targetHash);
  }

  State.currentContactFp = fp;
  UI.$('chat-messages').replaceChildren();

  contact.lastReadTimestamp = Date.now();
  await DB.put('contacts', contact);

  UI.$('sidebar-view').classList.add('max-md:hidden');
  UI.$('chat-view').classList.remove('hidden');
  UI.$('chat-view').classList.add('flex');
  UI.$('empty-state').classList.add('hidden');
  UI.$('chat-input-area').classList.remove('hidden');
  UI.$('chat-title').textContent = contact.name;
  closePeerDropdown();
  UI.$('btn-archive-contact').textContent = contact.archived
    ? 'Restore Peer'
    : 'Archive Peer';
  State.searchQuery = '';
  UI.$<HTMLInputElement>('chat-search-input').value = '';
  UI.$('search-bar-container').classList.add('hidden');

  await renderChatLog();
  await renderSidebar();
}

let renderSeq = 0;
async function renderChatLog() {
  if (!State.currentContactFp) return;
  const currentSeq = ++renderSeq;

  const msgs = await DB.getAll<MessageData>('messages');
  const sessions = await DB.getAll<ChannelSession>('sessions');
  if (currentSeq !== renderSeq) return;

  const session = sessions.find((s) => s.contactFp === State.currentContactFp);
  if (session) {
    if (
      session.state === 'HANDSHAKE_SENT' ||
      session.state === 'HANDSHAKE_RECEIVED'
    ) {
      UI.$('chat-status-text').textContent =
        session.state === 'HANDSHAKE_SENT'
          ? 'Awaiting RESP'
          : 'Handshake Pending';
      UI.$('chat-status-dot').className =
        'w-2 h-2 rounded-full bg-amber-400 animate-pulse';
      UI.$<HTMLInputElement>('chat-input').disabled =
        session.state === 'HANDSHAKE_SENT';
    } else {
      UI.$('chat-status-text').textContent = 'Channel Established';
      UI.$('chat-status-dot').className = 'w-2 h-2 rounded-full bg-emerald-400';
      UI.$<HTMLInputElement>('chat-input').disabled = false;
    }
  } else {
    UI.$('chat-status-text').textContent = 'Idle';
    UI.$('chat-status-dot').className = 'w-2 h-2 rounded-full bg-slate-500';
    UI.$<HTMLInputElement>('chat-input').disabled = false;
  }

  const query = State.searchQuery.toLowerCase();
  const chatMsgs = msgs
    .filter((m) => session && m.conversationId === session.conversationID)
    .sort((a, b) =>
      a.timestamp === b.timestamp
        ? a.messageId.localeCompare(b.messageId)
        : a.timestamp - b.timestamp,
    );

  const ctn = UI.$('chat-messages');
  const isNearBottom =
    ctn.scrollHeight - ctn.scrollTop - ctn.clientHeight < 150;
  const frag = document.createDocumentFragment();

  for (const m of chatMsgs) {
    if (query && !m.text.toLowerCase().includes(query)) continue;
    const div = document.createElement('div');
    div.className = `max-w-[85%] sm:max-w-[75%] p-3.5 rounded-2xl text-sm break-words shadow-sm border transition-all ${
      m.isMe
        ? 'bg-indigo-600 border-indigo-500/60 self-end rounded-br-xs text-indigo-50'
        : 'bg-slate-900 border-slate-800 self-start rounded-bl-xs text-slate-200'
    }`;

    if (query) {
      const regex = new RegExp(
        `(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`,
        'gi',
      );
      const parts = m.text.split(regex);
      for (const part of parts) {
        if (part.toLowerCase() === query) {
          const span = document.createElement('span');
          span.className = 'highlight-match';
          span.textContent = part;
          div.appendChild(span);
        } else {
          div.appendChild(document.createTextNode(part));
        }
      }
    } else {
      div.textContent = m.text;
    }

    div.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      showMessageMetadata(m);
    });

    frag.appendChild(div);
  }

  ctn.replaceChildren(frag);
  const lastMsg =
    chatMsgs.length > 0 ? chatMsgs[chatMsgs.length - 1] : undefined;
  if (isNearBottom || lastMsg?.isMe)
    requestAnimationFrame(() => (ctn.scrollTop = ctn.scrollHeight));
}

UI.$('btn-back-mobile').onclick = () => {
  resetChatView(true);
  renderSidebar();
};

UI.$('btn-copy-identity').onclick = async () => {
  try {
    const localIdentity = await getLocalIdentity();
    const serialized = serializeIdentityPublic(localIdentity);
    await navigator.clipboard.writeText(formatEnvelope(serialized));
    UI.showToast('Identity Bundle Copied');
  } catch (err) {
    UI.showToast('Clipboard Access Denied');
    console.error('[Clipboard] Identity copy error:', err);
  }
};

UI.$('btn-add-contact').onclick = async () => {
  try {
    const text = await navigator.clipboard.readText();
    const bytes = parseEnvelope(text);
    if (bytes[0] !== Config.IDENTITY_VERSION) throw new Error('Invalid format');

    const fp = calculateFingerprint(bytes);
    const localFp = await getLocalFingerprint();
    if (fp === localFp) return UI.showToast('Cannot Link Own Identity');
    if (await DB.get('contacts', fp))
      return UI.showToast('Peer Already Exists');

    UI.showModal(`
      <div class="p-4 bg-slate-900 border-b border-slate-800"><h3 class="font-bold text-slate-200">Link New Peer</h3></div>
      <div class="p-4">
        <label class="block text-xs text-slate-400 mb-1">Assign Local Alias</label>
        <input type="text" id="new-alias-input" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 focus:border-indigo-500 outline-none min-h-11 text-base sm:text-sm transition-colors" placeholder="e.g. Work Laptop" />
      </div>
      <div class="p-4 bg-slate-900 flex justify-end gap-2 border-t border-slate-800/50">
        <button id="btn-cancel-add" class="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 min-h-11 cursor-pointer transition-colors">Cancel</button>
        <button id="btn-confirm-add" class="px-4 py-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white font-medium rounded-lg min-h-11 cursor-pointer transition-colors shadow-sm">Save Peer</button>
      </div>
    `);

    setTimeout(() => UI.$<HTMLInputElement>('new-alias-input')?.focus());

    UI.$('btn-cancel-add').onclick = UI.closeModal;
    UI.$('btn-confirm-add').onclick = async () => {
      try {
        const name = UI.$<HTMLInputElement>('new-alias-input').value.trim();
        if (!name) return;
        await DB.put('contacts', {
          fingerprint: fp,
          bundle: encodeBase64URL(bytes),
          name,
          verified: true,
          archived: false,
          lastReadTimestamp: Date.now(),
        });
        UI.closeModal();
        UI.showToast('Peer Linked');
        await renderSidebar();
      } catch (err) {
        UI.showToast('Failed to Save Peer');
        console.error('[Storage] Save peer error:', err);
      }
    };
  } catch (err) {
    UI.showToast('Invalid Identity in Clipboard');
    console.error('[Clipboard] Parse identity error:', err);
  }
};

let isSending = false;
UI.$<HTMLFormElement>('chat-form').onsubmit = async (e) => {
  e.preventDefault();
  if (isSending) return;

  const input = UI.$<HTMLInputElement>('chat-input');
  const text = input.value.trim();
  if (!text || !State.currentContactFp) return;

  isSending = true;
  input.disabled = true;

  try {
    const sessions = await DB.getAll<ChannelSession>('sessions');
    const session = sessions.find(
      (s) => s.contactFp === State.currentContactFp,
    );

    if (!session) {
      const { packet, session: newSession } = await CreateInit(
        State.currentContactFp,
        text,
      );
      await DB.put('messages', {
        messageId: randomUUID(),
        conversationId: newSession.conversationID,
        isMe: true,
        text,
        timestamp: Date.now(),
      });
      await handleOutgoing(encodeBase64URL(packet));
    } else {
      const packet = await EncryptMessage(session, text);
      await DB.put('messages', {
        messageId: randomUUID(),
        conversationId: session.conversationID,
        isMe: true,
        text,
        timestamp: Date.now(),
      });
      let bundleBase64: string | undefined;
      if (session.lastRespPacket)
        bundleBase64 = encodeBase64URL(
          concatBytes(decodeBase64URL(session.lastRespPacket), packet),
        );
      await handleOutgoing(encodeBase64URL(packet), bundleBase64);
    }
    input.value = '';
    await renderChatLog();
  } catch (err) {
    const msg = err instanceof Error && err.message ? err.message : String(err);
    UI.showToast(`Crypto Error: ${msg}`);
    console.error('[Crypto] Outgoing processing error:', err);
  } finally {
    isSending = false;
    input.disabled = false;
    input.focus();
  }
};

UI.$('btn-toggle-archived').onclick = () => {
  State.showArchived = !State.showArchived;
  UI.$('btn-toggle-archived').textContent = State.showArchived
    ? 'Hide Archived'
    : 'Show Archived';
  renderSidebar();
};

UI.$('btn-peer-menu').onclick = () =>
  UI.$('peer-dropdown').classList.toggle('hidden');

document.addEventListener('click', (e) => {
  if (!UI.$('btn-peer-menu').contains(e.target as Node)) closePeerDropdown();
});

UI.$('btn-search-toggle').onclick = () => {
  const c = UI.$('search-bar-container');
  c.classList.toggle('hidden');
  if (!c.classList.contains('hidden')) {
    UI.$<HTMLInputElement>('chat-search-input').focus();
  } else {
    State.searchQuery = '';
    UI.$<HTMLInputElement>('chat-search-input').value = '';
    renderChatLog();
  }
};

UI.$<HTMLInputElement>('chat-search-input').oninput = (e) => {
  State.searchQuery = (e.target as HTMLInputElement).value;
  renderChatLog();
};

UI.$('btn-rename-contact').onclick = async () => {
  closePeerDropdown();
  if (!State.currentContactFp) return;
  const contact = await DB.get<PeerContact>('contacts', State.currentContactFp);
  if (!contact) return;

  UI.showModal(`
    <div class="p-4 border-b border-slate-800"><h3 class="font-bold text-slate-200">Rename Alias</h3></div>
    <div class="p-4"><input type="text" id="rename-val" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 min-h-11 text-base sm:text-sm text-slate-200 focus:border-indigo-500 outline-none transition-colors" /></div>
    <div class="p-4 flex justify-end gap-2 border-t border-slate-800/50">
      <button id="btn-cancel" class="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 min-h-11 cursor-pointer transition-colors">Cancel</button>
      <button id="btn-save" class="px-4 py-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg min-h-11 cursor-pointer transition-colors shadow-sm">Save</button>
    </div>
  `);

  setTimeout(() => {
    const input = UI.$<HTMLInputElement>('rename-val');
    if (input) {
      input.value = contact.name;
      input.focus();
    }
  });

  UI.$('btn-cancel').onclick = UI.closeModal;
  UI.$('btn-save').onclick = async () => {
    try {
      contact.name =
        UI.$<HTMLInputElement>('rename-val').value.trim() || contact.name;
      await DB.put('contacts', contact);
      UI.$('chat-title').textContent = contact.name;
      UI.closeModal();
      await renderSidebar();
    } catch (err) {
      UI.showToast('Failed to Save Alias');
      console.error('[Storage] Rename contact error:', err);
    }
  };
};

UI.$('btn-archive-contact').onclick = async () => {
  closePeerDropdown();
  if (!State.currentContactFp) return;
  try {
    const contact = await DB.get<PeerContact>(
      'contacts',
      State.currentContactFp,
    );
    if (!contact) return;
    contact.archived = !contact.archived;
    UI.$('btn-archive-contact').textContent = contact.archived
      ? 'Restore Peer'
      : 'Archive Peer';
    await DB.put('contacts', contact);
    UI.showToast(contact.archived ? 'Peer Archived' : 'Peer Restored');
    await renderSidebar();
  } catch (err) {
    UI.showToast('Failed to Update Peer');
    console.error('[Storage] Archive contact error:', err);
  }
};

UI.$('btn-delete-contact').onclick = async () => {
  closePeerDropdown();
  if (!State.currentContactFp) return;
  const targetFp = State.currentContactFp;
  const session = await DB.get<ChannelSession>('sessions', targetFp);
  const warningText = session
    ? 'Warning: This peer has an active channel. Deleting will permanently destroy local keys and message history.'
    : 'This will permanently delete the peer and all associated local history.';

  UI.showModal(`
    <div class="p-4 border-b border-red-900/50 bg-red-950/30"><h3 class="font-bold text-red-400">Confirm Deletion</h3></div>
    <div class="p-4 text-sm text-slate-300">${escapeHtml(warningText)}</div>
    <div class="p-4 flex justify-end gap-2 border-t border-slate-800/50">
      <button id="btn-cancel-del" class="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 min-h-11 cursor-pointer transition-colors">Cancel</button>
      <button id="btn-confirm-del" class="px-4 py-2 text-sm bg-red-600 hover:bg-red-500 text-white font-medium rounded-lg min-h-11 cursor-pointer transition-colors shadow-sm">Delete Peer</button>
    </div>
  `);

  UI.$('btn-cancel-del').onclick = UI.closeModal;
  UI.$('btn-confirm-del').onclick = async () => {
    try {
      await DB.delete('contacts', targetFp);
      await DB.delete('sessions', targetFp);
      if (session) await DB.deleteConversation(session.conversationID);
      UI.closeModal();
      resetChatView(true);
      UI.showToast('Peer Deleted');
      await renderSidebar();
    } catch (err) {
      UI.showToast('Failed to Delete Peer');
      console.error('[Storage] Delete contact error:', err);
    }
  };
};

UI.$('btn-reset-session').onclick = async () => {
  closePeerDropdown();
  if (!State.currentContactFp) return;
  const targetFp = State.currentContactFp;
  const session = await DB.get<ChannelSession>('sessions', targetFp);
  if (!session) return;

  UI.showModal(`
    <div class="p-4 border-b border-amber-900/50 bg-amber-950/30"><h3 class="font-bold text-amber-400">Wipe Channel State?</h3></div>
    <div class="p-4 text-sm text-slate-300">This drops handshake keys and clears local conversation history. It does not remove the peer from your contacts.</div>
    <div class="p-4 flex justify-end gap-2 border-t border-slate-800/50">
      <button id="btn-cancel-wipe" class="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 min-h-11 cursor-pointer transition-colors">Cancel</button>
      <button id="btn-confirm-wipe" class="px-4 py-2 text-sm bg-amber-600 hover:bg-amber-500 text-white font-medium rounded-lg min-h-11 cursor-pointer transition-colors shadow-sm">Wipe</button>
    </div>
  `);
  UI.$('btn-cancel-wipe').onclick = UI.closeModal;
  UI.$('btn-confirm-wipe').onclick = async () => {
    try {
      await DB.delete('sessions', targetFp);
      await DB.deleteConversation(session.conversationID);
      UI.closeModal();
      await renderChatLog();
      UI.showToast('Channel State Wiped');
    } catch (err) {
      UI.showToast('Failed to Wipe Channel');
      console.error('[Storage] Wipe session error:', err);
    }
  };
};

UI.$('btn-global-settings').onclick = () => {
  const cfg = Settings.get();
  UI.showModal(`
    <div class="p-4 border-b border-slate-800"><h3 class="font-bold text-slate-200">Global Settings</h3></div>
    <div class="p-4 space-y-4">
      <label class="flex items-center gap-3 text-sm text-slate-300 min-h-11 cursor-pointer select-none">
        <input type="checkbox" id="cfg-persist" class="rounded bg-slate-950 border-slate-700 text-indigo-500 w-4 h-4 focus:ring-indigo-500 transition-colors" ${cfg.persistHandshakes ? 'checked' : ''} />
        Persist Handshake State (default)
      </label>
    </div>
    <div class="p-4 flex justify-end border-t border-slate-800/50">
      <button id="btn-save-cfg" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium min-h-11 cursor-pointer transition-colors shadow-sm">Save Options</button>
    </div>
  `);
  UI.$('btn-save-cfg').onclick = () => {
    try {
      Settings.set({
        persistHandshakes: UI.$<HTMLInputElement>('cfg-persist').checked,
      });
      UI.closeModal();
      UI.showToast('Settings Saved');
    } catch (err) {
      UI.showToast('Failed to Save Settings');
      console.warn('[Storage] Failed to save settings:', err);
    }
  };
};

async function processClipboardText(rawText: string) {
  const text = rawText.trim();
  if (!text.startsWith(Config.PREFIX))
    return UI.showToast('Invalid Envelope Format');
  if (text.length > Config.MAX_PACKET_SIZE)
    return UI.showToast('Packet Exceeds Size Limit');

  try {
    const bytes = parseEnvelope(text);
    if (bytes[0] === Config.IDENTITY_VERSION && bytes.length > 1000)
      return UI.showToast("Identity Bundle Detected (Use 'Link New Peer')");

    let offset = 0;
    let sessionChanged = false;

    while (offset < bytes.length) {
      if (bytes.length - offset < 12)
        throw new Error('Truncated packet header');
      const { type, payloadLength } = parseHeader(
        bytes.slice(offset, offset + 12),
      );
      if (payloadLength > Config.MAX_PACKET_SIZE)
        throw new Error('Payload size constraint violation');

      const pktLen = 12 + payloadLength;
      if (bytes.length - offset < pktLen)
        throw new Error('Incomplete packet payload structure');
      const pktBytes = bytes.slice(offset, offset + pktLen);

      if (type === Config.PACKET_TYPES.INIT) {
        const { session, plaintext, respPacket } = await ProcessInit(pktBytes);
        await DB.put('messages', {
          messageId: randomUUID(),
          conversationId: session.conversationID,
          isMe: false,
          text: plaintext,
          timestamp: Date.now(),
        });
        UI.showToast('Handshake INIT Processed');
        await handleOutgoing(encodeBase64URL(respPacket));
        if (State.currentContactFp !== session.contactFp)
          await selectContact(session.contactFp);
        sessionChanged = true;
      } else if (type === Config.PACKET_TYPES.RESP) {
        const { alreadyEstablished, session } = await ProcessResp(pktBytes);
        if (alreadyEstablished)
          console.warn('[Ratchet] Skipping redundant RESP packet in bundle.');
        else {
          UI.showToast('Channel Established');
          sessionChanged = true;
        }
        if (State.currentContactFp !== session.contactFp)
          await selectContact(session.contactFp);
      } else if (type === Config.PACKET_TYPES.MSG) {
        const { session, plaintext } = await DecryptMessage(pktBytes);
        await DB.put('messages', {
          messageId: randomUUID(),
          conversationId: session.conversationID,
          isMe: false,
          text: plaintext,
          timestamp: Date.now(),
        });
        UI.showToast('Message Decrypted');
        sessionChanged = true;
      }
      offset += pktLen;
    }
    if (sessionChanged) {
      await renderChatLog();
      await renderSidebar();
    }
  } catch (err) {
    const msg = err instanceof Error && err.message ? err.message : String(err);
    UI.showToast(`Packet Dropped: ${msg}`);
    console.error('[Ratchet] Incoming packet error:', err);
  }
}

UI.$('btn-read').onclick = UI.$('btn-read-clipboard').onclick = async () => {
  try {
    const text = await navigator.clipboard.readText();
    await processClipboardText(text);
  } catch (err) {
    UI.showToast('Failed to Read Clipboard');
    console.error('[Clipboard] Read error:', err);
  }
};

document.addEventListener('paste', async (e) => {
  if (['INPUT', 'TEXTAREA'].includes((e.target as HTMLElement).tagName)) return;
  const text = (e.clipboardData?.getData('text') ?? '').trim();
  if (!text.startsWith(Config.PREFIX)) return;
  e.preventDefault();
  await processClipboardText(text);
});

async function showPeerMetadata(contactFp: string) {
  const session = await DB.get<ChannelSession>('sessions', contactFp);
  const contact = await DB.get<PeerContact>('contacts', contactFp);
  const stateColor = session
    ? session.state === 'ESTABLISHED'
      ? 'text-emerald-400'
      : 'text-amber-400'
    : 'text-slate-500';

  let bundleHashText = 'N/A';
  if (contact?.bundle)
    bundleHashText = `${calculateFingerprint(decodeBase64URL(contact.bundle)).substring(0, 16)}...`;

  UI.$('metadata-title').textContent = 'Peer Diagnostics';
  UI.$('metadata-content').innerHTML = `
    <div><strong>Peer FP:</strong> <span id="meta-fp"></span></div>
    <div><strong>Bundle Hash:</strong> <span id="meta-hash"></span></div>
    <hr class="border-slate-800 my-2" />
    <div><strong>Double Ratchet State:</strong> <span id="meta-state" class="${stateColor}"></span></div>
    ${
      session
        ? `<div><strong>Conversation ID:</strong> <span id="meta-cid"></span></div>
    <div><strong>Message Sequence (Ns):</strong> <span id="meta-ns"></span></div>
    <div><strong>Receive Sequence (Nr):</strong> <span id="meta-nr"></span></div>
    <div><strong>Previous Chain Length (PN):</strong> <span id="meta-pn"></span></div>
    <div><strong>Persisted:</strong> <span id="meta-persisted"></span></div>`
        : ''
    }
    <div class="mt-4 text-[9px] text-slate-500 italic">* Ephemeral key material zeroized for memory hygiene</div>
  `;

  UI.$('meta-fp').textContent = contact?.fingerprint || 'Unknown';
  UI.$('meta-hash').textContent = bundleHashText;
  UI.$('meta-state').textContent = session ? session.state : 'IDLE';

  if (session) {
    UI.$('meta-cid').textContent = session.conversationID.substring(0, 16);
    UI.$('meta-ns').textContent = session.Ns.toString();
    UI.$('meta-nr').textContent = session.Nr.toString();
    UI.$('meta-pn').textContent = session.PN.toString();
    UI.$('meta-persisted').textContent = Settings.get().persistHandshakes
      ? 'IndexedDB'
      : 'Volatile';
  }

  UI.$('metadata-overlay').classList.remove('hidden');
  UI.$('metadata-overlay').classList.add('flex');
}

function showMessageMetadata(msg: MessageData) {
  UI.$('metadata-title').textContent = 'Frame Diagnostics';
  UI.$('metadata-content').innerHTML = `
    <div><strong>Frame ID:</strong> <span id="meta-frame"></span></div>
    <div><strong>Vector:</strong> <span id="meta-vector"></span></div>
    <div><strong>Timestamp:</strong> <span id="meta-ts"></span> <small>(<span id="meta-ts-local"></span>)</small></div>
    <hr class="border-slate-800 my-2" />
    <div><strong>Symmetric Encryption:</strong> AES-256-GCM</div>
    <div><strong>Classical Key Exchange:</strong> X25519</div>
    <div><strong>Post-Quantum KEM:</strong> ML-KEM-1024</div>
    <div><strong>Post-Quantum Signature:</strong> ML-DSA-87</div>
    <div><strong>Key Derivation & Hashing:</strong> HKDF-SHA256 / HMAC-SHA256</div>
  `;

  UI.$('meta-frame').textContent = msg.messageId;
  UI.$('meta-vector').textContent = msg.isMe
    ? 'Egress (Local)'
    : 'Ingress (Remote)';
  const ts = new Date(msg.timestamp);
  UI.$('meta-ts').textContent = ts.toISOString();
  UI.$('meta-ts-local').textContent = ts.toLocaleString();
  UI.$('metadata-overlay').classList.remove('hidden');
  UI.$('metadata-overlay').classList.add('flex');
}

UI.$('metadata-overlay').addEventListener('click', () => {
  UI.$('metadata-overlay').classList.add('hidden');
  UI.$('metadata-overlay').classList.remove('flex');
});
UI.$('btn-close-metadata').onclick = () => {
  UI.$('metadata-overlay').classList.add('hidden');
  UI.$('metadata-overlay').classList.remove('flex');
};

async function handleRoute() {
  const hash = location.hash.replace(/^#/, '').trim();

  if (!hash) {
    resetChatView(false);
    await renderSidebar();
    return;
  }

  if (hash === State.currentContactFp) return;

  await selectContact(hash, true);
}

addEventListener('hashchange', handleRoute);

const initApp = async () => {
  try {
    await getLocalIdentity();
    await renderSidebar();
    await handleRoute();
    console.info('[App] Initialization complete.');
  } catch (err) {
    UI.showToast('Initialization Failed');
    console.error('[App] Boot failure:', err);
  }
};

if (document.readyState === 'loading')
  document.addEventListener('DOMContentLoaded', initApp);
else initApp();

addEventListener('load', async () => {
  try {
    const registration = await navigator.serviceWorker.register('/sw.js');
    console.info('[ServiceWorker] Registration complete.');

    registration.addEventListener('updatefound', () => {
      const newWorker = registration.installing;
      if (!newWorker) return;

      newWorker.addEventListener('statechange', () => {
        if (
          newWorker.state === 'installed' &&
          navigator.serviceWorker.controller
        ) {
          console.info('[ServiceWorker] New version available.');
          UI.showToast('Update Available');
        }
      });
    });

    setInterval(() => {
      registration.update();
    }, 60000);
  } catch (err) {
    console.error('[ServiceWorker] Registration failed:', err);
  }
});
