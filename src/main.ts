import { Config } from './config.js';
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
import { Message } from './types.js';

const State = {
  currentContactFp: undefined as string | undefined,
  showArchived: false,
  searchQuery: '',
};

let toastTimer: number | undefined;
const UI = {
  $: <T extends HTMLElement>(s: string) => {
    const el = document.querySelector(s);
    if (!el) throw new Error(`Required DOM element not found: ${s}`);
    return el as T;
  },
  showToast: (msg: string, duration = 3500) => {
    const t = UI.$('#toast');
    UI.$('#toast-msg').textContent = msg;
    t.classList.remove('opacity-0', 'pointer-events-none');
    t.classList.add('opacity-100');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      t.classList.remove('opacity-100');
      t.classList.add('opacity-0', 'pointer-events-none');
    }, duration);
  },
  showModal: (containerHtml: string) => {
    UI.$('#modal-container').innerHTML = containerHtml;
    UI.$('#modal-overlay').classList.remove('hidden');
    UI.$('#modal-overlay').classList.add('flex');
  },
  closeModal: () => {
    UI.$('#modal-overlay').classList.remove('flex');
    UI.$('#modal-overlay').classList.add('hidden');
  },
  closeMetadata: () => {
    UI.$('#metadata-overlay').classList.add('hidden');
    UI.$('#metadata-overlay').classList.remove('flex');
  },
};

UI.$('#modal-overlay').onclick = () => UI.closeModal();

const closePeerDropdown = () => UI.$('#peer-dropdown').classList.add('hidden');

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    UI.closeModal();
    UI.closeMetadata();
    closePeerDropdown();
  }
});

function resetChatView(updateHash = true) {
  delete State.currentContactFp;

  if (updateHash && location.hash)
    history.replaceState(null, '', location.pathname + location.search);

  UI.$('#chat-view').classList.add('hidden');
  UI.$('#chat-view').classList.remove('flex');
  UI.$('#sidebar-view').classList.remove('max-md:hidden');
  UI.$('#chat-messages').replaceChildren();
  UI.$('#chat-title').textContent = 'Select a Peer';
  UI.$('#chat-status-text').textContent = 'Idle';
  UI.$('#chat-status-dot').className = 'w-2 h-2 rounded-full bg-slate-500';
  UI.$('#chat-input-area').classList.add('hidden');
  UI.$('#empty-state').classList.remove('hidden');
}

async function copyToClipboard(text: string, msg: string) {
  try {
    await navigator.clipboard.writeText(text);
    UI.showToast(msg);
  } catch (err) {
    console.warn('[Clipboard] Write error, falling back to modal:', err);
    UI.showModal(`
      <div class="p-4 border-b border-slate-800"><h3 class="font-bold text-slate-200">Manual Copy Required</h3></div>
      <div class="p-4 space-y-3">
        <p class="text-xs text-amber-400">Your browser blocked automatic clipboard access. Please copy the text below manually:</p>
        <div id="fallback-text" class="flex min-h-11 items-center rounded-lg border border-slate-800/80 bg-slate-950 p-3 font-mono text-[11px] break-all text-emerald-300 shadow-inner select-all"></div>
      </div>
      <div class="p-4 flex justify-end gap-2 border-t border-slate-800/50">
        <button id="btn-close-fallback" class="px-4 py-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white font-medium rounded-lg min-h-11 cursor-pointer transition-colors shadow-sm">Done</button>
      </div>
    `);
    requestAnimationFrame(() => {
      UI.$<HTMLDivElement>('#fallback-text').textContent = text;
    });
    UI.$('#btn-close-fallback').onclick = UI.closeModal;
  }
}

async function handleOutgoing(packetBase64: string, bundleBase64?: string) {
  await copyToClipboard(
    formatEnvelope(decodeBase64URL(bundleBase64 ?? packetBase64)),
    `Encrypted ${typeof bundleBase64 !== 'undefined' ? 'Bundle' : 'Packet'} Copied`,
  );
}

async function renderSidebar() {
  UI.$('#my-fingerprint').textContent = calculateFingerprint(
    serializeIdentityPublic(await getLocalIdentity()),
  );

  let contacts = await DB.getAll('contacts');
  if (!State.showArchived)
    contacts = contacts.filter(({ archived }) => !archived);

  const sessions = await DB.getAll('sessions');

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
      const session = sessions.find(
        ({ contactFp }) => contactFp === c.fingerprint,
      );
      if (session)
        unreadCount = (
          await DB.getAllByIndex(
            'messages',
            'conversationId',
            session.conversationId,
          )
        ).filter(
          ({ isMe, timestamp }) => !isMe && timestamp > c.lastReadTimestamp,
        ).length;
    }

    const topRow = document.createElement('div');
    topRow.className = 'flex justify-between items-center gap-2';

    const nameSpan = document.createElement('span');
    nameSpan.className = 'font-medium truncate flex-1';
    nameSpan.textContent = c.name;
    topRow.appendChild(nameSpan);

    if (unreadCount) {
      const badge = document.createElement('span');
      badge.className =
        'bg-emerald-500 text-slate-950 text-[10px] font-bold px-1.5 py-0.5 rounded-full shrink-0 shadow-sm';
      badge.textContent = `${unreadCount}`;
      topRow.appendChild(badge);
    }

    const botRow = document.createElement('div');
    botRow.className =
      'flex justify-between items-center text-[10px] text-slate-500 font-mono';

    const fpSpan = document.createElement('span');
    fpSpan.className = 'truncate';
    fpSpan.textContent = c.fingerprint;
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
    div.oncontextmenu = (e) => {
      e.preventDefault();
      showPeerMetadata(c.fingerprint);
    };

    frag.appendChild(div);
  }
  UI.$('#contacts-list').replaceChildren(frag);
}

async function selectContact(fp: string, isNavigatingHistory = false) {
  if (fp === State.currentContactFp) return;

  const contact = await DB.get('contacts', fp);
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
  UI.$('#chat-messages').replaceChildren();

  contact.lastReadTimestamp = Date.now();
  await DB.put('contacts', contact);

  UI.$('#sidebar-view').classList.add('max-md:hidden');
  UI.$('#chat-view').classList.remove('hidden');
  UI.$('#chat-view').classList.add('flex');
  UI.$('#empty-state').classList.add('hidden');
  UI.$('#chat-input-area').classList.remove('hidden');
  UI.$('#chat-title').textContent = contact.name;
  closePeerDropdown();
  UI.$('#btn-archive-contact').textContent = contact.archived
    ? 'Restore Peer'
    : 'Archive Peer';
  State.searchQuery = '';
  UI.$<HTMLInputElement>('#chat-search-input').value = '';
  UI.$('#search-bar-container').classList.add('hidden');

  await renderChatLog(true);
  await renderSidebar();
}

let renderSeq = 0;
async function renderChatLog(isInitialView = false) {
  if (!State.currentContactFp) return;
  const currentSeq = ++renderSeq;

  const sessions = await DB.getAll('sessions');
  const session = sessions.find(
    ({ contactFp }) => contactFp === State.currentContactFp,
  );
  if (currentSeq !== renderSeq) return;

  if (session)
    if (
      session.state === 'HANDSHAKE_SENT' ||
      session.state === 'HANDSHAKE_RECEIVED'
    ) {
      UI.$('#chat-status-text').textContent =
        session.state === 'HANDSHAKE_SENT'
          ? 'Awaiting RESP'
          : 'Handshake Pending';
      UI.$('#chat-status-dot').className =
        'w-2 h-2 rounded-full bg-amber-400 animate-pulse';
      UI.$<HTMLInputElement>('#chat-input').disabled =
        UI.$<HTMLInputElement>('#media-input').disabled =
        UI.$<HTMLButtonElement>('#btn-attach').disabled =
          session.state === 'HANDSHAKE_SENT';
    } else {
      UI.$('#chat-status-text').textContent = 'Channel Established';
      UI.$('#chat-status-dot').className =
        'w-2 h-2 rounded-full bg-emerald-400';
      UI.$<HTMLInputElement>('#chat-input').disabled =
        UI.$<HTMLInputElement>('#media-input').disabled =
        UI.$<HTMLButtonElement>('#btn-attach').disabled =
          false;
    }
  else {
    UI.$('#chat-status-text').textContent = 'Idle';
    UI.$('#chat-status-dot').className = 'w-2 h-2 rounded-full bg-slate-500';
    UI.$<HTMLInputElement>('#chat-input').disabled =
      UI.$<HTMLInputElement>('#media-input').disabled =
      UI.$<HTMLButtonElement>('#btn-attach').disabled =
        false;
  }

  const query = State.searchQuery.toLowerCase();
  const highlightRegex = query
    ? new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi')
    : undefined;

  const allChatMsgs = session
    ? await DB.getAllByIndex(
        'messages',
        'conversationId',
        session.conversationId,
      )
    : [];

  const chatMsgs = allChatMsgs.sort((a, b) =>
    a.timestamp === b.timestamp
      ? a.id.localeCompare(b.id)
      : a.timestamp - b.timestamp,
  );

  const ctn = UI.$('#chat-messages');
  const frag = document.createDocumentFragment();

  let displayedCount = 0;
  for (const m of chatMsgs) {
    if (query && !m.text.toLowerCase().includes(query)) continue;
    displayedCount++;

    const div = document.createElement('div');
    div.className = `flex flex-col max-w-[85%] sm:max-w-[75%] p-3.5 rounded-2xl text-sm break-words shadow-sm border transition-all ${
      m.isMe
        ? 'bg-indigo-600 border-indigo-500/60 self-end rounded-br-xs text-indigo-50'
        : 'bg-slate-900 border-slate-800 self-start rounded-bl-xs text-slate-200'
    }`;

    if (m.text.startsWith('data:image/')) {
      const img = document.createElement('img');
      img.src = m.text;
      img.className = 'max-w-full max-h-80 rounded-lg object-contain my-1';
      div.appendChild(img);
    } else if (m.text.startsWith('data:video/')) {
      const vid = document.createElement('video');
      vid.src = m.text;
      vid.controls = true;
      vid.className = 'max-w-full max-h-80 rounded-lg object-contain my-1';
      div.appendChild(vid);
    } else if (m.text.startsWith('data:audio/')) {
      const aud = document.createElement('audio');
      aud.src = m.text;
      aud.controls = true;
      aud.className = 'max-w-full my-1';
      div.appendChild(aud);
    } else if (query && highlightRegex) {
      const span = document.createElement('span');
      div.appendChild(span);
      for (const part of m.text.split(highlightRegex))
        if (part.toLowerCase() === query) {
          const partSpan = document.createElement('span');
          partSpan.className =
            'bg-amber-500/30 text-white rounded px-0.5 font-semibold';
          partSpan.textContent = part;
          span.appendChild(partSpan);
        } else span.appendChild(document.createTextNode(part));
    } else div.textContent = m.text;

    const timeSpan = document.createElement('div');
    timeSpan.className = `text-[10px] mt-1.5 select-none flex justify-end ${
      m.isMe ? 'text-indigo-200/80' : 'text-slate-400'
    }`;
    timeSpan.textContent = new Date(m.timestamp).toLocaleString();
    div.appendChild(timeSpan);

    frag.appendChild(div);
  }

  if (query && !displayedCount) {
    const emptySearch = document.createElement('div');
    emptySearch.className =
      'flex flex-col items-center justify-center my-auto py-12 text-slate-500 text-xs';
    emptySearch.textContent = 'No matching messages found';
    frag.appendChild(emptySearch);
  }

  ctn.replaceChildren(frag);

  if (isInitialView) ctn.scrollTop = ctn.scrollHeight;
  else
    requestAnimationFrame(() => {
      ctn.scrollTo({ top: ctn.scrollHeight, behavior: 'smooth' });
    });
}

UI.$('#btn-attach').onclick = () => UI.$('#media-input').click();

let pendingMediaText = '';

const submitChatMessage = async () => {
  if (isSending) return;
  const input = UI.$<HTMLInputElement>('#chat-input');
  const text = pendingMediaText || input.value.trim();
  pendingMediaText = '';

  if (!text || !State.currentContactFp) return;

  isSending = true;
  input.disabled = true;

  const submitBtn = UI.$<HTMLButtonElement>('#chat-form button[type="submit"]');
  submitBtn.disabled = true;

  try {
    const session = await DB.get('sessions', State.currentContactFp);
    if (!session) {
      const { packet, session: newSession } = await CreateInit(
        State.currentContactFp,
        text,
      );
      await DB.put('messages', {
        id: randomUUID(),
        conversationId: newSession.conversationId,
        isMe: true,
        text,
        timestamp: Date.now(),
      });
      await handleOutgoing(encodeBase64URL(packet));
    } else {
      const packet = await EncryptMessage(session, text);
      await DB.put('messages', {
        id: randomUUID(),
        conversationId: session.conversationId,
        isMe: true,
        text,
        timestamp: Date.now(),
      });
      await handleOutgoing(
        encodeBase64URL(packet),
        session.lastRespPacket
          ? encodeBase64URL(
              concatBytes(decodeBase64URL(session.lastRespPacket), packet),
            )
          : undefined,
      );
    }
    input.value = '';
  } catch (err) {
    UI.showToast(
      `Crypto Error: ${err instanceof Error && err.message ? err.message : String(err)}`,
    );
    console.error('[Crypto] Outgoing processing error:', err);
  } finally {
    isSending = false;
    submitBtn.disabled = false;
    await renderChatLog();
    if (!input.disabled) input.focus();
  }
};

UI.$<HTMLInputElement>('#media-input').onchange = (e) => {
  const file = (e.target as HTMLInputElement).files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (re) => {
    pendingMediaText = re.target?.result as string;
    submitChatMessage();
    UI.$<HTMLInputElement>('#media-input').value = '';
  };
  reader.readAsDataURL(file);
};

UI.$<HTMLInputElement>('#chat-input').addEventListener('paste', (e) => {
  const items = e.clipboardData?.items;
  if (!items) return;
  for (const item of items)
    if (
      item.type.startsWith('image/') ||
      item.type.startsWith('video/') ||
      item.type.startsWith('audio/')
    ) {
      e.preventDefault();
      const file = item.getAsFile();
      if (!file) continue;
      const reader = new FileReader();
      reader.onload = (re) => {
        pendingMediaText = re.target?.result as string;
        submitChatMessage();
      };
      reader.readAsDataURL(file);
      break;
    }
});

let isSending = false;
UI.$<HTMLFormElement>('#chat-form').onsubmit = (e) => {
  e.preventDefault();
  submitChatMessage();
};

UI.$('#btn-back-mobile').onclick = () => {
  history.back();
};

UI.$('#btn-copy-identity').onclick = async () => {
  await copyToClipboard(
    formatEnvelope(serializeIdentityPublic(await getLocalIdentity())),
    'Identity Bundle Copied',
  );
};

UI.$('#btn-add-contact').onclick = async () => {
  try {
    const text = await navigator.clipboard.readText();
    const bytes = parseEnvelope(text);
    const fp = calculateFingerprint(bytes);
    const localFp = await getLocalFingerprint();
    if (fp === localFp) {
      UI.showToast('Cannot link own identity.');
      return;
    }
    if (await DB.get('contacts', fp)) {
      UI.showToast('Peer already exists.');
      return;
    }

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

    requestAnimationFrame(() => {
      const input = UI.$<HTMLInputElement>('#new-alias-input');
      if (input) {
        input.focus();
        input.onkeydown = (e) => {
          if (e.key === 'Enter') UI.$('#btn-confirm-add').click();
        };
      }
    });

    UI.$('#btn-cancel-add').onclick = UI.closeModal;
    UI.$('#btn-confirm-add').onclick = async () => {
      try {
        const name = UI.$<HTMLInputElement>('#new-alias-input').value.trim();
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
        UI.showToast('Peer linked successfully.');
        await renderSidebar();
      } catch (err) {
        UI.showToast('Failed to save peer.');
        console.error('[Storage] Save peer error:', err);
      }
    };
  } catch (err) {
    UI.showToast('Invalid identity format in clipboard.');
    console.error('[Clipboard] Parse identity error:', err);
  }
};

UI.$('#btn-toggle-archived').onclick = () => {
  State.showArchived = !State.showArchived;
  UI.$('#btn-toggle-archived').textContent = State.showArchived
    ? 'Hide Archived'
    : 'Show Archived';
  renderSidebar();
};

UI.$('#btn-peer-menu').onclick = () =>
  UI.$('#peer-dropdown').classList.toggle('hidden');

document.addEventListener('click', (e) => {
  if (
    !UI.$('#btn-peer-menu').contains(e.target as Node) &&
    !UI.$('#peer-dropdown').contains(e.target as Node)
  )
    closePeerDropdown();
});

UI.$('#btn-search-toggle').onclick = () => {
  const c = UI.$('#search-bar-container');
  c.classList.toggle('hidden');
  if (!c.classList.contains('hidden'))
    UI.$<HTMLInputElement>('#chat-search-input').focus();
  else {
    State.searchQuery = '';
    UI.$<HTMLInputElement>('#chat-search-input').value = '';
    renderChatLog();
  }
};

UI.$<HTMLInputElement>('#chat-search-input').oninput = (e) => {
  State.searchQuery = (e.target as HTMLInputElement).value;
  renderChatLog();
};

UI.$('#btn-rename-contact').onclick = async () => {
  closePeerDropdown();
  if (!State.currentContactFp) return;
  const contact = await DB.get('contacts', State.currentContactFp);
  if (!contact) return;

  UI.showModal(`
    <div class="p-4 border-b border-slate-800"><h3 class="font-bold text-slate-200">Rename Alias</h3></div>
    <div class="p-4"><input type="text" id="rename-val" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 min-h-11 text-base sm:text-sm text-slate-200 focus:border-indigo-500 outline-none transition-colors" /></div>
    <div class="p-4 flex justify-end gap-2 border-t border-slate-800/50">
      <button id="btn-cancel" class="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 min-h-11 cursor-pointer transition-colors">Cancel</button>
      <button id="btn-save" class="px-4 py-2 text-sm bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg min-h-11 cursor-pointer transition-colors shadow-sm">Save</button>
    </div>
  `);

  requestAnimationFrame(() => {
    const input = UI.$<HTMLInputElement>('#rename-val');
    if (input) {
      input.value = contact.name;
      input.focus();
      input.onkeydown = (e) => {
        if (e.key === 'Enter') UI.$('#btn-save').click();
      };
    }
  });

  UI.$('#btn-cancel').onclick = UI.closeModal;
  UI.$('#btn-save').onclick = async () => {
    try {
      contact.name =
        UI.$<HTMLInputElement>('#rename-val').value.trim() || contact.name;
      await DB.put('contacts', contact);
      UI.$('#chat-title').textContent = contact.name;
      UI.closeModal();
      await renderSidebar();
    } catch (err) {
      UI.showToast('Failed to save alias.');
      console.error('[Storage] Rename contact error:', err);
    }
  };
};

UI.$('#btn-archive-contact').onclick = async () => {
  closePeerDropdown();
  if (!State.currentContactFp) return;
  try {
    const contact = await DB.get('contacts', State.currentContactFp);
    if (!contact) return;
    contact.archived = !contact.archived;
    UI.$('#btn-archive-contact').textContent = contact.archived
      ? 'Restore Peer'
      : 'Archive Peer';
    await DB.put('contacts', contact);
    UI.showToast(contact.archived ? 'Peer archived.' : 'Peer restored.');
    await renderSidebar();
  } catch (err) {
    UI.showToast('Failed to update peer.');
    console.error('[Storage] Archive contact error:', err);
  }
};

UI.$('#btn-delete-contact').onclick = async () => {
  closePeerDropdown();
  if (!State.currentContactFp) return;
  const targetFp = State.currentContactFp;
  const session = await DB.get('sessions', targetFp);

  UI.showModal(`
    <div class="p-4 border-b border-red-900/50 bg-red-950/30"><h3 class="font-bold text-red-400">Confirm Deletion</h3></div>
    <div class="p-4 text-sm text-slate-300">${
      session
        ? 'Warning: This peer has an active channel. Deleting will permanently destroy local keys and message history.'
        : 'This will permanently delete the peer and all associated local history.'
    }</div>
    <div class="p-4 flex justify-end gap-2 border-t border-slate-800/50">
      <button id="btn-cancel-del" class="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 min-h-11 cursor-pointer transition-colors">Cancel</button>
      <button id="btn-confirm-del" class="px-4 py-2 text-sm bg-red-600 hover:bg-red-500 text-white font-medium rounded-lg min-h-11 cursor-pointer transition-colors shadow-sm">Delete Peer</button>
    </div>
  `);

  UI.$('#btn-cancel-del').onclick = UI.closeModal;
  UI.$('#btn-confirm-del').onclick = async () => {
    try {
      await DB.delete('contacts', targetFp);
      await DB.delete('sessions', targetFp);
      if (session) await DB.deleteConversation(session.conversationId);
      UI.closeModal();
      resetChatView(true);
      UI.showToast('Peer deleted.');
      await renderSidebar();
    } catch (err) {
      UI.showToast('Failed to delete peer.');
      console.error('[Storage] Delete contact error:', err);
    }
  };
};

UI.$('#btn-reset-session').onclick = async () => {
  closePeerDropdown();
  if (!State.currentContactFp) return;
  const targetFp = State.currentContactFp;
  const session = await DB.get('sessions', targetFp);
  if (!session) return;

  UI.showModal(`
    <div class="p-4 border-b border-amber-900/50 bg-amber-950/30"><h3 class="font-bold text-amber-400">Wipe Channel State?</h3></div>
    <div class="p-4 text-sm text-slate-300">This drops handshake keys and clears local conversation history. It does not remove the peer from your contacts.</div>
    <div class="p-4 flex justify-end gap-2 border-t border-slate-800/50">
      <button id="btn-cancel-wipe" class="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 min-h-11 cursor-pointer transition-colors">Cancel</button>
      <button id="btn-confirm-wipe" class="px-4 py-2 text-sm bg-amber-600 hover:bg-amber-500 text-white font-medium rounded-lg min-h-11 cursor-pointer transition-colors shadow-sm">Wipe</button>
    </div>
  `);
  UI.$('#btn-cancel-wipe').onclick = UI.closeModal;
  UI.$('#btn-confirm-wipe').onclick = async () => {
    try {
      await DB.delete('sessions', targetFp);
      await DB.deleteConversation(session.conversationId);
      UI.closeModal();
      await renderChatLog();
      UI.showToast('Channel state wiped.');
    } catch (err) {
      UI.showToast('Failed to wipe channel.');
      console.error('[Storage] Wipe session error:', err);
    }
  };
};

UI.$('#btn-global-settings').onclick = () => {
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
  UI.$('#btn-save-cfg').onclick = () => {
    try {
      Settings.set({
        persistHandshakes: UI.$<HTMLInputElement>('#cfg-persist').checked,
      });
      UI.closeModal();
      UI.showToast('Settings saved successfully.');
    } catch (err) {
      UI.showToast('Failed to save settings.');
      console.warn('[Storage] Failed to save settings:', err);
    }
  };
};

async function processClipboardText(rawText: string) {
  const text = rawText.trim();
  if (!text.startsWith(Config.PREFIX)) {
    UI.showToast('Invalid ECP envelope format.');
    return;
  }
  if (text.length > Config.MAX_PACKET_SIZE) {
    UI.showToast('Packet exceeds maximum size limits.');
    return;
  }

  try {
    const bytes = parseEnvelope(text);
    if (bytes[0] === Config.IDENTITY_VERSION && bytes.length === 4225) {
      UI.showToast("Identity bundle detected. Please use 'Link New Peer'.");
      return;
    }

    let offset = 0;
    let sessionChanged = false;

    while (offset < bytes.length) {
      if (bytes.length - offset < 12)
        throw new Error('Truncated packet header.');
      const { type, payloadLength } = parseHeader(
        bytes.slice(offset, offset + 12),
      );
      if (payloadLength > Config.MAX_PACKET_SIZE)
        throw new Error('Payload size constraint violation.');

      const pktLen = 12 + payloadLength;
      if (bytes.length - offset < pktLen)
        throw new Error('Incomplete packet payload structure.');
      const pktBytes = bytes.slice(offset, offset + pktLen);

      offset += pktLen;

      try {
        if (type === Config.PACKET_TYPES.INIT) {
          const { session, plaintext, respPacket } =
            await ProcessInit(pktBytes);
          await DB.put('messages', {
            id: randomUUID(),
            conversationId: session.conversationId,
            isMe: false,
            text: plaintext,
            timestamp: Date.now(),
          });
          if (State.currentContactFp === session.contactFp) {
            const contact = await DB.get('contacts', session.contactFp);
            if (contact) {
              contact.lastReadTimestamp = Date.now();
              await DB.put('contacts', contact);
            }
          }
          UI.showToast('Handshake INIT processed.');
          await handleOutgoing(encodeBase64URL(respPacket));
          sessionChanged = true;
        } else if (type === Config.PACKET_TYPES.RESP) {
          const { alreadyEstablished } = await ProcessResp(pktBytes);
          if (alreadyEstablished)
            console.warn('[Ratchet] Skipping redundant RESP packet in bundle.');
          else {
            UI.showToast('Channel established.');
            sessionChanged = true;
          }
        } else if (type === Config.PACKET_TYPES.MSG) {
          const { session, plaintext } = await DecryptMessage(pktBytes);
          await DB.put('messages', {
            id: randomUUID(),
            conversationId: session.conversationId,
            isMe: false,
            text: plaintext,
            timestamp: Date.now(),
          });
          if (State.currentContactFp === session.contactFp) {
            const contact = await DB.get('contacts', session.contactFp);
            if (contact) {
              contact.lastReadTimestamp = Date.now();
              await DB.put('contacts', contact);
            }
          }
          UI.showToast('Message decrypted.');
          sessionChanged = true;
        }
      } catch (err) {
        console.error('[Ratchet] Individual packet error skipped:', err);
      }
    }

    if (sessionChanged) {
      await renderChatLog();
      await renderSidebar();
    }
  } catch (err) {
    UI.showToast(
      `Bundle Rejected: ${err instanceof Error && err.message ? err.message : String(err)}`,
    );
    console.error('[Ratchet] Incoming bundle error:', err);
  }
}

UI.$('#btn-read').onclick = UI.$('#btn-read-clipboard').onclick = async () => {
  try {
    const text = await navigator.clipboard.readText();
    await processClipboardText(text);
  } catch (err) {
    UI.showToast('Failed to read clipboard.');
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
  const session = await DB.get('sessions', contactFp);
  const contact = await DB.get('contacts', contactFp);

  UI.$('#metadata-title').textContent = 'Peer Diagnostics';
  UI.$('#metadata-content').innerHTML = `
    <div><strong>Peer FP:</strong> <span id="meta-fp"></span></div>
    <hr class="border-slate-800 my-2" />
    <div><strong>Double Ratchet State:</strong> <span id="meta-state" class="${
      session
        ? session.state === 'ESTABLISHED'
          ? 'text-emerald-400'
          : 'text-amber-400'
        : 'text-slate-500'
    }"></span></div>
    ${
      session
        ? `<div><strong>Conversation ID:</strong> <span id="meta-cid"></span></div>
    <div><strong>Message Sequence (Ns):</strong> <span id="meta-ns"></span></div>
    <div><strong>Receive Sequence (Nr):</strong> <span id="meta-nr"></span></div>
    <div><strong>Previous Chain Length (PN):</strong> <span id="meta-pn"></span></div>`
        : ''
    }`;

  UI.$('#meta-fp').textContent = contact ? contact.fingerprint : 'Unknown';
  UI.$('#meta-state').textContent = session ? session.state : 'IDLE';

  if (session) {
    UI.$('#meta-cid').textContent = session.conversationId;
    UI.$('#meta-ns').textContent = `${session.Ns}`;
    UI.$('#meta-nr').textContent = `${session.Nr}`;
    UI.$('#meta-pn').textContent = `${session.PN}`;
  }

  UI.$('#metadata-overlay').classList.remove('hidden');
  UI.$('#metadata-overlay').classList.add('flex');
}

UI.$('#metadata-overlay').onclick = () => UI.closeMetadata();
UI.$('#btn-close-metadata').onclick = () => UI.closeMetadata();

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
    UI.showToast('Application initialization failed.');
    console.error('[App] Boot failure:', err);
  }
};

if (document.readyState === 'loading')
  document.addEventListener('DOMContentLoaded', initApp);
else initApp();

declare global {
  interface Window {
    __showToast: typeof UI.showToast;
  }
}

window.__showToast = UI.showToast;
