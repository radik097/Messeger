// Простая E2E криптография на WebCrypto: ECDSA(P-256), ECDH(P-256), HKDF, AES-GCM.
// Ключи и контакты — в IndexedDB. Минимум зависимостей и ноль «магии».

const DB_NAME = 'noda-im';
const DB_VER = 1;

let WS = null;
let ME = { did: null, idKey: null, dhKey: null, idPubJwk: null, dhPubJwk: null };
let CONTACTS = new Map(); // did -> { dhPubJwk }
let UI = {};

// --- system payload helpers ---
function myContactCard() {
  const nameEl = document.getElementById('user-name');
  const name = nameEl?.textContent || 'user';
  return { did: ME.did, name, dh_pub_jwk: ME.dhPubJwk };
}

function isSystemPayload(p) {
  return p && typeof p === 'object' && (p.kind === 'friend_request' || p.kind === 'friend_accept');
}

async function saveContactFromCard(card) {
  if (!card?.did || !card?.dh_pub_jwk) throw new Error('bad card');
  await idbAdd('contacts', { did: card.did, dhPubJwk: card.dh_pub_jwk });
  await loadContacts();
}

initUI();
openDB().then(async () => {
  await loadOrShowGenerate();
  bindUI();
  setupTabs();
  await loadLocalMessages();
});

function initUI() {
  UI.did = document.getElementById('did-box');
  UI.status = document.getElementById('status');
  UI.wsUrl = document.getElementById('ws-url');
  UI.btnConnect = document.getElementById('btn-connect');
  UI.btnGen = document.getElementById('btn-gen');
  UI.contactDid = document.getElementById('contact-did');
  UI.contactDh = document.getElementById('contact-dh');
  UI.btnAddContact = document.getElementById('btn-add-contact');
  UI.contactList = document.getElementById('contact-list');
  UI.toDid = document.getElementById('to-did');
  UI.msg = document.getElementById('msg');
  UI.btnSend = document.getElementById('btn-send');
  UI.messages = document.getElementById('messages');
  if (UI.btnSend) UI.btnSend.disabled = true;
}

function bindUI() {
  UI.btnGen.onclick = generateKeys;
  UI.btnConnect.onclick = connectWS;
  UI.btnAddContact.onclick = addContact;
  UI.btnRequest = document.getElementById('btn-request');
  if (UI.btnRequest) UI.btnRequest.onclick = async () => {
    const did = UI.contactDid.value.trim();
    if (!did) return;
    const payload = { kind: 'friend_request', card: myContactCard() };
    sendWS({ type: 'SEND', to: did, payload });
    logUI(`Запрос дружбы отправлен → ${did}`);
    UI.contactDid.value = '';
  };
  UI.btnSend.onclick = sendMessage;
  UI.onlineList = document.getElementById('online-list');
}

async function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VER);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
    db.createObjectStore('kv');
    db.createObjectStore('contacts', { keyPath: 'did' });
    db.createObjectStore('messages', { autoIncrement: true });
    };
    req.onsuccess = () => { window._db = req.result; resolve(); };
    req.onerror = () => reject(req.error);
  });
}

function idbGet(store, key) {
  return new Promise((resolve, reject) => {
    const tx = _db.transaction(store, 'readonly');
    const st = tx.objectStore(store);
    const r = st.get(key);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
function idbSet(store, key, val) {
  return new Promise((resolve, reject) => {
    const tx = _db.transaction(store, 'readwrite');
    const st = tx.objectStore(store);
    const r = st.put(val, key);
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
  });
}
function idbAdd(store, val) {
  return new Promise((resolve, reject) => {
    const tx = _db.transaction(store, 'readwrite');
    const st = tx.objectStore(store);
    const r = st.put(val);
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
  });
}
async function loadContacts() {
  CONTACTS.clear();
  await new Promise((resolve, reject) => {
    const tx = _db.transaction('contacts', 'readonly');
    const st = tx.objectStore('contacts');
    const req = st.openCursor();
    req.onsuccess = (e) => {
      const c = e.target.result;
      if (c) {
        CONTACTS.set(c.value.did, { dhPubJwk: c.value.dhPubJwk });
        c.continue();
      } else resolve();
    };
    req.onerror = () => reject(req.error);
  });
  renderContacts();
}

function renderContacts() {
  UI.contactList.innerHTML = '';
  for (const [did, v] of CONTACTS) {
    const li = document.createElement('li');
    li.textContent = did;
    li.onclick = () => { UI.toDid.value = did; };
    UI.contactList.appendChild(li);
  }
}

async function loadOrShowGenerate() {
  const idPubJwk = await idbGet('kv', 'id_pub_jwk');
  const dhPubJwk = await idbGet('kv', 'dh_pub_jwk');
  const did = await idbGet('kv', 'did');
  if (idPubJwk && dhPubJwk && did) {
    ME.did = did;
    ME.idPubJwk = idPubJwk;
    ME.dhPubJwk = dhPubJwk;
    ME.idKey = await loadKeyPair('id');
    ME.dhKey = await loadKeyPair('dh');
    UI.did.innerHTML = `<b>DID:</b> ${ME.did}`;
    await loadContacts();
  } else {
    UI.did.textContent = 'Ключей нет. Нажми «Сгенерировать ключи».';
  }
}

async function generateKeys() {
  const idPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
  );
  const idPubJwk = await crypto.subtle.exportKey('jwk', idPair.publicKey);

  const dhPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
  );
  const dhPubJwk = await crypto.subtle.exportKey('jwk', dhPair.publicKey);

  const rawIdPub = await crypto.subtle.exportKey('raw', idPair.publicKey);
  const did = 'did:noda:' + b64url(await sha256(rawIdPub));

  await storeKeyPair('id', idPair);
  await storeKeyPair('dh', dhPair);
  await idbSet('kv', 'id_pub_jwk', idPubJwk);
  await idbSet('kv', 'dh_pub_jwk', dhPubJwk);
  await idbSet('kv', 'did', did);

  ME.did = did;
  ME.idKey = idPair;
  ME.dhKey = dhPair;
  ME.idPubJwk = idPubJwk;
  ME.dhPubJwk = dhPubJwk;

  UI.did.innerHTML = `<b>DID:</b> ${ME.did}`;
  // show exported jwks
  document.getElementById('id-jwk').value = JSON.stringify(ME.idPubJwk, null, 2);
  document.getElementById('dh-jwk').value = JSON.stringify(ME.dhPubJwk, null, 2);
  document.getElementById('did-val').textContent = ME.did;
  // compute user name = hash(id_pub_jwk + dh_pub_jwk)
  const uname = await computeUserName(ME.idPubJwk, ME.dhPubJwk);
  document.getElementById('user-name').textContent = uname;
  document.getElementById('btn-export').disabled = false;
}

// Encryption for backup by password (PBKDF2 -> AES-GCM)
async function deriveKeyFromPassword(pass, salt) {
  const enc = new TextEncoder().encode(pass);
  const base = await crypto.subtle.importKey('raw', enc, 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt','decrypt']);
}

async function encryptWithPassword(pass, dataObj) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyFromPassword(pass, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(dataObj)));
  return { salt: b64url(salt), iv: b64url(iv), ct: b64url(ct) };
}

async function decryptWithPassword(pass, blob) {
  const salt = base64urlToBytes(blob.salt);
  const iv = base64urlToBytes(blob.iv);
  const key = await deriveKeyFromPassword(pass, salt);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, base64urlToBytes(blob.ct));
  return JSON.parse(new TextDecoder().decode(pt));
}

async function loadLocalMessages() {
  if (!window._db) return;
  const arr = [];
  await new Promise((resolve, reject) => {
    const tx = _db.transaction('messages', 'readonly');
    const st = tx.objectStore('messages');
    const req = st.openCursor();
    req.onsuccess = (e) => {
      const c = e.target.result;
      if (c) { arr.push(c.value); c.continue(); } else resolve();
    };
    req.onerror = () => reject(req.error);
  });
  UI.messages.innerHTML = '';
  for (const m of arr) addMsg(m.me, m.text || '[...]');
}

async function storeKeyPair(prefix, pair) {
  const priv = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  const pub = await crypto.subtle.exportKey('spki', pair.publicKey);
  await idbSet('kv', prefix+'_priv', arrayBufferToHex(priv));
  await idbSet('kv', prefix+'_pub', arrayBufferToHex(pub));
}

async function loadKeyPair(prefix) {
  const privHex = await idbGet('kv', prefix+'_priv');
  const pubHex = await idbGet('kv', prefix+'_pub');
  if (!privHex || !pubHex) return null;
  const priv = await crypto.subtle.importKey(
    'pkcs8', hexToArrayBuffer(privHex),
    prefix === 'id' ? { name: 'ECDSA', namedCurve: 'P-256' } : { name: 'ECDH', namedCurve: 'P-256' },
    true, prefix === 'id' ? ['sign'] : ['deriveBits', 'deriveKey']
  );
  const pub = await crypto.subtle.importKey(
    'spki', hexToArrayBuffer(pubHex),
    prefix === 'id' ? { name: 'ECDSA', namedCurve: 'P-256' } : { name: 'ECDH', namedCurve: 'P-256' },
    true, prefix === 'id' ? ['verify'] : []
  );
  return { privateKey: priv, publicKey: pub };
}

async function connectWS() {
  if (!ME.idKey) { alert('Сначала сгенерируй ключи'); return; }
  if (WS && WS.readyState === WebSocket.OPEN) return;
  const url = UI.wsUrl.value.trim();
  if (!url) { alert('Укажи WS URL'); return; }
  if (!url.startsWith('ws://') && !url.startsWith('wss://')) {
    alert('WS URL должен начинаться с ws:// или wss://');
    return;
  }
  // warn if using wss locally or wrong port
  if (url.startsWith('wss://') && (url.includes('127.0.0.1') || url.includes('localhost'))) {
    if (!confirm('Вы используете wss:// на локальном адресе. Продолжить?')) return;
  }
  try {
    WS = new WebSocket(url);
  } catch (e) {
    alert('Не удалось создать WebSocket: ' + e.message);
    return;
  }
  WS.onopen = () => {
    UI.status.textContent = 'online';
    console.log('WS open -> HELLO', ME.did);
    sendWS({ type: 'HELLO', did: ME.did });
  };
  WS.onclose = () => {
    UI.status.textContent = 'offline';
    if (UI.btnSend) UI.btnSend.disabled = true;
    updateOnlineList([]);
  };
  WS.onerror = (ev) => { UI.status.textContent = 'error'; console.error('WS error', ev); if (UI.btnSend) UI.btnSend.disabled = true; };
  WS.onmessage = onWSMessage;
}

function sendWS(obj) { WS?.send(JSON.stringify(obj)); }

async function onWSMessage(ev) {
  const m = JSON.parse(ev.data);
  if (m.type === 'CHALLENGE') {
    const sig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      ME.idKey.privateKey,
      hexToArrayBuffer(m.nonce)
    );
    sendWS({
      type: 'AUTH',
      did: ME.did,
      signature: arrayBufferToHex(sig),
      id_pub_jwk: ME.idPubJwk,
      dh_pub_jwk: ME.dhPubJwk
    });
  } else if (m.type === 'READY') {
  logUI('Сервер: READY');
  // mark online
  UI.status.textContent = 'online';
  } else if (m.type === 'RECV') {
    // Handle system payloads (friend_request / friend_accept) unencrypted first
    try {
      if (isSystemPayload(m.payload)) {
        const kind = m.payload.kind;
        if (kind === 'friend_request') {
          // show modal to accept/decline
          const card = m.payload.card;
          const accept = confirm(`Получен запрос дружбы от ${m.from}. Добавить контакт?`);
          if (accept) {
            await saveContactFromCard(card);
            // send friend_accept back
            const reply = { kind: 'friend_accept', card: myContactCard() };
            sendWS({ type: 'SEND', to: m.from, payload: reply });
            logUI(`Отправлен ответ на запрос дружбы → ${m.from}`);
          }
        } else if (kind === 'friend_accept') {
          // peer accepted our request; save their card
          await saveContactFromCard(m.payload.card);
          logUI(`Запрос дружбы принят: ${m.from}`);
        }
        // acknowledge receipt to server
        sendWS({ type: 'RCPT', id: m.id });
        return;
      }

      // Fallback: treat as encrypted E2E envelope
      const txt = await decryptFromPeer(m.from, m.payload);
      addMsg(false, txt);
      sendWS({ type: 'RCPT', id: m.id, status: 'delivered' });
    } catch (e) {
      console.error('RECV handling failed', e);
      addMsg(false, '[Ошибка при обработке полученного сообщения]');
    }
  } else if (m.type === 'ACK') {
    // можно подсветить доставку в UI
  } else if (m.type === 'PRESENCE') {
    // server tells which DIDs are online
    const online = Array.isArray(m.online) ? m.online : [];
    updateOnlineList(online);
  }
}

function updateOnlineList(online) {
  // keep a set of online
  const sel = UI.onlineList;
  if (!sel) return;
  // clear but keep first placeholder
  const placeholder = sel.querySelector('option[value=""]') || null;
  sel.innerHTML = '';
  const opt0 = document.createElement('option'); opt0.value = ''; opt0.textContent = '-- выберите --'; sel.appendChild(opt0);
  for (const did of online) {
    if (did === ME.did) continue; // don't show self
    // only show if did is in contacts (friend) or we explicitly allow listing all
    if (!CONTACTS.has(did)) continue;
    const o = document.createElement('option'); o.value = did; o.textContent = did; sel.appendChild(o);
  }
  // enable send button only when WS is open
  const isWsOpen = (typeof WebSocket !== 'undefined') && WS && WS.readyState === WebSocket.OPEN;
  if (UI.btnSend) UI.btnSend.disabled = !isWsOpen || sel.options.length <= 1;
}

// choose recipient preference: online select takes precedence over manual input
function getRecipientDid() {
  const sel = UI.onlineList;
  if (sel && sel.value) return sel.value;
  return UI.toDid.value.trim();
}

async function addContact() {
  const did = UI.contactDid.value.trim();
  if (!did) return;
  let dhPubJwk;
  try { dhPubJwk = JSON.parse(UI.contactDh.value); } catch { alert('Некорректный JWK'); return; }
  await idbAdd('contacts', { did, dhPubJwk });
  await loadContacts();
  UI.contactDid.value = '';
  UI.contactDh.value = '';
}

document.getElementById('btn-export').onclick = async () => {
  const payload = { did: ME.did, id_pub_jwk: ME.idPubJwk, dh_pub_jwk: ME.dhPubJwk };
  await navigator.clipboard.writeText(JSON.stringify(payload));
  alert('Public JWKs copied to clipboard');
};

// backup / restore buttons (encrypted)
const btnBackup = document.getElementById('btn-backup');
const btnRestore = document.getElementById('btn-restore');
if (btnBackup) btnBackup.onclick = async () => {
  const pass = document.getElementById('backup-pass').value || prompt('Пароль для бэкапа');
  if (!pass) return alert('Пароль обязателен');
  // gather kv, contacts, messages
  const kv = {};
  kv['id_pub_jwk'] = await idbGet('kv', 'id_pub_jwk');
  kv['dh_pub_jwk'] = await idbGet('kv', 'dh_pub_jwk');
  kv['id_priv'] = await idbGet('kv', 'id_priv');
  kv['dh_priv'] = await idbGet('kv', 'dh_priv');
  kv['did'] = await idbGet('kv', 'did');
  const contacts = [];
  await new Promise((resolve, reject) => {
    const tx = _db.transaction('contacts', 'readonly');
    const st = tx.objectStore('contacts');
    const req = st.openCursor();
    req.onsuccess = (e) => { const c = e.target.result; if (c) { contacts.push(c.value); c.continue(); } else resolve(); };
    req.onerror = () => reject(req.error);
  });
  const messages = [];
  await new Promise((resolve, reject) => {
    const tx = _db.transaction('messages', 'readonly');
    const st = tx.objectStore('messages');
    const req = st.openCursor();
    req.onsuccess = (e) => { const c = e.target.result; if (c) { messages.push(c.value); c.continue(); } else resolve(); };
    req.onerror = () => reject(req.error);
  });
  const blob = await encryptWithPassword(pass, { kv, contacts, messages });
  document.getElementById('backup-data').value = JSON.stringify(blob);
  alert('Бэкап готов (зашифрован). Скопируйте текст ниже.');
};
if (btnRestore) btnRestore.onclick = async () => {
  const pass = document.getElementById('backup-pass').value || prompt('Пароль для восстановления');
  if (!pass) return alert('Пароль обязателен');
  const txt = document.getElementById('backup-data').value.trim();
  if (!txt) return alert('Вставьте зашифрованный бэкап');
  let blob;
  try { blob = JSON.parse(txt); } catch { return alert('Некорректный формат бэкапа'); }
  let obj;
  try { obj = await decryptWithPassword(pass, blob); } catch (e) { return alert('Не удалось расшифровать. Неправильный пароль?'); }
  if (obj.kv) for (const k of Object.keys(obj.kv)) if (obj.kv[k]) await idbSet('kv', k, obj.kv[k]);
  if (obj.contacts) for (const c of obj.contacts) await idbAdd('contacts', { did: c.did, dhPubJwk: c.dhPubJwk });
  if (obj.messages) for (const m of obj.messages) await idbAdd('messages', m);
  // import restored keys and state into runtime immediately
  await loadOrShowGenerate();
  // ensure keys object populated
  ME.idPubJwk = await idbGet('kv', 'id_pub_jwk');
  ME.dhPubJwk = await idbGet('kv', 'dh_pub_jwk');
  // update hidden jqk fields and DID display
  const idj = document.getElementById('id-jwk'); if (idj) idj.value = JSON.stringify(ME.idPubJwk || {}, null, 2);
  const dhj = document.getElementById('dh-jwk'); if (dhj) dhj.value = JSON.stringify(ME.dhPubJwk || {}, null, 2);
  const didEl = document.getElementById('did-val'); if (didEl) didEl.textContent = ME.did || (await idbGet('kv', 'did'));
  try { const uname = ME.idPubJwk && ME.dhPubJwk ? await computeUserName(ME.idPubJwk, ME.dhPubJwk) : ''; if (uname) document.getElementById('user-name').textContent = uname; } catch (e) {}
  await loadContacts();
  await loadLocalMessages();
  // enable send if WS is open
  if (WS && WS.readyState === WebSocket.OPEN && UI.btnSend) UI.btnSend.disabled = false;
  alert('Восстановление завершено');
};

document.getElementById('btn-copy-username').onclick = async () => {
  const t = document.getElementById('user-name').textContent;
  if (t) await navigator.clipboard.writeText(t);
};

document.getElementById('btn-import').onclick = async () => {
  const txt = document.getElementById('contact-import').value.trim();
  if (!txt) return;
  let arr;
  try { arr = JSON.parse(txt); } catch { alert('Invalid JSON'); return; }
  for (const c of arr) {
    if (c.did && c.dh_pub_jwk) await idbAdd('contacts', { did: c.did, dhPubJwk: c.dh_pub_jwk });
  }
  await loadContacts();
  document.getElementById('contact-import').value = '';
};

document.getElementById('btn-fill-dh').onclick = async () => {
  // if contact-dh contains JSON with object having did/dh_pub_jwk, auto-fill
  const raw = document.getElementById('contact-dh').value.trim();
  try {
    const obj = JSON.parse(raw);
    if (obj.dh_pub_jwk) {
      document.getElementById('contact-dh').value = JSON.stringify(obj.dh_pub_jwk, null, 2);
      if (obj.did) document.getElementById('contact-did').value = obj.did;
    }
  } catch(e) {
    // nothing
  }
};

async function computeUserName(idj, dhj) {
  const s = JSON.stringify(idj) + JSON.stringify(dhj);
  const enc = new TextEncoder().encode(s);
  const h = await crypto.subtle.digest('SHA-256', enc);
  return arrayBufferToHex(h).slice(0, 16);
}

function setupTabs() {
  document.querySelectorAll('.tabs .tab').forEach(b => b.addEventListener('click', (e) => {
    document.querySelectorAll('.tabs .tab').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    const tab = b.dataset.tab;
    document.querySelectorAll('.pane').forEach(p => p.classList.add('hidden'));
    document.getElementById(tab).classList.remove('hidden');
  }));
  // sidebar side-tabs
  document.querySelectorAll('.side-tabs .side-tab').forEach(b => b.addEventListener('click', (e) => {
    document.querySelectorAll('.side-tabs .side-tab').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    const tab = b.dataset.tab;
    document.querySelectorAll('.pane').forEach(p => p.classList.add('hidden'));
    const el = document.getElementById(tab);
    if (el) el.classList.remove('hidden');
  }));
  document.querySelectorAll('.subtabs .subtab').forEach(b => b.addEventListener('click', (e) => {
    const parent = b.closest('.pane');
    parent.querySelectorAll('.subtab').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    const sub = b.dataset.sub;
    parent.querySelectorAll('[data-subpane]').forEach(sp => sp.classList.add('hidden'));
    parent.querySelector(`[data-subpane="${sub}"]`).classList.remove('hidden');
  }));
}

function addMsg(me, text) {
  const div = document.createElement('div');
  div.className = 'msg ' + (me ? 'me' : 'peer');
  div.textContent = text;
  UI.messages.appendChild(div);
  UI.messages.scrollTop = UI.messages.scrollHeight;
}

async function sendMessage() {
  const to = getRecipientDid();
  const text = UI.msg.value;
  if (!to || !text) return;
  if (!WS || WS.readyState !== WebSocket.OPEN) { alert('Нет соединения с сервером'); return; }
  const payload = await encryptToPeer(to, text);
  sendWS({ type: 'SEND', to, payload });
  addMsg(true, text);
  UI.msg.value = '';
}

async function encryptToPeer(peerDid, plaintext) {
  const contact = CONTACTS.get(peerDid);
  if (!contact) { alert('Нет контакта'); throw new Error('no contact'); }

  const peerPub = await crypto.subtle.importKey('jwk', contact.dhPubJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  const secret = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerPub }, ME.dhKey.privateKey, 256);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const baseKey = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('im/v1') },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false, ['encrypt','decrypt']
  );

  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(plaintext));
  return {
    header: {
      salt: b64url(salt),
      iv: b64url(iv),
    },
    ciphertext: b64url(ct)
  };
}

async function decryptFromPeer(peerDid, payload) {
  const contact = CONTACTS.get(peerDid);
  if (!contact) throw new Error('unknown peer');

  const peerPub = await crypto.subtle.importKey('jwk', contact.dhPubJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  const secret = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerPub }, ME.dhKey.privateKey, 256);

  const salt = base64urlToBytes(payload.header.salt);
  const iv = base64urlToBytes(payload.header.iv);
  const baseKey = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('im/v1') },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false, ['encrypt','decrypt']
  );

  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, base64urlToBytes(payload.ciphertext));
  return new TextDecoder().decode(pt);
}

// utils
async function sha256(buf) {
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return arrayBufferToBase64url(hash);
}
function arrayBufferToHex(buf) {
  const b = new Uint8Array(buf);
  return [...b].map(x => x.toString(16).padStart(2,'0')).join('');
}
function hexToArrayBuffer(hex) {
  const out = new Uint8Array(hex.length/2);
  for (let i=0;i<out.length;i++) out[i] = parseInt(hex.substr(i*2,2),16);
  return out.buffer;
}
function b64url(x) {
  if (x instanceof ArrayBuffer) x = new Uint8Array(x);
  let s = (typeof x === 'string') ? x : btoa(String.fromCharCode(...x));
  return s.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function arrayBufferToBase64url(buf) {
  const bin = String.fromCharCode(...new Uint8Array(buf));
  return b64url(btoa(bin));
}
function base64urlToBytes(s) {
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  s += '='.repeat(pad);
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i=0;i<raw.length;i++) out[i] = raw.charCodeAt(i);
  return out.buffer;
}
function logUI(msg) {
  const div = document.createElement('div'); div.className = 'msg peer'; div.textContent = msg;
  UI.messages.appendChild(div); UI.messages.scrollTop = UI.messages.scrollHeight;
}
