"use strict";

const $ = id => document.getElementById(id);

const META = "private_gallery_meta_v1";
const DB = "private_gallery_db_v1";
const STORE = "photos";

const ITERATIONS = 600000;
const LOCK_MS = 60000;
const MAX_FAILURES = 10;

let vaultKey = null;
let firstPassword = null;
let selected = new Set();
let failures1 = 0;
let failures2 = 0;
let lockUntil = 0;
let idleTimer = null;
let recoveryCode = null;
let urls = [];

function show(id) {
  ["setup","recoveryShow","step1","step2",
   "recovery","gallery"].forEach(name => {
    $(name).classList.toggle("hidden", name !== id);
  });
}

function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

function toBase64(bytes) {
  let s = "";
  bytes.forEach(b => s += String.fromCharCode(b));
  return btoa(s);
}

function fromBase64(s) {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

function encode(s) {
  return new TextEncoder().encode(s);
}

function metaGet() {
  try {
    return JSON.parse(localStorage.getItem(META));
  } catch {
    return null;
  }
}

function metaSave(m) {
  localStorage.setItem(META, JSON.stringify(m));
}

async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey(
    "raw", encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
    material, { name: "AES-GCM", length: 256 }, false, ["encrypt","decrypt"]
  );
}

async function verifier(password, salt, label) {
  const material = await crypto.subtle.importKey(
    "raw", encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: encode(label + ":" + salt), iterations: ITERATIONS, hash: "SHA-256" },
    material, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2,"0")).join("");
}

function openDB() {
  return new Promise((resolve,reject) => {
    const r = indexedDB.open(DB,1);
    r.onupgradeneeded = () => {
      if (!r.result.objectStoreNames.contains(STORE)) {
        r.result.createObjectStore(STORE,{keyPath:"id"});
      }
    };
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function dbPut(item) {
  const db = await openDB();
  return new Promise((resolve,reject) => {
    const tx = db.transaction(STORE,"readwrite");
    tx.objectStore(STORE).put(item);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

async function dbAll() {
  const db = await openDB();
  return new Promise((resolve,reject) => {
    const tx = db.transaction(STORE,"readonly");
    const r = tx.objectStore(STORE).getAll();
    r.onsuccess = () => { db.close(); resolve(r.result); };
    r.onerror = () => { db.close(); reject(r.error); };
  });
}

async function dbDelete(ids) {
  const db = await openDB();
  return new Promise((resolve,reject) => {
    const tx = db.transaction(STORE,"readwrite");
    const store = tx.objectStore(STORE);
    ids.forEach(id => store.delete(id));
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error); };
  });
}

async function wrapKey(key, raw) {
  const iv = randomBytes(12);
  const cipher = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, raw);
  return { iv: toBase64(iv), data: toBase64(new Uint8Array(cipher)) };
}

async function unwrapKey(key, wrapped) {
  const raw = await crypto.subtle.decrypt(
    { name:"AES-GCM", iv: fromBase64(wrapped.iv) }, key, fromBase64(wrapped.data)
  );
  return crypto.subtle.importKey("raw", raw, {name:"AES-GCM"}, false, ["encrypt","decrypt"]);
}

function saveFailures(m) {
  m.failures1 = failures1;
  m.failures2 = failures2;
  m.lockUntil = lockUntil;
  metaSave(m);
}

function init() {
  const m = metaGet();
  if (!m) { show("setup"); return; }
  failures1 = m.failures1 || 0;
  failures2 = m.failures2 || 0;
  lockUntil = m.lockUntil || 0;
  if (m.recoveryRequired) { show("recovery"); } 
  else { show("step1"); }
}

$("createBtn").onclick = async () => {
  const p1 = $("new1").value;
  const p2 = $("new2").value;
  if (p1.length < 10 || p2.length < 10) {
    $("setupStatus").textContent = "Both passwords must be at least 10 characters long.";
    return;
  }
  if (p1 === p2) {
    $("setupStatus").textContent = "Both passwords must be different.";
    return;
  }
  $("createBtn").disabled = true;
  try {
    const salt = toBase64(randomBytes(16));
    const raw = randomBytes(32);
    const wrapping = await deriveKey(p1 + "\u0000" + p2, fromBase64(salt));
    const recovery = toBase64(randomBytes(32));
    const recoveryKey = await deriveKey(recovery, fromBase64(salt));

    const m = {
      salt, iterations: ITERATIONS,
      check1: await verifier(p1,salt,"first"),
      check2: await verifier(p2,salt,"second"),
      wrapped: await wrapKey(wrapping,raw),
      wrappedRecovery: await wrapKey(recoveryKey,raw),
      recoveryCheck: await verifier(recovery,salt,"recovery"),
      failures1: 0, failures2: 0, lockUntil: 0, recoveryRequired: false
    };
    metaSave(m);
    recoveryCode = recovery;
    $("recoveryCode").textContent = recovery;
    $("new1").value = ""; $("new2").value = "";
    show("recoveryShow");
  } catch(e) {
    $("setupStatus").textContent = "Failed to create vault. Check HTTPS connection.";
  } finally {
    $("createBtn").disabled = false;
  }
};

$("continueBtn").onclick = () => {
  recoveryCode = null;
  show("step1");
};

function locked() { return Date.now() < lockUntil; }

function failure(stage) {
  if (stage === 1) failures1++; else failures2++;
  const m = metaGet();
  const count = stage === 1 ? failures1 : failures2;
  const status = stage === 1 ? "status1" : "status2";

  if (count >= MAX_FAILURES) {
    m.recoveryRequired = true;
    saveFailures(m);
    vaultKey = null; firstPassword = null;
    show("recovery");
    $("recoveryStatus").textContent = "10 failed attempts. Recovery code required.";
    return;
  }
  if (count % 3 === 0) {
    lockUntil = Date.now() + LOCK_MS;
    saveFailures(m);
    $(status).textContent = "Three failed attempts. Wait 60 seconds.";
  } else {
    saveFailures(m);
    $(status).textContent = `Wrong password. ${MAX_FAILURES-count} attempts left.`;
  }
}

$("step1Btn").onclick = async () => {
  if (locked()) {
    $("status1").textContent = `Locked. Wait ${Math.ceil((lockUntil-Date.now())/1000)} seconds.`;
    return;
  }
  const p = $("pass1").value;
  if (!p) return;
  const m = metaGet();
  const hash = await verifier(p,m.salt,"first");
  if (hash !== m.check1) { $("pass1").value = ""; failure(1); return; }
  failures1 = 0; firstPassword = p;
  $("pass1").value = ""; $("status1").textContent = "";
  show("step2");
};

$("step2Btn").onclick = async () => {
  if (locked()) {
    $("status2").textContent = `Locked. Wait ${Math.ceil((lockUntil-Date.now())/1000)} seconds.`;
    return;
  }
  if (!firstPassword) { show("step1"); return; }
  const p = $("pass2").value;
  if (!p) return;
  const m = metaGet();
  const hash = await verifier(p,m.salt,"second");
  if (hash !== m.check2) { firstPassword = null; $("pass2").value = ""; failure(2); return; }
  
  const wrapping = await deriveKey(firstPassword + "\u0000" + p, fromBase64(m.salt));
  vaultKey = await unwrapKey(wrapping,m.wrapped);
  
  firstPassword = null; $("pass2").value = "";
  failures1 = 0; failures2 = 0; lockUntil = 0;
  saveFailures(m);
  await renderGallery();
  show("gallery");
  startIdle();
};

$("recoverBtn").onclick = async () => {
  const code = $("recoveryInput").value.trim();
  const m = metaGet();
  try {
    const check = await verifier(code,m.salt,"recovery");
    if (check !== m.recoveryCheck) { $("recoveryStatus").textContent = "Invalid recovery code."; return; }
    const recoveryKey = await deriveKey(code, fromBase64(m.salt));
    vaultKey = await unwrapKey(recoveryKey, m.wrappedRecovery);
    failures1 = 0; failures2 = 0; lockUntil = 0;
    m.recoveryRequired = false;
    saveFailures(m);
    await renderGallery();
    show("gallery");
    startIdle();
  } catch(e) {
    $("recoveryStatus").textContent = "Recovery failed. Check the code.";
  }
};

async function renderGallery() {
  const grid = $("grid");
  urls.forEach(URL.revokeObjectURL); urls = [];
  grid.innerHTML = ""; selected.clear();
  const items = await dbAll();
  
  for (const item of items) {
    try {
      const plain = await crypto.subtle.decrypt(
        {name:"AES-GCM",iv:fromBase64(item.iv)}, vaultKey, fromBase64(item.data)
      );
      const blob = new Blob([plain],{type:item.type});
      const url = URL.createObjectURL(blob);
      urls.push(url);
      
      const tile = document.createElement("div");
      tile.className = "tile";
      
      let media;
      if (item.type.startsWith("video/")) {
        media = document.createElement("video"); media.muted = true; media.playsInline = true;
      } else {
        media = document.createElement("img"); media.alt = "Private photo";
      }
      media.src = url;
      
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.onchange = () => {
        if (checkbox.checked) selected.add(item.id); else selected.delete(item.id);
      };
      tile.append(media,checkbox); grid.append(tile);
    } catch(e) { console.warn("Encrypted item could not be opened"); }
  }
  $("count").textContent = `${items.length} items`;
  $("empty").classList.toggle("hidden",items.length > 0);
}

$("addBtn").onclick = () => $("fileInput").click();

$("fileInput").onchange = async e => {
  if (!vaultKey) return;
  for (const file of e.target.files) {
    const iv = randomBytes(12);
    const cipher = await crypto.subtle.encrypt({name:"AES-GCM",iv}, vaultKey, await file.arrayBuffer());
    const id = toBase64(randomBytes(16));
    await dbPut({
      id, name: file.name, type: file.type || "application/octet-stream",
      iv: toBase64(iv), data: toBase64(new Uint8Array(cipher))
    });
  }
  e.target.value = "";
  await renderGallery();
};

$("deleteBtn").onclick = async () => {
  if (!selected.size) { alert("Select items first."); return; }
  if (!confirm(`Delete ${selected.size} selected items?`)) return;
  await dbDelete([...selected]);
  await renderGallery();
};

$("shareBtn").onclick = async () => {
  if (!selected.size) { alert("Select items first."); return; }
  try {
    const items = (await dbAll()).filter(item => selected.has(item.id));
    const files = [];
    for (const item of items) {
      const plain = await crypto.subtle.decrypt(
        {name:"AES-GCM",iv:fromBase64(item.iv)}, vaultKey, fromBase64(item.data)
      );
      files.push(new File([plain], item.name, {type:item.type}));
    }
    if (navigator.share && navigator.canShare && navigator.canShare({files})) {
      await navigator.share({files,title:"Private Gallery"});
    } else {
      alert("File sharing is not supported in this browser.");
    }
  } catch(e) {
    if (e.name !== "AbortError") alert("Failed to share.");
  }
};

function lockGallery() {
  clearTimeout(idleTimer);
  vaultKey = null; firstPassword = null;
  urls.forEach(URL.revokeObjectURL); urls = [];
  $("grid").innerHTML = "";
  $("pass1").value = ""; $("pass2").value = "";
  init();
}

function startIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    lockGallery();
    alert("Gallery locked due to inactivity.");
  },60000);
}

$("lockBtn").onclick = lockGallery;

["pointerdown","keydown","touchstart"].forEach(event => {
  window.addEventListener(event,() => {
    if (!$("gallery").classList.contains("hidden")) startIdle();
  },{passive:true});
});

document.addEventListener("visibilitychange",() => {
  if (document.hidden && !$("gallery").classList.contains("hidden")) lockGallery();
});

if ("serviceWorker" in navigator && location.protocol === "https:") {
  navigator.serviceWorker.register("./sw.js").catch(() => {});
}

if (!crypto.subtle || !window.indexedDB) {
  alert("Please use a modern browser with HTTPS.");
}

init();
