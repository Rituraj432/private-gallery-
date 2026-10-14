"use strict";

/*
 * Private Gallery
 * Local encrypted photo and video vault.
 *
 * IMPORTANT:
 * Browser-only security has limitations.
 * This application does not guarantee protection
 * against a compromised device or modified JavaScript.
 */

const $ = (id) => document.getElementById(id);

const META_KEY = "private_gallery_meta_v2";
const DB_NAME = "private_gallery_db_v2";
const STORE_NAME = "photos";

const ITERATIONS = 600000;
const LOCK_MS = 60_000;
const MAX_FAILURES = 10;
const LOCK_EVERY = 3;
const IDLE_MS = 60_000;

let vaultKey = null;
let firstPassword = null;

let selected = new Set();
let urls = [];

let failureCounts = {
    step1: 0,
    step2: 0
};

let lockUntil = {
    step1: 0,
    step2: 0
};

let idleTimer = null;
let countdownTimer = null;
let busy = false;
let isPickingFile = false; // नया फ्लैग जो सिर्फ फाइल चुनते वक्त काम आएगा


/* =====================================================
   BASIC UTILITIES
===================================================== */

function setStatus(id, message) {
    const element = $(id);

    if (element) {
        element.textContent = message;
    }
}

function showScreen(id) {
    const screens = [
        "setup",
        "recoveryShow",
        "step1",
        "step2",
        "recovery",
        "gallery"
    ];

    for (const name of screens) {
        const element = $(name);

        if (element) {
            element.classList.toggle("hidden", name !== id);
        }
    }

    if (id !== "gallery") {
        stopIdleTimer();
    }
}

function randomBytes(length) {
    if (!crypto || !crypto.getRandomValues) {
        throw new Error("Secure random number generation is unavailable.");
    }

    return crypto.getRandomValues(new Uint8Array(length));
}

function toBase64(bytes) {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

function fromBase64(value) {
    return Uint8Array.from(
        atob(value),
        character => character.charCodeAt(0)
    );
}

function encode(value) {
    return new TextEncoder().encode(value);
}

function equalStrings(a, b) {
    if (typeof a !== "string" || typeof b !== "string") {
        return false;
    }

    if (a.length !== b.length) {
        return false;
    }

    let difference = 0;

    for (let i = 0; i < a.length; i++) {
        difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return difference === 0;
}

function getMeta() {
    try {
        const raw = localStorage.getItem(META_KEY);

        if (!raw) {
            return null;
        }

        const meta = JSON.parse(raw);

        if (
            !meta ||
            typeof meta !== "object" ||
            !meta.salt ||
            !meta.check1 ||
            !meta.check2 ||
            !meta.wrapped ||
            !meta.wrappedRecovery
        ) {
            return null;
        }

        return meta;
    } catch {
        return null;
    }
}

function saveMeta(meta) {
    localStorage.setItem(META_KEY, JSON.stringify(meta));
}

function secureEnvironmentAvailable() {
    return Boolean(
        window.isSecureContext &&
        window.crypto &&
        window.crypto.subtle &&
        window.indexedDB
    );
}


/* =====================================================
   PASSWORD KEY DERIVATION
===================================================== */

async function deriveWrappingKey(password, salt) {
    const material = await crypto.subtle.importKey(
        "raw",
        encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: ITERATIONS,
            hash: "SHA-256"
        },
        material,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

async function createVerifier(password, salt, label) {
    const material = await crypto.subtle.importKey(
        "raw",
        encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: encode(label + ":" + salt),
            iterations: ITERATIONS,
            hash: "SHA-256"
        },
        material,
        256
    );

    return Array.from(new Uint8Array(bits))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}


/* =====================================================
   DATABASE
===================================================== */

function openDatabase() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, 1);

        request.onupgradeneeded = () => {
            const db = request.result;

            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME, {
                    keyPath: "id"
                });
            }
        };

        request.onsuccess = () => resolve(request.result);

        request.onerror = () => {
            reject(request.error || new Error("Database open failed."));
        };
    });
}

async function dbPut(item) {
    const db = await openDatabase();

    try {
        await new Promise((resolve, reject) => {
            const transaction = db.transaction(
                STORE_NAME,
                "readwrite"
            );

            transaction.objectStore(STORE_NAME).put(item);

            transaction.oncomplete = resolve;

            transaction.onerror = () => {
                reject(transaction.error);
            };

            transaction.onabort = () => {
                reject(transaction.error || new Error("Write aborted."));
            };
        });
    } finally {
        db.close();
    }
}

async function dbGetAll() {
    const db = await openDatabase();

    try {
        return await new Promise((resolve, reject) => {
            const transaction = db.transaction(
                STORE_NAME,
                "readonly"
            );

            const request = transaction
                .objectStore(STORE_NAME)
                .getAll();

            request.onsuccess = () => resolve(request.result);

            request.onerror = () => {
                reject(request.error);
            };
        });
    } finally {
        db.close();
    }
}

async function dbDelete(ids) {
    const db = await openDatabase();

    try {
        await new Promise((resolve, reject) => {
            const transaction = db.transaction(
                STORE_NAME,
                "readwrite"
            );

            const store = transaction.objectStore(STORE_NAME);

            for (const id of ids) {
                store.delete(id);
            }

            transaction.oncomplete = resolve;

            transaction.onerror = () => {
                reject(transaction.error);
            };

            transaction.onabort = () => {
                reject(transaction.error || new Error("Delete aborted."));
            };
        });
    } finally {
        db.close();
    }
}


/* =====================================================
   AES-GCM ENCRYPTION
===================================================== */

async function encryptBytes(key, bytes) {
    const iv = randomBytes(12);

    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv
        },
        key,
        bytes
    );

    return {
        iv: toBase64(iv),
        data: toBase64(new Uint8Array(encrypted))
    };
}

async function decryptBytes(key, record) {
    return crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: fromBase64(record.iv)
        },
        key,
        fromBase64(record.data)
    );
}

async function importVaultKey(rawKey) {
    return crypto.subtle.importKey(
        "raw",
        rawKey,
        {
            name: "AES-GCM"
        },
        false,
        ["encrypt", "decrypt"]
    );
}

async function wrapRawKey(wrappingKey, rawKey) {
    return encryptBytes(wrappingKey, rawKey);
}

async function unwrapRawKey(wrappingKey, wrapped) {
    const rawKey = await decryptBytes(wrappingKey, wrapped);

    return importVaultKey(rawKey);
}


/* =====================================================
   COUNTDOWN AND LOCKOUT
===================================================== */

function getRemainingSeconds(stage) {
    return Math.max(
        0,
        Math.ceil((lockUntil[stage] - Date.now()) / 1000)
    );
}

function getStageElements(stage) {
    if (stage === "step1") {
        return {
            button: "step1Btn",
            status: "status1",
            timer: "timer1"
        };
    }

    return {
        button: "step2Btn",
        status: "status2",
        timer: "timer2"
    };
}

function refreshCountdown() {
    for (const stage of ["step1", "step2"]) {
        const elements = getStageElements(stage);
        const remaining = getRemainingSeconds(stage);

        const button = $(elements.button);

        if (button) {
            button.disabled = remaining > 0;
        }

        setStatus(
            elements.timer,
            remaining > 0
                ? `Locked. Try again in ${remaining} seconds.`
                : ""
        );

        if (remaining === 0 && lockUntil[stage] !== 0) {
            lockUntil[stage] = 0;
            saveFailureState();
        }
    }

    if (
        getRemainingSeconds("step1") === 0 &&
        getRemainingSeconds("step2") === 0
    ) {
        clearInterval(countdownTimer);
        countdownTimer = null;
    }
}

function startCountdown() {
    if (countdownTimer) {
        clearInterval(countdownTimer);
    }

    refreshCountdown();

    countdownTimer = setInterval(
        refreshCountdown,
        250
    );
}

function saveFailureState() {
    const meta = getMeta();

    if (!meta) {
        return;
    }

    meta.failures = {
        step1: failureCounts.step1,
        step2: failureCounts.step2
    };

    meta.lockUntil = {
        step1: lockUntil.step1,
        step2: lockUntil.step2
    };

    saveMeta(meta);
}

function loadFailureState(meta) {
    failureCounts = {
        step1: Number(meta.failures?.step1) || 0,
        step2: Number(meta.failures?.step2) || 0
    };

    lockUntil = {
        step1: Number(meta.lockUntil?.step1) || 0,
        step2: Number(meta.lockUntil?.step2) || 0
    };
}

function resetFailures() {
    failureCounts = {
        step1: 0,
        step2: 0
    };

    lockUntil = {
        step1: 0,
        step2: 0
    };

    saveFailureState();
}

function enterRecoveryMode() {
    const meta = getMeta();

    if (!meta) {
        return;
    }

    meta.recoveryRequired = true;

    saveMeta(meta);

    vaultKey = null;
    firstPassword = null;

    stopIdleTimer();
    clearGalleryURLs();

    $("grid").replaceChildren();

    showScreen("recovery");

    setStatus(
        "recoveryStatus",
        "Too many failed attempts. Enter your recovery code."
    );
}

function registerFailure(stage) {
    failureCounts[stage]++;

    const count = failureCounts[stage];
    const elements = getStageElements(stage);

    if (count >= MAX_FAILURES) {
        saveFailureState();
        enterRecoveryMode();
        return;
    }

    if (count % LOCK_EVERY === 0) {
        lockUntil[stage] = Date.now() + LOCK_MS;

        setStatus(
            elements.status,
            "Too many failed attempts."
        );

        saveFailureState();
        startCountdown();

        return;
    }

    setStatus(
        elements.status,
        `Incorrect password. ${MAX_FAILURES - count} attempts remain before recovery mode.`
    );

    saveFailureState();
}


/* =====================================================
   VAULT SETUP
===================================================== */

async function createVault() {
    if (busy) {
        return;
    }

    if (!secureEnvironmentAvailable()) {
        setStatus(
            "setupStatus",
            "A secure HTTPS connection and a modern browser are required."
        );

        return;
    }

    const password1 = $("new1").value;
    const password2 = $("new2").value;

    if (password1.length < 12 || password2.length < 12) {
        setStatus(
            "setupStatus",
            "Both passwords must contain at least 12 characters."
        );

        return;
    }

    if (password1 === password2) {
        setStatus(
            "setupStatus",
            "Choose two different passwords."
        );

        return;
    }

    if (getMeta()) {
        setStatus(
            "setupStatus",
            "A vault already exists in this browser. Do not overwrite it."
        );

        return;
    }

    busy = true;
    $("createBtn").disabled = true;

    try {
        const saltBytes = randomBytes(16);
        const salt = toBase64(saltBytes);

        const rawVaultKey = randomBytes(32);
        const vaultWrappingKey = await deriveWrappingKey(
            password1 + "\u0000" + password2,
            saltBytes
        );

        const recoveryBytes = randomBytes(32);
        const recoveryCode = toBase64(recoveryBytes);

        const recoveryWrappingKey = await deriveWrappingKey(
            recoveryCode,
            saltBytes
        );

        const wrapped = await wrapRawKey(
            vaultWrappingKey,
            rawVaultKey
        );

        const wrappedRecovery = await wrapRawKey(
            recoveryWrappingKey,
            rawVaultKey
        );

        const meta = {
            version: 2,
            salt,
            iterations: ITERATIONS,

            check1: await createVerifier(
                password1,
                salt,
                "first"
            ),

            check2: await createVerifier(
                password2,
                salt,
                "second"
            ),

            wrapped,
            wrappedRecovery,

            recoveryCheck: await createVerifier(
                recoveryCode,
                salt,
                "recovery"
            ),

            failures: {
                step1: 0,
                step2: 0
            },

            lockUntil: {
                step1: 0,
                step2: 0
            },

            recoveryRequired: false
        };

        saveMeta(meta);

        $("recoveryCode").textContent = recoveryCode;

        $("new1").value = "";
        $("new2").value = "";

        setStatus(
            "setupStatus",
            ""
        );

        showScreen("recoveryShow");

    } catch (error) {
        console.error("Vault setup failed:", error);

        setStatus(
            "setupStatus",
            "Vault creation failed. Check browser support and storage availability."
        );
    } finally {
        busy = false;
        $("createBtn").disabled = false;
    }
}


/* =====================================================
   PASSWORD VERIFICATION
===================================================== */

async function verifyFirstPassword() {
    if (busy || getRemainingSeconds("step1") > 0) {
        return;
    }

    const password = $("pass1").value;

    if (!password) {
        return;
    }

    const meta = getMeta();

    if (!meta || meta.recoveryRequired) {
        showScreen(meta ? "recovery" : "setup");
        return;
    }

    busy = true;
    $("step1Btn").disabled = true;

    try {
        const candidate = await createVerifier(
            password,
            meta.salt,
            "first"
        );

        if (!equalStrings(candidate, meta.check1)) {
            $("pass1").value = "";

            registerFailure("step1");

            return;
        }

        firstPassword = password;
        $("pass1").value = "";

        setStatus("status1", "");
        setStatus("timer1", "");

        showScreen("step2");

        startCountdown();

    } catch (error) {
        console.error("First verification failed:", error);

        setStatus(
            "status1",
            "Verification failed. Please try again."
        );
    } finally {
        busy = false;

        if (getRemainingSeconds("step1") === 0) {
            $("step1Btn").disabled = false;
        }
    }
}

async function verifySecondPassword() {
    if (busy || getRemainingSeconds("step2") > 0) {
        return;
    }

    if (!firstPassword) {
        showScreen("step1");
        return;
    }

    const password = $("pass2").value;

    if (!password) {
        return;
    }

    const meta = getMeta();

    if (!meta || meta.recoveryRequired) {
        firstPassword = null;
        showScreen(meta ? "recovery" : "setup");
        return;
    }

    busy = true;
    $("step2Btn").disabled = true;

    try {
        const candidate = await createVerifier(
            password,
            meta.salt,
            "second"
        );

        if (!equalStrings(candidate, meta.check2)) {
            $("pass2").value = "";
            firstPassword = null;

            registerFailure("step2");

            return;
        }

        const wrappingKey = await deriveWrappingKey(
            firstPassword + "\u0000" + password,
            fromBase64(meta.salt)
        );

        vaultKey = await unwrapRawKey(
            wrappingKey,
            meta.wrapped
        );

        firstPassword = null;
        $("pass2").value = "";

        resetFailures();

        setStatus("status2", "");
        setStatus("timer2", "");

        await renderGallery();

        showScreen("gallery");

        startIdleTimer();

    } catch (error) {
        console.error("Second verification failed:", error);

        vaultKey = null;
        firstPassword = null;

        setStatus(
            "status2",
            "Unable to unlock the vault. Check your passwords or stored data."
        );

    } finally {
        busy = false;

        if (getRemainingSeconds("step2") === 0) {
            $("step2Btn").disabled = false;
        }
    }
}


/* =====================================================
   RECOVERY
===================================================== */

async function recoverVault() {
    if (busy) {
        return;
    }

    const code = $("recoveryInput").value.trim();

    if (!code) {
        setStatus(
            "recoveryStatus",
            "Enter your recovery code."
        );

        return;
    }

    const meta = getMeta();

    if (!meta) {
        setStatus(
            "recoveryStatus",
            "Vault metadata is missing."
        );

        return;
    }

    busy = true;
    $("recoverBtn").disabled = true;

    try {
        const candidate = await createVerifier(
            code,
            meta.salt,
            "recovery"
        );

        if (!equalStrings(candidate, meta.recoveryCheck)) {
            setStatus(
                "recoveryStatus",
                "Invalid recovery code."
            );

            return;
        }

        const recoveryKey = await deriveWrappingKey(
            code,
            fromBase64(meta.salt)
        );

        vaultKey = await unwrapRawKey(
            recoveryKey,
            meta.wrappedRecovery
        );

        firstPassword = null;

        $("recoveryInput").value = "";

        meta.recoveryRequired = false;

        resetFailures();

        saveMeta(meta);

        await renderGallery();

        showScreen("gallery");

        startIdleTimer();

    } catch (error) {
        console.error("Recovery failed:", error);

        vaultKey = null;

        setStatus(
            "recoveryStatus",
            "Recovery failed. Check your recovery code and stored data."
        );
    } finally {
        busy = false;
        $("recoverBtn").disabled = false;
    }
}


/* =====================================================
   GALLERY DISPLAY
===================================================== */

function clearGalleryURLs() {
    for (const url of urls) {
        URL.revokeObjectURL(url);
    }

    urls = [];
}

async function renderGallery() {
    if (!vaultKey) {
        return;
    }

    const grid = $("grid");

    clearGalleryURLs();

    selected.clear();
    grid.replaceChildren();

    try {
        const items = await dbGetAll();

        for (const item of items) {
            if (!vaultKey) {
                break;
            }

            try {
                const plain = await decryptBytes(
                    vaultKey,
                    item
                );

                const blob = new Blob(
                    [plain],
                    {
                        type: item.type || "application/octet-stream"
                    }
                );

                const url = URL.createObjectURL(blob);

                urls.push(url);

                const tile = document.createElement("div");
                tile.className = "tile";

                let media;

                if (
                    typeof item.type === "string" &&
                    item.type.startsWith("video/")
                ) {
                    media = document.createElement("video");

                    media.muted = true;
                    media.playsInline = true;
                    media.preload = "metadata";

                } else {
                    media = document.createElement("img");

                    media.alt = "Private photo";
                    media.loading = "lazy";
                    media.draggable = false;
                }

                media.src = url;

                const checkbox = document.createElement("input");

                checkbox.type = "checkbox";
                checkbox.setAttribute(
                    "aria-label",
                    "Select media item"
                );

                checkbox.addEventListener("change", () => {
                    if (checkbox.checked) {
                        selected.add(item.id);
                    } else {
                        selected.delete(item.id);
                    }
                });

                tile.append(media, checkbox);

                grid.append(tile);

            } catch (error) {
                console.warn(
                    "An encrypted media item could not be decrypted."
                );
            }
        }

        $("count").textContent = `${items.length} items`;

        $("empty").classList.toggle(
            "hidden",
            items.length > 0
        );

        setStatus("galleryStatus", "");

    } catch (error) {
        console.error("Gallery loading failed:", error);

        setStatus(
            "galleryStatus",
            "Unable to load gallery data."
        );
    }
}


/* =====================================================
   ADD PHOTOS AND VIDEOS
===================================================== */

async function addFiles(event) {
    const files = Array.from(event.target.files || []);

    event.target.value = "";

    if (!vaultKey || files.length === 0) {
        return;
    }

    if (busy) {
        return;
    }

    busy = true;
    $("addBtn").disabled = true;

    try {
        for (const file of files) {
            if (!vaultKey) {
                break;
            }

            if (
                !file.type.startsWith("image/") &&
                !file.type.startsWith("video/")
            ) {
                continue;
            }

            const bytes = await file.arrayBuffer();

            const encrypted = await encryptBytes(
                vaultKey,
                bytes
            );

            const id = toBase64(randomBytes(16));

            await dbPut({
                id,
                name: file.name,
                type: file.type,
                size: file.size,
                iv: encrypted.iv,
                data: encrypted.data
            });
        }

        await renderGallery();

        setStatus(
            "galleryStatus",
            "Selected media has been processed."
        );

    } catch (error) {
        console.error("Adding media failed:", error);

        setStatus(
            "galleryStatus",
            "Unable to add media. Check available storage."
        );
    } finally {
        busy = false;
        $("addBtn").disabled = false;
    }
}


/* =====================================================
   DELETE SELECTED MEDIA
===================================================== */

async function deleteSelected() {
    if (!vaultKey) {
        return;
    }

    if (selected.size === 0) {
        alert("Select at least one item first.");
        return;
    }

    const confirmed = confirm(
        `Permanently delete ${selected.size} selected item(s) from this gallery?`
    );

    if (!confirmed) {
        return;
    }

    try {
        await dbDelete([...selected]);

        selected.clear();

        await renderGallery();

        setStatus(
            "galleryStatus",
            "Selected items deleted from the gallery database."
        );

    } catch (error) {
        console.error("Delete failed:", error);

        setStatus(
            "galleryStatus",
            "Unable to delete selected items."
        );
    }
}


/* =====================================================
   SHARE SELECTED MEDIA
===================================================== */

async function shareSelected() {
    if (!vaultKey) {
        return;
    }

    if (selected.size === 0) {
        alert("Select at least one item first.");
        return;
    }

    try {
        const items = await dbGetAll();

        const chosen = items.filter(
            item => selected.has(item.id)
        );

        const files = [];

        for (const item of chosen) {
            if (!vaultKey) {
                return;
            }

            const plain = await decryptBytes(
                vaultKey,
                item
            );

            files.push(
                new File(
                    [plain],
                    item.name || "private-media",
                    {
                        type: item.type || "application/octet-stream"
                    }
                )
            );
        }

        if (
            navigator.share &&
            navigator.canShare &&
            navigator.canShare({ files })
        ) {
            await navigator.share({
                title: "Private Gallery",
                files
            });

        } else {
            alert(
                "File sharing is not supported by this browser. Try a compatible mobile browser."
            );
        }

    } catch (error) {
        if (error.name !== "AbortError") {
            console.error("Sharing failed:", error);

            alert("Unable to share selected media.");
        }
    }
}


/* =====================================================
   IDLE LOCK
===================================================== */

function stopIdleTimer() {
    if (idleTimer) {
        clearTimeout(idleTimer);
        idleTimer = null;
    }
}

function startIdleTimer() {
    stopIdleTimer();

    if (!vaultKey) {
        return;
    }

    idleTimer = setTimeout(() => {
        lockVault();

        alert(
            "The vault has been locked due to inactivity."
        );
    }, IDLE_MS);
}

function lockVault() {
    stopIdleTimer();

    vaultKey = null;
    firstPassword = null;

    selected.clear();

    clearGalleryURLs();

    $("grid").replaceChildren();

    $("pass1").value = "";
    $("pass2").value = "";
    $("recoveryInput").value = "";

    init();
}


/* =====================================================
   INITIALIZATION
===================================================== */

function init() {
    if (!secureEnvironmentAvailable()) {
        showScreen("setup");

        setStatus(
            "setupStatus",
            "Use HTTPS on a modern browser to access secure cryptographic features."
        );

        return;
    }

    const meta = getMeta();

    if (!meta) {
        showScreen("setup");
        return;
    }

    loadFailureState(meta);

    if (meta.recoveryRequired) {
        showScreen("recovery");
    } else {
        showScreen("step1");
    }

    startCountdown();
}


/* =====================================================
   EVENT HANDLERS
===================================================== */

$("createBtn").addEventListener(
    "click",
    createVault
);

$("continueBtn").addEventListener("click", () => {
    showScreen("step1");
    startCountdown();
});

$("copyRecoveryBtn").addEventListener("click", async () => {
    const code = $("recoveryCode").textContent;

    try {
        await navigator.clipboard.writeText(code);

        setStatus(
            "recoveryShowStatus",
            "Recovery code copied. Store it securely."
        );

    } catch {
        setStatus(
            "recoveryShowStatus",
            "Copy unavailable. Select and copy the recovery code manually."
        );
    }
});

$("step1Btn").addEventListener(
    "click",
    verifyFirstPassword
);

$("step2Btn").addEventListener(
    "click",
    verifySecondPassword
);

$("recoverBtn").addEventListener(
    "click",
    recoverVault
);

$("fileInput").addEventListener(
    "change",
    addFiles
);

$("deleteBtn").addEventListener(
    "click",
    deleteSelected
);

$("shareBtn").addEventListener(
    "click",
    shareSelected
);

$("lockBtn").addEventListener(
    "click",
    lockVault
);

$("addBtn").addEventListener("click", () => {
    if (vaultKey) {
        isPickingFile = true; // यहाँ फ्लैग चालू किया
        $("fileInput").click();
    }
});


/* =====================================================
   ACTIVITY MONITORING
===================================================== */

function handleActivity() {
    if (vaultKey) {
        startIdleTimer();
    }
}

[
    "pointerdown",
    "keydown",
    "touchstart"
].forEach(eventName => {
    window.addEventListener(
        eventName,
        handleActivity,
        { passive: true }
    );
});

// बैकग्राउंड में जाने पर लॉक करने वाला लॉजिक
document.addEventListener(
    "visibilitychange",
    () => {
        if (document.hidden && vaultKey) {
            if (isPickingFile) {
                // अगर फाइल चुन रहे हैं, तो लॉक मत करो बस फ्लैग रिसेट कर दो
                isPickingFile = false;
            } else {
                // वरना तुरंत लॉक कर दो
                lockVault();
            }
        }
    }
);


/* =====================================================
   SERVICE WORKER
===================================================== */

if (
    "serviceWorker" in navigator &&
    window.isSecureContext
) {
    window.addEventListener("load", () => {
        navigator.serviceWorker
            .register("./sw.js")
            .catch(error => {
                console.warn(
                    "Service worker registration failed:",
                    error
                );
            });
    });
}


/* =====================================================
   START APPLICATION
===================================================== */

init();
