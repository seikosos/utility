// ==UserScript==
// @name         Remove bad games from roblos
// @namespace    NullFire
// @match        https://www.roblox.com/*
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_registerMenuCommand
// @version      1.7
// @author       seikoso
// @downloadURL https://raw.githubusercontent.com/seikosos/utility/refs/heads/main/RemoveGames.user.js
// @updateURL   https://raw.githubusercontent.com/seikosos/utility/refs/heads/main/RemoveGames.meta.js
// ==/UserScript==

(function () {
    'use strict';

    /* ---------------- Persistent Settings ---------------- */

    let settings = {
        blockRNG: GM_getValue("blockRNG", true)
    };

    function saveSetting(key, value) {
        settings[key] = value;
        GM_setValue(key, value);
    }

    /* ---------------- Words ---------------- */

    let baseForbiddenWords = [
        "67", "brainrot", "steal a", "don't steal", "modded", "feet", "ai", "poop",
        "tsunami", "waves", "gubby", "outfit", "headpats from", "lay", "fart",
        "clothing", "garden", "grow a", "offline", "spin a", "sleep on", "prove"
    ];

    function getForbiddenWords() {
        const words = [...baseForbiddenWords];
        if (settings.blockRNG) words.push("rng");
        return words;
    }

    function containsForbidden(text) {
        text = text.toLowerCase();
        return getForbiddenWords().some(w => text.includes(w));
    }

    /* ---------------- Statistics ---------------- */

    let stats = {
        scanned: GM_getValue("scanned", 0),
        blocked: GM_getValue("blocked", 0),
        rngBlocked: GM_getValue("rngBlocked", 0)
    };

    function updateStatsUI() {
        document.getElementById("statScanned").textContent = stats.scanned;
        document.getElementById("statBlocked").textContent = stats.blocked;
        document.getElementById("statRngBlocked").textContent = stats.rngBlocked;
        document.getElementById("statWords").textContent = getForbiddenWords().join(", ");
        document.getElementById("rngToggle").checked = settings.blockRNG;

        saveSetting("scanned", stats.scanned);
        saveSetting("blocked", stats.blocked);
        saveSetting("rngBlocked", stats.rngBlocked);
    }

    /* ---------------- Filtering ---------------- */

    function removeCard(cardLink, text) {
        let tileLi = cardLink.closest('li[id]') || cardLink;

        let el = tileLi;
        let a = 0;
        while (el && el !== document.body && a <= 2 &&
            !el.classList.contains("game-grid") &&
            !el.classList.contains("game-carousel")) {

            el.style.setProperty('display', 'none', 'important');
            el.style.setProperty('height', '0', 'important');
            el.style.setProperty('margin', '0', 'important');
            el.style.setProperty('padding', '0', 'important');
            el.style.setProperty('overflow', 'hidden', 'important');

            el = el.parentElement;
            a++;
        }

        stats.blocked++;
        if (text.toLowerCase().includes("rng")) {
            stats.rngBlocked++;
        }
        updateStatsUI();
    }

    function checkGameCard(cardLink) {
        const titleEl = cardLink.querySelector('.game-card-name.game-name-title');
        if (!titleEl) return;

        const text = (titleEl.textContent || titleEl.title || "").trim();
        if (!text) return;

        if (cardLink.__filtered) return;
        cardLink.__filtered = true;

        stats.scanned++;
        updateStatsUI();

        if (containsForbidden(text)) {
            removeCard(cardLink, text);
        }
    }

    function scan(root = document) {
        root.querySelectorAll('.game-card-link').forEach(checkGameCard);
    }

    const observer = new MutationObserver(mutations => {
        for (const m of mutations) {
            for (const node of m.addedNodes) {
                if (!(node instanceof HTMLElement)) continue;
                scan(node);
            }
        }
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true
    });

    setInterval(scan, 1500);

    /* ---------------- UI Panel ---------------- */

    const panel = document.createElement("div");
    panel.style.position = "fixed";
    panel.style.bottom = "20px";
    panel.style.right = "20px";
    panel.style.background = "#111";
    panel.style.color = "white";
    panel.style.padding = "12px";
    panel.style.borderRadius = "8px";
    panel.style.zIndex = "999999";
    panel.style.fontSize = "12px";
    panel.style.width = "220px";
    panel.style.fontFamily = "Arial";

    panel.innerHTML = `
        <div style="font-weight:bold; margin-bottom:6px;">
            Filter Extension
        </div>

        <label style="display:flex; align-items:center; margin-bottom:8px;">
            <input type="checkbox" id="rngToggle" style="margin-right:6px;">
            Block RNG
        </label>

        <div style="border-top:1px solid #333; padding-top:6px;">
            <div style="font-weight:bold; margin-bottom:4px;">Statistics</div>
            <div>Scanned: <span id="statScanned">0</span></div>
            <div>Blocked: <span id="statBlocked">0</span></div>
            <div>RNG Blocks: <span id="statRngBlocked">0</span></div>
            <div style="margin-top:6px; font-size:10px;">
                Active Words: <span id="statWords"></span>
            </div>
        </div>
    `;

    document.body.appendChild(panel);

    document.getElementById("rngToggle").addEventListener("change", function () {
        saveSetting("blockRNG", this.checked);
        updateStatsUI();
    });

    /* ---------------- Violentmonkey Menu ---------------- */

    function registerMenu() {
        GM_registerMenuCommand(
            settings.blockRNG ? "Disable RNG Blocking" : "Enable RNG Blocking",
            function () {
                saveSetting("blockRNG", !settings.blockRNG);
                location.reload();
            }
        );
    }

    registerMenu();
    updateStatsUI();

})();
