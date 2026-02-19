// ==UserScript==
// @name         Remove bad games from roblos
// @namespace    NullFire
// @match        https://www.roblox.com/*
// @grant        none
// @version      1.2
// @author       seikoso
// @downloadURL https://raw.githubusercontent.com/seikosos/utility/refs/heads/main/RemoveGames.user.js
// @updateURL   https://raw.githubusercontent.com/seikosos/utility/refs/heads/main/RemoveGames.meta.js
// ==/UserScript==

(function () {
    'use strict';

    const forbiddenWords = [
        "67", "brainrot", "steal a", "don't steal", "modded",
        "tsunami", "waves", "gubby", "outfit", "headpats from",
        "clothing", "garden", "grow a", "offline", "spin a", "sleep on", "femboy",
        "sammy", "escape", "lap",
    ];

    function containsForbidden(text) {
        text = text.toLowerCase();
        return forbiddenWords.some(w => text.includes(w));
    }

    function removeCard(cardLink) {
        let tileLi = cardLink.closest('li[id]') || cardLink;

        let el = tileLi;
        let a = 0;
        while (el && el !== document.body && a <= 2 && !el.classList.contains("game-grid") && !el.classList.contains("game-carousel")) {
            el.style.setProperty('display', 'none', 'important');
            el.style.setProperty('height', '0', 'important');
            el.style.setProperty('margin', '0', 'important');
            el.style.setProperty('padding', '0', 'important');
            el.style.setProperty('overflow', 'hidden', 'important');
            el = el.parentElement;
            a += 1;
        }
    }

    function checkGameCard(cardLink) {
        const titleEl = cardLink.querySelector('.game-card-name.game-name-title');
        if (!titleEl) return;

        const text = (titleEl.textContent || titleEl.title || "").trim();
        if (!text) return;

        if (cardLink.__filtered) return;
        cardLink.__filtered = true;

        if (containsForbidden(text)) {
            console.log("REMOVING game:", text);
            removeCard(cardLink);
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
})();
