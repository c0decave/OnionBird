/* SPDX-License-Identifier: MPL-2.0
 *
 * Cross-process content driver for E2E options-page tests.
 *
 * This frame script is loaded into the addon's options-page content
 * process (which is remote/out-of-process under Fission). It exposes a
 * tiny set of message handlers so the chrome-side test harness can
 * read/click/set DOM elements without an actual Marionette content
 * session (TB content tabs don't register as Marionette browsing
 * contexts).
 *
 * Protocol: chrome sends `t0:op` with `{ qid, ... }`; content replies
 * via `t0:result` with `{ qid, ok, value, error }`. The qid round-trips
 * so chrome can match request/response.
 */
"use strict";

(function () {
  function reply(qid, fn) {
    let ok = true, value = null, error = null;
    try {
      value = fn();
    } catch (e) {
      ok = false;
      error = (e && (e.message || String(e))) || "unknown error";
    }
    sendAsyncMessage("t0:result", { qid, ok, value, error });
  }

  function el(sel) {
    const node = content.document.querySelector(sel);
    if (!node) throw new Error("not found: " + sel);
    return node;
  }

  addMessageListener("t0:ping", function (msg) {
    reply(msg.data.qid, () => ({
      href: content.document.location.href,
      title: content.document.title,
      readyState: content.document.readyState,
    }));
  });

  addMessageListener("t0:text", function (msg) {
    reply(msg.data.qid, () => (el(msg.data.sel).textContent || "").trim());
  });

  addMessageListener("t0:attr", function (msg) {
    reply(msg.data.qid, () => el(msg.data.sel).getAttribute(msg.data.name));
  });

  addMessageListener("t0:value", function (msg) {
    reply(msg.data.qid, () => el(msg.data.sel).value || "");
  });

  addMessageListener("t0:click", function (msg) {
    reply(msg.data.qid, () => {
      el(msg.data.sel).click();
      return true;
    });
  });

  addMessageListener("t0:set-input", function (msg) {
    reply(msg.data.qid, () => {
      const node = el(msg.data.sel);
      node.value = msg.data.value;
      node.dispatchEvent(new content.Event("input", { bubbles: true }));
      node.dispatchEvent(new content.Event("change", { bubbles: true }));
      return true;
    });
  });

  addMessageListener("t0:select-option", function (msg) {
    reply(msg.data.qid, () => {
      const node = el(msg.data.sel);
      node.value = msg.data.value;
      node.dispatchEvent(new content.Event("change", { bubbles: true }));
      return true;
    });
  });

  addMessageListener("t0:count", function (msg) {
    reply(msg.data.qid, () => content.document.querySelectorAll(msg.data.sel).length);
  });

  addMessageListener("t0:eval-async", function (msg) {
    const qid = msg.data.qid;
    const fn = new content.wrappedJSObject.Function(
      "return (async () => { " + msg.data.code + " })();"
    );
    Promise.resolve()
      .then(() => fn())
      .then(
        (value) => sendAsyncMessage("t0:result", { qid, ok: true, value, error: null }),
        (err) => sendAsyncMessage("t0:result", {
          qid, ok: false, value: null,
          error: (err && (err.message || String(err))) || "unknown error",
        })
      );
  });

  addMessageListener("t0:patch-dialogs", function (msg) {
    reply(msg.data.qid, () => {
      // Patch the JS-visible `window.confirm`/`alert`/`prompt` in the
      // content page. Frame scripts run in a separate sandbox from the
      // page; setting `content.confirm` alone targets only the sandbox
      // wrapper. To override what the page's own JS sees, write into
      // `wrappedJSObject` (the actual content global). `exportFunction`
      // is required because we're crossing the chrome→content security
      // boundary — a raw function would be Xray-blocked.
      const w = content.wrappedJSObject;
      Cu.exportFunction(() => true, w, { defineAs: "confirm" });
      Cu.exportFunction(() => undefined, w, { defineAs: "alert" });
      Cu.exportFunction(() => null, w, { defineAs: "prompt" });
      return true;
    });
  });

  // Signal readiness so the chrome side knows the bridge is loaded.
  sendAsyncMessage("t0:ready", {});
})();
