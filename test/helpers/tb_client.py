"""Thunderbird Marionette client wrapper."""

from __future__ import annotations

import contextlib
import time
from pathlib import Path
from typing import Any, Callable

from marionette_driver.addons import Addons
from marionette_driver.marionette import Marionette


class TBClient:
    def __init__(self, host: str = "thunderbird", port: int = 2828) -> None:
        # marionette_driver 3.7.0 hardcodes self.host = "127.0.0.1" in __init__,
        # so we have to set it again after construction. This is a known quirk
        # of the upstream code (security default: Marionette listens on loopback
        # only). Inter-container access is bridged by socat in the TB container.
        self.m = Marionette(host=host, port=port, socket_timeout=120, startup_timeout=120)
        self.m.host = host
        # Auto-dismiss any modal dialog (TB throws "send failed" alerts).
        self.m.start_session({"unhandledPromptBehavior": "dismiss"})
        self.m.set_context(self.m.CONTEXT_CHROME)
        # nsIMsgCompose.sendMsg can take >30s for first send (SMTP TLS handshake).
        self.m.timeout.script = 90
        self.addons = Addons(self.m)
        self._installed_addons: list[str] = []

    def close(self) -> None:
        for addon_id in reversed(self._installed_addons):
            with contextlib.suppress(Exception):
                self.addons.uninstall(addon_id)
        self._installed_addons.clear()
        with contextlib.suppress(Exception):
            self.m.delete_session()

    def install_addon(self, xpi_path: str | Path, temporary: bool = True) -> str:
        addon_id = self.addons.install(str(xpi_path), temp=temporary)
        self._installed_addons.append(addon_id)
        return addon_id

    def uninstall_addon(self, addon_id: str) -> None:
        self.addons.uninstall(addon_id)
        with contextlib.suppress(ValueError):
            self._installed_addons.remove(addon_id)

    def get_pref(self, name: str) -> Any:
        script = """
            const name = arguments[0];
            const branch = Services.prefs;
            const type = branch.getPrefType(name);
            switch (type) {
              case branch.PREF_STRING: return branch.getStringPref(name);
              case branch.PREF_INT:    return branch.getIntPref(name);
              case branch.PREF_BOOL:   return branch.getBoolPref(name);
              default: return null;
            }
        """
        return self.m.execute_script(script, script_args=[name])

    def set_pref(self, name: str, value: Any) -> None:
        # Use setCharPref (not setStringPref): TB's SmtpServer reads via
        # getCharPref and treats getStringPref-stored values as unset.
        script = """
            const [name, value] = arguments;
            const branch = Services.prefs;
            if (typeof value === "boolean") branch.setBoolPref(name, value);
            else if (typeof value === "number") branch.setIntPref(name, value);
            else branch.setCharPref(name, String(value));
        """
        self.m.execute_script(script, script_args=[name, value])

    def exec_chrome(self, js: str, args: list[Any] | None = None) -> Any:
        # Wrap in async IIFE so top-level await works. Marionette awaits
        # returned Promises automatically.
        wrapped = f"return (async () => {{ {js} }})();"
        return self.m.execute_script(wrapped, script_args=args or [])

    def ensure_identity_and_smtp(
        self,
        *,
        identity_email: str,
        smtp_host: str,
        smtp_port: int,
    ) -> dict[str, str]:
        """Create or find an identity and SMTP server. Returns {identityKey, smtpKey}."""
        js = r"""
            const [identityEmail, smtpHost, smtpPort] = arguments;
            const { MailServices } = ChromeUtils.importESModule(
              "resource:///modules/MailServices.sys.mjs"
            );
            const Ci = Components.interfaces;
            const outgoing = MailServices.outgoingServer || MailServices.smtp;

            let smtp = null;
            for (const s of outgoing.servers) {
              const ss = s.QueryInterface ? s.QueryInterface(Ci.nsISmtpServer) : s;
              if (ss.hostname === smtpHost && ss.port === smtpPort) { smtp = ss; break; }
            }
            if (!smtp) {
              const raw = outgoing.createServer("smtp");
              smtp = raw.QueryInterface(Ci.nsISmtpServer);
              smtp.hostname = smtpHost;
              smtp.port = smtpPort;
              smtp.authMethod = 0;
              smtp.socketType = 0;
            }

            let identity = null;
            for (const i of MailServices.accounts.allIdentities) {
              if (i.email === identityEmail) { identity = i; break; }
            }
            if (!identity) {
              identity = MailServices.accounts.createIdentity();
              identity.email = identityEmail;
              identity.fullName = "onionbird test";
              identity.smtpServerKey = smtp.key;
              const account = MailServices.accounts.createAccount();
              const server = MailServices.accounts.createIncomingServer(
                "anon", "local.invalid", "none");
              account.incomingServer = server;
              account.addIdentity(identity);
            } else {
              identity.smtpServerKey = smtp.key;
            }

            return { identityKey: identity.key, smtpKey: smtp.key };
        """
        wrapped = f"return (async () => {{ {js} }})();"
        return self.m.execute_script(wrapped, script_args=[identity_email, smtp_host, smtp_port])

    def open_compose_window_and_send(
        self,
        *,
        identity_email: str,
        to: str,
        subject: str,
        body: str,
        wait_close_timeout: float = 5.0,
    ) -> dict:
        """Open a compose window via `MailServices.compose.OpenComposeWindowWithParams`,
        wait for it to appear, programmatically click the Send button via
        `goDoCommand('cmd_sendNow')` (the exact code path the UI button triggers,
        which is what `compose.onBeforeSend` is wired to). Returns a dict with:
          - opened: bool — compose window actually appeared
          - send_triggered: bool — cmd_sendNow ran without throw
          - still_open_after: bool — window still around after wait_close_timeout
            (true ⇒ send was cancelled by an onBeforeSend listener; false ⇒
            send proceeded and the window closed itself)
          - error: str | None

        T-076 behavioural verification target: with the addon's compose.onBeforeSend
        listener firing cancel:true, the window should still be open after the
        wait. With the listener regressed (deleted / wrong return shape / wrong
        verdict check), the window closes because the send proceeds.
        """
        js = r"""
            const [identityEmail, to, subject, body, waitMs] = arguments;
            const { MailServices } = ChromeUtils.importESModule(
              "resource:///modules/MailServices.sys.mjs"
            );
            const { Cc, Ci } = window;
            const result = { opened: false, send_triggered: false,
                             still_open_after: false, error: null };
            let identity = null;
            for (const i of MailServices.accounts.allIdentities) {
              if (i.email === identityEmail) { identity = i; break; }
            }
            if (!identity) { result.error = "identity not found: " + identityEmail; return result; }

            const compFields = Cc[
              "@mozilla.org/messengercompose/composefields;1"
            ].createInstance(Ci.nsIMsgCompFields);
            compFields.from = identityEmail;
            compFields.to = to;
            compFields.subject = subject;
            compFields.body = body;

            const params = Cc[
              "@mozilla.org/messengercompose/composeparams;1"
            ].createInstance(Ci.nsIMsgComposeParams);
            params.identity = identity;
            params.composeFields = compFields;
            params.format = Ci.nsIMsgCompFormat.PlainText;
            params.type = Ci.nsIMsgCompType.New;

            // Snapshot existing compose-window count so we can detect the new one.
            function listComposeWindows() {
              const wins = [];
              for (const w of Services.wm.getEnumerator("msgcompose")) wins.push(w);
              return wins;
            }
            const before = new Set(listComposeWindows());
            MailServices.compose.OpenComposeWindowWithParams(null, params);

            // Wait for the new window to appear, up to 5s.
            async function waitForWin(timeout) {
              const deadline = Date.now() + timeout;
              while (Date.now() < deadline) {
                for (const w of listComposeWindows()) {
                  if (!before.has(w)) return w;
                }
                await new Promise((r) => setTimeout(r, 50));
              }
              return null;
            }
            const win = await waitForWin(5000);
            if (!win) { result.error = "compose window did not open"; return result; }
            result.opened = true;

            // Some chrome init runs after window-open; give it a beat to wire
            // the controllers / commands so cmd_sendNow is enabled.
            async function waitForCmd(w, cmd, timeout) {
              const deadline = Date.now() + timeout;
              while (Date.now() < deadline) {
                try {
                  const ctrl = w.document.commandDispatcher
                    ? w.document.commandDispatcher.getControllerForCommand(cmd)
                    : null;
                  if (ctrl && ctrl.isCommandEnabled(cmd)) return true;
                } catch (e) {}
                await new Promise((r) => setTimeout(r, 50));
              }
              return false;
            }
            await waitForCmd(win, "cmd_sendNow", 3000);

            // Register a send-progress listener BEFORE triggering send.
            // This is the load-bearing distinguisher between
            //   "onBeforeSend cancelled the send" (onStartSending never fires)
            //   "send proceeded but transport failed" (onStartSending fires,
            //    then onStopSending with a failure status)
            //   "send proceeded and succeeded" (onStartSending fires, then
            //    onStopSending with NS_OK)
            //
            // The observed state lives in an IIFE-local closure variable —
            // NOT on the window — because TB auto-closes the compose
            // window on a successful send, and properties hung off the
            // window get garbage-collected with it. A closure-captured
            // object survives because the listener-binding closure (and
            // this IIFE) keep it reachable, regardless of window state.
            // Without this, the worst-case regression (`onBeforeSend`
            // returns undefined AND transport succeeds → window closes
            // cleanly) would surface as `start_sending: false` (the
            // "good" case) — the literal opposite of what's true.
            const observed = { startSending: false, stopSending: false, stopStatus: null, listenerAttached: false };
            try {
              if (win.gMsgCompose && win.gMsgCompose.addMsgSendListener) {
                win.gMsgCompose.addMsgSendListener({
                  QueryInterface: ChromeUtils.generateQI(["nsIMsgSendListener"]),
                  onStartSending() { observed.startSending = true; },
                  onSendProgress() {},
                  onStatus() {},
                  onStopSending(_uri, status) {
                    observed.stopSending = true;
                    observed.stopStatus = status;
                  },
                  onGetDraftFolderURI() {},
                  onSendNotPerformed() {},
                });
                observed.listenerAttached = true;
              }
            } catch (e) {
              result.listener_error = String(e);
            }

            // Trigger send via the same command the toolbar button uses;
            // this is the path the WebExt compose.onBeforeSend is hooked on.
            try {
              if (typeof win.goDoCommand === "function") {
                win.goDoCommand("cmd_sendNow");
              } else if (typeof win.SendMessage === "function") {
                win.SendMessage();
              } else {
                result.error = "no send entry-point on compose window";
                return result;
              }
              result.send_triggered = true;
            } catch (e) {
              result.error = "send trigger threw: " + String(e);
            }

            // Wait the caller-specified window. `still_open_after` is
            // a necessary-but-not-sufficient signal — SMTP failures
            // also leave the window open with an error notification.
            // The disambiguator is the notification box: a successful
            // onBeforeSend cancel leaves a notification whose body
            // text matches the addon's cancelMessage; an SMTP-transport
            // failure leaves a different notification (Mozilla's own
            // "couldn't connect" / "send failed" message).
            await new Promise((r) => setTimeout(r, waitMs));
            result.still_open_after = !win.closed;
            // Snapshot the observed send-progress state from the closure-
            // captured object — it survives window-close. `start_sending`
            // is the load-bearing signal: false iff onBeforeSend cancelled
            // the send before TB ever entered the sending state.
            // `listener_attached` is reported so the Python side can
            // refuse to interpret the result when the listener wiring
            // failed (e.g. gMsgCompose not present yet).
            result.listener_attached = observed.listenerAttached;
            result.start_sending = observed.startSending;
            result.stop_sending = observed.stopSending;
            result.stop_status = observed.stopStatus;
            // Collect every notification body the compose window
            // currently shows. Multiple element IDs are possible across
            // TB versions: `compose-notification-bottom` is the modern
            // ID; some skins use `compose-notification-top`. Fall back
            // to a name-agnostic walk through gComposeNotification /
            // gNotification globals if present.
            result.notification_texts = [];
            try {
              // S-6: in TB 115+ the canonical entry point is
              // `gComposeNotification.allNotifications`. We try that
              // first, then fall back to the legacy element IDs that
              // older TB versions used. Order matters — the canonical
              // global is the one a future-maintainer's grep will hit.
              const boxes = [];
              for (const g of ["gComposeNotification", "gNotification"]) {
                const box = win[g];
                if (box) boxes.push(box);
              }
              for (const id of [
                "compose-notification-bottom",
                "compose-notification-top",
                "compose-notification",
                "notification-bar-compose",
              ]) {
                const el = win.document.getElementById(id);
                if (el && !boxes.includes(el)) boxes.push(el);
              }
              for (const box of boxes) {
                const notes = box.allNotifications || box.notifications || [];
                for (const n of notes) {
                  const txt = (n.messageText && n.messageText.textContent) ||
                              n.label || n.value || "";
                  if (txt) result.notification_texts.push(String(txt));
                }
              }
            } catch (e) {
              result.notification_error = String(e);
            }
            // Tidy up: close the window if it's still hanging around so
            // the test environment doesn't leak compose windows across
            // subsequent tests.
            try { if (!win.closed) win.close(); } catch (e) {}
            return result;
        """
        wrapped = f"return (async () => {{ {js} }})();"
        wait_ms = int(wait_close_timeout * 1000)
        return self.m.execute_script(
            wrapped,
            script_args=[identity_email, to, subject, body, wait_ms],
        )

    def send_via_smtp(
        self,
        *,
        identity_email: str,
        smtp_host: str,
        smtp_port: int,
        to: str,
        subject: str,
        body: str,
    ) -> None:
        """Send a mail via nsIMsgCompose. Returns when send completes or raises."""
        self.ensure_identity_and_smtp(
            identity_email=identity_email,
            smtp_host=smtp_host,
            smtp_port=smtp_port,
        )
        js = r"""
            const [identityEmail, to, subject, body] = arguments;
            const { MailServices } = ChromeUtils.importESModule(
              "resource:///modules/MailServices.sys.mjs");
            const { Cc, Ci } = window;

            let identity = null;
            for (const i of MailServices.accounts.allIdentities) {
              if (i.email === identityEmail) { identity = i; break; }
            }
            if (!identity) throw new Error("identity not found");

            const fields = Cc[
              "@mozilla.org/messengercompose/composefields;1"
            ].createInstance(Ci.nsIMsgCompFields);
            fields.from = identityEmail;
            fields.to = to;
            fields.subject = subject;
            fields.body = body;

            const params = Cc[
              "@mozilla.org/messengercompose/composeparams;1"
            ].createInstance(Ci.nsIMsgComposeParams);
            params.composeFields = fields;
            params.identity = identity;
            params.format = Ci.nsIMsgCompFormat.PlainText;

            const compose = MailServices.compose.initCompose(params);
            return await new Promise((resolve, reject) => {
              const listener = {
                QueryInterface: ChromeUtils.generateQI(["nsIMsgSendListener"]),
                onStartSending() {},
                onSendProgress() {},
                onStatus() {},
                onStopSending(_uri, status) {
                  if (Components.isSuccessCode(status)) resolve(true);
                  else reject(new Error("send failed: 0x" + status.toString(16)));
                },
                onGetDraftFolderURI() {},
                onSendNotPerformed() { reject(new Error("not performed")); }
              };
              try {
                compose.sendMsg(
                  Ci.nsIMsgCompDeliverMode.Now,
                  identity,
                  "",
                  null,
                  listener
                );
              } catch (e) {
                reject(e);
              }
            });
        """
        wrapped = f"return (async () => {{ {js} }})();"
        self.m.execute_script(wrapped, script_args=[identity_email, to, subject, body])


    # ----- E2E driving of addon Options page via frame-script bridge -----
    #
    # TB content tabs run in remote (out-of-process) browsers under
    # Fission. Marionette content context doesn't see them as
    # window_handles, and chrome's `browser.contentDocument` is null
    # for remote browsers. We work around this by loading a frame
    # script (`_t0_content_bridge.js`) into the tab's contentprocess
    # via `frameLoader.messageManager.loadFrameScript`. The bridge
    # registers per-operation message handlers (t0:click, t0:text,
    # t0:set-input, etc.) that operate on the content DOM and reply
    # asynchronously. Chrome-side helpers send a request with a
    # generated `qid` and wait for the matching `t0:result` reply.

    _BRIDGE_PATH = Path(__file__).parent / "_t0_content_bridge.js"

    def get_addon_uuid(self, addon_id: str) -> str:
        return self.exec_chrome(
            "const [id] = arguments;"
            "const policy = WebExtensionPolicy.getByID(id);"
            "return policy.mozExtensionHostname;",
            args=[addon_id],
        )

    def open_addon_page(
        self, addon_id: str, page_path: str, timeout: float = 15.0
    ) -> str:
        """Open an addon-internal page (e.g. ui/options.html) in a TB
        content tab AND load the cross-process bridge frame script
        into it. After this returns, content-driving helpers
        (click/text/set_input/etc.) work via messageManager."""
        uuid = self.get_addon_uuid(addon_id)
        url = f"moz-extension://{uuid}/{page_path.lstrip('/')}"
        self.m.set_context(self.m.CONTEXT_CHROME)
        # Open the tab and stash a reference.
        self.exec_chrome(
            """
                const [url] = arguments;
                const win = Services.wm.getMostRecentWindow('mail:3pane');
                const tabmail = win.document.getElementById('tabmail');
                const tab = tabmail.openTab('contentTab', { url, background: false });
                tabmail.switchToTab(tab);
                win._t0_options_tab = tab;
                return true;
            """,
            args=[url],
        )
        # Wait for the tab's URI to be the addon URL AND for the
        # content to have loaded (contentTitle is the only signal
        # available cross-process from chrome).
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            last = self.exec_chrome("""
                const win = Services.wm.getMostRecentWindow('mail:3pane');
                const tab = win._t0_options_tab;
                if (!tab || !tab.linkedBrowser) return { phase: 'no-tab' };
                const b = tab.linkedBrowser;
                return {
                  uri: b.currentURI && b.currentURI.spec,
                  title: b.contentTitle,
                  isRemote: b.isRemoteBrowser,
                };
            """)
            if last.get("uri") == url and last.get("title"):
                break
            time.sleep(0.1)
        else:
            raise TimeoutError(
                f"options page never appeared within {timeout}s: {url}; "
                f"last={last!r}"
            )
        # Load the bridge frame script.
        bridge_src = self._BRIDGE_PATH.read_text(encoding="utf-8")
        self.exec_chrome(
            """
                const [src] = arguments;
                const win = Services.wm.getMostRecentWindow('mail:3pane');
                const tab = win._t0_options_tab;
                const mm = tab.linkedBrowser.frameLoader.messageManager;
                // Track the latest result per qid in a chrome-side map.
                if (!win._t0_results) win._t0_results = new Map();
                // Listeners must be re-installed on EACH tab's
                // messageManager — addMessageListener is per-mm and
                // each tab has its own. A previous test's listener
                // was registered against the previous tab's mm and is
                // dead with that tab.
                mm.addMessageListener('t0:result', function (msg) {
                  win._t0_results.set(msg.data.qid, msg.data);
                });
                mm.addMessageListener('t0:ready', function () {
                  win._t0_bridge_ready = true;
                });
                win._t0_bridge_ready = false;
                mm.loadFrameScript(
                  'data:application/javascript;charset=utf-8,' + encodeURIComponent(src),
                  false
                );
                return true;
            """,
            args=[bridge_src],
        )
        # Wait for bridge readiness signal.
        deadline = time.time() + 10.0
        while time.time() < deadline:
            ready = self.exec_chrome(
                "const win = Services.wm.getMostRecentWindow('mail:3pane');"
                "return !!win._t0_bridge_ready;"
            )
            if ready:
                # Give the page's async init (applyI18n, loadSocksOverride
                # etc.) a moment to settle now that the bridge is in.
                time.sleep(0.3)
                return url
            time.sleep(0.05)
        raise TimeoutError("content bridge never signaled ready")

    def close_addon_page(self) -> None:
        with contextlib.suppress(Exception):
            self.exec_chrome(
                """
                    const win = Services.wm.getMostRecentWindow('mail:3pane');
                    const tab = win._t0_options_tab;
                    if (tab) {
                      const tabmail = win.document.getElementById('tabmail');
                      try { tabmail.closeTab(tab); } catch (e) {}
                      delete win._t0_options_tab;
                    }
                    if (win._t0_results) win._t0_results.clear();
                """
            )

    def _bridge_call(self, op: str, extra: dict | None = None, timeout: float = 10.0):
        """Send a t0:<op> message and wait for the matching t0:result reply.
        Returns the value field; raises if the bridge reported error."""
        import uuid as _uuid
        qid = "q-" + _uuid.uuid4().hex
        payload = {"qid": qid}
        if extra:
            payload.update(extra)
        # Clear any prior result for this qid (defensive).
        self.exec_chrome(
            """
                const [op, payload] = arguments;
                const win = Services.wm.getMostRecentWindow('mail:3pane');
                const tab = win._t0_options_tab;
                if (!tab) throw new Error('options tab not open');
                const mm = tab.linkedBrowser.frameLoader.messageManager;
                if (win._t0_results) win._t0_results.delete(payload.qid);
                mm.sendAsyncMessage(op, payload);
                return true;
            """,
            args=[f"t0:{op}", payload],
        )
        deadline = time.time() + timeout
        while time.time() < deadline:
            res = self.exec_chrome(
                "const [qid] = arguments;"
                "const win = Services.wm.getMostRecentWindow('mail:3pane');"
                "if (!win._t0_results) return null;"
                "return win._t0_results.get(qid) || null;",
                args=[qid],
            )
            if res is not None:
                # Drop the recorded result to avoid map growth.
                self.exec_chrome(
                    "const [qid] = arguments;"
                    "const win = Services.wm.getMostRecentWindow('mail:3pane');"
                    "if (win._t0_results) win._t0_results.delete(qid);",
                    args=[qid],
                )
                if not res.get("ok"):
                    raise RuntimeError(
                        f"bridge op t0:{op} failed: {res.get('error')!r}"
                    )
                return res.get("value")
            time.sleep(0.05)
        raise TimeoutError(
            f"bridge op t0:{op} timed out after {timeout}s; payload={payload!r}"
        )

    def text(self, css: str) -> str:
        return self._bridge_call("text", {"sel": css})

    def attr(self, css: str, name: str):
        return self._bridge_call("attr", {"sel": css, "name": name})

    def input_value(self, css: str) -> str:
        return self._bridge_call("value", {"sel": css})

    def click(self, css: str) -> None:
        self._bridge_call("click", {"sel": css})

    def set_input(self, css: str, value: str) -> None:
        self._bridge_call("set-input", {"sel": css, "value": value})

    def select_option(self, css: str, value: str) -> None:
        self._bridge_call("select-option", {"sel": css, "value": value})

    def element_count(self, css: str) -> int:
        return self._bridge_call("count", {"sel": css})

    def eval_in_addon_page(self, code: str, timeout: float = 60.0):
        """Run arbitrary async JS in the options page context (where
        `browser.*` is available). The code body should `return` a
        JSON-serializable value."""
        return self._bridge_call("eval-async", {"code": code}, timeout=timeout)

    def auto_dismiss_dialogs(self) -> None:
        self._bridge_call("patch-dialogs", {})

    def wait_for_text(
        self,
        css: str,
        pred: Callable[[str], bool],
        timeout: float = 10.0,
        label: str = "",
    ) -> str:
        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            try:
                last = self.text(css)
                if pred(last):
                    return last
            except Exception:
                pass
            time.sleep(0.1)
        raise TimeoutError(
            f"wait_for_text({css!r}, label={label!r}) timed out after "
            f"{timeout}s; last text={last!r}"
        )
