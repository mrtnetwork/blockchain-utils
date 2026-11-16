/**
 * Example WebHID host for `hw::wasm_webhid` (Rust/WASM side declares only
 * raw `extern "C"` imports — this file serves them; no wasm-bindgen, no
 * bundler-generated glue).
 *
 * Lives in the APPLICATION, not the Rust crate (copied here as a starting
 * point). Plain JS: zero Rust dependencies either way.
 *
 * Two hard constraints shape this file (both documented on the Rust side):
 *
 * 1. WASM imports are SYNCHRONOUS, but every WebHID call is async.
 *    Therefore device selection/opening happens in normal async JS
 *    (inside a user gesture for `requestDevice()`), and the sync
 *    `hw_hid_open` import only CLAIMS an already-open device.
 *
 * 2. Blocking the main thread starves `oninputreport` events, so the
 *    WASM module must run in a Web Worker and block on `Atomics.wait`
 *    over a SharedArrayBuffer while the main thread pumps HID events.
 *    This requires cross-origin isolation headers:
 *      Cross-Origin-Opener-Policy: same-origin
 *      Cross-Origin-Embedder-Policy: require-corp
 *    Without them there is NO correct single-threaded blocking bridge —
 *    don't spin-wait on the main thread, the inbox will never fill.
 *
 * Wiring sketch (main thread):
 *   import { HidHost } from './host.js';
 *   const host = new HidHost();
 *   button.onclick = () => host.prepareDevice(0x2c97, 0); // gesture!
 *   const worker = new Worker('worker.js');
 *   // worker.js instantiates the WASM module with:
 *   //   WebAssembly.instantiate(bytes, { env: host.workerImports(memory, mailbox) })
 *   // where `mailbox` is a SharedArrayBuffer shared with the main thread.
 *
 * Threading deployment (app-specific; the file only assumes the
 * invariant): `hw_hid_read` must block a thread that ISN'T the one
 * pumping `oninputreport`, and `hw_hid_open` must claim a pre-opened
 * device. Simplest coherent setup: run HidHost + WASM together in one
 * dedicated Worker; the main thread forwards the click as
 * `worker.postMessage({type:'prepare', vid, pid})` and the worker awaits
 * `prepareDevice()` (transient activation usually propagates to a
 * same-origin worker for `requestDevice()`; if a browser refuses, open
 * once in the main thread and rely on `getDevices()` afterwards —
 * returning users need no gesture at all).
 *
 * Mailbox layout (Int32Array view, per open device):
 *   [0] state: 0 = empty, 1 = report ready
 *   [1] report length in bytes (follows in the byte view)
 *   [2..] report bytes (cap 64 + margin)
 *
 *
 * Worker-side mailbox plumbing (worker.js):
 *   import { HidHost } from './host.js';
 *   const host = new HidHost(); // same instance shared via messages, or
 *   // reconstruct: the WORKER creates one SAB per claimed handle and
 *   // hands it to the main thread once:
 *   const mailboxes = new Map(); // handle -> SharedArrayBuffer
 *   function mailboxFor(handle) { return mailboxes.get(handle); }
 *   const raw = host.workerImports(memory, mailboxFor);
 *   const env = {
 *     ...raw,
 *     hw_hid_open(vid, pid) {
 *       const h = raw.hw_hid_open(vid, pid);
 *       if (h >= 0 && !mailboxes.has(h)) {
 *         const sab = new SharedArrayBuffer(128);
 *         mailboxes.set(h, sab);
 *         postMessage({ type: 'hid-mailbox', handle: h, sab });
 *         // main thread: onmessage -> route oninputreport posts into sab
 *       }
 *       return h;
 *     },
 *   };
 *   const { instance } = await WebAssembly.instantiate(bytes, { env });
 * (The main thread keeps its own handle->sab map from the posted message
 * and runs the `oninputreport` pump from `workerImports` — in a real app,
 * restructure so device ownership stays in ONE place.)
 */

export const MAILBOX_WORDS = 32; // 128 bytes: status + len + 64B report + slack

export class HidHost {
  constructor() {
    this.devices = new Map(); // handle -> { device, vid, pid }
    this.nextHandle = 1;
    this.pending = []; // pre-opened devices awaiting claim by hw_hid_open
  }

  /**
   * Async part of open. MUST be called from a user gesture the first time
   * (requestDevice), or anytime for already-permissioned devices
   * (getDevices needs no gesture). After this resolves, the sync
   * `hw_hid_open` import can claim the device from any thread.
   */
  async prepareDevice(vid, pid) {
    if (!navigator.hid) throw new Error('WebHID unavailable (use Chrome/Edge; Safari unsupported)');
    const permitted = await navigator.hid.getDevices();
    let device = permitted.find(
      (d) => d.vendorId === vid && (pid === 0 || d.productId === pid) && d.opened,
    );
    if (!device) {
      const filters = pid === 0 ? [{ vendorId: vid }] : [{ vendorId: vid, productId: pid }];
      const [picked] = await navigator.hid.requestDevice({ filters });
      if (!picked) throw new Error('device selection cancelled');
      device = picked;
    }
    if (!device.opened) await device.open();
    this.pending.push(device);
    return true;
  }

  /**
   * Build the `env` import object for a worker running the WASM module.
   * `mailboxFor(handle)` must return the SharedArrayBuffer the main thread
   * associates with that handle (created at claim time, see below).
   */
  workerImports(wasmMemory, mailboxFor) {
    const host = this;
    return {
      hw_hid_open(vid, pid) {
        const i = host.pending.findIndex(
          (d) => d.vendorId === vid && (pid === 0 || d.productId === pid),
        );
        if (i < 0) return -1; // nothing prepared — app forgot prepareDevice()
        const [device] = host.pending.splice(i, 1);
        const handle = host.nextHandle++;
        device.oninputreport = (e) => {
          const sab = mailboxFor(handle);
          if (!sab) return;
          const view = new Int32Array(sab);
          if (Atomics.load(view, 0) !== 0) return; // previous report unconsumed: drop
          const bytes = new Uint8Array(e.data.buffer);
          const n = Math.min(bytes.length, 64);
          new Uint8Array(sab, 8, n).set(bytes.subarray(0, n));
          Atomics.store(view, 1, n);
          Atomics.store(view, 0, 1); // report ready (waiters watch [0])
          Atomics.notify(view, 0, 1);
        };
        host.devices.set(handle, { device, vid, pid });
        return handle;
      },

      hw_hid_write(handle, ptr, len) {
        const entry = host.devices.get(handle);
        if (!entry) return -1;
        try {
          if (ptr + len > wasmMemory.buffer.byteLength) return -1; // bounds: SECURITY
          // Copy: sendReport outlives this call, the buffer may move.
          const bytes = new Uint8Array(wasmMemory.buffer.slice(ptr, ptr + len));
          entry.device.sendReport(0, bytes).catch(() => {
            entry.writeFailed = true;
          });
          if (entry.writeFailed) {
            entry.writeFailed = false;
            return -1;
          }
          return len;
        } catch {
          return -1;
        }
      },

      hw_hid_read(handle, outPtr, cap, timeoutMs) {
        const entry = host.devices.get(handle);
        if (!entry) return -1;
        const sab = mailboxFor(handle);
        if (!sab) return -1;
        const view = new Int32Array(sab);
        // Block the WORKER thread (never the main thread) until the main
        // thread's oninputreport posts a report, or the deadline passes.
        const st = Atomics.wait(view, 0, 0, timeoutMs);
        if (st === 'timed-out' && Atomics.load(view, 0) === 0) return 0;
        // 'ok' or 'not-equal': a report is present — consume it.
        if (Atomics.load(view, 0) !== 1) return -1;
        const n = Math.min(Atomics.load(view, 1), cap);
        if (outPtr + n > wasmMemory.buffer.byteLength) {
          Atomics.store(view, 0, 0);
          return -1;
        }
        new Uint8Array(wasmMemory.buffer, outPtr, n).set(new Uint8Array(sab, 8, n));
        Atomics.store(view, 0, 0); // mark empty
        return n;
      },

      hw_hid_close(handle) {
        const entry = host.devices.get(handle);
        if (!entry) return;
        host.devices.delete(handle);
        entry.device.close().catch(() => {});
      },
    };
  }
}

// Keep import names stable for the Rust `extern "C"` block: if you bundle
// this file, disable property mangling for the four `hw_hid_*` keys.
