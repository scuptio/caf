// caf.worker.js — Web Worker host for untrusted .caf artifacts.
//
// Runs openCaf + component calls off the main thread; the main-thread wrapper
// (openCafWorker in caf.js) applies a watchdog timeout and terminates the
// worker on overrun — a best-effort CPU/memory backstop (the browser tab
// sandbox remains the real isolation boundary).
import * as CAF from "./caf.js";

let artifact = null;
let comp = null;

self.onmessage = async (e) => {
  const { id, op } = e.data;
  try {
    let value;
    if (op === "open") {
      artifact = await CAF.openCaf(e.data.source);
      comp = await artifact.instantiate(e.data.component ?? 0);
      value = {
        name: artifact.name,
        version: artifact.version,
        rootHash: artifact.rootHash,
        capabilities: artifact.capabilities,
        payloadFiles: artifact.payloadFiles(),
        signature: artifact.signature,
        jspi: comp.jspi,
      };
    } else if (op === "call") {
      value = await comp.call(e.data.name, ...e.data.args);
    } else if (op === "callPacked") {
      value = await comp.callPacked(e.data.name, ...e.data.args);
    } else if (op === "stats") {
      value = artifact.stats();
    } else {
      throw new Error(`unknown op ${op}`);
    }
    self.postMessage({ id, ok: true, value });
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err?.message ?? err) });
  }
};
