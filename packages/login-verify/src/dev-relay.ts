import express from "express";
import type { Server } from "node:http";
import { buildDidWebsDocument } from "./resolver.js";
import type { SiteIdentity } from "./types.js";

export interface DevRelayOptions {
  port?: number;
  host?: string;
  identities?: SiteIdentity[];
}

/** BLOCKED: production relay — dev stub only for local steel thread. */
export function createDevRelayServer(opts: DevRelayOptions = {}): {
  app: express.Express;
  start: () => Promise<{ url: string; server: Server }>;
  registerIdentity: (identity: SiteIdentity) => void;
} {
  const registry = new Map<string, SiteIdentity>();
  for (const id of opts.identities ?? []) {
    registry.set(id.aid, id);
  }

  const app = express();
  app.use(express.json());

  app.get("/:aid/did.json", (req, res) => {
    const identity = registry.get(req.params.aid);
    if (!identity) {
      return res.status(404).json({ error: "aid not found" });
    }
    const host = req.get("host") ?? "127.0.0.1:8765";
    res.json(buildDidWebsDocument(identity.aid, host, identity.publicKey));
  });

  app.get("/oobi/:aid", (_req, res) => {
    res.json({ status: "dev-relay-stub", note: "BLOCKED: production relay not shipped" });
  });

  // Dev-only: IA registers pairwise AIDs for did.json resolution during local steel thread.
  app.post("/_dev/register", (req, res) => {
    const { aid, public_key_b64: pubB64 } = req.body ?? {};
    if (!aid || !pubB64) {
      return res.status(400).json({ error: "aid and public_key_b64 required" });
    }
    const pub = Buffer.from(pubB64, "base64url");
    registry.set(aid, {
      aid,
      publicKey: pub,
      privateKey: new Uint8Array(0),
      oobiUrl: `${req.protocol}://${req.get("host")}/oobi/${aid}`,
    });
    res.json({ ok: true, aid });
  });

  return {
    app,
    registerIdentity: (identity: SiteIdentity) => registry.set(identity.aid, identity),
    start: () =>
      new Promise((resolve) => {
        const port = opts.port ?? 8765;
        const host = opts.host ?? "127.0.0.1";
        const server = app.listen(port, host, () => {
          const addr = server.address();
          const actualPort =
            typeof addr === "object" && addr !== null ? addr.port : port;
          resolve({ url: `http://${host}:${actualPort}`, server });
        });
      }),
  };
}