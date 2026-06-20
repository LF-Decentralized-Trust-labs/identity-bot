import type { SessionRecord, SessionState } from "./types.js";

export class InMemorySessionStore {
  private sessions = new Map<string, SessionRecord>();

  set(record: SessionRecord): void {
    this.sessions.set(record.token, record);
  }

  get(token: string): SessionRecord | undefined {
    const rec = this.sessions.get(token);
    if (!rec) return undefined;
    if (rec.state !== "verified" && rec.state !== "declined" && Date.parse(rec.expiresAt) < Date.now()) {
      rec.state = "expired";
    }
    return rec;
  }

  updateState(token: string, state: SessionState): SessionRecord | undefined {
    const rec = this.get(token);
    if (!rec) return undefined;
    rec.state = state;
    return rec;
  }

  markVerified(
    token: string,
    result: SessionRecord["verifiedResult"],
    pairwiseAid: string,
    appSessionToken: string,
  ): SessionRecord | undefined {
    const rec = this.get(token);
    if (!rec) return undefined;
    rec.state = "verified";
    rec.verifiedResult = result;
    rec.pairwiseAid = pairwiseAid;
    rec.appSessionToken = appSessionToken;
    return rec;
  }

  getNonce(token: string): string | undefined {
    return this.sessions.get(token)?.challenge.nonce;
  }
}