/**
 * "Where you are signed in": a utility app's page lists the sessions a person has
 * open at the app, lets them sign one out, and lets them set how many they allow.
 * It talks to the app's `GET /session/sessions`, `POST
 * /session/sessions/end` and `POST /session/sessions/limit`, as `appSession`'s
 * signed calls, and is the one drawing of it: a page has no copy of this.
 */
import type { AppSession } from "./app.js";
import { SessionEnded } from "./app.js";

export interface OpenSession {
  key: string;
  started: string;
  last_used: string;
  current: boolean;
}

export interface SessionsAnswer {
  sessions: OpenSession[];
  /** The limit in force: the person's own or the app's, whichever is lower; 0 is none. */
  max: number;
  /** The app's own limit and the person's own (0 is none), so the page can say whose binds. */
  app_max: number;
  own_max: number;
}

export interface SessionsHandlers {
  /** The session this page holds was ended (here or elsewhere): draw the sign-in again. */
  onEnded(e: SessionEnded): void;
  /** A sentence for the person: what went wrong and what to do. */
  onProblem(text: string): void;
}

/** How long ago, in words a person reads cold. */
export function ago(then: string, now: number): string {
  const s = Math.max(0, Math.round((now - Date.parse(then)) / 1000));
  if (!Number.isFinite(s)) return "a while ago";
  if (s < 60) return "just now";
  const unit = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"} ago`;
  if (s < 3600) return unit(Math.floor(s / 60), "minute");
  if (s < 86400) return unit(Math.floor(s / 3600), "hour");
  return unit(Math.floor(s / 86400), "day");
}

/** One line of the list, in words. */
export function describe(s: OpenSession, now: number): string {
  return `${s.current ? "This device" : "Another browser"}: signed in ${ago(s.started, now)}, last used ${ago(s.last_used, now)}`;
}

/** What the limit is, in words, saying whose it is when the app's binds. */
export function limitLine(a: Pick<SessionsAnswer, "max" | "app_max" | "own_max">): string {
  if (a.max === 0) return "You may be signed in on any number of browsers at once.";
  const whose = a.app_max > 0 && a.max === a.app_max && a.own_max !== a.max ? " (this app's own limit)" : "";
  return `You may be signed in on at most ${a.max} browser${a.max === 1 ? "" : "s"} at once${whose}. Signing in on another ends the one you used least recently.`;
}

export const LIMIT_CHOICES = [0, 1, 2, 3, 5, 10];

export async function readSessions(session: AppSession): Promise<SessionsAnswer> {
  const r = await session.call("GET", "/session/sessions");
  if (r.status !== 200) throw new Error("The app would not list where you are signed in just now. Reload the page to try again.");
  return r.json<SessionsAnswer>();
}

/** Draws the panel in `el` and keeps it current after each change. */
export async function mountSessions(el: HTMLElement, session: AppSession, h: SessionsHandlers, now: () => number = Date.now): Promise<void> {
  const doc = el.ownerDocument;
  const say = (text: string) => h.onProblem(text);
  async function act(f: () => Promise<void>) {
    try {
      await f();
    } catch (e) {
      if (e instanceof SessionEnded) h.onEnded(e);
      else say((e as Error).message);
    }
  }
  async function draw(): Promise<void> {
    el.textContent = "Loading where you are signed in…";
    let a: SessionsAnswer;
    try {
      a = await readSessions(session);
    } catch (e) {
      if (e instanceof SessionEnded) return h.onEnded(e);
      el.textContent = "";
      return say((e as Error).message);
    }
    el.textContent = "";
    const title = doc.createElement("h2");
    title.textContent = "Where you are signed in";
    const list = doc.createElement("ul");
    for (const s of a.sessions) {
      const li = doc.createElement("li");
      li.textContent = describe(s, now()) + " ";
      if (!s.current) {
        const b = doc.createElement("button");
        b.type = "button";
        b.textContent = "Sign this one out";
        b.onclick = () =>
          act(async () => {
            b.disabled = true;
            b.textContent = "Signing it out…";
            const r = await session.call("POST", "/session/sessions/end", JSON.stringify({ key: s.key }));
            if (r.status !== 200 && r.status !== 404) throw new Error("The app did not sign that one out. Try again.");
            await draw();
          });
        li.append(b);
      }
      list.append(li);
    }
    const limit = doc.createElement("p");
    limit.textContent = limitLine(a);
    const pick = doc.createElement("select");
    pick.setAttribute("aria-label", "How many browsers may be signed in at once");
    for (const n of LIMIT_CHOICES) {
      const o = doc.createElement("option");
      o.value = String(n);
      o.textContent = n === 0 ? "No limit" : `At most ${n}`;
      if (n === a.own_max) o.selected = true;
      pick.append(o);
    }
    pick.onchange = () =>
      act(async () => {
        pick.disabled = true;
        const r = await session.call("POST", "/session/sessions/limit", JSON.stringify({ max: Number(pick.value) }));
        if (r.status !== 200) throw new Error("The app did not change your limit. Try again.");
        await draw();
      });
    el.append(title, list, limit, pick);
  }
  await draw();
}
