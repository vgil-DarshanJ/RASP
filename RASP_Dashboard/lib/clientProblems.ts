"use client";

/**
 * Failed API calls seen by THIS browser tab (kept in sessionStorage, last
 * [MAX] only), for the "This browser" part of the System Status page. A call
 * that never reached the backend (backend down, wrong URL, CORS) is recorded
 * with status 0 — the backend cannot log what it never received.
 * Nothing of the request or response body is kept: method, path without
 * query, status, the API `error` code and the backend's request id.
 */
export interface ClientProblem {
  at: string;
  method: string;
  path: string;
  /** 0 = no answer (network / CORS / backend down). */
  status: number;
  code?: string;
  requestId?: string;
}

const KEY = "rasp_client_problems";
const MAX = 50;
export const CLIENT_PROBLEMS_EVENT = "rasp:client-problem";

export function readClientProblems(): ClientProblem[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = sessionStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as ClientProblem[]) : [];
  } catch {
    return [];
  }
}

export function recordClientProblem(problem: Omit<ClientProblem, "at">): void {
  if (typeof window === "undefined") return;
  try {
    const entry: ClientProblem = { ...problem, path: problem.path.split("?")[0], at: new Date().toISOString() };
    const list = [entry, ...readClientProblems()].slice(0, MAX);
    sessionStorage.setItem(KEY, JSON.stringify(list));
  } catch {
    // Storage full or blocked: the page still works, this list just stays empty.
  }
  window.dispatchEvent(new Event(CLIENT_PROBLEMS_EVENT));
}

export function clearClientProblems(): void {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    // ignore
  }
  window.dispatchEvent(new Event(CLIENT_PROBLEMS_EVENT));
}
