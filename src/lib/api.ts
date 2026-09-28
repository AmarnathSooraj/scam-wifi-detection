import type { Network } from "@/types/network";

const apiUrl = process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "");
let connected = false;

export function isBackendConnected() {
  return connected;
}

export function isBackendConfigured() {
  return Boolean(apiUrl);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  if (!apiUrl) {
    connected = false;
    throw new Error("Backend URL is not configured");
  }
  try {
    const response = await fetch(`${apiUrl}${path}`, {
      ...init,
      headers: { "Content-Type": "application/json", ...init?.headers },
      cache: "no-store",
    });
    if (!response.ok) throw new Error(`Backend request failed: ${response.status}`);
    connected = true;
    if (response.status === 204) return undefined as T;
    return response.json() as Promise<T>;
  } catch (error) {
    connected = false;
    throw error;
  }
}

export async function getNetworks(): Promise<Network[]> {
  try {
    return await request<Network[]>("/api/networks");
  } catch {
    connected = false;
    return [];
  }
}

export async function getNetworkDetails(bssid: string): Promise<Network | undefined> {
  try {
    return await request<Network>(`/api/networks/${encodeURIComponent(bssid)}`);
  } catch {
    connected = false;
    return undefined;
  }
}

export async function scanNetworks(): Promise<Network[]> {
  try {
    await request<unknown>("/api/scan", { method: "POST" });
    return await getNetworks();
  } catch {
    connected = false;
    return [];
  }
}

export async function getTrustedNetworks(): Promise<Network[]> {
  try {
    return await request<Network[]>("/api/trusted");
  } catch {
    connected = false;
    return [];
  }
}

export async function trustNetwork(network: Network): Promise<Network | undefined> {
  const saved = await request<Network | undefined>("/api/trusted", {
    method: "POST",
    body: JSON.stringify(network),
  });
  return saved;
}