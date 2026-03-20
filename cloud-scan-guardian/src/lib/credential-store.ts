import { LLMProvider } from './types';

const STORAGE_KEY = 'cs_creds';

export interface StoredConfig {
  accessKey: string;
  secretKey: string;
  sessionToken?: string;
  region: string;
  llmProvider: LLMProvider;
  profile?: string;
  credentialMode: 'keys' | 'profile';
}

export function storeCredentials(config: StoredConfig): void {
  try {
    const encoded = btoa(JSON.stringify(config));
    sessionStorage.setItem(STORAGE_KEY, encoded);
  } catch {
    // sessionStorage unavailable or quota exceeded — silently skip
  }
}

export function loadCredentials(): StoredConfig | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(atob(raw)) as StoredConfig;
  } catch {
    return null;
  }
}

export function clearCredentials(): void {
  try {
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
}
