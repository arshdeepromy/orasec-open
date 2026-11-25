import { useSyncExternalStore } from 'react'

/**
 * Which plugins work on the server this device is linked to.
 *
 * On an OraSec server every integration (a data source, the Ora assistant, phone notifications, …) is a plugin that
 * an administrator turns on or off. The server sends the list with the account details; the app shows only the
 * screens whose plugin works. A server from before plugins existed sends no list: then everything is shown.
 */
export type PluginMap = Record<string, boolean>

const STORAGE_KEY = 'orasec.plugins.v1'
const listeners = new Set<() => void>()
let current: PluginMap | null = read()

function read(): PluginMap | null {
  try {
    const raw = globalThis.localStorage?.getItem(STORAGE_KEY)
    const parsed: unknown = raw ? JSON.parse(raw) : null
    return isPluginMap(parsed) ? parsed : null
  } catch {
    return null
  }
}

function isPluginMap(value: unknown): value is PluginMap {
  return !!value && typeof value === 'object' && !Array.isArray(value) && Object.values(value).every((v) => typeof v === 'boolean')
}

/** Keep what the server said (null: the server sent no list, or the device was unlinked). */
export function setPlugins(next: unknown): void {
  const map = isPluginMap(next) ? next : null
  if (JSON.stringify(map) === JSON.stringify(current)) return
  current = map
  try {
    if (map) globalThis.localStorage?.setItem(STORAGE_KEY, JSON.stringify(map))
    else globalThis.localStorage?.removeItem(STORAGE_KEY)
  } catch {
    // the list still holds for this run
  }
  for (const listener of listeners) listener()
}

export function getPlugins(): PluginMap | null {
  return current
}

/** True unless the server said this plugin does not work. */
export function pluginOn(key: string, map: PluginMap | null = current): boolean {
  return map?.[key] !== false
}

/** True when at least one of these plugins works. */
export function anyPluginOn(keys: readonly string[], map: PluginMap | null = current): boolean {
  return keys.some((key) => pluginOn(key, map))
}

/** The sources that feed the Attacks screen (blocked traffic and security alerts). */
export const ATTACK_SOURCES = ['source.wazuh', 'source.opnsense', 'source.cloudflare', 'source.unifi'] as const

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/** The plugin list, re-rendering the caller when it changes. */
export function usePlugins(): PluginMap | null {
  return useSyncExternalStore(subscribe, getPlugins, getPlugins)
}
