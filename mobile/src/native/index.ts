/**
 * Native feature barrel export.
 *
 * Consumers can import everything from `@/native`:
 *
 *   import { useHaptics, light } from '@/native'
 */

// Capacitor initialisation
export { capacitorInit } from './capacitor-init'

// Haptics
export { useHaptics, light, medium, heavy, selection } from './haptics'
export type { UseHapticsResult } from './haptics'

// Network
export { useNetworkStatus } from './network'
export type { UseNetworkStatusResult } from './network'
