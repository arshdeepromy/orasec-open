/**
 * Open a web page outside the app shell — the in-app browser tab
 * (SFSafariViewController / Chrome Custom Tab) on native, a new tab on web.
 */
import { Capacitor } from '@capacitor/core'

export async function openExternalUrl(url: string): Promise<void> {
  if (Capacitor.isNativePlatform()) {
    const { Browser } = await import('@capacitor/browser')
    await Browser.open({ url })
    return
  }
  window.open(url, '_blank', 'noopener,noreferrer')
}

export async function closeBrowser(): Promise<void> {
  if (!Capacitor.isNativePlatform()) return
  try {
    const { Browser } = await import('@capacitor/browser')
    await Browser.close()
  } catch {
    // already closed
  }
}
