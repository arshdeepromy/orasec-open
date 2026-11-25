/**
 * Make a Capacitor plugin proxy safe to return from an async function.
 *
 * Capacitor's `registerPlugin` proxy forwards EVERY property access to a
 * native method call — including `.then`. Returning the proxy from an
 * async function (or resolving a promise with it) triggers thenable
 * assimilation: JS calls `proxy.then(...)`, the bridge invokes a native
 * method literally named "then", and iOS rejects with
 *   `"X.then()" is not implemented on ios`
 * which aborted auth restore and left the app on the boot spinner forever.
 *
 * Wrapping the proxy so `then` reads as undefined restores normal
 * (non-thenable) promise resolution while leaving every real method intact.
 */
export function unthenable<T extends object>(plugin: T): T {
  return new Proxy(plugin, {
    get(target, prop, receiver) {
      if (prop === 'then') return undefined
      return Reflect.get(target, prop, receiver)
    },
  }) as T
}
