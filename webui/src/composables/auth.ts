import { ref } from 'vue'
import { call, client, signedOut, type Schemas } from '../api/client'

/** The panel login state; `null` until read. */
export const auth = ref<Schemas['AuthStatus'] | null>(null)

/** The login requests give up after this long (the answer to a login can take a second on a small machine). */
const TIMEOUT_MS = 10_000

/** Reads the login state; the login page is left once the login is off or this browser is signed in. */
export async function loadAuth() {
  auth.value = await call(client.GET('/auth', { signal: AbortSignal.timeout(TIMEOUT_MS) }))
  if (!auth.value.enabled || auth.value.authenticated) signedOut.value = false
}

export async function login(username: string, password: string) {
  auth.value = await call(client.POST('/auth/login', { body: { username, password }, signal: AbortSignal.timeout(TIMEOUT_MS) }))
  signedOut.value = false
}

export async function logout() {
  await call(client.POST('/auth/logout'))
  location.reload()
}
