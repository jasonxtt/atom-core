import { ref } from 'vue'
import { call, client, signedOut, type Schemas } from '../api/client'

/** The panel login state; `null` until read. */
export const auth = ref<Schemas['AuthStatus'] | null>(null)

export async function loadAuth() {
  auth.value = await call(client.GET('/auth'))
  if (auth.value.authenticated) signedOut.value = false
}

export async function login(username: string, password: string) {
  auth.value = await call(client.POST('/auth/login', { body: { username, password } }))
  signedOut.value = false
}

export async function logout() {
  await call(client.POST('/auth/logout'))
  location.reload()
}
