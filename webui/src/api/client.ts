import createClient from 'openapi-fetch'
import { ref } from 'vue'
import type { components, paths } from './schema'

export type Schemas = components['schemas']

/** A refused or failed request: `status` 0 when atomdns could not be reached. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly body?: Schemas['Error']
  ) {
    super(message)
  }
}

// While the host publishes a new configuration generation it refuses requests before handling
// them with 503 `host is applying configuration`; such a request is sent again. Any other 503
// (a change that was handled but not fully published, for one) goes to the caller as it is.
const RETRIES = 6
const ADMISSION_REFUSAL = 'host is applying configuration'

async function refusedBeforeHandling(response: Response): Promise<boolean> {
  if (response.status !== 503) return false
  try {
    const body = (await response.clone().json()) as { error?: unknown }
    return body.error === ADMISSION_REFUSAL
  } catch {
    return false
  }
}

/** Set when a request outside `auth` is refused for want of a login (401): the app shows the login page. */
export const signedOut = ref(false)

async function retrying(request: Request): Promise<Response> {
  for (let attempt = 0; ; attempt++) {
    const response = await fetch(request.clone())
    if (response.status === 401 && !new URL(request.url).pathname.startsWith('/api/v1/atom/auth')) signedOut.value = true
    if (attempt >= RETRIES || !(await refusedBeforeHandling(response))) return response
    await new Promise((resolve) => setTimeout(resolve, 300 * (attempt + 1)))
  }
}

export const client = createClient<paths>({ baseUrl: '/api/v1/atom', fetch: retrying })

/** The data of an answer, or an `ApiError` with the server's `error` text. */
export async function call<T>(request: Promise<{ data?: T; error?: unknown; response: Response }>): Promise<T> {
  let answer
  try {
    answer = await request
  } catch {
    throw new ApiError(0, '无法连接 atomdns')
  }
  const { data, error, response } = answer
  if (!response.ok || error !== undefined) {
    const body = (error ?? undefined) as Schemas['Error'] | undefined
    throw new ApiError(response.status, body?.error || `请求失败（${response.status}）`, body)
  }
  return data as T
}

/** A message for a failure, with the status the API conventions give meaning to. */
export function describe(error: unknown): string {
  if (error instanceof ApiError) return error.status ? `${error.message}（${error.status}）` : error.message
  return String(error)
}
