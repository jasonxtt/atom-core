import { reactive } from 'vue'

export type ToastKind = 'ok' | 'warn' | 'bad' | 'acc'
export interface Toast {
  id: number
  kind: ToastKind
  text: string
}

export const toasts = reactive<Toast[]>([])
let next = 0

export function dismiss(id: number) {
  const index = toasts.findIndex((toast) => toast.id === id)
  if (index >= 0) toasts.splice(index, 1)
}

/** A message in the corner; errors stay until closed, the rest go after a few seconds
 * (`ms` sets the delay, and makes an error go too). */
export function toast(kind: ToastKind, text: string, ms?: number) {
  const id = ++next
  toasts.push({ id, kind, text })
  if (ms !== undefined || kind !== 'bad') setTimeout(() => dismiss(id), ms ?? 4000)
}
