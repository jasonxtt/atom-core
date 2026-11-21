/** Points of a sparkline over `values` in a `width × height` box (`max` is the top).
 * When `slots` is set, points right-align to that fixed window so partial history grows from the right. */
export function sparkCoords(
  values: number[],
  max: number,
  width = 300,
  height = 70,
  slots?: number
): Array<[number, number]> {
  if (!values.length) return []
  const padY = Math.min(4, height * 0.1)
  const usable = Math.max(1, height - padY * 2)
  const ceiling = max > 0 ? max : 1
  const yOf = (value: number) => height - padY - (Math.max(0, Math.min(value, ceiling)) / ceiling) * usable

  if (values.length === 1) {
    const y = yOf(values[0])
    const startX = slots && slots > 1 ? Math.max(0, width - Math.max(width / (slots - 1), 10)) : 0
    return [
      [startX, y],
      [width, y]
    ]
  }

  const totalSlots = Math.max(slots ?? values.length, values.length)
  const step = width / (totalSlots - 1)
  const offset = totalSlots - values.length
  return values.map((value, index) => [(offset + index) * step, yOf(value)])
}

export function sparkLine(values: number[], max: number, width = 300, height = 70, slots?: number): string {
  return sparkCoords(values, max, width, height, slots)
    .map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`)
    .join(' ')
}

export function sparkArea(values: number[], max: number, width = 300, height = 70, slots?: number): string {
  const coords = sparkCoords(values, max, width, height, slots)
  if (!coords.length) return ''
  const firstX = coords[0][0].toFixed(1)
  const lastX = coords[coords.length - 1][0].toFixed(1)
  const line = coords.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ')
  return `${firstX},${height} ${line} ${lastX},${height}`
}
