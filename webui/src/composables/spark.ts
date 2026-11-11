/** Points of a sparkline over `values` in a 300×70 box (`max` is the top). */
export function sparkLine(values: number[], max: number): string {
  if (!values.length) return ''
  const step = values.length > 1 ? 300 / (values.length - 1) : 0
  return values.map((value, index) => `${(index * step).toFixed(1)},${(70 - (Math.min(value, max) / (max || 1)) * 66).toFixed(1)}`).join(' ')
}

export function sparkArea(values: number[], max: number): string {
  const line = sparkLine(values, max)
  if (!line) return ''
  const last = values.length > 1 ? 300 : 0
  return `0,70 ${line} ${last},70`
}
