import type { Component } from 'vue'
import { ArrowLeftRight, Globe, House, LayoutGrid, Route, Server, Settings } from '@lucide/vue'

/** The first-level menu (design: 概览、节点组、节点、规则、连接、DNS、设置). */
export interface NavItem {
  path: string
  label: string
  icon: Component
}

export const navItems: NavItem[] = [
  { path: '/', label: '概览', icon: House },
  { path: '/groups', label: '节点组', icon: LayoutGrid },
  { path: '/nodes', label: '节点', icon: Server },
  { path: '/rules', label: '规则', icon: Route },
  { path: '/connections', label: '连接', icon: ArrowLeftRight },
  { path: '/dns', label: 'DNS', icon: Globe },
  { path: '/settings', label: '设置', icon: Settings }
]
