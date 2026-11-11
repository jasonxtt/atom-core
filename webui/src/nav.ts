/** The first-level menu (design: 概览、节点组、节点、规则、连接、DNS、设置). */
export interface NavItem {
  path: string
  label: string
  icon: string
}

export const navItems: NavItem[] = [
  { path: '/', label: '概览', icon: '<path d="M4 11l8-7 8 7v9H4z"/>' },
  {
    path: '/groups',
    label: '节点组',
    icon: '<rect x="3" y="4" width="8" height="7" rx="2"/><rect x="13" y="4" width="8" height="7" rx="2"/><rect x="3" y="13" width="8" height="7" rx="2"/><rect x="13" y="13" width="8" height="7" rx="2"/>'
  },
  { path: '/nodes', label: '节点', icon: '<rect x="3" y="5" width="18" height="6" rx="2"/><rect x="3" y="13" width="18" height="6" rx="2"/>' },
  { path: '/rules', label: '规则', icon: '<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>' },
  { path: '/connections', label: '连接', icon: '<path d="M7 7h11l-3-3M17 17H6l3 3"/>' },
  {
    path: '/dns',
    label: 'DNS',
    icon: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18"/>'
  },
  {
    path: '/settings',
    label: '设置',
    icon: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/>'
  }
]
