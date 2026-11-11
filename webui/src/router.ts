import { createRouter, createWebHashHistory } from 'vue-router'
import OverviewPage from './pages/OverviewPage.vue'
import SettingsPage from './pages/SettingsPage.vue'
import ConnectionsPage from './pages/ConnectionsPage.vue'
import DnsLogsPage from './pages/DnsLogsPage.vue'
import DnsOverviewPage from './pages/DnsOverviewPage.vue'
import DnsSettingsPage from './pages/DnsSettingsPage.vue'
import DnsUpstreamsPage from './pages/DnsUpstreamsPage.vue'
import GroupEditPage from './pages/GroupEditPage.vue'
import GroupsPage from './pages/GroupsPage.vue'
import NodesPage from './pages/NodesPage.vue'
import RuleEditPage from './pages/RuleEditPage.vue'
import RulesPage from './pages/RulesPage.vue'
import RulesetsPage from './pages/RulesetsPage.vue'

// Hash routes: the package works under any mount path (`/`, `/<name>/`) without the host
// knowing its routes.
export const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', component: OverviewPage, meta: { title: '概览' } },
    { path: '/groups', component: GroupsPage, meta: { title: '节点组' } },
    { path: '/groups/new', component: GroupEditPage, meta: { title: '新建节点组' } },
    { path: '/groups/:id', component: GroupEditPage, meta: { title: '编辑节点组' } },
    { path: '/nodes', component: NodesPage, meta: { title: '节点' } },
    { path: '/rules', component: RulesPage, meta: { title: '规则' } },
    { path: '/rules/sets', component: RulesetsPage, meta: { title: '规则' } },
    { path: '/rules/new', component: RuleEditPage, meta: { title: '新建规则' } },
    { path: '/rules/:id', component: RuleEditPage, meta: { title: '编辑规则' } },
    { path: '/connections', component: ConnectionsPage, meta: { title: '连接' } },
    { path: '/dns', component: DnsOverviewPage, meta: { title: 'DNS' } },
    { path: '/dns/upstreams', component: DnsUpstreamsPage, meta: { title: 'DNS' } },
    { path: '/dns/logs', component: DnsLogsPage, meta: { title: 'DNS' } },
    { path: '/dns/settings', component: DnsSettingsPage, meta: { title: 'DNS' } },
    { path: '/settings', component: SettingsPage, meta: { title: '设置' } },
    { path: '/:rest(.*)*', redirect: '/' }
  ]
})
