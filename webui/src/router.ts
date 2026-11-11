import { createRouter, createWebHashHistory } from 'vue-router'
import OverviewPage from './pages/OverviewPage.vue'
import SettingsPage from './pages/SettingsPage.vue'
import EmptyPage from './pages/EmptyPage.vue'
import GroupEditPage from './pages/GroupEditPage.vue'
import GroupsPage from './pages/GroupsPage.vue'
import NodesPage from './pages/NodesPage.vue'

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
    { path: '/rules', component: EmptyPage, meta: { title: '规则' } },
    { path: '/connections', component: EmptyPage, meta: { title: '连接' } },
    { path: '/dns', component: EmptyPage, meta: { title: 'DNS' } },
    { path: '/settings', component: SettingsPage, meta: { title: '设置' } },
    { path: '/:rest(.*)*', redirect: '/' }
  ]
})
