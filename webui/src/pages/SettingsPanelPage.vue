<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { call, client, describe } from '../api/client'
import SettingsTabs from '../components/SettingsTabs.vue'
import { auth, loadAuth } from '../composables/auth'
import { setTheme, theme, themeLabels, type Theme } from '../composables/theme'
import { toast } from '../composables/toast'

// The panel login: set, change (the current password when one is on) or turn off.
const login = reactive({ username: '', password: '', current: '' })
const loginError = ref('')
const loginBusy = ref(false)
onMounted(() => {
  loadAuth()
    .then(() => (login.username = auth.value?.username ?? ''))
    .catch((failure) => (loginError.value = describe(failure)))
})

async function saveLogin() {
  loginBusy.value = true
  loginError.value = ''
  try {
    const body = { username: login.username.trim(), password: login.password, ...(auth.value?.enabled ? { current_password: login.current } : {}) }
    auth.value = await call(client.PUT('/auth', { body }))
    login.password = ''
    login.current = ''
    toast('ok', '已保存')
  } catch (failure) {
    loginError.value = describe(failure)
  } finally {
    loginBusy.value = false
  }
}

async function disableLogin() {
  loginBusy.value = true
  loginError.value = ''
  try {
    auth.value = await call(client.DELETE('/auth', { body: { current_password: login.current } }))
    login.password = ''
    login.current = ''
    toast('ok', '已关闭登录')
  } catch (failure) {
    loginError.value = describe(failure)
  } finally {
    loginBusy.value = false
  }
}

const themes: Theme[] = ['system', 'light', 'dark']
</script>

<template>
  <SettingsTabs />
  <form class="card grid" style="gap: 10px" @submit.prevent="saveLogin">
    <div class="hd" style="margin: 0">
      <h2>面板登录</h2>
      <span class="sp"></span>
      <span v-if="auth" class="pill" :class="auth.enabled ? 'ok' : 'warn'"><span class="dot"></span>{{ auth.enabled ? '已开启' : '未开启' }}</span>
    </div>
    <div class="field">
      <label for="login-username">用户名</label>
      <input id="login-username" v-model="login.username" class="inp" autocomplete="username" :disabled="loginBusy || !auth" />
    </div>
    <div class="field">
      <label for="login-password">{{ auth?.enabled ? '新密码' : '密码' }}</label>
      <input id="login-password" v-model="login.password" class="inp" type="password" autocomplete="new-password" :disabled="loginBusy || !auth" />
    </div>
    <div v-if="auth?.enabled" class="field">
      <label for="login-current">当前密码</label>
      <input id="login-current" v-model="login.current" class="inp" type="password" autocomplete="current-password" :disabled="loginBusy" />
    </div>
    <div v-if="loginError" class="err">{{ loginError }}</div>
    <div class="row">
      <button class="btn pri" type="submit" :disabled="loginBusy || !auth || !login.username.trim() || !login.password || (auth.enabled && !login.current)">保存</button>
      <button v-if="auth?.enabled" class="btn danger" type="button" :disabled="loginBusy || !login.current" @click="disableLogin">关闭登录</button>
    </div>
  </form>
  <div class="card grid" style="gap: 10px">
    <h2>外观</h2>
    <div class="seg" style="justify-self: start">
      <button v-for="item in themes" :key="item" type="button" :class="{ on: theme === item }" @click="setTheme(item)">{{ themeLabels[item] }}</button>
    </div>
  </div>
</template>
