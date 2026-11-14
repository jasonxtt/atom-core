<script setup lang="ts">
import { ref } from 'vue'
import { describe } from '../api/client'
import { login } from '../composables/auth'

const username = ref('')
const password = ref('')
const error = ref('')
const busy = ref(false)

async function submit() {
  busy.value = true
  error.value = ''
  try {
    await login(username.value.trim(), password.value)
    location.reload()
  } catch (failure) {
    error.value = describe(failure)
    busy.value = false
  }
}
</script>

<template>
  <div class="login">
    <form class="card grid" style="gap: 12px" @submit.prevent="submit">
      <div class="brand"><i>a</i>atom</div>
      <div class="field">
        <label for="login-user">用户名</label>
        <input id="login-user" v-model="username" class="inp" autocomplete="username" autofocus :disabled="busy" />
      </div>
      <div class="field">
        <label for="login-pass">密码</label>
        <input id="login-pass" v-model="password" class="inp" type="password" autocomplete="current-password" :disabled="busy" />
      </div>
      <div v-if="error" class="err">{{ error }}</div>
      <button class="btn pri" type="submit" :disabled="busy || !username.trim() || !password">登录</button>
    </form>
  </div>
</template>

<style scoped>
.login {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 16px;
}
.login form {
  width: min(360px, 100%);
}
</style>
