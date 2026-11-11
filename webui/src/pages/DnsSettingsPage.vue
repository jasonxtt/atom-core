<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ApiError, call, client, describe, type Schemas } from '../api/client'
import DnsTabs from '../components/DnsTabs.vue'
import { lines } from '../composables/rules'
import { toast } from '../composables/toast'

type Dns = Schemas['Dns']
type Toggle = 'block_qtypes' | 'block_aaaa' | 'prefer_v4' | 'full_cache' | 'lazy_cache'
const TOGGLES: [Toggle, string][] = [
  ['block_qtypes', '屏蔽 SOA/PTR/HTTPS 查询'],
  ['block_aaaa', '屏蔽 AAAA'],
  ['prefer_v4', 'IPv4 优先'],
  ['full_cache', '全局缓存'],
  ['lazy_cache', '上游缓存']
]

const dns = ref<Dns | null>(null)
const form = reactive({ core_mode: 'compat' as 'compat' | 'safe', block_qtypes: false, block_aaaa: false, prefer_v4: false, full_cache: false, lazy_cache: false, learning: false, ecs: '' })
const settings = ref<Schemas['Settings'] | null>(null)
const ttl = reactive({ direct: '', fakeip: '' })
const rewrite = ref('')
const savedRewrite = ref('')
const errors = reactive({ load: '', dns: '', ttl: '', rewrite: '' })
const busy = ref('')

function fillDns(value: Dns) {
  dns.value = value
  Object.assign(form, {
    core_mode: value.core_mode,
    block_qtypes: value.block_qtypes,
    block_aaaa: value.block_aaaa,
    prefer_v4: value.prefer_v4,
    full_cache: value.full_cache,
    lazy_cache: value.lazy_cache,
    learning: !!value.learning?.enabled,
    ecs: value.ecs
  })
}
function fillSettings(value: Schemas['Settings']) {
  settings.value = value
  ttl.direct = String(value.direct_ttl_max)
  ttl.fakeip = String(value.fakeip_ttl_max)
}

onMounted(async () => {
  const results = await Promise.allSettled([call(client.GET('/dns')), call(client.GET('/settings')), call(client.GET('/rewrite'))])
  const [dnsNow, settingsNow, rewriteNow] = results
  if (dnsNow.status === 'fulfilled') fillDns(dnsNow.value)
  if (settingsNow.status === 'fulfilled') fillSettings(settingsNow.value)
  if (rewriteNow.status === 'fulfilled') {
    savedRewrite.value = rewriteNow.value.entries.join('\n')
    rewrite.value = savedRewrite.value
  }
  const failed = results.find((result) => result.status === 'rejected')
  errors.load = failed ? describe((failed as PromiseRejectedResult).reason) : ''
})

// Only what changed is sent (the last write wins: `dns` carries no version).
const dnsPatch = computed(() => {
  const current = dns.value
  if (!current) return {}
  const patch: Schemas['DnsPatch'] = {}
  if (form.core_mode !== current.core_mode) patch.core_mode = form.core_mode
  for (const [key] of TOGGLES) if (form[key] !== current[key]) patch[key] = form[key]
  if (form.learning !== !!current.learning?.enabled) patch.learning = { enabled: form.learning }
  if (form.ecs.trim() !== current.ecs) patch.ecs = form.ecs.trim()
  return patch
})

async function saveDns() {
  busy.value = 'dns'
  errors.dns = ''
  try {
    fillDns(await call(client.PUT('/dns', { body: dnsPatch.value })))
    toast('ok', '已保存')
  } catch (failure) {
    errors.dns = describe(failure)
  } finally {
    busy.value = ''
  }
}

const ttlChanged = computed(() => !!settings.value && (ttl.direct.trim() !== String(settings.value.direct_ttl_max) || ttl.fakeip.trim() !== String(settings.value.fakeip_ttl_max)))
async function saveTtl() {
  const current = settings.value
  if (!current) return
  const direct = Number(ttl.direct.trim())
  const fakeip = Number(ttl.fakeip.trim())
  if (![direct, fakeip].every((value) => Number.isInteger(value) && value >= 1 && value <= 86400)) {
    errors.ttl = 'TTL 上限应为 1–86400 的整数'
    return
  }
  busy.value = 'ttl'
  errors.ttl = ''
  try {
    fillSettings(await call(client.PUT('/settings', { body: { direct_ttl_max: direct, fakeip_ttl_max: fakeip, version: current.version } })))
    toast('ok', '已保存')
  } catch (failure) {
    if (failure instanceof ApiError && failure.status === 409 && failure.body?.version !== undefined) {
      try {
        fillSettings(await call(client.GET('/settings')))
        errors.ttl = '设置已在别处修改，已载入最新内容（409）'
      } catch (reload) {
        errors.ttl = `设置已在别处修改（409），重新读取失败：${describe(reload)}`
      }
    } else {
      errors.ttl = describe(failure)
    }
  } finally {
    busy.value = ''
  }
}

async function saveRewrite() {
  busy.value = 'rewrite'
  errors.rewrite = ''
  try {
    const answer = await call(client.PUT('/rewrite', { body: { entries: lines(rewrite.value) } }))
    savedRewrite.value = answer.entries.join('\n')
    rewrite.value = savedRewrite.value
    toast('ok', '已保存')
  } catch (failure) {
    errors.rewrite = describe(failure)
  } finally {
    busy.value = ''
  }
}
</script>

<template>
  <DnsTabs />
  <div v-if="errors.load" class="err">{{ errors.load }}</div>
  <div class="split3">
    <div v-if="dns" class="card grid" style="gap: 14px">
      <div class="hd" style="margin: 0">
        <h2>基本</h2>
        <span class="sp"></span>
        <button class="btn sm pri" type="button" :disabled="!!busy || !Object.keys(dnsPatch).length" @click="saveDns">保存</button>
      </div>
      <div class="field">
        <span class="label">未列入规则的域名</span>
        <div class="seg" style="align-self: flex-start">
          <button type="button" :class="{ on: form.core_mode === 'compat' }" @click="form.core_mode = 'compat'">兼容模式</button>
          <button type="button" :class="{ on: form.core_mode === 'safe' }" @click="form.core_mode = 'safe'">安全模式</button>
        </div>
      </div>
      <div v-for="item in TOGGLES" :key="item[0]" class="row">
        <div style="flex: 1">{{ item[1] }}</div>
        <button class="sw" type="button" :class="{ on: form[item[0]] }" :aria-pressed="form[item[0]]" :aria-label="item[1]" @click="form[item[0]] = !form[item[0]]"></button>
      </div>
      <div class="row">
        <div style="flex: 1">域名学习</div>
        <button class="sw" type="button" :class="{ on: form.learning }" :aria-pressed="form.learning" aria-label="域名学习" @click="form.learning = !form.learning"></button>
      </div>
      <div class="field">
        <label for="ecs">国外查询的 ECS 地址</label>
        <input id="ecs" v-model="form.ecs" class="inp mono" placeholder="留空用默认" autocomplete="off" />
      </div>
      <div v-if="errors.dns" class="err">{{ errors.dns }}</div>
    </div>
    <div class="grid" style="gap: 16px">
      <div v-if="settings" class="card grid" style="gap: 10px">
        <div class="hd" style="margin: 0">
          <h2>TTL 上限</h2>
          <span class="sp"></span>
          <button class="btn sm pri" type="button" :disabled="!!busy || !ttlChanged" @click="saveTtl">保存</button>
        </div>
        <div class="grid g2" style="gap: 10px">
          <div class="field">
            <label for="dttl">直连应答（秒）</label>
            <input id="dttl" v-model="ttl.direct" class="inp mono" inputmode="numeric" autocomplete="off" />
          </div>
          <div class="field">
            <label for="fttl">FakeIP 应答（秒）</label>
            <input id="fttl" v-model="ttl.fakeip" class="inp mono" inputmode="numeric" autocomplete="off" />
          </div>
        </div>
        <div v-if="errors.ttl" class="err">{{ errors.ttl }}</div>
      </div>
      <div class="card grid" style="gap: 10px">
        <div class="hd" style="margin: 0">
          <h2>重写 / hosts</h2>
          <span class="tag">{{ lines(rewrite).length }} 行</span>
          <span class="sp"></span>
          <button class="btn sm pri" type="button" :disabled="!!busy || rewrite === savedRewrite" @click="saveRewrite">保存</button>
        </div>
        <textarea v-model="rewrite" class="inp" aria-label="重写规则" placeholder="full:router.lan 192.168.1.1&#10;domain:corp.example.com 10.8.0.10"></textarea>
        <div v-if="errors.rewrite" class="err">{{ errors.rewrite }}</div>
      </div>
    </div>
  </div>
</template>
