<script setup>
import { ref } from 'vue'
import SettingSection from '../../components/settings/SettingSection.vue'
import SettingRow from '../../components/settings/SettingRow.vue'
import { appearance as a, applyAppearance, saveAppearance, resetAppearance } from '../../utils/glassAppearance'
const message = ref('')
const busy = ref(false)
function save() {
  try { saveAppearance(); message.value = '已保存到当前浏览器' }
  catch { message.value = '保存失败：浏览器存储不可用或空间不足，请换用更小的图片。当前预览未保存。' }
}
function reset() {
  try { resetAppearance(); message.value = '已恢复默认外观，并清除保存的图片' }
  catch { message.value = '浏览器不允许清除存储' }
}
async function upload(event) {
  const file = event.target.files?.[0]
  if (!file) return
  busy.value = true
  try {
    if (!['image/png', 'image/jpeg', 'image/webp', 'image/gif'].includes(file.type)) throw new Error('请选择 PNG、JPEG、WebP 或 GIF 图片')
    if (file.size > 3 * 1024 * 1024) throw new Error('图片不能超过 3 MB')
    const data = await new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => resolve(reader.result)
      reader.onerror = () => reject(new Error('图片读取失败'))
      reader.readAsDataURL(file)
    })
    await new Promise((resolve, reject) => {
      const img = new Image()
      img.onload = resolve
      img.onerror = () => reject(new Error('图片无法解码'))
      img.src = data
    })
    a.image = data; a.mode = 'upload'; applyAppearance(); save()
  } catch (error) { message.value = error.message }
  finally { busy.value = false; event.target.value = '' }
}
</script>
<template>
  <SettingSection id="glass-appearance" title="背景与玻璃外观" tiles>
    <SettingRow label="背景来源" layout="form" description="图片和外观仅保存在当前浏览器，清除网站数据后会删除；不会上传到服务器。">
      <select v-model="a.mode" aria-label="背景来源" @change="applyAppearance">
        <option value="none">默认渐变</option><option value="color">纯色</option><option value="upload">本地图片</option><option value="url">图片链接</option>
      </select>
    </SettingRow>
    <SettingRow v-if="a.mode === 'upload'" label="本地背景图" layout="form" description="PNG / JPEG / WebP / GIF，最大 3 MB。选择后自动保存。">
      <input type="file" accept="image/png,image/jpeg,image/webp,image/gif" aria-label="选择背景图片" :disabled="busy" @change="upload" />
      <img v-if="a.image" :src="a.image" alt="当前背景预览" class="bl-background-preview" />
      <button class="btn" @click="a.image = ''; applyAppearance(); save()">删除图片</button>
    </SettingRow>
    <SettingRow v-if="a.mode === 'url'" label="图片链接" layout="form" description="由浏览器直接加载 HTTP(S) 图片，不经过后端。">
      <input v-model="a.url" type="url" aria-label="背景图片链接" placeholder="https://…" @change="applyAppearance" />
    </SettingRow>
    <SettingRow v-if="a.mode === 'color'" label="纯色背景" layout="form">
      <label>浅色 <input v-model="a.lightColor" type="color" @input="applyAppearance" /></label>
      <label>深色 <input v-model="a.darkColor" type="color" @input="applyAppearance" /></label>
    </SettingRow>
    <SettingRow label="玻璃不透明度" layout="form" description="越低越透明，背景越清晰；0% 完全透明，100% 不透明。">
      <input v-model.number="a.opacity" type="range" min="0" max="1" step="0.01" aria-label="玻璃不透明度" @input="applyAppearance" /><output>{{ Math.round(a.opacity * 100) }}%</output>
    </SettingRow>
    <SettingRow label="磨砂模糊" layout="form">
      <input v-model.number="a.blur" type="range" min="0" max="40" step="1" aria-label="磨砂模糊" @input="applyAppearance" /><output>{{ a.blur }} px</output>
    </SettingRow>
    <SettingRow label="字体与强调色" layout="form">
      <label>字体 <input :value="a.text || '#1e252b'" type="color" @input="a.text = $event.target.value; applyAppearance()" /></label>
      <label>强调色 <input :value="a.accent || '#0f766e'" type="color" @input="a.accent = $event.target.value; applyAppearance()" /></label>
    </SettingRow>
    <SettingRow label="保存外观" layout="form" description="调整即时预览，点击保存后刷新页面仍然保留。">
      <button class="btn primary" :disabled="busy" @click="save">保存外观</button><button class="btn" :disabled="busy" @click="reset">恢复默认</button>
      <span role="status">{{ message }}</span>
    </SettingRow>
  </SettingSection>
</template>
