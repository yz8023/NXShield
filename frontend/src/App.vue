<script setup>
import { ref, computed, onMounted } from 'vue'
import HomePage from './pages/HomePage.vue'
import FeaturesPage from './pages/FeaturesPage.vue'
import LogsPage from './pages/LogsPage.vue'
import SettingsPage from './pages/SettingsPage.vue'
import { api } from './api'

const tabs = [
  { key: 'home', label: '主页', icon: '🏠', comp: HomePage },
  { key: 'features', label: '功能', icon: '🧩', comp: FeaturesPage },
  { key: 'logs', label: '日志', icon: '📜', comp: LogsPage },
  { key: 'settings', label: '设置', icon: '⚙️', comp: SettingsPage }
]

const active = ref('home')
const dark = ref(false)
const toast = ref('')
const health = ref(null)
const featureTotal = ref(0)

const currentComp = computed(() => tabs.find((t) => t.key === active.value).comp)

function showToast(msg) {
  toast.value = msg
  setTimeout(() => (toast.value = ''), 2200)
}

function toggleTheme() {
  dark.value = !dark.value
  document.documentElement.classList.toggle('dark', dark.value)
}

onMounted(async () => {
  try {
    health.value = await api.health()
  } catch (err) {
    health.value = { ok: false }
  }
  try {
    const f = await api.features()
    featureTotal.value = Object.keys(f.defaults || {}).length
  } catch (err) {
    featureTotal.value = 0
  }
})

defineExpose({ showToast })
</script>

<template>
  <div class="app-shell">
    <header class="top-bar">
      <div>
        <h1>NXShield</h1>
        <div class="subtitle">APK 加固控制台 · 全部功能自研</div>
      </div>
      <div class="row">
        <span class="badge" :class="health && health.ok ? 'success' : 'failed'">
          {{ health && health.ok ? '引擎在线' : '引擎离线' }}
        </span>
        <button class="icon-btn" @click="toggleTheme" :title="dark ? '浅色' : '深色'">
          {{ dark ? '☀' : '☾' }}
        </button>
      </div>
    </header>

    <main class="content">
      <component :is="currentComp" @toast="showToast" :health="health" />
    </main>

    <nav class="nav-bar">
      <button
        v-for="t in tabs"
        :key="t.key"
        class="nav-item"
        :class="{ active: active === t.key }"
        @click="active = t.key"
      >
        <span class="pill">{{ t.icon }}</span>
        <span>{{ t.label }}</span>
      </button>
    </nav>

    <div v-if="toast" class="toast">{{ toast }}</div>
  </div>
</template>
