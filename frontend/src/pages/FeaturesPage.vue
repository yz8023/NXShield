<script setup>
import { ref, computed, onMounted } from 'vue'
import { api } from '../api'

const emit = defineEmits(['toast'])

const featureDefs = [
  {
    key: 'extract_methods',
    title: '方法抽取混淆',
    desc: '将选中方法体抽离为 VM 调用桩，混淆调用关系，按比例抽取。'
  },
  {
    key: 'vm_protect',
    title: 'NX-VM 虚拟化',
    desc: '自研字节码翻译器将 Dalvik 指令转成 NX 指令集，加密后由运行时解释执行。'
  },
  {
    key: 'string_protect',
    title: '敏感字符串保护',
    desc: '识别并加密中文字符串与敏感英文关键词，运行时按索引解密还原。'
  },
  {
    key: 'encrypt_cjk',
    title: '中文字符串加密',
    desc: '将所有含中文字符的字符串常量纳入加密范围。'
  },
  {
    key: 'encrypt_vip_keywords',
    title: 'VIP / Premium 关键词',
    desc: '内置词表：vip、premium、pro、license、trial、unlock、paywall 等。'
  },
  {
    key: 'asset_encrypt',
    title: 'assets/ 加密',
    desc: '加密 assets/ 下资源为 .nxs，运行时解密到私有目录。'
  },
  {
    key: 'name_obfuscate',
    title: '标识符重命名',
    desc: '使用种子哈希重写字符串池中的标识符，降低可读性。'
  },
  {
    key: 'keep_signature',
    title: '保留原始签名',
    desc: '关闭后移除 META-INF 下原签名文件，需重新签名才能安装。'
  },
  {
    key: 'inject_stub_meta',
    title: '写入加固元数据',
    desc: '生成 assets/nxshield/meta.json，记录本次加固特征与统计。'
  }
]

const state = ref({})
const query = ref('')
const ratio = ref(0.45)
const extraKeywords = ref('')
const password = ref('nxshield')
const toggles = ref([])

const filtered = computed(() =>
  featureDefs.filter(
    (f) =>
      !query.value ||
      f.title.includes(query.value) ||
      f.desc.toLowerCase().includes(query.value.toLowerCase())
  )
)

const enabledCount = computed(() => featureDefs.filter((f) => state.value[f.key]).length)

async function toggle(def, val) {
  state.value[def.key] = val
  await api.addToggle(def.key, val).catch(() => {})
  emit('toast', `${def.title} 已${val ? '启用' : '关闭'}`)
  loadToggles()
}

async function loadToggles() {
  const res = await api.toggles().catch(() => ({ items: [] }))
  toggles.value = (res.items || []).slice(0, 12)
}

async function persist() {
  await api.saveSettings({
    ...state.value,
    extract_ratio: Number(ratio.value),
    extra_keywords: extraKeywords.value,
    password: password.value
  })
  emit('toast', '功能配置已保存')
}

onMounted(async () => {
  const res = await api.features().catch(() => null)
  if (res && res.defaults) state.value = { ...res.defaults }
  const s = await api.settings().catch(() => null)
  if (s && s.settings) {
    Object.assign(state.value, s.settings)
    ratio.value = s.settings.extract_ratio ?? 0.45
    extraKeywords.value = s.settings.extra_keywords || ''
    password.value = s.settings.password || 'nxshield'
  }
  loadToggles()
})
</script>

<template>
  <section>
    <div class="card">
      <div class="row between">
        <div>
          <h2 style="margin: 0">功能配置</h2>
          <small class="hint">{{ enabledCount }} / {{ featureDefs.length }} 已启用</small>
        </div>
        <button class="btn small" @click="persist">保存</button>
      </div>
      <input type="text" v-model="query" placeholder="搜索功能…" style="margin-top: 12px" />
    </div>

    <div class="card">
      <div class="feature-item" v-for="f in filtered" :key="f.key">
        <div style="padding-right: 12px">
          <div class="title">{{ f.title }}</div>
          <div class="desc">{{ f.desc }}</div>
        </div>
        <label class="switch">
          <input type="checkbox" :checked="!!state[f.key]" @change="toggle(f, $event.target.checked)" />
          <span class="slider"></span>
        </label>
      </div>
    </div>

    <div class="card">
      <h2>参数</h2>
      <div class="field">
        <label>方法抽取比例 ({{ Math.round(ratio * 100) }}%)</label>
        <input type="range" min="0" max="1" step="0.05" v-model.number="ratio" style="width: 100%" />
      </div>
      <div class="field">
        <label>自定义敏感关键词（逗号或换行分隔）</label>
        <textarea rows="3" v-model="extraKeywords" placeholder="例如：内部接口, secret_flag, enterprise"></textarea>
      </div>
      <div class="field">
        <label>加密口令</label>
        <input type="password" v-model="password" />
      </div>
    </div>

    <div class="card" v-if="toggles.length">
      <h2>启用历史</h2>
      <div v-for="(t, i) in toggles" :key="i" class="row between" style="padding: 6px 0">
        <span style="font-size: 13px">{{ t.feature }}</span>
        <span>
          <span class="badge" :class="t.enabled ? 'success' : 'failed'">
            {{ t.enabled ? '启用' : '关闭' }}
          </span>
          <small class="hint" style="margin-left: 8px">{{ t.ts.slice(0, 19).replace('T', ' ') }}</small>
        </span>
      </div>
    </div>
  </section>
</template>
