<script setup>
import { ref, onMounted } from 'vue'
import { api } from '../api'

const emit = defineEmits(['toast'])
const props = defineProps({ health: Object })

const settings = ref({
  password: 'nxshield',
  extract_ratio: 0.45,
  encrypt_cjk: true,
  encrypt_vip_keywords: true,
  asset_encrypt: true,
  keep_signature: false,
  name_obfuscate: false
})

async function load() {
  const res = await api.settings().catch(() => null)
  if (res && res.settings) settings.value = { ...settings.value, ...res.settings }
}

async function save() {
  await api.saveSettings(settings.value)
  emit('toast', '设置已保存')
}

onMounted(load)
</script>

<template>
  <section>
    <div class="card">
      <h2>引擎状态</h2>
      <div class="stat-grid">
        <div class="stat"><div class="k">后端服务</div><div class="v">{{ health && health.ok ? '在线' : '离线' }}</div></div>
        <div class="stat"><div class="k">引擎版本</div><div class="v">{{ (health && health.version) || '-' }}</div></div>
        <div class="stat"><div class="k">加固内核</div><div class="v">NXShield 1.0</div></div>
      </div>
    </div>

    <div class="card">
      <h2>默认加固策略</h2>
      <div class="field">
        <label>默认加密口令</label>
        <input type="password" v-model="settings.password" />
      </div>
      <div class="field">
        <label>默认抽取比例 ({{ Math.round((settings.extract_ratio || 0) * 100) }}%)</label>
        <input type="range" min="0" max="1" step="0.05" v-model.number="settings.extract_ratio" style="width: 100%" />
      </div>

      <div class="feature-item">
        <div>
          <div class="title">中文字符串加密</div>
          <div class="desc">默认开启，覆盖所有 CJK 字面量。</div>
        </div>
        <label class="switch">
          <input type="checkbox" v-model="settings.encrypt_cjk" />
          <span class="slider"></span>
        </label>
      </div>
      <div class="feature-item">
        <div>
          <div class="title">VIP / Premium 关键词</div>
          <div class="desc">默认开启。</div>
        </div>
        <label class="switch">
          <input type="checkbox" v-model="settings.encrypt_vip_keywords" />
          <span class="slider"></span>
        </label>
      </div>
      <div class="feature-item">
        <div>
          <div class="title">assets/ 加密</div>
          <div class="desc">默认开启。</div>
        </div>
        <label class="switch">
          <input type="checkbox" v-model="settings.asset_encrypt" />
          <span class="slider"></span>
        </label>
      </div>
      <div class="feature-item">
        <div>
          <div class="title">保留原始签名</div>
          <div class="desc">关闭时移除旧签名，需自行重新签名。</div>
        </div>
        <label class="switch">
          <input type="checkbox" v-model="settings.keep_signature" />
          <span class="slider"></span>
        </label>
      </div>
      <div class="feature-item">
        <div>
          <div class="title">标识符重命名</div>
          <div class="desc">实验性，可能影响部分反射调用。</div>
        </div>
        <label class="switch">
          <input type="checkbox" v-model="settings.name_obfuscate" />
          <span class="slider"></span>
        </label>
      </div>

      <div class="row" style="justify-content: flex-end; margin-top: 14px">
        <button class="btn" @click="save">保存设置</button>
      </div>
    </div>

    <div class="card">
      <h2>关于</h2>
      <p class="hint">
        NXShield 为自研 APK 加固引擎，包含 DEX 解析、方法抽取、NX-VM 字节码翻译、字符串与资源加密模块。
        本工具仅用于加固你拥有合法授权的应用。
      </p>
    </div>
  </section>
</template>
