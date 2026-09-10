<script setup>
import { ref, computed, onMounted } from 'vue'
import { api, subscribeJob } from '../api'

const emit = defineEmits(['toast'])

const file = ref(null)
const uploadId = ref('')
const uploadPct = ref(0)
const uploaded = ref(null)
const dragging = ref(false)

const options = ref({
  extract_methods: true,
  vm_protect: true,
  string_protect: true,
  encrypt_cjk: true,
  encrypt_vip_keywords: true,
  asset_encrypt: true,
  name_obfuscate: false,
  keep_signature: false,
  inject_stub_meta: true,
  extract_ratio: 0.45,
  extra_keywords: '',
  password: 'nxshield'
})

const running = ref(false)
const progress = ref(0)
const stage = ref('')
const logs = ref([])
const jobId = ref('')
const summary = ref(null)
const error = ref('')
const recent = ref([])

const statusText = computed(() => {
  if (error.value) return '失败'
  if (running.value) return `${progress.value}% · ${stage.value}`
  if (summary.value) return '加固完成'
  return '待命'
})

function pickFile(f) {
  if (!f) return
  if (!/\.(apk|zip)$/i.test(f.name)) {
    emit('toast', '请选择 .apk 文件')
    return
  }
  file.value = f
  uploaded.value = null
  uploadId.value = ''
}

function onDrop(e) {
  dragging.value = false
  const f = e.dataTransfer.files && e.dataTransfer.files[0]
  pickFile(f)
}

function onInput(e) {
  pickFile(e.target.files[0])
}

async function doUpload() {
  if (!file.value) return
  try {
    const res = await api.upload(file.value, (p) => (uploadPct.value = p))
    uploaded.value = res
    uploadId.value = res.upload_id
    emit('toast', `已上传 ${res.filename}`)
  } catch (err) {
    emit('toast', '上传失败: ' + err.message)
  }
}

function addLog(rec) {
  logs.value.push(rec)
  if (logs.value.length > 600) logs.value.splice(0, logs.value.length - 600)
}

async function startPack() {
  if (!uploadId.value) {
    emit('toast', '请先上传 APK')
    return
  }
  running.value = true
  progress.value = 0
  stage.value = '提交任务'
  logs.value = []
  summary.value = null
  error.value = ''
  try {
    const res = await api.pack(uploadId.value, options.value)
    jobId.value = res.job_id
    subscribeJob(
      res.job_id,
      (rec) => {
        addLog(rec)
        if (rec.extra && typeof rec.extra.elapsed_ms === 'number') {
          progress.value = Math.max(progress.value, 99)
        }
      },
      async (status) => {
        running.value = false
        progress.value = 100
        const job = await api.job(res.job_id).catch(() => null)
        if (job && job.summary) {
          summary.value = job.summary
          stage.value = '完成'
        }
        if (status === 'failed') {
          error.value = (job && job.error) || '加固失败'
          stage.value = '失败'
        }
        loadRecent()
      }
    )
  } catch (err) {
    running.value = false
    error.value = err.message
    emit('toast', '任务提交失败: ' + err.message)
  }
}

async function loadRecent() {
  const res = await api.jobs().catch(() => ({ items: [] }))
  recent.value = (res.items || []).slice(0, 5)
}

function humanSize(n) {
  if (!n && n !== 0) return '-'
  if (n < 1024) return n + ' B'
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB'
  return (n / 1024 / 1024).toFixed(2) + ' MB'
}

onMounted(async () => {
  const s = await api.settings().catch(() => null)
  if (s && s.settings) Object.assign(options.value, s.settings)
  loadRecent()
})
</script>

<template>
  <section>
    <div class="card">
      <h2>开始加固</h2>
      <p class="hint">上传 APK，引擎将执行抽函数、NX-VM、字符串与 assets 保护，全程记录日志。</p>

      <div
        class="drop-zone"
        :class="{ dragover: dragging }"
        @dragover.prevent="dragging = true"
        @dragleave="dragging = false"
        @drop.prevent="onDrop"
        @click="$refs.picker.click()"
      >
        <div class="big">📦</div>
        <div v-if="file">
          <strong>{{ file.name }}</strong>
          <div class="hint">{{ humanSize(file.size) }}</div>
        </div>
        <div v-else>点击或拖拽 APK 到此处</div>
        <input ref="picker" type="file" accept=".apk,.zip" hidden @change="onInput" />
      </div>

      <div class="row between" style="margin-top: 12px">
        <span v-if="uploaded" class="badge success">已上传 · {{ humanSize(uploaded.size) }}</span>
        <span v-else-if="uploadPct" class="badge">上传 {{ uploadPct }}%</span>
        <span v-else></span>
        <div class="row">
          <button class="btn tonal small" :disabled="!file || !!uploaded" @click="doUpload">
            上传
          </button>
          <button class="btn" :disabled="!uploadId || running" @click="startPack">
            {{ running ? '加固中…' : '开始加固' }}
          </button>
        </div>
      </div>

      <div v-if="running || progress" class="progress-track" style="margin-top: 14px">
        <div class="progress-fill" :style="{ width: progress + '%' }"></div>
      </div>
      <div class="row between" style="margin-top: 6px">
        <small class="hint">{{ statusText }}</small>
        <a
          v-if="summary && jobId"
          class="btn small"
          :href="api.downloadUrl(jobId)"
          style="text-decoration: none"
        >下载加固包</a>
      </div>
      <p v-if="error" class="hint" style="color: var(--md-error); margin-top: 8px">{{ error }}</p>
    </div>

    <div class="card">
      <h2>保护能力</h2>
      <div class="stat-grid">
        <div class="stat"><div class="k">方法抽取混淆</div><div class="v">{{ options.extract_methods ? '开' : '关' }}</div></div>
        <div class="stat"><div class="k">NX-VM 虚拟化</div><div class="v">{{ options.vm_protect ? '开' : '关' }}</div></div>
        <div class="stat"><div class="k">敏感字符串</div><div class="v">{{ options.string_protect ? '开' : '关' }}</div></div>
        <div class="stat"><div class="k">assets 加密</div><div class="v">{{ options.asset_encrypt ? '开' : '关' }}</div></div>
      </div>
      <p class="hint" style="margin-top: 12px">
        中文字符串与 vip / premium / pro 等关键词默认纳入加密。详细配置见「功能」页。
      </p>
    </div>

    <div class="card" v-if="logs.length">
      <h2>实时日志</h2>
      <div class="log-view">
        <div v-for="(l, i) in logs" :key="i" class="log-line" :class="l.level">
          [{{ (l.ts || '').slice(11, 19) }}] [{{ l.level }}] {{ l.message }}
        </div>
      </div>
    </div>

    <div class="card" v-if="summary">
      <h2>加固报告</h2>
      <div class="stat-grid">
        <div class="stat"><div class="k">抽取方法</div><div class="v">{{ summary.methods_extracted }}</div></div>
        <div class="stat"><div class="k">VM 函数</div><div class="v">{{ summary.vm_functions }}</div></div>
        <div class="stat"><div class="k">加密字符串</div><div class="v">{{ summary.strings }}</div></div>
        <div class="stat"><div class="k">加密 assets</div><div class="v">{{ summary.assets_encrypted }}</div></div>
        <div class="stat"><div class="k">耗时</div><div class="v">{{ summary.elapsed_ms }} ms</div></div>
        <div class="stat"><div class="k">输出大小</div><div class="v">{{ humanSize(summary.output_size) }}</div></div>
      </div>
      <p class="hint" style="margin-top: 10px; word-break: break-all">
        包名: {{ summary.package || '(未知)' }} · SHA256: {{ (summary.output_sha256 || '').slice(0, 32) }}…
      </p>
    </div>

    <div class="card" v-if="recent.length">
      <h2>最近任务</h2>
      <div v-for="j in recent" :key="j.id" class="job-item">
        <div class="row between">
          <strong style="font-size: 13px">{{ j.input }}</strong>
          <span class="badge" :class="j.status">{{ j.status }}</span>
        </div>
        <small class="hint">{{ j.created_at?.slice(0, 19).replace('T', ' ') }} · {{ j.stage }}</small>
      </div>
    </div>
  </section>
</template>
