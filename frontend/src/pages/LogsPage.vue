<script setup>
import { ref, onMounted } from 'vue'
import { api, subscribeJob } from '../api'

const emit = defineEmits(['toast'])

const jobs = ref([])
const activeJob = ref('')
const logLines = ref([])
const filterLevel = ref('ALL')
const tab = ref('jobs')
const toggleHistory = ref([])
let stopStream = null

async function loadJobs() {
  const res = await api.jobs().catch(() => ({ items: [] }))
  jobs.value = res.items || []
}

async function openJob(id) {
  activeJob.value = id
  if (stopStream) stopStream()
  const res = await api.jobLog(id, 1000).catch(() => ({ lines: [] }))
  logLines.value = res.lines || []
  const job = await api.job(id).catch(() => null)
  if (job && job.status === 'running') {
    stopStream = subscribeJob(
      id,
      (rec) => {
        logLines.value.push(`[${(rec.ts || '').slice(11, 19)}] [${rec.level}] ${rec.message}`)
      },
      (status) => {
        loadJobs()
      }
    )
  }
}

function levelOf(line) {
  const m = line.match(/\[(DEBUG|INFO|WARN|ERROR)\]/)
  return m ? m[1] : 'INFO'
}

const visible = () =>
  filterLevel.value === 'ALL'
    ? logLines.value
    : logLines.value.filter((l) => levelOf(l) === filterLevel.value)

async function save() {
  const blob = new Blob([logLines.value.join('\n')], { type: 'text/plain' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `${activeJob.value || 'nxshield'}.log`
  a.click()
  URL.revokeObjectURL(a.href)
}

async function loadToggles() {
  const res = await api.toggles().catch(() => ({ items: [] }))
  toggleHistory.value = res.items || []
}

function statusClass(s) {
  return s === 'success' ? 'success' : s === 'failed' ? 'failed' : 'running'
}

onMounted(async () => {
  await loadJobs()
  await loadToggles()
  if (jobs.value.length) openJob(jobs.value[0].id)
})
</script>

<template>
  <section>
    <div class="tabs">
      <button class="tab" :class="{ active: tab === 'jobs' }" @click="tab = 'jobs'">加固日志</button>
      <button class="tab" :class="{ active: tab === 'toggles' }" @click="tab = 'toggles'">启用记录</button>
      <button class="tab" :class="{ active: tab === 'files' }" @click="tab = 'files'">历史日志</button>
    </div>

    <template v-if="tab === 'jobs'">
      <div class="card">
        <h2>任务列表</h2>
        <div v-if="!jobs.length" class="empty">暂无任务</div>
        <div
          v-for="j in jobs"
          :key="j.id"
          class="job-item"
          :class="{ active: activeJob === j.id }"
          @click="openJob(j.id)"
        >
          <div class="row between">
            <strong style="font-size: 13px">{{ j.input }}</strong>
            <span class="badge" :class="statusClass(j.status)">{{ j.status }}</span>
          </div>
          <small class="hint">{{ j.created_at?.slice(0, 19).replace('T', ' ') }} · {{ j.stage }}</small>
        </div>
      </div>

      <div class="card" v-if="activeJob">
        <div class="row between">
          <h2 style="margin: 0">运行日志</h2>
          <div class="row">
            <select v-model="filterLevel" style="width: auto">
              <option>ALL</option>
              <option>DEBUG</option>
              <option>INFO</option>
              <option>WARN</option>
              <option>ERROR</option>
            </select>
            <button class="btn small tonal" @click="save">保存</button>
            <a class="btn small" :href="api.downloadUrl(activeJob)" style="text-decoration: none">下载 APK</a>
          </div>
        </div>
        <div class="log-view" style="margin-top: 10px">
          <div v-for="(l, i) in visible()" :key="i" class="log-line" :class="levelOf(l)">
            {{ l }}
          </div>
          <div v-if="!logLines.length" class="empty">暂无日志内容</div>
        </div>
      </div>
    </template>

    <template v-else-if="tab === 'toggles'">
      <div class="card">
        <h2>功能启用 / 关闭记录</h2>
        <div v-if="!toggleHistory.length" class="empty">暂无记录</div>
        <div v-for="(t, i) in toggleHistory" :key="i" class="row between" style="padding: 8px 0; border-bottom: 1px solid var(--md-outline-variant)">
          <div>
            <div style="font-size: 13px">{{ t.feature }}</div>
            <small class="hint">{{ t.ts.slice(0, 19).replace('T', ' ') }} · {{ t.source }}</small>
          </div>
          <span class="badge" :class="t.enabled ? 'success' : 'failed'">
            {{ t.enabled ? '启用' : '关闭' }}
          </span>
        </div>
      </div>
    </template>

    <template v-else>
      <div class="card">
        <h2>历史日志文件</h2>
        <div v-if="!jobs.length" class="empty">暂无日志</div>
        <div v-for="j in jobs" :key="j.id" class="job-item" @click="openJob(j.id); tab = 'jobs'">
          <div class="row between">
            <strong style="font-size: 13px">{{ j.id }}.log</strong>
            <span class="badge">{{ ((j.summary && j.summary.elapsed_ms) || 0) }} ms</span>
          </div>
          <small class="hint">{{ (j.updated_at || j.created_at || '').slice(0, 19).replace('T', ' ') }}</small>
        </div>
      </div>
    </template>
  </section>
</template>
