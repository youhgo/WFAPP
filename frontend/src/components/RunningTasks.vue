<template>
  <div class="tasks-wrapper">
    <div v-if="isLoading && tasks.length === 0" class="text-muted text-sm text-center py-4 flex-col d-flex align-center gap-2">
      <svg class="animate-spin h-6 w-6 text-primary" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
      </svg>
      Loading tasks...
    </div>

    <div v-else-if="tasks.length === 0" class="empty-state text-center py-6">
      <div class="empty-icon mb-2">📦</div>
      <h3 class="text-lg font-bold text-muted m-0">No active tasks</h3>
      <p class="text-sm text-muted mt-1">Submit a new analysis from the dashboard.</p>
    </div>

    <div v-else class="tasks-list d-flex flex-col gap-3">
      <div v-for="task in tasks" :key="task.id" class="task-card">
        <div class="task-header d-flex justify-between align-center">
          <div class="d-flex flex-col">
            <h4 class="task-title font-bold m-0" :title="task.archive_name">
              {{ truncate(task.archive_name, 35) }}
              <span class="text-xs font-normal text-muted ml-2">({{ formatName(task.name) }})</span>
            </h4>
            <p class="task-id text-xs text-muted m-0 mt-1 font-mono">{{ task.id }}</p>
          </div>
          <div class="d-flex align-center gap-2">
            <button @click="openLogModal(task.id)" class="btn btn-secondary btn-sm action-btn" title="View Live Logs">📄 Logs</button>
            <button @click="killTask(task.id)" class="btn btn-danger btn-sm action-btn" title="Delete Task">🗑️ Delete</button>
          </div>
        </div>
        
        <div class="task-status-row mt-3 d-flex align-center justify-between">
          <div class="status-badge" :class="getStatusClass(task.status)">
            STATUS: {{ task.status || 'UNKNOWN' }}
          </div>
        </div>

        <!-- Dynamic Progress Bar -->
        <div v-if="isActiveStatus(task.status)" class="progress-section mt-3">
          <div class="progress-container">
            <div 
              class="progress-bar" 
              :class="{'animate-pulse-fast': task.indeterminate, 'bg-success': task.progress === 100 && !task.indeterminate}"
              :style="{ width: (task.progress || 100) + '%' }"
            ></div>
          </div>
          <p class="progress-text text-xs text-muted mt-2 font-mono truncate" :title="task.progressText">
            {{ task.progressText || 'Initializing...' }}
          </p>
        </div>
      </div>
    </div>

    <!-- Log Viewer Modal -->
    <div v-if="isLogModalOpen" class="modal-overlay" @click.self="closeLogModal">
      <div class="modal-content glass-panel d-flex flex-col">
        <div class="modal-header d-flex justify-between align-center mb-3">
          <div class="d-flex align-center gap-4">
            <h3 class="text-lg font-bold m-0">Live Logs <span class="text-xs text-muted font-normal ml-2">{{ activeLogTaskId }}</span></h3>
            
            <div class="d-flex align-center gap-2">
              <label class="switch shrink-0" style="transform: scale(0.8);">
                <input type="checkbox" v-model="autoScrollEnabled" />
                <span class="slider"></span>
              </label>
              <span class="text-xs font-medium text-muted">Auto-scroll</span>
            </div>
          </div>
          <button @click="closeLogModal" class="close-btn text-muted hover:text-white">✕</button>
        </div>
        <div class="modal-body flex-1">
          <pre class="log-output custom-scrollbar" ref="logContainer">{{ currentLogContent || 'Loading logs...' }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, nextTick } from 'vue'

const tasks = ref([])
const isLoading = ref(true)
const logPollIntervals = ref({})
const currentLogContent = ref('')
const isLogModalOpen = ref(false)
const activeLogTaskId = ref(null)
const logContainer = ref(null)
const autoScrollEnabled = ref(true)

const formatName = (name) => {
  if (!name) return ''
  return name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
}

const fetchTasks = async () => {
  isLoading.value = true
  try {
    const response = await fetch('/api/get_running_tasks')
    const data = await response.json()
    
    if (response.ok && data.active && Object.keys(data.active).length > 0) {
      const allTasks = Object.values(data.active).flat()
      // Preserve existing progress data
      tasks.value = allTasks.map(newTask => {
        const existing = tasks.value.find(t => t.id === newTask.id)
        if (existing) {
          return { ...existing, status: newTask.status }
        }
        return {
          ...newTask,
          progress: 0,
          progressText: 'Initializing...',
          indeterminate: true
        }
      })
      setupPolling()
    } else {
      tasks.value = []
    }
  } catch (error) {
    console.error('Failed to fetch tasks', error)
  } finally {
    isLoading.value = false
  }
}

const setupPolling = () => {
  tasks.value.forEach(task => {
    if (isActiveStatus(task.status) && !logPollIntervals.value[task.id]) {
      logPollIntervals.value[task.id] = setInterval(() => pollTaskLog(task.id), 2000)
      pollTaskLog(task.id)
    }
  })

  // Cleanup completed tasks
  Object.keys(logPollIntervals.value).forEach(taskId => {
    const stillActive = tasks.value.find(t => t.id === taskId && isActiveStatus(t.status))
    if (!stillActive) {
      clearInterval(logPollIntervals.value[taskId])
      delete logPollIntervals.value[taskId]
    }
  })
}

const pollTaskLog = async (taskId) => {
  try {
    const response = await fetch(`/api/running_log/${taskId}`)
    if (!response.ok) return
    const logText = await response.text()
    
    // Update modal if open for this task
    if (isLogModalOpen.value && activeLogTaskId.value === taskId) {
      const allLines = (logText || '').split('\n')
      if (allLines.length > 1000) {
        currentLogContent.value = allLines.slice(-1000).join('\n')
      } else {
        currentLogContent.value = logText || 'Log is empty.'
      }
      
      if (autoScrollEnabled.value) {
        scrollToBottom()
      }
    }
    
    const lines = logText.trim().split('\n')
    const lastLine = lines[lines.length - 1]
    
    const taskIndex = tasks.value.findIndex(t => t.id === taskId)
    if (taskIndex === -1) return
    
    const task = tasks.value[taskIndex]
    let foundProgress = false
    
    // Extract granular progress from log lines
    for (let i = lines.length - 1; i >= Math.max(0, lines.length - 15); i--) {
      const line = lines[i]
      const matchXY = line.match(/(\d+)\s*\/\s*(\d+)/)
      const matchPct = line.match(/(\d+)%/)
      
      if (matchXY && parseInt(matchXY[2]) > 0) {
        const percent = Math.min(100, Math.round((parseInt(matchXY[1]) / parseInt(matchXY[2])) * 100))
        task.progress = percent
        task.indeterminate = false
        const cleanMsg = line.replace(/(\d+)\s*\/\s*(\d+)/, '').trim()
        task.progressText = `Progress: ${matchXY[1]}/${matchXY[2]} (${percent}%) - ${cleanMsg}`
        foundProgress = true
        break
      } else if (matchPct) {
        task.progress = parseInt(matchPct[1])
        task.indeterminate = false
        const cleanMsg = line.replace(/(\d+)%/, '').trim()
        task.progressText = `Progress: ${matchPct[1]}% - ${cleanMsg}`
        foundProgress = true
        break
      }
    }
    
    if (!foundProgress && lastLine) {
      task.progress = 100
      task.indeterminate = true
      let cleanLog = lastLine.replace(/^\[.*?\]\s*/, '')
      task.progressText = `Activity: ${cleanLog}`
    }
  } catch (e) {
    console.error("Log poll error", e)
  }
}

const killTask = async (taskId) => {
  if (!confirm(`Are you sure you want to delete task ${taskId}?`)) return
  
  try {
    await fetch(`/api/stop_task/${taskId}`, { method: 'POST' })
    fetchTasks()
  } catch (error) {
    console.error('Failed to kill task', error)
  }
}

const openLogModal = async (taskId) => {
  activeLogTaskId.value = taskId
  currentLogContent.value = 'Fetching logs...'
  isLogModalOpen.value = true
  
  // Try to fetch immediately if we aren't already polling it this second
  try {
    const response = await fetch(`/api/running_log/${taskId}`)
    if (response.ok) {
      const logText = await response.text()
      const allLines = (logText || '').split('\n')
      if (allLines.length > 1000) {
        currentLogContent.value = allLines.slice(-1000).join('\n')
      } else {
        currentLogContent.value = logText
      }
      if (autoScrollEnabled.value) {
        scrollToBottom()
      }
    }
  } catch (e) {
    currentLogContent.value = 'Failed to load logs.'
  }
}

const closeLogModal = () => {
  isLogModalOpen.value = false
  activeLogTaskId.value = null
  currentLogContent.value = ''
}

const scrollToBottom = async () => {
  await nextTick()
  if (logContainer.value) {
    logContainer.value.scrollTop = logContainer.value.scrollHeight
  }
}

const truncate = (str, len) => {
  if (!str) return ''
  return str.length > len ? str.substring(0, len) + '...' : str
}

const isActiveStatus = (status) => {
  return ['STARTED', 'ACTIVE', 'PENDING'].includes(status)
}

const getStatusClass = (status) => {
  if (status === 'SUCCESS') return 'status-success'
  if (status === 'FAILURE') return 'status-error'
  if (isActiveStatus(status)) return 'status-active'
  return 'status-unknown'
}

onMounted(() => {
  fetchTasks()
})

onUnmounted(() => {
  Object.values(logPollIntervals.value).forEach(clearInterval)
})

defineExpose({
  fetchTasks
})
</script>

<style scoped>
.tasks-wrapper {
  /* Inherits from Dashboard container */
}

.empty-state {
  border: 1px dashed rgba(51, 65, 85, 0.5);
  border-radius: 0.75rem;
  background: rgba(30, 41, 59, 0.2);
}

.empty-icon {
  font-size: 2.5rem;
  opacity: 0.5;
}

.task-card {
  background: rgba(30, 41, 59, 0.6);
  border: 1px solid rgba(51, 65, 85, 0.6);
  border-radius: 0.75rem;
  padding: 1.25rem;
  transition: all 0.2s;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
}

.task-card:hover {
  background: rgba(30, 41, 59, 0.8);
  border-color: rgba(99, 102, 241, 0.4);
}

.action-btn {
  border-radius: 0.5rem;
  padding: 0.35rem 0.75rem;
  font-weight: 600;
  font-size: 0.8rem;
}

.status-badge {
  display: inline-block;
  font-size: 0.7rem;
  font-weight: 700;
  padding: 0.25rem 0.6rem;
  border-radius: 0.375rem;
  letter-spacing: 0.05em;
}

.status-active { color: #818cf8; background: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.3); }
.status-success { color: #10b981; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); }
.status-error { color: #ef4444; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); }
.status-unknown { color: #94a3b8; background: rgba(148, 163, 184, 0.15); border: 1px solid rgba(148, 163, 184, 0.3); }

.progress-section {
  width: 100%;
}

.progress-container {
  width: 100%;
  background-color: rgba(15, 23, 42, 0.5);
  border-radius: 9999px;
  height: 4px;
  overflow: hidden;
  border: 1px solid rgba(255, 255, 255, 0.05);
}

.progress-bar {
  height: 100%;
  background-color: #818cf8;
  transition: width 0.3s ease;
}
.bg-success {
  background-color: #10b981 !important;
}

.animate-pulse-fast {
  animation: pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite;
  background-color: #6366f1;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.6; }
}

.animate-spin {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(2, 6, 23, 0.8);
  backdrop-filter: blur(4px);
  z-index: 100;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 2rem;
}

.modal-content {
  width: 100%;
  max-width: 900px;
  height: 80vh;
  border-radius: 1rem;
  background: rgba(15, 23, 42, 0.95);
  border: 1px solid rgba(51, 65, 85, 0.5);
  padding: 1.5rem;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
}

.close-btn {
  background: none;
  border: none;
  font-size: 1.25rem;
  cursor: pointer;
  padding: 0.25rem;
  transition: color 0.2s;
}

.log-output {
  background: #020617;
  color: #34d399; /* Terminal green */
  padding: 1rem;
  border-radius: 0.5rem;
  height: 100%;
  overflow-y: auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.85rem;
  white-space: pre-wrap;
  word-wrap: break-word;
  line-height: 1.4;
  border: 1px solid rgba(255,255,255,0.05);
}

.custom-scrollbar::-webkit-scrollbar {
  width: 8px;
}
.custom-scrollbar::-webkit-scrollbar-track {
  background: rgba(15, 23, 42, 0.5);
  border-radius: 4px;
}
.custom-scrollbar::-webkit-scrollbar-thumb {
  background: rgba(51, 65, 85, 0.8);
  border-radius: 4px;
}
.custom-scrollbar::-webkit-scrollbar-thumb:hover {
  background: rgba(71, 85, 105, 1);
}

/* Switch (Slider) */
.switch {
  position: relative;
  display: inline-block;
  width: 44px;
  height: 24px;
}
.switch input { 
  opacity: 0;
  width: 0;
  height: 0;
}
.slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(51, 65, 85, 0.8);
  transition: .3s;
  border-radius: 24px;
  border: 1px solid rgba(255, 255, 255, 0.05);
}
.slider:before {
  position: absolute;
  content: "";
  height: 18px;
  width: 18px;
  left: 3px;
  bottom: 2px;
  background-color: #94a3b8;
  transition: .3s;
  border-radius: 50%;
  box-shadow: 0 2px 4px rgba(0,0,0,0.2);
}
input:checked + .slider {
  background-color: rgba(16, 185, 129, 0.2);
  border-color: rgba(16, 185, 129, 0.4);
}
input:checked + .slider:before {
  transform: translateX(20px);
  background-color: #10b981;
}
</style>
