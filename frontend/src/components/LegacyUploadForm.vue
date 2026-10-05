<template>
  <div class="upload-form-container glass-panel p-4">
    <h2 class="mb-4 text-2xl font-bold">New Analysis (Legacy Mode)</h2>
    
    <form @submit.prevent="handleUpload" class="d-flex flex-col gap-4">
      
      <!-- Archive Info -->
      <div class="form-row">
        <div class="form-group flex-1">
          <label class="text-sm font-bold text-muted uppercase tracking-wider">Case Name</label>
          <input v-model="caseName" type="text" class="input-field mt-1 w-full rounded-lg" required placeholder="e.g. INC-2023-1244" />
        </div>
        
        <div class="form-group flex-1">
          <label class="text-sm font-bold text-muted uppercase tracking-wider">Machine Name</label>
          <input v-model="machineName" type="text" class="input-field mt-1 w-full rounded-lg" required placeholder="e.g. DESKTOP-XYZ" />
        </div>

        <div class="form-group flex-1">
          <label class="text-sm font-bold text-muted uppercase tracking-wider">Archive Type</label>
          <select v-model="archiveType" class="input-field mt-1 w-full rounded-lg" @change="onArchiveTypeChange">
            <option value="Windows">Windows</option>
            <option value="Linux">Linux</option>
            <option value="Mac">MacOS</option>
          </select>
        </div>

        
      </div>

      <div class="form-row" v-if="false">
        <div class="form-group flex-1">
          <label class="text-sm font-bold text-muted uppercase tracking-wider">Ogre Mode</label>
          <select v-model="ogreMode" class="input-field mt-1 w-full rounded-lg">
            <option value="orc">ORC (Full Parsing)</option>
            <option value="timeline">Timeline (CSV)</option>
          </select>
        </div>
      </div>

      <!-- Module Configuration Grid -->
      <div class="module-config-section mt-4">
        <div class="d-flex align-center justify-between mb-4">
          <h3 class="text-sm font-bold text-muted uppercase tracking-wider m-0">Modules to analyze</h3>
        </div>
        
        <div class="module-grid">
          <!-- Pre-processing -->
          <div class="module-card">
            <div class="module-card-header">
              <h4 class="module-category-title">1. Pre-processing</h4>
              <div class="module-actions">
                <button type="button" @click="selectAll('preprocessor')" title="Select All" class="action-btn text-primary">✓</button>
                <button type="button" @click="deselectAll('preprocessor')" title="Deselect All" class="action-btn text-danger">✕</button>
              </div>
            </div>
            <div class="module-list custom-scrollbar">
              <template v-for="mod in modulesByCategory.preprocessor" :key="mod.name">
                <div v-show="isModuleVisible(mod.name)" class="module-item" :class="{ 'disabled-item': isModuleDisabled(mod.name) }">
                  <label :for="'mod-' + mod.name" class="truncate flex-1 m-0 text-sm font-medium cursor-pointer" :title="mod.name">{{ formatName(mod.name) }}</label>
                  <label class="switch shrink-0">
                    <input type="checkbox" :id="'mod-' + mod.name" v-model="selectedModules[mod.name]" :disabled="isModuleDisabled(mod.name)" />
                    <span class="slider"></span>
                  </label>
                </div>
              </template>
            </div>
          </div>

          <!-- Parsing -->
          <div class="module-card">
            <div class="module-card-header">
              <h4 class="module-category-title">2. Parsing</h4>
              <div class="module-actions">
                <button type="button" @click="selectAll('pipeline')" title="Select All" class="action-btn text-primary">✓</button>
                <button type="button" @click="deselectAll('pipeline')" title="Deselect All" class="action-btn text-danger">✕</button>
              </div>
            </div>
            <div class="module-list custom-scrollbar">
              <template v-for="mod in modulesByCategory.pipeline" :key="mod.name">
                <div v-show="isModuleVisible(mod.name)" class="module-item" :class="{ 'disabled-item': isModuleDisabled(mod.name) }">
                  <label :for="'mod-' + mod.name" class="truncate flex-1 m-0 text-sm font-medium cursor-pointer" :title="mod.name">{{ formatName(mod.name) }}</label>
                  <label class="switch shrink-0">
                    <input type="checkbox" :id="'mod-' + mod.name" v-model="selectedModules[mod.name]" :disabled="isModuleDisabled(mod.name)" />
                    <span class="slider"></span>
                  </label>
                </div>
              </template>
            </div>
          </div>

          <!-- Standalone -->
          <div class="module-card">
            <div class="module-card-header">
              <h4 class="module-category-title">Non-Ogre Parsers</h4>
              <div class="module-actions">
                <button type="button" @click="selectAll('standalone')" title="Select All" class="action-btn text-primary">✓</button>
                <button type="button" @click="deselectAll('standalone')" title="Deselect All" class="action-btn text-danger">✕</button>
              </div>
            </div>
            <div class="module-list custom-scrollbar">
              <template v-for="mod in modulesByCategory.standalone" :key="mod.name">
                <div v-show="isModuleVisible(mod.name)" class="module-item" :class="{ 'disabled-item': isModuleDisabled(mod.name) }">
                  <label :for="'mod-' + mod.name" class="truncate flex-1 m-0 text-sm font-medium cursor-pointer" :title="mod.name">{{ formatName(mod.name) }}</label>
                  <label class="switch shrink-0">
                    <input type="checkbox" :id="'mod-' + mod.name" v-model="selectedModules[mod.name]" :disabled="isModuleDisabled(mod.name)" />
                    <span class="slider"></span>
                  </label>
                </div>
              </template>
            </div>
          </div>

          <!-- Post-processing -->
          <div class="module-card">
            <div class="module-card-header">
              <h4 class="module-category-title">3. Post-processing</h4>
              <div class="module-actions">
                <button type="button" @click="selectAll('postprocessor')" title="Select All" class="action-btn text-primary">✓</button>
                <button type="button" @click="deselectAll('postprocessor')" title="Deselect All" class="action-btn text-danger">✕</button>
              </div>
            </div>
            <div class="module-list custom-scrollbar">
              <template v-for="mod in modulesByCategory.postprocessor" :key="mod.name">
                <div v-show="isModuleVisible(mod.name)" class="module-item" :class="{ 'disabled-item': isModuleDisabled(mod.name) }">
                  <label :for="'mod-' + mod.name" class="truncate flex-1 m-0 text-sm font-medium cursor-pointer" :title="mod.name">{{ formatName(mod.name) }}</label>
                  <label class="switch shrink-0">
                    <input type="checkbox" :id="'mod-' + mod.name" v-model="selectedModules[mod.name]" :disabled="isModuleDisabled(mod.name)" />
                    <span class="slider"></span>
                  </label>
                </div>
              </template>
            </div>
          </div>

          <!-- Plaso -->
          <div class="module-card">
            <div class="module-card-header">
              <h4 class="module-category-title">4. Plaso & Derivatives</h4>
              <div class="module-actions">
                <button type="button" @click="selectAll('plaso')" title="Select All" class="action-btn text-primary">✓</button>
                <button type="button" @click="deselectAll('plaso')" title="Deselect All" class="action-btn text-danger">✕</button>
              </div>
            </div>
            <div class="module-list custom-scrollbar">
              <template v-for="mod in modulesByCategory.plaso" :key="mod.name">
                <div v-show="isModuleVisible(mod.name)" class="module-item" :class="{ 'disabled-item': isModuleDisabled(mod.name) }">
                  <label :for="'mod-' + mod.name" class="truncate flex-1 m-0 text-sm font-medium cursor-pointer" :title="mod.name">{{ formatName(mod.name) }}</label>
                  <label class="switch shrink-0">
                    <input type="checkbox" :id="'mod-' + mod.name" v-model="selectedModules[mod.name]" :disabled="isModuleDisabled(mod.name)" />
                    <span class="slider"></span>
                  </label>
                </div>
              </template>
            </div>
          </div>

          <!-- SIEM Exports -->
          <div class="module-card">
            <div class="module-card-header">
              <h4 class="module-category-title">5. SIEM Exports</h4>
              <div class="module-actions">
                <button type="button" @click="selectAll('export')" title="Select All" class="action-btn text-primary">✓</button>
                <button type="button" @click="deselectAll('export')" title="Deselect All" class="action-btn text-danger">✕</button>
              </div>
            </div>
            <div class="module-list custom-scrollbar">
              <template v-for="mod in modulesByCategory.export" :key="mod.name">
                <div v-show="isModuleVisible(mod.name)" class="module-item" :class="{ 'disabled-item': isModuleDisabled(mod.name) }">
                  <label :for="'mod-' + mod.name" class="truncate flex-1 m-0 text-sm font-medium cursor-pointer" :title="mod.name">{{ formatName(mod.name) }}</label>
                  <label class="switch shrink-0">
                    <input type="checkbox" :id="'mod-' + mod.name" v-model="selectedModules[mod.name]" :disabled="isModuleDisabled(mod.name)" />
                    <span class="slider"></span>
                  </label>
                </div>
              </template>
            </div>
          </div>
        </div>
      </div>

      <!-- Drag & Drop Archive File -->
      <div 
        class="drop-zone mt-4" 
        :class="{ 'is-dragover': isDraggingFile, 'has-file': !!selectedFile }"
        @dragover.prevent="isDraggingFile = true"
        @dragleave.prevent="isDraggingFile = false"
        @drop.prevent="onFileDrop"
        @click="$refs.fileInput.click()"
      >
        <input type="file" ref="fileInput" @change="onFileChange" class="d-none" required accept=".zip,.7z,.rar,.gz,.tar" />
        <div class="drop-content text-center">
          <i class="upload-icon mb-2">📁</i>
          <p v-if="!selectedFile" class="m-0">Drag & drop your archive here, or <span>click to browse</span></p>
          <p v-else class="m-0 file-name text-primary font-bold">{{ selectedFile.name }} <span class="file-size text-muted text-sm font-normal">({{ formatBytes(selectedFile.size) }})</span></p>
        </div>
      </div>

      <!-- Optional Custom YAML for Windows -->
      <transition name="slide-fade">
        <div class="form-group custom-yaml-group mt-2" v-if="false">
          <label class="text-sm font-bold text-muted uppercase tracking-wider d-flex align-center justify-between">
            Custom Ogre YAML (Optional)
            <span v-if="yamlStatus === 'valid'" class="badge badge-success text-xs">✓ Valid YAML</span>
            <span v-if="yamlStatus === 'invalid'" class="badge badge-danger text-xs">✗ Invalid Format</span>
          </label>
          <div 
            class="drop-zone mini-drop-zone mt-1"
            :class="{ 'is-dragover': isDraggingYaml, 'has-error': yamlStatus === 'invalid', 'has-success': yamlStatus === 'valid' }"
            @dragover.prevent="isDraggingYaml = true"
            @dragleave.prevent="isDraggingYaml = false"
            @drop.prevent="onYamlDrop"
            @click="$refs.yamlInput.click()"
          >
            <input type="file" ref="yamlInput" @change="onYamlChange" class="d-none" accept=".yaml,.yml" />
            <div class="drop-content text-center text-sm">
              <p v-if="!yamlFile" class="m-0 text-muted">Drop a custom .yaml file here (optional)</p>
              <p v-else class="m-0 text-primary">{{ yamlFile.name }}</p>
            </div>
          </div>
          <p v-if="yamlError" class="text-xs mt-1 text-danger animate-pulse">{{ yamlError }}</p>
        </div>
      </transition>

      <!-- Submit Action -->
      <div class="action-row mt-6">
        <button type="submit" class="btn btn-primary btn-block btn-lg rounded-xl shadow-md font-medium" :disabled="isUploading || !selectedFile || yamlStatus === 'invalid'">
          <span v-if="!isUploading" class="d-flex align-center justify-center gap-2">
            Upload & Start Analysis
          </span>
          <span v-else class="d-flex flex-col align-center w-full">
            <span class="mb-1 text-sm font-bold">Uploading... {{ uploadProgress }}%</span>
            <div class="progress-bar-container">
              <div class="progress-bar-fill" :style="{ width: uploadProgress + '%' }"></div>
            </div>
          </span>
        </button>
      </div>
    </form>

    <transition name="fade">
      <div v-if="statusMsg" :class="['status-alert mt-4', statusType]">
        <div class="d-flex align-center justify-center gap-2 font-medium">
          <span v-if="statusType === 'success'">✅</span>
          <span v-else-if="statusType === 'error'">❌</span>
          <span v-else>ℹ️</span>
          {{ statusMsg }}
        </div>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref, onMounted, reactive, watch } from 'vue'
import jsyaml from 'js-yaml'

const emit = defineEmits(['upload-success'])

const caseName = ref('')
const machineName = ref('')
const archiveType = ref('Windows')
const ogreMode = ref('orc')

const selectedFile = ref(null)
const yamlFile = ref(null)
const yamlContent = ref(null)
const yamlError = ref('')
const yamlStatus = ref('none')

const isDraggingFile = ref(false)
const isDraggingYaml = ref(false)

const isUploading = ref(false)
const uploadProgress = ref(0)
const statusMsg = ref('')
const statusType = ref('info')

// Modules Configuration state
const selectedModules = reactive({})
const modulesByCategory = reactive({
  preprocessor: [],
  pipeline: [],
  standalone: [],
  postprocessor: [],
  plaso: [],
  export: []
})

const EXPORT_MODULES = ["wazuh", "plaso2wazuh", "elk", "plaso2elk"]
const PLASO_MODULES = ["plaso", "mpp", "mactime"]
const STANDALONE_MODULES = ["process", "network", "system_info", "scripts"]

const formatName = (name) => {
  return name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
}

const fetchPipelines = async () => {
  try {
    const response = await fetch('/api/pipelines')
    const data = await response.json()
    if (data.status === 'OK' && data.pipelines) {
      sortPipelines(data.pipelines)
    } else {
      useFallbackPipelines()
    }
  } catch (err) {
    console.error("Failed to fetch pipelines:", err)
    useFallbackPipelines()
  }
}

const sortPipelines = (pipelines) => {
  Object.keys(modulesByCategory).forEach(k => modulesByCategory[k] = [])
  
  pipelines.forEach(mod => {
    const isChecked = !["restore", "rename_from_orc", "elk", "plaso2elk"].includes(mod.name)
    selectedModules[mod.name] = isChecked

    if (EXPORT_MODULES.includes(mod.name)) {
      modulesByCategory.export.push(mod)
    } else if (PLASO_MODULES.includes(mod.name)) {
      modulesByCategory.plaso.push(mod)
    } else if (STANDALONE_MODULES.includes(mod.name)) {
      modulesByCategory.standalone.push(mod)
    } else if (mod.type === 'preprocessor') {
      modulesByCategory.preprocessor.push(mod)
    } else if (mod.type === 'postprocessor') {
      modulesByCategory.postprocessor.push(mod)
    } else {
      modulesByCategory.pipeline.push(mod)
    }
  })
}

const useFallbackPipelines = () => {
  const fallback = ["disk", "wazuh", "evtx", "hives", "master_file_table", "network", "lnk", "plaso", "mpp", "plaso2wazuh", "prefetch", "process", "system_info", "browsers", "scripts"].map(name => ({
    name, description: "Fallback plugin", type: "pipeline"
  }))
  sortPipelines(fallback)
}

const isModuleDisabled = (moduleName) => {
  if (moduleName === 'extract') return true
  
  if (["plaso2wazuh", "mpp"].includes(moduleName)) {
    return !selectedModules['plaso']
  }
  
  if (archiveType.value === 'ORC') {
    if (moduleName.startsWith('ogre_') && moduleName !== 'ogre_preprocessor') {
      return !selectedModules['ogre_preprocessor']
    }
  }
  return false
}

const isModuleVisible = (moduleName) => { 
  return !moduleName.startsWith('ogre');
}

const selectAll = (category) => {
  modulesByCategory[category].forEach(mod => {
    if (isModuleVisible(mod.name) && !isModuleDisabled(mod.name)) {
      selectedModules[mod.name] = true
    }
  })
}

const deselectAll = (category) => {
  modulesByCategory[category].forEach(mod => {
    if (isModuleVisible(mod.name) && !isModuleDisabled(mod.name)) {
      selectedModules[mod.name] = false
    }
  })
}

const onProcessingModeChange = () => {
  // Reset selections based on mode
  Object.keys(selectedModules).forEach(modName => {
    if (isModuleVisible(modName)) {
      const isDefault = !["restore", "rename_from_orc", "elk", "plaso2elk"].includes(modName)
      selectedModules[modName] = isDefault
    } else {
      selectedModules[modName] = false
    }
  })
  selectedModules['extract'] = true
}

watch(() => selectedModules['plaso'], (newVal) => {
  if (!newVal) {
    selectedModules['plaso2wazuh'] = false
    selectedModules['mpp'] = false
  }
})

watch(() => selectedModules['ogre_preprocessor'], (newVal) => {
  if (!newVal && archiveType.value === 'Windows') {
    Object.keys(selectedModules).forEach(key => {
      if (key.startsWith('ogre_') && key !== 'ogre_preprocessor') {
        selectedModules[key] = false
      }
    })
  }
})

const onArchiveTypeChange = () => {
  if (archiveType.value !== 'Windows') {
    Object.keys(selectedModules).forEach(key => {
      if (key.startsWith('ogre')) selectedModules[key] = false
    })
  }
}

onMounted(() => {
  fetchPipelines()
})

const formatBytes = (bytes, decimals = 2) => {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const dm = decimals < 0 ? 0 : decimals
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i]
}

const handleFile = (file) => {
  if (!file) return
  selectedFile.value = file
}

const onFileChange = (e) => handleFile(e.target.files[0])
const onFileDrop = (e) => {
  isDraggingFile.value = false
  if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0])
}

const validateYaml = (file) => {
  if (!file) {
    yamlFile.value = null
    yamlContent.value = null
    yamlError.value = ''
    yamlStatus.value = 'none'
    return
  }

  const reader = new FileReader()
  reader.onload = (evt) => {
    try {
      const content = evt.target.result
      jsyaml.load(content)
      yamlContent.value = content
      yamlError.value = ''
      yamlFile.value = file
      yamlStatus.value = 'valid'
    } catch (err) {
      yamlError.value = 'Invalid YAML format: ' + err.message
      yamlContent.value = null
      yamlFile.value = file
      yamlStatus.value = 'invalid'
    }
  }
  reader.readAsText(file)
}

const onYamlChange = (e) => validateYaml(e.target.files[0])
const onYamlDrop = (e) => {
  isDraggingYaml.value = false
  if (e.dataTransfer.files.length) validateYaml(e.dataTransfer.files[0])
}

const handleUpload = async () => {
  if (!selectedFile.value) return
  
  isUploading.value = true
  statusMsg.value = 'Uploading archive...'
  statusType.value = 'info'
  uploadProgress.value = 0

  const formData = new FormData()
  formData.append('file', selectedFile.value)
  
  const parserConfig = {}
  for (const [key, val] of Object.entries(selectedModules)) {
    if (isModuleVisible(key)) {
      parserConfig[key] = val ? 1 : 0
    } else {
      parserConfig[key] = 0
    }
  }
  parserConfig['ogreMode'] = ogreMode.value
  
  const jsonData = {
    caseName: caseName.value,
    machineName: machineName.value,
    archiveType: archiveType.value,
    ogreMode: ogreMode.value,
    parser_config: parserConfig,
    artefact_config: yamlContent.value ? { custom_ogre_yaml_content: yamlContent.value } : {}
  }
  
  formData.append('json', JSON.stringify(jsonData))

  try {
    const xhr = new XMLHttpRequest()
    
    xhr.upload.addEventListener('progress', (event) => {
      if (event.lengthComputable) {
        uploadProgress.value = Math.round((event.loaded * 100) / event.total)
      }
    })

    xhr.addEventListener('load', () => {
      isUploading.value = false
      if (xhr.status >= 200 && xhr.status < 300) {
        statusMsg.value = 'Task successfully submitted!'
        statusType.value = 'success'
        emit('upload-success')
        
        setTimeout(() => {
          caseName.value = ''
          machineName.value = ''
          selectedFile.value = null
          yamlFile.value = null
          yamlContent.value = null
          yamlStatus.value = 'none'
          statusMsg.value = ''
        }, 3000)
      } else {
        statusMsg.value = `Server Error: ${xhr.responseText}`
        statusType.value = 'error'
      }
    })

    xhr.addEventListener('error', () => {
      isUploading.value = false
      statusMsg.value = 'Network error during upload.'
      statusType.value = 'error'
    })

    xhr.open('POST', '/api/parse/parse_legacy')
    xhr.send(formData)

  } catch (err) {
    isUploading.value = false
    statusMsg.value = `Upload failed: ${err.message}`
    statusType.value = 'error'
  }
}
</script>

<style scoped>
.upload-form-container {
  border-radius: 1rem;
  padding: 2rem;
  background: rgba(15, 23, 42, 0.3); /* Adding a slight background to make it pop */
}

.text-muted {
  color: #94a3b8;
}

.rounded-lg {
  border-radius: 0.5rem;
}
.rounded-xl {
  border-radius: 0.75rem;
}

.form-row {
  display: flex;
  gap: 1.5rem;
  flex-wrap: wrap;
}

.flex-1 {
  flex: 1 1 200px;
}

.w-full {
  width: 100%;
}

.tracking-wider {
  letter-spacing: 0.05em;
}

/* Modules Grid */
.module-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 1.5rem;
}
@media (min-width: 768px) {
  .module-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}
@media (min-width: 1200px) {
  .module-grid {
    grid-template-columns: repeat(3, 1fr);
  }
}

.module-card {
  background: rgba(30, 41, 59, 0.4);
  border: 1px solid rgba(51, 65, 85, 0.5);
  border-radius: 0.75rem;
  display: flex;
  flex-direction: column;
  box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
}

.module-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 1.25rem;
  border-bottom: 1px solid rgba(51, 65, 85, 0.3);
}

.module-category-title {
  font-size: 0.75rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin: 0;
  color: #cbd5e1;
}

.module-actions {
  display: flex;
  gap: 0.5rem;
  background: rgba(15, 23, 42, 0.5);
  padding: 0.35rem 0.5rem;
  border-radius: 0.5rem;
  border: 1px solid rgba(51, 65, 85, 0.5);
}

.action-btn {
  background: none;
  border: none;
  cursor: pointer;
  padding: 0.15rem 0.5rem;
  border-radius: 0.25rem;
  font-weight: bold;
  font-size: 0.9rem;
  transition: color 0.2s;
}
.action-btn:hover {
  background: rgba(255,255,255,0.1);
}
.text-primary { color: #818cf8; }
.text-primary:hover { color: #a5b4fc; }
.text-danger { color: #ef4444; }
.text-danger:hover { color: #f87171; }

.module-list {
  padding: 0.75rem 1.25rem 1.25rem 1.25rem;
  max-height: 250px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.module-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.6rem 0.85rem;
  border-radius: 0.5rem;
  border: 1px solid transparent;
  transition: all 0.2s;
}
.module-item:hover {
  background: rgba(15, 23, 42, 0.5);
  border-color: rgba(51, 65, 85, 0.3);
}

.input-field {
  padding: 0.75rem 1rem;
  background-color: rgba(15, 23, 42, 0.4);
  border: 1px solid rgba(51, 65, 85, 0.5);
  color: #f1f5f9;
  outline: none;
  transition: border-color 0.2s;
}
.input-field:focus {
  border-color: #818cf8;
}

.module-item.disabled-item {
  opacity: 0.4;
}
.module-item.disabled-item label {
  cursor: not-allowed;
}

/* Switch styling similar to the old HTML */
.switch {
  position: relative;
  display: inline-block;
  width: 34px;
  height: 20px;
}
.switch input {
  opacity: 0;
  width: 0;
  height: 0;
}
.slider {
  position: absolute;
  cursor: pointer;
  top: 0; left: 0; right: 0; bottom: 0;
  background-color: rgba(255, 255, 255, 0.15);
  transition: .3s;
  border-radius: 20px;
  border: 1px solid rgba(255,255,255,0.1);
}
.slider:before {
  position: absolute;
  content: "";
  height: 14px;
  width: 14px;
  left: 2px;
  bottom: 2px;
  background-color: #cbd5e1;
  transition: .3s;
  border-radius: 50%;
}
input:checked + .slider {
  background-color: #10b981; /* Bright Emerald Green */
  border-color: #059669;
}
input:checked + .slider:before {
  transform: translateX(14px);
  background-color: white;
}
input:disabled + .slider {
  cursor: not-allowed;
}

/* Drop Zone Styles */
.drop-zone {
  border: 2px dashed rgba(51, 65, 85, 0.8);
  border-radius: 0.75rem;
  padding: 2.5rem 1rem;
  transition: all 0.3s ease;
  cursor: pointer;
  background: rgba(30, 41, 59, 0.2);
  display: flex;
  justify-content: center;
  align-items: center;
}

.drop-zone:hover, .drop-zone.is-dragover {
  border-color: #818cf8;
  background: rgba(99, 102, 241, 0.05);
}

.drop-zone.has-file {
  border-style: solid;
  border-color: #818cf8;
  background: rgba(99, 102, 241, 0.1);
}

.mini-drop-zone {
  padding: 1.2rem;
  border-radius: 0.5rem;
}

.mini-drop-zone.has-error {
  border-color: #ef4444;
  background: rgba(239, 68, 68, 0.05);
}

.mini-drop-zone.has-success {
  border-color: #10b981;
  background: rgba(16, 185, 129, 0.05);
}

.upload-icon {
  font-size: 2.5rem;
  display: block;
}

.drop-content p span {
  color: #818cf8;
  text-decoration: underline;
}

/* Progress Bar */
.progress-bar-container {
  width: 100%;
  height: 6px;
  background: rgba(255,255,255,0.2);
  border-radius: 4px;
  overflow: hidden;
  margin-top: 0.5rem;
}
.progress-bar-fill {
  height: 100%;
  background: white;
  transition: width 0.2s ease;
}

.btn-block {
  width: 100%;
  display: block;
}

.btn-lg {
  padding: 0.85rem 1.5rem;
  font-size: 1.1rem;
}

.badge {
  padding: 0.2rem 0.5rem;
  border-radius: 0.375rem;
  font-weight: 700;
}
.badge-success { background: rgba(16, 185, 129, 0.2); color: #a7f3d0; }
.badge-danger { background: rgba(239, 68, 68, 0.2); color: #fecaca; }

/* Animations */
.animate-pulse {
  animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: .5; }
}

.slide-fade-enter-active {
  transition: all 0.3s ease-out;
}
.slide-fade-leave-active {
  transition: all 0.2s cubic-bezier(1, 0.5, 0.8, 1);
}
.slide-fade-enter-from, .slide-fade-leave-to {
  transform: translateY(-10px);
  opacity: 0;
}

.fade-enter-active, .fade-leave-active {
  transition: opacity 0.5s ease;
}
.fade-enter-from, .fade-leave-to {
  opacity: 0;
}

.status-alert {
  padding: 1rem;
  border-radius: 0.75rem;
}
.status-alert.info { background: rgba(99,102,241,0.1); border: 1px solid rgba(99,102,241,0.2); color: #c7d2fe; }
.status-alert.success { background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); color: #a7f3d0; }
.status-alert.error { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.2); color: #fecaca; }
</style>
