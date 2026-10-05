<template>
  <div class="container animate-fade-in">
    <header class="dashboard-header mb-3">
      <h1>DFIR Pipeline Dashboard</h1>
      <p class="text-muted">Upload and process forensic archives through the WFAPP engine.</p>
    </header>

    <div class="dashboard-grid">
      <!-- Upload Section -->
      <section class="d-flex flex-col gap-3">
        <!-- Tabs -->
        <div class="glass-panel p-2 d-flex gap-2" style="border-radius: 0.75rem;">
          <button 
            @click="activeTab = 'ogre'" 
            class="tab-btn flex-1 py-2 rounded-md font-bold transition-all"
            :class="activeTab === 'ogre' ? 'bg-indigo-600 text-white shadow-md' : 'text-muted hover:bg-slate-800'"
          >
            DFIR-Ogre (Windows)
          </button>
          <button 
            @click="activeTab = 'legacy'" 
            class="tab-btn flex-1 py-2 rounded-md font-bold transition-all"
            :class="activeTab === 'legacy' ? 'bg-indigo-600 text-white shadow-md' : 'text-muted hover:bg-slate-800'"
          >
            Legacy (Raw Files)
          </button>
        </div>

        <!-- Dynamic Form -->
        <transition name="fade" mode="out-in">
          <OgreUploadForm v-if="activeTab === 'ogre'" @upload-success="refreshTasks" />
          <LegacyUploadForm v-else @upload-success="refreshTasks" />
        </transition>
      </section>

      <!-- Running Tasks Section -->
      <section class="glass-panel p-3">
        <h2 class="mb-2 text-lg d-flex justify-between align-center">
          Running Tasks
          <button @click="refreshTasks" class="btn btn-secondary btn-sm" title="Refresh">
            ↻
          </button>
        </h2>
        
        <RunningTasks ref="tasksRef" />
      </section>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import OgreUploadForm from '../components/OgreUploadForm.vue'
import LegacyUploadForm from '../components/LegacyUploadForm.vue'
import RunningTasks from '../components/RunningTasks.vue'

const tasksRef = ref(null)
const activeTab = ref('ogre')

const refreshTasks = () => {
  if (tasksRef.value) {
    tasksRef.value.fetchTasks()
  }
}
</script>

<style scoped>
.dashboard-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 2rem;
}

@media (min-width: 900px) {
  .dashboard-grid {
    grid-template-columns: 1fr 1fr;
  }
}

.p-3 {
  padding: 1.5rem;
}

.text-lg {
  font-size: 1.25rem;
  font-weight: 600;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 0.75rem;
}

.btn-sm {
  padding: 0.25rem 0.75rem;
  font-size: 1rem;
}
</style>
