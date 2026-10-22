<template>
  <div class="container animate-fade-in orc-downloads-page">
    <!-- Header -->
    <header class="page-header mb-4">
      <div class="d-flex align-center justify-between flex-wrap gap-2">
        <div>
          <h1 class="text-2xl font-bold m-0 d-flex align-center gap-2">
            <svg class="header-icon text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Binaires & Agents DFIR-ORC
          </h1>
          <p class="text-muted mt-1">
            Téléchargez les exécutables DFIR-ORC (x64) pré-packagés et configurés selon vos scénarios d'intervention.
          </p>
        </div>
        <div class="d-flex align-center gap-2">
          <button @click="fetchBinariesInfo" class="btn btn-secondary btn-sm" title="Vérifier la disponibilité">
            <svg class="w-4 h-4 mr-1" :class="{ 'animate-spin': isLoading }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Actualiser
          </button>
        </div>
      </div>
    </header>

    <!-- Global Toast Alert -->
    <transition name="fade">
      <div v-if="toast.show" :class="['toast-alert', `toast-${toast.type}`]">
        <svg v-if="toast.type === 'success'" class="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
        </svg>
        <svg v-else-if="toast.type === 'error'" class="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <svg v-else class="w-5 h-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <span class="flex-1">{{ toast.message }}</span>
        <button @click="toast.show = false" class="close-toast-btn">✕</button>
      </div>
    </transition>

    <!-- Binaries Grid -->
    <div class="binaries-grid mb-6">
      <!-- 1. Classic Config -->
      <div class="glass-panel binary-card d-flex flex-col">
        <div class="card-top p-4 flex-1">
          <div class="d-flex justify-between align-start mb-3">
            <div class="binary-icon-box icon-classic">
              <svg class="w-6 h-6 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
            <span class="badge badge-indigo">Standard</span>
          </div>

          <h3 class="text-xl font-bold text-white mb-1">DFIR-ORC Classic</h3>
          <p class="text-xs font-mono text-indigo-300 mb-3">DFIR-Orc.exe</p>
          <p class="text-sm text-slate-300 mb-4 leading-relaxed">
            Configuration standard complète pour les systèmes connectés. Collecte l'ensemble des artefacts critiques du système d'exploitation Windows.
          </p>

          <!-- Feature Tags -->
          <div class="tags-container mb-4">
            <span class="tag-pill">$MFT</span>
            <span class="tag-pill">Journaux EVTX</span>
            <span class="tag-pill">Registres SAM/SYS</span>
            <span class="tag-pill">Autoruns</span>
            <span class="tag-pill">Navigateurs</span>
          </div>
        </div>

        <div class="card-bottom p-4 border-t bg-slate-900/40">
          <div class="d-flex justify-between align-center text-xs text-muted mb-3">
            <span>Taille : <strong class="text-white">{{ getBinarySize('classic', '8.14 Mo') }}</strong></span>
            <span>Arch : <strong class="text-white">x64 (PE)</strong></span>
          </div>
          <button 
            @click="downloadBinary('/api/download/dfir-orc-full', 'DFIR-Orc.exe', 'classic')" 
            class="btn btn-primary w-full"
            :disabled="downloadingId === 'classic'"
          >
            <svg v-if="downloadingId !== 'classic'" class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            <svg v-else class="w-4 h-4 mr-2 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            {{ downloadingId === 'classic' ? 'Téléchargement...' : 'Télécharger (.exe)' }}
          </button>
        </div>
      </div>

      <!-- 2. Offline Mode -->
      <div class="glass-panel binary-card d-flex flex-col">
        <div class="card-top p-4 flex-1">
          <div class="d-flex justify-between align-start mb-3">
            <div class="binary-icon-box icon-offline">
              <svg class="w-6 h-6 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
            </div>
            <span class="badge badge-emerald">Air-Gapped</span>
          </div>

          <h3 class="text-xl font-bold text-white mb-1">DFIR-ORC Offline</h3>
          <p class="text-xs font-mono text-emerald-300 mb-3">DFIR-Orc_offline.exe</p>
          <p class="text-sm text-slate-300 mb-4 leading-relaxed">
            Profil adapté aux machines isolées ou hors réseau. Enregistre automatiquement l'archive résultante en local sur le support amovible ou le disque cible.
          </p>

          <!-- Feature Tags -->
          <div class="tags-container mb-4">
            <span class="tag-pill">Stockage Local</span>
            <span class="tag-pill">Sans Réseau</span>
            <span class="tag-pill">Clé USB / Amovible</span>
            <span class="tag-pill">Isolé / OT</span>
          </div>
        </div>

        <div class="card-bottom p-4 border-t bg-slate-900/40">
          <div class="d-flex justify-between align-center text-xs text-muted mb-3">
            <span>Taille : <strong class="text-white">{{ getBinarySize('offline', '8.13 Mo') }}</strong></span>
            <span>Arch : <strong class="text-white">x64 (PE)</strong></span>
          </div>
          <button 
            @click="downloadBinary('/api/download/dfir-orc-offlinemode', 'DFIR-Orc_offline.exe', 'offline')" 
            class="btn btn-emerald w-full"
            :disabled="downloadingId === 'offline'"
          >
            <svg v-if="downloadingId !== 'offline'" class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            <svg v-else class="w-4 h-4 mr-2 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            {{ downloadingId === 'offline' ? 'Téléchargement...' : 'Télécharger (.exe)' }}
          </button>
        </div>
      </div>

      <!-- 3. WMemory -->
      <div class="glass-panel binary-card d-flex flex-col">
        <div class="card-top p-4 flex-1">
          <div class="d-flex justify-between align-start mb-3">
            <div class="binary-icon-box icon-wmem">
              <svg class="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M12 6V3m0 18v-3" />
              </svg>
            </div>
            <span class="badge badge-purple">RAM Live</span>
          </div>

          <h3 class="text-xl font-bold text-white mb-1">DFIR-ORC WMemory</h3>
          <p class="text-xs font-mono text-purple-300 mb-3">DFIR-Orc_wmem.exe</p>
          <p class="text-sm text-slate-300 mb-4 leading-relaxed">
            Configuration intégrant l'acquisition complète de la mémoire vive (RAM) à chaud en plus des artefacts système vitaux pour l'investigation approfondie.
          </p>

          <!-- Feature Tags -->
          <div class="tags-container mb-4">
            <span class="tag-pill">Dump Mémoire RAM</span>
            <span class="tag-pill">WinPmem</span>
            <span class="tag-pill">Live Triage</span>
            <span class="tag-pill">Processus Volatils</span>
          </div>
        </div>

        <div class="card-bottom p-4 border-t bg-slate-900/40">
          <div class="d-flex justify-between align-center text-xs text-muted mb-3">
            <span>Taille : <strong class="text-white">{{ getBinarySize('wmem', '8.14 Mo') }}</strong></span>
            <span>Arch : <strong class="text-white">x64 (PE)</strong></span>
          </div>
          <button 
            @click="downloadBinary('/api/download/dfir-orc-wmem', 'DFIR-Orc_wmem.exe', 'wmem')" 
            class="btn btn-purple w-full"
            :disabled="downloadingId === 'wmem'"
          >
            <svg v-if="downloadingId !== 'wmem'" class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            <svg v-else class="w-4 h-4 mr-2 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            {{ downloadingId === 'wmem' ? 'Téléchargement...' : 'Télécharger (.exe)' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Deployment & Instructions Guide -->
    <div class="glass-panel p-4 deployment-guide">
      <div class="d-flex align-center justify-between mb-3 pb-2 border-b flex-wrap gap-2">
        <h2 class="text-lg font-bold m-0 d-flex align-center gap-2">
          <svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
          </svg>
          Guide de déploiement et commandes rapides
        </h2>
        <div class="tabs-nav d-flex gap-1">
          <button 
            @click="activeDocTab = 'cmd'" 
            :class="['tab-pill', activeDocTab === 'cmd' ? 'active' : '']"
          >
            PowerShell / CMD
          </button>
          <button 
            @click="activeDocTab = 'bulk'" 
            :class="['tab-pill', activeDocTab === 'bulk' ? 'active' : '']"
          >
            Ingestion Automatisée
          </button>
          <button 
            @click="activeDocTab = 'tips'" 
            :class="['tab-pill', activeDocTab === 'tips' ? 'active' : '']"
          >
            Bonnes pratiques
          </button>
        </div>
      </div>

      <!-- Tab 1: Commands -->
      <div v-if="activeDocTab === 'cmd'" class="tab-content animate-fade-in">
        <p class="text-sm text-slate-300 mb-3">
          Exécutez le binaire en invite de commande avec élévation de privilèges (Administrateur ou compte <code>NT AUTHORITY\SYSTEM</code>) :
        </p>

        <div class="code-box mb-3">
          <div class="text-muted mb-1"># 1. Exécution standard (Classic)</div>
          <span class="text-emerald-400">.\DFIR-Orc.exe</span> /config=config\WolfLauncher.xml /out=C:\Temp\output.7z<br /><br />
          <div class="text-muted mb-1"># 2. Exécution hors-ligne autonome</div>
          <span class="text-emerald-400">.\DFIR-Orc_offline.exe</span><br /><br />
          <div class="text-muted mb-1"># 3. Exécution avec acquisition mémoire</div>
          <span class="text-emerald-400">.\DFIR-Orc_wmem.exe</span>
        </div>
      </div>

      <!-- Tab 2: Bulk -->
      <div v-if="activeDocTab === 'bulk'" class="tab-content animate-fade-in">
        <p class="text-sm text-slate-300 mb-3">
          Une fois les archives générées sur votre parc de machines, vous disposez de deux méthodes pour les analyser dans WFAPP :
        </p>
        <ul class="text-sm text-slate-300 space-y-2 list-disc pl-5">
          <li><strong>Upload Web :</strong> Déposez l'archive directement depuis l'onglet <em>Dashboard</em> (DFIR-Ogre).</li>
          <li>
            <strong>Dépôt en masse (Bulk Ingestion) :</strong> Copiez simplement les fichiers dans le dossier partagé <code>depot/</code> sur le serveur.
            Le service <code>wapp_watcher</code> détecte automatiquement les nouvelles archives, vérifie leur stabilité et déclenche le parsing en arrière-plan sans surcharger l'interface web.
          </li>
        </ul>
      </div>

      <!-- Tab 3: Tips -->
      <div v-if="activeDocTab === 'tips'" class="tab-content animate-fade-in">
        <div class="grid-tips">
          <div class="tip-card p-3 rounded-lg border">
            <h4 class="text-sm font-bold text-white mb-1">Privilèges Administrateur</h4>
            <p class="text-xs text-muted">
              L'accès à la table MFT brute et aux ruches SAM verrouillées par le noyau requiert les privilèges <code>SeBackupPrivilege</code> (exécuter en tant qu'Administrateur ou SYSTEM).
            </p>
          </div>
          <div class="tip-card p-3 rounded-lg border">
            <h4 class="text-sm font-bold text-white mb-1">Exclusion EDR / Antivirus</h4>
            <p class="text-xs text-muted">
              Certains EDR bloquent l'accès bas niveau à <code>\\.\PhysicalDrive0</code> ou le driver WinPmem. Prévoyez une exception temporaire sur le hash du binaire si nécessaire.
            </p>
          </div>
          <div class="tip-card p-3 rounded-lg border">
            <h4 class="text-sm font-bold text-white mb-1">Espace Disque</h4>
            <p class="text-xs text-muted">
              Pour le profil <em>WMemory</em>, prévoyez un espace libre sur le disque cible au moins égal à la taille de la RAM physique installée sur l'ordinateur cible.
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'

const isLoading = ref(false)
const downloadingId = ref(null)
const binariesInfo = ref([])
const activeDocTab = ref('cmd')

const toast = ref({
  show: false,
  message: '',
  type: 'info'
})

let toastTimeout = null
const showToast = (message, type = 'info') => {
  if (toastTimeout) clearTimeout(toastTimeout)
  toast.value = { show: true, message, type }
  toastTimeout = setTimeout(() => {
    toast.value.show = false
  }, 4500)
}

const fetchBinariesInfo = async () => {
  isLoading.value = true
  try {
    const res = await fetch('/api/binaries/info')
    if (res.ok) {
      binariesInfo.value = await res.json()
    }
  } catch (e) {
    console.error('Failed to load binaries info', e)
  } finally {
    isLoading.value = false
  }
}

const getBinarySize = (id, fallback) => {
  const item = binariesInfo.value.find(b => b.id === id)
  if (item && item.exists && item.size_mb) {
    return `${item.size_mb} Mo`
  }
  return fallback
}

// Download handler with progress trigger
const downloadBinary = async (url, filename, id) => {
  downloadingId.value = id
  showToast(`Préparation du téléchargement de ${filename}...`, 'info')

  try {
    const response = await fetch(url)
    if (!response.ok) {
      throw new Error(`Erreur serveur (${response.status})`)
    }

    const blob = await response.blob()
    const downloadUrl = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.style.display = 'none'
    a.href = downloadUrl
    a.download = filename
    document.body.appendChild(a)
    a.click()

    window.URL.revokeObjectURL(downloadUrl)
    a.remove()
    showToast(`Téléchargement de ${filename} réussi !`, 'success')
  } catch (error) {
    showToast(`Échec du téléchargement : ${error.message}`, 'error')
  } finally {
    downloadingId.value = null
  }
}

onMounted(() => {
  fetchBinariesInfo()
})
</script>

<style scoped>
.header-icon {
  width: 28px;
  height: 28px;
}

.binaries-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 1.5rem;
}

@media (min-width: 768px) {
  .binaries-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (min-width: 1120px) {
  .binaries-grid {
    grid-template-columns: repeat(3, 1fr);
  }
}

.binary-card {
  transition: transform 0.25s ease, box-shadow 0.25s ease;
  overflow: hidden;
}

.binary-card:hover {
  transform: translateY(-3px);
  box-shadow: 0 12px 28px rgba(0, 0, 0, 0.4);
}

.binary-icon-box {
  width: 48px;
  height: 48px;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
}

.icon-classic {
  background: rgba(99, 102, 241, 0.15);
  border: 1px solid rgba(99, 102, 241, 0.3);
}

.icon-offline {
  background: rgba(16, 185, 129, 0.15);
  border: 1px solid rgba(16, 185, 129, 0.3);
}

.icon-wmem {
  background: rgba(168, 85, 247, 0.15);
  border: 1px solid rgba(168, 85, 247, 0.3);
}

.btn-emerald {
  background-color: #059669;
  color: white;
  box-shadow: 0 4px 14px 0 rgba(16, 185, 129, 0.35);
}

.btn-emerald:hover {
  background-color: #047857;
  transform: translateY(-1px);
}

.btn-purple {
  background-color: #7c3aed;
  color: white;
  box-shadow: 0 4px 14px 0 rgba(124, 58, 237, 0.35);
}

.btn-purple:hover {
  background-color: #6d28d9;
  transform: translateY(-1px);
}

.tags-container {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
}

.tag-pill {
  font-size: 0.7rem;
  font-weight: 500;
  padding: 0.2rem 0.5rem;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 4px;
  color: #94a3b8;
}

.tabs-nav {
  background: rgba(15, 23, 42, 0.6);
  padding: 0.25rem;
  border-radius: var(--radius-md);
  border: 1px solid rgba(255, 255, 255, 0.08);
}

.tab-pill {
  background: none;
  border: none;
  padding: 0.35rem 0.75rem;
  font-size: 0.8rem;
  font-weight: 500;
  color: #94a3b8;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.tab-pill.active {
  background: var(--accent-color);
  color: white;
  box-shadow: 0 2px 8px rgba(99, 102, 241, 0.4);
}

.grid-tips {
  display: grid;
  grid-template-columns: 1fr;
  gap: 1rem;
}

@media (min-width: 768px) {
  .grid-tips {
    grid-template-columns: repeat(3, 1fr);
  }
}

.tip-card {
  background: rgba(15, 23, 42, 0.5);
  border-color: rgba(255, 255, 255, 0.08);
}

.border-b {
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.border-t {
  border-top: 1px solid rgba(255, 255, 255, 0.08);
}

.close-toast-btn {
  background: none;
  border: none;
  color: currentColor;
  opacity: 0.7;
  cursor: pointer;
  padding: 0.2rem 0.4rem;
}
.close-toast-btn:hover {
  opacity: 1;
}

.w-4 { width: 1rem; }
.h-4 { height: 1rem; }
.w-5 { width: 1.25rem; }
.h-5 { height: 1.25rem; }
.w-6 { width: 1.5rem; }
.h-6 { height: 1.5rem; }
</style>
