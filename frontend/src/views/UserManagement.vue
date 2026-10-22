<template>
  <div class="container animate-fade-in user-management-page">
    <!-- Header -->
    <header class="page-header mb-4">
      <div class="d-flex align-center justify-between flex-wrap gap-2">
        <div>
          <h1 class="text-2xl font-bold m-0 d-flex align-center gap-2">
            <svg class="header-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
            </svg>
            Gestion des Utilisateurs & Clés API
          </h1>
          <p class="text-muted mt-1">Consultez votre profil, gérez votre clé d'API personnelle et administrez les comptes d'accès.</p>
        </div>
        <div class="d-flex align-center gap-2">
          <button @click="refreshAll" class="btn btn-secondary btn-sm" title="Rafraîchir les données">
            <svg class="w-4 h-4 mr-1" :class="{ 'animate-spin': isRefreshing }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Rafraîchir
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

    <div class="user-layout-grid">
      <!-- Section 1: Mon Profil & Ma Clé d'API -->
      <section class="glass-panel p-4 profile-card">
        <div class="card-header d-flex justify-between align-center mb-3 pb-2 border-b">
          <h2 class="text-lg font-bold m-0 d-flex align-center gap-2">
            <svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
            </svg>
            Mon Profil
          </h2>
          <span :class="['badge', myProfile?.is_admin ? 'badge-indigo' : 'badge-slate']">
            {{ myProfile?.is_admin ? 'Administrateur' : 'Utilisateur' }}
          </span>
        </div>

        <div class="profile-details mb-4">
          <div class="d-flex align-center gap-3 mb-3">
            <div class="avatar-circle">
              {{ myProfile?.username ? myProfile.username.charAt(0).toUpperCase() : 'U' }}
            </div>
            <div>
              <div class="text-xs text-muted">Nom d'utilisateur</div>
              <div class="text-lg font-bold text-white">{{ myProfile?.username || 'Chargement...' }}</div>
              <div class="text-xs text-muted">Identifiant unique : #{{ myProfile?.id || '-' }}</div>
            </div>
          </div>

          <!-- API Key section -->
          <div class="api-key-box p-3 rounded-lg border">
            <div class="d-flex justify-between align-center mb-2">
              <label class="text-xs font-semibold uppercase tracking-wider text-muted d-flex align-center gap-1">
                <svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                </svg>
                Ma Clé API Personnelle
              </label>
              <button 
                v-if="myProfile?.api_key" 
                @click="isKeyRevealed = !isKeyRevealed" 
                class="btn-text-sm text-muted hover:text-white"
              >
                {{ isKeyRevealed ? 'Masquer' : 'Afficher' }}
              </button>
            </div>

            <div v-if="myProfile?.api_key" class="key-display-wrapper d-flex align-center gap-2">
              <div 
                class="key-code flex-1 font-mono text-sm" 
                :class="{ 'blur-key': !isKeyRevealed, 'revealed': isKeyRevealed }"
                @click="isKeyRevealed = !isKeyRevealed"
                title="Cliquez pour afficher ou masquer"
              >
                {{ myProfile.api_key }}
              </div>
              <button 
                @click="copyToClipboard(myProfile.api_key)" 
                class="btn btn-secondary btn-sm shrink-0" 
                :title="isCopied ? 'Copié !' : 'Copier dans le presse-papiers'"
              >
                <svg v-if="!isCopied" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
                </svg>
                <span v-else class="text-emerald-400 font-bold">✓</span>
                <span class="ml-1 text-xs">{{ isCopied ? 'Copié' : 'Copier' }}</span>
              </button>
            </div>
            <div v-else class="text-sm text-muted italic py-1">
              Aucune clé API active configurée pour votre compte.
            </div>

            <p class="text-xs text-muted mt-2">
              Cette clé secrète permet d'automatiser vos soumissions DFIR par script ou curl sans passer par l'interface web.
            </p>
          </div>

          <!-- API Key Actions -->
          <div class="d-flex gap-2 mt-3 flex-wrap">
            <button 
              @click="manageMyApiKey('generate')" 
              class="btn btn-primary btn-sm flex-1" 
              :disabled="isKeyLoading"
            >
              <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              {{ myProfile?.api_key ? 'Régénérer une clé' : 'Générer une clé API' }}
            </button>
            <button 
              v-if="myProfile?.api_key" 
              @click="manageMyApiKey('revoke')" 
              class="btn btn-danger btn-sm shrink-0" 
              :disabled="isKeyLoading"
            >
              Révoquer
            </button>
          </div>
        </div>

        <!-- Documentation API Callout -->
        <div class="api-doc-box mt-4 p-3 rounded-lg">
          <div class="text-xs font-bold uppercase tracking-wider text-indigo-300 mb-1 d-flex align-center gap-1">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
            </svg>
            Utilisation en ligne de commande
          </div>
          <p class="text-xs text-muted mb-2">Transmettez votre clé soit via l'en-tête <code>X-API-Key</code>, soit via <code>Authorization: Bearer</code> :</p>
          <div class="code-box text-xs">
            <span class="text-muted"># Exemple de soumission d'une archive ORC via cURL</span><br />
            curl -k -X POST https://wfapp/api/parse/parse_ogre \<br />
            &nbsp;&nbsp;-H <span class="text-emerald-400">"X-API-Key: {{ myProfile?.api_key || '$VOTRE_CLE' }}"</span> \<br />
            &nbsp;&nbsp;-F <span class="text-amber-300">"file=@evidence.7z"</span> \<br />
            &nbsp;&nbsp;-F <span class="text-amber-300">'json={"caseName":"incident_01","archiveType":"ORC"}'</span>
          </div>
        </div>
      </section>

      <!-- Section 2: Administration des Utilisateurs (Admin Only) -->
      <section v-if="myProfile?.is_admin" class="glass-panel p-4 admin-section">
        <div class="card-header d-flex justify-between align-center mb-3 pb-2 border-b flex-wrap gap-2">
          <div class="d-flex align-center gap-2">
            <h2 class="text-lg font-bold m-0 d-flex align-center gap-2">
              <svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
              </svg>
              Administration des Utilisateurs
            </h2>
            <span class="badge badge-emerald">{{ users.length }} utilisateur(s)</span>
          </div>

          <div class="d-flex align-center gap-2">
            <div class="search-input-wrapper">
              <input 
                v-model="userSearchQuery" 
                type="text" 
                placeholder="Filtrer utilisateurs..." 
                class="input-field search-input"
              />
            </div>
            <button @click="openAddModal" class="btn btn-primary btn-sm d-flex align-center gap-1">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
              </svg>
              Ajouter
            </button>
          </div>
        </div>

        <!-- Users Table -->
        <div class="table-container">
          <table class="custom-table">
            <thead>
              <tr>
                <th>Utilisateur</th>
                <th>Rôle</th>
                <th>Clé API</th>
                <th class="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="filteredUsers.length === 0">
                <td colspan="4" class="text-center py-6 text-muted">
                  {{ userSearchQuery ? 'Aucun utilisateur ne correspond à votre recherche.' : 'Aucun utilisateur trouvé.' }}
                </td>
              </tr>
              <tr v-for="u in filteredUsers" :key="u.id">
                <td>
                  <div class="d-flex align-center gap-2">
                    <div class="user-avatar-mini" :class="{ 'admin-avatar': u.is_admin }">
                      {{ u.username.charAt(0).toUpperCase() }}
                    </div>
                    <div>
                      <div class="font-semibold text-white d-flex align-center gap-1">
                        {{ u.username }}
                        <span v-if="u.id === myProfile?.id" class="text-xs text-indigo-400 font-normal">(vous)</span>
                      </div>
                      <div class="text-xs text-muted">ID: #{{ u.id }}</div>
                    </div>
                  </div>
                </td>
                <td>
                  <span :class="['badge', u.is_admin ? 'badge-indigo' : 'badge-slate']">
                    {{ u.is_admin ? 'Admin' : 'Standard' }}
                  </span>
                </td>
                <td>
                  <div v-if="u.api_key" class="d-flex align-center gap-1">
                    <span 
                      class="font-mono text-xs blur-key key-pill" 
                      @click="$event.target.classList.toggle('revealed')"
                      title="Cliquez pour révéler"
                    >
                      {{ u.api_key }}
                    </span>
                    <button 
                      @click="copyToClipboard(u.api_key)" 
                      class="copy-mini-btn" 
                      title="Copier la clé"
                    >
                      📋
                    </button>
                  </div>
                  <span v-else class="text-xs text-muted italic">Aucune</span>
                </td>
                <td class="text-right">
                  <div class="d-flex justify-end gap-1">
                    <button 
                      @click="openEditModal(u)" 
                      class="btn btn-secondary btn-xs" 
                      title="Modifier l'utilisateur"
                    >
                      Gérer
                    </button>
                    <button 
                      v-if="u.id !== myProfile?.id" 
                      @click="confirmDeleteUser(u)" 
                      class="btn btn-danger btn-xs" 
                      title="Supprimer l'utilisateur"
                    >
                      Supprimer
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <!-- Placeholder if not admin -->
      <section v-else class="glass-panel p-4 d-flex flex-col justify-center align-center text-center">
        <div class="w-16 h-16 rounded-full bg-slate-800 d-flex align-center justify-center mb-3">
          <svg class="w-8 h-8 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
        </div>
        <h3 class="text-lg font-bold text-slate-300 mb-1">Administration réservée</h3>
        <p class="text-sm text-muted max-w-sm">
          Vous êtes connecté en tant qu'utilisateur standard. L'ajout, la modification globale des comptes et la révocation des accès tiers nécessitent les privilèges d'administrateur.
        </p>
      </section>
    </div>

    <!-- Modal: Ajouter un utilisateur -->
    <div v-if="modals.add" class="modal-overlay" @click.self="modals.add = false">
      <div class="modal-dialog">
        <div class="modal-header">
          <h3 class="text-lg font-bold m-0 d-flex align-center gap-2">
            <svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z" />
            </svg>
            Ajouter un nouvel utilisateur
          </h3>
          <button @click="modals.add = false" class="close-btn text-muted hover:text-white">✕</button>
        </div>
        <form @submit.prevent="submitAddUser">
          <div class="modal-body">
            <div class="mb-3">
              <label class="block text-xs font-semibold uppercase tracking-wider text-muted mb-1">Nom d'utilisateur *</label>
              <input 
                v-model="addForm.username" 
                type="text" 
                required 
                placeholder="ex: analyst_forensic" 
                class="input-field" 
              />
            </div>
            <div class="mb-3">
              <label class="block text-xs font-semibold uppercase tracking-wider text-muted mb-1">Mot de passe *</label>
              <input 
                v-model="addForm.password" 
                type="password" 
                required 
                placeholder="••••••••••••" 
                class="input-field" 
              />
            </div>
            <div class="d-flex align-center gap-2 p-3 rounded-lg border bg-slate-900/40">
              <input 
                v-model="addForm.is_admin" 
                type="checkbox" 
                id="addAdminCheckbox" 
                class="checkbox-input"
              />
              <label for="addAdminCheckbox" class="text-sm font-medium text-slate-200 cursor-pointer">
                Attribuer les privilèges d'administrateur
              </label>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" @click="modals.add = false" class="btn btn-secondary btn-sm">Annuler</button>
            <button type="submit" class="btn btn-primary btn-sm" :disabled="isSubmitting">
              {{ isSubmitting ? 'Création...' : 'Créer le compte' }}
            </button>
          </div>
        </form>
      </div>
    </div>

    <!-- Modal: Gérer / Modifier un utilisateur -->
    <div v-if="modals.edit" class="modal-overlay" @click.self="modals.edit = false">
      <div class="modal-dialog">
        <div class="modal-header">
          <h3 class="text-lg font-bold m-0 d-flex align-center gap-2">
            <svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
            </svg>
            Gérer le compte : {{ editForm.username }}
          </h3>
          <button @click="modals.edit = false" class="close-btn text-muted hover:text-white">✕</button>
        </div>
        <form @submit.prevent="submitEditUser">
          <div class="modal-body">
            <div class="mb-3">
              <label class="block text-xs font-semibold uppercase tracking-wider text-muted mb-1">Nom d'utilisateur</label>
              <input 
                v-model="editForm.username" 
                type="text" 
                required 
                class="input-field" 
              />
            </div>
            <div class="mb-3">
              <label class="block text-xs font-semibold uppercase tracking-wider text-muted mb-1">
                Nouveau mot de passe <span class="text-muted font-normal">(laisser vide pour conserver l'actuel)</span>
              </label>
              <input 
                v-model="editForm.password" 
                type="password" 
                placeholder="Laisser vide pour ne pas modifier" 
                class="input-field" 
              />
            </div>
            <div class="d-flex align-center gap-2 p-3 rounded-lg border bg-slate-900/40 mb-4">
              <input 
                v-model="editForm.is_admin" 
                type="checkbox" 
                id="editAdminCheckbox" 
                class="checkbox-input"
              />
              <label for="editAdminCheckbox" class="text-sm font-medium text-slate-200 cursor-pointer">
                Privilèges d'administrateur
              </label>
            </div>

            <!-- Gestion clé API -->
            <div class="border-t pt-3">
              <label class="block text-xs font-semibold uppercase tracking-wider text-muted mb-2">
                Gestion de la Clé API
              </label>
              <div class="p-3 rounded-lg border bg-slate-900/60 mb-3">
                <div class="text-xs text-muted mb-1">Clé actuelle enregistrée :</div>
                <div class="font-mono text-xs text-slate-200 break-all">
                  {{ editForm.current_api_key || 'Aucune clé configurée' }}
                </div>
              </div>

              <div class="d-flex gap-2 flex-wrap mb-3">
                <button 
                  type="button" 
                  @click="editKeyAction = 'none'" 
                  :class="['btn btn-xs flex-1', editKeyAction === 'none' ? 'btn-primary' : 'btn-secondary']"
                >
                  Ne pas changer
                </button>
                <button 
                  type="button" 
                  @click="editKeyAction = 'generate'" 
                  :class="['btn btn-xs flex-1', editKeyAction === 'generate' ? 'btn-primary' : 'btn-secondary']"
                >
                  Régénérer auto
                </button>
                <button 
                  type="button" 
                  @click="editKeyAction = 'revoke'" 
                  :class="['btn btn-xs flex-1', editKeyAction === 'revoke' ? 'btn-danger' : 'btn-secondary']"
                >
                  Révoquer
                </button>
                <button 
                  type="button" 
                  @click="editKeyAction = 'custom'" 
                  :class="['btn btn-xs flex-1', editKeyAction === 'custom' ? 'btn-primary' : 'btn-secondary']"
                >
                  Clé personnalisée
                </button>
              </div>

              <div v-if="editKeyAction === 'custom'" class="animate-fade-in mb-2">
                <label class="block text-xs font-medium text-slate-300 mb-1">Entrez la clé personnalisée :</label>
                <input 
                  v-model="editForm.custom_api_key" 
                  type="text" 
                  placeholder="ex: wfapp-secret-uuid-or-token" 
                  class="input-field" 
                  required
                />
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" @click="modals.edit = false" class="btn btn-secondary btn-sm">Annuler</button>
            <button type="submit" class="btn btn-primary btn-sm" :disabled="isSubmitting">
              {{ isSubmitting ? 'Enregistrement...' : 'Enregistrer' }}
            </button>
          </div>
        </form>
      </div>
    </div>

    <!-- Modal: Confirmation Suppression -->
    <div v-if="modals.delete" class="modal-overlay" @click.self="modals.delete = false">
      <div class="modal-dialog max-w-sm">
        <div class="modal-body text-center pt-5">
          <div class="w-12 h-12 rounded-full bg-rose-500/20 text-rose-400 d-flex align-center justify-center mx-auto mb-3">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
          </div>
          <h3 class="text-lg font-bold text-white mb-2">Supprimer l'utilisateur ?</h3>
          <p class="text-sm text-muted">
            Êtes-vous certain de vouloir supprimer définitivement le compte de 
            <strong class="text-white">{{ userToDelete?.username }}</strong> ? 
            Cette action est irréversible.
          </p>
        </div>
        <div class="modal-footer justify-center">
          <button type="button" @click="modals.delete = false" class="btn btn-secondary btn-sm">Annuler</button>
          <button type="button" @click="executeDeleteUser" class="btn btn-danger btn-sm" :disabled="isSubmitting">
            {{ isSubmitting ? 'Suppression...' : 'Supprimer définitivement' }}
          </button>
        </div>
      </div>
    </div>

  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { user as authUser, setLoggedOut } from '../auth'

const router = useRouter()

// State
const myProfile = ref(null)
const users = ref([])
const isKeyRevealed = ref(false)
const isCopied = ref(false)
const isRefreshing = ref(false)
const isKeyLoading = ref(false)
const isSubmitting = ref(false)
const userSearchQuery = ref('')

// Toast notifications
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

// Modals State
const modals = ref({
  add: false,
  edit: false,
  delete: false
})

// Forms
const addForm = ref({
  username: '',
  password: '',
  is_admin: false
})

const editForm = ref({
  id: null,
  username: '',
  password: '',
  is_admin: false,
  current_api_key: '',
  custom_api_key: ''
})

const editKeyAction = ref('none') // 'none' | 'generate' | 'revoke' | 'custom'
const userToDelete = ref(null)

// Computed
const filteredUsers = computed(() => {
  if (!userSearchQuery.value.trim()) return users.value
  const query = userSearchQuery.value.toLowerCase()
  return users.value.filter(u => 
    u.username.toLowerCase().includes(query) ||
    (u.is_admin ? 'admin' : 'standard').includes(query)
  )
})

// Fetch Profile
const fetchProfile = async () => {
  try {
    const res = await fetch('/api/me')
    if (res.status === 401) {
      setLoggedOut()
      router.push('/login_page')
      return
    }
    if (res.ok) {
      const data = await res.json()
      myProfile.value = data
      // Update global authUser
      authUser.value = data
      if (data.is_admin) {
        fetchUsers()
      }
    }
  } catch (err) {
    console.error('Failed to load profile', err)
    showToast('Erreur lors du chargement du profil.', 'error')
  }
}

// Fetch Users (admin only)
const fetchUsers = async () => {
  try {
    const res = await fetch('/api/users')
    if (res.ok) {
      users.value = await res.json()
    }
  } catch (err) {
    console.error('Failed to load users', err)
  }
}

const refreshAll = async () => {
  isRefreshing.value = true
  await fetchProfile()
  isRefreshing.value = false
  showToast('Données synchronisées avec succès.', 'success')
}

// Manage My API Key
const manageMyApiKey = async (action) => {
  if (action === 'revoke' && !confirm('Êtes-vous sûr de vouloir révoquer votre clé API ? Vos intégrations externes cesseront immédiatement de fonctionner.')) {
    return
  }

  isKeyLoading.value = true
  try {
    const res = await fetch('/api/me/api_key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action })
    })

    const data = await res.json()
    if (res.ok) {
      showToast(
        action === 'generate' ? 'Nouvelle clé API générée avec succès !' : 'Clé API révoquée.', 
        'success'
      )
      await fetchProfile()
      isKeyRevealed.value = true
    } else {
      showToast(data.message || 'Échec de la mise à jour de la clé API.', 'error')
    }
  } catch (e) {
    showToast('Erreur réseau lors de la mise à jour.', 'error')
  } finally {
    isKeyLoading.value = false
  }
}

// Copy to Clipboard
const copyToClipboard = async (text) => {
  if (!text) return
  try {
    await navigator.clipboard.writeText(text)
    isCopied.value = true
    showToast('Clé copiée dans le presse-papiers !', 'success')
    setTimeout(() => {
      isCopied.value = false
    }, 2500)
  } catch (e) {
    showToast('Impossible de copier automatiquement.', 'error')
  }
}

// Add User
const openAddModal = () => {
  addForm.value = { username: '', password: '', is_admin: false }
  modals.value.add = true
}

const submitAddUser = async () => {
  isSubmitting.value = true
  try {
    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: addForm.value.username,
        password: addForm.value.password
      })
    })

    const data = await res.json()
    if (res.ok) {
      // If admin privileges were checked, update user to admin
      if (addForm.value.is_admin) {
        // Refresh users to get the new user ID
        const usersRes = await fetch('/api/users')
        if (usersRes.ok) {
          const allUsers = await usersRes.json()
          const createdUser = allUsers.find(u => u.username === addForm.value.username)
          if (createdUser) {
            await fetch(`/api/users/${createdUser.id}`, {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ is_admin: true })
            })
          }
        }
      }

      showToast(`Utilisateur "${addForm.value.username}" créé avec succès !`, 'success')
      modals.value.add = false
      await fetchUsers()
    } else {
      showToast(data.message || "Erreur lors de la création de l'utilisateur.", 'error')
    }
  } catch (err) {
    showToast('Erreur réseau lors de la création.', 'error')
  } finally {
    isSubmitting.value = false
  }
}

// Edit User
const openEditModal = (user) => {
  editForm.value = {
    id: user.id,
    username: user.username,
    password: '',
    is_admin: user.is_admin,
    current_api_key: user.api_key || '',
    custom_api_key: ''
  }
  editKeyAction.value = 'none'
  modals.value.edit = true
}

const submitEditUser = async () => {
  isSubmitting.value = true
  try {
    const payload = {
      username: editForm.value.username,
      is_admin: editForm.value.is_admin
    }

    if (editForm.value.password.trim()) {
      payload.password = editForm.value.password.trim()
    }

    if (editKeyAction.value === 'generate') {
      payload.generate_api_key = true
    } else if (editKeyAction.value === 'revoke') {
      payload.revoke_api_key = true
    } else if (editKeyAction.value === 'custom') {
      payload.api_key = editForm.value.custom_api_key.trim()
    }

    const res = await fetch(`/api/users/${editForm.value.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })

    const data = await res.json()
    if (res.ok) {
      showToast(`Compte "${editForm.value.username}" mis à jour avec succès.`, 'success')
      modals.value.edit = false
      await fetchUsers()
      if (editForm.value.id === myProfile.value?.id) {
        await fetchProfile()
      }
    } else {
      showToast(data.message || 'Erreur lors de la mise à jour.', 'error')
    }
  } catch (err) {
    showToast('Erreur réseau.', 'error')
  } finally {
    isSubmitting.value = false
  }
}

// Delete User
const confirmDeleteUser = (user) => {
  userToDelete.value = user
  modals.value.delete = true
}

const executeDeleteUser = async () => {
  if (!userToDelete.value) return
  isSubmitting.value = true
  try {
    const res = await fetch(`/api/users/${userToDelete.value.id}`, {
      method: 'DELETE'
    })
    if (res.ok) {
      showToast(`Utilisateur "${userToDelete.value.username}" supprimé.`, 'success')
      modals.value.delete = false
      userToDelete.value = null
      await fetchUsers()
    } else {
      showToast('Impossible de supprimer cet utilisateur.', 'error')
    }
  } catch (err) {
    showToast('Erreur réseau.', 'error')
  } finally {
    isSubmitting.value = false
  }
}

onMounted(() => {
  fetchProfile()
})
</script>

<style scoped>
.user-layout-grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: 2rem;
}

@media (min-width: 1024px) {
  .user-layout-grid {
    grid-template-columns: 420px 1fr;
  }
}

.header-icon {
  width: 28px;
  height: 28px;
  color: var(--accent-color);
}

.avatar-circle {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 1.25rem;
  color: white;
  box-shadow: 0 4px 12px rgba(99, 102, 241, 0.4);
}

.user-avatar-mini {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.1);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.85rem;
  font-weight: 600;
  color: #cbd5e1;
}

.user-avatar-mini.admin-avatar {
  background: rgba(99, 102, 241, 0.2);
  color: #a5b4fc;
  border: 1px solid rgba(99, 102, 241, 0.4);
}

.api-key-box {
  background: rgba(15, 23, 42, 0.6);
  border-color: rgba(255, 255, 255, 0.08);
}

.key-display-wrapper {
  background: rgba(2, 6, 23, 0.8);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: var(--radius-md);
  padding: 0.5rem 0.75rem;
}

.key-code {
  color: #38bdf8;
  word-break: break-all;
}

.key-pill {
  background: rgba(15, 23, 42, 0.8);
  border: 1px solid rgba(255, 255, 255, 0.08);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  color: #94a3b8;
  max-width: 140px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  display: inline-block;
}

.copy-mini-btn {
  background: none;
  border: none;
  cursor: pointer;
  padding: 0.2rem;
  font-size: 0.85rem;
  opacity: 0.7;
  transition: opacity 0.2s;
}

.copy-mini-btn:hover {
  opacity: 1;
}

.btn-text-sm {
  background: none;
  border: none;
  font-size: 0.75rem;
  cursor: pointer;
}

.btn-xs {
  padding: 0.25rem 0.6rem;
  font-size: 0.75rem;
}

.search-input {
  padding: 0.4rem 0.75rem;
  font-size: 0.85rem;
  width: 180px;
}

.checkbox-input {
  width: 18px;
  height: 18px;
  accent-color: var(--accent-color);
  cursor: pointer;
}

.api-doc-box {
  background: rgba(99, 102, 241, 0.05);
  border: 1px dashed rgba(99, 102, 241, 0.25);
}

.table-container {
  overflow-x: auto;
  margin-top: 0.5rem;
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

.border-b {
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.border-t {
  border-top: 1px solid rgba(255, 255, 255, 0.08);
}

.w-4 { width: 1rem; }
.h-4 { height: 1rem; }
.w-5 { width: 1.25rem; }
.h-5 { height: 1.25rem; }
.w-6 { width: 1.5rem; }
.h-6 { height: 1.5rem; }
.w-12 { width: 3rem; }
.h-12 { height: 3rem; }
.w-16 { width: 4rem; }
.h-16 { height: 4rem; }
</style>
