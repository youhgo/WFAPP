<template>
  <div id="app">
    <!-- Main Navbar -->
    <nav v-if="!isLoginPage" class="navbar glass-panel">
      <div class="container d-flex justify-between align-center nav-container">
        <!-- Brand -->
        <router-link to="/" class="brand text-decoration-none">
          <div class="brand-logo-glow">
            <svg class="logo-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
            </svg>
          </div>
          <div class="brand-titles">
            <span class="brand-text">WFAPP <span class="brand-sub">Platform</span></span>
            <span class="brand-sub-badge">DFIR Engine</span>
          </div>
        </router-link>

        <!-- Navigation Links -->
        <div class="nav-links">
          <router-link to="/" class="nav-link" active-class="nav-active" exact>
            <svg class="nav-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
            </svg>
            Dashboard
          </router-link>

          <router-link to="/downloads" class="nav-link" active-class="nav-active">
            <svg class="nav-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Binaires DFIR-ORC
          </router-link>

          <router-link to="/users" class="nav-link" active-class="nav-active">
            <svg class="nav-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
            </svg>
            Utilisateurs & Clés API
          </router-link>
        </div>

        <!-- User profile & Logout -->
        <div class="user-actions d-flex align-center gap-3">
          <router-link to="/users" v-if="user" class="user-pill d-flex align-center gap-2 text-decoration-none" title="Mon Profil & Clé API">
            <div class="user-avatar-dot" :class="{ 'admin-dot': user.is_admin }">
              {{ user.username ? user.username.charAt(0).toUpperCase() : 'U' }}
            </div>
            <div class="user-info-text d-none-sm">
              <span class="user-name">{{ user.username }}</span>
              <span class="user-role-text">{{ user.is_admin ? 'Admin' : 'Utilisateur' }}</span>
            </div>
          </router-link>

          <button @click="logout" class="btn btn-secondary btn-sm logout-btn" title="Se déconnecter">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
            </svg>
            Déconnexion
          </button>
        </div>
      </div>
    </nav>
    
    <!-- Router View -->
    <main class="main-content">
      <router-view v-slot="{ Component }">
        <transition name="fade" mode="out-in">
          <component :is="Component" />
        </transition>
      </router-view>
    </main>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { user, setLoggedOut } from './auth'

const route = useRoute()
const router = useRouter()

const isLoginPage = computed(() => route.path === '/login_page')

const logout = async () => {
  try {
    await fetch('/api/logout', { method: 'POST' })
  } catch (e) {
    console.error('Logout failed', e)
  } finally {
    setLoggedOut()
    router.push('/login_page')
  }
}
</script>

<style scoped>
.navbar {
  position: sticky;
  top: 0;
  z-index: 50;
  margin-bottom: 2rem;
  border-radius: 0;
  border-top: none;
  border-left: none;
  border-right: none;
  background: rgba(15, 23, 42, 0.85);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.nav-container {
  padding: 0.85rem 2rem;
}

.brand {
  display: flex;
  align-items: center;
  gap: 0.85rem;
}

.brand-logo-glow {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  background: linear-gradient(135deg, rgba(99, 102, 241, 0.25) 0%, rgba(168, 85, 247, 0.25) 100%);
  border: 1px solid rgba(99, 102, 241, 0.4);
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 0 15px rgba(99, 102, 241, 0.3);
}

.logo-icon {
  width: 22px;
  height: 22px;
  color: #a5b4fc;
}

.brand-titles {
  display: flex;
  flex-direction: column;
}

.brand-text {
  font-size: 1.15rem;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: #ffffff;
  line-height: 1.2;
}

.brand-sub {
  font-weight: 400;
  color: var(--accent-color);
}

.brand-sub-badge {
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-secondary);
  font-weight: 600;
}

.nav-links {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.nav-link {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  padding: 0.5rem 0.9rem;
  border-radius: var(--radius-md);
  color: var(--text-secondary);
  text-decoration: none;
  font-weight: 500;
  font-size: 0.9rem;
  transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
}

.nav-link:hover {
  color: #ffffff;
  background: rgba(255, 255, 255, 0.05);
}

.nav-link.nav-active {
  color: #ffffff;
  background: rgba(99, 102, 241, 0.2);
  border: 1px solid rgba(99, 102, 241, 0.4);
  box-shadow: 0 0 12px rgba(99, 102, 241, 0.2);
}

.nav-icon {
  width: 17px;
  height: 17px;
  opacity: 0.85;
}

.nav-link.nav-active .nav-icon {
  color: #a5b4fc;
  opacity: 1;
}

.user-pill {
  padding: 0.35rem 0.75rem;
  border-radius: 9999px;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.08);
  transition: all 0.2s;
  cursor: pointer;
}

.user-pill:hover {
  background: rgba(255, 255, 255, 0.08);
  border-color: rgba(99, 102, 241, 0.3);
}

.user-avatar-dot {
  width: 26px;
  height: 26px;
  border-radius: 50%;
  background: #334155;
  color: #cbd5e1;
  font-size: 0.75rem;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
}

.user-avatar-dot.admin-dot {
  background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
  color: white;
}

.user-info-text {
  display: flex;
  flex-direction: column;
  line-height: 1.1;
  text-align: left;
}

.user-name {
  font-size: 0.8rem;
  font-weight: 600;
  color: #f1f5f9;
}

.user-role-text {
  font-size: 0.65rem;
  color: var(--text-secondary);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.text-decoration-none {
  text-decoration: none;
}

.logout-btn {
  padding: 0.4rem 0.85rem;
  font-size: 0.85rem;
  border-radius: var(--radius-md);
}

.main-content {
  min-height: calc(100vh - 100px);
  padding-bottom: 3rem;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
  transform: translateY(4px);
}

@media (max-width: 860px) {
  .nav-container {
    padding: 0.75rem 1rem;
    flex-wrap: wrap;
    gap: 0.75rem;
  }
  
  .nav-links {
    order: 3;
    width: 100%;
    justify-content: space-around;
    overflow-x: auto;
  }

  .d-none-sm {
    display: none;
  }
}
</style>

