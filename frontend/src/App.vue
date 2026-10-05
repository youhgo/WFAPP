<template>
  <div id="app">
    <!-- Main Navbar -->
    <nav v-if="!isLoginPage" class="navbar glass-panel">
      <div class="container d-flex justify-between align-center" style="padding: 1rem 2rem;">
        <div class="brand">
          <svg class="logo-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
          </svg>
          <span class="brand-text">WFAPP <span class="brand-sub">Engine</span></span>
        </div>
        <div class="nav-links">
          <router-link to="/" class="nav-link">Dashboard</router-link>
          <button @click="logout" class="btn btn-secondary btn-sm">Logout</button>
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

const route = useRoute()
const router = useRouter()

const isLoginPage = computed(() => route.path === '/login_page')

const logout = async () => {
  try {
    const res = await fetch('/api/logout', { method: 'POST' })
    if (res.ok) {
      router.push('/login_page')
    }
  } catch (e) {
    console.error('Logout failed', e)
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
}

.brand {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.logo-icon {
  width: 28px;
  height: 28px;
  color: var(--accent-color);
}

.brand-text {
  font-size: 1.25rem;
  font-weight: 700;
  letter-spacing: -0.03em;
}

.brand-sub {
  font-weight: 400;
  color: var(--text-secondary);
}

.nav-links {
  display: flex;
  align-items: center;
  gap: 1.5rem;
}

.nav-link {
  color: var(--text-primary);
  text-decoration: none;
  font-weight: 500;
  font-size: 0.95rem;
  transition: var(--transition);
}

.nav-link:hover, .nav-link.router-link-active {
  color: var(--accent-color);
}

.btn-sm {
  padding: 0.4rem 1rem;
  font-size: 0.85rem;
}

.main-content {
  min-height: calc(100vh - 80px);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
