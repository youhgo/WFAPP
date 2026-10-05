<template>
  <div class="login-wrapper d-flex align-center justify-center">
    <div class="login-card glass-panel animate-fade-in">
      <div class="login-header text-center mb-3">
        <div class="logo-circle mx-auto mb-2">
          <svg class="logo-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
          </svg>
        </div>
        <h2>Welcome to WFAPP</h2>
        <p class="text-muted text-sm mt-1">Sign in to access your DFIR pipelines</p>
      </div>

      <form @submit.prevent="handleLogin" class="d-flex flex-col gap-2">
        <div class="form-group">
          <label class="text-sm font-medium text-muted">Username</label>
          <input 
            type="text" 
            v-model="username" 
            class="input-field mt-1" 
            placeholder="Enter your username" 
            required 
          />
        </div>
        
        <div class="form-group">
          <label class="text-sm font-medium text-muted">Password</label>
          <input 
            type="password" 
            v-model="password" 
            class="input-field mt-1" 
            placeholder="••••••••" 
            required 
          />
        </div>

        <div v-if="errorMsg" class="error-alert mt-1 text-sm">
          {{ errorMsg }}
        </div>

        <button type="submit" class="btn btn-primary mt-2" :disabled="isLoading">
          <span v-if="isLoading">Authenticating...</span>
          <span v-else>Sign In</span>
        </button>
      </form>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const username = ref('')
const password = ref('')
const errorMsg = ref('')
const isLoading = ref(false)

const handleLogin = async () => {
  errorMsg.value = ''
  isLoading.value = true
  
  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: username.value,
        password: password.value
      })
    })
    
    const data = await response.json()
    
    if (response.ok) {
      router.push('/')
    } else {
      errorMsg.value = data.message || 'Invalid credentials'
    }
  } catch (err) {
    errorMsg.value = 'Network error. Please try again.'
  } finally {
    isLoading.value = false
  }
}
</script>

<style scoped>
.login-wrapper {
  min-height: 100vh;
  padding: 1rem;
}

.login-card {
  width: 100%;
  max-width: 420px;
  padding: 2.5rem;
}

.logo-circle {
  width: 64px;
  height: 64px;
  background: rgba(99, 102, 241, 0.1);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto;
}

.logo-icon {
  width: 32px;
  height: 32px;
  color: var(--accent-color);
}

.error-alert {
  color: var(--danger);
  background: rgba(239, 68, 68, 0.1);
  padding: 0.75rem;
  border-radius: var(--radius-md);
  border: 1px solid rgba(239, 68, 68, 0.2);
  text-align: center;
}
</style>
