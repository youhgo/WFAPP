import { ref } from 'vue'

export const user = ref(null)
export const isAuthenticated = ref(false)
export const isAuthInitialized = ref(false)

export async function checkAuth(force = false) {
  if (isAuthInitialized.value && !force) {
    return isAuthenticated.value
  }

  try {
    const res = await fetch('/api/me')
    if (res.ok) {
      const data = await res.json()
      user.value = data
      isAuthenticated.value = true
      isAuthInitialized.value = true
      return true
    }
  } catch (err) {
    console.error('Failed to verify session', err)
  }

  user.value = null
  isAuthenticated.value = false
  isAuthInitialized.value = true
  return false
}

export function setAuthenticated(userData) {
  user.value = userData
  isAuthenticated.value = true
  isAuthInitialized.value = true
}

export function setLoggedOut() {
  user.value = null
  isAuthenticated.value = false
  isAuthInitialized.value = true
}
