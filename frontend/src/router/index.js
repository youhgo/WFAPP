import { createRouter, createWebHistory } from 'vue-router'
import Login from '../views/Login.vue'
import Dashboard from '../views/Dashboard.vue'

const routes = [
  {
    path: '/login_page',
    name: 'Login',
    component: Login
  },
  {
    path: '/',
    name: 'Dashboard',
    component: Dashboard,
    meta: { requiresAuth: true }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// Navigation Guard (Basic Example, will check for a token/cookie later if needed)
router.beforeEach((to, from, next) => {
  // Currently skipping strict auth check to allow testing the UI
  // Real implementation will verify session/cookie with Flask API
  next()
})

export default router
