import { createRouter, createWebHistory } from 'vue-router'
import Login from '../views/Login.vue'
import Dashboard from '../views/Dashboard.vue'

import { checkAuth } from '../auth'

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
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/'
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// Navigation Guard: redirects to /login_page if unauthenticated
router.beforeEach(async (to, from, next) => {
  const isAuthed = await checkAuth()

  if (to.matched.some(record => record.meta.requiresAuth)) {
    if (!isAuthed) {
      return next({ path: '/login_page', query: { redirect: to.fullPath } })
    }
    return next()
  }

  // If already logged in and visiting login page, redirect to Dashboard
  if (to.path === '/login_page' && isAuthed) {
    return next('/')
  }

  next()
})

export default router
