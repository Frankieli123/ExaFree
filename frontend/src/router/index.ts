import { createRouter, createWebHashHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = createRouter({
  history: createWebHashHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/public/uptime',
      name: 'public-uptime',
      component: () => import('@/views/PublicUptime.vue'),
      meta: { requiresAuth: false },
    },
    {
      path: '/public/logs',
      name: 'public-logs',
      component: () => import('@/views/PublicLogs.vue'),
      meta: { requiresAuth: false },
    },
    {
      path: '/login',
      name: 'login',
      component: () => import('@/views/Login.vue'),
      meta: { requiresAuth: false },
    },
    {
      path: '/',
      component: () => import('@/layouts/AppShell.vue'),
      meta: { requiresAuth: true },
      children: [
        {
          path: '',
          name: 'dashboard',
          component: () => import('@/views/Dashboard.vue'),
          meta: { roles: ['admin'] },
        },
        {
          path: 'accounts',
          name: 'accounts',
          component: () => import('@/views/Accounts.vue'),
          meta: { roles: ['admin'] },
        },
        {
          path: 'settings',
          name: 'settings',
          component: () => import('@/views/Settings.vue'),
          meta: { roles: ['admin'] },
        },
        {
          path: 'logs',
          name: 'logs',
          component: () => import('@/views/Logs.vue'),
          meta: { roles: ['admin'] },
        },
        {
          path: 'monitor',
          name: 'monitor',
          component: () => import('@/views/Monitor.vue'),
          meta: { roles: ['admin'] },
        },
        {
          path: 'docs',
          name: 'docs',
          component: () => import('@/views/Docs.vue'),
          meta: { roles: ['admin'] },
        },
        {
          path: 'users',
          name: 'users',
          component: () => import('@/views/Users.vue'),
          meta: { roles: ['admin'] },
        },
        {
          path: 'apikeys',
          name: 'apikeys',
          component: () => import('@/views/ApiKeys.vue'),
        },
        {
          path: 'profile',
          name: 'profile',
          component: () => import('@/views/Profile.vue'),
        },
      ],
    },
  ],
})

// 路由守卫
router.beforeEach(async (to) => {
  const authStore = useAuthStore()

  // 需要认证的路由
  if (to.meta.requiresAuth) {
    const isAuthenticated = await authStore.checkAuth()
    if (!isAuthenticated) {
      return { name: 'login' }
    }
    const allowedRoles = to.meta.roles as string[] | undefined
    if (allowedRoles && allowedRoles.length > 0) {
      const currentRole = authStore.role
      if (!allowedRoles.includes(currentRole)) {
        return authStore.isAdmin ? { name: 'dashboard' } : { name: 'apikeys' }
      }
    }
  }

  // 已登录用户访问登录页，重定向到首页
  if (to.name === 'login' && authStore.isLoggedIn) {
    return authStore.isAdmin ? { name: 'dashboard' } : { name: 'apikeys' }
  }
})

export default router
