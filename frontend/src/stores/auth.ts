import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { authApi } from '@/api/auth'
import type { PortalUser, UserApiKey, UserLimitSnapshot } from '@/types/api'

export const useAuthStore = defineStore('auth', () => {
  const isLoggedIn = ref(false)
  const isLoading = ref(false)
  const lastCheckedAt = ref(0)
  const AUTH_CACHE_MS = 5000
  const user = ref<PortalUser | null>(null)
  const limits = ref<UserLimitSnapshot | null>(null)
  const keys = ref<UserApiKey[]>([])
  let checkPromise: Promise<boolean> | null = null

  const role = computed(() => user.value?.role || '')
  const isAdmin = computed(() => role.value === 'admin')

  function resetAuth() {
    isLoggedIn.value = false
    user.value = null
    limits.value = null
    keys.value = []
    lastCheckedAt.value = 0
  }

  async function refreshMe() {
    const res = await authApi.me()
    isLoggedIn.value = true
    user.value = res.user
    limits.value = res.limits
    keys.value = res.keys || []
    lastCheckedAt.value = Date.now()
  }

  async function login(username: string, password: string) {
    isLoading.value = true
    try {
      await authApi.login({ username, password })
      await refreshMe()
      return true
    } catch (error) {
      resetAuth()
      throw error
    } finally {
      isLoading.value = false
    }
  }

  async function register(username: string, password: string) {
    return await authApi.register({ username, password })
  }

  async function logout() {
    try {
      await authApi.logout()
    } finally {
      resetAuth()
    }
  }

  async function checkAuth() {
    const now = Date.now()
    if (isLoggedIn.value && now - lastCheckedAt.value < AUTH_CACHE_MS) {
      return true
    }
    if (checkPromise) {
      return checkPromise
    }
    try {
      checkPromise = (async () => {
        await refreshMe()
        return true
      })()
      return await checkPromise
    } catch {
      resetAuth()
      return false
    } finally {
      checkPromise = null
    }
  }

  return {
    isLoggedIn,
    isLoading,
    user,
    limits,
    keys,
    role,
    isAdmin,
    resetAuth,
    refreshMe,
    login,
    register,
    logout,
    checkAuth,
  }
})
