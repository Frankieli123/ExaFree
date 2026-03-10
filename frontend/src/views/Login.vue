<template>
  <div class="min-h-screen px-4">
    <div class="flex min-h-screen items-center justify-center">
      <div class="w-full max-w-md rounded-[2.5rem] border border-border bg-card p-10 shadow-2xl shadow-black/10">
        <div class="text-center">
          <h1 class="text-3xl font-semibold text-foreground">ExaFree</h1>
          <p class="mt-2 text-sm text-muted-foreground">用户/管理员登录</p>
        </div>

        <div class="mt-6 grid rounded-2xl border border-border bg-background p-1 text-sm" :class="canPasswordRegister ? 'grid-cols-2' : 'grid-cols-1'">
          <button
            class="rounded-xl py-2 transition-colors"
            :class="mode === 'login' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'"
            @click="mode = 'login'"
          >
            登录
          </button>
          <button
            v-if="canPasswordRegister"
            class="rounded-xl py-2 transition-colors"
            :class="mode === 'register' ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'"
            @click="mode = 'register'"
          >
            注册
          </button>
        </div>

        <form v-if="mode === 'login'" @submit.prevent="handleLogin" class="mt-6 space-y-4">
          <div class="space-y-2">
            <label class="block text-sm font-medium text-foreground">用户名</label>
            <input
              v-model="username"
              type="text"
              required
              class="w-full rounded-2xl border border-input bg-background px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              placeholder="admin 或普通用户名"
              :disabled="isLoading"
            />
          </div>
          <div class="space-y-2">
            <label class="block text-sm font-medium text-foreground">密码</label>
            <input
              v-model="password"
              type="password"
              required
              class="w-full rounded-2xl border border-input bg-background px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              placeholder="请输入密码"
              :disabled="isLoading"
            />
          </div>

          <div v-if="errorMessage" class="rounded-2xl bg-destructive/10 px-4 py-3 text-sm text-destructive">
            {{ errorMessage }}
          </div>

          <button
            type="submit"
            :disabled="isLoading || !username || !password"
            class="w-full rounded-2xl bg-primary py-3 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {{ isLoading ? '登录中...' : '登录' }}
          </button>

          <button
            v-if="canOauthLogin"
            type="button"
            :disabled="isLoading"
            class="w-full rounded-2xl border border-input bg-background py-3 text-sm font-medium text-foreground transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
            @click="handleLinuxdoOauth"
          >
            使用 Linux DO OAuth 登录
          </button>
        </form>

        <form v-else @submit.prevent="handleRegister" class="mt-6 space-y-4">
          <div v-if="!registrationEnabled" class="rounded-2xl bg-amber-500/10 px-4 py-3 text-sm text-amber-700">
            当前已关闭用户注册
          </div>
          <div class="space-y-2">
            <label class="block text-sm font-medium text-foreground">用户名</label>
            <input
              v-model="registerUsername"
              type="text"
              required
              class="w-full rounded-2xl border border-input bg-background px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              placeholder="3-32位: 字母数字_.-"
              :disabled="isLoading || !canPasswordRegister"
            />
          </div>
          <div class="space-y-2">
            <label class="block text-sm font-medium text-foreground">密码</label>
            <input
              v-model="registerPassword"
              type="password"
              required
              class="w-full rounded-2xl border border-input bg-background px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
              placeholder="8位以上"
              :disabled="isLoading || !canPasswordRegister"
            />
          </div>

          <div v-if="registerResult" class="rounded-2xl bg-emerald-500/10 px-4 py-3 text-xs text-emerald-600">
            注册成功，首个 API Key：{{ registerResult }}
          </div>
          <div v-if="errorMessage" class="rounded-2xl bg-destructive/10 px-4 py-3 text-sm text-destructive">
            {{ errorMessage }}
          </div>

          <button
            type="submit"
            :disabled="isLoading || !registerUsername || !registerPassword || !canPasswordRegister"
            class="w-full rounded-2xl bg-primary py-3 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {{ isLoading ? '提交中...' : '注册并获取 Key' }}
          </button>

          <button
            v-if="canOauthRegister || canOauthLogin"
            type="button"
            :disabled="isLoading"
            class="w-full rounded-2xl border border-input bg-background py-3 text-sm font-medium text-foreground transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
            @click="handleLinuxdoOauth"
          >
            使用 Linux DO OAuth 注册/登录
          </button>
        </form>

      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { authApi } from '@/api/auth'
import type { AuthOptionsResponse } from '@/types/api'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

const mode = ref<'login' | 'register'>('login')
const username = ref('admin')
const password = ref('')
const registerUsername = ref('')
const registerPassword = ref('')
const errorMessage = ref('')
const isLoading = ref(false)
const registerResult = ref('')

const authOptions = ref<AuthOptionsResponse | null>(null)

const registrationEnabled = computed(() => authOptions.value?.registration_enabled ?? true)
const canPasswordRegister = computed(
  () => (authOptions.value?.registration_enabled ?? true) && (authOptions.value?.password_registration_enabled ?? true)
)
const canOauthRegister = computed(
  () =>
    (authOptions.value?.registration_enabled ?? true) &&
    (authOptions.value?.linuxdo_oauth_registration_enabled ?? true) &&
    (authOptions.value?.linuxdo_oauth_ready ?? false)
)
const canOauthLogin = computed(() => authOptions.value?.linuxdo_oauth_login_enabled ?? false)

async function loadAuthOptions() {
  try {
    const options = await authApi.options()
    authOptions.value = options
    if (!canPasswordRegister.value && mode.value === 'register') {
      mode.value = 'login'
    }
  } catch {
    authOptions.value = {
      registration_enabled: true,
      password_registration_enabled: true,
      linuxdo_oauth_registration_enabled: true,
      linuxdo_oauth_login_enabled: false,
      linuxdo_oauth_ready: false,
      linuxdo_oauth_start_url: '/auth/linuxdo/start',
    }
  }
}

function applyOauthErrorFromQuery() {
  const rawError = route.query.oauth_error
  if (!rawError) return
  const text = Array.isArray(rawError) ? rawError[0] : rawError
  if (!text) return
  errorMessage.value = decodeURIComponent(String(text))
}

async function handleLinuxdoOauth() {
  const startUrl = authOptions.value?.linuxdo_oauth_start_url || '/auth/linuxdo/start'
  window.location.href = startUrl
}

async function handleLogin() {
  if (!username.value || !password.value) return
  errorMessage.value = ''
  isLoading.value = true
  try {
    await authStore.login(username.value, password.value)
    if (authStore.isAdmin) {
      router.push({ name: 'dashboard' })
    } else {
      router.push({ name: 'apikeys' })
    }
  } catch (error: any) {
    errorMessage.value = error.message || '登录失败'
  } finally {
    isLoading.value = false
  }
}

async function handleRegister() {
  if (!canPasswordRegister.value) {
    errorMessage.value = '当前未启用账号密码注册'
    return
  }
  if (!registerUsername.value || !registerPassword.value) return
  errorMessage.value = ''
  registerResult.value = ''
  isLoading.value = true
  try {
    const res = await authStore.register(registerUsername.value, registerPassword.value)
    registerResult.value = res.api_key || ''
    mode.value = 'login'
    username.value = registerUsername.value
    password.value = ''
  } catch (error: any) {
    errorMessage.value = error.message || '注册失败'
  } finally {
    isLoading.value = false
  }
}

onMounted(async () => {
  applyOauthErrorFromQuery()
  await loadAuthOptions()
})
</script>
