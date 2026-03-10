<template>
  <div class="space-y-6">
    <section class="rounded-3xl border border-border bg-card p-6">
      <h3 class="text-lg font-semibold text-foreground">用户策略</h3>
      <div class="mt-4 space-y-4">
        <label class="flex items-center gap-2 text-sm text-foreground">
          <input v-model="policy.registration_enabled" type="checkbox" class="h-4 w-4" />
          允许用户注册
        </label>
        <label class="flex items-center gap-2 text-sm text-foreground">
          <input
            v-model="policy.password_registration_enabled"
            type="checkbox"
            class="h-4 w-4"
            :disabled="!policy.registration_enabled"
          />
          允许账号密码注册
        </label>
        <label class="flex items-center gap-2 text-sm text-foreground">
          <input
            v-model="policy.linuxdo_oauth_registration_enabled"
            type="checkbox"
            class="h-4 w-4"
            :disabled="!policy.registration_enabled"
          />
          允许 Linux DO OAuth 注册
        </label>
        <div class="grid gap-3 md:grid-cols-3">
          <label class="text-sm">
            <span class="mb-1 block text-muted-foreground">普通用户每日调用</span>
            <input v-model.number="policy.limits.user.daily_limit" type="number" min="1" class="w-full rounded-xl border border-input bg-background px-3 py-2" />
          </label>
          <label class="text-sm">
            <span class="mb-1 block text-muted-foreground">高级用户每日调用</span>
            <input v-model.number="policy.limits.premium.daily_limit" type="number" min="1" class="w-full rounded-xl border border-input bg-background px-3 py-2" />
          </label>
          <label class="text-sm">
            <span class="mb-1 block text-muted-foreground">普通用户窗口分钟</span>
            <input v-model.number="policy.limits.user.window_minutes" type="number" min="1" class="w-full rounded-xl border border-input bg-background px-3 py-2" />
          </label>
          <label class="text-sm">
            <span class="mb-1 block text-muted-foreground">普通用户窗口最大调用</span>
            <input v-model.number="policy.limits.user.window_max_calls" type="number" min="1" class="w-full rounded-xl border border-input bg-background px-3 py-2" />
          </label>
          <label class="text-sm">
            <span class="mb-1 block text-muted-foreground">高级用户窗口分钟</span>
            <input v-model.number="policy.limits.premium.window_minutes" type="number" min="1" class="w-full rounded-xl border border-input bg-background px-3 py-2" />
          </label>
          <label class="text-sm">
            <span class="mb-1 block text-muted-foreground">高级用户窗口最大调用</span>
            <input v-model.number="policy.limits.premium.window_max_calls" type="number" min="1" class="w-full rounded-xl border border-input bg-background px-3 py-2" />
          </label>
        </div>
        <button
          class="rounded-2xl bg-primary px-4 py-2 text-sm font-medium text-primary-foreground"
          :disabled="savingPolicy"
          @click="savePolicy"
        >
          {{ savingPolicy ? '保存中...' : '保存策略' }}
        </button>
      </div>
    </section>

    <section class="rounded-3xl border border-border bg-card p-6">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <h3 class="text-lg font-semibold text-foreground">兑换码管理</h3>
        <div class="flex flex-wrap items-center gap-2 text-xs">
          <label class="inline-flex items-center gap-2 rounded-lg border border-input bg-background px-2 py-1">
            <input v-model="includeUsedCodes" type="checkbox" class="h-3.5 w-3.5" />
            包含已使用
          </label>
          <button class="rounded-lg border border-border px-3 py-1.5" :disabled="loadingRedeemCodes" @click="loadRedeemCodes">
            {{ loadingRedeemCodes ? '刷新中...' : '刷新列表' }}
          </button>
        </div>
      </div>

      <div class="mt-4 grid gap-3 md:grid-cols-4">
        <label class="text-sm">
          <span class="mb-1 block text-muted-foreground">批量生成数量</span>
          <input v-model.number="generateForm.count" type="number" min="1" max="1000" class="w-full rounded-xl border border-input bg-background px-3 py-2" />
        </label>
        <label class="text-sm">
          <span class="mb-1 block text-muted-foreground">每个码长度</span>
          <input v-model.number="generateForm.length" type="number" min="6" max="64" class="w-full rounded-xl border border-input bg-background px-3 py-2" />
        </label>
        <div class="md:col-span-2 flex flex-wrap items-end gap-2">
          <button
            class="rounded-2xl bg-primary px-4 py-2 text-sm font-medium text-primary-foreground"
            :disabled="generatingCodes"
            @click="generateRedeemCodes"
          >
            {{ generatingCodes ? '生成中...' : '批量生成' }}
          </button>
          <button class="rounded-2xl border border-border px-4 py-2 text-sm" @click="exportRedeemCodes('txt', true)">
            导出未使用(TXT)
          </button>
          <button class="rounded-2xl border border-border px-4 py-2 text-sm" @click="exportRedeemCodes('json', false)">
            导出全部(JSON)
          </button>
        </div>
      </div>

      <div v-if="latestGeneratedCodes.length" class="mt-4 rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-xs text-emerald-700">
        <p class="mb-2 font-medium">本次生成 {{ latestGeneratedCodes.length }} 个兑换码：</p>
        <div class="max-h-24 overflow-auto whitespace-pre-wrap break-all">
          {{ latestGeneratedCodes.join('\n') }}
        </div>
      </div>

      <div class="mt-4 space-y-2">
        <label class="block text-sm text-muted-foreground">导入兑换码（逗号/空格/换行分隔）</label>
        <textarea
          v-model="importText"
          rows="4"
          placeholder="例如：CODE001 CODE002 CODE003"
          class="w-full rounded-xl border border-input bg-background px-3 py-2 text-sm"
        />
        <div class="flex flex-wrap items-center gap-2">
          <button class="rounded-2xl border border-border px-4 py-2 text-sm" :disabled="importingCodes" @click="importRedeemCodes">
            {{ importingCodes ? '导入中...' : '导入兑换码' }}
          </button>
          <label class="cursor-pointer rounded-2xl border border-border px-4 py-2 text-sm">
            读取文件
            <input type="file" accept=".txt,.csv,.json" class="hidden" @change="handleImportFile" />
          </label>
        </div>
      </div>

      <div class="mt-4 overflow-x-auto">
        <table class="min-w-full text-sm">
          <thead>
            <tr class="border-b border-border text-left text-muted-foreground">
              <th class="px-3 py-2">兑换码</th>
              <th class="px-3 py-2">状态</th>
              <th class="px-3 py-2">创建时间</th>
              <th class="px-3 py-2">使用时间</th>
              <th class="px-3 py-2">使用用户</th>
              <th class="px-3 py-2">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="code in redeemCodes" :key="code.code_id" class="border-b border-border/50">
              <td class="px-3 py-2 text-foreground">{{ code.code }}</td>
              <td class="px-3 py-2">
                <span :class="code.is_used ? 'text-amber-600' : 'text-emerald-600'">
                  {{ code.is_used ? '已使用' : '未使用' }}
                </span>
              </td>
              <td class="px-3 py-2 text-muted-foreground">{{ formatDateTime(code.created_at) }}</td>
              <td class="px-3 py-2 text-muted-foreground">{{ formatDateTime(code.used_at) }}</td>
              <td class="px-3 py-2 text-muted-foreground">{{ code.used_by_user_id || '-' }}</td>
              <td class="px-3 py-2">
                <button
                  class="rounded-lg border border-destructive/40 px-2 py-1 text-xs text-destructive"
                  @click="deleteRedeemCode(code.code_id)"
                >
                  删除
                </button>
              </td>
            </tr>
            <tr v-if="!redeemCodes.length">
              <td colspan="6" class="px-3 py-6 text-center text-sm text-muted-foreground">暂无兑换码</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section class="rounded-3xl border border-border bg-card p-6">
      <h3 class="text-lg font-semibold text-foreground">新增用户</h3>
      <form class="mt-4 grid gap-3 md:grid-cols-4" @submit.prevent="createUser">
        <input v-model="createForm.username" type="text" placeholder="用户名" class="rounded-xl border border-input bg-background px-3 py-2 text-sm" />
        <input v-model="createForm.password" type="password" placeholder="密码" class="rounded-xl border border-input bg-background px-3 py-2 text-sm" />
        <select v-model="createForm.role" class="rounded-xl border border-input bg-background px-3 py-2 text-sm">
          <option value="user">普通用户</option>
          <option value="premium">高级用户</option>
        </select>
        <label class="flex items-center gap-2 rounded-xl border border-input bg-background px-3 py-2 text-sm">
          <input v-model="createForm.create_key" type="checkbox" />
          创建首个 Key
        </label>
        <button class="rounded-2xl bg-primary px-4 py-2 text-sm font-medium text-primary-foreground md:col-span-4" :disabled="creatingUser">
          {{ creatingUser ? '创建中...' : '创建用户' }}
        </button>
      </form>
      <p v-if="createdApiKey" class="mt-3 rounded-xl bg-emerald-500/10 px-3 py-2 text-xs text-emerald-700">
        新用户首个 API Key: {{ createdApiKey }}
      </p>
    </section>

    <section class="rounded-3xl border border-border bg-card p-6">
      <div class="flex items-center justify-between">
        <h3 class="text-lg font-semibold text-foreground">用户列表</h3>
        <button class="rounded-xl border border-border px-3 py-2 text-xs" @click="loadUsers">刷新</button>
      </div>
      <div class="mt-4 overflow-x-auto">
        <table class="min-w-full text-sm">
          <thead>
            <tr class="border-b border-border text-left text-muted-foreground">
              <th class="px-3 py-2">用户名</th>
              <th class="px-3 py-2">角色</th>
              <th class="px-3 py-2">状态</th>
              <th class="px-3 py-2">调用次数</th>
              <th class="px-3 py-2">今日调用</th>
              <th class="px-3 py-2">最后调用</th>
              <th class="px-3 py-2">Key 数量</th>
              <th class="px-3 py-2">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="u in users" :key="u.user_id" class="border-b border-border/50">
              <td class="px-3 py-2 text-foreground">{{ u.username }}</td>
              <td class="px-3 py-2 text-foreground">{{ u.role }}</td>
              <td class="px-3 py-2">
                <span :class="u.is_active ? 'text-emerald-600' : 'text-destructive'">{{ u.is_active ? '启用' : '禁用' }}</span>
              </td>
              <td class="px-3 py-2 text-muted-foreground">{{ u.total_call_count }}</td>
              <td class="px-3 py-2 text-muted-foreground">{{ u.today_call_count }}</td>
              <td class="px-3 py-2 text-muted-foreground">{{ u.last_call_time || '-' }}</td>
              <td class="px-3 py-2 text-muted-foreground">{{ u.active_key_count }} / {{ u.total_key_count }}</td>
              <td class="px-3 py-2">
                <div class="flex flex-wrap gap-2">
                  <button
                    v-if="u.is_active"
                    class="rounded-lg border border-amber-300 px-2 py-1 text-xs text-amber-700"
                    @click="toggleUser(u.user_id, false)"
                  >
                    禁用
                  </button>
                  <button
                    v-else
                    class="rounded-lg border border-emerald-300 px-2 py-1 text-xs text-emerald-700"
                    @click="toggleUser(u.user_id, true)"
                  >
                    启用
                  </button>
                  <button
                    v-if="u.role !== 'admin'"
                    class="rounded-lg border border-destructive/40 px-2 py-1 text-xs text-destructive"
                    @click="deleteUser(u.user_id)"
                  >
                    删除
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { usersApi } from '@/api/users'
import type { AdminUser, RedeemCodeItem, UserPolicy } from '@/types/api'
import { useToast } from '@/composables/useToast'

const toast = useToast()
const users = ref<AdminUser[]>([])
const savingPolicy = ref(false)
const creatingUser = ref(false)
const createdApiKey = ref('')

const policy = reactive<UserPolicy>({
  registration_enabled: true,
  password_registration_enabled: true,
  linuxdo_oauth_registration_enabled: true,
  limits: {
    user: { daily_limit: 200, window_minutes: 10, window_max_calls: 30 },
    premium: { daily_limit: 1000, window_minutes: 10, window_max_calls: 120 },
  },
})

const createForm = reactive({
  username: '',
  password: '',
  role: 'user' as 'user' | 'premium',
  create_key: false,
})

const redeemCodes = ref<RedeemCodeItem[]>([])
const includeUsedCodes = ref(true)
const loadingRedeemCodes = ref(false)
const generatingCodes = ref(false)
const importingCodes = ref(false)
const latestGeneratedCodes = ref<string[]>([])
const importText = ref('')
const generateForm = reactive({
  count: 20,
  length: 12,
})

function formatDateTime(value?: string | null) {
  return value || '-'
}

function downloadText(filename: string, text: string, mime = 'text/plain;charset=utf-8') {
  const blob = new Blob([text], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

async function loadUsers() {
  const res = await usersApi.list(500)
  users.value = res.users
}

async function loadPolicy() {
  const res = await usersApi.getPolicy()
  Object.assign(policy, res.policy)
}

async function savePolicy() {
  savingPolicy.value = true
  try {
    const res = await usersApi.updatePolicy(policy)
    Object.assign(policy, res.policy)
    toast.success('策略已保存')
  } catch (error: any) {
    toast.error(error.message || '保存失败')
  } finally {
    savingPolicy.value = false
  }
}

async function createUser() {
  creatingUser.value = true
  createdApiKey.value = ''
  try {
    const res = await usersApi.create(createForm)
    createdApiKey.value = res.api_key || ''
    createForm.username = ''
    createForm.password = ''
    createForm.role = 'user'
    createForm.create_key = false
    toast.success('用户创建成功')
    await loadUsers()
  } catch (error: any) {
    toast.error(error.message || '创建失败')
  } finally {
    creatingUser.value = false
  }
}

async function toggleUser(userId: string, enable: boolean) {
  try {
    if (enable) {
      await usersApi.enable(userId)
    } else {
      await usersApi.disable(userId)
    }
    await loadUsers()
    toast.success(enable ? '已启用' : '已禁用')
  } catch (error: any) {
    toast.error(error.message || '操作失败')
  }
}

async function deleteUser(userId: string) {
  try {
    await usersApi.remove(userId)
    toast.success('已删除用户')
    await loadUsers()
  } catch (error: any) {
    toast.error(error.message || '删除失败')
  }
}

async function loadRedeemCodes() {
  loadingRedeemCodes.value = true
  try {
    const res = await usersApi.listRedeemCodes({ limit: 2000, include_used: includeUsedCodes.value })
    redeemCodes.value = res.codes
  } catch (error: any) {
    toast.error(error.message || '加载兑换码失败')
  } finally {
    loadingRedeemCodes.value = false
  }
}

async function generateRedeemCodes() {
  generatingCodes.value = true
  latestGeneratedCodes.value = []
  try {
    const res = await usersApi.generateRedeemCodes({
      count: generateForm.count,
      length: generateForm.length,
    })
    latestGeneratedCodes.value = res.plain_codes || []
    toast.success(`生成成功：${res.created_count} 个`)
    await loadRedeemCodes()
  } catch (error: any) {
    toast.error(error.message || '生成失败')
  } finally {
    generatingCodes.value = false
  }
}

async function importRedeemCodes() {
  if (!importText.value.trim()) {
    toast.error('请输入兑换码内容')
    return
  }
  importingCodes.value = true
  try {
    const res = await usersApi.importRedeemCodes({ codes: importText.value })
    toast.success(`导入完成：新增 ${res.created_count}，重复 ${res.duplicates_count}，无效 ${res.invalid_count}`)
    importText.value = ''
    await loadRedeemCodes()
  } catch (error: any) {
    toast.error(error.message || '导入失败')
  } finally {
    importingCodes.value = false
  }
}

async function handleImportFile(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  try {
    const content = await file.text()
    importText.value = content
    toast.success('文件已读取，请点击“导入兑换码”')
  } catch (error: any) {
    toast.error(error.message || '读取文件失败')
  } finally {
    input.value = ''
  }
}

async function deleteRedeemCode(codeId: string) {
  try {
    await usersApi.removeRedeemCode(codeId)
    toast.success('兑换码已删除')
    await loadRedeemCodes()
  } catch (error: any) {
    toast.error(error.message || '删除失败')
  }
}

async function exportRedeemCodes(format: 'txt' | 'json', onlyUnused: boolean) {
  try {
    const data = await usersApi.exportRedeemCodes({
      format,
      include_used: !onlyUnused,
      only_unused: onlyUnused,
    })
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    if (format === 'json') {
      downloadText(`redeem-codes-${timestamp}.json`, JSON.stringify(data, null, 2), 'application/json;charset=utf-8')
    } else {
      downloadText(`redeem-codes-${timestamp}.txt`, typeof data === 'string' ? data : '')
    }
    toast.success('导出成功')
  } catch (error: any) {
    toast.error(error.message || '导出失败')
  }
}

onMounted(async () => {
  await Promise.all([loadUsers(), loadPolicy(), loadRedeemCodes()])
})
</script>
