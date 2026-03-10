<template>
  <div class="space-y-6">
    <section class="rounded-3xl border border-border bg-card p-6">
      <h3 class="text-lg font-semibold text-foreground">当前账户限制</h3>
      <div v-if="limits" class="mt-4 grid gap-3 md:grid-cols-3">
        <div class="rounded-2xl border border-border bg-background p-4">
          <p class="text-xs text-muted-foreground">账户等级</p>
          <p class="mt-1 text-lg font-medium text-foreground">{{ limits.role }}</p>
        </div>
        <div class="rounded-2xl border border-border bg-background p-4">
          <p class="text-xs text-muted-foreground">今日调用</p>
          <p class="mt-1 text-lg font-medium text-foreground">
            {{ limits.today_call_count }} / {{ limits.daily_limit ?? '∞' }}
          </p>
        </div>
        <div class="rounded-2xl border border-border bg-background p-4">
          <p class="text-xs text-muted-foreground">{{ limits.window_minutes ?? '-' }} 分钟窗口</p>
          <p class="mt-1 text-lg font-medium text-foreground">
            {{ limits.window_call_count }} / {{ limits.window_max_calls ?? '∞' }}
          </p>
        </div>
      </div>
    </section>

    <section class="rounded-3xl border border-border bg-card p-6">
      <h3 class="text-lg font-semibold text-foreground">新增 API Key</h3>
      <form class="mt-4 flex flex-col gap-3 sm:flex-row" @submit.prevent="handleCreateKey">
        <input
          v-model="newKeyName"
          type="text"
          placeholder="Key 名称（例如：prod-client）"
          class="w-full rounded-2xl border border-input bg-background px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
        <button
          type="submit"
          :disabled="creating"
          class="rounded-2xl bg-primary px-4 py-3 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
        >
          {{ creating ? '创建中...' : '创建 Key' }}
        </button>
      </form>

      <div v-if="latestCreatedKey" class="mt-4 rounded-2xl bg-emerald-500/10 p-4 text-sm text-emerald-700">
        <p class="font-medium">请立即保存此 Key（仅展示一次）</p>
        <div class="mt-2 flex items-center gap-2">
          <code class="flex-1 break-all rounded-xl border border-emerald-200 bg-white/60 px-3 py-2">{{ latestCreatedKey }}</code>
          <button
            class="rounded-xl border border-emerald-300 px-3 py-2 text-xs transition-colors hover:bg-emerald-50"
            @click="copyText(latestCreatedKey)"
          >
            复制
          </button>
        </div>
      </div>
    </section>

    <section class="rounded-3xl border border-border bg-card p-6">
      <h3 class="text-lg font-semibold text-foreground">我的 API Keys</h3>
      <div class="mt-4 overflow-x-auto">
        <table class="min-w-full text-sm">
          <thead>
            <tr class="border-b border-border text-left text-muted-foreground">
              <th class="px-3 py-2">名称</th>
              <th class="px-3 py-2">Key 摘要</th>
              <th class="px-3 py-2">状态</th>
              <th class="px-3 py-2">创建时间</th>
              <th class="px-3 py-2">最后调用</th>
              <th class="px-3 py-2">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in keys" :key="item.key_id" class="border-b border-border/50">
              <td class="px-3 py-2 text-foreground">{{ item.name }}</td>
              <td class="px-3 py-2 font-mono text-xs text-foreground">{{ item.key_prefix }}</td>
              <td class="px-3 py-2">
                <span :class="item.is_active ? 'text-emerald-600' : 'text-destructive'">
                  {{ item.is_active ? '启用' : '已吊销' }}
                </span>
              </td>
              <td class="px-3 py-2 text-muted-foreground">{{ item.created_at || '-' }}</td>
              <td class="px-3 py-2 text-muted-foreground">{{ item.last_used_at || '-' }}</td>
              <td class="px-3 py-2">
                <button
                  class="rounded-xl border border-destructive/30 px-3 py-1 text-xs text-destructive transition-colors hover:bg-destructive/10 disabled:opacity-50"
                  :disabled="!item.is_active || revokingId === item.key_id"
                  @click="revoke(item.key_id)"
                >
                  吊销
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { authApi } from '@/api/auth'
import { useAuthStore } from '@/stores/auth'
import type { UserApiKey, UserLimitSnapshot } from '@/types/api'
import { useToast } from '@/composables/useToast'

const authStore = useAuthStore()
const toast = useToast()

const keys = ref<UserApiKey[]>([])
const limits = ref<UserLimitSnapshot | null>(null)
const newKeyName = ref('default')
const creating = ref(false)
const revokingId = ref('')
const latestCreatedKey = ref('')

async function loadData() {
  const res = await authApi.listApiKeys()
  keys.value = res.keys
  limits.value = res.limits
}

async function handleCreateKey() {
  creating.value = true
  latestCreatedKey.value = ''
  try {
    const result = await authApi.createApiKey({ name: newKeyName.value || 'default' })
    latestCreatedKey.value = result.api_key
    toast.success('API Key 已创建')
    await loadData()
    await authStore.refreshMe()
  } catch (error: any) {
    toast.error(error.message || '创建失败')
  } finally {
    creating.value = false
  }
}

async function revoke(keyId: string) {
  revokingId.value = keyId
  try {
    await authApi.revokeApiKey({ key_id: keyId })
    toast.success('已吊销')
    await loadData()
    await authStore.refreshMe()
  } catch (error: any) {
    toast.error(error.message || '操作失败')
  } finally {
    revokingId.value = ''
  }
}

async function copyText(value: string) {
  if (!value) return
  try {
    await navigator.clipboard.writeText(value)
    toast.success('已复制')
  } catch {
    toast.error('复制失败')
  }
}

onMounted(loadData)
</script>
