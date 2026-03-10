<template>
  <div class="space-y-6">
    <section class="rounded-3xl border border-border bg-card p-6">
      <h3 class="text-lg font-semibold text-foreground">账户信息</h3>
      <div class="mt-4 grid gap-3 md:grid-cols-3">
        <div class="rounded-2xl border border-border bg-background p-4">
          <p class="text-xs text-muted-foreground">用户名</p>
          <p class="mt-1 text-base font-medium text-foreground">{{ authStore.user?.username }}</p>
        </div>
        <div class="rounded-2xl border border-border bg-background p-4">
          <p class="text-xs text-muted-foreground">角色</p>
          <p class="mt-1 text-base font-medium text-foreground">{{ authStore.user?.role }}</p>
        </div>
        <div class="rounded-2xl border border-border bg-background p-4">
          <p class="text-xs text-muted-foreground">剩余今日调用</p>
          <p class="mt-1 text-base font-medium text-foreground">
            {{ authStore.limits?.remaining_today ?? '∞' }}
          </p>
        </div>
      </div>
    </section>

    <section v-if="authStore.user?.role === 'user'" class="rounded-3xl border border-border bg-card p-6">
      <h3 class="text-lg font-semibold text-foreground">兑换高级用户</h3>
      <form class="mt-4 flex flex-col gap-3 sm:flex-row" @submit.prevent="handleRedeem">
        <input
          v-model="redeemCode"
          type="text"
          placeholder="输入兑换码"
          class="w-full rounded-2xl border border-input bg-background px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
        <button
          type="submit"
          :disabled="redeeming || !redeemCode"
          class="rounded-2xl bg-primary px-4 py-3 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
        >
          {{ redeeming ? '兑换中...' : '立即兑换' }}
        </button>
      </form>
    </section>

    <section class="rounded-3xl border border-border bg-card p-6">
      <h3 class="text-lg font-semibold text-foreground">修改密码</h3>
      <form class="mt-4 space-y-3" @submit.prevent="handleChangePassword">
        <input
          v-model="oldPassword"
          type="password"
          placeholder="当前密码"
          class="w-full rounded-2xl border border-input bg-background px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
        <input
          v-model="newPassword"
          type="password"
          placeholder="新密码（至少8位）"
          class="w-full rounded-2xl border border-input bg-background px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
        <button
          type="submit"
          :disabled="changing || !oldPassword || !newPassword"
          class="rounded-2xl bg-primary px-4 py-3 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
        >
          {{ changing ? '保存中...' : '保存新密码' }}
        </button>
      </form>
    </section>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { authApi } from '@/api/auth'
import { useAuthStore } from '@/stores/auth'
import { useToast } from '@/composables/useToast'

const authStore = useAuthStore()
const toast = useToast()

const redeemCode = ref('')
const oldPassword = ref('')
const newPassword = ref('')
const redeeming = ref(false)
const changing = ref(false)

async function handleRedeem() {
  if (!redeemCode.value) return
  redeeming.value = true
  try {
    await authApi.redeem({ code: redeemCode.value })
    await authStore.refreshMe()
    toast.success('升级成功，当前为高级用户')
    redeemCode.value = ''
  } catch (error: any) {
    toast.error(error.message || '兑换失败')
  } finally {
    redeeming.value = false
  }
}

async function handleChangePassword() {
  changing.value = true
  try {
    await authApi.changePassword({
      old_password: oldPassword.value,
      new_password: newPassword.value,
    })
    oldPassword.value = ''
    newPassword.value = ''
    toast.success('密码已更新')
  } catch (error: any) {
    toast.error(error.message || '修改失败')
  } finally {
    changing.value = false
  }
}
</script>
