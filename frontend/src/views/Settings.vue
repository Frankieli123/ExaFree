<template>
  <div class="space-y-8">
    <section v-if="isLoading" class="rounded-3xl border border-border bg-card p-6 text-sm text-muted-foreground">
      正在加载设置...
    </section>

    <section v-else class="rounded-3xl border border-border bg-card p-6">
      <div class="flex items-center justify-between">
        <p class="text-base font-semibold text-foreground">配置面板</p>
        <button
          class="rounded-full bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-opacity
                 hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
          :disabled="isSaving || !localSettings"
          @click="handleSave"
        >
          保存设置
        </button>
      </div>

      <div v-if="errorMessage" class="mt-4 rounded-2xl bg-destructive/10 px-4 py-3 text-sm text-destructive">
        {{ errorMessage }}
      </div>

      <div v-if="localSettings" class="mt-6 space-y-8">
        <div class="grid gap-4 lg:grid-cols-3">
          <div class="space-y-4">
            <div class="rounded-2xl border border-border bg-card p-4">
              <p class="text-xs uppercase tracking-[0.3em] text-muted-foreground">基础</p>
              <div class="mt-4 space-y-3">
                <label class="block text-xs text-muted-foreground">基础地址</label>
                <input
                  v-model="localSettings.basic.base_url"
                  type="text"
                  class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                  placeholder="自动检测或手动填写"
                />
                <div class="mt-3 flex items-center justify-between gap-2 text-xs text-muted-foreground">
                  <span>Linux DO OAuth 登录</span>
                  <HelpTip text="用于用户通过 Linux DO 账号注册/登录。需在 Linux DO Connect 中配置回调地址。默认回调：{base_url}/auth/linuxdo/callback" />
                </div>
                <Checkbox v-model="localSettings.basic.linuxdo_oauth_enabled">
                  启用 Linux DO OAuth
                </Checkbox>
                <label class="block text-xs text-muted-foreground">Client ID</label>
                <input
                  v-model="localSettings.basic.linuxdo_client_id"
                  type="text"
                  class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                  :disabled="!localSettings.basic.linuxdo_oauth_enabled"
                  placeholder="Linux DO OAuth Client ID"
                />
                <label class="block text-xs text-muted-foreground">Client Secret</label>
                <input
                  v-model="localSettings.basic.linuxdo_client_secret"
                  type="text"
                  class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                  :disabled="!localSettings.basic.linuxdo_oauth_enabled"
                  placeholder="Linux DO OAuth Client Secret"
                />
                <label class="block text-xs text-muted-foreground">Authorize URL</label>
                <input
                  v-model="localSettings.basic.linuxdo_authorize_url"
                  type="text"
                  class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                  :disabled="!localSettings.basic.linuxdo_oauth_enabled"
                  placeholder="https://connect.linux.do/oauth2/authorize"
                />
                <label class="block text-xs text-muted-foreground">Token URL</label>
                <input
                  v-model="localSettings.basic.linuxdo_token_url"
                  type="text"
                  class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                  :disabled="!localSettings.basic.linuxdo_oauth_enabled"
                  placeholder="https://connect.linux.do/oauth2/token"
                />
                <label class="block text-xs text-muted-foreground">UserInfo URL</label>
                <input
                  v-model="localSettings.basic.linuxdo_userinfo_url"
                  type="text"
                  class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                  :disabled="!localSettings.basic.linuxdo_oauth_enabled"
                  placeholder="https://connect.linux.do/api/user"
                />
                <label class="block text-xs text-muted-foreground">Redirect URI（可选）</label>
                <input
                  v-model="localSettings.basic.linuxdo_redirect_uri"
                  type="text"
                  class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                  :disabled="!localSettings.basic.linuxdo_oauth_enabled"
                  placeholder="留空自动使用 {base_url}/auth/linuxdo/callback"
                />
                <p class="text-[11px] text-muted-foreground">
                  Linux DO Connect 回调地址填写：{{ linuxdoCallbackHint }}
                </p>
                <label class="block text-xs text-muted-foreground">Scope</label>
                <input
                  v-model="localSettings.basic.linuxdo_scope"
                  type="text"
                  class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                  :disabled="!localSettings.basic.linuxdo_oauth_enabled"
                  placeholder="openid profile email"
                />

              </div>
            </div>

            <div class="rounded-2xl border border-border bg-card p-4">
              <p class="text-xs uppercase tracking-[0.3em] text-muted-foreground">重试</p>
              <div class="mt-4 grid grid-cols-2 gap-3 text-sm">
                <label class="col-span-2 text-xs text-muted-foreground">账户切换次数</label>
                <input v-model.number="localSettings.retry.max_account_switch_tries" type="number" min="1" class="col-span-2 rounded-2xl border border-input bg-background px-3 py-2" />

                <label class="col-span-2 text-xs text-muted-foreground">请求冷却（小时）</label>
                <input v-model.number="textRateLimitCooldownHours" type="number" min="1" max="24" step="1" class="col-span-2 rounded-2xl border border-input bg-background px-3 py-2" />

                <label class="col-span-2 text-xs text-muted-foreground">会话缓存秒数</label>
                <input v-model.number="localSettings.retry.session_cache_ttl_seconds" type="number" min="0" class="col-span-2 rounded-2xl border border-input bg-background px-3 py-2" />

              </div>
            </div>

          </div>

          <div class="space-y-4">
            <div class="rounded-2xl border border-border bg-card p-4">
              <p class="text-xs uppercase tracking-[0.3em] text-muted-foreground">自动注册</p>
              <div class="mt-4 space-y-3">
                <div class="flex items-center justify-between gap-2 text-xs text-muted-foreground">
                  <span>临时邮箱服务</span>
                  <HelpTip text="选择用于自动注册账号的临时邮箱服务提供商。" />
                </div>
                <SelectMenu
                  v-model="localSettings.basic.temp_mail_provider"
                  :options="tempMailProviderOptions"
                  class="w-full"
                />
                <div class="flex items-center justify-between gap-2 text-xs text-muted-foreground">
                  <span>临时邮箱代理</span>
                  <HelpTip text="启用后临时邮箱请求将使用账户操作代理地址。" />
                </div>
                <Checkbox v-model="localSettings.basic.mail_proxy_enabled">
                  启用邮箱代理（使用账户操作代理）
                </Checkbox>
                <div class="flex items-center justify-between gap-2 text-xs text-muted-foreground">
                  <span>Exa 兑换码自动兑换</span>
                  <HelpTip text="默认关闭。开启后在注册流程中自动尝试兑换下方填写的兑换码。" />
                </div>
                <Checkbox v-model="localSettings.basic.exa_redeem_coupon_enabled">
                  启用兑换码自动兑换
                </Checkbox>
                <label class="block text-xs text-muted-foreground">Exa 兑换码</label>
                <input
                  v-model="localSettings.basic.exa_coupon_code"
                  type="text"
                  class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                  :disabled="!localSettings.basic.exa_redeem_coupon_enabled"
                  placeholder="例如：EXA50API"
                />

                <!-- DuckMail 配置 -->
                <template v-if="localSettings.basic.temp_mail_provider === 'duckmail'">
                  <Checkbox v-model="localSettings.basic.duckmail_verify_ssl">
                    DuckMail SSL 校验
                  </Checkbox>
                  <label class="block text-xs text-muted-foreground">DuckMail API</label>
                  <input
                    v-model="localSettings.basic.duckmail_base_url"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="https://api.duckmail.sbs"
                  />
                  <label class="block text-xs text-muted-foreground">DuckMail API 密钥</label>
                  <input
                    v-model="localSettings.basic.duckmail_api_key"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="dk_xxx"
                  />
                  <label class="block text-xs text-muted-foreground">DuckMail 域名（推荐）</label>
                  <input
                    v-model="localSettings.basic.register_domain"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="留空则自动选择"
                  />
                </template>

                <!-- Moemail 配置 -->
                <template v-if="localSettings.basic.temp_mail_provider === 'moemail'">
                  <label class="block text-xs text-muted-foreground">Moemail API</label>
                  <input
                    v-model="localSettings.basic.moemail_base_url"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="https://moemail.app"
                  />
                  <label class="block text-xs text-muted-foreground">Moemail API 密钥</label>
                  <input
                    v-model="localSettings.basic.moemail_api_key"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="X-API-Key"
                  />
                  <label class="block text-xs text-muted-foreground">Moemail 域名（可选，留空随机）</label>
                  <input
                    v-model="localSettings.basic.moemail_domain"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="moemail.app"
                  />
                </template>

                <!-- Freemail 配置 -->
                <template v-if="localSettings.basic.temp_mail_provider === 'freemail'">
                  <Checkbox v-model="localSettings.basic.freemail_verify_ssl">
                    Freemail SSL 校验
                  </Checkbox>
                  <label class="block text-xs text-muted-foreground">Freemail API</label>
                  <input
                    v-model="localSettings.basic.freemail_base_url"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="http://your-freemail-server.com"
                  />
                  <label class="block text-xs text-muted-foreground">Freemail JWT Token</label>
                  <input
                    v-model="localSettings.basic.freemail_jwt_token"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="eyJ..."
                  />
                  <label class="block text-xs text-muted-foreground">Freemail 域名（可选，留空随机）</label>
                  <input
                    v-model="localSettings.basic.freemail_domain"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="freemail.local"
                  />
                </template>

                <!-- GPTMail 配置 -->
                <template v-if="localSettings.basic.temp_mail_provider === 'gptmail'">
                  <Checkbox v-model="localSettings.basic.gptmail_verify_ssl">
                    GPTMail SSL 校验
                  </Checkbox>
                  <label class="block text-xs text-muted-foreground">GPTMail API</label>
                  <input
                    v-model="localSettings.basic.gptmail_base_url"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="https://mail.chatgpt.org.uk"
                  />
                  <label class="block text-xs text-muted-foreground">GPTMail API Key</label>
                  <input
                    v-model="localSettings.basic.gptmail_api_key"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="X-API-Key"
                  />
                  <label class="block text-xs text-muted-foreground">GPTMail 邮箱域名（可选，不带@）</label>
                  <input
                    v-model="localSettings.basic.gptmail_domain"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="留空则随机选择"
                  />
                </template>

                <!-- Cloudflare Mail 配置 -->
                <template v-if="localSettings.basic.temp_mail_provider === 'cfmail'">
                  <Checkbox v-model="localSettings.basic.cfmail_verify_ssl">
                    Cloudflare Mail SSL 校验
                  </Checkbox>
                  <label class="block text-xs text-muted-foreground">Cloudflare Mail API 地址</label>
                  <input
                    v-model="localSettings.basic.cfmail_base_url"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="https://your-cfmail-instance.example.com"
                  />
                  <label class="block text-xs text-muted-foreground">访问密码（x-custom-auth，无密码留空）</label>
                  <input
                    v-model="localSettings.basic.cfmail_api_key"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="留空则不使用密码"
                  />
                  <label class="block text-xs text-muted-foreground">邮箱域名（可选，不带@）</label>
                  <input
                    v-model="localSettings.basic.cfmail_domain"
                    type="text"
                    class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                    placeholder="留空则随机选择"
                  />
                </template>

                <label class="block text-xs text-muted-foreground">默认注册数量</label>
                <input
                  v-model.number="localSettings.basic.register_default_count"
                  type="number"
                  min="1"
                  class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                />
              </div>
            </div>
          </div>

          <div class="space-y-4">
            <div class="rounded-2xl border border-border bg-card p-4">
              <p class="text-xs uppercase tracking-[0.3em] text-muted-foreground">公开展示</p>
              <div class="mt-4 space-y-3">
                <label class="block text-xs text-muted-foreground">Logo 地址</label>
                <input
                  v-model="localSettings.public_display.logo_url"
                  type="text"
                  class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                  placeholder="logo 地址"
                />
                <label class="block text-xs text-muted-foreground">会话有效时长</label>
                <input
                  v-model.number="localSettings.session.expire_hours"
                  type="number"
                  min="1"
                  class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                />
              </div>
            </div>

            <div class="rounded-2xl border border-border bg-card p-4">
              <p class="text-xs uppercase tracking-[0.3em] text-muted-foreground">说明</p>
              <p class="mt-4 text-sm text-muted-foreground">
                保存后会直接写入配置文件并热更新。修改后请关注日志面板确认是否生效。
              </p>
            </div>

            <div class="rounded-2xl border border-border bg-card p-4">
              <p class="text-xs uppercase tracking-[0.3em] text-muted-foreground">数据库</p>
              <div class="mt-4 space-y-3">
                <button
                  class="w-full rounded-2xl border border-border px-4 py-2 text-sm text-foreground transition-colors hover:border-primary hover:text-primary disabled:opacity-50"
                  :disabled="dbExporting"
                  @click="handleExportDatabase"
                >
                  {{ dbExporting ? '导出中...' : '一键导出数据库（.db）' }}
                </button>
                <input
                  ref="dbFileInput"
                  type="file"
                  accept=".db,.sqlite,.sqlite3,application/octet-stream"
                  class="w-full rounded-2xl border border-input bg-background px-3 py-2 text-sm"
                />
                <button
                  class="w-full rounded-2xl border border-destructive/40 px-4 py-2 text-sm text-destructive transition-colors hover:bg-destructive/10 disabled:opacity-50"
                  :disabled="dbImporting"
                  @click="handleImportDatabase"
                >
                  {{ dbImporting ? '导入中...' : '一键导入并覆盖数据库' }}
                </button>
                <p class="text-[11px] text-muted-foreground">
                  导入会直接覆盖现有数据库，请先导出备份。
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useSettingsStore } from '@/stores/settings'
import { useToast } from '@/composables/useToast'
import { defaultMailProvider, mailProviderOptions } from '@/constants/mailProviders'
import { settingsApi } from '@/api/settings'
import SelectMenu from '@/components/ui/SelectMenu.vue'
import Checkbox from '@/components/ui/Checkbox.vue'
import HelpTip from '@/components/ui/HelpTip.vue'
import type { Settings } from '@/types/api'

const settingsStore = useSettingsStore()
const { settings, isLoading } = storeToRefs(settingsStore)
const toast = useToast()

const localSettings = ref<Settings | null>(null)
const isSaving = ref(false)
const errorMessage = ref('')
const dbFileInput = ref<HTMLInputElement | null>(null)
const dbExporting = ref(false)
const dbImporting = ref(false)

// 429冷却时间：小时 ↔ 秒 的转换
const DEFAULT_COOLDOWN_HOURS = {
  text: 2,
} as const

const toCooldownHours = (seconds: number | undefined, fallbackHours: number) => {
  if (!seconds) return fallbackHours
  return Math.max(1, Math.round(seconds / 3600))
}

const createCooldownHours = (
  key: 'text_rate_limit_cooldown_seconds' | 'images_rate_limit_cooldown_seconds' | 'videos_rate_limit_cooldown_seconds',
  fallbackHours: number
) => computed({
  get: () => toCooldownHours(localSettings.value?.retry?.[key], fallbackHours),
  set: (hours: number) => {
    if (localSettings.value?.retry) {
      localSettings.value.retry[key] = hours * 3600
    }
  }
})

const textRateLimitCooldownHours = createCooldownHours(
  'text_rate_limit_cooldown_seconds',
  DEFAULT_COOLDOWN_HOURS.text
)

const linuxdoCallbackHint = computed(() => {
  const settings = localSettings.value
  if (!settings) return '/auth/linuxdo/callback'
  const customRedirect = (settings.basic.linuxdo_redirect_uri || '').trim()
  if (customRedirect) return customRedirect
  const configuredBase = (settings.basic.base_url || '').trim().replace(/\/$/, '')
  const pageOrigin = typeof window !== 'undefined' ? window.location.origin : ''
  const base = configuredBase || pageOrigin
  if (!base) return '/auth/linuxdo/callback'
  return `${base}/auth/linuxdo/callback`
})

const tempMailProviderOptions = mailProviderOptions

watch(settings, (value) => {
  if (!value) return
  const next = JSON.parse(JSON.stringify(value))
  next.image_generation = next.image_generation || { enabled: false, supported_models: [], output_format: 'base64' }
  next.image_generation.output_format ||= 'base64'
  next.video_generation = next.video_generation || { output_format: 'html' }
  next.video_generation.output_format ||= 'html'
  next.basic = next.basic || {}
  next.basic.linuxdo_oauth_enabled = next.basic.linuxdo_oauth_enabled ?? false
  next.basic.linuxdo_client_id = typeof next.basic.linuxdo_client_id === 'string'
    ? next.basic.linuxdo_client_id
    : ''
  next.basic.linuxdo_client_secret = typeof next.basic.linuxdo_client_secret === 'string'
    ? next.basic.linuxdo_client_secret
    : ''
  next.basic.linuxdo_authorize_url = typeof next.basic.linuxdo_authorize_url === 'string'
    ? next.basic.linuxdo_authorize_url
    : 'https://connect.linux.do/oauth2/authorize'
  next.basic.linuxdo_token_url = typeof next.basic.linuxdo_token_url === 'string'
    ? next.basic.linuxdo_token_url
    : 'https://connect.linux.do/oauth2/token'
  next.basic.linuxdo_userinfo_url = typeof next.basic.linuxdo_userinfo_url === 'string'
    ? next.basic.linuxdo_userinfo_url
    : 'https://connect.linux.do/api/user'
  next.basic.linuxdo_redirect_uri = typeof next.basic.linuxdo_redirect_uri === 'string'
    ? next.basic.linuxdo_redirect_uri
    : ''
  next.basic.linuxdo_scope = typeof next.basic.linuxdo_scope === 'string'
    ? next.basic.linuxdo_scope
    : 'openid profile email'
  next.basic.duckmail_base_url ||= 'https://api.duckmail.sbs'
  next.basic.duckmail_verify_ssl = next.basic.duckmail_verify_ssl ?? true
  next.basic.refresh_window_hours = Number.isFinite(next.basic.refresh_window_hours)
    ? next.basic.refresh_window_hours
    : 0
  next.basic.register_default_count = Number.isFinite(next.basic.register_default_count)
    ? next.basic.register_default_count
    : 1
  next.basic.register_domain = typeof next.basic.register_domain === 'string'
    ? next.basic.register_domain
    : ''
  next.basic.exa_redeem_coupon_enabled = next.basic.exa_redeem_coupon_enabled ?? false
  next.basic.exa_coupon_code = typeof next.basic.exa_coupon_code === 'string'
    ? next.basic.exa_coupon_code
    : ''
  next.basic.duckmail_api_key = typeof next.basic.duckmail_api_key === 'string'
    ? next.basic.duckmail_api_key
    : ''
  next.basic.temp_mail_provider = next.basic.temp_mail_provider || defaultMailProvider
  next.basic.moemail_base_url = next.basic.moemail_base_url || 'https://moemail.app'
  next.basic.moemail_api_key = typeof next.basic.moemail_api_key === 'string'
    ? next.basic.moemail_api_key
    : ''
  next.basic.moemail_domain = typeof next.basic.moemail_domain === 'string'
    ? next.basic.moemail_domain
    : ''
  next.basic.freemail_base_url = next.basic.freemail_base_url || 'http://your-freemail-server.com'
  next.basic.freemail_jwt_token = typeof next.basic.freemail_jwt_token === 'string'
    ? next.basic.freemail_jwt_token
    : ''
  next.basic.freemail_verify_ssl = next.basic.freemail_verify_ssl ?? true
  next.basic.freemail_domain = typeof next.basic.freemail_domain === 'string'
    ? next.basic.freemail_domain
    : ''
  next.basic.mail_proxy_enabled = next.basic.mail_proxy_enabled ?? false
  next.basic.gptmail_base_url = next.basic.gptmail_base_url || 'https://mail.chatgpt.org.uk'
  next.basic.gptmail_api_key = typeof next.basic.gptmail_api_key === 'string'
    ? next.basic.gptmail_api_key
    : ''
  next.basic.gptmail_verify_ssl = next.basic.gptmail_verify_ssl ?? true
  next.basic.gptmail_domain = typeof next.basic.gptmail_domain === 'string'
    ? next.basic.gptmail_domain
    : ''
  next.basic.cfmail_base_url = typeof next.basic.cfmail_base_url === 'string'
    ? next.basic.cfmail_base_url
    : ''
  next.basic.cfmail_api_key = typeof next.basic.cfmail_api_key === 'string'
    ? next.basic.cfmail_api_key
    : ''
  next.basic.cfmail_verify_ssl = next.basic.cfmail_verify_ssl ?? true
  next.basic.cfmail_domain = typeof next.basic.cfmail_domain === 'string'
    ? next.basic.cfmail_domain
    : ''
  next.retry = next.retry || {}
  next.retry.auto_refresh_accounts_seconds = Number.isFinite(next.retry.auto_refresh_accounts_seconds)
    ? next.retry.auto_refresh_accounts_seconds
    : 0
  localSettings.value = next
})

onMounted(async () => {
  await settingsStore.loadSettings()
})

const handleSave = async () => {
  if (!localSettings.value) return
  errorMessage.value = ''
  isSaving.value = true

  try {
    await settingsStore.updateSettings(localSettings.value)
    toast.success('设置保存成功')
  } catch (error: any) {
    errorMessage.value = error.message || '保存失败'
    toast.error(error.message || '保存失败')
  } finally {
    isSaving.value = false
  }
}

const downloadBlob = (blob: Blob, filename: string) => {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

const handleExportDatabase = async () => {
  dbExporting.value = true
  try {
    const blob = await settingsApi.exportDatabase()
    const filename = `exafree-db-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.db`
    downloadBlob(blob, filename)
    toast.success('数据库导出成功')
  } catch (error: any) {
    toast.error(error.message || '数据库导出失败')
  } finally {
    dbExporting.value = false
  }
}

const handleImportDatabase = async () => {
  const file = dbFileInput.value?.files?.[0]
  if (!file) {
    toast.error('请先选择数据库文件')
    return
  }
  const confirmed = window.confirm('导入将覆盖当前数据库，是否继续？')
  if (!confirmed) return
  dbImporting.value = true
  try {
    await settingsApi.importDatabase(file)
    toast.success('数据库导入成功，已覆盖旧数据库')
  } catch (error: any) {
    toast.error(error.message || '数据库导入失败')
  } finally {
    dbImporting.value = false
    if (dbFileInput.value) {
      dbFileInput.value.value = ''
    }
  }
}
</script>

