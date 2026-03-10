// API 类型定义

export interface AdminAccount {
  id: string
  status?: string
  api_key?: string
  expires_at?: string
  remaining_hours?: number | null
  remaining_display?: string
  is_available: boolean
  error_count: number
  failure_count: number
  disabled: boolean
  disabled_reason: string | null
  cooldown_seconds?: number
  cooldown_reason?: string | null
  conversation_count: number
  trial_end?: string | null
  trial_days_remaining?: number | null
}

export interface AccountsListResponse {
  total: number
  accounts: AdminAccount[]
}

export interface AccountConfigItem {
  id: string
  secure_c_ses: string
  csesidx: string
  config_id: string
  exa_api_key?: string
  coupon_code?: string
  coupon_status?: string
  balance?: string
  host_c_oses?: string
  expires_at?: string
  mail_provider?: string
  mail_address?: string
  mail_password?: string
  mail_client_id?: string
  mail_refresh_token?: string
  mail_tenant?: string
  mail_base_url?: string
  mail_api_key?: string
  mail_jwt_token?: string
  mail_verify_ssl?: boolean
  mail_domain?: string
}

export interface AccountsConfigResponse {
  accounts: AccountConfigItem[]
}

export interface Stats {
  total_accounts: number
  active_accounts: number
  failed_accounts: number
  expired_accounts: number
  total_requests: number
  total_visitors: number
  requests_per_hour: number
}

export type TempMailProvider = 'duckmail' | 'moemail' | 'freemail' | 'gptmail' | 'cfmail'

export interface Settings {
  basic: {
    api_key?: string
    base_url?: string
    linuxdo_oauth_enabled?: boolean
    linuxdo_client_id?: string
    linuxdo_client_secret?: string
    linuxdo_authorize_url?: string
    linuxdo_token_url?: string
    linuxdo_userinfo_url?: string
    linuxdo_redirect_uri?: string
    linuxdo_scope?: string
    proxy_for_auth?: string
    proxy_for_chat?: string
    duckmail_base_url?: string
    duckmail_api_key?: string
    duckmail_verify_ssl?: boolean
    temp_mail_provider?: TempMailProvider
    moemail_base_url?: string
    moemail_api_key?: string
    moemail_domain?: string
    freemail_base_url?: string
    freemail_jwt_token?: string
    freemail_verify_ssl?: boolean
    freemail_domain?: string
    mail_proxy_enabled?: boolean
    gptmail_base_url?: string
    gptmail_api_key?: string
    gptmail_verify_ssl?: boolean
    gptmail_domain?: string
    cfmail_base_url?: string
    cfmail_api_key?: string
    cfmail_verify_ssl?: boolean
    cfmail_domain?: string
    refresh_window_hours?: number
    register_default_count?: number
    register_domain?: string
    exa_redeem_coupon_enabled?: boolean
    exa_coupon_code?: string
    image_expire_hours?: number
  }
  retry: {
    max_account_switch_tries: number
    account_failure_threshold: number
    text_rate_limit_cooldown_seconds: number
    images_rate_limit_cooldown_seconds: number
    videos_rate_limit_cooldown_seconds: number
    session_cache_ttl_seconds: number
    auto_refresh_accounts_seconds: number
    scheduled_refresh_enabled?: boolean
    scheduled_refresh_interval_minutes?: number
    scheduled_refresh_cron?: string
    refresh_batch_size?: number
    refresh_batch_interval_minutes?: number
    refresh_cooldown_hours?: number
  }
  public_display: {
    logo_url?: string
    chat_url?: string
  }
  image_generation: {
    enabled: boolean
    supported_models: string[]
    output_format?: 'base64' | 'url'
  }
  session: {
    expire_hours: number
  }
}

export interface LogEntry {
  time: string
  level: 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL' | 'DEBUG'
  message: string
}

export interface LogsResponse {
  total: number
  limit: number
  logs: LogEntry[]
}

export interface AdminLogStats {
  memory: {
    total: number
    by_level: Record<string, number>
    capacity: number
  }
  errors: {
    count: number
    recent: LogEntry[]
  }
  request_count: number
  chat_count?: number
}

export interface AdminLogsResponse extends LogsResponse {
  filters?: {
    level?: string | null
    search?: string | null
    start_time?: string | null
    end_time?: string | null
  }
  stats: AdminLogStats
}

export type PublicLogStatus = 'success' | 'error' | 'timeout' | 'in_progress'

export interface PublicLogEvent {
  time: string
  type: 'start' | 'select' | 'retry' | 'switch' | 'complete'
  status?: 'success' | 'error' | 'timeout'
  content: string
}

export interface PublicLogGroup {
  request_id: string
  start_time: string
  status: PublicLogStatus
  events: PublicLogEvent[]
}

export interface PublicLogsResponse {
  total: number
  logs: PublicLogGroup[]
  error?: string
}

export interface AdminStatsTrend {
  labels: string[]
  total_requests: number[]
  failed_requests: number[]
  api_requests?: Record<string, number[]>
  api_ttfb_times?: Record<string, number[]>
  api_total_times?: Record<string, number[]>
}

export interface AdminStats {
  total_accounts: number
  active_accounts: number
  failed_accounts: number
  idle_accounts: number
  success_count?: number
  failed_count?: number
  trend: AdminStatsTrend
}

export interface PublicStats {
  total_visitors: number
  total_requests: number
  requests_per_minute: number
  load_status: 'low' | 'medium' | 'high'
  load_color: string
}

export interface PublicDisplay {
  logo_url?: string
  chat_url?: string
}

export interface UptimeHeartbeat {
  time: string
  success: boolean
  latency_ms?: number | null
  status_code?: number | null
  level?: 'up' | 'down' | 'warn'
}

export interface UptimeService {
  name: string
  status: 'up' | 'down' | 'warn' | 'unknown'
  uptime: number
  total: number
  success: number
  heartbeats: UptimeHeartbeat[]
}

export interface UptimeResponse {
  services: Record<string, UptimeService>
  updated_at: string
}

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  success: boolean
  user?: PortalUser
  limits?: UserLimitSnapshot
  keys?: UserApiKey[]
  message?: string
}

export type PortalRole = 'admin' | 'user' | 'premium'

export interface PortalUser {
  user_id: string
  username: string
  role: PortalRole
  is_active: boolean
  created_at?: string
}

export interface UserApiKey {
  key_id: string
  user_id: string
  key_prefix: string
  name: string
  is_active: boolean
  created_at: string
  last_used_at?: string | null
}

export interface UserLimitSnapshot {
  role: PortalRole
  daily_limit: number | null
  window_minutes: number | null
  window_max_calls: number | null
  today_call_count: number
  window_call_count: number
  remaining_today: number | null
  remaining_window: number | null
  last_call_ts?: number | null
}

export interface AuthMeResponse {
  success: boolean
  user: PortalUser
  limits: UserLimitSnapshot
  keys: UserApiKey[]
}

export interface RegisterResponse {
  success: boolean
  user: PortalUser
  api_key: string
}

export interface AdminUser extends PortalUser {
  active_key_count: number
  total_key_count: number
  today_call_count: number
  total_call_count: number
  last_call_ts?: number | null
  last_call_time?: string | null
}

export interface AdminUsersResponse {
  total: number
  users: AdminUser[]
}

export interface UserPolicy {
  registration_enabled: boolean
  password_registration_enabled: boolean
  linuxdo_oauth_registration_enabled: boolean
  limits: {
    user: {
      daily_limit: number
      window_minutes: number
      window_max_calls: number
    }
    premium: {
      daily_limit: number
      window_minutes: number
      window_max_calls: number
    }
  }
}

export interface AuthOptionsResponse {
  registration_enabled: boolean
  password_registration_enabled: boolean
  linuxdo_oauth_registration_enabled: boolean
  linuxdo_oauth_login_enabled: boolean
  linuxdo_oauth_ready: boolean
  linuxdo_oauth_start_url: string
}

export interface RedeemCodeItem {
  code_id: string
  code: string
  is_used: boolean
  used_by_user_id?: string | null
  used_at?: string | null
  created_by?: string | null
  created_at?: string | null
}

export interface RedeemCodeListResponse {
  total: number
  used_count: number
  unused_count: number
  codes: RedeemCodeItem[]
}

export interface RedeemCodeGenerateResponse {
  success: boolean
  requested: number
  created_count: number
  duplicates_count: number
  codes: RedeemCodeItem[]
  plain_codes: string[]
}

export interface RedeemCodeImportResponse {
  success: boolean
  imported: number
  created_count: number
  duplicates_count: number
  invalid_count: number
  codes: RedeemCodeItem[]
  duplicates: string[]
  invalid: string[]
}

export type AutomationStatus = 'pending' | 'running' | 'success' | 'failed' | 'cancelled'

export interface RegisterTask {
  id: string
  count: number
  domain?: string | null
  status: AutomationStatus
  progress: number
  success_count: number
  fail_count: number
  created_at: number
  finished_at?: number | null
  results: Array<Record<string, any>>
  error?: string | null
  logs?: Array<{ time: string; level: string; message: string }>
  cancel_requested?: boolean
  cancel_reason?: string | null
}

export interface LoginTask {
  id: string
  account_ids: string[]
  status: AutomationStatus
  progress: number
  success_count: number
  fail_count: number
  created_at: number
  finished_at?: number | null
  results: Array<Record<string, any>>
  error?: string | null
  logs?: Array<{ time: string; level: string; message: string }>
  cancel_requested?: boolean
  cancel_reason?: string | null
}
