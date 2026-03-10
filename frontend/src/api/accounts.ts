import apiClient from './client'
import type {
  AccountsConfigResponse,
  AccountsListResponse,
  AccountConfigItem,
  RegisterTask,
  LoginTask,
} from '@/types/api'

export const accountsApi = {
  // 获取账户列表
  list: () =>
    apiClient.get<never, AccountsListResponse>('/admin/accounts'),

  // 获取账户配置
  getConfig: () =>
    apiClient.get<never, AccountsConfigResponse>('/admin/accounts-config'),

  // 更新账户配置
  updateConfig: (accounts: AccountConfigItem[]) =>
    apiClient.put('/admin/accounts-config', accounts),

  // 删除账户
  delete: (accountId: string) =>
    apiClient.delete(`/admin/accounts/${accountId}`),

  // 禁用账户
  disable: (accountId: string) =>
    apiClient.put(`/admin/accounts/${accountId}/disable`),

  // 启用账户
  enable: (accountId: string) =>
    apiClient.put(`/admin/accounts/${accountId}/enable`),

  // 批量启用账户（最多50个）
  bulkEnable: (accountIds: string[]) =>
    apiClient.put<never, { status: string; success_count: number; errors: string[] }>(
      '/admin/accounts/bulk-enable',
      accountIds
    ),

  // 批量禁用账户（最多50个）
  bulkDisable: (accountIds: string[]) =>
    apiClient.put<never, { status: string; success_count: number; errors: string[] }>(
      '/admin/accounts/bulk-disable',
      accountIds
    ),
  // 批量删除账户（最多50个）
  bulkDelete: (accountIds: string[]) =>
    apiClient.put<never, { status: string; success_count: number; errors: string[] }>(
      '/admin/accounts/bulk-delete',
      accountIds
    ),

  startRegister: (count?: number, domain?: string, mail_provider?: string) =>
    apiClient.post<never, RegisterTask>('/admin/register/start', { count, domain, mail_provider }),

  getRegisterTask: (taskId: string) =>
    apiClient.get<never, RegisterTask>(`/admin/register/task/${taskId}`),

  getRegisterCurrent: () =>
    apiClient.get<never, RegisterTask | { status: string }>('/admin/register/current'),

  cancelRegisterTask: (taskId: string, reason?: string) =>
    apiClient.post<{ reason?: string }, RegisterTask>(`/admin/register/cancel/${taskId}`, reason ? { reason } : {}),

  startLogin: async (_accountIds: string[]) =>
    ({
      id: '',
      account_ids: [],
      status: 'cancelled',
      progress: 0,
      success_count: 0,
      fail_count: 0,
      created_at: Date.now() / 1000,
      finished_at: Date.now() / 1000,
      results: [],
      logs: [],
    } as LoginTask),

  getLoginTask: async (_taskId: string) =>
    ({
      id: '',
      account_ids: [],
      status: 'cancelled',
      progress: 0,
      success_count: 0,
      fail_count: 0,
      created_at: Date.now() / 1000,
      finished_at: Date.now() / 1000,
      results: [],
      logs: [],
    } as LoginTask),

  getLoginCurrent: async () =>
    ({ status: 'idle' } as LoginTask | { status: string }),

  cancelLoginTask: async (_taskId: string, _reason?: string) =>
    ({
      id: '',
      account_ids: [],
      status: 'cancelled',
      progress: 0,
      success_count: 0,
      fail_count: 0,
      created_at: Date.now() / 1000,
      finished_at: Date.now() / 1000,
      results: [],
      logs: [],
    } as LoginTask),

  checkLogin: async () =>
    ({ status: 'idle' } as LoginTask | { status: string }),
}
