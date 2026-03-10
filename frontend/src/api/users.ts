import apiClient from './client'
import type {
  AdminUsersResponse,
  PortalUser,
  UserPolicy,
  RedeemCodeGenerateResponse,
  RedeemCodeImportResponse,
  RedeemCodeListResponse,
} from '@/types/api'

export const usersApi = {
  list: (limit = 200) =>
    apiClient.get(`/admin/users?limit=${limit}`) as Promise<AdminUsersResponse>,

  create: (data: { username: string; password: string; role: 'user' | 'premium'; create_key: boolean }) =>
    apiClient.post<typeof data, { success: boolean; user: PortalUser; api_key?: string | null }>('/admin/users', data),

  remove: (userId: string) =>
    apiClient.delete(`/admin/users/${encodeURIComponent(userId)}`),

  enable: (userId: string) =>
    apiClient.put(`/admin/users/${encodeURIComponent(userId)}/enable`),

  disable: (userId: string) =>
    apiClient.put(`/admin/users/${encodeURIComponent(userId)}/disable`),

  getPolicy: () =>
    apiClient.get('/admin/user-policy') as Promise<{ policy: UserPolicy }>,

  updatePolicy: (policy: Partial<UserPolicy>) =>
    apiClient.put('/admin/user-policy', policy) as Promise<{ success: boolean; policy: UserPolicy }>,

  listRedeemCodes: (params?: { limit?: number; include_used?: boolean }) =>
    apiClient.get('/admin/redeem-codes', { params }) as Promise<RedeemCodeListResponse>,

  generateRedeemCodes: (data: { count: number; length: number }) =>
    apiClient.post<typeof data, RedeemCodeGenerateResponse>('/admin/redeem-codes/generate', data),

  importRedeemCodes: (data: { codes: string[] | string }) =>
    apiClient.post<typeof data, RedeemCodeImportResponse>('/admin/redeem-codes/import', data),

  removeRedeemCode: (codeId: string) =>
    apiClient.delete(`/admin/redeem-codes/${encodeURIComponent(codeId)}`),

  exportRedeemCodes: (params?: { format?: 'txt' | 'json'; include_used?: boolean; only_unused?: boolean }) =>
    apiClient.get('/admin/redeem-codes/export', { params }),
}
