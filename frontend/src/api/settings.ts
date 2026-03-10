import apiClient from './client'
import type { Settings } from '@/types/api'

export const settingsApi = {
  // 获取设置
  get: () =>
    apiClient.get<never, Settings>('/api/admin/settings'),

  // 更新设置
  update: (settings: Settings) =>
    apiClient.put('/api/admin/settings', settings),

  exportDatabase: () =>
    apiClient.get<never, Blob>('/api/admin/database/export', {
      responseType: 'blob',
    }),

  importDatabase: (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    return apiClient.post<FormData, { success: boolean; message: string }>(
      '/api/admin/database/import',
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      },
    )
  },
}
