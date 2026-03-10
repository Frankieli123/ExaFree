<template>
  <div class="space-y-6">
    <section class="rounded-3xl border border-border bg-card p-6">
      <div class="space-y-1">
        <p class="text-base font-semibold text-foreground">帮助中心</p>
        <p class="text-xs text-muted-foreground">Exa API 池化与常见问题</p>
      </div>

      <div class="mt-6 flex rounded-full border border-border bg-muted/30 p-1 text-xs">
        <button
          v-for="tab in tabs"
          :key="tab.id"
          class="flex-1 rounded-full px-4 py-2 font-medium transition-colors"
          :class="activeTab === tab.id ? 'bg-foreground text-background' : 'text-muted-foreground hover:text-foreground'"
          @click="activeTab = tab.id"
        >
          {{ tab.label }}
        </button>
      </div>

      <div v-if="activeTab === 'api'" class="mt-6 space-y-4 text-sm text-foreground">
        <div class="space-y-2">
          <p class="font-semibold">`/search`（推荐入口）</p>
          <pre class="overflow-x-auto whitespace-pre-wrap rounded-2xl border border-border bg-card px-4 py-3 text-xs font-mono scrollbar-slim">curl -X POST "http://localhost:7860/search" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "query": "latest exa ai funding news",
    "numResults": 5
  }'</pre>
        </div>

        <div class="space-y-2">
          <p class="font-semibold">原生 Exa 反代入口</p>
          <pre class="overflow-x-auto whitespace-pre-wrap rounded-2xl border border-border bg-card px-4 py-3 text-xs font-mono scrollbar-slim">POST /answer
POST /search
POST /contents
POST /findSimilar
POST /research/v1
GET  /research/v1
GET  /research/v1/{researchId}</pre>
          <p class="text-xs text-muted-foreground">上述接口均走账号池轮询，自动切换失效 key。</p>
        </div>

        <div class="space-y-2">
          <p class="font-semibold">账户配置格式（简化）</p>
          <pre class="overflow-x-auto whitespace-pre-wrap rounded-2xl border border-border bg-card px-4 py-3 text-xs font-mono scrollbar-slim">[
  {
    "id": "account_1",
    "exa_api_key": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "mail_provider": "duckmail",
    "mail_address": "user@example.com",
    "mail_password": "******"
  }
]</pre>
        </div>
      </div>

      <div v-else class="mt-6 space-y-3 text-xs text-muted-foreground leading-relaxed">
        <div class="rounded-2xl border border-amber-200 bg-amber-50 p-4">
          <p class="font-medium text-amber-700">仅限学习与研究用途，禁止滥用。</p>
        </div>
        <div class="rounded-2xl border border-border bg-muted/30 p-4">
          <p class="font-medium text-foreground">你需要自行承担以下责任：</p>
          <ul class="mt-2 space-y-1 pl-4">
            <li>• 遵守 Exa 及邮箱服务商条款</li>
            <li>• 遵守所在地区法律法规</li>
            <li>• 对账号封禁、数据丢失等后果自行负责</li>
          </ul>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const activeTab = ref('api')
const tabs = [
  { id: 'api', label: 'API 文档' },
  { id: 'disclaimer', label: '使用声明' },
]
</script>
