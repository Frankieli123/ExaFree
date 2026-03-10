<template>
  <div class="space-y-5">
    <section class="grid grid-cols-2 gap-3 md:grid-cols-2 xl:grid-cols-4">
      <div
        v-for="stat in stats"
        :key="stat.label"
        class="rounded-3xl border border-border bg-card p-4"
      >
        <div class="flex items-start justify-between gap-3">
          <div class="flex-1 min-w-0">
            <p class="text-xs uppercase tracking-[0.3em] text-muted-foreground">{{ stat.label }}</p>
            <p class="mt-2 text-2xl font-semibold text-foreground tabular-nums">{{ stat.value }}</p>
            <p class="mt-1.5 text-xs leading-relaxed text-muted-foreground">{{ stat.caption }}</p>
          </div>
          <div class="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-full" :class="stat.iconBg">
            <Icon :icon="stat.icon" class="h-4 w-4" :class="stat.iconColor" />
          </div>
        </div>
      </div>
    </section>

    <section class="grid grid-cols-1 gap-4">
      <div class="rounded-3xl border border-border bg-card p-5">
        <div class="flex items-center justify-between mb-4">
          <p class="text-sm font-medium text-foreground">接口请求分布</p>
          <div class="flex items-center gap-1">
            <button
              v-for="range in timeRanges"
              :key="range.value"
              @click="timeRangeHourlyRequests = range.value"
              :class="timeRangeHourlyRequests === range.value
                ? 'bg-accent text-foreground border-primary/50 font-semibold'
                : 'bg-transparent text-muted-foreground hover:bg-accent/50 hover:text-foreground border-border'"
              class="rounded-lg px-3 py-1.5 text-xs font-medium transition-all border"
            >
              {{ range.label }}
            </button>
          </div>
        </div>
        <div ref="hourlyRequestsChartRef" class="h-72 w-full px-2"></div>
      </div>
    </section>

    <section class="grid grid-cols-1 gap-4">
      <div class="rounded-3xl border border-border bg-card p-5">
        <div class="flex items-center justify-between mb-4">
          <p class="text-sm font-medium text-foreground">调用趋势</p>
          <div class="flex items-center gap-1">
            <button
              v-for="range in timeRanges"
              :key="range.value"
              @click="timeRangeTrend = range.value"
              :class="timeRangeTrend === range.value
                ? 'bg-accent text-foreground border-primary/50 font-semibold'
                : 'bg-transparent text-muted-foreground hover:bg-accent/50 hover:text-foreground border-border'"
              class="rounded-lg px-3 py-1.5 text-xs font-medium transition-all border"
            >
              {{ range.label }}
            </button>
          </div>
        </div>
        <div ref="trendChartRef" class="h-56 w-full"></div>
      </div>
    </section>

    <section class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div class="rounded-3xl border border-border bg-card p-5">
        <div class="flex items-center justify-between mb-4">
          <p class="text-sm font-medium text-foreground">成功率趋势</p>
          <div class="flex items-center gap-1">
            <button
              v-for="range in timeRanges"
              :key="range.value"
              @click="timeRangeSuccessRate = range.value"
              :class="timeRangeSuccessRate === range.value
                ? 'bg-accent text-foreground border-primary/50 font-semibold'
                : 'bg-transparent text-muted-foreground hover:bg-accent/50 hover:text-foreground border-border'"
              class="rounded-lg px-3 py-1.5 text-xs font-medium transition-all border"
            >
              {{ range.label }}
            </button>
          </div>
        </div>
        <div ref="successRateChartRef" class="h-56 w-full"></div>
      </div>

      <div class="rounded-3xl border border-border bg-card p-5">
        <div class="flex items-center justify-between mb-4">
          <p class="text-sm font-medium text-foreground">平均响应时间</p>
          <div class="flex items-center gap-1">
            <button
              v-for="range in timeRanges"
              :key="range.value"
              @click="timeRangeResponseTime = range.value"
              :class="timeRangeResponseTime === range.value
                ? 'bg-accent text-foreground border-primary/50 font-semibold'
                : 'bg-transparent text-muted-foreground hover:bg-accent/50 hover:text-foreground border-border'"
              class="rounded-lg px-3 py-1.5 text-xs font-medium transition-all border"
            >
              {{ range.label }}
            </button>
          </div>
        </div>
        <div ref="responseTimeChartRef" class="h-56 w-full"></div>
      </div>
    </section>

    <section class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <div class="rounded-3xl border border-border bg-card p-5">
        <div class="flex items-center justify-between mb-4">
          <p class="text-sm font-medium text-foreground">接口调用占比</p>
          <div class="flex items-center gap-1">
            <button
              v-for="range in timeRanges"
              :key="range.value"
              @click="timeRangeApiShare = range.value"
              :class="timeRangeApiShare === range.value
                ? 'bg-accent text-foreground border-primary/50 font-semibold'
                : 'bg-transparent text-muted-foreground hover:bg-accent/50 hover:text-foreground border-border'"
              class="rounded-lg px-3 py-1.5 text-xs font-medium transition-all border"
            >
              {{ range.label }}
            </button>
          </div>
        </div>
        <div ref="apiShareChartRef" class="h-56 w-full"></div>
      </div>

      <div class="rounded-3xl border border-border bg-card p-5">
        <div class="flex items-center justify-between mb-4">
          <p class="text-sm font-medium text-foreground">接口调用排行</p>
          <div class="flex items-center gap-1">
            <button
              v-for="range in timeRanges"
              :key="range.value"
              @click="timeRangeApiRank = range.value"
              :class="timeRangeApiRank === range.value
                ? 'bg-accent text-foreground border-primary/50 font-semibold'
                : 'bg-transparent text-muted-foreground hover:bg-accent/50 hover:text-foreground border-border'"
              class="rounded-lg px-3 py-1.5 text-xs font-medium transition-all border"
            >
              {{ range.label }}
            </button>
          </div>
        </div>
        <div ref="apiRankChartRef" class="h-56 w-full"></div>
      </div>
    </section>

  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { Icon } from '@iconify/vue'
import { statsApi } from '@/api'
import {
  getLineChartTheme,
  getPieChartTheme,
  createLineSeries,
  createPieDataItem,
  chartColors,
  getApiColor,
  filterValidApis,
  formatApiLabel,
} from '@/lib/chartTheme'

type ChartInstance = {
  setOption: (option: unknown) => void
  resize: () => void
  dispose: () => void
  off?: (eventName: string) => void
  on?: (eventName: string, handler: (params: any) => void) => void
  dispatchAction?: (action: { type: string; name: string }) => void
}

// 时间范围选择
const timeRanges = [
  { label: '24小时', value: '24h' },
  { label: '7天', value: '7d' },
  { label: '30天', value: '30d' },
]

// 每个图表独立的时间范围
const timeRangeHourlyRequests = ref('24h')
const timeRangeTrend = ref('24h')
const timeRangeSuccessRate = ref('24h')
const timeRangeApiShare = ref('24h')
const timeRangeApiRank = ref('24h')
const timeRangeResponseTime = ref('24h')

// 创建图表监听器的工厂函数
function createChartWatcher(chartType: string, updateFn: () => void) {
  return async (newVal: string) => {
    await loadChartData(chartType, newVal)
    updateFn()
  }
}

// 监听各图表时间范围变化 - 只更新对应图表
watch(timeRangeHourlyRequests, createChartWatcher('hourlyRequests', updateHourlyRequestsChart))
watch(timeRangeTrend, createChartWatcher('trend', updateTrendChart))
watch(timeRangeSuccessRate, createChartWatcher('successRate', updateSuccessRateChart))
watch(timeRangeApiShare, createChartWatcher('apiShare', updateApiShareChart))
watch(timeRangeApiRank, createChartWatcher('apiRank', updateApiRankChart))
watch(timeRangeResponseTime, createChartWatcher('responseTime', updateResponseTimeChart))

const stats = ref([
  {
    label: '24h 总请求',
    value: '0',
    caption: '搜索 API 全部调用次数',
    icon: 'lucide:activity',
    iconBg: 'bg-sky-100',
    iconColor: 'text-sky-600'
  },
  {
    label: '24h 成功请求',
    value: '0',
    caption: '状态码 2xx 的成功调用',
    icon: 'lucide:check-circle',
    iconBg: 'bg-emerald-100',
    iconColor: 'text-emerald-600'
  },
  {
    label: '24h 失败请求',
    value: '0',
    caption: '状态码非 2xx 的失败调用',
    icon: 'lucide:alert-circle',
    iconBg: 'bg-red-100',
    iconColor: 'text-red-600'
  },
  {
    label: '24h 成功率',
    value: '100%',
    caption: '成功请求 / 总请求',
    icon: 'lucide:badge-percent',
    iconBg: 'bg-amber-100',
    iconColor: 'text-amber-600'
  },
])

// 每个图表独立的数据状态
const chartData = ref({
  hourlyRequests: {
    labels: [] as string[],
    apiRequests: {} as Record<string, number[]>,
  },
  trend: {
    labels: [] as string[],
    totalRequests: [] as number[],
    failedRequests: [] as number[],
    successRequests: [] as number[],
  },
  successRate: {
    labels: [] as string[],
    totalRequests: [] as number[],
    failedRequests: [] as number[],
  },
  apiShare: {
    apiRequests: {} as Record<string, number[]>,
  },
  apiRank: {
    apiRequests: {} as Record<string, number[]>,
  },
  responseTime: {
    labels: [] as string[],
    apiTtfbTimes: {} as Record<string, number[]>,
    apiTotalTimes: {} as Record<string, number[]>,
  },
})

const trendChartRef = ref<HTMLDivElement | null>(null)
const apiShareChartRef = ref<HTMLDivElement | null>(null)
const successRateChartRef = ref<HTMLDivElement | null>(null)
const hourlyRequestsChartRef = ref<HTMLDivElement | null>(null)
const apiRankChartRef = ref<HTMLDivElement | null>(null)
const responseTimeChartRef = ref<HTMLDivElement | null>(null)

const charts = {
  trend: null as ChartInstance | null,
  apiShare: null as ChartInstance | null,
  successRate: null as ChartInstance | null,
  hourlyRequests: null as ChartInstance | null,
  apiRank: null as ChartInstance | null,
  responseTime: null as ChartInstance | null,
}

function initChart(
  ref: HTMLDivElement | null,
  key: keyof typeof charts,
  updateFn: () => void
) {
  const echarts = (window as any).echarts as { init: (el: HTMLElement) => ChartInstance } | undefined
  if (!echarts || !ref) return
  charts[key] = echarts.init(ref)
  updateFn()
}

onMounted(async () => {
  // 加载账号统计
  await loadAccountStats()

  // 初始化所有图表（使用默认24h数据）
  await Promise.all([
    loadChartData('hourlyRequests', timeRangeHourlyRequests.value),
    loadChartData('trend', timeRangeTrend.value),
    loadChartData('successRate', timeRangeSuccessRate.value),
    loadChartData('apiShare', timeRangeApiShare.value),
    loadChartData('apiRank', timeRangeApiRank.value),
    loadChartData('responseTime', timeRangeResponseTime.value),
  ])

  initChart(trendChartRef.value, 'trend', updateTrendChart)
  initChart(apiShareChartRef.value, 'apiShare', updateApiShareChart)
  initChart(successRateChartRef.value, 'successRate', updateSuccessRateChart)
  initChart(hourlyRequestsChartRef.value, 'hourlyRequests', updateHourlyRequestsChart)
  initChart(apiRankChartRef.value, 'apiRank', updateApiRankChart)
  initChart(responseTimeChartRef.value, 'responseTime', updateResponseTimeChart)

  window.addEventListener('resize', handleResize)
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', handleResize)
  Object.values(charts).forEach(chart => chart?.dispose())
})

function updateTrendChart() {
  if (!charts.trend) return

  const theme = getLineChartTheme()

  charts.trend.setOption({
    ...theme,
    xAxis: {
      ...theme.xAxis,
      data: chartData.value.trend.labels,
    },
    series: [
      createLineSeries('成功', chartData.value.trend.successRequests, chartColors.primary, {
        areaOpacity: 0.25,
        zIndex: 1,
      }),
      createLineSeries('失败', chartData.value.trend.failedRequests, chartColors.danger, {
        areaOpacity: 0.3,
        zIndex: 2,
      }),
    ],
  })
  requestAnimationFrame(() => charts.trend?.resize())
}

function getApiTotals() {
  return Object.entries(chartData.value.apiShare.apiRequests)
    .map(([apiName, data]) => ({
      apiName,
      data: createPieDataItem(formatApiLabel(apiName), data.reduce((sum, item) => sum + item, 0), getApiColor(apiName)),
      total: data.reduce((sum, item) => sum + item, 0),
    }))
    .filter(item => item.total > 0)
}

function updateApiShareChart() {
  if (!charts.apiShare) return

  const isMobile = window.innerWidth < 768
  const theme = getPieChartTheme(isMobile)
  const apiData = getApiTotals().map(item => item.data)

  charts.apiShare.setOption({
    ...theme,
    tooltip: {
      ...theme.tooltip,
      formatter: (params: { name: string; value: number; percent: number }) =>
        `${params.name}: ${params.value} 次 (${params.percent}%)`,
    },
    legend: {
      ...theme.legend,
      data: apiData.map(item => item.name),
    },
    series: [
      {
        ...theme.series,
        center: ['50%', '50%'],
        data: apiData,
      },
    ],
  })
  requestAnimationFrame(() => charts.apiShare?.resize())
}

function handleResize() {
  Object.entries(charts).forEach(([key, chart]) => {
    if (chart) {
      if (key === 'apiShare') {
        updateApiShareChart()
      } else {
        chart.resize()
      }
    }
  })
}

// 加载数据面板统计
async function loadAccountStats() {
  try {
    const overview = await statsApi.overview('24h')
    const trend = overview.trend || {
      total_requests: [],
      failed_requests: [],
    }

    const totalRequests = (trend.total_requests || []).reduce((sum, item) => sum + item, 0)
    const failedRequests = (trend.failed_requests || []).reduce((sum, item) => sum + item, 0)
    const successRequests = Math.max(totalRequests - failedRequests, 0)
    const successRate = totalRequests > 0 ? ((successRequests / totalRequests) * 100).toFixed(1) : '100.0'

    stats.value[0].value = totalRequests.toLocaleString()
    stats.value[1].value = successRequests.toLocaleString()
    stats.value[2].value = failedRequests.toLocaleString()
    stats.value[3].value = `${successRate}%`
  } catch (error) {
    console.error('Failed to load account stats:', error)
  }
}

// 为指定图表加载数据
async function loadChartData(chartType: string, timeRange: string) {
  try {
    const overview = await statsApi.overview(timeRange)
    const trend = overview.trend || {
      labels: [],
      total_requests: [],
      failed_requests: [],
      api_requests: {},
      api_ttfb_times: {},
      api_total_times: {},
    }

    const apiRequests = trend.api_requests || {}
    const apiTtfbTimes = trend.api_ttfb_times || {}
    const apiTotalTimes = trend.api_total_times || {}
    const failed = trend.failed_requests || []
    const successSeries = (trend.total_requests || []).map((total, idx) => Math.max(total - (failed[idx] || 0), 0))

    // 根据图表类型更新对应的数据
    switch (chartType) {
      case 'hourlyRequests':
        chartData.value.hourlyRequests.labels = trend.labels || []
        chartData.value.hourlyRequests.apiRequests = filterValidApis(apiRequests)
        break
      case 'trend':
        chartData.value.trend.labels = trend.labels || []
        chartData.value.trend.totalRequests = trend.total_requests || []
        chartData.value.trend.failedRequests = failed
        chartData.value.trend.successRequests = successSeries
        break
      case 'successRate':
        chartData.value.successRate.labels = trend.labels || []
        chartData.value.successRate.totalRequests = trend.total_requests || []
        chartData.value.successRate.failedRequests = failed
        break
      case 'apiShare':
        chartData.value.apiShare.apiRequests = filterValidApis(apiRequests)
        break
      case 'apiRank':
        chartData.value.apiRank.apiRequests = filterValidApis(apiRequests)
        break
      case 'responseTime':
        chartData.value.responseTime.labels = trend.labels || []
        chartData.value.responseTime.apiTtfbTimes = filterValidApis(apiTtfbTimes)
        chartData.value.responseTime.apiTotalTimes = filterValidApis(apiTotalTimes)
        break
    }
  } catch (error) {
    console.error(`Failed to load ${chartType} data:`, error)
  }
}


function updateSuccessRateChart() {
  if (!charts.successRate) return

  const theme = getLineChartTheme()
  const successRates = chartData.value.successRate.totalRequests.map((total, idx) => {
    const failure = chartData.value.successRate.failedRequests[idx] || 0
    return total > 0 ? Math.round(((total - failure) / total) * 100) : 100
  })

  charts.successRate.setOption({
    ...theme,
    tooltip: {
      ...theme.tooltip,
      trigger: 'axis',
      formatter: (params: any) => {
        if (!params || params.length === 0) return ''
        const param = params[0]
        return `<div style="font-weight: 600; margin-bottom: 4px;">${param.axisValue}</div>
          <div style="display: flex; justify-content: space-between; gap: 16px; align-items: center;">
            <span>${param.marker} ${param.seriesName}</span>
            <span style="font-weight: 600;">${param.value}%</span>
          </div>`
      },
    },
    grid: {
      ...theme.grid,
      top: 32,
      bottom: 32,
    },
    xAxis: {
      ...theme.xAxis,
      data: chartData.value.successRate.labels,
    },
    yAxis: {
      ...theme.yAxis,
      max: 100,
      axisLabel: {
        ...theme.yAxis.axisLabel,
        formatter: '{value}%',
      },
    },
    series: [
      {
        name: '成功率',
        type: 'line',
        data: successRates,
        smooth: true,
        showSymbol: false,
        lineStyle: {
          width: 3,
        },
        areaStyle: {
          opacity: 0.3,
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: chartColors.success },
              { offset: 1, color: 'rgba(16, 185, 129, 0.1)' },
            ],
          },
        },
        itemStyle: {
          color: chartColors.success,
        },
      },
    ],
  })
  requestAnimationFrame(() => charts.successRate?.resize())
}

function updateHourlyRequestsChart() {
  if (!charts.hourlyRequests) return

  const theme = getLineChartTheme()
  const apiNames = Object.keys(chartData.value.hourlyRequests.apiRequests)

  if (apiNames.length === 0) {
    charts.hourlyRequests.setOption({
      ...theme,
      grid: {
        ...theme.grid,
        top: 32,
        bottom: 32,
      },
      xAxis: {
        ...theme.xAxis,
        data: chartData.value.hourlyRequests.labels,
      },
      yAxis: {
        ...theme.yAxis,
      },
      series: [
        {
          name: '总请求',
          type: 'bar',
          data: [],
          barWidth: '60%',
          itemStyle: {
            color: chartColors.primary,
            borderRadius: [4, 4, 0, 0],
          },
        },
      ],
    })
    requestAnimationFrame(() => charts.hourlyRequests?.resize())
    return
  }

  const series = apiNames.map((apiName, index) => ({
    name: formatApiLabel(apiName),
    type: 'bar',
    stack: 'total',
    data: chartData.value.hourlyRequests.apiRequests[apiName],
    itemStyle: {
      color: getApiColor(apiName),
      borderRadius: index === apiNames.length - 1 ? [4, 4, 0, 0] : [0, 0, 0, 0],
    },
  }))

  charts.hourlyRequests.setOption({
    ...theme,
    tooltip: {
      ...theme.tooltip,
      trigger: 'axis',
      axisPointer: {
        type: 'shadow',
      },
      formatter: (params: any) => {
        if (!params || params.length === 0) return ''
        let result = `<div style="font-weight: 600; margin-bottom: 4px;">${params[0].axisValue}</div>`
        let total = 0
        params.forEach((item: any) => {
          total += item.value || 0
          result += `<div style="display: flex; justify-content: space-between; gap: 16px; align-items: center;">
            <span>${item.marker} ${item.seriesName}</span>
            <span style="font-weight: 600;">${item.value || 0}</span>
          </div>`
        })
        result += `<div style="margin-top: 6px; padding-top: 6px; border-top: 1px solid #e5e5e5; font-weight: 600;">
          总计: ${total}
        </div>`
        return result
      },
    },
    legend: {
      ...theme.legend,
      data: apiNames.map(apiName => formatApiLabel(apiName)),
      top: 0,
      right: 0,
      type: 'scroll',
      pageIconSize: 10,
      pageTextStyle: {
        fontSize: 10,
      },
    },
    grid: {
      ...theme.grid,
      top: apiNames.length > 5 ? 56 : 48,
      bottom: 32,
    },
    xAxis: {
      ...theme.xAxis,
      data: chartData.value.hourlyRequests.labels,
    },
    yAxis: {
      ...theme.yAxis,
    },
    series: series,
  })

  requestAnimationFrame(() => charts.hourlyRequests?.resize())
}

function updateApiRankChart() {
  if (!charts.apiRank) return

  const theme = getLineChartTheme()
  const apiTotals = Object.entries(chartData.value.apiRank.apiRequests)
    .map(([apiName, data]) => ({
      apiName,
      label: formatApiLabel(apiName),
      total: data.reduce((sum, item) => sum + item, 0),
    }))
    .filter(item => item.total > 0)
    .sort((a, b) => b.total - a.total)

  const apiLabels = apiTotals.map(item => item.label)
  const apiValues = apiTotals.map(item => item.total)
  const apiColors = apiTotals.map(item => getApiColor(item.apiName))

  charts.apiRank.setOption({
    ...theme,
    grid: {
      left: 12,
      right: 60,
      top: 16,
      bottom: 16,
      containLabel: true,
    },
    xAxis: {
      type: 'value',
      axisLine: {
        show: false,
      },
      axisTick: {
        show: false,
      },
      axisLabel: {
        ...theme.xAxis.axisLabel,
        fontSize: 10,
      },
      splitLine: {
        lineStyle: {
          color: '#e5e5e5',
          type: 'solid',
        },
      },
    },
    yAxis: {
      type: 'category',
      data: apiLabels,
      axisLine: {
        show: false,
      },
      axisTick: {
        show: false,
      },
      axisLabel: {
        ...theme.yAxis.axisLabel,
        fontSize: 11,
      },
    },
    series: [
      {
        type: 'bar',
        data: apiValues.map((value, idx) => ({
          value,
          itemStyle: {
            color: apiColors[idx],
            borderRadius: [0, 4, 4, 0],
          },
        })),
        barWidth: '50%',
        label: {
          show: true,
          position: 'right',
          fontSize: 11,
          color: '#6b6b6b',
          formatter: '{c}',
        },
      },
    ],
  })
  requestAnimationFrame(() => charts.apiRank?.resize())
}

function updateResponseTimeChart() {
  if (!charts.responseTime) return

  const theme = getLineChartTheme()
  const apiNames = Object.keys(chartData.value.responseTime.apiTtfbTimes)

  if (apiNames.length === 0) {
    charts.responseTime.setOption({
      ...theme,
      grid: {
        ...theme.grid,
        top: 32,
        bottom: 32,
      },
      xAxis: {
        ...theme.xAxis,
        data: chartData.value.responseTime.labels,
      },
      yAxis: {
        ...theme.yAxis,
        axisLabel: {
          ...theme.yAxis.axisLabel,
          formatter: '{value}s',
        },
      },
      series: [],
    })
    requestAnimationFrame(() => charts.responseTime?.resize())
    return
  }

  // 构建系列：每个接口两条线（完成实线 + 首响虚线）
  const series: any[] = []
  const legendData: string[] = []

  apiNames.forEach((apiName) => {
    const color = getApiColor(apiName)
    const apiLabel = formatApiLabel(apiName)
    legendData.push(apiLabel)

    // 将毫秒转换为秒
    const ttfbInSeconds = chartData.value.responseTime.apiTtfbTimes[apiName].map((ms: number) => Number((ms / 1000).toFixed(2)))
    const totalInSeconds = chartData.value.responseTime.apiTotalTimes[apiName].map((ms: number) => Number((ms / 1000).toFixed(2)))

    // 完成时间 - 实线（主线，显示在图例中）
    series.push(
      createLineSeries(apiLabel, totalInSeconds, color, {
        smooth: true,
        areaOpacity: 0.15,
        zIndex: 2,
      })
    )

    // 首响时间 - 虚线（不显示在图例中，但跟随主线的显示状态）
    const ttfbSeries = createLineSeries(apiLabel, ttfbInSeconds, color, {
      smooth: true,
      areaOpacity: 0,
      zIndex: 1,
      lineStyle: {
        type: 'dashed',
        width: 2,
      },
    })
    // 修改name以区分，但使用相同的legendName来关联
    ttfbSeries.name = `${apiLabel}-ttfb`
    series.push(ttfbSeries)
  })

  charts.responseTime.setOption({
    ...theme,
    tooltip: {
      ...theme.tooltip,
      trigger: 'axis',
      formatter: (params: any) => {
        if (!params || params.length === 0) return ''
        let result = `<div style="font-weight: 600; margin-bottom: 4px;">${params[0].axisValue}</div>`

        // 按接口分组显示
        const apiMap = new Map<string, { total?: number, ttfb?: number, color?: string }>()
        params.forEach((item: any) => {
          const seriesName = item.seriesName
          if (seriesName.endsWith('-ttfb')) {
            const apiName = seriesName.replace('-ttfb', '')
            const data = apiMap.get(apiName) || {}
            data.ttfb = item.value
            data.color = item.color
            apiMap.set(apiName, data)
          } else {
            const data = apiMap.get(seriesName) || {}
            data.total = item.value
            data.color = item.color
            apiMap.set(seriesName, data)
          }
        })

        apiMap.forEach((data, apiName) => {
          const marker = `<span style="display:inline-block;margin-right:4px;border-radius:10px;width:10px;height:10px;background-color:${data.color};"></span>`
          result += `<div style="margin-top: 4px;">
            <div style="font-weight: 600; margin-bottom: 2px;">${marker}${apiName}</div>
            <div style="display: flex; justify-content: space-between; gap: 16px; padding-left: 14px;">
              <span style="color: #6b6b6b;">完成时间</span>
              <span style="font-weight: 600;">${data.total || 0}s</span>
            </div>
            <div style="display: flex; justify-content: space-between; gap: 16px; padding-left: 14px;">
              <span style="color: #6b6b6b;">首响时间</span>
              <span style="font-weight: 600;">${data.ttfb || 0}s</span>
            </div>
          </div>`
        })
        return result
      },
    },
    legend: {
      ...theme.legend,
      data: legendData,
      top: 0,
      right: 0,
      type: 'scroll',
      pageIconSize: 10,
      pageTextStyle: {
        fontSize: 10,
      },
      selectedMode: 'multiple',
    },
    grid: {
      ...theme.grid,
      top: apiNames.length > 3 ? 56 : 48,
      bottom: 32,
    },
    xAxis: {
      ...theme.xAxis,
      data: chartData.value.responseTime.labels,
    },
    yAxis: {
      ...theme.yAxis,
      axisLabel: {
        ...theme.yAxis.axisLabel,
        formatter: '{value}s',
      },
    },
    series: series,
  })

  // 监听图例选择事件，同步控制首响时间线的显示/隐藏
  charts.responseTime.off?.('legendselectchanged')
  charts.responseTime.on?.('legendselectchanged', (params: any) => {
    const selected = params.selected

    // 遍历所有接口，控制对应的ttfb线
    Object.keys(selected).forEach((apiLabel) => {
      const ttfbSeriesName = `${apiLabel}-ttfb`
      const isSelected = selected[apiLabel]

      // 使用dispatchAction来控制series的显示/隐藏
      charts.responseTime.dispatchAction?.({
        type: isSelected ? 'legendSelect' : 'legendUnSelect',
        name: ttfbSeriesName,
      })
    })
  })

  requestAnimationFrame(() => charts.responseTime?.resize())
}

</script>

