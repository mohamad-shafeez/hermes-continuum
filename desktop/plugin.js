/**
 * Continuum Console - the Hermes Desktop surface for hermes-continuum.
 *
 * Loaded uncompiled (no JSX, SDK + react only).  All colors come from the
 * active theme's CSS variables, so the Console reskins with every theme.
 *
 * Surfaces:
 *   - full page `/continuum` with Overview, Timeline, Memory, and
 *     Security & Checkpoints views
 *   - a compact right-hand pane
 *   - a status-bar review counter
 *   - a palette command and a `mod+alt+c` keybind
 */

import {
  Codicon,
  cn,
  host,
  KEYBINDS_AREA,
  PALETTE_AREA,
  PANES_AREA,
  queryClient,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  STATUSBAR_AREAS,
  useQuery,
  useValue
} from '@hermes/plugin-sdk'
import { useEffect, useMemo, useState } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

const ROUTE = '/continuum'
const QUERY_ROOT = ['continuum']

const VIEWS = [
  { id: 'overview', label: 'Overview', icon: 'pulse' },
  { id: 'pillars', label: 'Nine Systems', icon: 'layers' },
  { id: 'forge', label: 'Forge', icon: 'layers' },
  { id: 'timeline', label: 'Timeline', icon: 'history' },
  { id: 'memory', label: 'Memory', icon: 'database' },
  { id: 'security', label: 'Security & Checkpoints', icon: 'shield' }
]

const MODULE_TABS = [
  'All',
  'Tripwire',
  'Oneiros',
  'Continuum',
  'Kairos',
  'Aletheia',
  'Telos',
  'Moirai',
  'Metis',
  'Hephaestus'
]

const MODULE_COLORS = {
  Tripwire: 'var(--ui-red)',
  Oneiros: 'var(--ui-yellow)',
  Continuum: 'var(--ui-cyan)',
  Kairos: 'var(--ui-cyan)',
  Aletheia: 'var(--ui-green)',
  Telos: 'var(--ui-purple)',
  Moirai: 'var(--ui-orange)',
  Metis: 'var(--ui-red)',
  Hephaestus: 'var(--ui-warm)',
  System: 'var(--ui-text-quaternary)'
}

const OUTCOME_COLORS = {
  block: 'var(--ui-red)',
  approve: 'var(--ui-orange)',
  allow: 'var(--ui-green)'
}

const STATUS_COLORS = {
  confirmed: 'var(--ui-green)',
  candidate: 'var(--ui-yellow)',
  rejected: 'var(--ui-red)',
  superseded: 'var(--ui-text-quaternary)',
  contradicted: 'var(--ui-purple)'
}

const surface = {
  border: '1px solid var(--ui-stroke-secondary)',
  background: 'var(--ui-bg-card)',
  borderRadius: '12px'
}

function panelStyle(extra) {
  return Object.assign({}, surface, extra || {})
}

function fmtInt(value) {
  const number = Number(value || 0)
  return Number.isFinite(number) ? number.toLocaleString() : '0'
}

function fmtTs(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return date.toLocaleString()
}

function shortId(value) {
  const text = String(value || '')
  return text.length > 10 ? text.slice(0, 10) : text
}

function groupFacts(facts) {
  const groups = new Map()
  for (const fact of facts || []) {
    const key = String(fact.fact_key || 'fact')
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(fact)
  }
  const result = []
  groups.forEach((versions, key) => {
    versions.sort((a, b) => Number(b.version || 0) - Number(a.version || 0))
    const head =
      versions.find(item => item.is_current_confirmed) ||
      versions.find(item => item.is_latest) ||
      versions[0]
    result.push({ key, versions, head })
  })
  result.sort((a, b) => a.key.localeCompare(b.key))
  return result
}

function eventTickHeight(event) {
  const text = `${event.event_type || ''}:${event.id || ''}`
  let hash = 0
  for (let i = 0; i < text.length; i += 1) hash = (hash * 31 + text.charCodeAt(i)) >>> 0
  return 22 + (hash % 78)
}

function useAction() {
  const [busy, setBusy] = useState(false)
  const run = async (fn, successMessage) => {
    setBusy(true)
    try {
      const result = await fn()
      queryClient.invalidateQueries({ queryKey: QUERY_ROOT })
      if (successMessage) host.notify({ kind: 'info', message: successMessage })
      return result
    } catch (error) {
      host.notifyError(error, 'Continuum action failed')
      return null
    } finally {
      setBusy(false)
    }
  }
  return [busy, run]
}

// ---------------------------------------------------------------------------
// Primitive UI
// ---------------------------------------------------------------------------
function OrbitMark() {
  return jsxs('div', {
    className: 'relative h-11 w-11 shrink-0',
    children: [
      jsx('div', {
        className: 'absolute inset-0 rounded-full',
        style: { border: '1px solid var(--ui-stroke-secondary)' }
      }),
      jsx('div', {
        className: 'absolute rounded-full',
        style: { inset: '7px', border: '1px solid var(--ui-accent)', opacity: 0.75 }
      }),
      jsx('div', {
        className: 'absolute left-1/2 top-1/2 h-1.5 w-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full',
        style: { background: 'var(--ui-accent)' }
      }),
      jsx('div', {
        className: 'absolute inset-0 animate-spin',
        style: { animationDuration: '18s' },
        children: jsx('div', {
          className: 'absolute left-1/2 -translate-x-1/2 rounded-full h-2 w-2',
          style: { top: '-4px', background: 'var(--ui-warm)' }
        })
      })
    ]
  })
}

function Badge({ children, color, title }) {
  return jsx('span', {
    title,
    className: 'inline-flex items-center px-2 py-0.5 rounded-full text-[10px] uppercase whitespace-nowrap',
    style: {
      color,
      border: `1px solid ${color}`,
      letterSpacing: '0.08em',
      opacity: 0.95
    },
    children
  })
}

function ActionButton({ children, onClick, tone, disabled, title, type }) {
  let style
  if (tone === 'primary') {
    style = {
      background: 'var(--ui-accent)',
      color: 'var(--ui-bg-editor)',
      border: '1px solid var(--ui-accent)'
    }
  } else if (tone === 'danger') {
    style = {
      color: 'var(--ui-red)',
      border: '1px solid var(--ui-red)',
      background: 'transparent'
    }
  } else {
    style = {
      color: 'var(--ui-text-secondary)',
      border: '1px solid var(--ui-stroke-secondary)',
      background: 'transparent'
    }
  }
  return jsx('button', {
    type: type || 'button',
    disabled,
    title,
    onClick,
    className:
      'px-3 py-1 rounded-md text-xs font-medium cursor-pointer transition-colors disabled:opacity-50 disabled:cursor-default',
    style,
    children
  })
}

function TextInput(props) {
  const { value, onChange, placeholder, type, onKeyDown, name, style } = props
  return jsx('input', {
    type: type || 'text',
    name: name || undefined,
    value: value === undefined || value === null ? '' : value,
    placeholder,
    spellCheck: false,
    autoComplete: type === 'password' ? 'new-password' : 'off',
    onKeyDown,
    onChange: event => onChange(event.target.value),
    className: 'px-3 py-1.5 text-xs rounded-md w-full',
    style: Object.assign(
      {
        border: '1px solid var(--ui-stroke-secondary)',
        background: 'var(--ui-bg-input)',
        color: 'var(--ui-text-primary)'
      },
      style || {}
    )
  })
}

function Panel({ children, className, style }) {
  return jsx('div', {
    className: cn('p-4', className),
    style: panelStyle(style),
    children
  })
}

function SectionTitle({ children, hint }) {
  return jsxs('div', {
    className: 'flex items-baseline justify-between gap-3 mb-3',
    children: [
      jsx('div', {
        className: 'text-[10px] uppercase font-semibold',
        style: { color: 'var(--ui-text-tertiary)', letterSpacing: '0.14em' },
        children
      }),
      hint
        ? jsx('div', {
            className: 'text-[10px] tabular-nums',
            style: { color: 'var(--ui-text-quaternary)' },
            children: hint
          })
        : null
    ]
  })
}

function StatTile({ label, value, detail, accent }) {
  return jsxs('div', {
    className: 'p-3 flex flex-col gap-1',
    style: panelStyle({ borderRadius: '10px' }),
    children: [
      jsx('div', {
        className: 'text-[10px] uppercase',
        style: { color: 'var(--ui-text-tertiary)', letterSpacing: '0.12em' },
        children: label
      }),
      jsx('div', {
        className: 'text-xl font-semibold tabular-nums leading-none',
        style: { color: accent || 'var(--ui-text-primary)' },
        children: fmtInt(value)
      }),
      detail
        ? jsx('div', {
            className: 'text-[10px] truncate',
            style: { color: 'var(--ui-text-quaternary)' },
            children: detail
          })
        : null
    ]
  })
}

function EmptyNote({ children }) {
  return jsx('div', {
    className: 'text-xs py-6 text-center',
    style: { color: 'var(--ui-text-quaternary)' },
    children
  })
}

function GatewayChip({ gateway }) {
  const open = gateway === 'open'
  return jsxs('span', {
    className: 'inline-flex items-center gap-1.5 text-[10px]',
    style: { color: 'var(--ui-text-tertiary)' },
    children: [
      jsx('span', {
        className: 'h-1.5 w-1.5 rounded-full',
        style: {
          background: open ? 'var(--ui-green)' : 'var(--ui-orange)',
          boxShadow: open ? '0 0 0 3px color-mix(in srgb, var(--ui-green) 18%, transparent)' : 'none'
        }
      }),
      open ? 'gateway open' : `gateway ${gateway || 'idle'}`
    ]
  })
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------
function Ribbon({ events }) {
  const ordered = [...(events || [])].reverse()
  if (!ordered.length) {
    return jsx('div', {
      className: 'h-12 flex items-center text-xs',
      style: { color: 'var(--ui-text-quaternary)' },
      children: 'No events recorded yet. Continuum starts observing on the next turn.'
    })
  }
  return jsx('div', {
    className: 'flex items-end gap-1 h-12',
    children: ordered.map((event, index) =>
      jsx(
        'div',
        {
          title: `${event.event_type} · ${event.summary}`,
          className: 'flex-1 rounded-sm',
          style: {
            minWidth: '2px',
            height: `${eventTickHeight(event)}%`,
            background: MODULE_COLORS[event.module] || MODULE_COLORS.System,
            opacity: event.event_type === 'action_blocked' ? 1 : 0.62
          }
        },
        `${event.event_id || index}`
      )
    )
  })
}

function EventRow({ event, onOpen }) {
  return jsxs('div', {
    className: 'flex items-center gap-3 py-2',
    style: { borderTop: '1px solid var(--ui-stroke-tertiary)' },
    children: [
      jsx('span', {
        className: 'h-1.5 w-1.5 rounded-full shrink-0',
        style: { background: MODULE_COLORS[event.module] || MODULE_COLORS.System }
      }),
      jsxs('div', {
        className: 'min-w-0 flex-1',
        children: [
          jsx('div', {
            className: 'text-xs truncate',
            style: { color: 'var(--ui-text-primary)' },
            children: event.summary
          }),
          jsxs('div', {
            className: 'text-[10px] truncate',
            style: { color: 'var(--ui-text-quaternary)' },
            children: [event.event_type, ' · ', event.module]
          })
        ]
      }),
      jsx('div', {
        className: 'text-[10px] whitespace-nowrap tabular-nums',
        style: { color: 'var(--ui-text-tertiary)' },
        children: fmtTs(event.timestamp_utc)
      }),
      onOpen
        ? jsx('button', {
            type: 'button',
            onClick: onOpen,
            className: 'text-[10px] cursor-pointer',
            style: { color: 'var(--ui-accent)' },
            children: 'open'
          })
        : null
    ]
  })
}

function ReviewRow({ fact, busy, onConfirm, onReject }) {
  return jsxs('div', {
    className: 'py-2 flex flex-col gap-1',
    style: { borderTop: '1px solid var(--ui-stroke-tertiary)' },
    children: [
      jsx('div', {
        className: 'text-xs font-medium truncate',
        style: { color: 'var(--ui-text-primary)' },
        children: fact.fact_key
      }),
      jsx('div', {
        className: 'text-[10px] truncate',
        style: { color: 'var(--ui-text-tertiary)' },
        children: fact.value
      }),
      jsxs('div', {
        className: 'flex items-center gap-2 pt-1',
        children: [
          jsx(ActionButton, {
            tone: 'primary',
            disabled: busy,
            onClick: () => onConfirm(fact),
            children: 'Confirm'
          }),
          jsx(ActionButton, {
            disabled: busy,
            onClick: () => onReject(fact),
            children: 'Reject'
          }),
          jsx('span', {
            className: 'text-[10px] ml-auto',
            style: { color: 'var(--ui-text-quaternary)' },
            children: `v${fact.version} · ${Math.round(Number(fact.confidence || 0) * 100)}%`
          })
        ]
      })
    ]
  })
}

function OverviewView({ ctx, status, overview, onRefresh, onNavigate, onRunDream, busy, run }) {
  const stats = (status && status.stats) || {}
  const memory = (status && status.memory_counts) || {}
  const security = (status && status.security_counts) || {}
  const pending = (overview && overview.pending_candidates) || []
  const resume = status && status.active_resume_brief

  const mutate = (path, body, message) =>
    run(() => ctx.rest(path, { method: 'POST', body: body || {} }), message)

  return jsxs('div', {
    className: 'flex flex-col gap-4',
    children: [
      resume
        ? jsxs('div', {
            className: 'p-3 flex items-start gap-3',
            style: {
              border: '1px solid var(--ui-accent)',
              background: 'color-mix(in srgb, var(--ui-accent) 8%, transparent)',
              borderRadius: '10px'
            },
            children: [
              jsx(Codicon, {
                name: 'bookmark',
                size: '0.8rem',
                style: { color: 'var(--ui-accent)' }
              }),
              jsxs('div', {
                className: 'min-w-0 flex-1',
                children: [
                  jsx('div', {
                    className: 'text-[10px] uppercase font-semibold',
                    style: { color: 'var(--ui-accent)', letterSpacing: '0.12em' },
                    children: 'Active resume brief'
                  }),
                  jsx('div', {
                    className: 'text-xs pt-1',
                    style: { color: 'var(--ui-text-secondary)' },
                    children: resume.preview
                  })
                ]
              }),
              jsx(ActionButton, {
                disabled: busy,
                onClick: () => host.navigate(ROUTE),
                children: 'Open'
              }),
              jsx(ActionButton, {
                disabled: busy,
                onClick: () =>
                  mutate(
                    `/resume-brief/${encodeURIComponent(resume.id)}/dismiss`,
                    {},
                    'Resume brief dismissed'
                  ),
                children: 'Dismiss'
              })
            ]
          })
        : null,
      jsxs('div', {
        className: 'grid grid-cols-2 lg:grid-cols-6 gap-3',
        children: [
          jsx(StatTile, { label: 'Events', value: stats.events, detail: status.last_event_at ? fmtTs(status.last_event_at) : 'none yet' }),
          jsx(StatTile, { label: 'Sources', value: stats.sources, detail: 'labelled origins' }),
          jsx(StatTile, { label: 'Episodes', value: stats.episodes, detail: 'captured turns' }),
          jsx(StatTile, { label: 'Facts', value: stats.facts, detail: `${fmtInt(memory.confirmed)} confirmed`, accent: 'var(--ui-green)' }),
          jsx(StatTile, { label: 'Review', value: status.needs_review, detail: 'pending candidates', accent: status.needs_review ? 'var(--ui-yellow)' : undefined }),
          jsx(StatTile, { label: 'Decisions', value: stats.decisions, detail: `${fmtInt(security.block)} blocked`, accent: security.block ? 'var(--ui-red)' : undefined })
        ]
      }),
      jsxs(Panel, {
        children: [
          jsx(SectionTitle, {
            hint: `${(overview.recent_events || []).length} recent`,
            children: 'Continuity ribbon'
          }),
          jsx(Ribbon, { events: overview.recent_events || [] })
        ]
      }),
      jsxs('div', {
        className: 'grid grid-cols-1 xl:grid-cols-2 gap-4',
        children: [
          jsxs(Panel, {
            children: [
              jsx(SectionTitle, { hint: 'newest first', children: 'Recent activity' }),
              (overview.recent_events || []).length
                ? (overview.recent_events || []).slice(0, 6).map(event =>
                    jsx(EventRow, { event }, event.event_id)
                  )
                : jsx(EmptyNote, { children: 'Nothing captured yet.' })
            ]
          }),
          jsxs(Panel, {
            children: [
              jsx(SectionTitle, {
                hint: `${fmtInt(status.needs_review)} pending`,
                children: 'Oneiros review queue'
              }),
              pending.length
                ? pending.slice(0, 5).map(fact =>
                    jsx(
                      ReviewRow,
                      {
                        fact,
                        busy,
                        onConfirm: item =>
                          mutate(
                            `/memory/${encodeURIComponent(item.id)}/confirm`,
                            {},
                            `Confirmed ${item.fact_key}`
                          ),
                        onReject: item =>
                          mutate(
                            `/memory/${encodeURIComponent(item.id)}/reject`,
                            {},
                            `Rejected ${item.fact_key}`
                          )
                      },
                      fact.id
                    )
                  )
                : jsx(EmptyNote, {
                    children: 'No candidates waiting. Explicit corrections appear here for review.'
                  })
            ]
          })
        ]
      }),
      jsxs(Panel, {
        children: [
          jsx(SectionTitle, { hint: 'instrument state', children: 'Integrity' }),
          jsxs('div', {
            className: 'grid grid-cols-2 lg:grid-cols-4 gap-3 text-[10px]',
            children: [
              jsx('div', { style: { color: 'var(--ui-text-tertiary)' }, children: `schema ${status.schema_version}` }),
              jsx('div', { style: { color: 'var(--ui-text-tertiary)' }, children: `policy ${status.policy_version}` }),
              jsx('div', { style: { color: 'var(--ui-text-tertiary)' }, children: `plugin v${status.version}` }),
              jsx('div', {
                className: 'truncate',
                style: { color: 'var(--ui-text-tertiary)' },
                children: `installation ${shortId(status.installation_id)}`
              })
            ]
          }),
          jsxs('div', {
            className: 'flex items-center gap-2 pt-3',
            children: [
              jsx(ActionButton, {
                disabled: busy,
                onClick: () => onRunDream(),
                children: 'Run dream consolidation'
              }),
              jsx(ActionButton, {
                disabled: busy,
                onClick: () => onRefresh(),
                children: 'Refresh'
              }),
              jsx(ActionButton, {
                onClick: () => onNavigate('memory'),
                children: 'Review memory'
              }),
              jsx(ActionButton, {
                onClick: () => onNavigate('security'),
                children: 'Checkpoints'
              })
            ]
          })
        ]
      })
    ]
  })
}

export default {
  id: 'hermes-continuum',
  name: 'Continuum',
  description:
    'Nine systems for continuity, evidence, intent, security, foresight, resilience, reviewed memory, and trace distillation.',
  register(ctx) {
    ctx.registerMany([
      {
        id: 'page',
        area: ROUTES_AREA,
        data: { path: ROUTE },
        render: () => jsx(ContinuumPage, { ctx })
      },
      {
        id: 'nav',
        area: SIDEBAR_NAV_AREA,
        order: 40,
        data: { path: ROUTE, label: 'Continuum', codicon: 'pulse' }
      },
      {
        id: 'pane',
        area: PANES_AREA,
        title: 'continuum',
        order: 60,
        data: { placement: 'right', width: '280px' },
        render: () => jsx(ContinuumPane, { ctx })
      },
      {
        id: 'chip',
        area: STATUSBAR_AREAS.right,
        order: 75,
        render: () => jsx(ContinuumChip, { ctx })
      },
      {
        id: 'open',
        area: PALETTE_AREA,
        data: {
          id: 'continuum.open',
          label: 'Open Continuum Console',
          keywords: ['continuum', 'memory', 'timeline', 'checkpoint', 'security', 'forge', 'lease', 'skill'],
          run: () => host.navigate(ROUTE)
        }
      },
      {
        id: 'open-key',
        area: KEYBINDS_AREA,
        data: {
          id: 'continuum.open',
          label: 'Open Continuum Console',
          category: 'view',
          defaults: ['mod+alt+c'],
          run: () => host.navigate(ROUTE)
        }
      }
    ])
  }
}

// ---------------------------------------------------------------------------
// Page shell (defined after use in register is fine: function declarations hoist)
// ---------------------------------------------------------------------------
function ViewRail({ view, onSelect, needsReview }) {
  return jsxs('div', {
    className: 'flex lg:flex-col gap-1 px-3 lg:px-5 py-3 lg:py-4 overflow-x-auto lg:overflow-visible shrink-0',
    style: { borderBottom: '1px solid var(--ui-stroke-secondary)' },
    children: [
      jsx('div', {
        className: 'hidden lg:block text-[10px] uppercase font-semibold pb-2',
        style: { color: 'var(--ui-text-quaternary)', letterSpacing: '0.16em' },
        children: 'Views'
      }),
      ...VIEWS.map(item =>
        jsxs(
          'button',
          {
            type: 'button',
            onClick: () => onSelect(item.id),
            className:
              'flex items-center gap-2 px-3 py-2 rounded-lg text-xs whitespace-nowrap cursor-pointer transition-colors text-left',
            style:
              view === item.id
                ? {
                    background: 'color-mix(in srgb, var(--ui-accent) 12%, transparent)',
                    color: 'var(--ui-text-primary)',
                    border: '1px solid color-mix(in srgb, var(--ui-accent) 40%, transparent)'
                  }
                : {
                    color: 'var(--ui-text-tertiary)',
                    border: '1px solid transparent',
                    background: 'transparent'
                  },
            children: [
              jsx(Codicon, { name: item.icon, size: '0.75rem' }),
              jsx('span', { children: item.label }),
              item.id === 'memory' && needsReview
                ? jsx('span', {
                    className: 'ml-auto px-1.5 rounded-full text-[10px] tabular-nums',
                    style: { background: 'var(--ui-yellow)', color: 'var(--ui-bg-editor)' },
                    children: fmtInt(needsReview)
                  })
                : null
            ]
          },
          item.id
        )
      )
    ]
  })
}

function ContinuumPage({ ctx }) {
  const [view, setView] = useState(() => {
    try {
      return ctx.storage.get('view', 'overview') || 'overview'
    } catch (error) {
      return 'overview'
    }
  })
  const [busy, run] = useAction()
  const gateway = useValue(host.state.gateway)
  const profile = useValue(host.state.profile)

  const overviewQuery = useQuery({
    queryKey: [...QUERY_ROOT, 'overview'],
    queryFn: () => ctx.rest('/overview'),
    refetchInterval: 30000
  })
  const statusQuery = useQuery({
    queryKey: [...QUERY_ROOT, 'status'],
    queryFn: () => ctx.rest('/status'),
    refetchInterval: 30000
  })

  useEffect(() => {
    try {
      ctx.storage.set('view', view)
    } catch (error) {
      /* storage is best-effort */
    }
  }, [ctx, view])

  const status = statusQuery.data || (overviewQuery.data && overviewQuery.data.status) || {}
  const overview = overviewQuery.data || { recent_events: [], recent_decisions: [], recent_checkpoints: [], sources: [] }

  const selectView = next => setView(next)

  return jsxs('div', {
    className: 'flex flex-col h-full min-h-0',
    style: { background: 'var(--ui-bg-editor)', color: 'var(--ui-text-primary)' },
    children: [
      jsxs('div', {
        className: 'flex items-center gap-4 px-5 pt-5 pb-4',
        style: { borderBottom: '1px solid var(--ui-stroke-secondary)' },
        children: [
          jsx(OrbitMark, {}),
          jsxs('div', {
            className: 'min-w-0 flex-1',
            children: [
              jsx('div', {
                className: 'text-lg font-semibold',
                style: { letterSpacing: '-0.01em' },
                children: 'Continuum'
              }),
              jsx('div', {
                className: 'text-xs truncate',
                style: { color: 'var(--ui-text-tertiary)' },
                children:
                  'Continuity, evidence, intent, resilience, and reviewed distillation for this Hermes profile'
              })
            ]
          }),
          jsxs('div', {
            className: 'hidden md:flex items-center gap-3',
            children: [
              jsx(GatewayChip, { gateway }),
              jsx('span', {
                className: 'text-[10px]',
                style: { color: 'var(--ui-text-quaternary)' },
                children: profile ? `profile ${profile}` : ''
              }),
              status.version
                ? jsx('span', {
                    className: 'text-[10px] tabular-nums',
                    style: { color: 'var(--ui-text-quaternary)' },
                    children: `v${status.version}`
                  })
                : null
            ]
          }),
          jsx(ActionButton, {
            disabled: busy,
            onClick: () => {
              overviewQuery.refetch()
              statusQuery.refetch()
            },
            children: 'Refresh'
          })
        ]
      }),
      jsxs('div', {
        className: 'flex min-h-0 flex-1 flex-col lg:flex-row',
        children: [
          jsx(ViewRail, {
            view,
            onSelect: selectView,
            needsReview: status.needs_review
          }),
          jsx('div', {
            className: 'min-h-0 flex-1 overflow-y-auto px-4 lg:px-6 py-4',
            children:
              view === 'overview'
                ? jsx(OverviewView, {
                    ctx,
                    status,
                    overview,
                    busy,
                    run,
                    onRefresh: () => {
                      overviewQuery.refetch()
                      statusQuery.refetch()
                    },
                    onNavigate: selectView,
                    onRunDream: () =>
                      run(() => ctx.rest('/dream', { method: 'POST' }), 'Dream consolidation finished')
                  })
                : view === 'pillars'
                ? jsx(PillarsView, {
                    ctx,
                    status,
                    busy,
                    run,
                    onNavigate: selectView
                  })
                : view === 'forge'
                ? jsx(ForgeView, { ctx })
                : view === 'timeline'
                ? jsx(TimelineView, { ctx })
                : view === 'memory'
                ? jsx(MemoryView, { ctx })
                : jsx(SecurityView, { ctx })
          })
        ]
      })
    ]
  })
}

// ---------------------------------------------------------------------------
// Eight systems / four pillars
// ---------------------------------------------------------------------------
function metricPairs(metrics) {
  return Object.entries(metrics || {}).filter(([, value]) => value !== null && value !== undefined)
}

function PillarCard({ pillar, busy, run, ctx, onNavigate }) {
  const accent =
    pillar.id === 'continuity'
      ? 'var(--ui-cyan)'
      : pillar.id === 'memory'
      ? 'var(--ui-green)'
      : pillar.id === 'intent'
      ? 'var(--ui-purple)'
      : 'var(--ui-orange)'
  const metrics = metricPairs(pillar.metrics)
  const latestSnapshot = pillar.latest_snapshot
  const latestDiff = pillar.latest_diff
  const receipts = pillar.receipts || []
  const protectedItems = pillar.protected || []
  const charter = pillar.charter
  const drift = pillar.drift || []
  const previews = pillar.previews || []
  const circuits = (pillar.circuits || []).filter(item => item.status === 'open')

  const body = []
  if (pillar.id === 'continuity') {
    body.push(
      jsx('div', {
        className: 'text-[10px]',
        style: { color: 'var(--ui-text-tertiary)' },
        children: latestSnapshot
          ? `Latest snapshot ${shortId(latestSnapshot.fingerprint_hash)} · ${fmtTs(latestSnapshot.captured_at)}`
          : 'No environment snapshot yet. A checkpoint will create one.'
      })
    )
    if (latestDiff) {
      body.push(
        jsxs('div', {
          className: 'flex items-center gap-2 text-[10px]',
          children: [
            jsx(Badge, {
              color:
                latestDiff.level === 'GREEN'
                  ? 'var(--ui-green)'
                  : latestDiff.level === 'AMBER'
                  ? 'var(--ui-yellow)'
                  : 'var(--ui-red)',
              children: latestDiff.level
            }),
            jsx('span', {
              className: 'truncate',
              style: { color: 'var(--ui-text-secondary)' },
              children: latestDiff.summary
            })
          ]
        })
      )
    }
  }
  if (pillar.id === 'memory') {
    if (receipts.length) {
      body.push(
        jsxs('div', {
          className: 'flex flex-col gap-1',
          children: [
            jsx('div', {
              className: 'text-[10px] uppercase',
              style: { color: 'var(--ui-text-quaternary)', letterSpacing: '0.12em' },
              children: 'Recent evidence'
            }),
            ...receipts.slice(0, 3).map(receipt =>
              jsxs(
                'div',
                {
                  className: 'flex items-center gap-2 text-[10px]',
                  children: [
                    jsx(Badge, {
                      color:
                        receipt.status === 'current'
                          ? 'var(--ui-green)'
                          : receipt.status === 'stale'
                          ? 'var(--ui-yellow)'
                          : 'var(--ui-text-quaternary)',
                      children: receipt.status
                    }),
                    jsx('span', {
                      className: 'truncate flex-1',
                      style: { color: 'var(--ui-text-secondary)' },
                      children: receipt.artifact_ref
                    })
                  ]
                },
                receipt.id
              )
            )
          ]
        })
      )
    } else {
      body.push(
        jsx('div', {
          className: 'text-[10px]',
          style: { color: 'var(--ui-text-tertiary)' },
          children: 'No evidence receipts yet. Record one from a tool or the CLI.'
        })
      )
    }
    if (protectedItems.length) {
      body.push(
        jsx('div', {
          className: 'text-[10px]',
          style: { color: 'var(--ui-text-quaternary)' },
          children: `${protectedItems.length} protection record(s); changes require a held approval.`
        })
      )
    }
  }
  if (pillar.id === 'intent') {
    body.push(
      jsx('div', {
        className: 'text-[10px]',
        style: { color: 'var(--ui-text-secondary)' },
        children: charter
          ? `v${charter.version}: ${charter.original_request}`
          : 'No active charter. Telos creates one only from user-authored input.'
      })
    )
    if (drift.length) {
      body.push(
        jsxs('div', {
          className: 'flex flex-col gap-1',
          children: [
            jsx('div', {
              className: 'text-[10px] uppercase',
              style: { color: 'var(--ui-text-quaternary)', letterSpacing: '0.12em' },
              children: 'Recent drift'
            }),
            ...drift.slice(0, 3).map(item =>
              jsxs(
                'div',
                {
                  className: 'flex items-start gap-2 text-[10px]',
                  children: [
                    jsx(Badge, {
                      color: item.severity === 'high' ? 'var(--ui-red)' : 'var(--ui-yellow)',
                      children: item.severity || item.kind
                    }),
                    jsx('span', {
                      className: 'truncate',
                      style: { color: 'var(--ui-text-secondary)' },
                      children: item.detail
                    })
                  ]
                },
                item.id
              )
            )
          ]
        })
      )
    }
  }
  if (pillar.id === 'resilience') {
    if (circuits.length) {
      body.push(
        jsxs('div', {
          className: 'flex flex-col gap-1',
          children: [
            jsx('div', {
              className: 'text-[10px] uppercase',
              style: { color: 'var(--ui-text-quaternary)', letterSpacing: '0.12em' },
              children: 'Open circuits'
            }),
            ...circuits.slice(0, 3).map(circuit =>
              jsxs(
                'div',
                {
                  className: 'flex items-center gap-2 text-[10px]',
                  children: [
                    jsx('span', {
                      className: 'truncate flex-1',
                      style: { color: 'var(--ui-text-secondary)' },
                      children: `${circuit.tool_name}: ${circuit.reason}`
                    }),
                    jsx(ActionButton, {
                      tone: 'danger',
                      disabled: busy,
                      onClick: () =>
                        run(
                          () =>
                            ctx.rest(`/execution/${encodeURIComponent(circuit.id)}/reset`, {
                              method: 'POST',
                              body: { reason: 'Reset from Console' }
                            }),
                          'Metis circuit reset'
                        ),
                      children: 'Reset'
                    })
                  ]
                },
                circuit.id
              )
            )
          ]
        })
      )
    } else {
      body.push(
        jsx('div', {
          className: 'text-[10px]',
          style: { color: 'var(--ui-text-tertiary)' },
          children: 'No retry circuit open. Failures are recorded with fingerprints.'
        })
      )
    }
    if (previews.length) {
      body.push(
        jsx('div', {
          className: 'text-[10px] truncate',
          style: { color: 'var(--ui-text-quaternary)' },
          children: `Latest preview: ${previews[0].level} — ${previews[0].proposed_action}`
        })
      )
    }
  }

  const actions = []
  if (pillar.id === 'continuity') {
    actions.push(
      jsx(
        ActionButton,
        {
          tone: 'primary',
          disabled: busy,
          onClick: () =>
            run(
              () => ctx.rest('/reality/snapshot', { method: 'POST', body: {} }),
              'Environment snapshot recorded'
            ),
          children: 'Snapshot now'
        },
        'snapshot'
      ),
      jsx(
        ActionButton,
        {
          disabled: busy,
          onClick: () =>
            run(
              () => ctx.rest('/reality/diff', { method: 'POST', body: {} }),
              'Reality diff recorded'
            ),
          children: 'Check reality'
        },
        'diff'
      )
    )
  }
  if (pillar.id === 'memory') {
    actions.push(
      jsx(
        ActionButton,
        { onClick: () => onNavigate('memory'), children: 'Review memory' },
        'memory'
      )
    )
  }
  if (pillar.id === 'intent') {
    actions.push(
      jsx(
        ActionButton,
        { onClick: () => onNavigate('timeline'), children: 'Inspect decisions' },
        'timeline'
      )
    )
  }
  if (pillar.id === 'resilience') {
    actions.push(
      jsx(
        ActionButton,
        { onClick: () => onNavigate('timeline'), children: 'Inspect failures' },
        'execution-timeline'
      )
    )
  }

  return jsxs(Panel, {
    className: 'flex flex-col gap-3',
    style: { borderTop: `2px solid ${accent}` },
    children: [
      jsxs('div', {
        className: 'flex items-start gap-3',
        children: [
          jsxs('div', {
            className: 'min-w-0 flex-1',
            children: [
              jsx('div', {
                className: 'text-sm font-semibold',
                children: pillar.name
              }),
              jsxs('div', {
                className: 'flex flex-wrap gap-1 mt-1',
                children: (pillar.systems || []).map(system =>
                  jsx(Badge, { color: accent, children: system }, system)
                )
              })
            ]
          })
        ]
      }),
      jsx('div', {
        className: 'text-[10px]',
        style: { color: 'var(--ui-text-quaternary)' },
        children: pillar.description
      }),
      jsx('div', {
        className: 'grid grid-cols-2 md:grid-cols-3 gap-2',
        children: metrics.slice(0, 6).map(([key, value]) =>
          jsxs(
            'div',
            {
              className: 'px-2 py-1 rounded-md',
              style: { background: 'var(--ui-bg-input)' },
              children: [
                jsx('div', {
                  className: 'text-[9px] uppercase truncate',
                  style: { color: 'var(--ui-text-quaternary)' },
                  children: key.replace(/_/g, ' ')
                }),
                jsx('div', {
                  className: 'text-xs tabular-nums font-medium',
                  style: { color: 'var(--ui-text-secondary)' },
                  children:
                    typeof value === 'boolean'
                      ? value
                        ? 'yes'
                        : 'no'
                      : typeof value === 'number'
                      ? fmtInt(value)
                      : String(value)
                })
              ]
            },
            key
          )
        )
      }),
      ...body,
      actions.length
        ? jsx('div', { className: 'flex flex-wrap gap-2 mt-auto pt-1', children: actions })
        : null
    ]
  })
}

function PillarsView({ ctx, status, busy, run, onNavigate }) {
  const [toolName, setToolName] = useState('write_file')
  const [previewPath, setPreviewPath] = useState('')
  const [lastPreview, setLastPreview] = useState(null)
  const query = useQuery({
    queryKey: [...QUERY_ROOT, 'pillars'],
    queryFn: () => ctx.rest('/pillars'),
    refetchInterval: 30000
  })
  const pillars = (query.data && query.data.pillars) || []
  const snapshot = status.active_resume_brief

  return jsxs('div', {
    className: 'flex flex-col gap-4',
    children: [
      jsxs(Panel, {
        children: [
          jsx(SectionTitle, {
            hint: 'one spine · nine systems · one approval engine',
            children: 'Five pillars'
          }),
          jsx('div', {
            className: 'text-xs',
            style: { color: 'var(--ui-text-secondary)' },
            children:
              'Continuum, Kairos, Oneiros, Aletheia, Telos, Tripwire, Moirai, Metis, and Hephaestus share one append-only Event Spine. Previews are advisory, receipts are observations, forged artifacts are reviewable, and Tripwire or the host remains the only authorisation path.'
          }),
          snapshot
            ? jsxs('div', {
                className: 'mt-3 flex items-center gap-2 text-[10px]',
                style: { color: 'var(--ui-text-tertiary)' },
                children: [
                  jsx(Badge, { color: 'var(--ui-yellow)', children: 'Resume brief' }),
                  jsx('span', {
                    className: 'truncate',
                    children: snapshot.brief
                  })
                ]
              })
            : null
        ]
      }),
      jsx('div', {
        className: 'grid grid-cols-1 xl:grid-cols-2 gap-3',
        children: pillars.length
          ? pillars.map(pillar =>
              jsx(
                PillarCard,
                { pillar, busy, run, ctx, onNavigate },
                pillar.id
              )
            )
          : jsx(EmptyNote, { children: 'Loading nine-system state…' })
      }),
      jsxs(Panel, {
        children: [
          jsx(SectionTitle, {
            hint: 'side-effect free',
            children: 'Preview an action'
          }),
          jsxs('div', {
            className: 'grid grid-cols-1 md:grid-cols-[1fr_1.4fr_auto] gap-2 items-center',
            children: [
              jsx(TextInput, {
                value: toolName,
                onChange: setToolName,
                placeholder: 'Tool name, e.g. write_file'
              }),
              jsx(TextInput, {
                value: previewPath,
                onChange: setPreviewPath,
                placeholder: 'Optional target path'
              }),
              jsx(ActionButton, {
                tone: 'primary',
                disabled: busy || !toolName.trim(),
                onClick: async () => {
                  const result = await run(
                    () =>
                      ctx.rest('/previews', {
                        method: 'POST',
                        body: {
                          tool_name: toolName.trim(),
                          args: previewPath.trim() ? { path: previewPath.trim() } : {}
                        }
                      }),
                    'Impact preview generated'
                  )
                  if (result && result.preview) setLastPreview(result.preview)
                },
                children: 'Preview'
              })
            ]
          }),
          lastPreview
            ? jsxs('div', {
                className: 'mt-3 flex flex-col gap-1 text-[10px]',
                style: { color: 'var(--ui-text-tertiary)' },
                children: [
                  jsx(Badge, {
                    color:
                      lastPreview.level === 'VERIFIED PREVIEW'
                        ? 'var(--ui-green)'
                        : lastPreview.level === 'PARTIAL PREVIEW'
                        ? 'var(--ui-yellow)'
                        : 'var(--ui-red)',
                    children: lastPreview.level
                  }),
                  jsx('div', {
                    style: { color: 'var(--ui-text-secondary)' },
                    children: lastPreview.summary
                  }),
                  jsx('div', {
                    children:
                      'Preview only. Nothing was executed, and no preview grants approval.'
                  })
                ]
              })
            : jsx('div', {
                className: 'mt-3 text-[10px]',
                style: { color: 'var(--ui-text-quaternary)' },
                children:
                  'Moirai reports VERIFIED, PARTIAL, or UNSUPPORTED confidence and never executes the proposed action.'
              })
        ]
      })
    ]
  })
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------
function TimelineView({ ctx }) {
  const [module, setModule] = useState('All')
  const [search, setSearch] = useState('')
  const [draft, setDraft] = useState('')
  const [limit, setLimit] = useState(100)
  const [expanded, setExpanded] = useState(null)

  const params = new URLSearchParams()
  params.set('limit', String(limit))
  if (module !== 'All') params.set('module', module)
  if (search) params.set('search', search)

  const query = useQuery({
    queryKey: [...QUERY_ROOT, 'timeline', module, search, limit],
    queryFn: () => ctx.rest(`/timeline?${params.toString()}`),
    refetchInterval: 30000
  })
  const events = (query.data && query.data.events) || []

  return jsxs('div', {
    className: 'flex flex-col gap-4',
    children: [
      jsxs(Panel, {
        children: [
          jsx(SectionTitle, {
            hint: `${events.length} record${events.length === 1 ? '' : 's'}`,
            children: 'Event Spine'
          }),
          jsxs('div', {
            className: 'flex flex-wrap items-center gap-2',
            children: [
              ...MODULE_TABS.map(tab =>
                jsx(
                  'button',
                  {
                    type: 'button',
                    onClick: () => setModule(tab),
                    className: 'px-3 py-1 rounded-md text-xs cursor-pointer',
                    style:
                      module === tab
                        ? {
                            border: '1px solid var(--ui-accent)',
                            color: 'var(--ui-accent)',
                            background: 'color-mix(in srgb, var(--ui-accent) 10%, transparent)'
                          }
                        : {
                            border: '1px solid var(--ui-stroke-secondary)',
                            color: 'var(--ui-text-tertiary)',
                            background: 'transparent'
                          },
                    children: tab
                  },
                  tab
                )
              ),
              jsx('div', {
                className: 'flex items-center gap-2 flex-1 min-w-[200px]',
                children: jsx(TextInput, {
                  value: draft,
                  placeholder: 'Search summaries and event types…',
                  onChange: setDraft,
                  onKeyDown: event => {
                    if (event.key === 'Enter') setSearch(draft.trim())
                  }
                })
              }),
              jsx(ActionButton, {
                onClick: () => setSearch(draft.trim()),
                children: 'Search'
              }),
              search
                ? jsx(ActionButton, {
                    onClick: () => {
                      setDraft('')
                      setSearch('')
                    },
                    children: 'Clear'
                  })
                : null
            ]
          })
        ]
      }),
      jsx(Panel, {
        className: 'p-0',
        children: jsxs('div', {
          children: [
            events.length
              ? events.map(event =>
                  jsxs(
                    'div',
                    {
                      className: 'px-4 py-3',
                      style: { borderTop: '1px solid var(--ui-stroke-tertiary)' },
                      children: [
                        jsxs('div', {
                          className: 'flex items-center gap-3',
                          children: [
                            jsx('span', {
                              className: 'h-2 w-2 rounded-full shrink-0',
                              style: {
                                background: MODULE_COLORS[event.module] || MODULE_COLORS.System
                              }
                            }),
                            jsxs('div', {
                              className: 'min-w-0 flex-1',
                              children: [
                                jsx('div', {
                                  className: 'text-xs',
                                  style: { color: 'var(--ui-text-primary)' },
                                  children: event.summary
                                }),
                                jsxs('div', {
                                  className: 'text-[10px] truncate',
                                  style: { color: 'var(--ui-text-quaternary)' },
                                  children: [
                                    event.event_type,
                                    ' · ',
                                    event.module,
                                    event.session_id ? ` · session ${shortId(event.session_id)}` : ''
                                  ]
                                })
                              ]
                            }),
                            event.security_decision
                              ? jsx(Badge, {
                                  color:
                                    OUTCOME_COLORS[event.security_decision] ||
                                    'var(--ui-text-tertiary)',
                                  children: event.security_decision
                                })
                              : null,
                            event.trust_label
                              ? jsx(Badge, {
                                  color:
                                    event.trust_label === 'UNTRUSTED_EXTERNAL'
                                      ? 'var(--ui-red)'
                                      : 'var(--ui-text-tertiary)',
                                  children: event.trust_label
                                })
                              : null,
                            jsx('span', {
                              className: 'text-[10px] whitespace-nowrap tabular-nums',
                              style: { color: 'var(--ui-text-tertiary)' },
                              children: fmtTs(event.timestamp_utc)
                            }),
                            jsx('button', {
                              type: 'button',
                              onClick: () =>
                                setExpanded(current =>
                                  current === event.event_id ? null : event.event_id
                                ),
                              className: 'text-[10px] cursor-pointer',
                              style: { color: 'var(--ui-accent)' },
                              children: expanded === event.event_id ? 'hide' : 'details'
                            })
                          ]
                        }),
                        expanded === event.event_id
                          ? jsx('pre', {
                              className: 'mt-2 p-3 text-[10px] whitespace-pre-wrap break-words rounded-md',
                              style: {
                                background: 'var(--ui-bg-secondary)',
                                color: 'var(--ui-text-tertiary)',
                                border: '1px solid var(--ui-stroke-tertiary)'
                              },
                              children: JSON.stringify(
                                {
                                  event_id: event.event_id,
                                  type: event.event_type,
                                  details: event.details,
                                  source_ref: event.source_ref,
                                  payload_ref: event.payload_ref
                                },
                                null,
                                2
                              )
                            })
                          : null
                      ]
                    },
                    event.event_id
                  )
                )
              : jsx(EmptyNote, {
                  children: query.isLoading ? 'Loading Event Spine…' : 'No matching events.'
                }),
            events.length >= limit && limit < 500
              ? jsx('div', {
                  className: 'px-4 py-3',
                  style: { borderTop: '1px solid var(--ui-stroke-tertiary)' },
                  children: jsx(ActionButton, {
                    onClick: () => setLimit(current => Math.min(500, current + 100)),
                    children: 'Load more'
                  })
                })
              : null
          ]
        })
      })
    ]
  })
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------
function ConfidenceBar({ value }) {
  const pct = Math.max(0, Math.min(100, Math.round(Number(value || 0) * 100)))
  return jsx('div', {
    className: 'h-1 w-16 rounded-full overflow-hidden',
    style: { background: 'var(--ui-stroke-tertiary)' },
    children: jsx('div', {
      className: 'h-full rounded-full',
      style: {
        width: `${pct}%`,
        background: pct >= 80 ? 'var(--ui-green)' : 'var(--ui-yellow)'
      }
    })
  })
}

function FactCard({ group, ctx, busy, run }) {
  const head = group.head
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(head.value || '')
  const [confirmForget, setConfirmForget] = useState(false)
  const [showHistory, setShowHistory] = useState(false)

  const mutate = (path, body, message) =>
    run(() => ctx.rest(path, { method: 'POST', body: body || {} }), message)

  return jsxs('div', {
    className: 'p-4 flex flex-col gap-2',
    style: panelStyle(),
    children: [
      jsxs('div', {
        className: 'flex items-center gap-2',
        children: [
          jsx('div', {
            className: 'text-xs font-semibold truncate flex-1',
            style: { color: 'var(--ui-text-primary)' },
            children: group.key
          }),
          jsx(Badge, {
            color: STATUS_COLORS[head.status] || 'var(--ui-text-tertiary)',
            children: head.status
          }),
          jsx(Badge, {
            color: 'var(--ui-text-quaternary)',
            children: `v${head.version}`
          })
        ]
      }),
      editing
        ? jsxs('div', {
            className: 'flex flex-col gap-2',
            children: [
              jsx('textarea', {
                value: draft,
                rows: 3,
                spellCheck: false,
                onChange: event => setDraft(event.target.value),
                className: 'p-2 text-xs rounded-md w-full',
                style: {
                  border: '1px solid var(--ui-stroke-secondary)',
                  background: 'var(--ui-bg-input)',
                  color: 'var(--ui-text-primary)'
                }
              }),
              jsxs('div', {
                className: 'flex items-center gap-2',
                children: [
                  jsx(ActionButton, {
                    tone: 'primary',
                    disabled: busy || !draft.trim(),
                    onClick: async () => {
                      const result = await mutate(
                        `/memory/${encodeURIComponent(head.id)}/edit`,
                        { value: draft.trim() },
                        'Memory edited as a new version'
                      )
                      if (result) setEditing(false)
                    },
                    children: 'Save as new version'
                  }),
                  jsx(ActionButton, {
                    onClick: () => {
                      setEditing(false)
                      setDraft(head.value || '')
                    },
                    children: 'Cancel'
                  })
                ]
              })
            ]
          })
        : jsx('div', {
            className: 'text-sm',
            style: { color: 'var(--ui-text-secondary)' },
            children: head.value
          }),
      jsxs('div', {
        className: 'flex flex-wrap items-center gap-3 text-[10px]',
        style: { color: 'var(--ui-text-quaternary)' },
        children: [
          jsx(ConfidenceBar, { value: head.confidence }),
          jsx('span', { children: `${Math.round(Number(head.confidence || 0) * 100)}% confidence` }),
          head.provenance ? jsx('span', { className: 'truncate', children: head.provenance }) : null,
          head.source_ref ? jsx('span', { className: 'truncate', children: `source ${shortId(head.source_ref)}` }) : null,
          jsx('span', { children: `observed ${fmtTs(head.last_observed_utc)}` })
        ]
      }),
      !editing
        ? jsxs('div', {
            className: 'flex flex-wrap items-center gap-2 pt-1',
            children: [
              head.status === 'candidate'
                ? jsx(ActionButton, {
                    tone: 'primary',
                    disabled: busy,
                    onClick: () =>
                      mutate(
                        `/memory/${encodeURIComponent(head.id)}/confirm`,
                        {},
                        `Confirmed ${group.key}`
                      ),
                    children: 'Confirm'
                  })
                : null,
              head.status === 'candidate'
                ? jsx(ActionButton, {
                    disabled: busy,
                    onClick: () =>
                      mutate(
                        `/memory/${encodeURIComponent(head.id)}/reject`,
                        {},
                        `Rejected ${group.key}`
                      ),
                    children: 'Reject'
                  })
                : null,
              jsx(ActionButton, {
                disabled: busy,
                onClick: () => {
                  setDraft(head.value || '')
                  setEditing(true)
                },
                children: 'Edit'
              }),
              confirmForget
                ? jsxs('span', {
                    className: 'flex items-center gap-2',
                    children: [
                      jsx('span', {
                        className: 'text-[10px]',
                        style: { color: 'var(--ui-red)' },
                        children: 'Delete permanently?'
                      }),
                      jsx(ActionButton, {
                        tone: 'danger',
                        disabled: busy,
                        onClick: () => mutate(`/memory/${encodeURIComponent(head.id)}/forget`, { confirm: true }, 'Memory deleted'),
                        children: 'Delete'
                      }),
                      jsx(ActionButton, {
                        onClick: () => setConfirmForget(false),
                        children: 'Keep'
                      })
                    ]
                  })
                : jsx(ActionButton, {
                    tone: 'danger',
                    disabled: busy,
                    onClick: () => setConfirmForget(true),
                    children: 'Forget'
                  }),
              group.versions.length > 1
                ? jsx(ActionButton, {
                    onClick: () => setShowHistory(current => !current),
                    children: showHistory
                      ? 'Hide history'
                      : `History (${group.versions.length})`
                  })
                : null
            ]
          })
        : null,
      showHistory
        ? jsx('div', {
            className: 'flex flex-col gap-1 pt-2',
            style: { borderTop: '1px solid var(--ui-stroke-tertiary)' },
            children: group.versions.map(version =>
              jsxs(
                'div',
                {
                  className: 'flex items-center gap-3 text-[10px] py-1',
                  children: [
                    jsx('span', {
                      className: 'tabular-nums',
                      style: { color: 'var(--ui-text-quaternary)' },
                      children: `v${version.version}`
                    }),
                    jsx(Badge, {
                      color: STATUS_COLORS[version.status] || 'var(--ui-text-tertiary)',
                      children: version.status
                    }),
                    jsx('span', {
                      className: 'truncate flex-1',
                      style: { color: 'var(--ui-text-tertiary)' },
                      children: version.value
                    }),
                    version.superseded_by
                      ? jsx('span', {
                          style: { color: 'var(--ui-text-quaternary)' },
                          children: 'superseded'
                        })
                      : null,
                    jsx('span', {
                      style: { color: 'var(--ui-text-quaternary)' },
                      children: fmtTs(version.last_observed_utc)
                    })
                  ]
                },
                version.id
              )
            )
          })
        : null
    ]
  })
}

function MemoryView({ ctx }) {
  const [busy, run] = useAction()
  const [status, setStatus] = useState('candidate')
  const [search, setSearch] = useState('')
  const [draft, setDraft] = useState('')

  const query = useQuery({
    queryKey: [...QUERY_ROOT, 'memory'],
    queryFn: () => ctx.rest('/memory?limit=1000'),
    refetchInterval: 60000
  })
  const counts = (query.data && query.data.counts) || {}
  const facts = (query.data && query.data.facts) || []
  const groups = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return groupFacts(facts).filter(group => {
      if (status !== 'all' && !group.versions.some(version => version.status === status)) {
        return false
      }
      if (!needle) return true
      return (
        group.key.toLowerCase().includes(needle) ||
        group.versions.some(version =>
          String(version.value || '').toLowerCase().includes(needle)
        )
      )
    })
  }, [facts, search, status])

  return jsxs('div', {
    className: 'flex flex-col gap-4',
    children: [
      jsxs(Panel, {
        children: [
          jsxs('div', {
            className: 'flex items-center gap-3 flex-wrap',
            children: [
              jsx(SectionTitle, {
                hint: `${groups.length} memor${groups.length === 1 ? 'y' : 'ies'}`,
                children: 'Oneiros memory'
              }),
              jsx('div', { className: 'flex-1' }),
              jsx(ActionButton, {
                disabled: busy,
                onClick: () =>
                  run(() => ctx.rest('/dream', { method: 'POST' }), 'Dream consolidation finished'),
                children: 'Run dream'
              })
            ]
          }),
          jsxs('div', {
            className: 'flex flex-wrap items-center gap-2',
            children: [
              ...['candidate', 'confirmed', 'rejected', 'superseded', 'contradicted', 'all'].map(
                tab =>
                  jsx(
                    'button',
                    {
                      type: 'button',
                      onClick: () => setStatus(tab),
                      className: 'px-3 py-1 rounded-md text-xs cursor-pointer',
                      style:
                        status === tab
                          ? {
                              border: '1px solid var(--ui-accent)',
                              color: 'var(--ui-accent)',
                              background:
                                'color-mix(in srgb, var(--ui-accent) 10%, transparent)'
                            }
                          : {
                              border: '1px solid var(--ui-stroke-secondary)',
                              color: 'var(--ui-text-tertiary)',
                              background: 'transparent'
                            },
                      children: `${tab}${counts[tab] !== undefined ? ` ${counts[tab]}` : ''}`
                    },
                    tab
                  )
              ),
              jsx('div', {
                className: 'flex items-center gap-2 flex-1 min-w-[180px]',
                children: jsx(TextInput, {
                  value: draft,
                  placeholder: 'Search keys and values…',
                  onChange: setDraft,
                  onKeyDown: event => {
                    if (event.key === 'Enter') setSearch(draft.trim())
                  }
                })
              }),
              jsx(ActionButton, {
                onClick: () => setSearch(draft.trim()),
                children: 'Search'
              })
            ]
          })
        ]
      }),
      groups.length
        ? groups.map(group => jsx(FactCard, { group, ctx, busy, run }, group.key))
        : jsxs(Panel, {
            children: [
              jsx(EmptyNote, {
                children: query.isLoading
                  ? 'Loading memory…'
                  : 'No memory facts match this filter. Explicit corrections become candidates after the next turn.'
              })
            ]
          })
    ]
  })
}

// ---------------------------------------------------------------------------
// Security & Checkpoints
// ---------------------------------------------------------------------------
function DecisionRow({ decision }) {
  const [open, setOpen] = useState(false)
  const color = OUTCOME_COLORS[decision.outcome] || 'var(--ui-text-tertiary)'
  return jsxs('div', {
    className: 'py-2',
    style: { borderTop: '1px solid var(--ui-stroke-tertiary)' },
    children: [
      jsxs('div', {
        className: 'flex items-center gap-3',
        children: [
          jsx(Badge, { color, children: decision.outcome }),
          jsx('span', {
            className: 'text-xs font-medium truncate',
            style: { color: 'var(--ui-text-primary)' },
            children: decision.tool_name
          }),
          jsx('code', {
            className: 'text-[10px] truncate hidden md:block',
            style: { color: 'var(--ui-text-quaternary)' },
            children: decision.rule_key
          }),
          jsx('span', {
            className: 'text-[10px] whitespace-nowrap tabular-nums ml-auto',
            style: { color: 'var(--ui-text-tertiary)' },
            children: fmtTs(decision.created_at)
          }),
          jsx('button', {
            type: 'button',
            className: 'text-[10px] cursor-pointer',
            style: { color: 'var(--ui-accent)' },
            onClick: () => setOpen(current => !current),
            children: open ? 'hide' : 'details'
          })
        ]
      }),
      jsx('div', {
        className: 'text-[10px] pt-1',
        style: { color: 'var(--ui-text-tertiary)' },
        children: decision.reason
      }),
      open
        ? jsx('pre', {
            className: 'mt-2 p-3 text-[10px] whitespace-pre-wrap break-words rounded-md',
            style: {
              background: 'var(--ui-bg-secondary)',
              color: 'var(--ui-text-tertiary)',
              border: '1px solid var(--ui-stroke-tertiary)'
            },
            children: JSON.stringify(
              {
                category: decision.action_category,
                evidence: decision.evidence,
                redacted_args: decision.redacted_args
              },
              null,
              2
            )
          })
        : null
    ]
  })
}

function CheckpointPanel({ ctx, busy, run, checkpointData }) {
  const [passphrase, setPassphrase] = useState('')
  const [confirmPassphrase, setConfirmPassphrase] = useState('')
  const [importPath, setImportPath] = useState('')
  const [preview, setPreview] = useState(null)
  const [result, setResult] = useState(null)

  const records = (checkpointData && checkpointData.records) || []
  const files = (checkpointData && checkpointData.files) || []

  const exportNow = async () => {
    if (passphrase.length < 8) {
      host.notify({ kind: 'warning', message: 'Use at least 8 characters for the passphrase.' })
      return
    }
    if (passphrase !== confirmPassphrase) {
      host.notify({ kind: 'warning', message: 'The passphrases do not match.' })
      return
    }
    const response = await run(
      () => ctx.rest('/checkpoints/export', { method: 'POST', body: { passphrase } }),
      'Encrypted checkpoint exported'
    )
    setResult(response)
    setPassphrase('')
    setConfirmPassphrase('')
  }

  const previewNow = async () => {
    if (!importPath.trim() || !passphrase) {
      host.notify({ kind: 'warning', message: 'Choose a checkpoint file and enter its passphrase.' })
      return
    }
    const response = await run(
      () =>
        ctx.rest('/checkpoints/import', {
          method: 'POST',
          body: { path: importPath.trim(), passphrase, confirm: false }
        }),
      undefined
    )
    if (response) setPreview(response.result)
  }

  const importNow = async () => {
    if (!importPath.trim() || !passphrase) return
    const response = await run(
      () =>
        ctx.rest('/checkpoints/import', {
          method: 'POST',
          body: { path: importPath.trim(), passphrase, confirm: true }
        }),
      'Checkpoint import applied'
    )
    if (response) {
      setResult(response.result)
      setPreview(null)
      setPassphrase('')
    }
  }

  return jsxs(Panel, {
    children: [
      jsx(SectionTitle, {
        hint: `${records.length} record${records.length === 1 ? '' : 's'} · ${files.length} file${files.length === 1 ? '' : 's'}`,
        children: 'Encrypted checkpoints'
      }),
      jsxs('div', {
        className: 'grid grid-cols-1 lg:grid-cols-2 gap-4',
        children: [
          jsxs('div', {
            className: 'flex flex-col gap-2',
            children: [
              jsx('div', {
                className: 'text-[10px] uppercase font-semibold',
                style: { color: 'var(--ui-text-tertiary)', letterSpacing: '0.12em' },
                children: 'Export'
              }),
              jsx('div', {
                className: 'text-[10px]',
                style: { color: 'var(--ui-text-quaternary)' },
                children:
                  'Passphrases stay in this window only and are never stored. AES-256-GCM + scrypt.'
              }),
              jsx(TextInput, {
                type: 'password',
                name: 'continuum-export-passphrase',
                value: passphrase,
                placeholder: 'Passphrase (min 8 characters)',
                onChange: setPassphrase
              }),
              jsx(TextInput, {
                type: 'password',
                name: 'continuum-export-passphrase-confirm',
                value: confirmPassphrase,
                placeholder: 'Confirm passphrase',
                onChange: setConfirmPassphrase
              }),
              jsx(ActionButton, {
                tone: 'primary',
                disabled: busy || !passphrase || !confirmPassphrase,
                onClick: exportNow,
                children: 'Export checkpoint'
              })
            ]
          }),
          jsxs('div', {
            className: 'flex flex-col gap-2',
            children: [
              jsx('div', {
                className: 'text-[10px] uppercase font-semibold',
                style: { color: 'var(--ui-text-tertiary)', letterSpacing: '0.12em' },
                children: 'Import'
              }),
              files.length
                ? jsx('select', {
                    value: importPath,
                    onChange: event => setImportPath(event.target.value),
                    className: 'px-3 py-1.5 text-xs rounded-md',
                    style: {
                      border: '1px solid var(--ui-stroke-secondary)',
                      background: 'var(--ui-bg-input)',
                      color: 'var(--ui-text-primary)'
                    },
                    children: [
                      jsx('option', { value: '', children: 'Choose a local .hcc file…' }),
                      ...files.map(file =>
                        jsx('option', { value: file.path, children: file.filename }, file.path)
                      )
                    ]
                  })
                : null,
              jsx(TextInput, {
                value: importPath,
                placeholder: 'Absolute path to a .hcc file',
                onChange: setImportPath,
                name: 'continuum-import-path'
              }),
              jsx(TextInput, {
                type: 'password',
                name: 'continuum-import-passphrase',
                value: passphrase,
                placeholder: 'Passphrase for this file',
                onChange: setPassphrase
              }),
              jsxs('div', {
                className: 'flex items-center gap-2',
                children: [
                  jsx(ActionButton, {
                    disabled: busy || !importPath || !passphrase,
                    onClick: previewNow,
                    children: 'Preview'
                  }),
                  preview
                    ? jsx(ActionButton, {
                        tone: 'primary',
                        disabled: busy,
                        onClick: importNow,
                        children: 'Apply import'
                      })
                    : null
                ]
              })
            ]
          })
        ]
      }),
      preview
        ? jsxs('div', {
            className: 'mt-3 p-3 rounded-md text-[10px]',
            style: {
              border: '1px solid var(--ui-stroke-secondary)',
              background: 'var(--ui-bg-secondary)',
              color: 'var(--ui-text-tertiary)'
            },
            children: [
              jsx('div', {
                className: 'font-semibold',
                style: { color: 'var(--ui-text-secondary)' },
                children: 'Preview'
              }),
              jsx('div', { children: `checksum ${shortId(preview.checksum)}` }),
              jsx('div', {
                children: `counts ${Object.entries(preview.counts || {})
                  .slice(0, 8)
                  .map(([key, value]) => `${key}:${value}`)
                  .join(' · ')}`
              }),
              jsx('div', {
                children: `${(preview.conflicts || []).length} conflict(s) will become reviewable candidates.`
              })
            ]
          })
        : null,
      result
        ? jsx('pre', {
            className: 'mt-3 p-3 text-[10px] whitespace-pre-wrap break-words rounded-md',
            style: {
              border: '1px solid var(--ui-stroke-secondary)',
              background: 'var(--ui-bg-secondary)',
              color: 'var(--ui-text-tertiary)'
            },
            children: JSON.stringify(
              {
                status: result.status || 'exported',
                checkpoint_id: result.checkpoint_id,
                path: result.path,
                checksum: result.checksum,
                truncated: result.truncated,
                imported: result.imported,
                conflicts: (result.conflicts || []).length
              },
              null,
              2
            )
          })
        : null,
      records.length || files.length
        ? jsx('div', {
            className: 'mt-4 flex flex-col',
            children: jsxs('div', {
              children: [
                jsxs('div', {
                  className: 'grid grid-cols-12 gap-2 py-2 text-[10px] uppercase',
                  style: { color: 'var(--ui-text-quaternary)', letterSpacing: '0.1em' },
                  children: [
                    jsx('div', { className: 'col-span-5', children: 'file' }),
                    jsx('div', { className: 'col-span-3', children: 'status' }),
                    jsx('div', { className: 'col-span-2', children: 'size' }),
                    jsx('div', { className: 'col-span-2', children: 'modified' })
                  ]
                }),
                ...files.map(file =>
                  jsxs(
                    'div',
                    {
                      className: 'grid grid-cols-12 gap-2 py-2 text-[10px] items-center',
                      style: { borderTop: '1px solid var(--ui-stroke-tertiary)' },
                      children: [
                        jsx('div', {
                          className: 'col-span-5 truncate',
                          style: { color: 'var(--ui-text-primary)' },
                          children: file.filename
                        }),
                        jsx('div', {
                          className: 'col-span-3',
                          style: { color: 'var(--ui-text-tertiary)' },
                          children: 'local file'
                        }),
                        jsx('div', {
                          className: 'col-span-2 tabular-nums',
                          style: { color: 'var(--ui-text-tertiary)' },
                          children: `${Math.max(1, Math.round(Number(file.size_bytes || 0) / 1024))} KB`
                        }),
                        jsx('div', {
                          className: 'col-span-2',
                          style: { color: 'var(--ui-text-quaternary)' },
                          children: fmtTs(Number(file.modified_at || 0) * 1000)
                        })
                      ]
                    },
                    file.path
                  )
                )
              ]
            })
          })
        : null
    ]
  })
}

function AttackLabPanel({ ctx, busy, run, lab, suite }) {
  const results = (lab && lab.results) || []
  const isHephaestus = suite === 'hephaestus'
  return jsxs(Panel, {
    children: [
      jsx(SectionTitle, {
        hint: lab ? `${lab.passed}/${lab.total} passed · ${fmtTs(lab.run_at)}` : 'not run yet',
        children: isHephaestus ? 'Hephaestus Attack Lab' : 'Attack Lab'
      }),
      jsx('div', {
        className: 'text-[10px] pb-2',
        style: { color: 'var(--ui-text-quaternary)' },
        children: isHephaestus
          ? 'Deterministic leakage, containment, budget, and environment-drift cases only. Leases remain guardrails, never approvals.'
          : 'Deterministic synthetic cases only. This is not a claim of perfect prompt-injection protection.'
      }),
      results.length
        ? jsx('div', {
            className: 'flex flex-col',
            children: results.map(item =>
              jsxs(
                'div',
                {
                  className: 'flex items-center gap-2 py-1.5 text-[10px]',
                  style: { borderTop: '1px solid var(--ui-stroke-tertiary)' },
                  children: [
                    jsx(Badge, {
                      color: item.passed ? 'var(--ui-green)' : 'var(--ui-red)',
                      children: item.passed ? 'pass' : 'fail'
                    }),
                    jsx('span', {
                      className: 'truncate flex-1',
                      style: { color: 'var(--ui-text-secondary)' },
                      children: item.name
                    }),
                    jsx('span', {
                      className: 'whitespace-nowrap',
                      style: { color: 'var(--ui-text-quaternary)' },
                      children: `expected ${item.expected} · got ${item.actual}`
                    })
                  ]
                },
                item.id
              )
            )
          })
        : null,
      jsx('div', {
        className: 'pt-2',
        children: jsx(ActionButton, {
          disabled: busy,
          onClick: () =>
            run(
              () =>
                ctx.rest('/attack-lab/run', {
                  method: 'POST',
                  body: isHephaestus ? { suite: 'hephaestus' } : {}
                }),
              isHephaestus ? 'Hephaestus Attack Lab complete' : 'Attack Lab complete'
            ),
          children: isHephaestus ? 'Run 4-case lab' : 'Run 12-case lab'
        })
      })
    ]
  })
}

function RetentionPanel({ ctx, busy, run }) {
  const [days, setDays] = useState('30')
  const numeric = Math.max(1, Math.min(3650, Number(days) || 30))
  return jsxs(Panel, {
    children: [
      jsx(SectionTitle, {
        hint: 'episodes, sources, and old events',
        children: 'Retention'
      }),
      jsx('div', {
        className: 'text-[10px] pb-2',
        style: { color: 'var(--ui-text-quaternary)' },
        children:
          'Prunes records older than the selected window. Checkpoint and deletion audit records are preserved.'
      }),
      jsxs('div', {
        className: 'flex items-end gap-2',
        children: [
          jsx('div', {
            className: 'flex-1',
            children: jsx(TextInput, {
              type: 'number',
              value: days,
              onChange: setDays,
              placeholder: '30'
            })
          }),
          jsx(ActionButton, {
            tone: 'danger',
            disabled: busy,
            onClick: () =>
              run(
                () => ctx.rest('/retention', { method: 'POST', body: { days: numeric } }),
                `Retention applied (${numeric} days)`
              ),
            children: 'Apply retention'
          })
        ]
      })
    ]
  })
}

function SecurityView({ ctx }) {
  const [busy, run] = useAction()
  const securityQuery = useQuery({
    queryKey: [...QUERY_ROOT, 'security'],
    queryFn: () => ctx.rest('/security'),
    refetchInterval: 30000
  })
  const checkpointQuery = useQuery({
    queryKey: [...QUERY_ROOT, 'checkpoints'],
    queryFn: () => ctx.rest('/checkpoints'),
    refetchInterval: 60000
  })
  const security = securityQuery.data || {}
  const counts = security.counts || {}
  const decisions = security.decisions || []
  const sources = security.sources || []
  const resume = security.active_resume_brief

  return jsxs('div', {
    className: 'flex flex-col gap-4',
    children: [
      jsxs('div', {
        className: 'grid grid-cols-3 gap-3',
        children: [
          jsx(StatTile, { label: 'Blocked', value: counts.block, accent: 'var(--ui-red)' }),
          jsx(StatTile, { label: 'Approval required', value: counts.approve, accent: 'var(--ui-orange)' }),
          jsx(StatTile, { label: 'Allowed', value: counts.allow, accent: 'var(--ui-green)' })
        ]
      }),
      resume
        ? jsxs(Panel, {
            style: { border: '1px solid var(--ui-accent)' },
            children: [
              jsx(SectionTitle, { hint: resume.id, children: 'Resume brief' }),
              jsx('div', {
                className: 'text-xs',
                style: { color: 'var(--ui-text-secondary)' },
                children: resume.preview
              }),
              jsx('div', {
                className: 'pt-2',
                children: jsx(ActionButton, {
                  disabled: busy,
                  onClick: () =>
                    run(
                      () =>
                        ctx.rest(
                          `/resume-brief/${encodeURIComponent(resume.id)}/dismiss`,
                          { method: 'POST' }
                        ),
                      'Resume brief dismissed'
                    ),
                  children: 'Dismiss brief'
                })
              })
            ]
          })
        : null,
      jsxs('div', {
        className: 'grid grid-cols-1 xl:grid-cols-2 gap-4',
        children: [
          jsx(AttackLabPanel, { ctx, busy, run, lab: security.last_attack_lab }),
          jsxs(Panel, {
            children: [
              jsx(SectionTitle, {
                hint: `${sources.length} labelled`,
                children: 'Provenance sources'
              }),
              sources.length
                ? sources.slice(0, 8).map(source =>
                    jsxs(
                      'div',
                      {
                        className: 'flex items-center gap-2 py-2 text-[10px]',
                        style: { borderTop: '1px solid var(--ui-stroke-tertiary)' },
                        children: [
                          jsx(Badge, {
                            color:
                              source.trust_label === 'UNTRUSTED_EXTERNAL'
                                ? 'var(--ui-red)'
                                : 'var(--ui-text-tertiary)',
                            children: source.trust_label
                          }),
                          jsx('span', {
                            className: 'font-medium',
                            style: { color: 'var(--ui-text-secondary)' },
                            children: source.tool_name
                          }),
                          jsx('span', {
                            className: 'truncate flex-1',
                            style: { color: 'var(--ui-text-quaternary)' },
                            children: source.reference
                          }),
                          jsx('span', {
                            className: 'whitespace-nowrap tabular-nums',
                            style: { color: 'var(--ui-text-quaternary)' },
                            children: fmtTs(source.first_seen_utc)
                          })
                        ]
                      },
                      source.id
                    )
                  )
                : jsx(EmptyNote, { children: 'No external sources labelled yet.' })
            ]
          })
        ]
      }),
      jsx(RetentionPanel, { ctx, busy, run }),
      jsxs(Panel, {
        children: [
          jsx(SectionTitle, {
            hint: `policy ${security.policy_version || '—'}`,
            children: 'Tripwire decision ledger'
          }),
          decisions.length
            ? decisions.slice(0, 40).map(decision =>
                jsx(DecisionRow, { decision }, decision.id)
              )
            : jsx(EmptyNote, {
                children: 'No decisions recorded. Sensitive and blocked actions appear here.'
              })
        ]
      }),
      jsx(CheckpointPanel, {
        ctx,
        busy,
        run,
        checkpointData: checkpointQuery.data
      })
    ]
  })
}

// ---------------------------------------------------------------------------
// Hephaestus forge
// ---------------------------------------------------------------------------
function splitList(value) {
  return String(value || '')
    .split(/[,\n]/)
    .map(item => item.trim())
    .filter(Boolean)
}

function playbookColor(status) {
  if (status === 'active' || status === 'forged') return 'var(--ui-green)'
  if (status === 'quarantined') return 'var(--ui-red)'
  return 'var(--ui-yellow)'
}

function ForgeView({ ctx }) {
  const [busy, run] = useAction()
  const [sessionId, setSessionId] = useState('')
  const [name, setName] = useState('')
  const [tools, setTools] = useState('read_file, write_file')
  const [paths, setPaths] = useState('')
  const [domains, setDomains] = useState('')
  const [cronJobId, setCronJobId] = useState('')
  const [maxCalls, setMaxCalls] = useState('10')
  const [preview, setPreview] = useState(null)

  const query = useQuery({
    queryKey: [...QUERY_ROOT, 'forge'],
    queryFn: () => ctx.rest('/forge'),
    refetchInterval: 30000
  })
  const data = query.data || {}
  const counts = data.counts || {}
  const playbooks = data.playbooks || []
  const leases = data.leases || []

  const options = () => {
    const body = {
      session_id: sessionId.trim(),
      allowed_tools: splitList(tools),
      allowed_paths: splitList(paths),
      allowed_domains: splitList(domains)
    }
    if (name.trim()) body.name = name.trim()
    if (cronJobId.trim()) body.cron_job_id = cronJobId.trim()
    const calls = Number(maxCalls)
    if (Number.isFinite(calls) && calls > 0) body.max_tool_calls = Math.floor(calls)
    return body
  }

  const inspect = async () => {
    const result = await run(
      () => ctx.rest('/forge/preview', { method: 'POST', body: options() }),
      'Forge preview ready'
    )
    if (result) setPreview(result)
  }

  const forgeNow = async () => {
    if (!preview) {
      host.notify({ kind: 'warning', message: 'Preview the trace before forging.' })
      return
    }
    const body = Object.assign({}, options(), { confirm: true })
    const result = await run(
      () => ctx.rest('/forge', { method: 'POST', body }),
      'Playbook forged from the reviewed trace'
    )
    if (result) setPreview(null)
  }

  return jsxs('div', {
    className: 'flex flex-col gap-4',
    children: [
      jsxs('div', {
        className: 'grid grid-cols-2 xl:grid-cols-4 gap-3',
        children: [
          jsx(StatTile, {
            label: 'Playbooks',
            value: counts.playbooks,
            detail: `${fmtInt(counts.active_playbooks)} active`,
            accent: 'var(--ui-warm)'
          }),
          jsx(StatTile, {
            label: 'Active leases',
            value: counts.active_leases,
            detail: 'bounded unattended scope',
            accent: 'var(--ui-green)'
          }),
          jsx(StatTile, {
            label: 'Quarantined',
            value: counts.quarantined,
            detail: 'blocked from new leases',
            accent: counts.quarantined ? 'var(--ui-red)' : undefined
          }),
          jsx(StatTile, {
            label: 'Lease runs',
            value: counts.lease_usage,
            detail: 'per-run usage records'
          })
        ]
      }),
      jsxs(Panel, {
        children: [
          jsx(SectionTitle, {
            hint: 'explicit confirmation required',
            children: 'Distill a verified trace'
          }),
          jsx('div', {
            className: 'text-[10px] pb-2',
            style: { color: 'var(--ui-text-quaternary)' },
            children:
              'Hephaestus turns successful, source-labelled tool steps into a reviewable SKILL.md, an automation blueprint, and a bounded safety lease. Untrusted evidence is quoted, never treated as instructions, and a lease never grants approval.'
          }),
          jsxs('div', {
            className: 'grid grid-cols-1 md:grid-cols-2 gap-2',
            children: [
              jsx(TextInput, {
                value: sessionId,
                onChange: setSessionId,
                placeholder: 'Source session id'
              }),
              jsx(TextInput, {
                value: name,
                onChange: setName,
                placeholder: 'Playbook name (optional)'
              }),
              jsx(TextInput, {
                value: tools,
                onChange: setTools,
                placeholder: 'Allowed tools, comma separated'
              }),
              jsx(TextInput, {
                value: paths,
                onChange: setPaths,
                placeholder: 'Allowed path prefixes, comma separated'
              }),
              jsx(TextInput, {
                value: domains,
                onChange: setDomains,
                placeholder: 'Allowed domains (for external tools)'
              }),
              jsx(TextInput, {
                value: cronJobId,
                onChange: setCronJobId,
                placeholder: 'Bind to Cron job id (optional)'
              }),
              jsx(TextInput, {
                type: 'number',
                value: maxCalls,
                onChange: setMaxCalls,
                placeholder: 'Max tool calls per run'
              })
            ]
          }),
          jsxs('div', {
            className: 'mt-3 flex flex-wrap items-center gap-2',
            children: [
              jsx(ActionButton, {
                tone: 'primary',
                disabled: busy || !sessionId.trim(),
                onClick: inspect,
                children: 'Preview forge'
              }),
              jsx(ActionButton, {
                tone: 'danger',
                disabled: busy || !preview || !preview.can_forge,
                onClick: forgeNow,
                children: 'Forge with confirmation'
              }),
              jsx('span', {
                className: 'text-[10px]',
                style: { color: 'var(--ui-text-quaternary)' },
                children:
                  'Forge refuses unreviewed untrusted or low-confidence traces. Use the CLI for an explicit override.'
              })
            ]
          }),
          preview
            ? jsxs('div', {
                className: 'mt-3 rounded-md p-3 flex flex-col gap-1 text-[10px]',
                style: { border: '1px solid var(--ui-stroke-secondary)' },
                children: [
                  jsxs('div', {
                    className: 'flex flex-wrap items-center gap-2',
                    children: [
                      jsx(Badge, {
                        color: preview.can_forge ? 'var(--ui-green)' : 'var(--ui-red)',
                        children: preview.can_forge ? 'forge ready' : 'forge refused'
                      }),
                      jsx('span', {
                        style: { color: 'var(--ui-text-secondary)' },
                        children: `${Math.round(
                          Number((preview.trace && preview.trace.confidence) || 0) * 100
                        )}% confidence · ${fmtInt(
                          preview.trace && preview.trace.steps_succeeded
                        )}/${fmtInt(preview.trace && preview.trace.steps_attempted)} steps`
                      }),
                      jsx('span', {
                        style: { color: 'var(--ui-text-quaternary)' },
                        children: `${fmtInt(
                          preview.trace && preview.trace.untrusted_steps
                        )} untrusted step(s) excluded`
                      })
                    ]
                  }),
                  ...(preview.warnings || []).map((warning, index) =>
                    jsx(
                      'div',
                      {
                        style: { color: 'var(--ui-yellow)' },
                        children: warning
                      },
                      `warning-${index}`
                    )
                  ),
                  jsx('div', {
                    style: { color: 'var(--ui-text-tertiary)' },
                    children: preview.disclaimer
                  })
                ]
              })
            : null
        ]
      }),
      jsxs('div', {
        className: 'grid grid-cols-1 xl:grid-cols-2 gap-4',
        children: [
          jsxs(Panel, {
            children: [
              jsx(SectionTitle, {
                hint: `${playbooks.length} total`,
                children: 'Forged playbooks'
              }),
              playbooks.length
                ? playbooks.slice(0, 25).map(item => {
                    const quarantined = item.status === 'quarantined'
                    const action = quarantined ? 'unquarantine' : 'quarantine'
                    return jsxs(
                      'div',
                      {
                        className: 'py-2 flex flex-col gap-1',
                        style: { borderTop: '1px solid var(--ui-stroke-tertiary)' },
                        children: [
                          jsxs('div', {
                            className: 'flex flex-wrap items-center gap-2 text-[10px]',
                            children: [
                              jsx('span', {
                                className: 'font-medium',
                                style: { color: 'var(--ui-text-primary)' },
                                children: item.name
                              }),
                              jsx(Badge, {
                                color: playbookColor(item.status),
                                children: item.status
                              }),
                              jsx('span', {
                                style: { color: 'var(--ui-text-quaternary)' },
                                children: `${fmtInt(item.confidence_percent)}% · ${fmtInt(
                                  item.steps_succeeded
                                )}/${fmtInt(item.steps_attempted)} steps`
                              })
                            ]
                          }),
                          jsx('div', {
                            className: 'truncate',
                            style: { color: 'var(--ui-text-quaternary)' },
                            children: item.skill_path || 'artifact path unavailable'
                          }),
                          jsxs('div', {
                            className: 'flex flex-wrap items-center gap-2 pt-1',
                            children: [
                              jsx('span', {
                                className: 'text-[10px]',
                                style: { color: 'var(--ui-text-quaternary)' },
                                children: item.cron_job_id
                                  ? `cron ${item.cron_job_id}`
                                  : 'no cron binding'
                              }),
                              jsx(ActionButton, {
                                tone: 'primary',
                                disabled: busy || !splitList(tools).length,
                                onClick: () => {
                                  const body = Object.assign({}, options(), {
                                    playbook_id: item.id,
                                    confirm: true
                                  })
                                  delete body.session_id
                                  delete body.name
                                  return run(
                                    () =>
                                      ctx.rest('/leases', {
                                        method: 'POST',
                                        body
                                      }),
                                    'Safety lease issued'
                                  )
                                },
                                children: 'Issue lease'
                              }),
                              jsx(ActionButton, {
                                tone: quarantined ? 'primary' : 'danger',
                                disabled: busy,
                                onClick: () =>
                                  run(
                                    () =>
                                      ctx.rest(
                                        `/forge/${encodeURIComponent(item.id)}/${action}`,
                                        {
                                          method: 'POST',
                                          body: {
                                            confirm: true,
                                            reason: 'Reviewed from Continuum Console'
                                          }
                                        }
                                      ),
                                    quarantined
                                      ? 'Playbook released from quarantine'
                                      : 'Playbook quarantined'
                                  ),
                                children: quarantined ? 'Release' : 'Quarantine'
                              })
                            ]
                          })
                        ]
                      },
                      item.id
                    )
                  })
                : jsx(EmptyNote, {
                    children: 'No forged playbooks yet. Preview a verified trace above.'
                  })
            ]
          }),
          jsxs('div', {
            className: 'flex flex-col gap-4',
            children: [
              jsx(AttackLabPanel, {
                ctx,
                busy,
                run,
                lab: data.attack_lab,
                suite: 'hephaestus'
              }),
              jsxs(Panel, {
                children: [
                  jsx(SectionTitle, {
                    hint: `${leases.length} recorded`,
                    children: 'Safety leases'
                  }),
                  leases.length
                    ? leases.slice(0, 20).map(item =>
                        jsxs(
                          'div',
                          {
                            className: 'py-2 flex flex-col gap-1 text-[10px]',
                            style: { borderTop: '1px solid var(--ui-stroke-tertiary)' },
                            children: [
                              jsxs('div', {
                                className: 'flex flex-wrap items-center gap-2',
                                children: [
                                  jsx(Badge, {
                                    color:
                                      item.status === 'active'
                                        ? 'var(--ui-green)'
                                        : 'var(--ui-text-quaternary)',
                                    children: item.status
                                  }),
                                  jsx('span', {
                                    className: 'truncate flex-1',
                                    style: { color: 'var(--ui-text-secondary)' },
                                    children: item.cron_job_id
                                      ? `cron ${item.cron_job_id}`
                                      : shortId(item.playbook_id)
                                  }),
                                  item.status === 'active'
                                    ? jsx(ActionButton, {
                                        tone: 'danger',
                                        disabled: busy,
                                        onClick: () =>
                                          run(
                                            () =>
                                              ctx.rest(
                                                `/leases/${encodeURIComponent(item.id)}/revoke`,
                                                {
                                                  method: 'POST',
                                                  body: {
                                                    confirm: true,
                                                    reason: 'Revoked from Continuum Console'
                                                  }
                                                }
                                              ),
                                            'Safety lease revoked'
                                          ),
                                        children: 'Revoke'
                                      })
                                    : null
                                ]
                              }),
                              jsx('div', {
                                className: 'truncate',
                                style: { color: 'var(--ui-text-quaternary)' },
                                children: `tools ${(item.allowed_tools || []).join(', ') || 'none'} · paths ${
                                  (item.allowed_paths || []).join(', ') || 'none'
                                }`
                              }),
                              jsx('div', {
                                style: { color: 'var(--ui-text-quaternary)' },
                                children: `budget ${fmtInt(
                                  item.max_tool_calls
                                )} calls · expires ${fmtTs(item.expires_at)}`
                              })
                            ]
                          },
                          item.id
                        )
                      )
                    : jsx(EmptyNote, {
                        children: 'No leases issued. A lease scopes unattended Cron runs; it does not approve them.'
                      })
                ]
              })
            ]
          })
        ]
      })
    ]
  })
}

// ---------------------------------------------------------------------------
// Compact pane and status chip
// ---------------------------------------------------------------------------
function ContinuumPane({ ctx }) {
  const statusQuery = useQuery({
    queryKey: [...QUERY_ROOT, 'pane-status'],
    queryFn: () => ctx.rest('/status'),
    refetchInterval: 60000
  })
  const timelineQuery = useQuery({
    queryKey: [...QUERY_ROOT, 'pane-timeline'],
    queryFn: () => ctx.rest('/timeline?limit=5'),
    refetchInterval: 60000
  })
  const [busy, run] = useAction()
  const status = statusQuery.data || {}
  const events = (timelineQuery.data && timelineQuery.data.events) || []

  return jsxs('div', {
    className: 'flex flex-col h-full min-h-0 text-xs',
    style: { color: 'var(--ui-text-primary)' },
    children: [
      jsxs('div', {
        className: 'flex items-center gap-2 px-3 py-2',
        style: { borderBottom: '1px solid var(--ui-stroke-secondary)' },
        children: [
          jsx('span', {
            className: 'h-1.5 w-1.5 rounded-full',
            style: { background: 'var(--ui-accent)' }
          }),
          jsx('span', { className: 'font-medium', children: 'Continuum' }),
          jsx('span', {
            className: 'ml-auto text-[10px] tabular-nums',
            style: { color: 'var(--ui-yellow)' },
            children: `${fmtInt(status.needs_review)} to review`
          })
        ]
      }),
      jsx('div', {
        className: 'flex-1 min-h-0 overflow-y-auto px-3 py-2',
        children: events.length
          ? events.map(event =>
              jsxs(
                'div',
                {
                  className: 'flex items-start gap-2 py-1.5',
                  children: [
                    jsx('span', {
                      className: 'mt-1 h-1.5 w-1.5 rounded-full shrink-0',
                      style: {
                        background: MODULE_COLORS[event.module] || MODULE_COLORS.System
                      }
                    }),
                    jsxs('div', {
                      className: 'min-w-0',
                      children: [
                        jsx('div', {
                          className: 'truncate text-[10px]',
                          style: { color: 'var(--ui-text-secondary)' },
                          children: event.summary
                        }),
                        jsx('div', {
                          className: 'text-[10px]',
                          style: { color: 'var(--ui-text-quaternary)' },
                          children: fmtTs(event.timestamp_utc)
                        })
                      ]
                    })
                  ]
                },
                event.event_id
              )
            )
          : jsx('div', {
              className: 'py-4 text-center text-[10px]',
              style: { color: 'var(--ui-text-quaternary)' },
              children: 'No events yet.'
            })
      }),
      jsxs('div', {
        className: 'flex items-center gap-2 px-3 py-2',
        style: { borderTop: '1px solid var(--ui-stroke-secondary)' },
        children: [
          jsx(ActionButton, {
            onClick: () => host.navigate(ROUTE),
            children: 'Open Console'
          }),
          jsx(ActionButton, {
            disabled: busy,
            onClick: () =>
              run(() => ctx.rest('/dream', { method: 'POST' }), 'Dream consolidation finished'),
            children: 'Dream'
          })
        ]
      })
    ]
  })
}

function ContinuumChip({ ctx }) {
  const statusQuery = useQuery({
    queryKey: [...QUERY_ROOT, 'chip'],
    queryFn: () => ctx.rest('/status'),
    refetchInterval: 60000,
    retry: 1
  })
  const needsReview = statusQuery.data ? statusQuery.data.needs_review : 0
  const blocked =
    statusQuery.data && statusQuery.data.security_counts
      ? statusQuery.data.security_counts.block
      : 0
  if (statusQuery.isError) return null
  return jsxs('button', {
    type: 'button',
    onClick: () => host.navigate(ROUTE),
    title: `Continuum: ${fmtInt(needsReview)} memory candidate(s) to review, ${fmtInt(blocked)} blocked action(s)`,
    className: 'inline-flex h-full items-center gap-1 px-1.5 text-[10px] tabular-nums cursor-pointer',
    style: { color: 'var(--ui-text-tertiary)' },
    children: [
      jsx(Codicon, { name: 'pulse', size: '0.7rem' }),
      jsx('span', { children: fmtInt(needsReview) }),
      blocked
        ? jsx('span', {
            className: 'rounded-full px-1',
            style: { background: 'var(--ui-red)', color: 'var(--ui-bg-editor)' },
            children: fmtInt(blocked)
          })
        : null
    ]
  })
}
