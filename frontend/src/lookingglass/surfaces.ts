'use client'

import type { ComponentType } from 'react'
import { SSFLabChrome, type LookingGlassChromeProps } from './components/ssf/SSFLabChrome'

export type LookingGlassExtraTab = 'state' | 'set'

export interface LookingGlassSurface {
  session: {
    resetOnFlowChange: boolean
    mintSessionPerExecute: boolean
    accumulateWire: boolean
  }
  copy: {
    flowNoun: string
    executeLabel: string
    executeAgainLabel: string
    subtitle: string
    emptyTitle: string
    emptySubtitle: string
  }
  hideFlowSelector?: boolean
  chrome: ComponentType<LookingGlassChromeProps> | null
  panel: {
    extraTabs: LookingGlassExtraTab[]
    actors: 'transmitter-receiver' | 'default'
  }
}

const SSF_SURFACE: LookingGlassSurface = {
  session: {
    resetOnFlowChange: false,
    mintSessionPerExecute: false,
    accumulateWire: true,
  },
  copy: {
    flowNoun: 'Lab',
    executeLabel: 'Fire event',
    executeAgainLabel: 'Fire event',
    subtitle: 'Pick a subject and CAEP/RISC event, then fire a SET. RP account state changes only after that SET is verified — not after stream discovery.',
    emptyTitle: 'Select Shared Signals to open the stream lab',
    emptySubtitle: 'Fire event sends a SET. Verify stream only reads transmitter metadata and does not change RP posture.',
  },
  hideFlowSelector: true,
  chrome: SSFLabChrome,
  panel: {
    extraTabs: ['state', 'set'],
    actors: 'transmitter-receiver',
  },
}

export function getLookingGlassSurface(protocolId: string | null | undefined): LookingGlassSurface | null {
  if (protocolId === 'ssf') {
    return SSF_SURFACE
  }
  return null
}

export type { LookingGlassChromeProps }
