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
    flowNoun: 'Action',
    executeLabel: 'Fire event',
    executeAgainLabel: 'Fire event',
    subtitle: 'Configure the stream, fire CAEP and RISC events, and inspect Transmitter and Receiver traffic',
    emptyTitle: 'Select an action preset to begin',
    emptySubtitle: 'Subject, event type, and delivery stay on one Looking Glass session until you reset',
  },
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
