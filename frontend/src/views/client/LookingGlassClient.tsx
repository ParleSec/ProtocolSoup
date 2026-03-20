'use client'

import dynamic from 'next/dynamic'

const LookingGlass = dynamic(
  () => import('@/views/LookingGlass').then((module) => module.LookingGlass),
  { ssr: false },
)

export function LookingGlassClient() {
  return <LookingGlass />
}

