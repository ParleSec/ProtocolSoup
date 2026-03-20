'use client'

import dynamic from 'next/dynamic'

const Callback = dynamic(
  () => import('@/views/Callback').then((module) => module.Callback),
  { ssr: false },
)

export function CallbackClient() {
  return <Callback />
}

