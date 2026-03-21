'use client'

import dynamic from 'next/dynamic'

const SSFSandbox = dynamic(
  () => import('@/views/SSFSandbox').then((module) => module.SSFSandbox),
  { ssr: false },
)

export function SSFSandboxClient() {
  return <SSFSandbox />
}

