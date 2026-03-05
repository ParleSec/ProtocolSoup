import { decodeBase64URLToString } from '../../utils/crypto'

export interface OID4VPDCQLPreset {
  id: string
  label: string
  description: string
  query: string
}

export const OID4VP_DEFAULT_DISCLOSURE_HINTS = [
  'degree',
  'graduation_year',
  'department',
  'given_name',
  'family_name',
]

export const OID4VP_DCQL_PRESETS: OID4VPDCQLPreset[] = [
  {
    id: 'degree-core',
    label: 'Degree core',
    description: 'Requests degree + graduation year from UniversityDegreeCredential.',
    query: JSON.stringify(
      {
        credentials: [
          {
            id: 'university_degree',
            meta: {
              vct_values: ['https://protocolsoup.com/credentials/university_degree'],
            },
            claims: [{ path: ['degree'] }, { path: ['graduation_year'] }],
          },
        ],
      },
      null,
      2,
    ),
  },
  {
    id: 'degree-and-department',
    label: 'Degree + department',
    description: 'Requests academic credential plus department for employer verification.',
    query: JSON.stringify(
      {
        credentials: [
          {
            id: 'university_degree',
            meta: {
              vct_values: ['https://protocolsoup.com/credentials/university_degree'],
            },
            claims: [{ path: ['degree'] }, { path: ['graduation_year'] }, { path: ['department'] }],
          },
        ],
      },
      null,
      2,
    ),
  },
  {
    id: 'multi-credential',
    label: 'Multi-credential query',
    description: 'Demonstrates DCQL with two credential slots and constrained claims.',
    query: JSON.stringify(
      {
        credentials: [
          {
            id: 'degree_credential',
            meta: {
              vct_values: ['https://protocolsoup.com/credentials/university_degree'],
            },
            claims: [{ path: ['degree'] }, { path: ['graduation_year'] }],
          },
          {
            id: 'employment_credential',
            meta: {
              vct_values: ['https://protocolsoup.com/credentials/university_degree'],
            },
            claims: [{ path: ['department'] }],
          },
        ],
      },
      null,
      2,
    ),
  },
]

export const DEFAULT_OID4VP_DCQL_PRESET_ID = OID4VP_DCQL_PRESETS[0]?.id || 'degree-core'

export function parseSDJWTDisclosureClaimNames(rawCredential: string): string[] {
  const normalized = rawCredential.trim()
  if (!normalized) {
    return []
  }

  const parts = normalized
    .split('~')
    .map((part) => part.trim())
    .filter(Boolean)
  if (parts.length < 2) {
    return []
  }

  const claimNames = new Set<string>()
  for (const encodedDisclosure of parts.slice(1)) {
    const decodedDisclosure = decodeBase64URLToString(encodedDisclosure) || ''
    if (!decodedDisclosure) {
      continue
    }
    try {
      const parsedDisclosure = JSON.parse(decodedDisclosure) as unknown
      if (
        Array.isArray(parsedDisclosure) &&
        parsedDisclosure.length >= 3 &&
        typeof parsedDisclosure[1] === 'string'
      ) {
        claimNames.add(parsedDisclosure[1])
      }
    } catch {
      // Ignore malformed segments (for example optional KB-JWT segment).
    }
  }

  return Array.from(claimNames).sort()
}

export function humanizeOID4VPTrustMode(mode: string): string {
  const normalized = mode.trim().toLowerCase()
  if (normalized === 'controlled_trust_mode') {
    return 'controlled trust mode'
  }
  if (normalized === 'interop_mode') {
    return 'interop mode'
  }
  return mode
}
