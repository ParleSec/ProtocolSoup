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
    id: 'degree-sdjwt',
    label: 'Degree dc+sd-jwt',
    description: 'Requests degree + graduation_year from an SD-JWT VC credential.',
    query: JSON.stringify(
      {
        credentials: [
          {
            id: 'university_degree',
            format: 'dc+sd-jwt',
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
    id: 'degree-jwt-vc-json',
    label: 'Degree jwt_vc_json',
    description: 'Requests degree + department from a JWT VC JSON credential.',
    query: JSON.stringify(
      {
        credentials: [
          {
            id: 'university_degree',
            format: 'jwt_vc_json',
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
    id: 'degree-jwt-vc-json-ld',
    label: 'Degree jwt_vc_json-ld',
    description: 'Requests degree claims from a JWT VC JSON-LD profile.',
    query: JSON.stringify(
      {
        credentials: [
          {
            id: 'university_degree',
            format: 'jwt_vc_json-ld',
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
    id: 'degree-ldp-vc',
    label: 'Degree ldp_vc',
    description: 'Requests degree claims from an ldp_vc profile.',
    query: JSON.stringify(
      {
        credentials: [
          {
            id: 'university_degree',
            format: 'ldp_vc',
            meta: {
              vct_values: ['https://protocolsoup.com/credentials/university_degree'],
            },
            claims: [{ path: ['degree'] }, { path: ['department'] }],
          },
        ],
      },
      null,
      2,
    ),
  },
  {
    id: 'degree-mso-mdoc',
    label: 'Degree mso_mdoc',
    description: 'Requests holder identity and department from mso_mdoc profile.',
    query: JSON.stringify(
      {
        credentials: [
          {
            id: 'university_degree_mdoc',
            format: 'mso_mdoc',
            meta: {
              doctype_values: ['org.iso.18013.5.1.mDL'],
            },
            claims: [{ path: ['given_name'] }, { path: ['family_name'] }, { path: ['department'] }],
          },
        ],
      },
      null,
      2,
    ),
  },
  {
    id: 'multi-format-matrix',
    label: 'Multi-format matrix',
    description: 'Demonstrates DCQL constraints over sd-jwt and mso_mdoc credential slots.',
    query: JSON.stringify(
      {
        credentials: [
          {
            id: 'university_degree_sd',
            format: 'dc+sd-jwt',
            meta: {
              vct_values: ['https://protocolsoup.com/credentials/university_degree'],
            },
            claims: [{ path: ['degree'] }, { path: ['graduation_year'] }],
          },
          {
            id: 'university_degree_mdoc',
            format: 'mso_mdoc',
            meta: {
              doctype_values: ['org.iso.18013.5.1.mDL'],
            },
            claims: [{ path: ['given_name'] }, { path: ['family_name'] }],
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
