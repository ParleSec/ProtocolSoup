import { decodeBase64URLToString } from '../../utils/crypto'

export interface OID4VPDCQLPreset {
  id: string
  label: string
  description: string
  query: string
}

export interface OID4VPDCQLCredentialRequirement {
  id: string
  format: string
}

export const OID4VP_DEFAULT_DISCLOSURE_HINTS = [
  'family_name',
  'given_name',
  'document_number',
  'birth_date',
  'degree',
  'graduation_year',
  'department',
]

/** Educational university-degree VCT advertised by UniversityDegreeCredential. */
export const UNIVERSITY_DEGREE_EDUCATIONAL_VCT = 'https://protocolsoup.com/credentials/university_degree'

/** HAIP SD-JWT VC type-metadata path (OID4VCI 1.0 / SD-JWT VC type metadata). */
export const UNIVERSITY_DEGREE_TYPE_METADATA_PATH = '/oid4vci/credential-types/university-degree'

export function universityDegreeTypeMetadataVCT(issuerOrigin: string): string {
  const origin = issuerOrigin.replace(/\/$/, '')
  if (!origin) {
    return `https://protocolsoup.com${UNIVERSITY_DEGREE_TYPE_METADATA_PATH}`
  }
  return `${origin}${UNIVERSITY_DEGREE_TYPE_METADATA_PATH}`
}

/**
 * Set dc+sd-jwt vct_values to the HAIP type-metadata VCT that
 * UniversityDegreeCredentialSDJWTHAIP issues (plugin.go Initialize overwrites
 * the educational VCT). A HAIP presentation query must ask for that credential.
 */
export function withHAIPUniversityDegreeVCT(queryJSON: string, issuerOrigin: string): string {
  const parsed = JSON.parse(queryJSON) as { credentials?: Array<Record<string, unknown>> }
  if (!Array.isArray(parsed.credentials)) {
    return queryJSON
  }
  const haipVCT = universityDegreeTypeMetadataVCT(issuerOrigin)
  for (const credential of parsed.credentials) {
    if (String(credential.format || '').trim() !== 'dc+sd-jwt') {
      continue
    }
    const meta =
      credential.meta && typeof credential.meta === 'object' && !Array.isArray(credential.meta)
        ? { ...(credential.meta as Record<string, unknown>) }
        : {}
    meta.vct_values = [haipVCT]
    credential.meta = meta
  }
  return JSON.stringify(parsed, null, 2)
}

export const OID4VP_DCQL_PRESETS: OID4VPDCQLPreset[] = [
  {
    id: 'mdl-mso-mdoc',
    label: 'Mobile Driving Licence mso_mdoc',
    description: 'Requests family_name + document_number from an ISO/IEC 18013-5 mDL (mso_mdoc).',
    query: JSON.stringify(
      {
        credentials: [
          {
            id: 'mdl',
            format: 'mso_mdoc',
            meta: {
              // OID4VP 1.0 Final Appendix B.2.2: singular string doctype_value
              // (not the draft-era plural doctype_values array).
              doctype_value: 'org.iso.18013.5.1.mDL',
            },
            claims: [
              { path: ['org.iso.18013.5.1', 'family_name'] },
              { path: ['org.iso.18013.5.1', 'document_number'] },
            ],
          },
        ],
      },
      null,
      2,
    ),
  },
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
    id: 'multi-format-matrix',
    label: 'Multi-format matrix',
    description: 'Demonstrates DCQL constraints across sd-jwt, jwt_vc_json, and ldp_vc credential slots.',
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
            id: 'university_degree_jwt',
            format: 'jwt_vc_json',
            meta: {
              vct_values: ['https://protocolsoup.com/credentials/university_degree'],
            },
            claims: [{ path: ['department'] }, { path: ['given_name'] }],
          },
        ],
      },
      null,
      2,
    ),
  },
]

export const DEFAULT_OID4VP_DCQL_PRESET_ID = OID4VP_DCQL_PRESETS[0]?.id || 'mdl-mso-mdoc'

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null
  }
  return value as Record<string, unknown>
}

export function parseOID4VPDCQLCredentialRequirements(rawQuery: string): OID4VPDCQLCredentialRequirement[] {
  const normalized = rawQuery.trim()
  if (!normalized) {
    return []
  }

  const payload = asRecord(JSON.parse(normalized))
  if (!payload || !Array.isArray(payload.credentials)) {
    return []
  }

  return payload.credentials
    .map((rawCredential) => {
      const credential = asRecord(rawCredential)
      if (!credential) {
        return null
      }
      return {
        id: typeof credential.id === 'string' ? credential.id.trim() : '',
        format: typeof credential.format === 'string' ? credential.format.trim() : '',
      }
    })
    .filter((requirement): requirement is OID4VPDCQLCredentialRequirement => Boolean(requirement))
}

export function getOID4VPDCQLCredentialFormats(rawQuery: string): string[] {
  const formats = parseOID4VPDCQLCredentialRequirements(rawQuery)
    .map((requirement) => requirement.format)
    .filter(Boolean)

  return Array.from(new Set(formats)).sort()
}

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
