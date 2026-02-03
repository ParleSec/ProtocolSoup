/**
 * SCIM Inspector Component
 * 
 * Visualizes SCIM resources, schemas, and operations for educational purposes.
 */

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

// ============================================================================
// Types
// ============================================================================

interface SCIMResource {
  schemas: string[]
  id?: string
  externalId?: string
  meta?: {
    resourceType?: string
    created?: string
    lastModified?: string
    location?: string
    version?: string
  }
  [key: string]: unknown
}

interface SCIMSchemaAttribute {
  name: string
  type: string
  multiValued: boolean
  description?: string
  required: boolean
  caseExact?: boolean
  mutability: string
  returned: string
  uniqueness?: string
  subAttributes?: SCIMSchemaAttribute[]
}

interface PatchOperation {
  op: string
  path?: string
  value?: unknown
}

interface SCIMInspectorProps {
  data: SCIMResource | SCIMResource[] | PatchOperation[]
  type: 'resource' | 'list' | 'patch' | 'filter' | 'schema'
  title?: string
}

// ============================================================================
// Schema URN Labels
// ============================================================================

const schemaLabels: Record<string, { label: string; color: string }> = {
  'urn:ietf:params:scim:schemas:core:2.0:User': { label: 'User', color: 'bg-blue-500' },
  'urn:ietf:params:scim:schemas:core:2.0:Group': { label: 'Group', color: 'bg-purple-500' },
  'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User': { label: 'Enterprise', color: 'bg-amber-500' },
  'urn:ietf:params:scim:api:messages:2.0:ListResponse': { label: 'List', color: 'bg-green-500' },
  'urn:ietf:params:scim:api:messages:2.0:PatchOp': { label: 'Patch', color: 'bg-orange-500' },
  'urn:ietf:params:scim:api:messages:2.0:BulkRequest': { label: 'Bulk', color: 'bg-red-500' },
  'urn:ietf:params:scim:api:messages:2.0:BulkResponse': { label: 'Bulk', color: 'bg-red-500' },
  'urn:ietf:params:scim:api:messages:2.0:Error': { label: 'Error', color: 'bg-red-600' },
}

const mutabilityColors: Record<string, string> = {
  readOnly: 'text-gray-400',
  readWrite: 'text-green-400',
  immutable: 'text-amber-400',
  writeOnly: 'text-blue-400',
}

// ============================================================================
// Main Component
// ============================================================================

export function SCIMInspector({ data, type, title }: SCIMInspectorProps) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['root']))

  const toggleSection = (section: string) => {
    const newExpanded = new Set(expandedSections)
    if (newExpanded.has(section)) {
      newExpanded.delete(section)
    } else {
      newExpanded.add(section)
    }
    setExpandedSections(newExpanded)
  }

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-700 overflow-hidden">
      {title && (
        <div className="px-4 py-3 border-b border-slate-700 bg-slate-800">
          <h3 className="text-sm font-medium text-slate-200">{title}</h3>
        </div>
      )}
      
      <div className="p-4">
        {type === 'resource' && (
          <ResourceView 
            resource={data as SCIMResource} 
            expanded={expandedSections}
            onToggle={toggleSection}
          />
        )}
        
        {type === 'list' && (
          <ListView 
            resources={Array.isArray(data) ? data as SCIMResource[] : [data as SCIMResource]}
            expanded={expandedSections}
            onToggle={toggleSection}
          />
        )}
        
        {type === 'patch' && (
          <PatchView operations={data as PatchOperation[]} />
        )}
        
        {type === 'filter' && (
          <FilterView filter={data as unknown as string} />
        )}
        
        {type === 'schema' && (
          <SchemaView schema={data as unknown as { attributes: SCIMSchemaAttribute[] }} />
        )}
      </div>
    </div>
  )
}

// ============================================================================
// Resource View
// ============================================================================

interface ResourceViewProps {
  resource: SCIMResource
  expanded: Set<string>
  onToggle: (section: string) => void
}

function ResourceView({ resource, expanded, onToggle }: ResourceViewProps) {
  const schemas = resource.schemas || []
  const meta = resource.meta

  return (
    <div className="space-y-3">
      {/* Schema Badges */}
      {schemas.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {schemas.map((schema, i) => {
            const info = schemaLabels[schema] || { label: 'Custom', color: 'bg-slate-500' }
            return (
              <span
                key={i}
                className={`${info.color} text-white text-xs px-2 py-1 rounded-full font-mono`}
                title={schema}
              >
                {info.label}
              </span>
            )
          })}
        </div>
      )}

      {/* Meta Information */}
      {meta && (
        <div className="text-xs text-slate-400 space-y-1 bg-slate-800/50 rounded p-2">
          <div className="flex items-center gap-4">
            {meta.resourceType && (
              <span>
                <span className="text-slate-500">Type:</span> {meta.resourceType}
              </span>
            )}
            {meta.version && (
              <span>
                <span className="text-slate-500">ETag:</span>{' '}
                <code className="text-green-400">{meta.version}</code>
              </span>
            )}
          </div>
          {meta.created && (
            <div>
              <span className="text-slate-500">Created:</span> {new Date(meta.created).toLocaleString()}
            </div>
          )}
          {meta.lastModified && (
            <div>
              <span className="text-slate-500">Modified:</span> {new Date(meta.lastModified).toLocaleString()}
            </div>
          )}
        </div>
      )}

      {/* Resource Attributes */}
      <AttributeTree 
        data={resource} 
        expanded={expanded}
        onToggle={onToggle}
        path="root"
        excludeKeys={['schemas', 'meta']}
      />
    </div>
  )
}

// ============================================================================
// Attribute Tree
// ============================================================================

interface AttributeTreeProps {
  data: Record<string, unknown>
  expanded: Set<string>
  onToggle: (section: string)=>void
  path: string
  excludeKeys?: string[]
}

function AttributeTree({ data, expanded, onToggle, path, excludeKeys = [] }: AttributeTreeProps) {
  const entries = Object.entries(data).filter(([key]) => !excludeKeys.includes(key))

  return (
    <div className="space-y-1 font-mono text-sm">
      {entries.map(([key, value]) => (
        <AttributeNode
          key={key}
          name={key}
          value={value}
          expanded={expanded}
          onToggle={onToggle}
          path={`${path}.${key}`}
        />
      ))}
    </div>
  )
}

interface AttributeNodeProps {
  name: string
  value: unknown
  expanded: Set<string>
  onToggle: (section: string) => void
  path: string
}

function AttributeNode({ name, value, expanded, onToggle, path }: AttributeNodeProps) {
  const isExpanded = expanded.has(path)
  const isComplex = typeof value === 'object' && value !== null
  const isArray = Array.isArray(value)

  // Handle enterprise extension key specially
  const displayName = name.startsWith('urn:ietf:params:scim') 
    ? schemaLabels[name]?.label || 'Extension'
    : name

  if (isComplex) {
    const itemCount = isArray ? (value as unknown[]).length : Object.keys(value as object).length

    return (
      <div className="ml-2">
        <button
          onClick={() => onToggle(path)}
          className="flex items-center gap-2 hover:bg-slate-800 px-2 py-1 rounded w-full text-left"
        >
          <span className={`transition-transform ${isExpanded ? 'rotate-90' : ''}`}>
            ▶
          </span>
          <span className="text-cyan-400">{displayName}</span>
          <span className="text-slate-500">
            {isArray ? `[${itemCount}]` : `{${itemCount}}`}
          </span>
        </button>
        
        <AnimatePresence>
          {isExpanded && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="ml-4 border-l border-slate-700 pl-2"
            >
              {isArray ? (
                (value as unknown[]).map((item, i) => (
                  <div key={i} className="my-1">
                    {typeof item === 'object' && item !== null ? (
                      <AttributeTree
                        data={item as Record<string, unknown>}
                        expanded={expanded}
                        onToggle={onToggle}
                        path={`${path}[${i}]`}
                      />
                    ) : (
                      <ValueDisplay value={item} />
                    )}
                  </div>
                ))
              ) : (
                <AttributeTree
                  data={value as Record<string, unknown>}
                  expanded={expanded}
                  onToggle={onToggle}
                  path={path}
                />
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2 ml-2 px-2 py-1">
      <span className="text-cyan-400">{displayName}:</span>
      <ValueDisplay value={value} />
    </div>
  )
}

function ValueDisplay({ value }: { value: unknown }) {
  if (value === null) return <span className="text-slate-500">null</span>
  if (value === undefined) return <span className="text-slate-500">undefined</span>
  if (typeof value === 'boolean') {
    return <span className={value ? 'text-green-400' : 'text-red-400'}>{String(value)}</span>
  }
  if (typeof value === 'number') {
    return <span className="text-amber-400">{value}</span>
  }
  if (typeof value === 'string') {
    // Check if it's a URL
    if (value.startsWith('http://') || value.startsWith('https://')) {
      return <a href={value} className="text-blue-400 hover:underline" target="_blank" rel="noopener noreferrer">{value}</a>
    }
    return <span className="text-green-400">"{value}"</span>
  }
  return <span className="text-slate-400">{JSON.stringify(value)}</span>
}

// ============================================================================
// List View
// ============================================================================

interface ListViewProps {
  resources: SCIMResource[]
  expanded: Set<string>
  onToggle: (section: string) => void
}

function ListView({ resources, expanded, onToggle }: ListViewProps) {
  const [selectedIndex, setSelectedIndex] = useState(0)

  if (resources.length === 0) {
    return (
      <div className="text-center text-slate-500 py-8">
        No resources found
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Resource Selector */}
      <div className="flex gap-2 flex-wrap">
        {resources.map((resource, i) => (
          <button
            key={i}
            onClick={() => setSelectedIndex(i)}
            className={`px-3 py-1.5 rounded text-sm transition-colors ${
              selectedIndex === i
                ? 'bg-blue-600 text-white'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
            }`}
          >
            {(resource as { userName?: string; displayName?: string }).userName || 
             (resource as { displayName?: string }).displayName || 
             resource.id || 
             `Resource ${i + 1}`}
          </button>
        ))}
      </div>

      {/* Selected Resource */}
      <ResourceView 
        resource={resources[selectedIndex]}
        expanded={expanded}
        onToggle={onToggle}
      />
    </div>
  )
}

// ============================================================================
// Patch View
// ============================================================================

interface PatchViewProps {
  operations: PatchOperation[]
}

function PatchView({ operations }: PatchViewProps) {
  const opColors: Record<string, string> = {
    add: 'bg-green-600',
    remove: 'bg-red-600',
    replace: 'bg-amber-600',
  }

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-400 mb-2">
        RFC 7644 Section 3.5.2 - PATCH Operations
      </div>
      
      {operations.map((op, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: i * 0.1 }}
          className="bg-slate-800 rounded-lg p-3 border border-slate-700"
        >
          <div className="flex items-center gap-3 mb-2">
            <span className={`${opColors[op.op] || 'bg-slate-600'} text-white text-xs px-2 py-1 rounded font-bold uppercase`}>
              {op.op}
            </span>
            {op.path && (
              <code className="text-cyan-400 text-sm">{op.path}</code>
            )}
          </div>
          
          {op.value !== undefined && (
            <div className="mt-2 pl-4 border-l-2 border-slate-600">
              <div className="text-xs text-slate-500 mb-1">Value:</div>
              <pre className="text-sm text-green-400 overflow-x-auto">
                {JSON.stringify(op.value, null, 2)}
              </pre>
            </div>
          )}
        </motion.div>
      ))}
    </div>
  )
}

// ============================================================================
// Filter View
// ============================================================================

interface FilterViewProps {
  filter: string
}

function FilterView({ filter }: FilterViewProps) {
  // Simple filter highlighting
  const highlighted = filter
    .replace(/\b(eq|ne|co|sw|ew|gt|lt|ge|le|pr)\b/gi, '<span class="text-amber-400 font-bold">$1</span>')
    .replace(/\b(and|or|not)\b/gi, '<span class="text-purple-400 font-bold">$1</span>')
    .replace(/"([^"]+)"/g, '<span class="text-green-400">"$1"</span>')
    .replace(/\b(true|false)\b/gi, '<span class="text-blue-400">$1</span>')

  return (
    <div className="space-y-4">
      <div className="text-xs text-slate-400">
        RFC 7644 Section 3.4.2.2 - Filter Syntax
      </div>
      
      <div className="bg-slate-800 rounded p-4 font-mono">
        <div 
          className="text-slate-200"
          dangerouslySetInnerHTML={{ __html: highlighted }}
        />
      </div>

      <div className="text-xs text-slate-500 space-y-1">
        <div><span className="text-amber-400">eq ne co sw ew gt lt ge le pr</span> - Comparison operators</div>
        <div><span className="text-purple-400">and or not</span> - Logical operators</div>
        <div><span className="text-green-400">"..."</span> - String values</div>
      </div>
    </div>
  )
}

// ============================================================================
// Schema View
// ============================================================================

interface SchemaViewProps {
  schema: { attributes: SCIMSchemaAttribute[] }
}

function SchemaView({ schema }: SchemaViewProps) {
  const [expandedAttrs, setExpandedAttrs] = useState<Set<string>>(new Set())

  const toggleAttr = (name: string) => {
    const newExpanded = new Set(expandedAttrs)
    if (newExpanded.has(name)) {
      newExpanded.delete(name)
    } else {
      newExpanded.add(name)
    }
    setExpandedAttrs(newExpanded)
  }

  return (
    <div className="space-y-2">
      <div className="text-xs text-slate-400 mb-3">
        RFC 7643 Section 7 - Schema Definition
      </div>

      {schema.attributes?.map((attr) => (
        <SchemaAttribute 
          key={attr.name}
          attribute={attr}
          expanded={expandedAttrs.has(attr.name)}
          onToggle={() => toggleAttr(attr.name)}
        />
      ))}
    </div>
  )
}

interface SchemaAttributeProps {
  attribute: SCIMSchemaAttribute
  expanded: boolean
  onToggle: () => void
}

function SchemaAttribute({ attribute, expanded, onToggle }: SchemaAttributeProps) {
  const hasSubAttrs = attribute.subAttributes && attribute.subAttributes.length > 0

  return (
    <div className="border border-slate-700 rounded">
      <button
        onClick={onToggle}
        className="w-full px-3 py-2 flex items-center justify-between hover:bg-slate-800 transition-colors"
      >
        <div className="flex items-center gap-3">
          {hasSubAttrs && (
            <span className={`transition-transform ${expanded ? 'rotate-90' : ''}`}>▶</span>
          )}
          <span className="text-cyan-400 font-mono">{attribute.name}</span>
          <span className="text-slate-500 text-xs">{attribute.type}</span>
          {attribute.multiValued && (
            <span className="text-xs bg-slate-700 px-1.5 rounded">array</span>
          )}
          {attribute.required && (
            <span className="text-xs bg-red-900 text-red-300 px-1.5 rounded">required</span>
          )}
        </div>
        <span className={`text-xs ${mutabilityColors[attribute.mutability] || 'text-slate-400'}`}>
          {attribute.mutability}
        </span>
      </button>

      <AnimatePresence>
        {expanded && hasSubAttrs && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-slate-700 bg-slate-800/50 px-3 py-2"
          >
            <div className="space-y-1 ml-4">
              {attribute.subAttributes?.map((sub) => (
                <div key={sub.name} className="flex items-center gap-2 text-sm">
                  <span className="text-slate-400">•</span>
                  <span className="text-cyan-300 font-mono">{sub.name}</span>
                  <span className="text-slate-500 text-xs">{sub.type}</span>
                  <span className={`text-xs ${mutabilityColors[sub.mutability] || 'text-slate-400'}`}>
                    {sub.mutability}
                  </span>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default SCIMInspector

