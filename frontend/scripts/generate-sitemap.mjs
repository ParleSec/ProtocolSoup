/**
 * Dynamic Sitemap Generator
 * 
 * Automatically discovers all routes by parsing source files:
 * - Static routes from App.tsx
 * - Protocol/flow routes from Protocols.tsx
 * 
 * Features:
 * - Image sitemap support (xmlns:image)
 * - SEO-optimized titles and descriptions per page
 * - Proper change frequency based on content type
 * 
 * Add protocols to Protocols.tsx and the sitemap updates automatically on build.
 */

import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const srcDir = join(__dirname, '..', 'src');
const publicDir = join(__dirname, '..', 'public');

const SITE_URL = 'https://protocolsoup.com';
const OG_IMAGE = `${SITE_URL}/og-image.png`;

// =============================================================================
// SEO Metadata for Pages
// =============================================================================

const PAGE_TITLES = {
  '/': 'Protocol Soup - Interactive Authentication Protocol Playground',
  '/protocols': 'Identity Protocol Reference Guide - OAuth 2.0, OIDC, SAML, SPIFFE, SCIM, SSF',
  '/looking-glass': 'Looking Glass - Live Protocol Flow Execution & Traffic Inspector',
  '/ssf-sandbox': 'SSF Sandbox - Shared Signals Framework Interactive Playground',
};

const PROTOCOL_TITLES = {
  oauth2: 'OAuth 2.0 Tutorial - Complete Authorization Framework Guide',
  oidc: 'OpenID Connect Tutorial - Authentication Layer for OAuth 2.0',
  saml: 'SAML 2.0 Tutorial - Enterprise SSO & Federation Explained',
  spiffe: 'SPIFFE/SPIRE Tutorial - Zero Trust Workload Identity',
  scim: 'SCIM 2.0 Tutorial - Cross-Domain Identity Provisioning',
};

// =============================================================================
// Parse Static Routes from App.tsx
// =============================================================================

function parseStaticRoutes() {
  const appPath = join(srcDir, 'App.tsx');
  const content = readFileSync(appPath, 'utf-8');
  
  const routes = [];
  
  // Match all <Route path="..." patterns
  const routeRegex = /<Route\s+path=["']([^"']+)["']/g;
  let match;
  
  while ((match = routeRegex.exec(content)) !== null) {
    const path = match[1];
    
    // Skip dynamic routes (contain :) and callback routes
    if (path.includes(':') || path === '/callback') {
      continue;
    }
    
    routes.push(path);
  }
  
  return routes;
}

// =============================================================================
// Parse Protocols from Protocols.tsx
// =============================================================================

function parseProtocols() {
  const protocolsPath = join(srcDir, 'pages', 'Protocols.tsx');
  const content = readFileSync(protocolsPath, 'utf-8');
  
  const protocols = [];
  
  // Extract the protocols array - match from 'const protocols = [' to the closing ']'
  const protocolsArrayMatch = content.match(/const\s+protocols\s*=\s*\[([\s\S]*?)\n\]/);
  
  if (!protocolsArrayMatch) {
    console.warn('⚠️  Could not parse protocols array from Protocols.tsx');
    return protocols;
  }
  
  const protocolsContent = protocolsArrayMatch[1];
  
  // Extract each protocol block with name and description
  const protocolBlockRegex = /\{\s*id:\s*['"]([^'"]+)['"]\s*,\s*name:\s*['"]([^'"]+)['"]\s*,\s*description:\s*['"]([^'"]+)['"]/g;
  const flowsRegex = /\{\s*id:\s*['"]([^'"]+)['"][^}]*flows:\s*\[([\s\S]*?)\]\s*,?\s*\}/g;
  
  let protocolMatch;
  
  // First pass: get protocol metadata
  const protocolMeta = {};
  while ((protocolMatch = protocolBlockRegex.exec(protocolsContent)) !== null) {
    protocolMeta[protocolMatch[1]] = {
      name: protocolMatch[2],
      description: protocolMatch[3],
    };
  }
  
  // Second pass: get flows
  let flowsMatch;
  while ((flowsMatch = flowsRegex.exec(protocolsContent)) !== null) {
    const protocolId = flowsMatch[1];
    const flowsContent = flowsMatch[2];
    
    // Extract flow IDs and names
    const flows = [];
    const flowDetailRegex = /\{\s*id:\s*['"]([^'"]+)['"]\s*,\s*name:\s*['"]([^'"]+)['"]/g;
    let flowMatch;
    
    while ((flowMatch = flowDetailRegex.exec(flowsContent)) !== null) {
      flows.push({
        id: flowMatch[1],
        name: flowMatch[2],
      });
    }
    
    protocols.push({
      id: protocolId,
      name: protocolMeta[protocolId]?.name || protocolId,
      description: protocolMeta[protocolId]?.description || '',
      flows,
    });
  }
  
  return protocols;
}

// =============================================================================
// Generate All Sitemap Entries
// =============================================================================

function generateEntries() {
  const entries = [];
  const today = new Date().toISOString().split('T')[0];
  
  // Static routes
  const staticRoutes = parseStaticRoutes();
  for (const path of staticRoutes) {
    entries.push({
      url: `${SITE_URL}${path === '/' ? '' : path}`,
      lastmod: today,
      changefreq: 'weekly',
      priority: path === '/' ? 1.0 : 0.9,
      title: PAGE_TITLES[path] || 'Protocol Soup',
      image: OG_IMAGE,
    });
  }
  
  // Protocol and flow routes
  const protocols = parseProtocols();
  for (const protocol of protocols) {
    // Protocol overview page
    entries.push({
      url: `${SITE_URL}/protocol/${protocol.id}`,
      lastmod: today,
      changefreq: 'monthly',
      priority: 0.8,
      title: PROTOCOL_TITLES[protocol.id] || `${protocol.name} Tutorial`,
      image: OG_IMAGE,
    });
    
    // Flow detail pages
    for (const flow of protocol.flows) {
      entries.push({
        url: `${SITE_URL}/protocol/${protocol.id}/flow/${flow.id}`,
        lastmod: today,
        changefreq: 'monthly',
        priority: 0.7,
        title: `${flow.name} - ${protocol.name} Flow Guide`,
        image: OG_IMAGE,
      });
    }
  }
  
  return { entries, staticCount: staticRoutes.length, protocols };
}

// =============================================================================
// Generate XML with Image Sitemap Support
// =============================================================================

function generateXml(entries) {
  const urlEntries = entries.map(entry => {
    const imageSection = entry.image ? `
    <image:image>
      <image:loc>${entry.image}</image:loc>
      <image:title>${escapeXml(entry.title)}</image:title>
    </image:image>` : '';
    
    return `  <url>
    <loc>${entry.url}</loc>
    <lastmod>${entry.lastmod}</lastmod>
    <changefreq>${entry.changefreq}</changefreq>
    <priority>${entry.priority.toFixed(1)}</priority>${imageSection}
  </url>`;
  }).join('\n');
  
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9
        http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd
        http://www.google.com/schemas/sitemap-image/1.1
        http://www.google.com/schemas/sitemap-image/1.1/sitemap-image.xsd">
  <!-- 
    Protocol Soup Sitemap
    Auto-generated: ${new Date().toISOString()}
    
    This file is automatically generated from source files.
    Routes parsed from: App.tsx, Protocols.tsx
    
    Features:
    - Image sitemap support for rich results
    - SEO-optimized page titles
  -->
${urlEntries}
</urlset>`;
}

/**
 * Escape special XML characters
 */
function escapeXml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// =============================================================================
// Main
// =============================================================================

function main() {
  console.log('Generating enhanced sitemap from source files...\n');
  
  try {
    const { entries, staticCount, protocols } = generateEntries();
    const xml = generateXml(entries);
    
    const outputPath = join(publicDir, 'sitemap.xml');
    writeFileSync(outputPath, xml, 'utf-8');
    
    const flowCount = protocols.reduce((sum, p) => sum + p.flows.length, 0);
    
    console.log('Parsed sources:');
    console.log('   └─ src/App.tsx');
    console.log('   └─ src/pages/Protocols.tsx\n');
    
    console.log(`Generated sitemap.xml with ${entries.length} URLs:`);
    console.log(`   ├─ ${staticCount} static pages`);
    console.log(`   ├─ ${protocols.length} protocol pages`);
    console.log(`   └─ ${flowCount} flow pages\n`);
    
    console.log('Discovered protocols:');
    for (const p of protocols) {
      console.log(`   └─ ${p.id} (${p.flows.length} flows)`);
    }
    
    console.log('\nImage sitemap: Enabled');
    console.log('SEO titles: Included');
    
    console.log(`\nOutput: public/sitemap.xml`);
    console.log('✨ Done!\n');
  } catch (error) {
    console.error(' Failed to generate sitemap:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

main();
