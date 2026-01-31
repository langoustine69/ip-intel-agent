import { createAgent } from '@lucid-agents/core';
import { http } from '@lucid-agents/http';
import { createAgentApp } from '@lucid-agents/hono';
import { payments, paymentsFromEnv } from '@lucid-agents/payments';
import { z } from 'zod';

const agent = await createAgent({
  name: 'ip-intel-agent',
  version: '1.0.0',
  description: 'IP Intelligence API - Aggregated geolocation, ISP, threat detection from multiple sources. Built for agents that need IP context.',
})
  .use(http())
  .use(payments({ config: paymentsFromEnv() }))
  .build();

const { app, addEntrypoint } = await createAgentApp(agent);

// === HELPER: Fetch JSON with timeout ===
async function fetchJSON(url: string, timeoutMs = 5000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) throw new Error(`API error: ${response.status}`);
    return response.json();
  } finally {
    clearTimeout(timeout);
  }
}

// === IP validation helper ===
function isValidIP(ip: string): boolean {
  const ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6 = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^([0-9a-fA-F]{1,4}:){1,7}:$|^:(:([0-9a-fA-F]{1,4})){1,7}$/;
  return ipv4.test(ip) || ipv6.test(ip);
}

// === Haversine distance calculation ===
function haversineDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371; // Earth's radius in km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

// === FREE ENDPOINT: Overview ===
addEntrypoint({
  key: 'overview',
  description: 'Free overview - see available endpoints and test the API',
  input: z.object({}),
  price: { amount: 0 },
  handler: async () => {
    const testIP = await fetchJSON('http://ip-api.com/json/?fields=query');
    return {
      output: {
        agent: 'ip-intel-agent',
        description: 'Aggregated IP intelligence from 3 data sources',
        endpoints: {
          'lookup': { price: '$0.001', description: 'Basic IP lookup (single source)' },
          'full': { price: '$0.002', description: 'Full intelligence (3 sources aggregated)' },
          'batch': { price: '$0.003', description: 'Batch lookup up to 10 IPs' },
          'threat': { price: '$0.002', description: 'Threat assessment (VPN/proxy/hosting)' },
          'distance': { price: '$0.002', description: 'Geo distance between two IPs' },
        },
        dataSources: ['ip-api.com', 'ipinfo.io', 'ipwho.is'],
        sampleIP: testIP.query,
        fetchedAt: new Date().toISOString(),
      },
    };
  },
});

// === PAID ENDPOINT 1: Basic lookup ($0.001) ===
addEntrypoint({
  key: 'lookup',
  description: 'Basic IP lookup - geolocation, ISP, org from primary source',
  input: z.object({ ip: z.string() }),
  price: { amount: 1000 },
  handler: async (ctx) => {
    const { ip } = ctx.input;
    if (!isValidIP(ip)) {
      return { output: { error: 'Invalid IP address format', ip } };
    }
    
    const data = await fetchJSON(
      `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query`
    );
    
    if (data.status !== 'success') {
      return { output: { error: data.message || 'Lookup failed', ip } };
    }
    
    return {
      output: {
        ip: data.query,
        location: {
          country: data.country,
          countryCode: data.countryCode,
          region: data.regionName,
          city: data.city,
          zip: data.zip,
          lat: data.lat,
          lon: data.lon,
          timezone: data.timezone,
        },
        network: {
          isp: data.isp,
          org: data.org,
          asn: data.as,
          asnName: data.asname,
        },
        source: 'ip-api.com',
        fetchedAt: new Date().toISOString(),
      },
    };
  },
});

// === PAID ENDPOINT 2: Full intelligence ($0.002) ===
addEntrypoint({
  key: 'full',
  description: 'Full IP intelligence - aggregated data from 3 sources with threat indicators',
  input: z.object({ ip: z.string() }),
  price: { amount: 2000 },
  handler: async (ctx) => {
    const { ip } = ctx.input;
    if (!isValidIP(ip)) {
      return { output: { error: 'Invalid IP address format', ip } };
    }
    
    const [ipApi, ipInfo, ipWho] = await Promise.allSettled([
      fetchJSON(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query`),
      fetchJSON(`https://ipinfo.io/${ip}/json`),
      fetchJSON(`https://ipwho.is/${ip}`),
    ]);
    
    const primary = ipApi.status === 'fulfilled' ? ipApi.value : null;
    const secondary = ipInfo.status === 'fulfilled' ? ipInfo.value : null;
    const tertiary = ipWho.status === 'fulfilled' ? ipWho.value : null;
    
    return {
      output: {
        ip,
        location: {
          country: primary?.country || secondary?.country || tertiary?.country,
          countryCode: primary?.countryCode || secondary?.country || tertiary?.country_code,
          region: primary?.regionName || secondary?.region || tertiary?.region,
          city: primary?.city || secondary?.city || tertiary?.city,
          zip: primary?.zip || secondary?.postal || tertiary?.postal,
          lat: primary?.lat || (secondary?.loc ? parseFloat(secondary.loc.split(',')[0]) : null) || tertiary?.latitude,
          lon: primary?.lon || (secondary?.loc ? parseFloat(secondary.loc.split(',')[1]) : null) || tertiary?.longitude,
          timezone: primary?.timezone || secondary?.timezone || tertiary?.timezone?.id,
        },
        network: {
          isp: primary?.isp || tertiary?.connection?.isp,
          org: primary?.org || secondary?.org || tertiary?.connection?.org,
          asn: primary?.as || secondary?.org || `AS${tertiary?.connection?.asn}`,
          hostname: primary?.reverse || secondary?.hostname,
          domain: tertiary?.connection?.domain,
        },
        threat: {
          isProxy: primary?.proxy ?? false,
          isVPN: primary?.proxy ?? false,
          isHosting: primary?.hosting ?? false,
          isMobile: primary?.mobile ?? false,
          isAnycast: secondary?.anycast ?? false,
        },
        confidence: {
          sourcesQueried: 3,
          sourcesResponded: [primary, secondary, tertiary].filter(Boolean).length,
        },
        sources: ['ip-api.com', 'ipinfo.io', 'ipwho.is'],
        fetchedAt: new Date().toISOString(),
      },
    };
  },
});

// === PAID ENDPOINT 3: Batch lookup ($0.003) ===
addEntrypoint({
  key: 'batch',
  description: 'Batch IP lookup - query up to 10 IPs at once',
  input: z.object({
    ips: z.array(z.string()).min(1).max(10),
  }),
  price: { amount: 3000 },
  handler: async (ctx) => {
    const { ips } = ctx.input;
    const validIPs = ips.filter(isValidIP);
    const invalidIPs = ips.filter(ip => !isValidIP(ip));
    
    const results = await Promise.all(
      validIPs.map(async (ip) => {
        try {
          const data = await fetchJSON(
            `http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,lat,lon,isp,org,as,proxy,hosting,query`
          );
          if (data.status !== 'success') {
            return { ip, error: 'Lookup failed' };
          }
          return {
            ip: data.query,
            country: data.country,
            countryCode: data.countryCode,
            city: data.city,
            lat: data.lat,
            lon: data.lon,
            isp: data.isp,
            org: data.org,
            asn: data.as,
            isProxy: data.proxy,
            isHosting: data.hosting,
          };
        } catch (e) {
          return { ip, error: 'Request failed' };
        }
      })
    );
    
    return {
      output: {
        results,
        invalidIPs: invalidIPs.length > 0 ? invalidIPs : undefined,
        count: {
          requested: ips.length,
          valid: validIPs.length,
          invalid: invalidIPs.length,
        },
        source: 'ip-api.com',
        fetchedAt: new Date().toISOString(),
      },
    };
  },
});

// === PAID ENDPOINT 4: Threat assessment ($0.002) ===
addEntrypoint({
  key: 'threat',
  description: 'Threat assessment - VPN/proxy/hosting/mobile detection with risk score',
  input: z.object({ ip: z.string() }),
  price: { amount: 2000 },
  handler: async (ctx) => {
    const { ip } = ctx.input;
    if (!isValidIP(ip)) {
      return { output: { error: 'Invalid IP address format', ip } };
    }
    
    const data = await fetchJSON(
      `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,isp,org,as,asname,reverse,mobile,proxy,hosting,query`
    );
    
    if (data.status !== 'success') {
      return { output: { error: data.message || 'Lookup failed', ip } };
    }
    
    // Calculate risk score (0-100)
    let riskScore = 0;
    const riskFactors: string[] = [];
    
    if (data.proxy) {
      riskScore += 40;
      riskFactors.push('proxy_or_vpn');
    }
    if (data.hosting) {
      riskScore += 30;
      riskFactors.push('datacenter_hosting');
    }
    if (data.mobile) {
      riskScore += 10;
      riskFactors.push('mobile_carrier');
    }
    if (!data.reverse) {
      riskScore += 10;
      riskFactors.push('no_reverse_dns');
    }
    
    const riskLevel = riskScore >= 50 ? 'high' : riskScore >= 20 ? 'medium' : 'low';
    
    return {
      output: {
        ip: data.query,
        threat: {
          isProxy: data.proxy,
          isVPN: data.proxy,
          isHosting: data.hosting,
          isMobile: data.mobile,
          hasReverseDNS: !!data.reverse,
          reverseDNS: data.reverse || null,
        },
        risk: {
          score: riskScore,
          level: riskLevel,
          factors: riskFactors,
        },
        network: {
          isp: data.isp,
          org: data.org,
          asn: data.as,
          asnName: data.asname,
        },
        source: 'ip-api.com',
        fetchedAt: new Date().toISOString(),
      },
    };
  },
});

// === PAID ENDPOINT 5: Distance calculation ($0.002) ===
addEntrypoint({
  key: 'distance',
  description: 'Calculate geographic distance between two IPs',
  input: z.object({
    ip1: z.string(),
    ip2: z.string(),
  }),
  price: { amount: 2000 },
  handler: async (ctx) => {
    const { ip1, ip2 } = ctx.input;
    
    if (!isValidIP(ip1) || !isValidIP(ip2)) {
      return { output: { error: 'Invalid IP address format', ip1, ip2 } };
    }
    
    const [data1, data2] = await Promise.all([
      fetchJSON(`http://ip-api.com/json/${ip1}?fields=status,country,city,lat,lon,query`),
      fetchJSON(`http://ip-api.com/json/${ip2}?fields=status,country,city,lat,lon,query`),
    ]);
    
    if (data1.status !== 'success' || data2.status !== 'success') {
      return { output: { error: 'One or both IP lookups failed', ip1, ip2 } };
    }
    
    const distanceKm = haversineDistance(data1.lat, data1.lon, data2.lat, data2.lon);
    const distanceMiles = distanceKm * 0.621371;
    
    return {
      output: {
        ip1: {
          ip: data1.query,
          country: data1.country,
          city: data1.city,
          lat: data1.lat,
          lon: data1.lon,
        },
        ip2: {
          ip: data2.query,
          country: data2.country,
          city: data2.city,
          lat: data2.lat,
          lon: data2.lon,
        },
        distance: {
          km: Math.round(distanceKm * 100) / 100,
          miles: Math.round(distanceMiles * 100) / 100,
        },
        sameCountry: data1.country === data2.country,
        sameCity: data1.city === data2.city,
        source: 'ip-api.com',
        fetchedAt: new Date().toISOString(),
      },
    };
  },
});

const port = Number(process.env.PORT ?? 3000);
console.log(`🔍 IP Intel Agent running on port ${port}`);

export default { port, fetch: app.fetch };
