-- Campaign Tracker Schema v1

CREATE TABLE IF NOT EXISTS campaigns (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  name TEXT NOT NULL,
  description TEXT,
  status TEXT DEFAULT 'ACTIVE',
  threat_level TEXT DEFAULT 'MEDIUM',
  target TEXT,
  target_type TEXT,
  entity_count INTEGER DEFAULT 0,
  coordination_score FLOAT DEFAULT 0,
  infrastructure_overlap FLOAT DEFAULT 0,
  geographic_spread TEXT[] DEFAULT '{}',
  platforms TEXT[] DEFAULT '{}',
  tactics TEXT[] DEFAULT '{}',
  summary TEXT,
  evidence_hash TEXT,
  first_detected TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS campaign_entities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,
  entity_input TEXT NOT NULL,
  entity_type TEXT DEFAULT 'UNKNOWN',
  role TEXT DEFAULT 'ACTOR',
  threat_score FLOAT DEFAULT 0,
  first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  activity_count INTEGER DEFAULT 1,
  signals JSONB DEFAULT '[]'::jsonb,
  ip_addresses TEXT[] DEFAULT '{}',
  platforms TEXT[] DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS campaign_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,
  entity_id UUID REFERENCES campaign_entities(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  description TEXT,
  severity TEXT DEFAULT 'INFO',
  metadata JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS evidence_packages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,
  package_type TEXT DEFAULT 'STANDARD',
  recipient TEXT,
  content JSONB NOT NULL,
  hash TEXT NOT NULL,
  exported_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);
CREATE INDEX IF NOT EXISTS idx_campaigns_threat ON campaigns(threat_level);
CREATE INDEX IF NOT EXISTS idx_campaign_entities_campaign ON campaign_entities(campaign_id);
CREATE INDEX IF NOT EXISTS idx_campaign_events_campaign ON campaign_events(campaign_id);
CREATE INDEX IF NOT EXISTS idx_evidence_campaign ON evidence_packages(campaign_id);
