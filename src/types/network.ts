export type Classification = "TRUSTED" | "SUSPICIOUS" | "HIGH_RISK";

export type Network = {
  ssid: string;
  bssid: string;
  signal: number;
  channel: number;
  frequency: number;
  security: string;
  risk_score: number;
  classification: Classification;
  reasons: string[];
};

export type RiskFilter = "ALL" | Classification;