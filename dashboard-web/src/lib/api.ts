import axios from 'axios';
import type { ThreatReport, DashboardStats, SystemConfig } from '@/types';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Reports API
export const reportsApi = {
  getAll: async (params?: {
    limit?: number;
    offset?: number;
    severity?: string;
    minRiskScore?: number;
  }): Promise<ThreatReport[]> => {
    const { data } = await api.get('/reports', { params });
    return data;
  },

  getById: async (id: number): Promise<ThreatReport> => {
    const { data } = await api.get(`/reports/${id}`);
    return data;
  },

  getRecent: async (limit: number = 10): Promise<ThreatReport[]> => {
    const { data } = await api.get(`/reports/recent?limit=${limit}`);
    return data;
  },

  getHighRisk: async (minScore: number = 70): Promise<ThreatReport[]> => {
    const { data } = await api.get(`/reports/high-risk?min_score=${minScore}`);
    return data;
  },

  getStats: async (): Promise<DashboardStats> => {
    const { data } = await api.get('/reports/stats');
    return data;
  },

  getTimeSeriesData: async (days: number = 7): Promise<any[]> => {
    const { data } = await api.get(`/reports/timeseries?days=${days}`);
    return data;
  },
};

// System Configuration API
export const configApi = {
  get: async (): Promise<SystemConfig> => {
    const { data } = await api.get('/config');
    return data;
  },

  update: async (config: Partial<SystemConfig>): Promise<void> => {
    await api.put('/config', config);
  },

  testConnection: async (service: 'wazuh' | 'opencti' | 'llm' | 'database'): Promise<{
    success: boolean;
    message: string;
  }> => {
    const { data } = await api.post(`/config/test/${service}`);
    return data;
  },
};

// Health check
export const healthApi = {
  check: async (): Promise<{ status: string; services: any }> => {
    const { data } = await api.get('/health');
    return data;
  },
};

export default api;
