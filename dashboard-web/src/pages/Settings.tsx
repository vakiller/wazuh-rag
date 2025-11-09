import { useEffect, useState } from 'react';
import {
  Settings as SettingsIcon,
  Shield,
  Brain,
  Database,
  CheckCircle,
  XCircle,
  AlertCircle,
  Send,
  Bell,
  Save,
  Loader,
} from 'lucide-react';
import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

interface ServiceStatus {
  status: string;
  message: string;
  host?: string;
  url?: string;
  model?: string;
}

interface SystemStatus {
  wazuh: ServiceStatus;
  opencti: ServiceStatus;
  llm: ServiceStatus;
}

interface TelegramConfig {
  bot_token: string;
  chat_id: string;
  enabled: boolean;
  min_severity: string;
}

export default function Settings() {
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [telegramConfig, setTelegramConfig] = useState<TelegramConfig>({
    bot_token: '',
    chat_id: '',
    enabled: false,
    min_severity: 'medium',
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [statusRes, telegramRes] = await Promise.all([
        axios.get(`${API_BASE_URL}/config/status`),
        axios.get(`${API_BASE_URL}/config/telegram`),
      ]);
      setSystemStatus(statusRes.data);
      setTelegramConfig(telegramRes.data);
    } catch (error) {
      console.error('Failed to load settings:', error);
      showMessage('error', 'Failed to load settings');
    } finally {
      setLoading(false);
    }
  };

  const showMessage = (type: 'success' | 'error', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 5000);
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      await axios.post(`${API_BASE_URL}/config/telegram`, telegramConfig);
      showMessage('success', 'Configuration saved successfully');
    } catch (error: any) {
      showMessage('error', error.response?.data?.detail || 'Failed to save configuration');
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    try {
      setTesting(true);
      await axios.post(`${API_BASE_URL}/config/telegram/test`, telegramConfig);
      showMessage('success', 'Test message sent successfully! Check your Telegram.');
    } catch (error: any) {
      showMessage('error', error.response?.data?.detail || 'Failed to send test message');
    } finally {
      setTesting(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'connected':
        return <CheckCircle className="w-5 h-5 text-green-500" />;
      case 'disconnected':
        return <XCircle className="w-5 h-5 text-gray-500" />;
      case 'error':
        return <AlertCircle className="w-5 h-5 text-critical" />;
      default:
        return <AlertCircle className="w-5 h-5 text-gray-500" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected':
        return 'border-green-500/30 bg-green-500/5';
      case 'disconnected':
        return 'border-gray-600 bg-gray-900/30';
      case 'error':
        return 'border-critical/30 bg-critical/5';
      default:
        return 'border-dark-border bg-dark-surface';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <Loader className="w-12 h-12 text-info animate-spin mx-auto mb-4" />
          <p className="text-gray-400">Loading settings...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8 space-y-8 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-center space-x-4">
        <SettingsIcon className="w-8 h-8 text-info" />
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">System Settings</h1>
          <p className="text-gray-400">Monitor services and configure notifications</p>
        </div>
      </div>

      {/* Message Banner */}
      {message && (
        <div
          className={`p-4 rounded-lg border ${
            message.type === 'success'
              ? 'bg-green-500/10 border-green-500/30 text-green-500'
              : 'bg-critical/10 border-critical/30 text-critical'
          }`}
        >
          {message.text}
        </div>
      )}

      {/* System Status */}
      <div className="bg-dark-card border border-dark-border rounded-lg overflow-hidden">
        <div className="bg-dark-surface border-b border-dark-border p-6">
          <h2 className="text-xl font-semibold text-white flex items-center space-x-2">
            <Shield className="w-6 h-6 text-info" />
            <span>Service Connection Status</span>
          </h2>
        </div>

        <div className="p-6 grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Wazuh Status */}
          {systemStatus?.wazuh && (
            <div className={`border rounded-lg p-6 ${getStatusColor(systemStatus.wazuh.status)}`}>
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <Database className="w-8 h-8 text-info" />
                  <div>
                    <h3 className="text-lg font-semibold text-white">Wazuh Indexer</h3>
                    <p className="text-sm text-gray-400">Security Event Source</p>
                  </div>
                </div>
                {getStatusIcon(systemStatus.wazuh.status)}
              </div>
              <div className="space-y-2">
                {systemStatus.wazuh.host && (
                  <p className="text-sm text-gray-300">
                    <span className="text-gray-500">Host:</span> {systemStatus.wazuh.host}
                  </p>
                )}
                <p className="text-sm text-gray-400">{systemStatus.wazuh.message}</p>
              </div>
            </div>
          )}

          {/* OpenCTI Status */}
          {systemStatus?.opencti && (
            <div className={`border rounded-lg p-6 ${getStatusColor(systemStatus.opencti.status)}`}>
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <Shield className="w-8 h-8 text-high" />
                  <div>
                    <h3 className="text-lg font-semibold text-white">OpenCTI</h3>
                    <p className="text-sm text-gray-400">Threat Intelligence</p>
                  </div>
                </div>
                {getStatusIcon(systemStatus.opencti.status)}
              </div>
              <div className="space-y-2">
                {systemStatus.opencti.url && (
                  <p className="text-sm text-gray-300 truncate">
                    <span className="text-gray-500">URL:</span> {systemStatus.opencti.url}
                  </p>
                )}
                <p className="text-sm text-gray-400">{systemStatus.opencti.message}</p>
              </div>
            </div>
          )}

          {/* LLM Status */}
          {systemStatus?.llm && (
            <div className={`border rounded-lg p-6 ${getStatusColor(systemStatus.llm.status)}`}>
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <Brain className="w-8 h-8 text-medium" />
                  <div>
                    <h3 className="text-lg font-semibold text-white">LLM Service</h3>
                    <p className="text-sm text-gray-400">AI Analysis Engine</p>
                  </div>
                </div>
                {getStatusIcon(systemStatus.llm.status)}
              </div>
              <div className="space-y-2">
                {systemStatus.llm.url && (
                  <p className="text-sm text-gray-300 truncate">
                    <span className="text-gray-500">URL:</span> {systemStatus.llm.url}
                  </p>
                )}
                {systemStatus.llm.model && (
                  <p className="text-sm text-gray-300">
                    <span className="text-gray-500">Model:</span> {systemStatus.llm.model}
                  </p>
                )}
                <p className="text-sm text-gray-400">{systemStatus.llm.message}</p>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Telegram Notifications */}
      <div className="bg-dark-card border border-dark-border rounded-lg overflow-hidden">
        <div className="bg-dark-surface border-b border-dark-border p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Bell className="w-6 h-6 text-info" />
              <h2 className="text-xl font-semibold text-white">Telegram Notifications</h2>
            </div>
            <label className="flex items-center space-x-3 cursor-pointer">
              <span className="text-sm text-gray-400">Enable Notifications</span>
              <div className="relative">
                <input
                  type="checkbox"
                  checked={telegramConfig.enabled}
                  onChange={(e) =>
                    setTelegramConfig({ ...telegramConfig, enabled: e.target.checked })
                  }
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-info"></div>
              </div>
            </label>
          </div>
          <p className="text-sm text-gray-400 mt-2">
            Get instant alerts in Telegram when new threats are detected
          </p>
        </div>

        <div className="p-6 space-y-6">
          {/* Bot Token */}
          <div>
            <label className="block text-sm font-semibold text-gray-300 mb-2">
              Bot Token
              <span className="text-critical ml-1">*</span>
            </label>
            <input
              type="text"
              placeholder="1234567890:ABCdefGHIjklMNOpqrsTUVwxyz"
              value={telegramConfig.bot_token}
              onChange={(e) =>
                setTelegramConfig({ ...telegramConfig, bot_token: e.target.value })
              }
              className="w-full bg-dark-surface border border-dark-border rounded-lg px-4 py-3 text-gray-200 placeholder-gray-500 focus:outline-none focus:border-info transition-colors"
            />
            <p className="text-xs text-gray-500 mt-1">
              Get your bot token from{' '}
              <a
                href="https://t.me/BotFather"
                target="_blank"
                rel="noopener noreferrer"
                className="text-info hover:underline"
              >
                @BotFather
              </a>
            </p>
          </div>

          {/* Chat ID */}
          <div>
            <label className="block text-sm font-semibold text-gray-300 mb-2">
              Chat ID
              <span className="text-critical ml-1">*</span>
            </label>
            <input
              type="text"
              placeholder="123456789 or -100123456789"
              value={telegramConfig.chat_id}
              onChange={(e) =>
                setTelegramConfig({ ...telegramConfig, chat_id: e.target.value })
              }
              className="w-full bg-dark-surface border border-dark-border rounded-lg px-4 py-3 text-gray-200 placeholder-gray-500 focus:outline-none focus:border-info transition-colors"
            />
            <p className="text-xs text-gray-500 mt-1">
              Get your chat ID from{' '}
              <a
                href="https://t.me/userinfobot"
                target="_blank"
                rel="noopener noreferrer"
                className="text-info hover:underline"
              >
                @userinfobot
              </a>
            </p>
          </div>

          {/* Minimum Severity */}
          <div>
            <label className="block text-sm font-semibold text-gray-300 mb-2">
              Minimum Severity Level
            </label>
            <select
              value={telegramConfig.min_severity}
              onChange={(e) =>
                setTelegramConfig({ ...telegramConfig, min_severity: e.target.value })
              }
              className="w-full bg-dark-surface border border-dark-border rounded-lg px-4 py-3 text-gray-200 focus:outline-none focus:border-info transition-colors"
            >
              <option value="low">Low (All alerts)</option>
              <option value="medium">Medium and above</option>
              <option value="high">High and Critical only</option>
              <option value="critical">Critical only</option>
            </select>
            <p className="text-xs text-gray-500 mt-1">
              Only send notifications for threats at or above this severity level
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center space-x-3 pt-4 border-t border-dark-border">
            <button
              onClick={handleTest}
              disabled={!telegramConfig.bot_token || !telegramConfig.chat_id || testing}
              className="flex items-center space-x-2 px-6 py-3 bg-dark-surface hover:bg-dark-hover border border-dark-border hover:border-info/30 text-gray-200 rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {testing ? (
                <Loader className="w-5 h-5 animate-spin" />
              ) : (
                <Send className="w-5 h-5" />
              )}
              <span>{testing ? 'Sending...' : 'Test Configuration'}</span>
            </button>

            <button
              onClick={handleSave}
              disabled={saving}
              className="flex items-center space-x-2 px-6 py-3 bg-info hover:bg-info-light text-white rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saving ? (
                <Loader className="w-5 h-5 animate-spin" />
              ) : (
                <Save className="w-5 h-5" />
              )}
              <span>{saving ? 'Saving...' : 'Save Configuration'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
