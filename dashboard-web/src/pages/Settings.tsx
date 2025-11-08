import { Settings as SettingsIcon } from 'lucide-react';

export default function Settings() {
  return (
    <div className="p-8 space-y-8 max-w-[1200px] mx-auto">
      <div className="flex items-center space-x-4">
        <SettingsIcon className="w-8 h-8 text-info" />
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">System Configuration</h1>
          <p className="text-gray-400">Configure Wazuh, OpenCTI, LLM, and cronjob settings</p>
        </div>
      </div>

      <div className="bg-dark-card border border-dark-border rounded-lg p-8">
        <div className="text-center py-12">
          <SettingsIcon className="w-16 h-16 text-gray-600 mx-auto mb-4" />
          <p className="text-gray-400 mb-2">Configuration UI</p>
          <p className="text-sm text-gray-500">
            Settings interface will allow configuration of:
            <br />• Wazuh Indexer connection
            <br />• OpenCTI API settings
            <br />• LLM service configuration
            <br />• PostgreSQL database settings
            <br />• Cronjob schedules
          </p>
        </div>
      </div>
    </div>
  );
}
