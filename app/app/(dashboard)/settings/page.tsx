'use client';

import { useState } from 'react';
import { User, Shield, Bell, Database, Key, Save, ChevronRight, Check } from 'lucide-react';
import TopBar from '@/components/TopBar';

const SettingRow = ({ label, description, children }: { label: string; description: string; children: React.ReactNode }) => (
  <div className="flex items-center justify-between py-4 border-b border-slate-100 last:border-0">
    <div className="flex-1 pr-8">
      <div className="text-sm font-semibold text-slate-800 mb-0.5">{label}</div>
      <div className="text-xs text-slate-500">{description}</div>
    </div>
    <div className="flex-shrink-0">{children}</div>
  </div>
);

const Toggle = ({ defaultOn = false }: { defaultOn?: boolean }) => {
  const [on, setOn] = useState(defaultOn);
  return (
    <button
      onClick={() => setOn(!on)}
      className={`relative w-10 h-5 rounded-full transition-colors ${on ? 'bg-blue-600' : 'bg-slate-200'}`}
    >
      <span className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${on ? 'translate-x-5' : ''}`} />
    </button>
  );
};

const settingsSections = [
  { id: 'workspace', label: 'Workspace', icon: <Shield className="w-4 h-4" /> },
  { id: 'profile', label: 'Profile', icon: <User className="w-4 h-4" /> },
  { id: 'notifications', label: 'Notifications', icon: <Bell className="w-4 h-4" /> },
  { id: 'security', label: 'Security', icon: <Key className="w-4 h-4" /> },
  { id: 'data', label: 'Data & Privacy', icon: <Database className="w-4 h-4" /> },
];

export default function SettingsPage() {
  const [activeSection, setActiveSection] = useState('workspace');
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="pt-14">
      <TopBar breadcrumb="Settings" />
      <div className="p-6">
        {/* Header */}
        <div className="mb-6">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-widest mb-1">CONFIGURATION</div>
          <h1 className="text-2xl font-bold text-slate-800">Settings</h1>
        </div>

        <div className="flex gap-6">
          {/* Nav */}
          <div className="w-52 flex-shrink-0">
            <nav className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
              {settingsSections.map(s => (
                <button
                  key={s.id}
                  onClick={() => setActiveSection(s.id)}
                  className={`w-full flex items-center gap-2.5 px-4 py-3 text-sm font-medium transition-colors border-b border-slate-100 last:border-0 ${
                    activeSection === s.id
                      ? 'bg-blue-50 text-blue-700 border-r-2 border-blue-600'
                      : 'text-slate-600 hover:bg-slate-50'
                  }`}
                >
                  <span className={activeSection === s.id ? 'text-blue-600' : 'text-slate-400'}>{s.icon}</span>
                  {s.label}
                </button>
              ))}
            </nav>
          </div>

          {/* Content */}
          <div className="flex-1">
            {activeSection === 'workspace' && (
              <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
                <h2 className="text-base font-bold text-slate-800 mb-5">Workspace Settings</h2>
                <div>
                  <SettingRow label="Organization Name" description="The name of your workspace organization">
                    <input defaultValue="Acme Corporation" className="px-3 py-2 border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none focus:ring-1 focus:ring-blue-500 w-52" />
                  </SettingRow>
                  <SettingRow label="Demo Mode" description="Run analysis using pre-loaded realistic demo data without API keys">
                    <Toggle defaultOn={true} />
                  </SettingRow>
                  <SettingRow label="Analysis Engine" description="Enable AI-powered threat scoring engine">
                    <Toggle defaultOn={true} />
                  </SettingRow>
                  <SettingRow label="Auto-create Cases" description="Automatically create cases for emails scoring above 60/100">
                    <Toggle defaultOn={true} />
                  </SettingRow>
                  <SettingRow label="Risk Threshold Alert" description="Send alerts for emails above this risk score">
                    <select className="px-3 py-2 border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none">
                      <option>60/100 (Suspicious+)</option>
                      <option>80/100 (Critical only)</option>
                      <option>All emails</option>
                    </select>
                  </SettingRow>
                </div>
              </div>
            )}

            {activeSection === 'profile' && (
              <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
                <h2 className="text-base font-bold text-slate-800 mb-5">Profile Settings</h2>
                <div className="flex items-center gap-4 mb-6 pb-5 border-b border-slate-100">
                  <div className="w-16 h-16 bg-blue-600 rounded-2xl flex items-center justify-center text-white text-2xl font-bold">AM</div>
                  <div>
                    <div className="font-bold text-slate-800">Alex Morgan</div>
                    <div className="text-sm text-slate-500">Administrator · admin@acmecorp.com</div>
                    <button className="mt-2 text-xs text-blue-600 hover:text-blue-700 font-medium">Change avatar</button>
                  </div>
                </div>
                <SettingRow label="Display Name" description="Your name shown in the platform">
                  <input defaultValue="Alex Morgan" className="px-3 py-2 border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none focus:ring-1 focus:ring-blue-500 w-52" />
                </SettingRow>
                <SettingRow label="Role" description="Your access level in this workspace">
                  <select className="px-3 py-2 border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none">
                    <option>Administrator</option>
                    <option>Senior Analyst</option>
                    <option>Analyst</option>
                  </select>
                </SettingRow>
                <SettingRow label="Timezone" description="Your local timezone for timestamps">
                  <select className="px-3 py-2 border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none">
                    <option>Asia/Kolkata (IST)</option>
                    <option>America/New_York (EST)</option>
                    <option>UTC</option>
                  </select>
                </SettingRow>
              </div>
            )}

            {activeSection === 'notifications' && (
              <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
                <h2 className="text-base font-bold text-slate-800 mb-5">Notification Preferences</h2>
                <SettingRow label="Critical threat alerts" description="Get notified when emails score 81+ (Critical)">
                  <Toggle defaultOn={true} />
                </SettingRow>
                <SettingRow label="New case assigned" description="Get notified when a case is assigned to you">
                  <Toggle defaultOn={true} />
                </SettingRow>
                <SettingRow label="Case status updates" description="Get notified on case escalation or resolution">
                  <Toggle defaultOn={false} />
                </SettingRow>
                <SettingRow label="Weekly threat summary" description="Receive a weekly digest of detected threats">
                  <Toggle defaultOn={true} />
                </SettingRow>
                <SettingRow label="Report generation complete" description="Get notified when forensic reports are ready">
                  <Toggle defaultOn={true} />
                </SettingRow>
              </div>
            )}

            {activeSection === 'security' && (
              <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
                <h2 className="text-base font-bold text-slate-800 mb-5">Security Settings</h2>
                <SettingRow label="Two-Factor Authentication" description="Add an extra layer of security to your account">
                  <button className="px-4 py-2 bg-blue-600 text-white text-xs font-semibold rounded-lg hover:bg-blue-700 transition-colors">Enable 2FA</button>
                </SettingRow>
                <SettingRow label="Session Timeout" description="Auto-logout after inactivity">
                  <select className="px-3 py-2 border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none">
                    <option>30 minutes</option>
                    <option>1 hour</option>
                    <option>4 hours</option>
                    <option>8 hours</option>
                  </select>
                </SettingRow>
                <SettingRow label="IP Allowlist" description="Restrict access to specific IP ranges">
                  <Toggle defaultOn={false} />
                </SettingRow>
                <SettingRow label="Audit all actions" description="Log every analyst action for compliance">
                  <Toggle defaultOn={true} />
                </SettingRow>
                <SettingRow label="Evidence hashing" description="Auto-hash all uploaded email evidence">
                  <Toggle defaultOn={true} />
                </SettingRow>
              </div>
            )}

            {activeSection === 'data' && (
              <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
                <h2 className="text-base font-bold text-slate-800 mb-5">Data & Privacy</h2>
                <SettingRow label="Data Retention Period" description="How long case data is retained before deletion">
                  <select className="px-3 py-2 border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none">
                    <option>90 days</option>
                    <option>180 days</option>
                    <option>1 year</option>
                    <option>Indefinitely</option>
                  </select>
                </SettingRow>
                <SettingRow label="Mask Email Bodies" description="Mask sensitive email content in reports by default">
                  <Toggle defaultOn={false} />
                </SettingRow>
                <SettingRow label="PII Anonymization" description="Automatically anonymize personal identifiable info">
                  <Toggle defaultOn={false} />
                </SettingRow>
                <SettingRow label="Share Threat Intelligence" description="Contribute IOCs to community threat feeds (anonymized)">
                  <Toggle defaultOn={false} />
                </SettingRow>

                <div className="mt-5 pt-5 border-t border-slate-100">
                  <h3 className="text-sm font-semibold text-red-600 mb-3">Danger Zone</h3>
                  <button className="px-4 py-2 border border-red-200 text-red-600 text-sm font-medium rounded-lg hover:bg-red-50 transition-colors">
                    Delete all case data
                  </button>
                </div>
              </div>
            )}

            {/* Save button */}
            <div className="mt-4 flex justify-end">
              <button
                onClick={handleSave}
                className={`flex items-center gap-2 px-6 py-2.5 rounded-xl font-semibold text-sm transition-all ${
                  saved ? 'bg-emerald-600 text-white' : 'bg-blue-600 hover:bg-blue-700 text-white'
                }`}
              >
                {saved ? <><Check className="w-4 h-4" /> Saved!</> : <><Save className="w-4 h-4" /> Save changes</>}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
