'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Shield, Mail, Eye, EyeOff, AlertTriangle, Zap } from 'lucide-react';
import { authAPI } from '@/lib/api';

const DEMO_CREDENTIALS = [
  { email: 'admin@mailtrace.ai', password: 'Admin@1234', role: 'Administrator' },
  { email: 'senior@mailtrace.ai', password: 'Senior@1234', role: 'Senior Analyst' },
  { email: 'analyst@mailtrace.ai', password: 'Analyst@1234', role: 'Analyst' },
];

// Fallback mock users if backend is unavailable
const MOCK_USERS = [
  { email: 'admin@acmecorp.com', password: 'admin123', name: 'Alex Morgan', role: 'Administrator', initials: 'AM' },
  { email: 'analyst@acmecorp.com', password: 'analyst123', name: 'Sarah Kim', role: 'Senior Analyst', initials: 'SK' },
  { email: 'raj@acmecorp.com', password: 'raj123', name: 'Raj Kumar', role: 'Analyst', initials: 'RK' },
];

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('admin@mailtrace.ai');
  const [password, setPassword] = useState('Admin@1234');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      // Try real backend first
      const result = await authAPI.login(email, password);
      if (result.access_token) {
        localStorage.setItem('mt_token', result.access_token);
        localStorage.setItem('mt_user', JSON.stringify({
          ...result.user,
          initials: result.user.name.split(' ').map((n: string) => n[0]).join('').toUpperCase(),
        }));
        router.push('/overview');
        return;
      }
    } catch {
      // Backend unavailable — fallback to mock auth
      const mockUser = MOCK_USERS.find(u => u.email === email && u.password === password);
      if (mockUser) {
        localStorage.setItem('mt_user', JSON.stringify(mockUser));
        router.push('/overview');
        return;
      }
      setError('Invalid credentials. Use admin@mailtrace.ai / Admin@1234');
      setLoading(false);
    }
  };

  const handleQuickLogin = (cred: typeof DEMO_CREDENTIALS[0]) => {
    setEmail(cred.email);
    setPassword(cred.password);
  };

  return (
    <div className="min-h-screen bg-[#0f172a] flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background grid */}
      <div className="absolute inset-0 opacity-5" style={{
        backgroundImage: 'linear-gradient(rgba(59,130,246,0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,0.5) 1px, transparent 1px)',
        backgroundSize: '50px 50px'
      }} />
      {/* Gradient orbs */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-600 opacity-10 rounded-full blur-3xl" />
      <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-indigo-600 opacity-10 rounded-full blur-3xl" />

      <div className="w-full max-w-md relative z-10">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-3 mb-4">
            <div className="w-12 h-12 bg-blue-600 rounded-xl flex items-center justify-center relative">
              <Shield className="w-6 h-6 text-white" />
              <div className="absolute -top-1 -right-1 w-4 h-4 bg-white rounded-full flex items-center justify-center">
                <Mail className="w-2.5 h-2.5 text-blue-600" />
              </div>
            </div>
            <div className="text-left">
              <div className="text-2xl font-bold text-white">MailTrace <span className="text-blue-400">AI</span></div>
              <div className="text-xs text-slate-400 font-medium">Email Threat Intelligence</div>
            </div>
          </div>
          <p className="text-slate-400 text-sm">Sign in to your security workspace</p>
        </div>

        {/* Login card */}
        <div className="bg-[#1e293b] border border-slate-700 rounded-2xl p-8 shadow-2xl">
          <form onSubmit={handleLogin} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Email address</label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="analyst@acmecorp.com"
                className="w-full px-4 py-3 bg-[#0f172a] border border-slate-600 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full px-4 py-3 bg-[#0f172a] border border-slate-600 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors pr-12"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-300 transition-colors"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {error && (
              <div className="flex items-start gap-2 bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3">
                <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
                <p className="text-red-400 text-sm">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 disabled:opacity-60 text-white font-semibold rounded-xl transition-all duration-200 flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Authenticating...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4" />
                  Sign in to workspace
                </>
              )}
            </button>
          </form>

          {/* Quick login */}
          <div className="mt-6 pt-6 border-t border-slate-700">
            <p className="text-xs text-slate-500 mb-3 uppercase tracking-wider font-medium">Quick access — Demo accounts</p>
            <div className="space-y-2">
              {DEMO_CREDENTIALS.map(cred => (
                <button
                  key={cred.email}
                  onClick={() => handleQuickLogin(cred)}
                  className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-slate-700/50 transition-colors text-left group"
                >
                  <div className="w-8 h-8 bg-blue-600/20 border border-blue-500/30 rounded-full flex items-center justify-center text-blue-400 text-xs font-bold group-hover:bg-blue-600/30 transition-colors">
                    {cred.role.split(' ').map(w => w[0]).join('')}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-slate-300 text-sm font-medium truncate">{cred.email}</div>
                    <div className="text-slate-500 text-xs">{cred.role} · {cred.password}</div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>

        <p className="text-center text-xs text-slate-600 mt-4">
          MailTrace AI — SIH 2026 Prototype · For authorized use only
        </p>
      </div>
    </div>
  );
}

                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-slate-300 group-hover:text-white transition-colors">{user.name}</div>
                    <div className="text-xs text-slate-500">{user.role} — {user.email}</div>
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>

        <p className="text-center text-xs text-slate-600 mt-6">
          MailTrace AI v2.1 · SIH 2026 Prototype · All analysis data is simulated
        </p>
      </div>
    </div>
  );
}
