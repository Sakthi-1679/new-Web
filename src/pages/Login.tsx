
import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNotification } from '../context/NotificationContext';
import { login, googleLogin } from '../services/storage';
import { useNavigate, Link } from 'react-router-dom';
import { UserRole } from '../types';
import { Eye, EyeOff, Flower2, Sparkles } from 'lucide-react';

export const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const { loginUser } = useAuth();
  const { notify } = useNotification();
  const navigate = useNavigate();
  const googleBtnRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const initGoogle = () => {
      if ((window as any).google && googleBtnRef.current) {
        // SECURITY: Google client ID loaded from environment variable (not hardcoded)
        const googleClientId = (import.meta as any).env?.VITE_GOOGLE_CLIENT_ID || '';
        (window as any).google.accounts.id.initialize({
          client_id: googleClientId,
          callback: handleGoogleResponse,
        });
        (window as any).google.accounts.id.renderButton(googleBtnRef.current, {
          theme: 'outline', size: 'large', width: '100%', text: 'signin_with',
        });
      }
    };
    initGoogle();
    const timer = setTimeout(initGoogle, 500);
    return () => clearTimeout(timer);
  }, []);

  const handleGoogleResponse = async (response: any) => {
    try {
      const data = await googleLogin(response.credential);
      if (data && data.user) {
        loginUser(data);
        notify(`Welcome, ${data.user.name}!`, 'success');
        if (data.user.role === UserRole.ADMIN) navigate('/admin');
        else navigate('/');
      }
    } catch (err: any) {
      notify(err.message || 'Google sign-in failed', 'error');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await login(email.trim(), password.trim());
      if (response && response.user) {
        loginUser(response);
        notify(`Welcome back, ${response.user.name}!`, "success");
        if (response.user.role === UserRole.ADMIN) {
          navigate('/admin');
        } else {
          navigate('/');
        }
      }
    } catch (err: any) {
      notify(err.message || 'Invalid credentials. Please verify your email and password.', "error");
    }
  };

  return (
    <div className="min-h-[calc(100vh-9rem)] flex">
      {/* Left Panel — Violet/Purple Theme */}
      <div className="hidden lg:flex lg:w-5/12 bg-gradient-to-br from-violet-600 via-violet-700 to-purple-800 flex-col justify-between p-12 relative overflow-hidden">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-16 right-8 w-56 h-56 bg-violet-400/20 rounded-full blur-3xl"></div>
          <div className="absolute bottom-16 left-8 w-72 h-72 bg-purple-500/20 rounded-full blur-3xl"></div>
        </div>
        <Link to="/" className="relative z-10 flex items-center gap-2.5">
          <div className="bg-white/20 backdrop-blur p-2.5 rounded-xl border border-white/30">
            <Flower2 className="h-6 w-6 text-white" />
          </div>
          <span className="text-white font-black text-xl tracking-tight">VKM Flowers</span>
        </Link>
        <div className="relative z-10 py-8">
          <div className="inline-flex items-center gap-2 bg-white/10 border border-white/20 text-violet-100 text-xs font-semibold px-3 py-1.5 rounded-full mb-5">
            <Sparkles className="h-3.5 w-3.5" /> Welcome Back
          </div>
          <h2 className="text-4xl font-black text-white leading-tight mb-3">
            Sign in to your<br /><span className="text-violet-200">VKM account</span>
          </h2>
          <p className="text-violet-200 font-medium leading-relaxed mb-8">
            Access your orders, track deliveries, and explore our fresh floral collection.
          </p>
          <div className="space-y-3">
            {['Fresh flowers from Kanchipuram', 'Same-day delivery available', 'Custom arrangements made to order'].map((text, i) => (
              <div key={i} className="flex items-center gap-3 text-white/80 text-sm font-medium">
                <div className="w-5 h-5 bg-white/20 rounded-full flex items-center justify-center flex-shrink-0">
                  <svg className="w-3 h-3 text-white" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                </div>
                {text}
              </div>
            ))}
          </div>
        </div>
        <div className="relative z-10 text-violet-300 text-xs font-medium">
          &copy; {new Date().getFullYear()} VKM Flower Shop, Kanchipuram
        </div>
      </div>

      {/* Right Panel — Form */}
      <div className="flex-1 flex items-center justify-center p-6 md:p-12 bg-gray-50">
        <div className="w-full max-w-md">
          <div className="mb-8">
            <div className="lg:hidden flex items-center gap-2 mb-6">
              <div className="bg-violet-600 p-2 rounded-xl">
                <Flower2 className="h-5 w-5 text-white" />
              </div>
              <span className="font-black text-gray-900">VKM Flowers</span>
            </div>
            <h2 className="text-3xl font-black text-gray-900 tracking-tight mb-1">Log in</h2>
            <p className="text-gray-500 font-medium">Enter your credentials to continue</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="text-xs font-bold text-gray-600 uppercase tracking-widest block mb-2">Email Address</label>
              <input
                type="email"
                required
                className="w-full bg-white border-2 border-gray-200 rounded-2xl p-4 font-medium text-gray-900 placeholder-gray-300 focus:outline-none focus:border-violet-400 focus:ring-4 focus:ring-violet-50 transition-all"
                placeholder="you@example.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
              />
            </div>
            <div>
              <label className="text-xs font-bold text-gray-600 uppercase tracking-widest block mb-2">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  className="w-full bg-white border-2 border-gray-200 rounded-2xl p-4 pr-12 font-medium text-gray-900 placeholder-gray-300 focus:outline-none focus:border-violet-400 focus:ring-4 focus:ring-violet-50 transition-all"
                  placeholder="••••••••"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(v => !v)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 hover:text-violet-600 transition-colors"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                </button>
              </div>
            </div>
            <button type="submit" className="w-full bg-gradient-to-r from-violet-600 to-purple-600 text-white py-4 rounded-2xl font-black uppercase tracking-widest shadow-xl shadow-violet-100 hover:from-violet-700 hover:to-purple-700 hover:-translate-y-0.5 transition-all active:scale-[0.98] text-sm">
              Sign In
            </button>
          </form>

          <div className="flex items-center my-6">
            <div className="flex-1 h-px bg-gray-200" />
            <span className="px-4 text-xs font-bold text-gray-400 uppercase tracking-widest">or</span>
            <div className="flex-1 h-px bg-gray-200" />
          </div>
          <div ref={googleBtnRef} className="flex justify-center" />

          <div className="text-center mt-6">
            <span className="text-gray-500 text-sm font-medium">Don't have an account? </span>
            <Link to="/signup" className="text-violet-600 hover:text-violet-700 font-bold text-sm underline decoration-2 underline-offset-4 transition-colors">Create one free</Link>
          </div>

          <div className="mt-8 pt-6 border-t border-gray-100 text-center">
            <p className="text-[11px] text-gray-400 font-medium tracking-wide">
              Securely managed by VKM Flower Shop Systems
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};


