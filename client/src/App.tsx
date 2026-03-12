
import React, { useEffect, useState, lazy, Suspense, useCallback, memo } from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { NotificationProvider } from './context/NotificationContext';
import { Layout } from './components/Layout';
import { Home } from './pages/Home';
import { UserRole, OrderStatus } from './types';
import { getAllOrders, getAllCustomOrders, getAdminContact } from './services/storage';
import { Package, ShoppingBag, Clock, FileText, Phone, X, ZoomIn } from 'lucide-react';

// PERF: Lazy-load heavy route components – they aren't needed on initial page load.
// This splits them into separate JS chunks that load on-demand, reducing initial bundle size.
const Login = lazy(() => import('./pages/Login').then(m => ({ default: m.Login })));
const Signup = lazy(() => import('./pages/Signup').then(m => ({ default: m.Signup })));
const AdminDashboard = lazy(() => import('./pages/AdminDashboard').then(m => ({ default: m.AdminDashboard })));
const CustomOrderForm = lazy(() => import('./pages/CustomOrder').then(m => ({ default: m.CustomOrderForm })));

// PERF: Lightweight loading spinner for Suspense fallbacks
const PageSpinner = () => (
  <div className="flex items-center justify-center py-24">
    <div className="animate-spin h-8 w-8 border-4 border-emerald-500 border-t-transparent rounded-full" />
  </div>
);

// PERF: Memoize to avoid re-rendering on every parent render (purely display-driven)
const StatusBadge = memo(({ status }: { status: OrderStatus }) => {
  const colors = {
    [OrderStatus.PENDING]: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    [OrderStatus.CONFIRMED]: 'bg-blue-100 text-blue-800 border-blue-200',
    [OrderStatus.COMPLETED]: 'bg-green-100 text-green-800 border-green-200',
    [OrderStatus.CANCELLED]: 'bg-red-100 text-red-800 border-red-200',
  };
  return <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${colors[status]}`}>{status}</span>;
});
StatusBadge.displayName = 'StatusBadge';

const History: React.FC = () => {
  const { user } = useAuth();
  const [orders, setOrders] = React.useState<any[]>([]);
  const [customOrders, setCustomOrders] = React.useState<any[]>([]);
  const [adminPhone, setAdminPhone] = React.useState('');
  const [lightboxImage, setLightboxImage] = React.useState<string | null>(null);

  // PERF: Use server-side filtered endpoint directly (no more fetching all orders then filtering in JS).
  // This eliminates the N+1 anti-pattern: previously the client downloaded every order from the DB
  // then ran .filter() in the browser, wasting bandwidth and CPU.
  const load = useCallback(async () => {
    if (user) {
      try {
        const [uOrders, uCustom, contact] = await Promise.all([
          getAllOrders(),       // Server now filters by user_id automatically for non-admins
          getAllCustomOrders(), // Same server-side filtering
          getAdminContact(),
        ]);

        setOrders(uOrders);
        setCustomOrders(uCustom);
        setAdminPhone(contact);
      } catch (e) {
        console.error("Failed to load history data");
      }
    }
  }, [user]);

  React.useEffect(() => {
    load();
    // PERF: Increased polling interval from 10s to 30s – reduces server load by 3x
    // while still providing reasonably fresh data for order tracking
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [user, load]);

  const getTimeStatus = (deadline: string) => {
    const now = new Date();
    const target = new Date(deadline);
    const diff = target.getTime() - now.getTime();
    if (diff <= 0) return "Arriving shortly...";
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    return `ETA: ${hours}h ${mins}m`;
  };

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-10">
      {/* Emerald Header */}
      <div className="bg-gradient-to-r from-emerald-500 to-green-600 rounded-3xl px-6 sm:px-10 py-8 text-white relative overflow-hidden">
        <div className="absolute top-0 right-0 w-40 h-40 bg-white/10 rounded-full -translate-y-12 translate-x-12" />
        <div className="absolute bottom-0 left-0 w-28 h-28 bg-white/10 rounded-full translate-y-10 -translate-x-8" />
        <div className="relative flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-12 w-12 bg-white/20 rounded-2xl flex items-center justify-center">
              <Package className="h-7 w-7 text-white" />
            </div>
            <div>
              <h1 className="text-2xl sm:text-3xl font-black tracking-tight">Your Activity</h1>
              <p className="text-emerald-100 text-sm font-medium mt-0.5">Track your orders &amp; requests</p>
            </div>
          </div>
          {adminPhone && (
            <div className="bg-white/20 backdrop-blur-sm text-white px-4 py-2.5 rounded-2xl text-sm font-bold flex items-center gap-2 border border-white/20 self-start sm:self-auto">
              <Phone className="h-4 w-4" />
              Store Support: {adminPhone}
            </div>
          )}
        </div>
      </div>

      <section>
        <h2 className="text-lg font-black mb-5 flex items-center gap-2 text-gray-800">
          <ShoppingBag className="h-5 w-5 text-emerald-500" /> Product Orders
        </h2>
        {orders.length === 0 ? (
          <div className="text-center py-12 bg-emerald-50 rounded-2xl border border-dashed border-emerald-200">
            <ShoppingBag className="h-10 w-10 text-emerald-300 mx-auto mb-3" />
            <p className="text-gray-500 font-medium">You haven't placed any orders yet.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {orders.map(order => (
              <div key={order.id} className="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden hover:shadow-md hover:border-emerald-200 transition-all flex flex-col">
                <div className="flex h-full">
                  <div className="w-28 sm:w-32 bg-emerald-50 flex-shrink-0">
                    <img src={order.productImage || 'https://via.placeholder.com/150'} alt="" className="w-full h-full object-cover" />
                  </div>
                  <div className="p-4 flex flex-col justify-between flex-grow">
                    <div>
                      <div className="flex justify-between items-start mb-1 gap-2">
                        <h3 className="font-black text-gray-900 line-clamp-1 text-sm" title={order.productTitle}>{order.productTitle}</h3>
                        <StatusBadge status={order.status} />
                      </div>
                      <p className="text-xs text-gray-400 mb-2 font-bold uppercase tracking-wider">Order #{order.id}</p>
                      {order.status === OrderStatus.CONFIRMED && (
                        <p className="text-xs font-bold text-emerald-600 flex items-center gap-1 mt-1">
                          <Clock className="h-3 w-3" /> {getTimeStatus(order.expectedDeliveryAt)}
                        </p>
                      )}
                      {order.description && <p className="text-xs text-gray-500 bg-gray-50 p-2 rounded-lg mt-2 italic line-clamp-2">"{order.description}"</p>}
                    </div>
                    <div className="mt-2 pt-2 border-t flex justify-between items-end">
                      <div className="text-xs text-gray-500 font-bold">Qty: {order.quantity}</div>
                      <div className="text-base font-black text-emerald-600">₹{order.totalPrice}</div>
                    </div>
                  </div>
                </div>
                <div className="bg-emerald-50/50 px-4 py-2 border-t border-emerald-100 text-[10px] text-gray-400 flex justify-between items-center">
                  <span className="uppercase font-bold tracking-wider">Ordered: {new Date(order.createdAt).toLocaleDateString()}</span>
                  <span className="flex items-center gap-1 text-emerald-500 font-bold"><Phone className="h-3 w-3" /> {adminPhone}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section>
        <h2 className="text-lg font-black mb-5 flex items-center gap-2 text-gray-800">
          <FileText className="h-5 w-5 text-emerald-500" /> Custom Requests
        </h2>
        {customOrders.length === 0 ? (
          <div className="text-center py-12 bg-emerald-50 rounded-2xl border border-dashed border-emerald-200">
            <FileText className="h-10 w-10 text-emerald-300 mx-auto mb-3" />
            <p className="text-gray-500 font-medium">No custom requests found.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {customOrders.map(o => (
              <div key={o.id} className="bg-white rounded-2xl shadow-sm border-l-4 border-l-emerald-500 border border-gray-100 p-5 hover:shadow-md hover:border-l-emerald-600 transition-all flex flex-col">
                <div className="flex justify-between items-start mb-3 gap-2">
                  <div>
                    <h3 className="font-black text-gray-900 text-sm">Request #{o.id}</h3>
                    <div className="text-[10px] text-gray-400 flex items-center gap-1 mt-1 font-bold uppercase tracking-wider">
                      <Clock className="h-3 w-3" /> {new Date(o.createdAt).toLocaleDateString()}
                    </div>
                  </div>
                  <StatusBadge status={o.status} />
                </div>

                <p className="text-gray-600 text-sm mb-4 line-clamp-3 bg-gray-50 p-3 rounded-xl flex-grow">
                  {o.description}
                </p>

                <div className="text-xs text-emerald-600 mb-3 font-bold">
                  <p>Required by: {o.requestedDate} at {o.requestedTime}</p>
                  {o.status === OrderStatus.CONFIRMED && (
                    <p className="flex items-center gap-1 mt-1">
                      <Clock className="h-3 w-3" /> {getTimeStatus(o.deadlineAt)}
                    </p>
                  )}
                </div>

                {o.images && o.images.length > 0 && (
                  <div className="flex -space-x-2 overflow-hidden py-1 mb-3">
                    {o.images.map((img: string, i: number) => (
                      <div key={i} className="relative group cursor-pointer" onClick={() => setLightboxImage(img)}>
                        <img className="inline-block h-8 w-8 rounded-full ring-2 ring-white object-cover shadow-sm transition-transform hover:scale-110 hover:z-10" src={img} alt="" />
                      </div>
                    ))}
                  </div>
                )}

                <div className="pt-3 border-t mt-auto text-[10px] flex justify-end">
                  <span className="flex items-center gap-1 text-emerald-500 font-bold uppercase tracking-widest"><Phone className="h-3 w-3" /> Contact Shop: {adminPhone}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Lightbox for Custom Order Images */}
      {lightboxImage && (
        <div className="fixed inset-0 bg-black/90 z-50 flex items-center justify-center p-4 animate-fade-in" onClick={() => setLightboxImage(null)}>
          <button className="absolute top-4 right-4 text-white hover:text-gray-300">
            <X className="h-8 w-8" />
          </button>
          <img src={lightboxImage} alt="Full size" className="max-w-full max-h-[90vh] object-contain rounded-lg shadow-2xl animate-scale-up" onClick={(e) => e.stopPropagation()} />
        </div>
      )}
    </div>
  );
};

// PERF: Memoized to avoid re-evaluation on every parent render
const ProtectedRoute = memo<{ children: React.ReactNode; adminOnly?: boolean; customerOnly?: boolean }>(({ children, adminOnly = false, customerOnly = false }) => {
  const { isAuthenticated, user } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" />;
  if (adminOnly && user?.role !== UserRole.ADMIN) return <Navigate to="/" />;
  if (customerOnly && user?.role === UserRole.ADMIN) return <Navigate to="/admin" />;
  return <>{children}</>;
});
ProtectedRoute.displayName = 'ProtectedRoute';

const App: React.FC = () => {
  return (
    <NotificationProvider>
      <AuthProvider>
        <HashRouter>
          <Layout>
            {/* PERF: Suspense wraps lazy-loaded routes with a lightweight spinner */}
            <Suspense fallback={<PageSpinner />}>
              <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/login" element={<Login />} />
                <Route path="/signup" element={<Signup />} />
                <Route path="/custom-order" element={<ProtectedRoute customerOnly><CustomOrderForm /></ProtectedRoute>} />
                <Route path="/history" element={<ProtectedRoute customerOnly><History /></ProtectedRoute>} />
                <Route path="/admin" element={<ProtectedRoute adminOnly><AdminDashboard /></ProtectedRoute>} />
              </Routes>
            </Suspense>
          </Layout>
        </HashRouter>
      </AuthProvider>
    </NotificationProvider>
  );
};

export default App;
