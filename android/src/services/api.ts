import AsyncStorage from '@react-native-async-storage/async-storage';
import { User, Product, Order, CustomOrder, OrderStatus, AuthResponse } from '../types';

// ─────────────────────────────────────────────────────────────
// CONFIG — update API_URL after deploying to Render
// For local Android emulator testing: http://10.0.2.2:3001/api
// For local physical device testing:  http://YOUR_LAN_IP:3001/api
// For production (Render): https://new-web-2o8n.onrender.com/api
// ─────────────────────────────────────────────────────────────
export const API_URL = 'https://new-web-2o8n.onrender.com/api';

const SESSION_KEY = 'vkm_session';

// ─── Session ────────────────────────────────────────────────
export const saveSession = async (data: AuthResponse) => {
  await AsyncStorage.setItem(SESSION_KEY, JSON.stringify(data));
};
export const getSession = async (): Promise<AuthResponse | null> => {
  try {
    const raw = await AsyncStorage.getItem(SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
};
export const clearSession = async () => AsyncStorage.removeItem(SESSION_KEY);

// ─── Core Request ────────────────────────────────────────────
const request = async (endpoint: string, method = 'GET', body?: any) => {
  const session = await getSession();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (session?.token) headers['Authorization'] = `Bearer ${session.token}`;

  const res = await fetch(`${API_URL}${endpoint}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const ct = res.headers.get('content-type') ?? '';
  if (ct.includes('application/json')) {
    const data = await res.json();
    if (!res.ok) throw new Error(data.error ?? `Error ${res.status}`);
    return data;
  }
  const text = await res.text();
  throw new Error(`Non-JSON ${res.status}: ${text.slice(0, 100)}`);
};

// ─── Auth ────────────────────────────────────────────────────
export const login = async (email: string, password: string): Promise<AuthResponse> => {
  const data = await request('/login', 'POST', { email, password });
  await saveSession(data);
  return data;
};

export const register = async (userData: {
  name: string; email: string; password: string; phone: string; city: string; area: string;
}): Promise<AuthResponse> => {
  const data = await request('/register', 'POST', userData);
  await saveSession(data);
  return data;
};

export const logout = () => clearSession();

// ─── Push Token ─────────────────────────────────────────────
export const savePushToken = async (token: string): Promise<void> => {
  await request('/push-token', 'POST', { token });
};

// ─── Admin Contact ───────────────────────────────────────────
export const getAdminContact = async (): Promise<string> => {
  try { const d = await request('/settings/contact'); return d.phone || '9999999999'; }
  catch { return '9999999999'; }
};
export const updateAdminContact = async (phone: string) =>
  request('/settings/contact', 'PUT', { phone });

// ─── Products ───────────────────────────────────────────────
export const getProducts = async (): Promise<Product[]> => {
  try { return await request('/products'); } catch { return []; }
};
export const addProduct = async (p: Omit<Product, 'id'>): Promise<Product> =>
  request('/products', 'POST', p);
export const updateProduct = async (id: string, p: Partial<Product>): Promise<Product> =>
  request(`/products/${id}`, 'PUT', p);
export const deleteProduct = async (id: string) => request(`/products/${id}`, 'DELETE');

// ─── Orders ─────────────────────────────────────────────────
export const getAllOrders = async (): Promise<Order[]> => {
  try { return await request('/orders'); } catch { return []; }
};
export const placeOrder = async (data: {
  userId: string; productId: string; quantity: number; description?: string;
}): Promise<Order> => request('/orders', 'POST', data);

export const updateOrderStatus = async (
  type: 'normal' | 'custom', id: string, status: OrderStatus
) => {
  const ep = type === 'normal' ? `/orders/${id}/status` : `/custom-orders/${id}/status`;
  return request(ep, 'PUT', { status });
};
export const deleteOrder = async (id: string) => request(`/orders/${id}`, 'DELETE');

// ─── Custom Orders ───────────────────────────────────────────
export const getAllCustomOrders = async (): Promise<CustomOrder[]> => {
  try { return await request('/custom-orders'); } catch { return []; }
};
export const placeCustomOrder = async (data: {
  userId: string; description: string; requestedDate: string; requestedTime: string;
  contactName: string; contactPhone: string; images: string[];
}): Promise<CustomOrder> => request('/custom-orders', 'POST', data);
export const deleteCustomOrder = async (id: string) => request(`/custom-orders/${id}`, 'DELETE');

// ─── User Helpers ────────────────────────────────────────────
export const getUserOrders = async (userId: string): Promise<Order[]> => {
  const all = await getAllOrders();
  return all.filter(o => o.userId === userId);
};
export const getUserCustomOrders = async (userId: string): Promise<CustomOrder[]> => {
  const all = await getAllCustomOrders();
  return all.filter(o => o.userId === userId);
};
