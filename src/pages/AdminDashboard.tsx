
import React, { useState, useEffect } from 'react';
import { Product, Order, OrderStatus, User, CustomOrder } from '../types';
import { 
  getProducts, addProduct, updateProduct, deleteProduct, 
  getAllOrders, updateOrderStatus,
  deleteOrder,
  getAdminContact, updateAdminContact,
  getUserById,
  getAllCustomOrders, deleteCustomOrder
} from '../services/storage';
import { useNotification } from '../context/NotificationContext';
import { Plus, Trash2, Clock, Upload, X, Bell, Phone, User as UserIcon, MapPin, FileText, CheckCircle2, AlertCircle, ShoppingBag, ListChecks, Sparkles, Loader2, FileDigit, Pencil, Ban } from 'lucide-react';

export const AdminDashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'products' | 'orders' | 'custom'>('products');
  const [products, setProducts] = useState<Product[]>([]);
  const [orders, setOrders] = useState<Order[]>([]);
  const [customOrders, setCustomOrders] = useState<CustomOrder[]>([]);
  const [isAddingProduct, setIsAddingProduct] = useState(false);
  const [editingProduct, setEditingProduct] = useState<Product | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [pendingOrdersCount, setPendingOrdersCount] = useState(0);
  const [pendingCustomCount, setPendingCustomCount] = useState(0);
  const [adminPhone, setAdminPhone] = useState('');

  const { notify, confirm } = useNotification();
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [newProd, setNewProd] = useState<Partial<Product>>({ title: '', price: undefined, durationHours: undefined, description: '', images: [] });

  const loadData = async (includePhone = false) => {
    try {
        const promises: Promise<any>[] = [
            getProducts(),
            getAllOrders(),
            getAllCustomOrders(),
        ];
        if (includePhone) promises.push(getAdminContact());

        const results = await Promise.all(promises);
        const [loadedProducts, loadedOrders, loadedCustomOrders] = results;

        setProducts(loadedProducts);
        setOrders(loadedOrders);
        setCustomOrders(loadedCustomOrders);
        if (includePhone) setAdminPhone(results[3]);

        setPendingOrdersCount(loadedOrders.filter((o: any) => o.status === OrderStatus.PENDING).length);
        setPendingCustomCount(loadedCustomOrders.filter((o: any) => o.status === OrderStatus.PENDING).length);
    } catch (error) {
        console.error("Error loading admin data:", error);
    }
  };

  useEffect(() => {
    loadData(true); // load phone only on first mount
    const interval = setInterval(() => loadData(false), 10000); // poll orders/products, NOT phone
    return () => clearInterval(interval);
  }, []);

  const handleUpdatePhone = async () => {
    if (!/^\d{10}$/.test(adminPhone)) {
        notify('Please enter a valid 10-digit phone number.', 'error');
        return;
    }
    try {
        await updateAdminContact(adminPhone);
        notify('Store contact number updated!', 'success');
    } catch (err) {
        notify('Failed to update contact number', 'error');
    }
  };

  const fileToBase64 = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.readAsDataURL(file);
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = error => reject(error);
    });
  };

  const handleSaveProduct = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!newProd.title || newProd.price === undefined || newProd.durationHours === undefined) {
      notify("Please fill in all required fields.", "error");
      return;
    }

    setIsSubmitting(true);
    try {
      const productData = {
        title: newProd.title,
        description: newProd.description || '',
        price: Number(newProd.price),
        durationHours: Number(newProd.durationHours),
        images: newProd.images && newProd.images.length > 0 
          ? newProd.images 
          : ['https://images.unsplash.com/photo-1522673607200-164883524354?auto=format&fit=crop&q=80&w=800']
      };
      
      if (editingProduct) {
        await updateProduct(editingProduct.id, productData);
        notify("Product updated successfully!", "success");
      } else {
        await addProduct(productData as Product);
        notify("Product added to catalog!", "success");
      }
      
      resetForm();
      await loadData();
    } catch (err: any) {
      notify(`Error: ${err.message}`, "error");
    } finally {
      setIsSubmitting(false);
    }
  };

  const resetForm = () => {
    setIsAddingProduct(false);
    setEditingProduct(null);
    setNewProd({ title: '', price: undefined, durationHours: undefined, description: '', images: [] });
  };

  const startEditProduct = (product: Product) => {
    setEditingProduct(product);
    setNewProd({ ...product });
    setIsAddingProduct(true);
    // Scroll to top to see form
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleImageUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const files: File[] = Array.from(e.target.files);
      try {
        const base64Images = await Promise.all(files.map(file => fileToBase64(file)));
        setNewProd(prev => ({ ...prev, images: [...(prev.images || []), ...base64Images] }));
      } catch (err) {
        notify("Failed to process images.", "error");
      }
    }
  };

  const removeNewImage = (index: number) => {
    setNewProd(prev => ({
      ...prev,
      images: prev.images?.filter((_, i) => i !== index)
    }));
  };

  const handleDeleteProduct = (e: React.MouseEvent, id: string) => {
    e.preventDefault();
    e.stopPropagation(); 
    confirm(
      "Delete Product?",
      "This item will be permanently removed from the catalog. This cannot be undone.",
      async () => {
        try {
          await deleteProduct(id);
          await loadData();
          notify("Product deleted.", "success");
        } catch (err: any) {
          notify(`Failed: ${err.message}`, "error");
        }
      }
    );
  };

  const handleStatusUpdate = async (type: 'normal' | 'custom', id: string, status: OrderStatus) => {
    try {
        await updateOrderStatus(type, id, status);
        await loadData();
        notify(`Order status updated to ${status}.`, "success");
    } catch (err) {
        notify('Failed to update status', 'error');
    }
  };

  const handleViewCustomer = async (userId: string) => {
    const user = await getUserById(userId);
    if (user) setSelectedUser(user);
    else notify("User details not found.", "error");
  };

  const getTimeRemaining = (deadline: string) => {
    const now = new Date();
    const target = new Date(deadline);
    const diff = target.getTime() - now.getTime();
    if (diff <= 0) return { label: 'Overdue!', color: 'text-red-600 font-bold' };
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    return { label: `${hours}h ${minutes}m left`, color: 'text-indigo-600' };
  };

  const sortActive = (a: any, b: any) => {
    const deadlineA = new Date(a.expectedDeliveryAt || a.deadlineAt).getTime();
    const deadlineB = new Date(b.expectedDeliveryAt || b.deadlineAt).getTime();
    return deadlineA - deadlineB;
  };

  let filteredPending: any[] = [];
  let filteredActive: any[] = [];
  let filteredHistory: any[] = [];

  if (activeTab === 'orders') {
    const data = orders.map(o => ({ ...o, type: 'normal' }));
    filteredPending = data.filter(o => o.status === OrderStatus.PENDING);
    filteredActive = data.filter(o => o.status === OrderStatus.CONFIRMED).sort(sortActive);
    filteredHistory = data.filter(o => o.status === OrderStatus.COMPLETED || o.status === OrderStatus.CANCELLED);
  } else if (activeTab === 'custom') {
    const data = customOrders.map(o => ({ ...o, type: 'custom' }));
    filteredPending = data.filter(o => o.status === OrderStatus.PENDING);
    filteredActive = data.filter(o => o.status === OrderStatus.CONFIRMED).sort(sortActive);
    filteredHistory = data.filter(o => o.status === OrderStatus.COMPLETED || o.status === OrderStatus.CANCELLED);
  }

  const StatusBadge = ({ status }: { status: OrderStatus }) => {
    const colors = {
      [OrderStatus.PENDING]: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
      [OrderStatus.CONFIRMED]: 'bg-teal-500/10 text-teal-400 border-teal-500/30',
      [OrderStatus.COMPLETED]: 'bg-green-500/10 text-green-400 border-green-500/30',
      [OrderStatus.CANCELLED]: 'bg-slate-600 text-slate-400 border-slate-500/30',
    };
    return <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase border whitespace-nowrap ${colors[status]}`}>{status}</span>;
  };

  const OrderRow: React.FC<{ order: any }> = ({ order }) => {
    const isCustom = order.type === 'custom';
    const timeStatus = order.status === OrderStatus.CONFIRMED ? getTimeRemaining(order.expectedDeliveryAt || order.deadlineAt) : null;

    return (
      <div className="bg-slate-800 border border-slate-700 rounded-2xl p-4 flex flex-col gap-4 hover:border-teal-600/50 hover:shadow-xl hover:shadow-black/30 transition-all relative overflow-hidden group">
        <div className={`absolute top-0 left-0 w-1.5 h-full ${isCustom ? 'bg-purple-500' : 'bg-teal-500'}`}></div>
        
        <div className="flex gap-4">
          <div className="flex-shrink-0 w-20 h-20 sm:w-28 sm:h-28 bg-slate-700 rounded-xl overflow-hidden border border-slate-600">
             {isCustom ? (
               order.images && order.images[0] ? <img src={order.images[0]} className="w-full h-full object-cover" alt="" /> : <div className="w-full h-full flex items-center justify-center text-slate-500"><FileText /></div>
             ) : (
               <img src={order.productImage} className="w-full h-full object-cover" alt="" />
             )}
          </div>
          
          <div className="flex-grow space-y-1">
             <div className="flex flex-wrap justify-between items-start gap-2">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                      <h4 className="font-black text-white text-sm sm:text-base truncate max-w-[150px] sm:max-w-none">{isCustom ? "Custom Request" : order.productTitle}</h4>
                      <span className={`text-[8px] sm:text-[9px] px-2 py-0.5 rounded-full font-black tracking-wider shadow-sm ${isCustom ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' : 'bg-teal-500/20 text-teal-300 border border-teal-500/30'}`}>
                          {isCustom ? 'CUSTOM' : 'CATALOG'}
                      </span>
                  </div>
                  {/* Bill ID Display */}
                  <div className="flex flex-col mt-0.5">
                     <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">ID: #{order.id}</p>
                     {order.billId && (
                       <p className="text-[10px] text-teal-400 font-bold uppercase tracking-widest flex items-center gap-1">
                          <FileDigit className="h-3 w-3" /> {order.billId}
                       </p>
                     )}
                  </div>
                </div>
                <StatusBadge status={order.status} />
             </div>

             <div className="hidden sm:block bg-slate-700/50 p-3 rounded-xl text-sm text-slate-400 leading-relaxed border border-slate-600/50">
                {isCustom ? order.description : (order.description || "No specific instructions provided.")}
             </div>
          </div>
        </div>

        <div className="sm:hidden bg-slate-700/50 p-2 rounded-lg text-xs text-slate-400 leading-relaxed border border-slate-600/50 italic">
          {isCustom ? order.description : (order.description || "No specific instructions.")}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-700">
          <div className="flex flex-wrap items-center gap-2 sm:gap-4 w-full sm:w-auto">
             <button onClick={() => handleViewCustomer(order.userId)} className="text-teal-400 flex items-center gap-2 hover:bg-teal-500/10 px-2 sm:px-3 py-1.5 rounded-lg font-bold text-[10px] sm:text-xs transition-colors border border-transparent hover:border-teal-500/30">
                <UserIcon className="h-4 w-4" /> {isCustom ? order.contactName : "Customer Info"}
             </button>
             {!isCustom && <span className="font-black text-slate-300 text-[10px] sm:text-xs px-2 sm:px-3 py-1.5 bg-slate-700 rounded-lg border border-slate-600">Qty: {order.quantity} | ₹{order.totalPrice}</span>}
          </div>
          
          {timeStatus && (
            <div className={`flex items-center gap-1.5 text-[10px] sm:text-xs font-black bg-slate-700 px-2 sm:px-3 py-1.5 rounded-lg border border-slate-600 ${timeStatus.color}`}>
              <Clock className="h-3.5 w-3.5" /> {timeStatus.label}
            </div>
          )}
        </div>

        <div className="flex flex-row flex-wrap gap-2 pt-3 border-t border-slate-700 md:flex-col md:border-t-0 md:pt-0 md:border-l md:border-slate-700 md:pl-4 md:min-w-[140px]">
           {order.status === OrderStatus.PENDING && (
             <>
               <button onClick={() => handleStatusUpdate(order.type, order.id, OrderStatus.CONFIRMED)} className="flex-1 bg-green-600 text-white text-[10px] font-black py-3 px-2 rounded-xl hover:bg-green-700 shadow-md transition-all active:scale-95 uppercase tracking-wider">Accept</button>
               <button onClick={() => handleStatusUpdate(order.type, order.id, OrderStatus.CANCELLED)} className="flex-1 border-2 border-red-900/50 text-red-400 text-[10px] font-black py-3 px-2 rounded-xl hover:bg-red-900/20 transition-all active:scale-95 uppercase tracking-wider">Decline</button>
             </>
           )}
           {order.status === OrderStatus.CONFIRMED && (
             <button onClick={() => handleStatusUpdate(order.type, order.id, OrderStatus.COMPLETED)} className="w-full bg-teal-600 text-white text-[10px] font-black py-4 rounded-xl hover:bg-teal-700 shadow-lg flex items-center justify-center gap-2 transition-all active:scale-95 uppercase tracking-widest">
                <CheckCircle2 className="h-4 w-4" /> Mark Completed
             </button>
           )}
           {(order.status === OrderStatus.COMPLETED || order.status === OrderStatus.CANCELLED) && (
             <button onClick={() => confirm("Delete Record?", "This order record will be permanently deleted.", () => {
                const action = order.type === 'normal' ? deleteOrder(order.id) : deleteCustomOrder(order.id);
                action.then(() => { loadData(); notify("Record deleted.", "success"); });
             })} className="text-slate-500 hover:text-red-400 p-3 rounded-full hover:bg-red-900/20 transition-all mx-auto">
                <Trash2 className="h-6 w-6" />
             </button>
           )}
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Dark Teal Header */}
      <div className="bg-gradient-to-r from-slate-800 to-teal-900 border-b border-slate-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5 flex flex-col lg:flex-row lg:items-center justify-between gap-5">
          <div>
            <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight">Management Hub</h1>
            <p className="text-slate-400 text-sm mt-0.5 font-medium">VKM Flowers — Operational Control</p>
          </div>

          <div className="flex flex-col sm:flex-row flex-wrap items-start sm:items-center gap-3">
            {/* WhatsApp phone input */}
            <div className="bg-slate-700/50 border border-slate-600 rounded-2xl px-4 py-2.5 flex items-center gap-3 w-full sm:w-auto">
              <Phone className="h-4 w-4 text-teal-400 flex-shrink-0" />
              <div className="flex-grow min-w-0">
                <label className="text-[9px] font-bold text-slate-400 uppercase tracking-widest block">WhatsApp Number</label>
                <input
                  className="bg-transparent text-sm font-bold text-white outline-none w-full sm:w-32 placeholder-slate-500"
                  value={adminPhone}
                  onChange={(e) => setAdminPhone(e.target.value.replace(/\D/g, '').slice(0, 10))}
                  placeholder="10 Digits"
                  maxLength={10}
                />
              </div>
              <button onClick={handleUpdatePhone} className="text-[10px] bg-teal-500 hover:bg-teal-600 text-white px-3 py-1.5 rounded-xl font-bold uppercase tracking-widest transition-all active:scale-95 flex-shrink-0">Set</button>
            </div>

            {/* Tab switcher */}
            <div className="flex p-1.5 bg-slate-700/50 rounded-2xl border border-slate-600 overflow-x-auto w-full sm:w-auto">
              <button onClick={() => setActiveTab('products')} className={`px-4 py-2 rounded-xl text-xs sm:text-sm font-bold transition-all flex items-center gap-2 whitespace-nowrap ${activeTab === 'products' ? 'bg-teal-500 text-white shadow-md' : 'text-slate-400 hover:text-white'}`}>
                <ShoppingBag className="h-3.5 w-3.5 sm:h-4 sm:w-4" /> Catalog
              </button>
              <button onClick={() => setActiveTab('orders')} className={`px-4 py-2 rounded-xl text-xs sm:text-sm font-bold transition-all flex items-center gap-2 whitespace-nowrap ${activeTab === 'orders' ? 'bg-teal-500 text-white shadow-md' : 'text-slate-400 hover:text-white'}`}>
                <ListChecks className="h-3.5 w-3.5 sm:h-4 sm:w-4" /> Orders {pendingOrdersCount > 0 && <span className="bg-red-500 text-white text-[8px] px-1.5 py-0.5 rounded-full font-black">{pendingOrdersCount}</span>}
              </button>
              <button onClick={() => setActiveTab('custom')} className={`px-4 py-2 rounded-xl text-xs sm:text-sm font-bold transition-all flex items-center gap-2 whitespace-nowrap ${activeTab === 'custom' ? 'bg-teal-500 text-white shadow-md' : 'text-slate-400 hover:text-white'}`}>
                <Sparkles className="h-3.5 w-3.5 sm:h-4 sm:w-4" /> Custom {pendingCustomCount > 0 && <span className="bg-purple-500 text-white text-[8px] px-1.5 py-0.5 rounded-full font-black">{pendingCustomCount}</span>}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 pb-24 space-y-6">
      {activeTab === 'products' ? (
        <div className="space-y-5 animate-fade-in">
          <div className="flex flex-col sm:flex-row justify-between items-center gap-4">
            <h2 className="text-xl font-black flex items-center gap-2.5 text-white"><ShoppingBag className="h-5 w-5 text-teal-400" /> Product Catalog</h2>
            <button onClick={() => { setIsAddingProduct(!isAddingProduct); if(isAddingProduct) resetForm(); }} className="w-full sm:w-auto bg-teal-500 hover:bg-teal-600 text-white px-6 py-3 rounded-2xl flex items-center justify-center gap-2 shadow-lg transition-all active:scale-95 font-bold uppercase text-xs tracking-widest">
              {isAddingProduct ? <><Ban className="h-4 w-4" /> Cancel</> : <><Plus className="h-4 w-4" /> Add New Item</>}
            </button>
          </div>

          {isAddingProduct && (
            <div className="bg-slate-800 border border-slate-600 p-6 sm:p-8 rounded-3xl shadow-2xl">
              <h3 className="text-lg font-black text-white mb-6 border-b border-slate-700 pb-4">
                {editingProduct ? 'Update Product' : 'New Product'}
              </h3>
              <form onSubmit={handleSaveProduct} className="grid grid-cols-1 md:grid-cols-2 gap-5">
                <div className="space-y-2">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-widest">Product Name</label>
                  <input className="w-full bg-slate-700 border-2 border-slate-600 text-white placeholder-slate-500 p-3 rounded-2xl focus:ring-4 focus:ring-teal-500/20 focus:border-teal-500 outline-none font-medium transition-all" value={newProd.title} onChange={e => setNewProd({...newProd, title: e.target.value})} required />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-xs font-bold text-slate-400 uppercase tracking-widest">Price (₹)</label>
                    <input type="text" inputMode="numeric" pattern="[0-9]*" className="w-full bg-slate-700 border-2 border-slate-600 text-white placeholder-slate-500 p-3 rounded-2xl focus:ring-4 focus:ring-teal-500/20 focus:border-teal-500 outline-none font-medium transition-all" placeholder="e.g. 499" value={newProd.price ?? ''} onChange={e => { const v = e.target.value.replace(/[^0-9]/g,''); setNewProd({...newProd, price: v === '' ? undefined : Number(v)}); }} required />
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs font-bold text-slate-400 uppercase tracking-widest">Prep Hours</label>
                    <input type="text" inputMode="numeric" pattern="[0-9]*" className="w-full bg-slate-700 border-2 border-slate-600 text-white placeholder-slate-500 p-3 rounded-2xl focus:ring-4 focus:ring-teal-500/20 focus:border-teal-500 outline-none font-medium transition-all" placeholder="e.g. 24" value={newProd.durationHours ?? ''} onChange={e => { const v = e.target.value.replace(/[^0-9]/g,''); setNewProd({...newProd, durationHours: v === '' ? undefined : Number(v)}); }} required />
                  </div>
                </div>

                <div className="md:col-span-2 border-2 border-dashed border-slate-600 rounded-2xl p-6 bg-slate-700/30 text-center">
                  <div className="flex flex-col items-center gap-3">
                    <Upload className="h-6 w-6 text-slate-500" />
                    <p className="font-bold text-slate-300 text-sm">Gallery Photos</p>
                    <label className="flex items-center justify-center px-5 py-2.5 border-2 border-teal-500 text-teal-400 rounded-xl font-bold bg-transparent hover:bg-teal-500 hover:text-white cursor-pointer transition-all shadow-sm active:scale-95 uppercase text-xs tracking-widest">
                      Browse Files
                      <input type="file" className="hidden" multiple accept="image/*" onChange={handleImageUpload} />
                    </label>
                  </div>
                  {newProd.images && newProd.images.length > 0 && (
                    <div className="flex gap-4 mt-6 overflow-x-auto pb-2 justify-start sm:justify-center">
                      {newProd.images.map((img, idx) => (
                        <div key={idx} className="relative flex-shrink-0">
                          <img src={img} className="h-20 w-20 object-cover rounded-xl border-2 border-slate-600 shadow-lg" alt="" />
                          <button type="button" onClick={() => removeNewImage(idx)} className="absolute -top-2 -right-2 bg-red-500 text-white rounded-full p-1 shadow-xl"><X className="h-3 w-3" /></button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="md:col-span-2 space-y-2">
                  <label className="text-xs font-bold text-slate-400 uppercase tracking-widest">Description <span className="normal-case font-normal text-slate-500">(optional)</span></label>
                  <textarea rows={4} className="w-full bg-slate-700 border-2 border-slate-600 text-white placeholder-slate-500 p-3 rounded-2xl focus:ring-4 focus:ring-teal-500/20 focus:border-teal-500 outline-none font-medium transition-all resize-none" value={newProd.description} onChange={e => setNewProd({...newProd, description: e.target.value})} />
                </div>
                <div className="md:col-span-2 flex flex-col sm:flex-row justify-end gap-3 pt-4 border-t border-slate-700">
                  <button type="button" onClick={resetForm} className="px-6 py-3 text-slate-400 font-bold hover:bg-slate-700 rounded-2xl uppercase tracking-widest text-xs transition-all">Cancel</button>
                  <button type="submit" disabled={isSubmitting} className="px-8 py-3 bg-teal-500 hover:bg-teal-600 text-white font-black rounded-2xl shadow-lg uppercase tracking-widest text-xs flex items-center justify-center gap-2 transition-all active:scale-95">
                    {isSubmitting ? <><Loader2 className="h-4 w-4 animate-spin" /> Saving...</> : (editingProduct ? "Update Item" : "Save Item")}
                  </button>
                </div>
              </form>
            </div>
          )}

          {products.length === 0 ? (
            <div className="text-center py-20 bg-slate-800 rounded-3xl border border-dashed border-slate-700">
              <ShoppingBag className="h-12 w-12 text-slate-600 mx-auto mb-4" />
              <p className="text-slate-500 font-bold uppercase tracking-widest text-sm">No products in catalog yet.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
              {products.map(p => (
                <div key={p.id} className="bg-slate-800 rounded-3xl shadow-md hover:shadow-xl hover:shadow-teal-900/30 transition-all duration-300 overflow-hidden border border-slate-700 group flex flex-col">
                  <div className="relative h-48 bg-slate-700 overflow-hidden">
                    <img src={p.images[0]} alt={p.title} className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500" />
                    <div className="absolute inset-0 bg-gradient-to-t from-slate-900/80 to-transparent opacity-0 group-hover:opacity-100 transition-all duration-300 flex items-end p-4 gap-2">
                      <button onClick={(e) => { e.stopPropagation(); startEditProduct(p); }} className="bg-white/95 text-gray-900 flex-1 py-3 rounded-xl font-black flex items-center justify-center gap-2 hover:bg-white transition-all uppercase text-[9px] tracking-widest shadow-xl active:scale-95">
                        <Pencil className="h-3.5 w-3.5" /> Edit
                      </button>
                      <button onClick={(e) => handleDeleteProduct(e, p.id)} className="bg-red-500/95 text-white w-12 py-3 rounded-xl font-black flex items-center justify-center hover:bg-red-500 transition-all shadow-xl active:scale-95">
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                    <div className="absolute top-3 right-3 bg-slate-900/80 backdrop-blur text-teal-400 px-3 py-1.5 rounded-xl text-[9px] font-black border border-teal-500/30 flex items-center gap-1.5">
                      <Clock className="h-3 w-3" /> {p.durationHours}H
                    </div>
                  </div>
                  <div className="p-5 flex flex-col flex-grow">
                    <h3 className="font-black text-base text-white mb-1 leading-tight line-clamp-2 group-hover:text-teal-300 transition-colors">{p.title}</h3>
                    <p className="text-slate-500 text-xs mb-4 line-clamp-2 leading-relaxed flex-grow">{p.description}</p>
                    <div className="flex items-center justify-between pt-4 border-t border-slate-700">
                      <span className="font-black text-2xl text-teal-400">₹{p.price}</span>
                      <div className="h-10 w-10 rounded-xl bg-teal-500/10 flex items-center justify-center text-teal-400 group-hover:bg-teal-500 group-hover:text-white transition-all">
                        <ShoppingBag className="h-5 w-5" />
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 animate-fade-in">

          <div className="space-y-4">
            <div className="flex items-center gap-2 px-1">
              <Bell className="h-4 w-4 text-yellow-400" />
              <h3 className="text-xs font-black text-slate-400 uppercase tracking-[0.3em]">Inbound ({filteredPending.length})</h3>
            </div>
            <div className="space-y-3">
              {filteredPending.length === 0 ? (
                <div className="bg-slate-800 border border-dashed border-slate-700 p-12 rounded-3xl text-center text-slate-600 font-black uppercase text-[9px] tracking-widest flex flex-col items-center gap-3">
                  <ListChecks className="h-7 w-7 text-slate-700" />Queue is Empty
                </div>
              ) : filteredPending.map(o => <OrderRow key={o.id} order={o} />)}
            </div>
          </div>

          <div className="lg:col-span-2 space-y-4">
            <div className="flex justify-between items-center px-1">
              <div className="flex items-center gap-2">
                <AlertCircle className={`h-4 w-4 ${activeTab === 'custom' ? 'text-purple-400' : 'text-teal-400'}`} />
                <h3 className={`text-xs font-black uppercase tracking-[0.3em] ${activeTab === 'custom' ? 'text-purple-400' : 'text-teal-400'}`}>
                  Queue Progress ({filteredActive.length})
                </h3>
              </div>
              <span className="text-[10px] text-slate-500 font-bold uppercase tracking-widest bg-slate-800 px-3 py-1 rounded-full border border-slate-700">Priority: Deadline</span>
            </div>
            <div className="space-y-3">
              {filteredActive.length === 0 ? (
                <div className="bg-slate-800/50 border-2 border-dashed border-slate-700 p-20 rounded-3xl text-center text-slate-600 font-black uppercase text-[9px] tracking-widest">
                  Workshop Floor Clear.
                </div>
              ) : filteredActive.map(o => <OrderRow key={o.id} order={o} />)}
            </div>

            {filteredHistory.length > 0 && (
              <div className="mt-12 space-y-4">
                <h3 className="text-xs font-black text-slate-500 uppercase tracking-[0.3em] px-1">History</h3>
                <div className="space-y-2">
                  {filteredHistory.slice(0, 10).map((o: any) => (
                    <div key={o.id} className="bg-slate-800 border border-slate-700 rounded-2xl p-4 flex flex-wrap justify-between items-center gap-3 group hover:border-slate-600 transition-all">
                      <div className="flex items-center gap-4 min-w-0 flex-grow">
                        <div className={`flex-shrink-0 h-10 w-10 rounded-xl flex items-center justify-center ${o.status === OrderStatus.COMPLETED ? 'bg-teal-500/10 text-teal-400' : 'bg-slate-700 text-slate-500'}`}>
                          <CheckCircle2 className="h-5 w-5" />
                        </div>
                        <div className="min-w-0">
                          <p className="font-bold text-white text-sm truncate">{o.type === 'custom' ? 'Custom Req' : o.productTitle}</p>
                          <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest truncate">#{o.id} {o.billId ? `/ ${o.billId}` : ''}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 ml-auto">
                        <StatusBadge status={o.status} />
                        <button onClick={() => confirm("Delete Record?", "This order record will be permanently deleted.", () => {
                          const action = o.type === 'normal' ? deleteOrder(o.id) : deleteCustomOrder(o.id);
                          action.then(() => { loadData(); notify("Record deleted.", "success"); });
                        })} className="text-slate-600 hover:text-red-400 transition-colors p-2 hover:bg-red-500/10 rounded-full">
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
      </div>  {/* end main content */}

      {selectedUser && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-xl flex items-end sm:items-center justify-center p-0 sm:p-6 z-[100] animate-fade-in">
            <div className="bg-white rounded-t-[40px] sm:rounded-[48px] w-full max-w-sm shadow-2xl overflow-hidden border border-white/20 transform transition-transform animate-scale-up">
                <div className="bg-gradient-to-br from-teal-600 to-slate-700 px-6 sm:px-8 py-8 sm:py-12 flex flex-col items-center text-white relative">
                    <button onClick={() => setSelectedUser(null)} className="absolute top-6 right-6 text-white/40 hover:text-white transition-all"><X className="h-6 w-6 sm:h-8 sm:w-8" /></button>
                    <div className="h-20 w-20 sm:h-28 sm:w-28 bg-white/10 backdrop-blur-2xl rounded-[32px] sm:rounded-[40px] flex items-center justify-center text-white text-3xl sm:text-5xl font-black mb-4 sm:mb-6 border border-white/20 shadow-2xl">
                        {selectedUser.name.charAt(0).toUpperCase()}
                    </div>
                    <h4 className="text-xl sm:text-3xl font-black tracking-tight">{selectedUser.name}</h4>
                    <span className="text-[10px] sm:text-sm text-teal-100/60 font-black uppercase tracking-widest mt-1">{selectedUser.email}</span>
                </div>
                <div className="p-6 sm:p-10 space-y-4 sm:space-y-5 bg-slate-800 pb-10 sm:pb-10">
                    <div className="space-y-3 sm:space-y-4">
                        <div className="flex items-center gap-4 sm:gap-5 bg-slate-700 p-4 sm:p-6 rounded-[24px] sm:rounded-[32px] border border-slate-600">
                            <div className="h-10 w-10 sm:h-14 sm:w-14 bg-slate-600 text-teal-400 rounded-2xl flex items-center justify-center shadow-sm border border-slate-500"><Phone className="h-5 w-5 sm:h-6 sm:w-6" /></div>
                            <div>
                                <p className="text-[8px] sm:text-[10px] text-slate-400 font-black uppercase tracking-widest mb-1">Phone</p>
                                <p className="text-white font-black text-sm sm:text-lg">{selectedUser.phone}</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-4 sm:gap-5 bg-slate-700 p-4 sm:p-6 rounded-[24px] sm:rounded-[32px] border border-slate-600">
                            <div className="h-10 w-10 sm:h-14 sm:w-14 bg-slate-600 text-teal-400 rounded-2xl flex items-center justify-center shadow-sm border border-slate-500"><MapPin className="h-5 w-5 sm:h-6 sm:w-6" /></div>
                            <div>
                                <p className="text-[8px] sm:text-[10px] text-slate-400 font-black uppercase tracking-widest mb-1">Service Area</p>
                                <p className="text-white font-black text-sm sm:text-lg">{selectedUser.area}</p>
                                <p className="text-[8px] sm:text-[10px] text-slate-400 font-black uppercase mt-0.5 tracking-wider">{selectedUser.city}</p>
                            </div>
                        </div>
                    </div>
                    <button onClick={() => setSelectedUser(null)} className="w-full bg-teal-600 text-white font-black py-4 sm:py-6 rounded-[24px] sm:rounded-[32px] hover:bg-teal-700 transition-all shadow-lg mt-4 sm:mt-8 active:scale-[0.96] uppercase tracking-[0.2em] text-[10px]">Close</button>
                </div>
            </div>
        </div>
      )}
    </div>
  );
};
