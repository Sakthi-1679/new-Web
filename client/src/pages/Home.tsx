
import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Product, UserRole } from '../types';
import { getProducts, placeOrder, getAdminContact } from '../services/storage';
import { useAuth } from '../context/AuthContext';
import { useNotification } from '../context/NotificationContext';
import { Search, ShoppingCart, Clock, Info, ShieldAlert, Loader2, Flower2, ChevronLeft, ChevronRight, ZoomIn, X, Sparkles, Truck, BadgeCheck, Star } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export const Home: React.FC = () => {
  const [products, setProducts] = useState<Product[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedProduct, setSelectedProduct] = useState<Product | null>(null);
  const [activeImageIndex, setActiveImageIndex] = useState(0);
  const [orderQty, setOrderQty] = useState(1);
  const [orderNote, setOrderNote] = useState('');
  const [zoomedImages, setZoomedImages] = useState<string[]>([]);
  const [zoomedIndex, setZoomedIndex] = useState(0);
  const [loading, setLoading] = useState(true);
  const { isAuthenticated, user } = useAuth();
  const { notify } = useNotification();
  const navigate = useNavigate();

  useEffect(() => {
    getProducts()
      .then((data) => {
        setProducts(data);
      })
      .catch(err => {
        console.warn("Could not fetch products, showing empty list.");
        setProducts([]);
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  const openZoom = (images: string[], index = 0) => {
    setZoomedImages(images);
    setZoomedIndex(index);
  };
  const closeZoom = () => setZoomedImages([]);
  const zoomPrev = (e: React.MouseEvent) => { e.stopPropagation(); setZoomedIndex(i => (i - 1 + zoomedImages.length) % zoomedImages.length); };
  const zoomNext = (e: React.MouseEvent) => { e.stopPropagation(); setZoomedIndex(i => (i + 1) % zoomedImages.length); };

  // PERF: useMemo avoids re-computing the filtered list on every render unless
  // products or searchTerm actually change. Saves CPU on every keystroke during search.
  const filteredProducts = useMemo(() =>
    products.filter(p =>
      p.title.toLowerCase().includes(searchTerm.toLowerCase())
    ),
    [products, searchTerm]
  );

  const handleOrderClick = (product: Product) => {
    if (user?.role === UserRole.ADMIN) {
      notify("Administrators cannot place personal orders.", "error");
      return;
    }

    if (!isAuthenticated) {
      navigate('/login');
      return;
    }
    setSelectedProduct(product);
    setActiveImageIndex(0);
    setOrderQty(1);
    setOrderNote('');
  };

  const submitOrder = async () => {
    if (!selectedProduct || !user) return;
    try {
      await placeOrder({
        userId: user.id,
        productId: selectedProduct.id,
        quantity: orderQty,
        description: orderNote
      });
      const adminPhone = await getAdminContact();
      const totalAmount = selectedProduct.price * orderQty;
      const now = new Date().toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });

      const message = [
        '🌸 *New Order – VKM Flowers*',
        '',
        `👤 Customer: ${user.name}`,
        `📞 Phone: ${user.phone}`,
        `📦 Product: ${selectedProduct.title}`,
        `🔢 Quantity: ${orderQty}`,
        orderNote ? `📝 Note: ${orderNote}` : '',
        `💰 Amount Due: ₹${totalAmount}`,
        `📅 Ordered On: ${now}`,
      ].filter(Boolean).join('\n');

      window.open(`https://wa.me/91${adminPhone}?text=${encodeURIComponent(message)}`, '_blank');
      setSelectedProduct(null);
      notify('Order placed! WhatsApp opened to notify admin.', 'success');
    } catch (e: any) {
      const msg = e?.message || '';
      if (msg.includes('Invalid token') || msg.includes('No token')) {
        notify('Session expired. Please log out and log back in.', 'error');
      } else {
        notify(msg || 'Failed to place order. Please check your connection.', 'error');
      }
    }
  };

  const isUserAdmin = user?.role === UserRole.ADMIN;

  const nextImage = () => {
    if (selectedProduct && selectedProduct.images.length > 1) {
      setActiveImageIndex((prev) => (prev + 1) % selectedProduct.images.length);
    }
  };

  const prevImage = () => {
    if (selectedProduct && selectedProduct.images.length > 1) {
      setActiveImageIndex((prev) => (prev - 1 + selectedProduct.images.length) % selectedProduct.images.length);
    }
  };

  return (
    <div>
      {/* Hero Banner - shown to non-authenticated users */}
      {!isAuthenticated && !loading && (
        <div className="bg-gradient-to-r from-rose-500 via-rose-600 to-pink-600 relative overflow-hidden">
          <div className="absolute top-0 right-0 w-96 h-96 bg-pink-400/30 rounded-full translate-x-32 -translate-y-32 blur-3xl pointer-events-none"></div>
          <div className="absolute bottom-0 left-0 w-64 h-64 bg-rose-300/20 rounded-full -translate-x-16 translate-y-16 blur-3xl pointer-events-none"></div>
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-14 md:py-20 relative z-10">
            <div className="max-w-2xl">
              <div className="inline-flex items-center gap-2 bg-white/20 backdrop-blur-sm text-white text-xs font-bold px-3 py-1.5 rounded-full mb-5 border border-white/30">
                <Sparkles className="h-3.5 w-3.5" /> Kanchipuram's #1 Flower Shop
              </div>
              <h1 className="text-4xl md:text-5xl font-black text-white leading-tight mb-4">
                Fresh Flowers,<br /><span className="text-pink-100">Delivered Today</span>
              </h1>
              <p className="text-rose-100 text-base md:text-lg mb-8 font-medium max-w-lg leading-relaxed">
                Handpicked blooms for every occasion. Browse our fresh collection and order with ease.
              </p>
              <div className="flex flex-col sm:flex-row gap-3">
                <a href="#products" className="inline-flex items-center justify-center gap-2 bg-white text-rose-600 font-black px-6 py-3.5 rounded-2xl hover:bg-rose-50 transition-all shadow-xl text-sm">
                  <Flower2 className="h-4 w-4" /> Shop Now
                </a>
                <button onClick={() => navigate('/signup')} className="inline-flex items-center justify-center gap-2 bg-white/10 backdrop-blur-sm text-white font-bold px-6 py-3.5 rounded-2xl border border-white/30 hover:bg-white/20 transition-all text-sm">
                  Create Account
                </button>
              </div>
            </div>
          </div>
          <div className="border-t border-white/10 bg-black/10 backdrop-blur-sm">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3">
              <div className="flex flex-wrap gap-5 justify-center md:justify-start text-white/90 text-xs font-semibold">
                <span className="flex items-center gap-1.5"><Truck className="h-3.5 w-3.5" /> Fast Delivery</span>
                <span className="flex items-center gap-1.5"><BadgeCheck className="h-3.5 w-3.5" /> Fresh Guaranteed</span>
                <span className="flex items-center gap-1.5"><Star className="h-3.5 w-3.5" /> Premium Quality</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main Product Section */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8" id="products">
        <div className="space-y-6">
          {/* Section Header & Search */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <h2 className="text-2xl font-black text-gray-900 tracking-tight">
                {isAuthenticated ? 'Our Collection' : 'Browse Flowers'}
              </h2>
              <p className="text-gray-400 text-sm mt-0.5 font-medium">
                {loading ? 'Loading...' : `${filteredProducts.length} arrangement${filteredProducts.length !== 1 ? 's' : ''} available`}
              </p>
            </div>
            <div className="relative w-full sm:w-72">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                className="w-full pl-10 pr-4 py-3 bg-white border-2 border-gray-100 rounded-2xl shadow-sm placeholder-gray-300 focus:outline-none focus:border-rose-300 focus:ring-4 focus:ring-rose-50 text-sm font-medium transition-all"
                placeholder="Search arrangements..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>

          {loading ? (
            <div className="flex flex-col items-center justify-center py-24 text-gray-400">
              <Loader2 className="h-10 w-10 animate-spin mb-4 text-rose-400" />
              <p className="font-bold text-sm tracking-widest uppercase">Loading Collection...</p>
            </div>
          ) : filteredProducts.length > 0 ? (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4 md:gap-5">
              {filteredProducts.map(product => (
                <div key={product.id} className="bg-white rounded-3xl overflow-hidden shadow-sm hover:shadow-xl transition-all duration-300 border border-gray-100 flex flex-col group">
                  {/* Product Image */}
                  <div className="relative overflow-hidden bg-rose-50 h-44 md:h-56">
                    <img
                      src={product.images && product.images.length > 0 ? product.images[0] : 'https://via.placeholder.com/300?text=No+Image'}
                      alt={product.title}
                      className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-105 cursor-zoom-in"
                      onClick={() => openZoom(product.images && product.images.length > 0 ? product.images : [], 0)}
                    />
                    <div onClick={() => openZoom(product.images && product.images.length > 0 ? product.images : [], 0)} className="absolute top-2.5 left-2.5 bg-white/80 backdrop-blur-sm p-1.5 rounded-full shadow-sm opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer hover:bg-white">
                      <ZoomIn className="h-3.5 w-3.5 text-gray-600" />
                    </div>
                    <div className="absolute top-2.5 right-2.5 bg-white shadow-md px-2.5 py-1 rounded-full text-[10px] font-black text-gray-700 flex items-center gap-1">
                      <Clock className="h-3 w-3 text-rose-500" /> {product.durationHours}h
                    </div>
                    <div className="absolute inset-0 bg-gradient-to-t from-black/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none"></div>
                  </div>

                  {/* Card Body */}
                  <div className="p-4 flex flex-col flex-grow">
                    <h3 className="text-sm md:text-base font-bold text-gray-900 leading-snug line-clamp-1 mb-1">
                      {product.title}
                    </h3>
                    <p className="text-xs text-gray-400 line-clamp-2 flex-grow leading-relaxed mb-3">
                      {product.description}
                    </p>
                    <div className="flex items-center justify-between pt-3 border-t border-gray-50">
                      <span className="text-lg md:text-xl font-black text-rose-600">₹{product.price}</span>
                      <button
                        onClick={() => handleOrderClick(product)}
                        disabled={isUserAdmin}
                        className={`flex items-center gap-1.5 py-2 px-4 rounded-xl transition-all duration-200 text-xs font-bold active:scale-95
                          ${isUserAdmin
                            ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                            : 'bg-rose-500 text-white hover:bg-rose-600 shadow-md shadow-rose-100'}`}
                      >
                        {isUserAdmin ? <ShieldAlert className="h-3.5 w-3.5" /> : <ShoppingCart className="h-3.5 w-3.5" />}
                        <span className="hidden sm:inline">{isUserAdmin ? 'Admin' : 'Order'}</span>
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-24 bg-white rounded-3xl border border-dashed border-rose-100">
              <div className="w-20 h-20 bg-rose-50 rounded-full flex items-center justify-center mx-auto mb-4">
                <Info className="h-10 w-10 text-rose-300" />
              </div>
              <h3 className="text-lg font-black text-gray-900 mb-1">No Arrangements Found</h3>
              <p className="text-gray-400 text-sm">Try a different search term or check back later.</p>
            </div>
          )}
        </div>
      </div>

      {/* Image Zoom Lightbox */}
      {zoomedImages.length > 0 && (
        <div className="fixed inset-0 bg-black/95 backdrop-blur-md z-[200] flex items-center justify-center p-4" onClick={closeZoom}>
          <button className="absolute top-4 right-4 bg-white/10 hover:bg-white/20 text-white p-3 rounded-full transition-all z-10" onClick={closeZoom}>
            <X className="h-6 w-6" />
          </button>
          {zoomedImages.length > 1 && (
            <div className="absolute top-4 left-1/2 -translate-x-1/2 bg-black/50 text-white text-xs font-black px-4 py-2 rounded-full uppercase tracking-widest">
              {zoomedIndex + 1} / {zoomedImages.length}
            </div>
          )}
          {zoomedImages.length > 1 && (
            <button onClick={zoomPrev} className="absolute left-3 top-1/2 -translate-y-1/2 bg-white/10 hover:bg-white/25 text-white p-3 rounded-full transition-all z-10">
              <ChevronLeft className="h-7 w-7" />
            </button>
          )}
          <img src={zoomedImages[zoomedIndex]} alt={`Photo ${zoomedIndex + 1}`} className="max-w-full max-h-[85vh] object-contain rounded-2xl shadow-2xl select-none" onClick={e => e.stopPropagation()} />
          {zoomedImages.length > 1 && (
            <button onClick={zoomNext} className="absolute right-3 top-1/2 -translate-y-1/2 bg-white/10 hover:bg-white/25 text-white p-3 rounded-full transition-all z-10">
              <ChevronRight className="h-7 w-7" />
            </button>
          )}
          {zoomedImages.length > 1 && (
            <div className="absolute bottom-5 left-1/2 -translate-x-1/2 flex gap-2">
              {zoomedImages.map((_, idx) => (
                <button key={idx} onClick={e => { e.stopPropagation(); setZoomedIndex(idx); }} className={`rounded-full transition-all ${idx === zoomedIndex ? 'bg-white w-5 h-2' : 'bg-white/40 w-2 h-2'}`} />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Order Modal */}
      {selectedProduct && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-3xl max-w-2xl w-full shadow-2xl overflow-hidden flex flex-col md:flex-row max-h-[92vh] md:max-h-[600px]">
            {/* Image Panel */}
            <div className="w-full md:w-2/5 bg-rose-50 relative overflow-hidden flex-shrink-0">
              {selectedProduct.images.length > 0 ? (
                <>
                  <img src={selectedProduct.images[activeImageIndex]} alt={selectedProduct.title} className="w-full h-56 md:h-full object-cover cursor-zoom-in" onClick={() => openZoom(selectedProduct.images, activeImageIndex)} />
                  {selectedProduct.images.length > 1 && (
                    <>
                      <button onClick={prevImage} className="absolute left-2 top-1/2 -translate-y-1/2 bg-white/80 hover:bg-white p-2 rounded-full shadow-md transition-all">
                        <ChevronLeft className="h-4 w-4 text-gray-700" />
                      </button>
                      <button onClick={nextImage} className="absolute right-2 top-1/2 -translate-y-1/2 bg-white/80 hover:bg-white p-2 rounded-full shadow-md transition-all">
                        <ChevronRight className="h-4 w-4 text-gray-700" />
                      </button>
                      <div className="absolute bottom-3 left-1/2 -translate-x-1/2 flex gap-1.5">
                        {selectedProduct.images.map((_, i) => (
                          <button key={i} onClick={() => setActiveImageIndex(i)} className={`rounded-full transition-all ${i === activeImageIndex ? 'bg-rose-500 w-4 h-2' : 'bg-white/70 w-2 h-2'}`} />
                        ))}
                      </div>
                    </>
                  )}
                </>
              ) : (
                <div className="w-full h-56 md:h-full flex items-center justify-center">
                  <Flower2 className="h-16 w-16 text-rose-200" />
                </div>
              )}
            </div>

            {/* Order Form Panel */}
            <div className="flex flex-col flex-1 overflow-hidden">
              <div className="p-6 overflow-y-auto flex-grow">
                <div className="flex justify-between items-start mb-3">
                  <div>
                    <h3 className="font-black text-xl text-gray-900 leading-tight">{selectedProduct.title}</h3>
                    <span className="text-rose-600 font-black text-2xl">₹{selectedProduct.price * orderQty}</span>
                  </div>
                  <button onClick={() => setSelectedProduct(null)} className="p-2 hover:bg-gray-100 rounded-xl transition-all text-gray-400 hover:text-gray-600 flex-shrink-0 ml-2">
                    <X className="h-5 w-5" />
                  </button>
                </div>
                <p className="text-gray-500 text-sm mb-4 leading-relaxed">{selectedProduct.description}</p>
                <div className="flex items-center gap-2 text-sm text-gray-600 mb-5 bg-rose-50 px-4 py-2.5 rounded-xl">
                  <Clock className="h-4 w-4 text-rose-400 flex-shrink-0" />
                  <span className="font-medium">Ready in <strong className="text-rose-600">{selectedProduct.durationHours} hours</strong></span>
                </div>

                <div className="space-y-4">
                  <div>
                    <label className="text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] block mb-2">Quantity</label>
                    <div className="flex items-center gap-3">
                      <button onClick={() => setOrderQty(Math.max(1, orderQty - 1))} className="w-10 h-10 rounded-xl bg-gray-100 hover:bg-rose-100 hover:text-rose-600 font-black text-xl transition-all flex items-center justify-center">−</button>
                      <span className="text-xl font-black text-gray-900 w-8 text-center">{orderQty}</span>
                      <button onClick={() => setOrderQty(orderQty + 1)} className="w-10 h-10 rounded-xl bg-gray-100 hover:bg-rose-100 hover:text-rose-600 font-black text-xl transition-all flex items-center justify-center">+</button>
                    </div>
                  </div>
                  <div>
                    <label className="text-[10px] font-black text-gray-400 uppercase tracking-[0.2em] block mb-2">Special Note (optional)</label>
                    <textarea
                      rows={3}
                      className="w-full bg-gray-50 border-2 border-gray-100 rounded-2xl px-4 py-3 text-sm font-medium text-gray-700 focus:outline-none focus:border-rose-300 focus:ring-4 focus:ring-rose-50 transition-all resize-none"
                      placeholder="Any special requests..."
                      value={orderNote}
                      onChange={e => setOrderNote(e.target.value)}
                    />
                  </div>
                </div>
              </div>

              <div className="p-5 border-t border-gray-50 bg-white">
                <button onClick={submitOrder} className="w-full bg-gradient-to-r from-rose-500 to-rose-600 text-white font-black py-4 rounded-2xl hover:from-rose-600 hover:to-rose-700 transition-all shadow-xl shadow-rose-100 flex items-center justify-center gap-2 uppercase tracking-wider text-sm active:scale-[0.98]">
                  <ShoppingCart className="h-5 w-5" /> Place Order via WhatsApp
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
