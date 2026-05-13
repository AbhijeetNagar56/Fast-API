import { Link, useLocation } from "react-router";
import { User, Activity, ChevronDown, Menu } from 'lucide-react';

export default function Navbar() {
  const location = useLocation();

  // Helper to check active route for styling
  const isActive = (path) => location.pathname === path;

  return (
    <div className="sticky top-0 z-100 w-full px-4 py-3">
      <div className="navbar bg-white/80 backdrop-blur-md border border-white/20 shadow-lg rounded-2xl max-w-7xl mx-auto px-6">
        
        {/* --- NAVBAR START (Logo) --- */}
        <div className="navbar-start">
          <div className="dropdown">
            <div tabIndex={0} role="button" className="btn btn-ghost lg:hidden mr-2">
              <Menu size={24} />
            </div>
            <ul
              tabIndex={0}
              className="menu menu-sm dropdown-content bg-base-100 rounded-2xl z-1 mt-4 w-64 p-4 shadow-2xl border border-slate-100"
            >
              <li><Link to="/" className="py-3 font-medium">Home</Link></li>
              <li>
                <div className="font-medium py-3">Services</div>
                <ul className="pl-4 border-l ml-2 border-slate-100">
                  <li><Link to="/services">Other</Link></li>
                </ul>
              </li>
              <li><Link to="/about" className="py-3 font-medium">About</Link></li>
            </ul>
          </div>
          
          <Link to="/" className="flex items-center gap-2 group">
            <div className="bg-indigo-600 p-1.5 rounded-lg group-hover:rotate-12 transition-transform duration-300">
              <Activity className="text-white" size={22} />
            </div>
            <span className="font-black text-2xl tracking-tight bg-linear-to-r from-slate-800 to-slate-500 bg-clip-text text-transparent">
              MediRaksha
            </span>
          </Link>
        </div>

        {/* --- NAVBAR CENTER (Desktop Menu) --- */}
        <div className="navbar-center hidden lg:flex">
          <ul className="menu menu-horizontal gap-2 px-1">
            <li>
              <Link 
                to="/" 
                className={`px-4 py-2 rounded-xl font-medium transition-all ${
                  isActive('/') ? "bg-indigo-50 text-indigo-600" : "hover:bg-slate-50 text-slate-600"
                }`}
              >
                Home
              </Link>
            </li>
            
            {/* Services Dropdown */}
            <li className="dropdown dropdown-hover">
              <div 
                tabIndex={0} 
                role="button" 
                className="flex items-center gap-1 px-4 py-2 rounded-xl font-medium text-slate-600 hover:bg-slate-50 transition-all cursor-pointer"
              >
                Services <ChevronDown size={16} className="mt-0.5 opacity-50" />
              </div>
              <ul tabIndex={0} className="dropdown-content z-1 menu p-3 shadow-2xl bg-white rounded-2xl w-56 border border-slate-50 mt-1">
                <li><Link to="/mapc" className="rounded-lg py-2.5">Nearby hospital</Link></li>
                <li><Link to="/upload" className="rounded-lg py-2.5">Upload report</Link></li>
                <li><Link to="/services" className="rounded-lg py-2.5">All Services</Link></li>
              </ul>
            </li>

            <li>
              <Link 
                to="/about" 
                className={`px-4 py-2 rounded-xl font-medium transition-all ${
                  isActive('/about') ? "bg-indigo-50 text-indigo-600" : "hover:bg-slate-50 text-slate-600"
                }`}
              >
                About
              </Link>
            </li>
          </ul>
        </div>

        {/* --- NAVBAR END (Profile) --- */}
        <div className="navbar-end gap-3">
          <Link to="/detail">
            <div className="btn btn-ghost bg-slate-50 hover:bg-indigo-50 hover:text-indigo-600 border-none rounded-xl px-5 flex items-center gap-2 group transition-all">
              <div className="w-8 h-8 rounded-full bg-indigo-100 flex items-center justify-center group-hover:bg-indigo-600 group-hover:text-white transition-colors">
                <User size={18} />
              </div>
              <span className="hidden sm:inline font-semibold">Profile</span>
            </div>
          </Link>
        </div>
      </div>
    </div>
  );
}