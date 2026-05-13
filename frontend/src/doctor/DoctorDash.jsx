import { User, LayoutDashboard, Users, Calendar, Bell, ChevronRight } from "lucide-react";
import { Link, useLocation } from "react-router";
import AddAvailability from "../doctor/AddAvailability";
import MeetingRequests from "../doctor/MeetingRequests";

const DoctorDash = () => {
  const location = useLocation();

  // Helper to highlight active link
  const isActive = (path) => location.pathname === path ? "bg-primary/10 text-primary font-bold" : "";

  return (
    <div className="min-h-screen bg-slate-50/50">
      {/* Navbar */}
      <div className="navbar bg-white border-b border-slate-200 px-4 md:px-8 sticky top-0 z-50">
        <div className="navbar-start">
          <div className="dropdown">
            <div tabIndex={0} role="button" className="btn btn-ghost lg:hidden">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h8m-8 6h16" />
              </svg>
            </div>
            <ul tabIndex={0} className="menu menu-sm dropdown-content bg-base-100 rounded-box z-1 mt-3 w-52 p-4 shadow-xl border border-slate-100">
              <li><Link className={isActive('/doctordash')} to="/doctordash">Dashboard</Link></li>
              <li><Link className={isActive('/patients')} to="/patients">My Patients</Link></li>
            </ul>
          </div>
          <div className="flex items-center gap-2">
            <div className="bg-primary p-1.5 rounded-lg">
              <div className="w-6 h-6 bg-white rounded-sm rotate-45 flex items-center justify-center">
                <span className="text-primary -rotate-45 font-black text-xs">M</span>
              </div>
            </div>
            <span className="font-display font-bold text-xl tracking-tight hidden sm:block">
              MediRaksha <span className="text-slate-400 font-medium text-sm ml-1">Doctor</span>
            </span>
          </div>
        </div>

        <div className="navbar-center hidden lg:flex">
          <ul className="menu menu-horizontal px-1 gap-2">
            <li>
              <Link to="/doctordash" className={`px-4 py-2 rounded-xl transition-all ${isActive('/doctordash')}`}>
                <LayoutDashboard size={18} /> Dashboard
              </Link>
            </li>
            <li>
              <Link to="/patients" className={`px-4 py-2 rounded-xl transition-all ${isActive('/patients')}`}>
                <Users size={18} /> My Patients
              </Link>
            </li>
          </ul>
        </div>

        <div className="navbar-end gap-3">
          <button className="btn btn-ghost btn-circle text-slate-500">
            <div className="indicator">
              <Bell size={20} />
              <span className="badge badge-xs badge-secondary indicator-item"></span>
            </div>
          </button>
          <div className="divider divider-horizontal mx-0 h-8 self-center"></div>
          <Link to="/doctorprofile">
            <div className="btn btn-ghost gap-2 pl-2 pr-4 rounded-xl border border-slate-100 bg-white">
              <div className="avatar placeholder">
                <div className="bg-primary text-primary-content rounded-lg w-8">
                  <User size={18} />
                </div>
              </div>
              <span className="text-sm font-semibold hidden md:block">Profile</span>
            </div>
          </Link>
        </div>
      </div>

      {/* Main Content Area */}
      <main className="max-w-7xl mx-auto p-4 md:p-8">
        
        {/* Welcome Header */}
        <header className="mb-8">
          <h1 className="text-3xl font-bold text-slate-800">Doctor Dashboard</h1>
          <p className="text-slate-500">Welcome back! You have 3 new appointment requests today.</p>
        </header>

        {/* Quick Stats / Summary Row */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="stats shadow-sm border border-slate-100 bg-white">
            <div className="stat">
              <div className="stat-figure text-primary">
                <Calendar size={24} />
              </div>
              <div className="stat-title text-xs font-bold uppercase text-slate-400 tracking-wider">Availability</div>
              <div className="stat-value text-2xl text-slate-800">Active</div>
              <div className="stat-desc mt-1">Next: Monday 09:00 AM</div>
            </div>
          </div>
          
          <div className="stats shadow-sm border border-slate-100 bg-white">
            <div className="stat">
              <div className="stat-figure text-secondary">
                <Bell size={24} />
              </div>
              <div className="stat-title text-xs font-bold uppercase text-slate-400 tracking-wider">Pending Requests</div>
              <div className="stat-value text-2xl text-slate-800">08</div>
              <div className="stat-desc text-secondary font-medium">Needs Attention</div>
            </div>
          </div>

          <div className="stats shadow-sm border border-slate-100 bg-white">
            <div className="stat">
              <div className="stat-figure text-emerald-500">
                <Users size={24} />
              </div>
              <div className="stat-title text-xs font-bold uppercase text-slate-400 tracking-wider">Total Patients</div>
              <div className="stat-value text-2xl text-slate-800">124</div>
              <div className="stat-desc flex items-center gap-1 text-emerald-600 font-medium">
                View all patients <ChevronRight size={14} />
              </div>
            </div>
          </div>
        </div>

        {/* Two-Column Grid for Functional Components */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          
          {/* Requests Section - Larger Column */}
          <div className="lg:col-span-7 xl:col-span-8">
            <div className="bg-white rounded-3xl shadow-sm border border-slate-100 overflow-hidden">
              <div className="p-6 border-b border-slate-50">
                <h2 className="text-xl font-bold text-slate-800 flex items-center gap-2">
                  <Bell className="text-secondary" size={20} />
                  Meeting Requests
                </h2>
              </div>
              <div className="p-2">
                <MeetingRequests />
              </div>
            </div>
          </div>

          {/* Availability Section - Sidebar Style */}
          <div className="lg:col-span-5 xl:col-span-4 space-y-6">
            <div className="bg-white rounded-3xl shadow-sm border border-slate-100 overflow-hidden">
              <div className="p-6 border-b border-slate-50 bg-slate-50/50">
                <h2 className="text-xl font-bold text-slate-800 flex items-center gap-2">
                  <Calendar className="text-primary" size={20} />
                  Manage Availability
                </h2>
              </div>
              <div className="p-6">
                <AddAvailability />
              </div>
            </div>

            {/* Quick Tips Card */}
            <div className="card bg-primary text-primary-content shadow-lg shadow-primary/20">
              <div className="card-body p-6">
                <h3 className="card-title text-lg font-bold">Pro Tip</h3>
                <p className="text-sm opacity-90">Keep your availability updated to ensure patients can find your latest schedule easily.</p>
              </div>
            </div>
          </div>

        </div>
      </main>
    </div>
  );
};

export default DoctorDash;