import { useState, useEffect } from "react";
import { 
  ArrowLeft, ChevronDown, ChevronUp, Calendar, 
  Clock, User2, Search, Filter, Mail, Users
} from "lucide-react";
import { Link } from "react-router";
import axiosInstance from "../api/axios";

const STATUS_STYLE = {
  pending:   "bg-amber-100 text-amber-700 border-amber-200",
  confirmed: "bg-emerald-100 text-emerald-700 border-emerald-200",
  cancelled: "bg-rose-100 text-rose-700 border-rose-200",
};

export default function MyPatients() {
  const [patients, setPatients]     = useState([]);
  const [loading, setLoading]       = useState(true);
  const [expanded, setExpanded]     = useState(null);
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    fetchPatients();
  }, []);

  const fetchPatients = async () => {
    setLoading(true);
    try {
      const { data } = await axiosInstance.get("/doctor/patients");
      setPatients(data);
    } catch (err) {
      console.error("Failed to fetch patients", err);
    } finally {
      setLoading(false);
    }
  };

  const filtered = patients.filter((p) =>
    p.name?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const toggle = (id) => setExpanded((prev) => (prev === id ? null : id));

  return (
    <div className="min-h-screen bg-slate-50/50 p-4 md:p-8">
      <div className="max-w-5xl mx-auto space-y-6">
        
        {/* Header Section */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <Link to="/doctordash" className="btn btn-ghost btn-circle bg-white shadow-sm hover:text-primary">
              <ArrowLeft size={20} />
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-slate-800 tracking-tight">Patient Directory</h1>
              <p className="text-slate-500 text-sm">Manage and review your patient history</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="bg-white px-4 py-2 rounded-xl shadow-sm border border-slate-200 flex items-center gap-3">
              <Users size={18} className="text-primary" />
              <span className="font-bold text-slate-700">{patients.length}</span>
              <span className="text-slate-400 text-sm font-medium">Total Patients</span>
            </div>
          </div>
        </div>

        {/* Search & Actions */}
        <div className="relative group">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400 group-focus-within:text-primary transition-colors" size={20} />
          <input
            type="text"
            placeholder="Search by patient name..."
            className="input input-bordered w-full pl-12 h-14 rounded-2xl bg-white border-slate-200 focus:border-primary shadow-sm transition-all"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        {/* List Section */}
        {loading ? (
          <div className="flex flex-col items-center justify-center py-24 gap-4">
            <span className="loading loading-spinner loading-lg text-primary" />
            <p className="text-slate-400 font-medium animate-pulse">Loading patient data...</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="bg-white rounded-3xl border border-dashed border-slate-300 py-20 text-center">
            <div className="bg-slate-50 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
               <User2 size={32} className="text-slate-300" />
            </div>
            <h3 className="text-slate-800 font-bold text-lg">No Patients Found</h3>
            <p className="text-slate-500 max-w-xs mx-auto text-sm mt-1">
              {searchTerm ? "Try adjusting your search terms to find the patient." : "Patients will appear here once they book appointments."}
            </p>
          </div>
        ) : (
          <div className="grid gap-4">
            {filtered.map((patient) => {
              const isOpen = expanded === patient._id;
              const upcoming = patient.appointments?.filter(
                (a) => a.status !== "cancelled" && new Date(a.date) >= new Date()
              );
              const past = patient.appointments?.filter(
                (a) => a.status === "cancelled" || new Date(a.date) < new Date()
              );

              return (
                <div
                  key={patient._id}
                  className={`group bg-white border transition-all duration-300 rounded-2xl overflow-hidden shadow-sm hover:shadow-md 
                    ${isOpen ? 'border-primary ring-1 ring-primary/10' : 'border-slate-200'}`}
                >
                  {/* Patient Row */}
                  <div
                    className="flex flex-col md:flex-row md:items-center justify-between p-5 cursor-pointer gap-4"
                    onClick={() => toggle(patient._id)}
                  >
                    <div className="flex items-center gap-4">
                      {/* Avatar */}
                      <div className="avatar placeholder">
                        <div className="bg-primary/10 text-primary rounded-2xl w-14 h-14 ring-4 ring-primary/5">
                          <span className="text-xl font-black">
                            {patient.name?.[0]?.toUpperCase() ?? "?"}
                          </span>
                        </div>
                      </div>

                      {/* Info */}
                      <div>
                        <p className="font-bold text-slate-800 text-lg leading-tight mb-1">{patient.name}</p>
                        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                          {patient.age && (
                            <span className="flex items-center gap-1.5 text-xs font-semibold text-slate-500">
                              <User2 size={13} className="text-slate-400" /> {patient.age} Years
                            </span>
                          )}
                          {patient.gender && (
                            <span className="badge badge-sm bg-slate-100 text-slate-600 border-none font-bold uppercase tracking-wider text-[10px]">
                              {patient.gender}
                            </span>
                          )}
                          {patient.email && (
                            <span className="flex items-center gap-1.5 text-xs font-medium text-slate-400">
                              <Mail size={13} /> {patient.email}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center justify-between md:justify-end gap-4 border-t md:border-t-0 pt-4 md:pt-0">
                      <div className="text-right hidden sm:block">
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Medical History</p>
                        <p className="text-sm font-bold text-slate-700">{patient.appointments?.length ?? 0} Total Visits</p>
                      </div>
                      <div className={`p-2 rounded-xl transition-colors ${isOpen ? 'bg-primary text-white' : 'bg-slate-50 text-slate-400 group-hover:bg-slate-100'}`}>
                        {isOpen ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                      </div>
                    </div>
                  </div>

                  {/* Expanded Section */}
                  {isOpen && (
                    <div className="px-6 py-6 bg-slate-50/80 border-t border-slate-100 animate-in slide-in-from-top-2 duration-300">
                      <div className="grid md:grid-cols-2 gap-8">
                        
                        {/* Upcoming Section */}
                        <div className="space-y-4">
                          <h4 className="flex items-center gap-2 text-xs font-black text-slate-400 uppercase tracking-[2px]">
                            <div className="w-2 h-2 rounded-full bg-emerald-500" />
                            Upcoming Visits
                          </h4>
                          {upcoming?.length > 0 ? (
                            <div className="space-y-3">
                              {upcoming.map((appt) => (
                                <AppointmentRow key={appt._id} appt={appt} />
                              ))}
                            </div>
                          ) : (
                            <div className="p-4 rounded-xl border border-dashed border-slate-300 text-center text-slate-400 text-xs">
                              No future appointments scheduled
                            </div>
                          )}
                        </div>

                        {/* Past Section */}
                        <div className="space-y-4">
                          <h4 className="flex items-center gap-2 text-xs font-black text-slate-400 uppercase tracking-[2px]">
                            <div className="w-2 h-2 rounded-full bg-slate-400" />
                            Visit History
                          </h4>
                          {past?.length > 0 ? (
                            <div className="space-y-3">
                              {past.map((appt) => (
                                <AppointmentRow key={appt._id} appt={appt} isPast />
                              ))}
                            </div>
                          ) : (
                            <div className="p-4 rounded-xl border border-dashed border-slate-300 text-center text-slate-400 text-xs">
                              No past records found
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function AppointmentRow({ appt, isPast }) {
  return (
    <div className={`flex items-center justify-between p-4 rounded-2xl border bg-white shadow-sm transition-all hover:border-primary/20 
      ${isPast ? 'opacity-80 grayscale-[0.3]' : 'ring-1 ring-emerald-500/5 border-emerald-100'}`}>
      <div className="flex items-center gap-3">
        <div className={`p-2.5 rounded-xl ${isPast ? 'bg-slate-50 text-slate-400' : 'bg-emerald-50 text-emerald-600'}`}>
          <Calendar size={18} />
        </div>
        <div>
          <p className="font-bold text-slate-800 text-sm">
            {new Date(appt.date).toLocaleDateString("en-IN", {
              day: "numeric", month: "short", year: "numeric",
            })}
          </p>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="flex items-center gap-1 text-[11px] font-medium text-slate-400">
              <Clock size={12} /> {appt.startTime}
            </span>
            {appt.reason && (
              <span className="text-[11px] font-medium text-slate-300">| {appt.reason}</span>
            )}
          </div>
        </div>
      </div>
      
      <span className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-wider border ${STATUS_STYLE[appt.status]}`}>
        {appt.status}
      </span>
    </div>
  );
}