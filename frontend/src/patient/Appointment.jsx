import { useState, useEffect } from "react";
import FullCalendar from "@fullcalendar/react";
import dayGridPlugin from "@fullcalendar/daygrid";
import timeGridPlugin from "@fullcalendar/timegrid";
import interactionPlugin from "@fullcalendar/interaction";
import { ArrowLeft, X, Search, Calendar as CalIcon, Clock, User, Plus, Trash2 } from "lucide-react";
import { Link } from "react-router";
import axiosInstance from "../api/axios";

const STATUS_CONFIG = {
  pending: { class: "badge-warning", dot: "bg-warning" },
  confirmed: { class: "badge-success", dot: "bg-success" },
  cancelled: { class: "badge-error", dot: "bg-error" },
};

export default function AppointmentCalendar() {
  const [events, setEvents] = useState([]);
  const [meetings, setMeetings] = useState([]);
  const [doctors, setDoctors] = useState([]);
  const [doctorSearch, setDoctorSearch] = useState("");
  const [showModal, setShowModal] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [form, setForm] = useState({
    doctorId: "",
    doctorName: "",
    date: "",
    startTime: "",
    reason: "",
  });

  useEffect(() => {
    fetchAppointments();
  }, []);

  const fetchAppointments = async () => {
    try {
      const { data } = await axiosInstance.get("/home/appointments");
      setMeetings(data);
      setEvents(
        data
          .filter((m) => m.status !== "cancelled")
          .map((m) => ({
            id: m._id,
            title: `Dr. ${m.doctor?.name}`,
            start: `${m.date.split("T")[0]}T${m.startTime}`,
            backgroundColor: m.status === "confirmed" ? "#dcfce7" : "#fef3c7",
            textColor: m.status === "confirmed" ? "#166534" : "#92400e",
            borderColor: m.status === "confirmed" ? "#22c55e" : "#f59e0b",
            extendedProps: { ...m },
          }))
      );
    } catch (err) {
      console.error("Failed to fetch appointments", err);
    }
  };

  /* ... (Logic for Search, Submit, and Cancel remains same as your original) ... */
  useEffect(() => {
    if (!doctorSearch.trim()) { setDoctors([]); return; }
    const delay = setTimeout(async () => {
      try {
        const { data } = await axiosInstance.get(`/home/appointments/doctors?name=${doctorSearch}`);
        setDoctors(data);
      } catch { setDoctors([]); }
    }, 400);
    return () => clearTimeout(delay);
  }, [doctorSearch]);

  const handleSubmit = async () => {
    setError("");
    if (!form.doctorId || !form.date || !form.startTime) {
      setError("Please fill in all required fields.");
      return;
    }
    setLoading(true);
    try {
      await axiosInstance.post("/home/appointments", {
        doctorId: form.doctorId,
        date: form.date,
        startTime: form.startTime,
        reason: form.reason,
      });
      setShowModal(false);
      resetForm();
      fetchAppointments();
    } catch (err) {
      setError(err.response?.data?.msg || "Booking failed.");
    } finally { setLoading(false); }
  };

  const handleCancel = async (id) => {
    if (!window.confirm("Are you sure you want to cancel this appointment?")) return;
    try {
      await axiosInstance.delete(`/home/appointments/${id}`);
      fetchAppointments();
    } catch (err) { alert("Could not cancel."); }
  };

  const resetForm = () => {
    setForm({ doctorId: "", doctorName: "", date: "", startTime: "", reason: "" });
    setDoctorSearch("");
  };

  const closeModal = () => { setShowModal(false); resetForm(); setError(""); };

  return (
    <div className="min-h-screen bg-slate-50/50 p-4 md:p-8">
      <div className="max-w-7xl mx-auto space-y-6">
        
        {/* ── Header Card ── */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center bg-white p-6 rounded-2xl shadow-sm border border-slate-100 gap-4">
          <div className="flex items-center gap-4">
            <Link to="/" className="btn btn-ghost btn-circle bg-slate-50 hover:bg-slate-100">
              <ArrowLeft size={20} className="text-slate-600" />
            </Link>
            <div>
              <h2 className="text-2xl font-bold text-slate-800 tracking-tight">Appointments</h2>
              <p className="text-slate-500 text-sm">Schedule and manage your consultations</p>
            </div>
          </div>
          <button 
            onClick={() => setShowModal(true)} 
            className="btn btn-primary shadow-lg shadow-primary/20 px-6 rounded-xl border-none"
          >
            <Plus size={18} className="mr-1" /> New Appointment
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          
          {/* ── Main Calendar Section ── */}
          <div className="lg:col-span-8 bg-white p-6 rounded-2xl shadow-sm border border-slate-100">
            <div className="calendar-container transition-all">
              <FullCalendar
                plugins={[dayGridPlugin, timeGridPlugin, interactionPlugin]}
                initialView="dayGridMonth"
                headerToolbar={{
                  left: "prev,next today",
                  center: "title",
                  right: "dayGridMonth,timeGridWeek",
                }}
                events={events}
                eventClassNames="rounded-md border-l-4 px-1 py-0.5 text-xs font-medium cursor-pointer transition-transform hover:scale-102"
                height="700px"
              />
            </div>
          </div>

          {/* ── Side Appointments List ── */}
          <div className="lg:col-span-4 space-y-4">
            <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-100 flex flex-col h-[700px]">
              <h3 className="text-lg font-bold text-slate-800 mb-4 flex items-center gap-2">
                <CalIcon size={18} className="text-primary" /> Upcoming Agenda
              </h3>
              
              <div className="flex-1 overflow-y-auto space-y-3 pr-2 scrollbar-hide">
                {meetings.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-center p-6 opacity-40">
                    <CalIcon size={48} className="mb-2" />
                    <p className="text-sm">No appointments scheduled yet</p>
                  </div>
                ) : (
                  meetings.map((m) => (
                    <div key={m._id} className="group relative bg-slate-50 border border-slate-100 rounded-xl p-4 transition-all hover:bg-white hover:shadow-md hover:border-primary/20">
                      <div className="flex justify-between items-start">
                        <div>
                          <p className="font-bold text-slate-800">Dr. {m.doctor?.name}</p>
                          <p className="text-xs font-medium text-primary mb-2 uppercase tracking-wider">{m.doctor?.specialization}</p>
                        </div>
                        <span className={`badge badge-sm font-bold border-none py-3 px-3 ${STATUS_CONFIG[m.status].class} text-white/90`}>
                          {m.status}
                        </span>
                      </div>
                      
                      <div className="flex items-center gap-4 text-xs text-slate-500 font-medium">
                        <div className="flex items-center gap-1">
                          <CalIcon size={14} /> {new Date(m.date).toLocaleDateString()}
                        </div>
                        <div className="flex items-center gap-1">
                          <Clock size={14} /> {m.startTime}
                        </div>
                      </div>

                      {m.status !== "cancelled" && (
                        <button 
                          className="absolute bottom-3 right-3 opacity-0 group-hover:opacity-100 btn btn-ghost btn-circle btn-xs text-error transition-all"
                          onClick={() => handleCancel(m._id)}
                        >
                          <Trash2 size={14} />
                        </button>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>

        {/* ── Professional Booking Modal ── */}
        {showModal && (
          <div className="fixed inset-0 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center z-50 p-4 transition-all">
            <div className="bg-white rounded-3xl shadow-2xl w-full max-w-lg overflow-hidden animate-in zoom-in-95 duration-200">
              <div className="p-6 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
                <h3 className="text-xl font-bold text-slate-800">Schedule Consultation</h3>
                <button onClick={closeModal} className="btn btn-ghost btn-circle btn-sm"><X size={20} /></button>
              </div>

              <div className="p-8 space-y-5">
                {error && <div className="alert alert-error rounded-xl py-3 text-sm text-white shadow-lg shadow-error/20 border-none">{error}</div>}

                {/* Search */}
                <div className="space-y-2">
                  <label className="text-sm font-bold text-slate-700 flex items-center gap-2"><User size={16}/> Select Doctor</label>
                  <div className="relative">
                    <Search size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" />
                    <input
                      className="input input-bordered w-full pl-12 rounded-xl bg-slate-50 border-slate-200 focus:bg-white"
                      placeholder="Search by name or specialty..."
                      value={doctorSearch}
                      onChange={(e) => setDoctorSearch(e.target.value)}
                    />
                  </div>
                  {/* Dropdown UI */}
                  {doctors.length > 0 && (
                    <div className="absolute z-10 w-full max-w-[448px] bg-white border border-slate-100 shadow-2xl rounded-xl mt-1 max-h-52 overflow-y-auto">
                      {doctors.map((d) => (
                        <button 
                          key={d._id} 
                          className="flex flex-col w-full px-4 py-3 hover:bg-slate-50 border-b last:border-0 border-slate-50 text-left"
                          onClick={() => {
                            setForm({ ...form, doctorId: d._id, doctorName: d.name });
                            setDoctorSearch(d.name);
                            setDoctors([]);
                          }}
                        >
                          <span className="font-bold text-slate-800">Dr. {d.name}</span>
                          <span className="text-xs text-slate-400 uppercase tracking-tighter">{d.specialization}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                {/* Date & Time */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm font-bold text-slate-700">Preferred Date</label>
                    <input type="date" className="input input-bordered w-full rounded-xl" min={new Date().toISOString().split("T")[0]} value={form.date} onChange={(e) => setForm({ ...form, date: e.target.value })} />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-bold text-slate-700">Preferred Time</label>
                    <input type="time" className="input input-bordered w-full rounded-xl" value={form.startTime} onChange={(e) => setForm({ ...form, startTime: e.target.value })} />
                  </div>
                </div>

                {/* Reason */}
                <div className="space-y-2">
                  <label className="text-sm font-bold text-slate-700">Reason for Visit</label>
                  <textarea className="textarea textarea-bordered w-full rounded-xl h-24 bg-slate-50" placeholder="A brief description of your health concern..." value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
                </div>

                <div className="flex gap-3 pt-2">
                  <button className="btn btn-ghost flex-1 rounded-xl" onClick={closeModal}>Discard</button>
                  <button className="btn btn-primary flex-2 rounded-xl shadow-lg shadow-primary/30 border-none" onClick={handleSubmit} disabled={loading}>
                    {loading ? <span className="loading loading-spinner" /> : "Confirm Appointment"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
      
      {/* ── Custom CSS for Calendar (Add to your global CSS or inside a <style> tag) ── */}
      <style>{`
        .fc { --fc-border-color: #f1f5f9; --fc-button-bg-color: #3b82f6; --fc-button-border-color: #3b82f6; --fc-button-hover-bg-color: #2563eb; font-family: inherit; }
        .fc .fc-toolbar-title { font-size: 1.25rem; font-weight: 700; color: #1e293b; }
        .fc .fc-button-primary { border-radius: 8px; text-transform: capitalize; font-weight: 600; padding: 0.5rem 1rem; }
        .fc .fc-daygrid-day-number { font-weight: 600; color: #64748b; font-size: 0.85rem; }
        .fc .fc-col-header-cell-cushion { color: #94a3b8; font-weight: 700; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }
        .fc-event-title { white-space: normal !important; }
      `}</style>
    </div>
  );
}