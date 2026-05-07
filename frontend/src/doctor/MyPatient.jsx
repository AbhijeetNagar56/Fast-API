import { useState, useEffect } from "react";
import { ArrowLeft, ChevronDown, ChevronUp, Calendar, Clock, User2 } from "lucide-react";
import { Link } from "react-router";
import axiosInstance from "../api/axios"; // adjust path

const STATUS_STYLE = {
  pending:   "badge-warning",
  confirmed: "badge-success",
  cancelled: "badge-error",
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
    <div className="max-w-3xl mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Link to="/doctordash" className="text-gray-500 hover:text-gray-700">
          <ArrowLeft size={24} />
        </Link>
        <h1 className="text-2xl font-bold">My Patients</h1>
        <span className="badge badge-primary ml-1">{patients.length}</span>
      </div>

      {/* Search */}
      <input
        type="text"
        placeholder="Search patient by name..."
        className="input input-bordered w-full"
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
      />

      {/* List */}
      {loading ? (
        <div className="flex justify-center py-16">
          <span className="loading loading-spinner loading-lg" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-16 space-y-2">
          <p className="text-4xl">🧑‍⚕️</p>
          <p className="text-base-content/50">
            {searchTerm ? "No patients match your search." : "No patients registered yet."}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
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
                className="bg-base-100 border border-base-300 rounded-xl overflow-hidden shadow-sm"
              >
                {/* Patient row */}
                <div
                  className="flex items-center justify-between px-5 py-4 cursor-pointer hover:bg-base-200 transition-colors"
                  onClick={() => toggle(patient._id)}
                >
                  <div className="flex items-center gap-4">
                    {/* Avatar */}
                    <div className="avatar placeholder">
                      <div className="bg-primary text-primary-content rounded-full w-12">
                        <span className="text-lg font-bold">
                          {patient.name?.[0]?.toUpperCase() ?? "?"}
                        </span>
                      </div>
                    </div>

                    {/* Info */}
                    <div>
                      <p className="font-semibold text-base">{patient.name}</p>
                      <div className="flex gap-3 text-xs text-base-content/50 mt-0.5">
                        {patient.age && (
                          <span className="flex items-center gap-1">
                            <User2 size={11} /> {patient.age} yrs
                          </span>
                        )}
                        {patient.gender && (
                          <span className="capitalize">{patient.gender}</span>
                        )}
                        {patient.email && (
                          <span className="hidden sm:inline">{patient.email}</span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    {/* Appointment count pill */}
                    <span className="badge badge-ghost text-xs">
                      <Calendar size={11} className="mr-1" />
                      {patient.appointments?.length ?? 0} visits
                    </span>
                    {isOpen ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                  </div>
                </div>

                {/* Expanded appointment history */}
                {isOpen && (
                  <div className="border-t border-base-300 px-5 py-4 bg-base-50 space-y-4">

                    {/* Upcoming */}
                    {upcoming?.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-base-content/40 uppercase tracking-wide mb-2">
                          Upcoming
                        </p>
                        <div className="space-y-2">
                          {upcoming.map((appt) => (
                            <AppointmentRow key={appt._id} appt={appt} />
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Past */}
                    {past?.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-base-content/40 uppercase tracking-wide mb-2">
                          Past / Cancelled
                        </p>
                        <div className="space-y-2">
                          {past.map((appt) => (
                            <AppointmentRow key={appt._id} appt={appt} />
                          ))}
                        </div>
                      </div>
                    )}

                    {/* No appointments */}
                    {patient.appointments?.length === 0 && (
                      <p className="text-sm text-base-content/40 text-center py-2">
                        No appointment history yet.
                      </p>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* ── Small appointment row sub-component ── */
function AppointmentRow({ appt }) {
  return (
    <div className="flex items-center justify-between bg-base-200 rounded-lg px-3 py-2 text-sm">
      <div className="flex items-center gap-3">
        <Calendar size={14} className="text-primary shrink-0" />
        <div>
          <span className="font-medium">
            {new Date(appt.date).toLocaleDateString("en-IN", {
              day: "numeric", month: "short", year: "numeric",
            })}
          </span>
          <span className="text-base-content/50 ml-2 text-xs">
            <Clock size={11} className="inline mr-0.5" />
            {appt.startTime}
          </span>
        </div>
      </div>
      <div className="flex items-center gap-2">
        {appt.reason && (
          <span className="text-xs text-base-content/40 hidden sm:inline truncate max-w-32">
            {appt.reason}
          </span>
        )}
        <span className={`badge badge-sm ${STATUS_STYLE[appt.status]}`}>
          {appt.status}
        </span>
      </div>
    </div>
  );
}

