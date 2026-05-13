import { useEffect, useState } from "react";
import axiosInstance from "../api/axios";
import { CheckCircle, XCircle, Clock, ChevronDown, ChevronUp } from "lucide-react";

const STATUS_STYLE = {
  pending:   { badge: "badge-warning",  icon: <Clock size={14} /> },
  confirmed: { badge: "badge-success",  icon: <CheckCircle size={14} /> },
  cancelled: { badge: "badge-error",    icon: <XCircle size={14} /> },
};

const FILTERS = ["all", "pending", "confirmed", "cancelled"];

export default function MeetingRequests() {
  const [meetings, setMeetings]   = useState([]);
  const [loading, setLoading]     = useState(true);
  const [filter, setFilter]       = useState("pending");
  const [expanded, setExpanded]   = useState(null);
  const [acting, setActing]       = useState(null); // id currently being approved/denied

  useEffect(() => {
    fetchMeetings();
  }, []);

  const fetchMeetings = async () => {
    setLoading(true);
    try {
      const { data } = await axiosInstance.get("/doctor/appointments");
      setMeetings(data);
    } catch (err) {
      console.error("Failed to load appointments", err);
    } finally {
      setLoading(false);
    }
  };

  const handleAction = async (id, status) => {
    setActing(id);
    try {
      await axiosInstance.patch(`/doctor/appointments/${id}`, { status });
      // Optimistically update local state
      setMeetings((prev) =>
        prev.map((m) => (m._id === id ? { ...m, status } : m))
      );
    } catch (err) {
      alert(err.response?.data?.msg || "Action failed.");
    } finally {
      setActing(null);
    }
  };

  const filtered = filter === "all"
    ? meetings
    : meetings.filter((m) => m.status === filter);

  const counts = {
    all:       meetings.length,
    pending:   meetings.filter((m) => m.status === "pending").length,
    confirmed: meetings.filter((m) => m.status === "confirmed").length,
    cancelled: meetings.filter((m) => m.status === "cancelled").length,
  };

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold">Meeting Requests</h2>
        <button
          onClick={fetchMeetings}
          className="btn btn-ghost btn-sm"
        >
          Refresh
        </button>
      </div>

      {/* Filter tabs */}
      <div className="tabs tabs-boxed w-fit">
        {FILTERS.map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`tab capitalize ${filter === f ? "tab-active" : ""}`}
          >
            {f}
            <span className="ml-1.5 badge badge-sm">{counts[f]}</span>
          </button>
        ))}
      </div>

      {/* List */}
      {loading ? (
        <div className="flex justify-center py-12">
          <span className="loading loading-spinner loading-lg" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-12 text-gray-400">
          No {filter === "all" ? "" : filter} requests found.
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((m) => {
            const isExpanded = expanded === m._id;
            const isActing   = acting === m._id;
            const { badge, icon } = STATUS_STYLE[m.status];

            return (
              <div
                key={m._id}
                className="bg-base-200 rounded-xl overflow-hidden border border-base-300"
              >
                {/* Card header — always visible */}
                <div
                  className="flex items-center justify-between px-4 py-3 cursor-pointer hover:bg-base-300 transition-colors"
                  onClick={() => setExpanded(isExpanded ? null : m._id)}
                >
                  <div className="flex items-center gap-3">
                    <div className="avatar placeholder">
                      <div className="bg-primary text-primary-content rounded-full w-10">
                        <span className="text-sm font-bold">
                          {m.patient?.name?.[0]?.toUpperCase() ?? "?"}
                        </span>
                      </div>
                    </div>
                    <div>
                      <p className="font-semibold">{m.patient?.name ?? "Unknown Patient"}</p>
                      <p className="text-xs text-gray-500">
                        {new Date(m.date).toLocaleDateString("en-IN", {
                          day: "numeric", month: "short", year: "numeric",
                        })}{" "}
                        at <span className="font-medium">{m.startTime}</span>
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className={`badge ${badge} gap-1`}>
                      {icon} {m.status}
                    </span>
                    {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                  </div>
                </div>

                {/* Expanded detail */}
                {isExpanded && (
                  <div className="px-4 pb-4 pt-1 border-t border-base-300 space-y-3">
                    {/* Patient info row */}
                    <div className="flex gap-6 text-sm">
                      {m.patient?.age && (
                        <span>
                          <span className="text-gray-400">Age: </span>
                          <span className="font-medium">{m.patient.age}</span>
                        </span>
                      )}
                      {m.patient?.gender && (
                        <span>
                          <span className="text-gray-400">Gender: </span>
                          <span className="font-medium capitalize">{m.patient.gender}</span>
                        </span>
                      )}
                    </div>

                    {/* Reason */}
                    <div className="bg-base-100 rounded-lg px-3 py-2 text-sm">
                      <span className="text-gray-400 text-xs uppercase tracking-wide">Reason</span>
                      <p className="mt-0.5">{m.reason || "No reason provided"}</p>
                    </div>

                    {/* Action buttons — only for pending */}
                    {m.status === "pending" && (
                      <div className="flex gap-2 justify-end pt-1">
                        <button
                          className="btn btn-error btn-sm gap-1"
                          disabled={isActing}
                          onClick={() => handleAction(m._id, "cancelled")}
                        >
                          {isActing ? (
                            <span className="loading loading-spinner loading-xs" />
                          ) : (
                            <XCircle size={15} />
                          )}
                          Deny
                        </button>
                        <button
                          className="btn btn-success btn-sm gap-1"
                          disabled={isActing}
                          onClick={() => handleAction(m._id, "confirmed")}
                        >
                          {isActing ? (
                            <span className="loading loading-spinner loading-xs" />
                          ) : (
                            <CheckCircle size={15} />
                          )}
                          Approve
                        </button>
                      </div>
                    )}

                    {/* Already actioned label */}
                    {m.status !== "pending" && (
                      <p className="text-xs text-gray-400 text-right">
                        This request has been {m.status}.
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