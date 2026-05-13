import { useState, useEffect } from "react";
import RegisteredDoctor from "./RegisteredDoctor";
import { ArrowLeft, Search, Building2, Star, Loader2, X, ArrowLeftRight } from "lucide-react";
import { Link } from "react-router";
import axiosInstance from "../api/axios";

const MAX = 3;

export default function MyDoctor() {
  const [searchTerm, setSearchTerm]       = useState("");
  const [searchResults, setSearchResults] = useState([]);
  const [searchLoading, setSearchLoading] = useState(false);
  const [myDoctors, setMyDoctors]         = useState([]);
  const [pageLoading, setPageLoading]     = useState(true);
  const [actionId, setActionId]           = useState(null);

  // Swap dialog state
  const [swapModal, setSwapModal]         = useState(false);
  const [pendingDoctor, setPendingDoctor] = useState(null); // doctor user wants to add
  const [swapTargetId, setSwapTargetId]  = useState("");   // doctor to remove

  useEffect(() => { fetchMyDoctors(); }, []);

  const fetchMyDoctors = async () => {
    setPageLoading(true);
    try {
      const { data } = await axiosInstance.get("/home/my-doctors");
      setMyDoctors(data);
    } catch (err) {
      console.error(err);
    } finally {
      setPageLoading(false);
    }
  };

  /* ── Debounced search ── */
  useEffect(() => {
    if (!searchTerm.trim()) { setSearchResults([]); return; }
    const delay = setTimeout(async () => {
      setSearchLoading(true);
      try {
        const { data } = await axiosInstance.get(`/home/doctors?name=${searchTerm}`);
        setSearchResults(data);
      } catch {
        setSearchResults([]);
      } finally {
        setSearchLoading(false);
      }
    }, 400);
    return () => clearTimeout(delay);
  }, [searchTerm]);

  /* ── Register doctor ── */
  const handleRegister = async (doctor) => {
    // Already registered
    if (myDoctors.some((d) => d._id === doctor._id)) return;

    // At limit → open swap dialog
    if (myDoctors.length >= MAX) {
      setPendingDoctor(doctor);
      setSwapTargetId(myDoctors[0]._id); // default: replace first
      setSwapModal(true);
      return;
    }

    setActionId(doctor._id);
    try {
      const { data } = await axiosInstance.post("/home/my-doctors", { doctorId: doctor._id });
      setMyDoctors(data.doctors);
      setSearchTerm("");
      setSearchResults([]);
    } catch (err) {
      alert(err.response?.data?.msg || "Failed to register doctor.");
    } finally {
      setActionId(null);
    }
  };

  /* ── Confirm swap ── */
  const handleSwapConfirm = async () => {
    if (!swapTargetId || !pendingDoctor) return;
    setActionId(pendingDoctor._id);
    try {
      const { data } = await axiosInstance.patch("/home/my-doctors/swap", {
        removeId: swapTargetId,
        addId: pendingDoctor._id,
      });
      setMyDoctors(data.doctors);
      setSwapModal(false);
      setPendingDoctor(null);
      setSearchTerm("");
      setSearchResults([]);
    } catch (err) {
      alert(err.response?.data?.msg || "Swap failed.");
    } finally {
      setActionId(null);
    }
  };

  /* ── Remove doctor ── */
  const handleRemove = async (doctorId) => {
    if (!window.confirm("Remove this doctor from your list?")) return;
    try {
      await axiosInstance.delete(`/home/my-doctors/${doctorId}`);
      setMyDoctors((prev) => prev.filter((d) => d._id !== doctorId));
    } catch (err) {
      alert(err.response?.data?.msg || "Failed to remove.");
    }
  };

  const isRegistered = (doc) => myDoctors.some((d) => d._id === doc._id);
  const atLimit      = myDoctors.length >= MAX;

  return (
    <div className="max-w-2xl mx-auto p-6 space-y-8">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Link to="/" className="text-gray-500 hover:text-gray-700">
          <ArrowLeft size={24} />
        </Link>
        <h1 className="text-2xl font-bold">My Doctors</h1>
      </div>

      {/* Limit banner */}
      {atLimit && (
        <div className="alert alert-warning py-2 text-sm">
          <span>
            You've reached the 3-doctor limit. Register a new one to swap out an existing doctor.
          </span>
        </div>
      )}

      {/* Registered doctors */}
      {pageLoading ? (
        <div className="flex justify-center py-10">
          <span className="loading loading-spinner loading-lg" />
        </div>
      ) : (
        <RegisteredDoctor
          doctors={myDoctors}
          onRemove={handleRemove}
          onChangeClick={() => document.getElementById("search-input").focus()}
        />
      )}

      <div className="divider">Find a Doctor</div>

      {/* Search */}
      <div className="relative">
        <Search size={16} className="absolute left-3 top-3.5 text-gray-400" />
        <input
          id="search-input"
          type="text"
          placeholder="Search by name or specialization..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="input input-bordered w-full pl-9"
        />
        {searchLoading && (
          <Loader2 size={16} className="absolute right-3 top-3.5 text-gray-400 animate-spin" />
        )}
      </div>

      {/* Results */}
      {searchTerm && (
        <div className="space-y-3">
          {searchResults.length === 0 && !searchLoading ? (
            <p className="text-center text-base-content/50 py-4">No doctors found.</p>
          ) : (
            searchResults.map((doc) => {
              const registered = isRegistered(doc);
              return (
                <div key={doc._id} className="card bg-base-200 border border-base-300">
                  <div className="card-body py-4 flex-row items-center justify-between gap-4">
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="avatar placeholder shrink-0">
                        <div className="bg-primary/20 text-primary rounded-full w-11">
                          <span className="font-bold">{doc.name?.[0]?.toUpperCase()}</span>
                        </div>
                      </div>
                      <div className="min-w-0">
                        <p className="font-semibold truncate">Dr. {doc.name}</p>
                        <p className="text-xs text-primary">{doc.specialization}</p>
                        <div className="flex gap-3 mt-0.5 text-xs text-base-content/50">
                          {doc.hospital && (
                            <span className="flex items-center gap-1">
                              <Building2 size={11} /> {doc.hospital}
                            </span>
                          )}
                          {doc.experience && (
                            <span className="flex items-center gap-1">
                              <Star size={11} /> {doc.experience} yrs
                            </span>
                          )}
                        </div>
                      </div>
                    </div>

                    <button
                      className={`btn btn-sm shrink-0 gap-1 ${
                        registered
                          ? "btn-success pointer-events-none"
                          : atLimit
                          ? "btn-warning"
                          : "btn-primary"
                      }`}
                      onClick={() => !registered && handleRegister(doc)}
                      disabled={actionId === doc._id}
                    >
                      {actionId === doc._id ? (
                        <span className="loading loading-spinner loading-xs" />
                      ) : registered ? (
                        "✓ Registered"
                      ) : atLimit ? (
                        <><ArrowLeftRight size={13} /> Swap</>
                      ) : (
                        "Register"
                      )}
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* ── Swap Dialog ── */}
      {swapModal && pendingDoctor && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
          <div className="bg-base-100 rounded-xl p-6 w-full max-w-sm space-y-4 relative">
            <button
              className="absolute top-3 right-3 btn btn-ghost btn-xs"
              onClick={() => setSwapModal(false)}
            >
              <X size={16} />
            </button>

            <h3 className="text-lg font-bold">Swap a Doctor</h3>
            <p className="text-sm text-base-content/60">
              You already have 3 doctors. Choose one to replace with{" "}
              <span className="font-semibold text-base-content">
                Dr. {pendingDoctor.name}
              </span>
              .
            </p>

            {/* Pick which doctor to remove */}
            <div className="space-y-2">
              {myDoctors.map((d) => (
                <label
                  key={d._id}
                  className={`flex items-center gap-3 p-3 rounded-xl border-2 cursor-pointer transition-colors ${
                    swapTargetId === d._id
                      ? "border-primary bg-primary/5"
                      : "border-base-300 hover:border-base-400"
                  }`}
                >
                  <input
                    type="radio"
                    name="swapTarget"
                    className="radio radio-primary radio-sm"
                    checked={swapTargetId === d._id}
                    onChange={() => setSwapTargetId(d._id)}
                  />
                  <div>
                    <p className="font-medium text-sm">Dr. {d.name}</p>
                    <p className="text-xs text-base-content/50">{d.specialization}</p>
                  </div>
                </label>
              ))}
            </div>

            <div className="flex justify-end gap-2 pt-1">
              <button className="btn btn-ghost btn-sm" onClick={() => setSwapModal(false)}>
                Cancel
              </button>
              <button
                className="btn btn-primary btn-sm gap-1"
                onClick={handleSwapConfirm}
                disabled={!swapTargetId || actionId === pendingDoctor._id}
              >
                {actionId === pendingDoctor._id ? (
                  <span className="loading loading-spinner loading-xs" />
                ) : (
                  <><ArrowLeftRight size={13} /> Confirm Swap</>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}