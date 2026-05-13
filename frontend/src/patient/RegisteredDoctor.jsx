import { Phone, Mail, Building2, Star, CalendarPlus, UserMinus } from "lucide-react";
import { useNavigate } from "react-router";

export default function RegisteredDoctor({ doctors = [], onRemove, onChangeClick }) {
  const navigate = useNavigate();

  if (doctors.length === 0) {
    return (
      <div className="card bg-base-200 border border-dashed border-base-300">
        <div className="card-body items-center text-center py-10">
          <div className="text-5xl mb-2">🩺</div>
          <h3 className="card-title text-base-content/60">No Doctors Registered</h3>
          <p className="text-sm text-base-content/40">
            Search and register up to 3 primary doctors.
          </p>
          <button className="btn btn-primary btn-sm mt-2" onClick={onChangeClick}>
            Find a Doctor
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Slot indicators */}
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-base-content/60">
          Your Doctors
        </p>
        <div className="flex gap-1.5 items-center">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className={`w-3 h-3 rounded-full border-2 transition-colors ${
                i < doctors.length
                  ? "bg-primary border-primary"
                  : "bg-base-300 border-base-300"
              }`}
            />
          ))}
          <span className="text-xs text-base-content/40 ml-1">
            {doctors.length}/3
          </span>
        </div>
      </div>

      {/* Doctor cards */}
      {doctors.map((doctor) => (
        <div key={doctor._id} className="card bg-base-100 shadow border border-base-300">
          <div className="card-body gap-3 py-4">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="avatar placeholder">
                  <div className="bg-primary text-primary-content rounded-full w-12">
                    <span className="text-lg font-bold">
                      {doctor.name?.[0]?.toUpperCase()}
                    </span>
                  </div>
                </div>
                <div>
                  <p className="font-bold">Dr. {doctor.name}</p>
                  <p className="text-xs text-primary font-medium">{doctor.specialization}</p>
                </div>
              </div>
              <span className="badge badge-success badge-sm">Registered</span>
            </div>

            <div className="grid grid-cols-2 gap-1.5 text-xs text-base-content/60">
              {doctor.hospital && (
                <span className="flex items-center gap-1">
                  <Building2 size={12} className="text-primary" /> {doctor.hospital}
                </span>
              )}
              {doctor.experience && (
                <span className="flex items-center gap-1">
                  <Star size={12} className="text-warning" /> {doctor.experience} yrs exp
                </span>
              )}
              {doctor.contact && (
                <span className="flex items-center gap-1">
                  <Phone size={12} className="text-success" /> {doctor.contact}
                </span>
              )}
              {doctor.email && (
                <span className="flex items-center gap-1 truncate">
                  <Mail size={12} className="text-info shrink-0" />
                  <span className="truncate">{doctor.email}</span>
                </span>
              )}
            </div>

            <div className="card-actions justify-end gap-2 pt-1">
              <button
                className="btn btn-ghost btn-xs text-error gap-1"
                onClick={() => onRemove(doctor._id)}
              >
                <UserMinus size={13} /> Remove
              </button>
              <button
                className="btn btn-primary btn-xs gap-1"
                onClick={() => navigate("/appointments")}
              >
                <CalendarPlus size={13} /> Book
              </button>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}