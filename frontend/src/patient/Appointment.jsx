import { useEffect, useMemo, useState } from "react";
import axiosInstance from "../api/axios";
import { Link } from "react-router";
import { ArrowLeft } from "lucide-react";

const BASE_SPECIALITIES = [
  "General Physician",
  "Cardiologist",
  "Dermatologist",
  "Neurologist",
];

const normalizeSpeciality = (value) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized || normalized === "general") return "General Physician";
  if (normalized === "general medicine") return "General Physician";
  return String(value).trim();
};

export default function BookAppointment() {
  const [step, setStep] = useState(1);

  const [speciality, setSpeciality] = useState("");
  const [allDoctors, setAllDoctors] = useState([]);
  const [doctorList, setDoctorList] = useState([]);
  const [selectedDoctor, setSelectedDoctor] = useState(null);

  const [date, setDate] = useState("");
  const [slots, setSlots] = useState([]);
  const [slotsLoading, setSlotsLoading] = useState(false);
  const [selectedSlot, setSelectedSlot] = useState(null);

  const [patient, setPatient] = useState({
    name: "",
    phone: "",
    age: "",
    notes: "",
  });

  const [bookingLoading, setBookingLoading] = useState(false);
  const [bookingError, setBookingError] = useState("");
  const [bookingSuccess, setBookingSuccess] = useState(null);
  const [myAppointments, setMyAppointments] = useState([]);
  const [appointmentsLoading, setAppointmentsLoading] = useState(false);
  const [appointmentsError, setAppointmentsError] = useState("");

  useEffect(() => {
    const loadDoctors = async () => {
      try {
        const { data } = await axiosInstance.get("/slots/doctors");
        const doctors = (Array.isArray(data) ? data : []).map((doc) => ({
          id: doc._id,
          name: doc.name,
          speciality: normalizeSpeciality(doc.specialization),
          hospital: doc.hospital || "Unknown Hospital",
        }));
        setAllDoctors(doctors);
      } catch (error) {
        console.error("Failed to load doctors:", error);
        setAllDoctors([]);
      }
    };

    loadDoctors();
  }, []);

  const loadMyAppointments = async () => {
    setAppointmentsLoading(true);
    setAppointmentsError("");
    try {
      const { data } = await axiosInstance.get("/home/appointments");
      setMyAppointments(Array.isArray(data) ? data : []);
    } catch (error) {
      setAppointmentsError(
        error.response?.data?.msg || "Failed to load your appointments"
      );
      setMyAppointments([]);
    } finally {
      setAppointmentsLoading(false);
    }
  };

  useEffect(() => {
    loadMyAppointments();
  }, []);

  const specialities = useMemo(() => {
    const dynamic = allDoctors.map((doc) => doc.speciality).filter(Boolean);
    return [...new Set([...BASE_SPECIALITIES, ...dynamic])];
  }, [allDoctors]);

  useEffect(() => {
    if (!speciality) {
      setDoctorList(allDoctors);
      setSelectedDoctor(null);
      return;
    }

    const filtered = allDoctors.filter((doc) => doc.speciality === speciality);
    setDoctorList(filtered);
    setSelectedDoctor(null);
    setSlots([]);
    setSelectedSlot(null);
  }, [speciality, allDoctors]);

  const handleSelectDoctor = (doc) => {
    setSelectedDoctor(doc);
    setStep(2);
    setSlots([]);
    setSelectedSlot(null);
    setBookingError("");
    setBookingSuccess(null);
  };

  const handleLoadSlots = async () => {
    if (!date || !selectedDoctor) return;

    setSlotsLoading(true);
    setSlots([]);
    setSelectedSlot(null);
    setBookingError("");
    setBookingSuccess(null);

    try {
      const { data } = await axiosInstance.get(`/slots/${selectedDoctor.id}/${date}`);
      setSlots(Array.isArray(data) ? data : []);
    } catch (err) {
      setBookingError(err.response?.data?.message || "Failed to fetch slots");
    } finally {
      setSlotsLoading(false);
    }
  };

  const handleConfirm = async () => {
    if (!selectedDoctor || !selectedSlot || !date) return;

    if (!patient.name || !patient.phone) {
      setBookingError("Please fill your name and phone number.");
      return;
    }

    setBookingLoading(true);
    setBookingError("");
    setBookingSuccess(null);

    try {
      const { data } = await axiosInstance.post("/slots/book", {
        slotId: selectedSlot._id,
        patient: {
          name: patient.name,
          phone: patient.phone,
          age: patient.age,
          notes: patient.notes,
        },
      });

      setBookingSuccess({
        bookingId: data?.appointment?.bookingId,
        doctor: selectedDoctor,
        date,
        slot: selectedSlot.time,
      });

      setSlots((prev) =>
        prev.map((s) =>
          selectedSlot._id === s._id
            ? { ...s, status: "booked" }
            : s
        )
      );

      setStep(3);
      await loadMyAppointments();
    } catch (err) {
      setBookingError(err.response?.data?.message || "Booking failed");
    } finally {
      setBookingLoading(false);
    }
  };

  const resetAll = () => {
    setStep(1);
    setSpeciality("");
    setDoctorList([]);
    setSelectedDoctor(null);
    setDate("");
    setSlots([]);
    setSelectedSlot(null);
    setPatient({ name: "", phone: "", age: "", notes: "" });
    setBookingError("");
    setBookingSuccess(null);
  };

  const toggleSelectedSlot = (slot) => {
    if (slot.status !== "available") return;
    setSelectedSlot((prev) => (prev?._id === slot._id ? null : slot));
  };

  return (
    <div className="max-w-5xl mx-auto px-4 py-10">
      <div className="mb-6">
        <Link to="/services" className="btn btn-ghost btn-circle">
          <ArrowLeft size={22} />
        </Link>
        <h1 className="text-3xl font-bold text-[#14532d] mb-1">
          Book Appointment
        </h1>
        <p className="text-sm text-gray-600">
          Choose a speciality, select your doctor, pick a time and confirm your
          visit.
        </p>
      </div>

      <div className="flex flex-wrap gap-4 mb-8">
        {[
          { id: 1, label: "Speciality" },
          { id: 2, label: "Date & Slot" },
          { id: 3, label: "Your Details" },
        ].map((s) => (
          <div
            key={s.id}
            className={`flex items-center gap-2 px-4 py-2 rounded-full text-sm border ${
              step === s.id
                ? "bg-[#2ecc71] text-white border-[#2ecc71]"
                : step > s.id
                ? "bg-[#e6f9ee] text-[#14532d] border-[#a7e8c3]"
                : "bg-white text-gray-500 border-gray-300"
            }`}
          >
            <span className="font-semibold">{s.id}</span>
            <span>{s.label}</span>
          </div>
        ))}
      </div>

      <div className="bg-white rounded-2xl shadow-md p-6 grid gap-8 md:grid-cols-3">
        <div className="md:col-span-1 border-r border-gray-100 pr-0 md:pr-6">
          <div className="mb-5">
            <label className="block text-xs font-semibold text-gray-500 mb-1 uppercase">
              Speciality
            </label>
            <select
              className="w-full border rounded-lg px-3 py-2 text-sm"
              value={speciality}
              onChange={(e) => setSpeciality(e.target.value)}
            >
              <option value="">All specialities</option>
              {specialities.map((sp) => (
                <option key={sp} value={sp}>
                  {sp}
                </option>
              ))}
            </select>
          </div>

          <div className="mb-5">
            <label className="block text-xs font-semibold text-gray-500 mb-1 uppercase">
              Doctor
            </label>
            {allDoctors.length === 0 && (
              <p className="text-xs text-gray-500">
                No doctors have published slots yet.
              </p>
            )}
            {allDoctors.length > 0 && doctorList.length === 0 && (
              <p className="text-xs text-gray-500">
                No doctors found for this speciality.
              </p>
            )}
            <div className="mt-2 space-y-2 max-h-52 overflow-y-auto pr-1">
              {doctorList.map((doc) => (
                <button
                  key={doc.id}
                  type="button"
                  onClick={() => handleSelectDoctor(doc)}
                  className={`w-full text-left border rounded-lg px-3 py-2 text-sm ${
                    selectedDoctor?.id === doc.id
                      ? "border-[#2ecc71] bg-[#e6f9ee]"
                      : "border-gray-200 hover:border-[#2ecc71]/60"
                  }`}
                >
                  <div className="font-semibold text-[#14532d]">{doc.name}</div>
                  <div className="text-xs text-gray-500">
                    {doc.speciality} - {doc.hospital}
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="md:col-span-1">
          <div className="mb-4">
            <label className="block text-xs font-semibold text-gray-500 mb-1 uppercase">
              Choose Date
            </label>
            <input
              type="date"
              className="w-full border rounded-lg px-3 py-2 text-sm"
              value={date}
              min={new Date().toISOString().split("T")[0]}
              onChange={(e) => setDate(e.target.value)}
            />
          </div>

          <button
            type="button"
            disabled={!selectedDoctor || !date}
            onClick={handleLoadSlots}
            className={`w-full mb-3 text-sm font-semibold rounded-lg px-3 py-2 ${
              !selectedDoctor || !date
                ? "bg-gray-200 text-gray-400"
                : "bg-[#2ecc71] text-white hover:bg-[#219150]"
            }`}
          >
            {slotsLoading ? "Loading Slots..." : "Show Available Slots"}
          </button>

          <p className="text-xs text-gray-500 mb-2">
            Select one slot for this day.
          </p>

          <div className="mt-2 grid grid-cols-2 sm:grid-cols-3 gap-2">
            {slots.map((slot) => (
              <button
                key={slot._id}
                type="button"
                disabled={slot.status !== "available"}
                onClick={() => toggleSelectedSlot(slot)}
                className={`text-xs border rounded-lg px-2 py-2 ${
                  slot.status !== "available"
                    ? "bg-gray-100 text-gray-400 line-through"
                    : selectedSlot?._id === slot._id
                    ? "bg-[#2ecc71] text-white"
                    : "bg-white text-[#14532d]"
                }`}
              >
                {slot.time}
              </button>
            ))}
          </div>
        </div>

        <div className="md:col-span-1 bg-[#f8fffb] rounded-xl p-4 border">
          <input
            className="w-full border rounded-lg px-3 py-2 mb-2"
            placeholder="Full Name"
            value={patient.name}
            onChange={(e) => setPatient((p) => ({ ...p, name: e.target.value }))}
          />
          <input
            className="w-full border rounded-lg px-3 py-2 mb-2"
            placeholder="Phone Number"
            value={patient.phone}
            onChange={(e) => setPatient((p) => ({ ...p, phone: e.target.value }))}
          />
          <input
            className="w-full border rounded-lg px-3 py-2 mb-2"
            placeholder="Age (optional)"
            value={patient.age}
            onChange={(e) => setPatient((p) => ({ ...p, age: e.target.value }))}
          />
          <textarea
            className="w-full border rounded-lg px-3 py-2 mb-2"
            rows={3}
            placeholder="Notes / reason"
            value={patient.notes}
            onChange={(e) => setPatient((p) => ({ ...p, notes: e.target.value }))}
          />

          {bookingError && <div className="text-xs text-red-600 mb-2">{bookingError}</div>}

          {bookingSuccess && (
            <div className="text-xs bg-green-100 p-2 rounded mb-2">
              Appointment confirmed successfully
            </div>
          )}

          <button
            onClick={handleConfirm}
            disabled={!selectedSlot || bookingLoading}
            className="w-full bg-[#2ecc71] text-white rounded-lg py-2 disabled:bg-gray-300"
          >
            {bookingLoading ? "Booking..." : "Confirm Appointment"}
          </button>

          <button
            onClick={resetAll}
            className="w-full mt-2 text-xs underline text-gray-500"
          >
            Reset form
          </button>
        </div>
      </div>

      <div className="mt-8 bg-white rounded-2xl shadow-md p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-2xl font-bold text-[#14532d]">My Appointments</h2>
          <button
            type="button"
            onClick={loadMyAppointments}
            className="text-sm px-3 py-1.5 rounded-lg border border-gray-300 hover:border-[#2ecc71] text-gray-700"
          >
            Refresh
          </button>
        </div>

        {appointmentsError && (
          <div className="text-sm text-red-600 mb-3">{appointmentsError}</div>
        )}

        {appointmentsLoading ? (
          <p className="text-sm text-gray-500">Loading appointments...</p>
        ) : myAppointments.length === 0 ? (
          <p className="text-sm text-gray-500">No appointments booked yet.</p>
        ) : (
          <div className="space-y-3">
            {myAppointments
              .slice()
              .sort(
                (a, b) =>
                  new Date(b.appointmentDate || b.date).getTime() -
                  new Date(a.appointmentDate || a.date).getTime()
              )
              .map((appointment) => (
                <div
                  key={appointment._id}
                  className="border border-gray-200 rounded-xl p-4"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                    <p className="font-semibold text-[#14532d]">
                      {appointment.doctorName || appointment.doctor?.name || "Doctor"}
                    </p>
                    <span
                      className={`text-xs px-2.5 py-1 rounded-full capitalize ${
                        appointment.status === "confirmed"
                          ? "bg-green-100 text-green-700"
                          : appointment.status === "cancelled"
                          ? "bg-red-100 text-red-700"
                          : "bg-yellow-100 text-yellow-700"
                      }`}
                    >
                      {appointment.status || "pending"}
                    </span>
                  </div>

                  <p className="text-sm text-gray-600">
                    {(appointment.speciality || appointment.doctor?.specialization || "Speciality")}
                    {" | "}
                    {(appointment.hospitalName || appointment.doctor?.hospital || "Hospital")}
                  </p>
                  <p className="text-sm text-gray-700 mt-1">
                    {new Date(appointment.appointmentDate || appointment.date).toLocaleDateString("en-IN", {
                      day: "numeric",
                      month: "short",
                      year: "numeric",
                    })}
                    {" at "}
                    <span className="font-medium">
                      {appointment.slotTime || appointment.startTime || "09:00"}
                    </span>
                  </p>

                  {appointment.reason && (
                    <p className="text-sm text-gray-600 mt-1">
                      Reason: {appointment.reason}
                    </p>
                  )}
                </div>
              ))}
          </div>
        )}
      </div>
    </div>
  );
}
