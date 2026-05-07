import { useEffect, useMemo, useState } from "react";
import { Calendar, Clock, Hospital } from "lucide-react";
import axiosInstance from "../api/axios";

export default function AddAvailability() {
  const [doctors, setDoctors] = useState([]);
  const [doctorId, setDoctorId] = useState("");
  const [date, setDate] = useState("");
  const [selectedTimes, setSelectedTimes] = useState([]);

  const TIMES = [
    "09:00 - 09:15",
    "09:15 - 09:30",
    "09:30 - 09:45",
    "10:00 - 10:15",
  ];

  useEffect(() => {
    const fetchDoctor = async () => {
      try {
        const { data } = await axiosInstance.get("/doctor");
        setDoctorId(data?._id || "");
      } catch (error) {
        console.error("Failed to fetch doctor:", error);
      }
    };

    fetchDoctor();
  }, []);

  const fetchDoctorsFromSlots = async () => {
    try {
      const { data } = await axiosInstance.get("/slots/my");
      setDoctors(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error("Failed to fetch doctors from slots:", error);
      setDoctors([]);
    }
  };

  useEffect(() => {
    fetchDoctorsFromSlots();
  }, []);

  const formatDate = (dateValue) => {
    const parsed = new Date(`${dateValue}T00:00:00`);
    if (Number.isNaN(parsed.getTime())) return dateValue;

    return parsed.toLocaleDateString("en-IN", {
      weekday: "short",
      day: "2-digit",
      month: "short",
      year: "numeric",
    });
  };

  const doctorsWithGroupedSlots = useMemo(() => {
    return doctors.map((doc) => {
      const grouped = (doc.availability || []).reduce((acc, rawSlot) => {
        const [datePart, timePart] = String(rawSlot).split("|").map((v) => v?.trim());
        if (!datePart || !timePart) return acc;

        if (!acc[datePart]) acc[datePart] = new Set();
        acc[datePart].add(timePart);
        return acc;
      }, {});

      const slotGroups = Object.entries(grouped).map(([date, times]) => ({
        date,
        displayDate: formatDate(date),
        times: Array.from(times).sort(),
      }));

      slotGroups.sort((a, b) => a.date.localeCompare(b.date));

      return { ...doc, slotGroups };
    });
  }, [doctors]);

  const toggleTime = (time) => {
    setSelectedTimes((prev) =>
      prev.includes(time)
        ? prev.filter((t) => t !== time)
        : [...prev, time]
    );
  };

  const createSlots = async () => {
    if (!doctorId) {
      alert("Doctor not found. Please login again.");
      return;
    }

    if (!date) {
      alert("Please select a date");
      return;
    }

    if (selectedTimes.length === 0) {
      alert("Please select at least one time slot");
      return;
    }

    try {
      const { data } = await axiosInstance.post("/slots/create", {
        doctorId,
        date,
        times: selectedTimes,
      });

      if (!data) {
        alert("Failed to publish slots");
        return;
      }

      alert(data.message || "Slots published successfully");
      setSelectedTimes([]);
      fetchDoctorsFromSlots();
    } catch (error) {
      console.error("Frontend error:", error);
      alert(error.response?.data?.message || "Something went wrong");
    }
  };

  return (
    <div className="flex flex-col min-h-screen">

      <main className="grow max-w-7xl mx-auto px-4 py-8 space-y-10">
        <h1 className="text-3xl font-bold text-base-content">
          Doctor Availability
        </h1>

        <section>
          <h2 className="text-xl font-semibold mb-4">Your Published Slots</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {doctorsWithGroupedSlots.map((doc) => (
              <div key={doc._id} className="card bg-base-100 shadow-lg">
                <div className="card-body">
                  <h3 className="card-title">{doc.name}</h3>

                  <p className="flex items-center gap-2 text-sm">
                    <Hospital size={16} /> {doc.hospital}
                  </p>

                    <p className="text-sm text-base-content/70">
                      {doc.specialization}
                    </p>

                  <div className="mt-3">
                    <p className="font-medium flex items-center gap-2">
                      <Clock size={16} /> Availability
                    </p>
                    {doc.slotGroups.length === 0 ? (
                      <p className="text-sm text-base-content/70 mt-2">
                        No slots available
                      </p>
                    ) : (
                      <div className="mt-2 space-y-3">
                        {doc.slotGroups.map((group) => (
                          <div key={group.date} className="bg-base-200 rounded-lg p-3">
                            <p className="text-sm font-semibold">{group.displayDate}</p>
                            <div className="flex flex-wrap gap-2 mt-2">
                              {group.times.map((time) => (
                                <span key={`${group.date}-${time}`} className="badge badge-outline">
                                  {time}
                                </span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Doctor View */}
        <section className="bg-base-200 p-6 rounded-2xl shadow">
          <h2 className="text-xl font-semibold mb-4">
            Doctor: Add Availability
          </h2>

          <div className="flex flex-col gap-4">
            <label className="form-control w-full md:w-1/3">
              <div className="label">
                <span className="label-text">Select Date</span>
              </div>
              <input
                type="date"
                className="input input-bordered w-full"
                value={date}
                onChange={(e) => setDate(e.target.value)}
              />
            </label>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
              {TIMES.map((time) => (
                <button
                  key={time}
                  type="button"
                  onClick={() => toggleTime(time)}
                  className={`btn btn-outline justify-start ${
                    selectedTimes.includes(time) ? "btn-primary" : ""
                  }`}
                >
                  {time}
                </button>
              ))}
            </div>

            <button onClick={createSlots} className="btn btn-primary w-fit">
              <Calendar size={18} />
              Publish Slots
            </button>
          </div>
        </section>
      </main>
    </div>
  );
}
