import { useEffect, useMemo, useState } from "react";
import { Clock, Hospital, ArrowLeft } from "lucide-react";
import { Link } from "react-router";
import axiosInstance from "../api/axios";

export default function DoctorAvailability() {
  const [doctors, setDoctors] = useState([]);

  useEffect(() => {
    const fetchDoctorsFromSlots = async () => {
      try {
        const { data } = await axiosInstance.get("/slots/doctors");
        setDoctors(Array.isArray(data) ? data : []);
      } catch (error) {
        console.error("Failed to fetch doctor availability:", error);
        setDoctors([]);
      }
    };

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

  return (
    <div className="flex flex-col min-h-screen">
      
      <main className="grow max-w-7xl mx-auto px-4 py-8 space-y-10">
        
        <h1 className="text-3xl font-bold text-base-content">
          <Link to="/services" className="text-gray-500 hover:text-gray-700">
            <ArrowLeft size={24} />
          </Link>
          <span className="inline">Doctor Availability</span> 
        </h1>

        {/* Patient View */}
        <section>
          <h2 className="text-xl font-semibold mb-4">Available Doctors</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {doctorsWithGroupedSlots.map((doc) => (
              <div key={doc._id} className="card bg-base-200 shadow-lg">
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
                          <div key={group.date} className="bg-base-100 rounded-lg p-3">
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
        
      </main>

    </div>
  );
}
