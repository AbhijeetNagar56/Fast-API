import { useState } from "react";
import { Calendar, Clock, Hospital, ArrowLeft } from "lucide-react";
import { Link } from "react-router";

// Mock data (frontend-only)
const initialDoctors = [
  {
    id: 1,
    name: "Dr. Anil Sharma",
    hospital: "City Care Hospital",
    specialization: "Cardiologist",
    availability: ["10:00 AM - 12:00 PM", "4:00 PM - 6:00 PM"],
  },
  {
    id: 2,
    name: "Dr. Neha Verma",
    hospital: "Green Life Hospital",
    specialization: "Dermatologist",
    availability: ["11:00 AM - 2:00 PM"],
  },
];

export default function DoctorAvailability() {
  const [doctors, setDoctors] = useState(initialDoctors);
  const [newSlot, setNewSlot] = useState("");
  const [selectedDoctor, setSelectedDoctor] = useState(null);

  const addAvailability = () => {
    if (!newSlot || selectedDoctor === null) return;

    setDoctors((prev) =>
      prev.map((doc) =>
        doc.id === selectedDoctor
          ? { ...doc, availability: [...doc.availability, newSlot] }
          : doc
      )
    );

    setNewSlot("");
    setSelectedDoctor(null);
  };

  return (
    <div className="flex flex-col min-h-screen">
      
      <main className="grow max-w-7xl mx-auto px-4 py-8 space-y-10">
        
        <h1 className="text-3xl font-bold text-base-content">
          <Link to="/" className="text-gray-500 hover:text-gray-700">
            <ArrowLeft size={24} />
          </Link>
          <span className="inline">Doctor Availability</span> 
        </h1>

        {/* Patient View */}
        <section>
          <h2 className="text-xl font-semibold mb-4">Available Doctors</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {doctors.map((doc) => (
              <div key={doc.id} className="card bg-base-200 shadow-lg">
                <div className="card-body">
                  <h2>{doc.id}</h2>
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
                    <ul className="list-disc list-inside text-sm">
                      {doc.availability.map((slot, idx) => (
                        <li key={idx}>{slot}</li>
                      ))}
                    </ul>
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
