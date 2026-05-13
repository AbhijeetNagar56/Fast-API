import { useState } from "react";
import {
  BedDouble,
  HeartPulse,
  Stethoscope,
  Hospital,
  ArrowLeft,
  LocateFixed,
  Flame,
} from "lucide-react";
import { Link } from "react-router";

const initialData = [
  {
    id: 1,
    hospitalName: "City Care Hospital",
    location: "Bangalore",
    bedsAvailable: 12,
    icuAvailable: 4,
    ventilatorsAvailable: 3,
    oxygenAvailable: true,
  },
  {
    id: 2,
    hospitalName: "Green Life Medical Center",
    location: "Hyderabad",
    bedsAvailable: 0,
    icuAvailable: 1,
    ventilatorsAvailable: 0,
    oxygenAvailable: true,
  },
  {
    id: 3,
    hospitalName: "Apollo Health Hub",
    location: "Chennai",
    bedsAvailable: 6,
    icuAvailable: 0,
    ventilatorsAvailable: 2,
    oxygenAvailable: false,
  },
];

export default function BedAvailability() {
  const [hospitals] = useState(initialData);

  return (
    <div className="flex flex-col min-h-screen">
      <main className="grow max-w-7xl mx-auto px-4 py-10">
        <div className="mb-8">
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Link to="/" className="text-gray-500 hover:text-gray-700 mr-3">
              <ArrowLeft size={24} />
            </Link>
            <Hospital /> Hospital Bed & Equipment Availability
          </h1>
          <p className="text-base-content/70 mt-2">
            Live overview of beds and critical equipment across hospitals
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {hospitals.map((hospital) => (
            <div
              key={hospital.id}
              className="card bg-base-100 shadow-xl border"
            >
              <div className="card-body">
                <h2 className="card-title text-xl">
                  {hospital.hospitalName}
                </h2>
                <p className="text-sm text-base-content/70">
                  <LocateFixed className="inline" /> {hospital.location}
                </p>

                <div className="mt-4 space-y-2 text-sm">
                  <div className="flex items-center gap-2">
                    <BedDouble className="text-primary" />
                    Beds Available:
                    <span
                      className={
                        hospital.bedsAvailable > 0
                          ? "text-success"
                          : "text-error"
                      }
                    >
                      {hospital.bedsAvailable}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <HeartPulse className="text-secondary" />
                    ICU Beds:
                    <span
                      className={
                        hospital.icuAvailable > 0
                          ? "text-success"
                          : "text-error"
                      }
                    >
                      {hospital.icuAvailable}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <Stethoscope className="text-accent" />
                    Ventilators:
                    <span
                      className={
                        hospital.ventilatorsAvailable > 0
                          ? "text-success"
                          : "text-error"
                      }
                    >
                      {hospital.ventilatorsAvailable}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <Flame /> Oxygen Supply:
                    <span
                      className={
                        hospital.oxygenAvailable
                          ? "text-success"
                          : "text-error"
                      }
                    >
                      {hospital.oxygenAvailable
                        ? "Available"
                        : "Not Available"}
                    </span>
                  </div>
                </div>

                <div className="card-actions justify-end mt-4">
                  <button className="btn btn-sm btn-primary">
                    Request Admission
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
