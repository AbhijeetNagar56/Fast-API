import { useEffect, useState, useRef } from "react";
import { MapContainer, TileLayer, Marker, Popup, useMap } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import L from "leaflet";
import { ArrowLeft, MapPin } from "lucide-react";
import { Link } from "react-router";


const userIcon = new L.Icon({
  iconUrl: "https://unpkg.com/leaflet@1.7.1/dist/images/marker-icon.png",
  iconRetinaUrl:
    "https://unpkg.com/leaflet@1.7.1/dist/images/marker-icon-2x.png",
  shadowUrl: "https://unpkg.com/leaflet@1.7.1/dist/images/marker-shadow.png",
  iconSize: [25, 41],
  iconAnchor: [12, 41],
});

const hospitalIcon = new L.Icon({
  iconUrl: "https://cdn-icons-png.flaticon.com/512/854/854878.png",
  iconSize: [30, 30],
  iconAnchor: [15, 30],
});

const hospitalIconHighlight = new L.Icon({
  iconUrl: "https://cdn-icons-png.flaticon.com/512/854/854878.png",
  iconSize: [40, 40],
  iconAnchor: [20, 40],
});

/* ---------------- DISTANCE FUNCTION ---------------- */

const getDistanceInKm = (lat1, lon1, lat2, lon2) => {
  const R = 6371;
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) ** 2;

  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
};

/* ---------------- MAP FLY HELPER ---------------- */

function FlyToHospital({ hospital }) {
  const map = useMap();

  useEffect(() => {
    if (hospital) {
      map.flyTo([hospital.lat, hospital.lon], 15, { duration: 0.8 });
    }
  }, [hospital, map]);

  return null;
}

/* ---------------- COMPONENT ---------------- */

export default function MapComponent() {
  const [position, setPosition] = useState(null);
  const [hospitals, setHospitals] = useState([]);
  const [hoveredHospital, setHoveredHospital] = useState(null);
  const [selectedRange, setSelectedRange] = useState(5);
  const markerRefs = useRef({});

  /* -------- GET USER LOCATION -------- */

  useEffect(() => {
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setPosition([pos.coords.latitude, pos.coords.longitude]);
      },
      () => {
        setPosition([15.3647, 75.124]); // fallback
      }
    );
  }, []);

  /* -------- FETCH HOSPITALS -------- */

  const fetchHospitals = async () => {
    if (!position) return;
    const [lat, lon] = position;

    const viewbox = `${lon - 0.1},${lat + 0.1},${lon + 0.1},${lat - 0.1}`;
    const url = `https://nominatim.openstreetmap.org/search?format=json&q=hospital&limit=40&viewbox=${viewbox}&bounded=1`;

    const res = await fetch(url, {
      headers: { "User-Agent": "MediRaksha/1.0" },
    });
    const data = await res.json();

    const formatted = data
      .map((place, index) => {
        const distance = getDistanceInKm(
          lat,
          lon,
          parseFloat(place.lat),
          parseFloat(place.lon)
        );

        return {
          id: place.place_id || index,
          lat: parseFloat(place.lat),
          lon: parseFloat(place.lon),
          name: place.display_name,
          distance,
        };
      })
      .sort((a, b) => a.distance - b.distance);

    setHospitals(formatted);
  };

  /* -------- FILTER BY RANGE -------- */

  const filteredHospitals = hospitals.filter(
    (h) => h.distance <= selectedRange
  );

  /* -------- OPEN GOOGLE MAPS DIRECTIONS -------- */

  const openDirections = (hospital) => {
    if (!position) return;

    const [userLat, userLon] = position;
    const url = `https://www.google.com/maps/dir/?api=1&origin=${userLat},${userLon}&destination=${hospital.lat},${hospital.lon}&travelmode=driving`;

    window.open(url, "_blank");
  };

  /* ---------------- UI ---------------- */

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="container mx-auto p-4">
        <Link to="/" className="text-gray-500">
          <ArrowLeft size={24} />
        </Link>

        <h1 className="text-3xl font-bold text-center mb-4">
          Hospital Locator
        </h1>

        <div className="justify-self-center mb-5">
          {/* RANGE BUTTONS */}
          <div className="inline gap-3 mb-4">
            {[2, 5, 10].map((km) => (
              <button
                key={km}
                onClick={() => setSelectedRange(km)}
                className={`px-4 py-2 mx-2 rounded-lg font-medium ${
                  selectedRange === km
                    ? "bg-blue-600 text-white"
                    : "bg-white border"
                }`}
              >
                {km} km
              </button>
            ))}
          </div>

          <div className=" inline text-center mb-10 ml-15">
            <button
              onClick={fetchHospitals}
              disabled={!position}
              className="bg-blue-600 text-white px-6 py-2 rounded-lg shadow disabled:bg-gray-400"
            >
              Show Hospitals
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-125">
          {/* HOSPITAL LIST */}
          <div className="bg-white p-4 rounded-lg shadow overflow-y-auto">
            <h2 className="font-semibold mb-3">
              Hospitals within {selectedRange} km ({filteredHospitals.length})
            </h2>

            {filteredHospitals.map((hospital) => (
              <div
                key={hospital.id}
                onMouseEnter={() => {
                  setHoveredHospital(hospital);
                  markerRefs.current[hospital.id]?.openPopup();
                }}
                onMouseLeave={() => setHoveredHospital(null)}
                onClick={() => openDirections(hospital)}
                className="p-3 mb-2 rounded border hover:bg-blue-50 cursor-pointer"
              >
                <h3 className="text-sm font-medium">
                  {hospital.name.split(",")[0]}
                </h3>
                <p className="text-xs text-gray-500">
                  <MapPin /> {hospital.distance.toFixed(2)} km away
                </p>
              </div>
            ))}
          </div>

          {/* MAP */}
          <div className="lg:col-span-2 bg-white rounded-lg shadow overflow-hidden">
            {position && (
              <MapContainer
                center={position}
                zoom={13}
                style={{ height: "600px" }}
              >
                <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />

                <Marker position={position} icon={userIcon}>
                  <Popup>You are here 📍</Popup>
                </Marker>

                {filteredHospitals.map((hospital) => (
                  <Marker
                    key={hospital.id}
                    position={[hospital.lat, hospital.lon]}
                    icon={
                      hoveredHospital?.id === hospital.id
                        ? hospitalIconHighlight
                        : hospitalIcon
                    }
                    ref={(ref) =>
                      ref && (markerRefs.current[hospital.id] = ref)
                    }
                  >
                    <Popup>
                      <div className="text-sm">
                        <p className="font-semibold">{hospital.name}</p>
                        <p>{hospital.distance.toFixed(2)} km away</p>
                        <button
                          onClick={() => openDirections(hospital)}
                          className="mt-2 bg-blue-600 text-white px-3 py-1 rounded text-xs"
                        >
                          Get Directions
                        </button>
                      </div>
                    </Popup>
                  </Marker>
                ))}

                {hoveredHospital && (
                  <FlyToHospital hospital={hoveredHospital} />
                )}
              </MapContainer>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
