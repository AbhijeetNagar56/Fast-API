import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import axiosInstance from "../api/axios";
import toast from "react-hot-toast";

export default function DoctorDetail() {
  const [doctor, setDoctor] = useState(null);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);

  const [formData, setFormData] = useState({
    doctorId: "",
    name: "",
    age: "",
    hospital: "",
  });

  const navigate = useNavigate();

  useEffect(() => {
    const fetchDoctor = async () => {
      try {
        const res = await axiosInstance.get("/doctor");
        const data = res.data;

        setDoctor(data);
        setFormData({
          doctorId: data.doctorId || "",
          name: data.name || "",
          age: data.age || "",
          hospital: data.hospital || "",
        });
      } catch (error) {
        console.error(
          error.response?.data?.msg || "Error fetching doctor details"
        );
        navigate("/doctor");
      } finally {
        setLoading(false);
      }
    };

    fetchDoctor();
  }, [navigate]);

  const handleLogout = async () => {
    await axiosInstance.post("/auth/logout");
    navigate("/");
  };

  const goHome = () => {
    navigate("/doctordash");
  };

  const handleEditToggle = () => {
    setEditing((prev) => !prev);
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSave = async () => {
    try {
      const res = await axiosInstance.patch("/doctor/update", {
        doctorId: formData.doctorId,
        name: formData.name,
        age: formData.age,
        hospital: formData.hospital,
      });

      const data = res.data;

      toast.success("Doctor details updated successfully!");

      // ✅ IMPORTANT FIX (prevents white screen)
      setDoctor(data);
      setFormData({
        doctorId: data.doctorId,
        name: data.name,
        age: data.age,
        hospital: data.hospital,
      });

      setEditing(false);
    } catch (error) {
      console.error(
        error.response?.data?.msg || "Error updating doctor details"
      );
      toast.error("Failed to update doctor details");
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-screen">
        <span className="loading loading-spinner loading-lg text-primary"></span>
      </div>
    );
  }

  if (!doctor) {
    return (
      <div className="text-center text-red-500 mt-10">
        No doctor found
      </div>
    );
  }

  return (
    <div className="flex justify-center items-center h-screen bg-base-200">
      <div className="card w-96 bg-base-100 shadow-xl p-5">
        <h2 className="text-2xl font-bold text-center mb-4">
          Doctor Details
        </h2>

        {editing ? (
          <>
            <div className="mb-4">
              <label className="block mb-1 font-bold">Name</label>
              <input
                type="text"
                name="name"
                value={formData.name}
                onChange={handleChange}
                className="input input-bordered w-full"
              />
            </div>

            <div className="mb-4">
              <label className="block mb-1 font-bold">Doctor ID</label>
              <input
                type="text"
                name="doctorId"
                value={formData.doctorId}
                disabled
                className="input input-bordered w-full"
              />
            </div>

            <div className="mb-4">
              <label className="block mb-1 font-bold">Hospital</label>
              <input
                type="text"
                name="hospital"
                value={formData.hospital}
                onChange={handleChange}
                className="input input-bordered w-full"
              />
            </div>

            <div className="mb-4">
              <label className="block mb-1 font-bold">Age</label>
              <input
                type="number"
                name="age"
                value={formData.age}
                onChange={handleChange}
                className="input input-bordered w-full"
              />
            </div>

            <div className="flex gap-3">
              <button className="btn btn-success flex-1" onClick={handleSave}>
                Save
              </button>
              <button
                className="btn btn-secondary flex-1"
                onClick={handleEditToggle}
              >
                Cancel
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="mb-4">
              <span className="font-bold">Name:</span> {doctor.name}
            </div>
            <div className="mb-4">
              <span className="font-bold">Doctor ID:</span> {doctor.doctorId}
            </div>
            <div className="mb-4">
              <span className="font-bold">Hospital:</span> {doctor.hospital}
            </div>
            <div className="mb-4">
              <span className="font-bold">Age:</span> {doctor.age}
            </div>

            <div className="flex gap-3">
              <button className="btn btn-primary flex-1" onClick={goHome}>
                Back
              </button>
              <button
                className="btn btn-warning flex-1"
                onClick={handleEditToggle}
              >
                Edit
              </button>
              <button
                className="btn btn-error flex-1"
                onClick={handleLogout}
              >
                Logout
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
