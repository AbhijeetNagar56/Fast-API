import { useState } from "react";
import axiosInstance from "../api/axios";
import toast from "react-hot-toast";

const DoctorDetails = () => {
  const [name, setName] = useState("");
  const [hospital, setHospital] = useState("");
  const [age, setAge] = useState("");

  const handleSubmit = async () => {
    try {
      const response = await axiosInstance.patch(
        "/doctor/details", // 👈 Backend endpoint
        { name, hospital, age }
      );

      console.log("Doctor details saved:", response.data);
      toast.success("Doctor details submitted successfully!");

      // Redirect to homepage or dashboard
      window.location.href = "/doctordash";
    } catch (error) {
      console.error("Error saving doctor details:", error.response?.data || error.message);
    }
  };

  return (
    <div data-theme="forest" className="min-h-screen flex items-center justify-center bg-base-200">
      <div className="card w-full max-w-sm shadow-xl bg-base-100">
        <div className="card-body">
          <h2 className="text-2xl font-bold text-center">Doctor Details</h2>

          {/* Doctor's Name */}
          <label className="form-control w-full mb-4">
            <div className="label">
              <span className="label-text">Name</span>
            </div>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Enter doctor's name"
              className="input input-bordered w-full"
            />
          </label>

          {/* Hospital Name */}
          <label className="form-control w-full mb-4">
            <div className="label">
              <span className="label-text">Hospital</span>
            </div>
            <input
              type="text"
              value={hospital}
              onChange={(e) => setHospital(e.target.value)}
              placeholder="Enter hospital name"
              className="input input-bordered w-full"
            />
          </label>

          {/* Age */}
          <label className="form-control w-full mb-6">
            <div className="label">
              <span className="label-text">Age</span>
            </div>
            <input
              type="number"
              value={age}
              onChange={(e) => {
                if (e.target.value != null && e.target.value < 1) {
                  toast.error("Invalid Age.");
                } else {
                  setAge(e.target.value);
                }
              }}
              placeholder="Enter doctor's age"
              className="input input-bordered w-full"
            />
          </label>

          <button onClick={handleSubmit} className="btn btn-primary w-full">
            Submit
          </button>
        </div>
      </div>
    </div>
  );
};

export default DoctorDetails;
