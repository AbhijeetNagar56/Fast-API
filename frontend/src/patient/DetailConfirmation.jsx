import { useState } from "react";
import axiosInstance from "../api/axios";
import toast from "react-hot-toast";

const UserDetails = () => {
  const [gender, setGender] = useState("");
  const [age, setAge] = useState("");

  const handleSubmit = async () => {
    try {

      const response = await axiosInstance.patch(
        "/home/details", // 👈 Backend endpoint
        { gender, age }
      );

      console.log("Details saved:", response.data);
      toast.success("Details submitted successfully!");

      // Redirect to homepage or dashboard
      window.location.href = "/";
    } catch (error) {
      console.error("Error saving details:", error.response?.data || error.message);
    }
  };

  return (
    <div data-theme="forest" className="min-h-screen flex items-center justify-center bg-base-200">
      <div className="card w-full max-w-sm shadow-xl bg-base-100">
        <div className="card-body">
          <h2 className="text-2xl font-bold text-center">Your Details</h2>

          {/* Gender */}
          <label className="form-control w-full mb-4">
            <div className="label">
              <span className="label-text">Gender</span>
            </div>
            <select
              value={gender}
              onChange={(e) => setGender(e.target.value)}
              className="select select-bordered w-full"
            >
              <option value="">Select Gender</option>
              <option value="Male">Male</option>
              <option value="Female">Female</option>
              <option value="Other">Other</option>
            </select>
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
                
                if(e.target.value != null && e.target.value < 5) {
                  toast.error("Invalid Age")
                } else {
                  setAge(e.target.value)
                }
              }}
              placeholder="Enter your age"
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

export default UserDetails;
