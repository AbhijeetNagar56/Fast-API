import { useState } from "react";
import axiosInstance from "../api/axios";
import toast from "react-hot-toast";
import { useNavigate } from "react-router";
import {
  AGE_MAX,
  AGE_MIN,
  isValidGender,
  isValidPhoneNumber,
  parseAge,
} from "../utils/validation";

const UserDetails = () => {
  const navigate = useNavigate();
  const [gender, setGender] = useState("");
  const [age, setAge] = useState("");
  const [phoneNumber, setPhoneNumber] = useState("");

  const handleSubmit = async () => {
    try {
      const parsedAge = parseAge(age);

      if (!isValidGender(gender)) {
        toast.error("Please select a valid gender");
        return;
      }

      if (parsedAge === null) {
        toast.error(`Age must be a whole number between ${AGE_MIN} and ${AGE_MAX}`);
        return;
      }

      if (!isValidPhoneNumber(phoneNumber)) {
        toast.error("Phone number must be exactly 10 digits");
        return;
      }

      const response = await axiosInstance.patch(
        "/home/details",
        { gender, age: parsedAge, phoneNumber: phoneNumber.trim() }
      );

      console.log("Details saved:", response.data);
      toast.success("Details submitted successfully!");
      navigate("/");
    } catch (error) {
      console.error("Error saving details:", error.response?.data || error.message);
      toast.error(error.response?.data?.msg || "Failed to save details");
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
              onChange={(e) => { setAge(e.target.value) }}
              placeholder="Enter your age"
              className="input input-bordered w-full"
              min={AGE_MIN}
              max={AGE_MAX}
            />
          </label>

          {/* Phone Number */}
          <label className="form-control w-full mb-6">
            <div className="label">
              <span className="label-text">Phone Number</span>
            </div>
            <input
              type="tel"
              value={phoneNumber}
              onChange={(e) =>
                setPhoneNumber(e.target.value.replace(/\D/g, "").slice(0, 10))
              }
              placeholder="Enter 10-digit phone number"
              className="input input-bordered w-full"
              maxLength={10}
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
