import { useState } from "react";
import axiosInstance from "../api/axios";
import { Link } from "react-router";
import { ArrowLeft } from "lucide-react";
import toast from "react-hot-toast";
import { parseAge } from "../utils/validation";
import { useNavigate } from "react-router";

const DoctorAuth = () => {
  const navigate = useNavigate();
  const [su, setsu] = useState(true);
  const [doctorId, setDoctorId] = useState("");
  const [password, setPassword] = useState("");

  // 🔹 Doctor Signup
  const handleSignup = async () => {
    try {
      await axiosInstance.post("/auth/doctor", {
        doctorId,
        password,
      });

      toast.success("Request sent for verification 🩺");
      await handleLogin(); // auto-login (if allowed)
    } catch (error) {
      toast.error(
        error.response?.data?.message ||
          "Doctor already registered or invalid ID"
      );
    }
  };

  // 🔹 Doctor Login
  const handleLogin = async () => {
    try {
      await axiosInstance.post("/auth/doctor/login", {
        doctorId,
        password,
      });

      toast.success("Welcome back, Doctor");

      const res = await axiosInstance.get('/doctor');

      const data = res.data; 

      if (!data.name || !data.hospital || parseAge(data.age) === null) {
        navigate("/doctordetail");
      } else {
        navigate("/doctordash");
      }
      
    } catch (error) {
      toast.error(
        error.response?.data?.message ||
          "Invalid DoctorID or password"
      );
    }
  };

  // 🔹 Signup UI
  if (su) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-base-200">
        <div className="card w-full max-w-sm shadow-xl bg-base-100">
          <div className="card-body">
            <div className="flex items-center justify-between mb-4">
              <Link to="/" className="text-gray-500 hover:text-gray-700">
                <ArrowLeft size={24} />
              </Link>
              <h2 className="text-2xl font-bold text-center grow">
                Doctor&apos;s Registration
              </h2>
              <div className="w-6"></div>
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSignup();
              }}
            >
              <label className="form-control w-full mb-4">
                <div className="label">
                  <span className="label-text">DoctorID</span>
                </div>
                <input
                  type="text"
                  value={doctorId}
                  onChange={(e) => setDoctorId(e.target.value)}
                  placeholder="DoctorID"
                  className="input input-bordered w-full"
                  required
                />
              </label>

              <label className="form-control w-full mb-6">
                <div className="label">
                  <span className="label-text">Password</span>
                </div>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Password"
                  className="input input-bordered w-full"
                  required
                />
              </label>

              <button type="submit" className="btn mt-4 btn-primary w-full">
                Send for verification
              </button>
            </form>

            <p className="mt-2 text-red-500 justify-self-start">
              MediRaksha will verify then let you in.
            </p>

            <p className="justify-self-start cursor-pointer">
              <span onClick={() => setsu(false)}>Already registered?</span>
              <Link to="/auth" className="ml-3">
                Patient Registration?
              </Link>
            </p>
          </div>
        </div>
      </div>
    );
  }

  // 🔹 Login UI
  return (
    <div className="min-h-screen flex items-center justify-center bg-base-200">
      <div className="card w-full max-w-sm shadow-xl bg-base-100">
        <div className="card-body">
          <div className="flex items-center justify-between mb-4">
            <Link to="/" className="text-gray-500 hover:text-gray-700">
              <ArrowLeft size={24} />
            </Link>
            <h2 className="text-2xl font-bold text-center grow">
              Welcome back doctor
            </h2>
            <div className="w-6"></div>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleLogin();
            }}
          >
            <label className="form-control w-full mb-4">
              <div className="label">
                <span className="label-text">DoctorID</span>
              </div>
              <input
                type="text"
                value={doctorId}
                onChange={(e) => setDoctorId(e.target.value)}
                placeholder="DoctorID"
                className="input input-bordered w-full"
                autoFocus
                required
              />
            </label>

            <label className="form-control w-full mb-6">
              <div className="label">
                <span className="label-text">Password</span>
              </div>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
                className="input input-bordered w-full"
                required
              />
            </label>

            <button type="submit" className="btn mt-4 btn-accent w-full">
              Log In
            </button>
          </form>

          <p
            className="justify-self-start cursor-pointer"
            onClick={() => setsu(true)}
          >
            Not a registered Doctor?
          </p>
        </div>
      </div>
    </div>
  );
};

export default DoctorAuth;
