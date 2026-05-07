import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import axiosInstance from "../api/axios";
import toast from "react-hot-toast";
import {
  AGE_MAX,
  AGE_MIN,
  isValidGender,
  isValidPhoneNumber,
  parseAge,
} from "../utils/validation";

export default function MyDetail() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false); 
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    gender: "",
    age: "",
    phoneNumber: "",
  });

  const navigate = useNavigate();

  useEffect(() => {
    const fetchUser = async () => {
      try {

        // 🔹 Axios GET request
        const res = await axiosInstance.get("/home");

        const data = res.data;
        setUser(data);
        setFormData({
          name: data.name || "",
          email: data.email || "",
          gender: data.gender || "",
          age: data.age || "",
          phoneNumber: data.phoneNumber || "",
        });
      } catch (error) {
        console.error(error.response?.data?.msg || "Error fetching user details");
        navigate("/auth");
      } finally {
        setLoading(false);
      }
    };

    fetchUser();
  }, [navigate]);

  const handleLogout = async () => {
    await axiosInstance.post('/auth/logout');
    navigate("/");
  };

  const goHome = () => {
    navigate("/");
  };

  const handleEditToggle = () => {
    setEditing(!editing);
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
      const parsedAge = parseAge(formData.age);
      if (!isValidGender(formData.gender)) {
        toast.error("Please select a valid gender");
        return;
      }
      if (parsedAge === null) {
        toast.error(`Age must be a whole number between ${AGE_MIN} and ${AGE_MAX}`);
        return;
      }
      if (!formData.name?.trim()) {
        toast.error("Name is required");
        return;
      }
      if (!isValidPhoneNumber(formData.phoneNumber)) {
        toast.error("Phone number must be exactly 10 digits");
        return;
      }

      // 🔹 Axios PATCH request
      const res = await axiosInstance.patch("/home/update", {
        gender: formData.gender,
        age: parsedAge,
        name: formData.name.trim(),
        phoneNumber: formData.phoneNumber.trim(),
      });

      const data = res.data;
      toast.success("Details updated successfully");
      setUser(data.user); // Updated user
      setEditing(false);
    } catch (error) {
      console.error(error.response?.data?.msg || "Error updating details");
      toast.error(error.response?.data?.msg || "Error updating details");
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-screen">
        <span className="loading loading-spinner loading-lg text-primary"></span>
      </div>
    );
  }

  if (!user) {
    return <div className="text-center text-red-500 mt-10">No user found</div>;
  }

  return (
    <div className="flex justify-center items-center h-screen bg-base-200">
      <div className="card w-96 bg-base-100 shadow-xl p-5">
        <h2 className="text-2xl font-bold text-center mb-4">My Details</h2>

        {editing ? (
          <>
            {/* Editable Form */}
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
              <label className="block mb-1 font-bold">Useraname</label>
              <input
                type="email"
                name="email"
                value={formData.email}
                disabled
                className="input input-bordered w-full"
              />
            </div>

            <div className="mb-4">
              <label className="block mb-1 font-bold">Phone Number</label>
              <input
                type="tel"
                name="phoneNumber"
                value={formData.phoneNumber}
                onChange={(e) =>
                  setFormData((prev) => ({
                    ...prev,
                    phoneNumber: e.target.value.replace(/\D/g, "").slice(0, 10),
                  }))
                }
                className="input input-bordered w-full"
                maxLength={10}
              />
            </div>

            <div className="mb-4">
              <label className="block mb-1 font-bold">Gender</label>
              <select
                name="gender"
                value={formData.gender}
                onChange={handleChange}
                className="select select-bordered w-full"
              >
                <option value="">Select Gender</option>
                <option value="Male">Male</option>
                <option value="Female">Female</option>
                <option value="Other">Other</option>
              </select>
            </div>

            <div className="mb-4">
              <label className="block mb-1 font-bold">Age</label>
              <input
                type="number"
                name="age"
                value={formData.age}
                onChange={handleChange}
                className="input input-bordered w-full"
                min={AGE_MIN}
                max={AGE_MAX}
              />
            </div>

            <div className="flex gap-3">
              <button className="btn btn-success flex-1" onClick={handleSave}>
                Save
              </button>
              <button className="btn btn-secondary flex-1" onClick={handleEditToggle}>
                Cancel
              </button>
            </div>
          </>
        ) : (
          <>
            {/* View Mode */}
            <div className="mb-4">
              <span className="font-bold">Name:</span> {user.name}
            </div>
            <div className="mb-4">
              <span className="font-bold">Username:</span> {user.email}
            </div>
            <div className="mb-4">
              <span className="font-bold">Gender:</span> {user.gender}
            </div>
            <div className="mb-4">
              <span className="font-bold">Age:</span> {user.age}
            </div>
            <div className="mb-4">
              <span className="font-bold">Phone Number:</span> {user.phoneNumber}
            </div>

            <div className="flex gap-3">
              <button className="btn btn-primary flex-1" onClick={goHome}>
                Back
              </button>
              <button className="btn btn-warning flex-1" onClick={handleEditToggle}>
                Edit
              </button>
              <button className="btn btn-error flex-1" onClick={handleLogout}>
                Logout
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
