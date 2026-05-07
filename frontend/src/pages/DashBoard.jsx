import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import { Link } from "react-router";
import { useState, useEffect } from "react";
import { useNavigate } from "react-router";
import axiosInstance from "../api/axios";
import car1 from '../assets/car1.jpg';
import car2 from '../assets/car21.png';

import { Brain, Hospital } from "lucide-react";
// import toast from "react-hot-toast";
// Placeholder data for demonstration 
const quickActions = [
  {
    id: 1,
    title: "Find Nearby Hospitals",
    icon: <Hospital />,
    description: "Use real-time location tracking.",
    style: "btn-primary",
    view: "/map",
  },
  {
    id: 2,
    title: "AI chat",
    icon: <Brain />,
    description: "Ask the ai about the symtoms and get cured",
    style: "btn-neutral",
    view: "/ai",
  },
];

export default function Dashboard() {
  const navigate = useNavigate();
  const [name, setName] = useState("Sign up to access features");

  const getUser = async () => {
    try {
      const res = await axiosInstance.get("/home");
      const data = res.data;
      setName(data.name || "Sign up to access features");
    } catch (error) {
      // console.error(error.response?.data?.msg || "Error fetching user details");
    }
  };
  const getDoctor = async () => {
    try {
      await axiosInstance.get('/doctor');
      navigate('/doctordash');
    } catch (error) {
      // console.error(error.response?.data?.msg || "Error fetching user details");
    }
  }


  useEffect(() => {
    getDoctor();
    getUser();
  }, []);

  return (
    <div className="flex flex-col min-h-screen">
      <Navbar />

      <main className="grow max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-10 space-y-12">
        {/* Personalized Welcome Banner */}
        <div className="hero rounded-2xl bg-base-200 p-8 shadow-xl">
          <div className="hero-content flex-col lg:flex-row-reverse w-full p-0">
            <div>
              <h1 className="text-4xl font-bold text-base-content">
                Hello, {name}!
              </h1>
              <p className="py-2 text-lg text-base-content/80">
                Your health ecosystem is live. Quickly access nearby care,
                manage your reports, and stay connected.
              </p>
            </div>
          </div>
        </div>
        {/*banner */}
        <div className="carousel w-full">
          <div id="slide1" className="carousel-item relative w-full">
            <img
              src={car1}
              className="w-full" />
            <div className="absolute left-5 right-5 top-1/2 flex -translate-y-1/2 transform justify-between">
              <a href="#slide2" className="btn btn-circle">❮</a>
              <a href="#slide2" className="btn btn-circle">❯</a>
            </div>
          </div>
          <div id="slide2" className="carousel-item relative w-full">
            <img
              src={car2}
              className="w-full" />
            <div className="absolute left-5 right-5 top-1/2 flex -translate-y-1/2 transform justify-between">
              <a href="#slide1" className="btn btn-circle">❮</a>
              <a href="#slide1" className="btn btn-circle">❯</a>
            </div>
          </div>
        </div>


        {/* Quick Actions Section */}
        <section>
          <h2 className="text-2xl font-semibold mb-6 text-base-content">
            Quick Access to Services
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {quickActions.map((action) => (
              <div
                key={action.id}
                className="card shadow-lg bg-base-100 transition duration-300 transform hover:scale-[1.02] cursor-pointer"
              >
                <div className="card-body p-6">
                  <div
                    className={`text-4xl font-bold mb-3 ${action.style.replace("btn-", "text-")}`}
                  >
                    {action.icon}
                  </div>
                  <h3 className="card-title text-xl text-base-content">
                    {action.title}
                  </h3>
                  <p className="text-base-content/70 text-sm mt-1">
                    {action.description}
                  </p>
                  <div className="card-actions justify-end mt-4">
                    <Link
                      to={action.view}
                      className={`btn btn-sm ${action.style}`}
                    >
                      Go Now
                    </Link>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      </main>

      <Footer />
    </div>
  );
}
