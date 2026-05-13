import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import { Link } from "react-router";
import { useEffect, useState } from "react";
import axiosInstance from "../api/axios";
import car1 from '../assets/car1.jpg';
import car2 from '../assets/car21.png';

import { Brain, Hospital, ShieldCheck, MapPin, Sparkles, ArrowRight } from "lucide-react";

const quickActions = [
  {
    id: 1,
    title: "Nearby Care",
    icon: <MapPin size={28} />,
    description: "Locate certified hospitals and clinics using real-time GPS tracking.",
    style: "bg-blue-50 text-blue-600 ring-blue-100",
    view: "/map",
    btnClass: "btn-primary"
  },
  {
    id: 2,
    title: "AI Medical Assistant",
    icon: <Brain size={28} />,
    description: "Get instant health insights and symptom analysis powered by AI.",
    style: "bg-purple-50 text-purple-600 ring-purple-100",
    view: "/ai",
    btnClass: "btn-secondary"
  },
  {
    id: 3,
    title: "View Health Summary",
    icon: <ShieldCheck size={28} />,
    description: "Access a detailed chronological history of your medical interactions.",
    style: "bg-emerald-50 text-emerald-600 ring-emerald-100",
    view: "/history",
    btnClass: "btn-accent"
  }
];

export default function Dashboard() {
  const [name, setName] = useState("");
  const [loading, setLoading] = useState(true);

  const getUser = async () => {
    try {
      const res = await axiosInstance.get("/home");
      setName(res.data.name);
    } catch (error) {
      console.error("User not logged in");
    } finally {
      setLoading(false);
    }
  };

  const checkDoctor = async () => {
    try {
      const res = await axiosInstance.get('/doctor');
      if (res.data) window.location.href = '/doctordash';
    } catch (e) { /* Not a doctor */ }
  };

  // useEffect(() => {
  //   checkDoctor();
  //   getUser();
  // }, []);

  return (
    <div className="flex flex-col min-h-screen bg-slate-50/50">
      <Navbar />

      <main className="grow max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-8 space-y-10">
        
        {/* --- WELCOME HERO SECTION --- */}
        <section className="relative overflow-hidden rounded-[2.5rem] bg-slate-900 text-white p-8 md:p-12 shadow-2xl">
          <div className="relative z-10 lg:w-2/3">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-xs font-bold tracking-widest uppercase mb-6">
              <Sparkles size={14} /> Global Health Ecosystem
            </div>
            <h1 className="text-4xl md:text-5xl font-black mb-4 tracking-tight">
              {name ? `Welcome back, ${name.split(' ')[0]}!` : "Your Health, Fully Protected."}
            </h1>
            <p className="text-lg text-slate-300 mb-8 max-w-xl leading-relaxed">
              MediRaksha bridges the gap between you and world-class care. 
              Manage records, find doctors, and get AI-driven health support in one place.
            </p>
            {!name && (
              <Link to="/auth" className="btn btn-primary bg-indigo-600 border-none hover:bg-indigo-700 px-8 rounded-xl h-12">
                Get Started Now <ArrowRight size={18} />
              </Link>
            )}
          </div>
          
          {/* Abstract background shapes for the professional look */}
          <div className="absolute top-0 right-0 w-1/3 h-full bg-linear-to-l from-indigo-600/20 to-transparent pointer-events-none"></div>
          <div className="absolute -bottom-24 -right-24 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl"></div>
        </section>

        {/* --- CAROUSEL / PROMOTIONS --- */}
        <section className="relative group">
          <div className="carousel w-full rounded-4xl shadow-xl border border-white h-75 md:h-100">
            <div id="slide1" className="carousel-item relative w-full overflow-hidden">
              <img src={car1} className="w-full object-cover" alt="Health Banner 1" />
              <div className="absolute inset-0 bg-black/20"></div>
              <div className="absolute bottom-10 left-10 text-white">
                <h3 className="text-2xl font-bold">Advanced Diagnostics</h3>
                <p className="opacity-80">Access AI-powered health analysis anywhere.</p>
              </div>
              <div className="absolute left-5 right-5 top-1/2 flex -translate-y-1/2 justify-between">
                <a href="#slide2" className="btn btn-circle bg-white/20 border-none text-white backdrop-blur-md hover:bg-white/40">❮</a>
                <a href="#slide2" className="btn btn-circle bg-white/20 border-none text-white backdrop-blur-md hover:bg-white/40">❯</a>
              </div>
            </div>
            <div id="slide2" className="carousel-item relative w-full overflow-hidden">
              <img src={car2} className="w-full object-cover" alt="Health Banner 2" />
              <div className="absolute inset-0 bg-black/20"></div>
              <div className="absolute bottom-10 left-10 text-white">
                <h3 className="text-2xl font-bold">Verified Hospitals</h3>
                <p className="opacity-80">Real-time availability at your fingertips.</p>
              </div>
              <div className="absolute left-5 right-5 top-1/2 flex -translate-y-1/2 justify-between">
                <a href="#slide1" className="btn btn-circle bg-white/20 border-none text-white backdrop-blur-md hover:bg-white/40">❮</a>
                <a href="#slide1" className="btn btn-circle bg-white/20 border-none text-white backdrop-blur-md hover:bg-white/40">❯</a>
              </div>
            </div>
          </div>
        </section>

        {/* --- QUICK ACTIONS SECTION --- */}
        <section>
          <div className="flex items-end justify-between mb-8">
            <div>
              <h2 className="text-3xl font-black text-slate-800 tracking-tight">Quick Services</h2>
              <p className="text-slate-500 mt-1 font-medium">Everything you need for your healthcare journey</p>
            </div>
            <div className="hidden md:block h-px grow mx-8 bg-slate-200"></div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {quickActions.map((action) => (
              <div
                key={action.id}
                className="group relative bg-white border border-slate-100 p-8 rounded-4xl shadow-sm hover:shadow-xl hover:-translate-y-2 transition-all duration-300"
              >
                <div className={`w-14 h-14 rounded-2xl flex items-center justify-center mb-6 ring-4 ${action.style}`}>
                  {action.icon}
                </div>
                <h3 className="text-xl font-bold text-slate-800 mb-3 tracking-tight">
                  {action.title}
                </h3>
                <p className="text-slate-500 text-sm leading-relaxed mb-6">
                  {action.description}
                </p>
                <Link
                  to={action.view}
                  className={`flex items-center gap-2 font-bold text-sm group-hover:gap-4 transition-all duration-300 ${action.style.split(' ')[1]}`}
                >
                  Explore Service <ArrowRight size={16} />
                </Link>
              </div>
            ))}
          </div>
        </section>

        {/* --- INFO / TRUST SECTION --- */}
        <section className="bg-indigo-50/50 rounded-[2.5rem] p-8 md:p-12 border border-indigo-100/50 flex flex-col md:flex-row items-center gap-10">
          <div className="md:w-1/2">
            <h2 className="text-3xl font-black text-slate-800 mb-4 leading-tight">Your Data, Encrypted <br/> & Secure.</h2>
            <p className="text-slate-600 mb-6 leading-relaxed">
              We use AES-256 encryption to ensure your medical records are only accessible to you and the doctors you authorize. No third-party access, ever.
            </p>
            <div className="flex gap-6">
              <div className="flex flex-col">
                <span className="text-2xl font-black text-indigo-600">100%</span>
                <span className="text-xs font-bold text-slate-400 uppercase tracking-widest">Privacy</span>
              </div>
              <div className="flex flex-col">
                <span className="text-2xl font-black text-indigo-600">24/7</span>
                <span className="text-xs font-bold text-slate-400 uppercase tracking-widest">AI Support</span>
              </div>
            </div>
          </div>
          <div className="md:w-1/2 grid grid-cols-2 gap-4">
            <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-100">
               <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center text-blue-600 mb-3">
                 <ShieldCheck size={20} />
               </div>
               <p className="font-bold text-slate-800 text-sm">HIPAA Compliant</p>
            </div>
            <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-100 mt-4">
               <div className="w-10 h-10 bg-indigo-100 rounded-full flex items-center justify-center text-indigo-600 mb-3">
                 <Brain size={20} />
               </div>
               <p className="font-bold text-slate-800 text-sm">LLM Analysis</p>
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  );
}