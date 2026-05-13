import { useState } from "react";
import axiosInstance from "../api/axios";
import { Link } from "react-router";
import { ArrowLeft } from "lucide-react";
import toast from "react-hot-toast";
import { GoogleLogin } from "@react-oauth/google";

const Auth = () => {
  const [isSignUp, setIsSignUp] = useState(true);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");

  const handlePostAuthRedirect = (data) => {
    if (!data.gender || !data.age) {
      window.location.href = "/details";
    } else {
      window.location.href = "/";
    }
  };

  const handleSignup = async (e) => {
    e.preventDefault();
    try {
      await axiosInstance.post("/auth", { name, email, password });
      toast.success("Signup successful");
      await handleLogin(); 
    } catch (err) {
      toast.error(err.response?.data?.message || "User already exists.");
    }
  };

  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    try {
      await axiosInstance.post("/auth/login", { email, password });
      toast.success("Login successful");
      const res = await axiosInstance.get("/home");
      handlePostAuthRedirect(res.data);
    } catch (err) {
      toast.error(err.response?.data?.message || "Wrong username or password");
    }
  };

  const handleGoogleSuccess = async (credentialResponse) => {
    try {
      const res = await axiosInstance.post("/auth/google", {
        token: credentialResponse.credential,
      });
      toast.success("Logged in with Google");
      handlePostAuthRedirect(res.data);
    } catch (err) {
      toast.error("Google login failed");
    }
  };

  return (
    <div className="min-h-screen bg-slate-100 flex items-center justify-center p-4 font-sans">
      {/* Back Button */}
      <Link to="/" className="absolute top-8 left-8 flex items-center gap-2 text-slate-500 hover:text-indigo-600 transition-colors group">
        <ArrowLeft size={20} className="group-hover:-translate-x-1 transition-transform" />
        <span className="font-medium">Back to Home</span>
      </Link>

      {/* Main Auth Card */}
      <div className="relative w-full max-w-4xl h-[650px] bg-white rounded-[2rem] shadow-2xl overflow-hidden flex">
        
        {/* --- SIGN IN FORM (Left Side) --- */}
        <div className={`absolute top-0 left-0 w-1/2 h-full transition-all duration-700 ease-in-out z-[1] ${isSignUp ? "translate-x-full opacity-0" : "translate-x-0 opacity-100"}`}>
          <div className="h-full flex flex-col justify-center px-16">
            <form onSubmit={handleLogin} className="space-y-5">
              <div className="text-center mb-8">
                <h1 className="text-4xl font-black text-slate-800 tracking-tight">Welcome Back</h1>
                <p className="text-slate-400 mt-2">Please enter your details</p>
              </div>
              
              <div className="space-y-4">
                <input 
                  type="text" 
                  placeholder="Username / Email"
                  className="input input-bordered w-full bg-slate-50 border-none ring-1 ring-slate-200 focus:ring-2 focus:ring-indigo-500 transition-all" 
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required 
                />
                <input 
                  type="password" 
                  placeholder="Password"
                  className="input input-bordered w-full bg-slate-50 border-none ring-1 ring-slate-200 focus:ring-2 focus:ring-indigo-500 transition-all" 
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required 
                />
              </div>

              <button className="btn btn-primary w-full bg-indigo-600 border-none hover:bg-indigo-700 text-white shadow-lg shadow-indigo-100 rounded-xl h-12">
                Sign In
              </button>
              
              <div className="divider text-xs text-slate-300 font-medium">OR CONTINUE WITH</div>
              
              <div className="flex justify-center scale-95">
                <GoogleLogin onSuccess={handleGoogleSuccess} onError={() => toast.error("Google login failed")} />
              </div>
            </form>
          </div>
        </div>

        {/* --- SIGN UP FORM (Right Side) --- */}
        <div className={`absolute top-0 left-0 w-1/2 h-full transition-all duration-700 ease-in-out z-[2] ${isSignUp ? "translate-x-full opacity-100" : "translate-x-0 opacity-0 pointer-events-none"}`}>
          <div className="h-full flex flex-col justify-center px-16">
            <form onSubmit={handleSignup} className="space-y-4">
              <div className="text-center mb-6">
                <h1 className="text-4xl font-black text-slate-800 tracking-tight">Create Account</h1>
                <p className="text-slate-400 mt-2">Join our healthcare community</p>
              </div>
              
              <div className="space-y-3">
                <input 
                  type="text" 
                  placeholder="Full Name"
                  className="input input-bordered w-full bg-slate-50 border-none ring-1 ring-slate-200 focus:ring-2 focus:ring-indigo-500 transition-all" 
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required 
                />
                <input 
                  type="email" 
                  placeholder="Email"
                  className="input input-bordered w-full bg-slate-50 border-none ring-1 ring-slate-200 focus:ring-2 focus:ring-indigo-500 transition-all" 
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required 
                />
                <input 
                  type="password" 
                  placeholder="Password"
                  className="input input-bordered w-full bg-slate-50 border-none ring-1 ring-slate-200 focus:ring-2 focus:ring-indigo-500 transition-all" 
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required 
                />
              </div>

              <button className="btn btn-primary w-full bg-indigo-600 border-none hover:bg-indigo-700 text-white shadow-lg shadow-indigo-100 rounded-xl h-12 mt-4">
                Sign Up
              </button>

              <div className="divider text-xs text-slate-300 font-medium">OR</div>
              
              <div className="flex justify-center scale-95">
                <GoogleLogin onSuccess={handleGoogleSuccess} onError={() => toast.error("Google login failed")} />
              </div>
            </form>
          </div>
        </div>

        {/* --- SLIDING OVERLAY PANEL --- */}
        <div 
          className={`absolute top-0 left-1/2 w-1/2 h-full z-[100] transition-transform duration-700 ease-in-out overflow-hidden
            ${isSignUp ? "-translate-x-full" : "translate-x-0"}`}
        >
          <div 
            className={`relative -left-full h-full w-[200%] transform transition-transform duration-700 ease-in-out text-white flex
              ${isSignUp ? "translate-x-1/2" : "translate-x-0"}`}
            style={{ background: 'linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)' }}
          >
            {/* Content for Login Side */}
            <div className="w-1/2 h-full flex flex-col items-center justify-center p-12 text-center">
              <h2 className="text-4xl font-bold mb-4">One of us?</h2>
              <p className="mb-8 opacity-80 leading-relaxed text-lg">If you already have an account, just sign in.</p>
              <button 
                onClick={() => setIsSignUp(false)}
                className="btn btn-outline border-white text-white hover:bg-white hover:text-indigo-600 px-12 rounded-full border-2 h-12"
              >
                SIGN IN
              </button>
              <Link to="/doctor" className="mt-8 text-sm underline opacity-70 hover:opacity-100 transition-opacity">
                Are you a doctor?
              </Link>
            </div>

            {/* Content for Signup Side */}
            <div className="w-1/2 h-full flex flex-col items-center justify-center p-12 text-center">
              <h2 className="text-4xl font-bold mb-4">New Here?</h2>
              <p className="mb-8 opacity-80 leading-relaxed text-lg">Enter your personal details and start your journey with our healthcare platform.</p>
              <button 
                onClick={() => setIsSignUp(true)}
                className="btn btn-outline border-white text-white hover:bg-white hover:text-indigo-600 px-12 rounded-full border-2 h-12"
              >
                SIGN UP
              </button>
              <Link to="/doctor" className="mt-8 text-sm underline opacity-70 hover:opacity-100 transition-opacity">
                Are you a doctor?
              </Link>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};

export default Auth;