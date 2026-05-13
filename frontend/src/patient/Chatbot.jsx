import { useState } from "react";
import { 
  Bot, ArrowLeft, Heart, Activity, Scale, Ruler, Droplets, 
  Thermometer, Sparkles, Pill, Hospital, UserCog, Stethoscope, ClipboardList 
} from "lucide-react";
import { Link } from "react-router";

export default function AiHealthChatbot() {
  const [step, setStep] = useState(0); 
  const [loading, setLoading] = useState(false);
  
  const [vitals, setVitals] = useState({
    height: "", weight: "", bloodPressure: "", oxygen: "", temperature: "",
    pastDiseases: "", medications: "", allergies: ""
  });

  const [symptoms, setSymptoms] = useState("");

  const handleInputChange = (e) => {
    setVitals({ ...vitals, [e.target.name]: e.target.value });
  };

  const runAnalysis = () => {
    setLoading(true);
    setStep(3);
    // Simulate API delay
    setTimeout(() => {
      setLoading(false);
    }, 2000);
  };

  return (
    <div className="flex flex-col min-h-screen bg-slate-50 font-sans">
      <nav className="bg-white border-b border-slate-200 px-6 py-4 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-4">
          <Link to="/" className="p-2 hover:bg-slate-100 rounded-full transition-colors">
            <ArrowLeft size={20} className="text-slate-600" />
          </Link>
          <h1 className="text-xl font-black text-slate-800 tracking-tight flex items-center gap-2">
            <div className="w-8 h-8 bg-indigo-600 rounded-lg flex items-center justify-center text-white">
                <Bot size={20} />
            </div>
            HealthAI Diagnostic
          </h1>
        </div>
      </nav>

      <main className="flex-1 flex flex-col items-center py-10 px-6 max-w-5xl mx-auto w-full">
        
        {/* --- AI ROBOT AVATAR --- */}
        <div className="relative mb-8">
          <div className={`absolute inset-0 rounded-full bg-indigo-500/20 animate-ping ${loading ? 'opacity-100' : 'opacity-0'}`}></div>
          <div className="relative w-24 h-24 bg-white rounded-full shadow-xl border-4 border-indigo-50 flex items-center justify-center z-10">
            <Bot size={40} className={`${loading ? 'text-indigo-600 animate-bounce' : 'text-slate-400'}`} />
          </div>
        </div>

        <div className="w-full bg-white rounded-[2.5rem] shadow-xl shadow-slate-200/60 p-8 md:p-12 border border-slate-100">
          
          {/* Step 1: Extended Vitals & History */}
          {step === 1 && (
            <div className="space-y-8">
              <div className="flex items-center justify-between">
                <h3 className="text-2xl font-bold text-slate-800 flex items-center gap-2">
                    <Activity className="text-indigo-600" /> Vitals & History
                </h3>
                <span className="text-xs font-bold text-slate-400 uppercase tracking-widest bg-slate-100 px-3 py-1 rounded-full">Step 1 of 2</span>
              </div>
              <div className="form-control">
                <label className="label text-xs font-black uppercase text-slate-400 tracking-widest">Height (cm)</label>
                <div className="relative">
                  <Ruler className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
                  <input type="number" name="height" placeholder="175" className="input input-bordered w-full pl-12 rounded-xl" onChange={handleInputChange} />
                </div>
              </div>
              <div className="form-control">
                <label className="label text-xs font-black uppercase text-slate-400 tracking-widest">Weight (kg)</label>
                <div className="relative">
                  <Scale className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
                  <input type="number" name="weight" placeholder="70" className="input input-bordered w-full pl-12 rounded-xl" onChange={handleInputChange} />
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="form-control">
                  <label className="label text-[10px] font-black uppercase text-slate-400">BP (mmHg)</label>
                  <input type="text" name="bloodPressure" placeholder="120/80" className="input input-bordered rounded-xl" onChange={handleInputChange} />
                </div>
                <div className="form-control">
                  <label className="label text-[10px] font-black uppercase text-slate-400">Oxygen (SpO2%)</label>
                  <input type="number" name="oxygen" placeholder="98" className="input input-bordered rounded-xl" onChange={handleInputChange} />
                </div>
                <div className="form-control">
                  <label className="label text-[10px] font-black uppercase text-slate-400">Temp (°C)</label>
                  <input type="number" name="temperature" placeholder="36.5" className="input input-bordered rounded-xl" onChange={handleInputChange} />
                </div>
              </div>

              <div className="divider text-slate-300 text-[10px] font-bold uppercase tracking-widest">Medical Background</div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="form-control">
                  <label className="label text-xs font-bold text-slate-600">Past Diseases / Surgeries</label>
                  <textarea name="pastDiseases" placeholder="Diabetes, Hypertension, etc." className="textarea textarea-bordered rounded-xl h-24" onChange={handleInputChange}></textarea>
                </div>
                <div className="form-control">
                  <label className="label text-xs font-bold text-slate-600">Current Medications & Allergies</label>
                  <textarea name="medications" placeholder="Aspirin, Penicillin allergy, etc." className="textarea textarea-bordered rounded-xl h-24" onChange={handleInputChange}></textarea>
                </div>
              </div>

              <div className="flex justify-end pt-4">
                 <button onClick={() => setStep(2)} className="btn bg-indigo-600 hover:bg-indigo-700 text-white border-none rounded-xl px-10">Next: Symptoms</button>
              </div>
            </div>
          )}

          {/* Step 2: Symptoms */}
          {step === 2 && (
            <div className="space-y-6">
               <h3 className="text-2xl font-bold text-slate-800 flex items-center gap-2">
                <Thermometer className="text-indigo-600" /> Describe Condition
              </h3>
              <textarea 
                className="textarea textarea-bordered w-full h-48 rounded-2xl text-lg p-6 focus:ring-2 focus:ring-indigo-500 transition-all" 
                placeholder="Example: I have a sharp pain in my lower back and mild fever since yesterday..."
                value={symptoms}
                onChange={(e) => setSymptoms(e.target.value)}
              />
              <div className="flex justify-between">
                <button onClick={() => setStep(1)} className="btn btn-ghost">Back</button>
                <button onClick={runAnalysis} className="btn bg-indigo-600 text-white border-none rounded-xl px-12">Analyze Now</button>
              </div>
            </div>
          )}

          {/* Step 3: Dummy Results Dashboard */}
          {step === 3 && (
            <div className="space-y-8 animate-in fade-in zoom-in duration-500">
              {loading ? (
                <div className="text-center py-20">
                    <span className="loading loading-spinner loading-lg text-indigo-600 mb-4"></span>
                    <p className="text-slate-500 font-bold animate-pulse tracking-widest">CALCULATING ACCURACY & RISKS...</p>
                </div>
              ) : (
                <>
                  <div className="flex flex-col md:flex-row items-center justify-between gap-4 border-b border-slate-100 pb-8">
                    <div>
                        <h3 className="text-3xl font-black text-slate-800 tracking-tight">Diagnostic Summary</h3>
                        <p className="text-slate-500">Based on provided vitals and historical data</p>
                    </div>
                    <div className="radial-progress text-indigo-600 font-black" style={{"--value":85, "--size": "5rem", "--thickness": "8px"}} role="progressbar">
                        85% <span className="text-[10px] block">Accurate</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {/* Prescriptions */}
                    <div className="bg-emerald-50 rounded-3xl p-6 border border-emerald-100">
                        <div className="flex items-center gap-2 text-emerald-700 font-bold mb-4 uppercase text-xs tracking-wider">
                            <Pill size={18} /> Suggested Precautions
                        </div>
                        <ul className="space-y-3">
                            <li className="flex gap-2 text-sm text-emerald-800 font-medium">
                                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 mt-1.5"></div>
                                Paracetamol 500mg (If fever persists)
                            </li>
                            <li className="flex gap-2 text-sm text-emerald-800 font-medium">
                                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 mt-1.5"></div>
                                Increased Electrolyte intake (ORS)
                            </li>
                            <li className="flex gap-2 text-sm text-emerald-800 font-medium">
                                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 mt-1.5"></div>
                                Bed rest for 24-48 hours
                            </li>
                        </ul>
                    </div>

                    {/* Specialists */}
                    <div className="bg-blue-50 rounded-3xl p-6 border border-blue-100">
                        <div className="flex items-center gap-2 text-blue-700 font-bold mb-4 uppercase text-xs tracking-wider">
                            <Stethoscope size={18} /> Consult Specialist
                        </div>
                        <div className="flex items-center gap-4 bg-white p-3 rounded-2xl border border-blue-50 mb-3">
                            <div className="bg-blue-600 text-white p-2 rounded-xl"><UserCog size={20}/></div>
                            <div>
                                <p className="text-sm font-bold text-slate-800">General Physician</p>
                                <p className="text-[10px] text-slate-500">Immediate Consultation</p>
                            </div>
                        </div>
                        <div className="flex items-center gap-4 bg-white p-3 rounded-2xl border border-blue-50">
                            <div className="bg-indigo-600 text-white p-2 rounded-xl"><ClipboardList size={20}/></div>
                            <div>
                                <p className="text-sm font-bold text-slate-800">Diagnostic Lab</p>
                                <p className="text-[10px] text-slate-500">CBC & CRP Blood Test</p>
                            </div>
                        </div>
                    </div>
                  </div>

                  {/* Hospital Recommendation */}
                  <div className="bg-slate-900 rounded-[2rem] p-8 text-white relative overflow-hidden">
                    <div className="relative z-10">
                        <div className="flex items-center gap-2 text-indigo-400 font-bold text-xs tracking-widest uppercase mb-4">
                            <Hospital size={18} /> Recommended Center
                        </div>
                        <h4 className="text-xl font-bold">City Central Hospital & Trauma Center</h4>
                        <p className="text-slate-400 text-sm mt-2">2.4 km away • 24/7 Emergency Available</p>
                        <button className="btn btn-sm mt-6 bg-indigo-600 border-none text-white px-6">Book Appointment</button>
                    </div>
                    <Hospital className="absolute -right-4 -bottom-4 text-white/5" size={150} />
                  </div>

                  <button onClick={() => setStep(0)} className="btn btn-block bg-slate-100 border-none text-slate-600 hover:bg-slate-200 rounded-xl">Start New Diagnostic</button>
                </>
              )}
            </div>
          )}

          {/* Welcome Screen */}
          {step === 0 && (
            <div className="text-center py-10">
                <h2 className="text-4xl font-black text-slate-800 mb-4 tracking-tight">Virtual Health Scan</h2>
                <p className="text-slate-500 text-lg mb-10 max-w-md mx-auto">Let's analyze your health data. I'll ask for your vitals, history, and symptoms to give a precise summary.</p>
                <button onClick={() => setStep(1)} className="btn btn-lg bg-indigo-600 text-white border-none rounded-2xl px-12 shadow-xl shadow-indigo-100">Begin Assessment</button>
            </div>
          )}

        </div>
      </main>
    </div>
  );
}