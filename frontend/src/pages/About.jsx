import Navbar from '../components/Navbar';
import Footer from '../components/Footer';
import { MapPinned, GlobeLock, FileCog, ShieldCheck, HeartPulse, Target } from 'lucide-react';

const About = () => {
  return (
    <div className="flex flex-col min-h-screen bg-white">
      <Navbar />

      <main className="grow">
        {/* --- HERO SECTION --- */}
        <section className="relative bg-slate-900 py-24 sm:py-32 overflow-hidden">
          <div className="absolute inset-0 opacity-10">
            <div className="absolute -top-24 -left-24 w-96 h-96 bg-indigo-500 rounded-full blur-3xl"></div>
            <div className="absolute top-1/2 left-1/2 w-full h-full bg-slate-800 rotate-12 transform -translate-x-1/2 -translate-y-1/2"></div>
          </div>

          <div className="relative max-w-7xl mx-auto px-6 lg:px-8 text-center">
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-bold tracking-widest uppercase mb-8">
              <HeartPulse size={14} /> Our Mission
            </div>
            <h1 className="text-5xl md:text-7xl font-black tracking-tight text-white mb-8">
              Bridging the Gap Between <br/>
              <span className="bg-gradient-to-r from-indigo-400 to-cyan-400 bg-clip-text text-transparent">Care and Patient</span>
            </h1>
            <p className="max-w-3xl mx-auto text-xl text-slate-400 leading-relaxed">
              MediRaksha was founded on a simple premise: in a medical crisis, every second counts. 
              We leverage cutting-edge technology to ensure that life-saving data and professional care 
              are never more than a click away.
            </p>
          </div>
        </section>

        {/* --- STATS SECTION --- */}
        <section className="py-12 bg-indigo-600">
          <div className="max-w-7xl mx-auto px-6 grid grid-cols-1 md:grid-cols-3 gap-8 text-center">
            <div>
              <div className="text-4xl font-black text-white">24/7</div>
              <div className="text-indigo-100 text-sm font-bold uppercase tracking-widest mt-1">Availability</div>
            </div>
            <div>
              <div className="text-4xl font-black text-white">100%</div>
              <div className="text-indigo-100 text-sm font-bold uppercase tracking-widest mt-1">Data Privacy</div>
            </div>
            <div>
              <div className="text-4xl font-black text-white">Instant</div>
              <div className="text-indigo-100 text-sm font-bold uppercase tracking-widest mt-1">AI Diagnostics</div>
            </div>
          </div>
        </section>

        {/* --- OUR VALUES SECTION --- */}
        <section id="our-values" className="py-24 bg-slate-50">
          <div className="max-w-7xl mx-auto px-6">
            <div className="flex flex-col md:flex-row justify-between items-end mb-16 gap-4">
              <div className="max-w-2xl">
                <h2 className="text-4xl font-black text-slate-800 tracking-tight mb-4">Our Commitment</h2>
                <p className="text-lg text-slate-500 leading-relaxed">
                  MediRaksha is built on three core pillars designed to empower patients and 
                  streamline the clinical workflow for providers.
                </p>
              </div>
              <div className="hidden md:block h-px grow mx-12 bg-slate-200"></div>
            </div>
            
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-10">
              
              {/* Card 1 */}
              <div className="group bg-white p-10 rounded-[2.5rem] border border-slate-100 shadow-sm hover:shadow-2xl hover:-translate-y-2 transition-all duration-500">
                <div className="w-16 h-16 rounded-2xl bg-blue-50 text-blue-600 flex items-center justify-center mb-8 ring-4 ring-blue-50 transition-transform group-hover:scale-110">
                  <MapPinned size={32} />
                </div>
                <h3 className="text-2xl font-bold text-slate-800 mb-4 tracking-tight">Real-Time Accessibility</h3>
                <p className="text-slate-500 leading-relaxed">
                  Instantly connect with nearby facilities. Our live tracking ensures timely and effective 
                  emergency response, significantly reducing critical wait times during golden hours.
                </p>
              </div>

              {/* Card 2 */}
              <div className="group bg-white p-10 rounded-[2.5rem] border border-slate-100 shadow-sm hover:shadow-2xl hover:-translate-y-2 transition-all duration-500">
                <div className="w-16 h-16 rounded-2xl bg-indigo-50 text-indigo-600 flex items-center justify-center mb-8 ring-4 ring-indigo-50 transition-transform group-hover:scale-110">
                  <GlobeLock size={32} />
                </div>
                <h3 className="text-2xl font-bold text-slate-800 mb-4 tracking-tight">Data Security & Privacy</h3>
                <p className="text-slate-500 leading-relaxed">
                  We prioritize patient trust through military-grade encryption. Your medical records 
                  belong to you, and we ensure they remain protected, private, and portable.
                </p>
              </div>

              {/* Card 3 */}
              <div className="group bg-white p-10 rounded-[2.5rem] border border-slate-100 shadow-sm hover:shadow-2xl hover:-translate-y-2 transition-all duration-500">
                <div className="w-16 h-16 rounded-2xl bg-emerald-50 text-emerald-600 flex items-center justify-center mb-8 ring-4 ring-emerald-50 transition-transform group-hover:scale-110">
                  <FileCog size={32} />
                </div>
                <h3 className="text-2xl font-bold text-slate-800 mb-4 tracking-tight">Digital Efficiency</h3>
                <p className="text-slate-500 leading-relaxed">
                  Our seamless digital pipeline eliminates traditional paperwork. By digitizing 
                  reports, we ensure providers have access to vital data when it matters most.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* --- VISION SECTION --- */}
        <section className="py-24 bg-white overflow-hidden">
          <div className="max-w-7xl mx-auto px-6 lg:px-8">
            <div className="bg-slate-900 rounded-[3rem] p-10 md:p-20 relative overflow-hidden">
              <div className="relative z-10 flex flex-col md:flex-row items-center gap-12">
                <div className="md:w-1/2">
                  <div className="flex items-center gap-3 text-indigo-400 font-bold tracking-widest uppercase text-xs mb-6">
                    <Target size={18} /> Our Vision
                  </div>
                  <h2 className="text-4xl font-black text-white mb-6 leading-tight">
                    The Future of Healthcare <br/> is Borderless.
                  </h2>
                  <p className="text-slate-400 text-lg leading-relaxed mb-8">
                    We are building an ecosystem where geographical location no longer dictates 
                    the quality of healthcare. MediRaksha aims to become the global standard for 
                    patient-provider connectivity and secure health data management.
                  </p>
                  <div className="flex items-center gap-4">
                    <div className="w-12 h-12 rounded-xl bg-white/5 flex items-center justify-center text-indigo-400 border border-white/10">
                      <ShieldCheck size={24} />
                    </div>
                    <span className="text-white font-bold">Trusted by 500+ Medical Institutions</span>
                  </div>
                </div>
                <div className="md:w-1/2 flex justify-center">
                   {/* Abstract graphic placeholder */}
                   <div className="w-full aspect-square max-w-[400px] bg-gradient-to-br from-indigo-500/20 to-cyan-500/20 rounded-full flex items-center justify-center p-8">
                      <div className="w-full h-full bg-slate-800 rounded-full border border-white/10 shadow-2xl flex items-center justify-center">
                         <HeartPulse className="text-indigo-500 animate-pulse" size={120} />
                      </div>
                   </div>
                </div>
              </div>
              <div className="absolute -bottom-10 -left-10 w-64 h-64 bg-indigo-600/20 rounded-full blur-3xl"></div>
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  );
};

export default About;