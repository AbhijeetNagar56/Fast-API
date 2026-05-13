import logo from '../assets/cclogo.png'

const Splash = () => (
  <div className="fixed inset-0 flex items-center justify-center bg-base-100 z-9999 overflow-hidden">
    {/* Animated Background Decoration */}
    <div className="absolute inset-0 pointer-events-none">
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-125 h-125 bg-primary/5 rounded-full blur-[120px] animate-pulse"></div>
    </div>

    <style>
      {`
        @keyframes splash-entrance {
            0% { transform: scale(0.9); opacity: 0; filter: blur(10px); }
            20% { transform: scale(1); opacity: 1; filter: blur(0px); }
            85% { transform: scale(1.05); opacity: 1; }
            100% { transform: scale(1.1); opacity: 0; }
        }

        .animate-splash-content {
            animation: splash-entrance 3s cubic-bezier(0.4, 0, 0.2, 1) forwards;
        }

        .letter-glow {
            text-shadow: 0 0 20px rgba(var(--p), 0.2);
        }
      `}
    </style>

    <div className="flex flex-col items-center justify-center animate-splash-content px-6">
      {/* Logo Container */}
      <div className="relative mb-8">
        <img 
          src={logo} 
          alt="MediRaksha Logo" 
          className='w-24 h-24 md:w-32 md:h-32 object-contain drop-shadow-2xl' 
        />
        {/* Subtle ring around logo */}
        <div className="absolute inset-0 border-2 border-primary/20 rounded-full scale-125 animate-ping opacity-20"></div>
      </div>

      {/* Brand Identity */}
      <div className="text-center space-y-2">
        <h1 className="text-5xl font-black text-base-content tracking-[0.2em] uppercase letter-glow">
          Medi<span className="text-primary">Raksha</span>
        </h1>
        <p className="text-slate-400 font-medium tracking-[0.3em] text-xs uppercase opacity-70">
          Your Health, Protected
        </p>
      </div>

      {/* Modern Loading Indicator */}
      <div className="mt-12 flex flex-col items-center gap-3">
        <span className="loading loading-infinity loading-lg text-primary opacity-80"></span>
        <span className="text-[10px] font-bold text-base-content/30 tracking-[0.2em] uppercase">
          Initializing Secure Portal
        </span>
      </div>
    </div>
  </div>
);

export default Splash;