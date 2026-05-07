import logo from '../assets/cclogo.png'

const Splash = () => (
  <div className="fixed inset-0 flex items-center justify-center bg-base-100 z-9999 p-8">
    <style>
      {`
            /* Define the Keyframes for the zoom-out and fade effect */
            @keyframes logo-zoom-out {
                0% { transform: scale(1.5); opacity: 1; }
                80% { transform: scale(1.0); opacity: 1; }
                100% { transform: scale(0.5); opacity: 0; }
            }

            /* Apply the animation class */
            .animate-splash {
                animation: logo-zoom-out 2.5s ease-out forwards;
            }
            `}
    </style>

    <div className="flex flex-col items-center justify-center animate-splash">
      {/* Logo Placeholder: Use the brand name with primary color emphasis */}
      <img src={logo} alt="logo" className='w-[15%] mb-5' />
      <h1 className="text-4xl font-extrabold text-base-content tracking-wider">
        MediRaksha
      </h1>
      <span className="loading loading-dots loading-lg text-primary mt-6"></span>
    </div>
  </div>
);

export default Splash