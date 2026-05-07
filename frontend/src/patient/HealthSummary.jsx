import Navbar from "../components/Navbar";
import Footer from "../components/Footer";


export default function HealthSummary() {

    return (
        <div className="flex flex-col min-h-screen">
            <Navbar />
            
            <main className="grow w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-12">
                
                <header className="text-center py-4 border-b border-base-300">
                    <h1 className="text-5xl font-extrabold text-base-content">
                        Personal Health <span className="text-accent">Summary</span>
                    </h1>
                    <p className="text-lg text-base-content/70 mt-2">
                        Your latest vitals, history, and medical records at a glance.
                    </p>

                    <h1 className="text-4xl mt-5">Coming Soon...</h1>
                </header>

            </main>
            
            <Footer />
        </div>
    );
}
