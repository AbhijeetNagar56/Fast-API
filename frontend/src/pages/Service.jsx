import {  ClipboardMinus, FileClock, CalendarCheck2, Bed, BriefcaseMedical, UserSearch } from "lucide-react";
import { Link } from "react-router";
import Navbar from "../components/Navbar"
import Footer from "../components/Footer"

const quickActions = [
  
  {
    id: 1,
    title: "Upload Medical Reports",
    icon: <ClipboardMinus />,
    description: "Securely upload and manage reports.",
    style: "btn-secondary",
    view: "/upload",
  },
  
  {
    id: 2,
    title: "Book an Appointment",
    icon: <CalendarCheck2 />,
    description: "Book an appointment with specilist pratitioners.",
    style: "btn-info",
    view: "/appointment",
  },
  
  {
    id: 3,
    title: "Doctor availability",
    icon: <UserSearch />,
    description: "See the doctor availability.",
    style: "btn-neutral",
    view: "/slots",
  },
  {
    id: 4,
    title: "Search for doctor",
    icon: <BriefcaseMedical />, 
    description: "Find a doctor",
    style: "btn-secondary",
    view: "/mydoctor",
  },
  {
    id: 5,
    title: "View Health Summary",
    icon: <FileClock />,
    description: "See history and recent interactions.",
    style: "btn-accent",
    view: "/history",
  },
  {
    id: 6,
    title: "Bed availability",
    icon: <Bed />,
    description: "See the bed available in the hospitals.",
    style: "btn-success",
    view: "/bedavailable",
  },

];


const Service = () => {
  return (
    <div>
        <Navbar />
        <div className="container justify-self-center my-10">
        <section>
          <h2 className="text-2xl font-semibold ml-5 mb-6 text-base-content">
            All Services
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {quickActions.map((action) => (
              <div
                key={action.id}
                className="card mx-5 shadow-lg bg-base-100 transition duration-300 transform hover:scale-[1.02] cursor-pointer"
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
        </div>
        <Footer />
    </div>
  )
}

export default Service
