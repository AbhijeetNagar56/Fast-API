// utility imports
import { useState, useEffect } from "react";
import { Toaster } from 'react-hot-toast';
import { Route, Routes } from 'react-router';


// page imports
import Dashboard from './pages/DashBoard';
import About from "./pages/About";
import Service from "./pages/Service";


// component imports
import Splash from './components/Splash';


// doctor page imports
import DoctorDet from './doctor/DoctorDet'
import DoctorDetails from './doctor/DoctorDetail';
import MyPatient from './doctor/MyPatient';
import DoctorAuth from './doctor/DoctorAuth';
import DoctorDash from './doctor/DoctorDash';


// patient page imports
import HealthSummary from './patient/HealthSummary';
import AppointmentCalendar from './patient/Appointment';
import Chatbot from './patient/Chatbot';
import Upload from './patient/Upload'
import MyDetail from './patient/MyDet';
import Map from './patient/MapComponent'
import MyDoctor from './patient/MyDoctor';
import Auth from './patient/Auth';
import DetailConfirmation from './patient/DetailConfirmation'
import DoctorAvailability from './patient/DoctorAvailability';
import BedAvailability from './patient/BedAvailability';


export default function App() {

  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsLoading(false);
    }, 3000);

    return () => clearTimeout(timer);
  }, []);

  if (isLoading) {
    return <Splash />;
  }
  

  return (
    <div>
      <Toaster />
      <Routes>
        {/* Define routes for the application */}
        <Route path="/" element={<Dashboard />} />
        <Route path="/auth" element={<Auth />} />
        <Route path='/details' element={<DetailConfirmation />} />
        <Route path='/detail' element={<MyDetail />} />
        <Route path='/upload' element={<Upload />} />
        <Route path='/map' element={<Map />} />
        <Route path='/about' element={<About />} />
        <Route path='/mydoctor' element={<MyDoctor />} />
        <Route path='/appointment' element={<AppointmentCalendar />} />
        <Route path='/ai' element={<Chatbot />} />
        <Route path='/bedavailable' element={<BedAvailability />} />
        <Route path='/history' element={<HealthSummary/>} />
        <Route path='/services' element={<Service/>} />
        

        {/* Doctor related routes */}
        <Route path='/doctor' element={<DoctorAuth />} />
        <Route path='/doctordash' element={<DoctorDash />} />
        <Route path='/doctoravailable' element={<DoctorAvailability />} />
        <Route path='/doctordetail' element={<DoctorDetails />} />
        <Route path='/doctorprofile' element={<DoctorDet />} />
        <Route path='/patients' element={<MyPatient />} />
        
      </Routes>
    </div>
  );
}

