import { useEffect, useState } from "react";
import { Outlet, useNavigate } from "react-router";
import axiosInstance from "../api/axios";

export default function RequireUser() {
  const navigate = useNavigate();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    let isMounted = true;

    const verify = async () => {
      try {
        await axiosInstance.get("/home");
        if (isMounted) setChecking(false);
      } catch (error) {
        if (isMounted) navigate("/auth");
      }
    };

    verify();

    return () => {
      isMounted = false;
    };
  }, [navigate]);

  if (checking) {
    return (
      <div className="flex justify-center items-center h-screen">
        <span className="loading loading-spinner loading-lg text-primary"></span>
      </div>
    );
  }

  return <Outlet />;
}
