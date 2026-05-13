import axios from "axios";

const axiosInstance = axios.create({
  baseURL: import.meta.env.PROD 
    ? "/api"
    : "http://localhost:5000/api",
  withCredentials: true,
});

export default axiosInstance;