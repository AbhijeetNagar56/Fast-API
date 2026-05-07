import { Link } from "react-router";
import { User } from 'lucide-react';



export default function Navbar() {

  return (
    <div className="navbar bg-base-100 shadow-sm relative z-50">
      <div className="navbar-start">
        <div className="dropdown">
          <div tabIndex={0} role="button" className="btn btn-ghost lg:hidden">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              className="h-5 w-5"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M4 6h16M4 12h8m-8 6h16"
              />
            </svg>
          </div>
          <ul
            tabIndex={0}
            className="menu menu-sm dropdown-content bg-base-100 rounded-box z-1 mt-3 w-52 p-2 shadow"
          >
            <li>
              <Link to="/">Home</Link>
            </li>
            <li>
              <Link to="/services">Services</Link>
              {/* <details>
                <summary>Services</summary>
                <ul className="p-2 z-1">
                  <li>
                    <Link to="/map">Nearby hospitals</Link>
                  </li>
                  <li>
                    <Link to="/upload">Upload report</Link>
                  </li>
                  <li>
                    <Link to="/slots">Doctor Availability</Link>
                  </li>
                </ul>
              </details> */}
            </li>
            <li>
              <Link to="/about">About</Link>
            </li>
          </ul>
        </div>
        <a className="mx-2 font-bold text-2xl">MediRaksha</a>
      </div>
      <div className="navbar-center hidden lg:flex">
        <ul className="menu menu-horizontal px-1">
          <li>
            <Link to="/">Home</Link>
          </li>
          <li>
            
            <Link to="/services">Services</Link>
            
            {/* <details>
              <summary>Services</summary>
              <ul className="p-2 z-50">
                <li>
                  <Link to="/map">Nearby hospitals</Link>
                </li>
                <li>
                  <Link to="/upload">Upload report</Link>
                </li>
                <li>
                  <Link to="/slots">Doctor Availability</Link>
                </li>
                <li>
                  <Link to="/mydoctor">Search for doctor</Link>
                </li>
              </ul>
            </details> */}
          </li>
          <li>
            <Link to="/about">About</Link>
          </li>
        </ul>
      </div>
      <div className="navbar-end">
        <Link to="/detail">
          <div className="btn">
            <User />
            Profile
          </div>
        </Link>
        
      </div>
    </div>
  );
}
