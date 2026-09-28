import { Outlet } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

export default function PublicLayout() {
  return (
    <div className="flex min-h-screen flex-col bg-bg-main">
      <Navbar />
      <main className="fade-in-up flex-1">
        <Outlet />
      </main>
      <Footer />
    </div>
  );
}
