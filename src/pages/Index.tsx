import Leaderboard from "@/components/Leaderboard";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Settings, LogOut } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { toast } from "sonner";

const Index = () => {
  const { isAuthenticated, isAdmin, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login");
    toast.success("Logged out successfully");
  };

  return (
    <div className="relative">
      {/* Top Right Buttons */}
      <div className="fixed top-4 right-4 z-50 flex gap-2 flex-wrap justify-end">
        {/* Admin Editor Button - Only for admins */}
        {isAdmin && (
          <Link to="/admin">
            <Button 
              variant="outline" 
              size="sm" 
              className="gap-2 rounded-full shadow-sm bg-background/80 backdrop-blur-sm border-amber-700/50 text-amber-400 hover:bg-amber-950/20"
            >
              <Settings className="w-4 h-4" />
              Editor
            </Button>
          </Link>
        )}

        {/* Logout Button */}
        {isAuthenticated && (
          <Button
            variant="outline"
            size="sm"
            onClick={handleLogout}
            className="gap-2 rounded-full shadow-sm bg-background/80 backdrop-blur-sm"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </Button>
        )}
      </div>
      <Leaderboard />
    </div>
  );
};

export default Index;
