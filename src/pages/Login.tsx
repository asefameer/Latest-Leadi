import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";
import { Trophy, Eye, EyeOff } from "lucide-react";

type LoginTab = "tso" | "management" | "admin";

const Login = () => {
  const [tab, setTab] = useState<LoginTab>("tso");

  // TSO fields
  const [tsoUsername, setTsoUsername] = useState("");
  const [tsoPassword, setTsoPassword] = useState("");

  // Management fields
  const [mgmtUserId, setMgmtUserId] = useState("");
  const [mgmtPassword, setMgmtPassword] = useState("");

  // Admin fields
  const [adminEmail, setAdminEmail] = useState("");
  const [adminPassword, setAdminPassword] = useState("");

  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const { login, loginTSO, loginManagement } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      if (tab === "tso") {
        await loginTSO(tsoUsername, tsoPassword);
      } else if (tab === "management") {
        await loginManagement(mgmtUserId, mgmtPassword);
      } else {
        await login(adminEmail, adminPassword);
      }
      toast.success("Logged in successfully!");
      navigate("/");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Login failed");
    } finally {
      setIsLoading(false);
    }
  };

  const tabs: { key: LoginTab; label: string }[] = [
    { key: "tso", label: "TSO" },
    { key: "management", label: "Management" },
    { key: "admin", label: "Admin" },
  ];

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 to-slate-800 p-4">
      <div className="w-full max-w-md space-y-8">
        <div className="text-center space-y-2">
          <div className="flex justify-center">
            <div className="bg-gradient-to-br from-amber-400 to-orange-500 p-3 rounded-full">
              <Trophy className="w-8 h-8 text-white" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-white">Top Performers</h1>
          <p className="text-slate-400">Leaderboard Management System</p>
        </div>

        <Card className="bg-slate-800 border-slate-700">
          <CardHeader className="space-y-2">
            <CardTitle className="text-white">Sign In</CardTitle>
            <CardDescription>Select your role and enter your credentials</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-1 mb-6 bg-slate-900 p-1 rounded-lg">
              {tabs.map((t) => (
                <button
                  key={t.key}
                  type="button"
                  onClick={() => setTab(t.key)}
                  className={`flex-1 py-2 text-sm font-medium rounded-md transition-colors ${
                    tab === t.key ? "bg-amber-500 text-white" : "text-slate-400 hover:text-white"
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              {tab === "tso" && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="tso-username" className="text-slate-300">Username</Label>
                    <Input
                      id="tso-username"
                      type="text"
                      placeholder="Enter your username"
                      value={tsoUsername}
                      onChange={(e) => setTsoUsername(e.target.value)}
                      disabled={isLoading}
                      className="bg-slate-700 border-slate-600 text-white placeholder:text-slate-500"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="tso-password" className="text-slate-300">Password</Label>
                    <div className="relative">
                      <Input
                        id="tso-password"
                        type={showPassword ? "text" : "password"}
                        placeholder="••••••••"
                        value={tsoPassword}
                        onChange={(e) => setTsoPassword(e.target.value)}
                        disabled={isLoading}
                        className="bg-slate-700 border-slate-600 text-white placeholder:text-slate-500 pr-10"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-300"
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                </>
              )}

              {tab === "management" && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="mgmt-userid" className="text-slate-300">User ID</Label>
                    <Input
                      id="mgmt-userid"
                      type="text"
                      placeholder="Enter your user ID"
                      value={mgmtUserId}
                      onChange={(e) => setMgmtUserId(e.target.value)}
                      disabled={isLoading}
                      className="bg-slate-700 border-slate-600 text-white placeholder:text-slate-500"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="mgmt-password" className="text-slate-300">Password</Label>
                    <div className="relative">
                      <Input
                        id="mgmt-password"
                        type={showPassword ? "text" : "password"}
                        placeholder="••••••••"
                        value={mgmtPassword}
                        onChange={(e) => setMgmtPassword(e.target.value)}
                        disabled={isLoading}
                        className="bg-slate-700 border-slate-600 text-white placeholder:text-slate-500 pr-10"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-300"
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                </>
              )}

              {tab === "admin" && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="admin-email" className="text-slate-300">Email</Label>
                    <Input
                      id="admin-email"
                      type="email"
                      placeholder="admin@example.com"
                      value={adminEmail}
                      onChange={(e) => setAdminEmail(e.target.value)}
                      disabled={isLoading}
                      className="bg-slate-700 border-slate-600 text-white placeholder:text-slate-500"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="admin-password" className="text-slate-300">Password</Label>
                    <div className="relative">
                      <Input
                        id="admin-password"
                        type={showPassword ? "text" : "password"}
                        placeholder="••••••••"
                        value={adminPassword}
                        onChange={(e) => setAdminPassword(e.target.value)}
                        disabled={isLoading}
                        className="bg-slate-700 border-slate-600 text-white placeholder:text-slate-500 pr-10"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-300"
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                </>
              )}

              <Button
                type="submit"
                disabled={isLoading}
                className="w-full bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-600 hover:to-orange-600 text-white font-semibold"
              >
                {isLoading ? "Signing in..." : "Sign In"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Login;