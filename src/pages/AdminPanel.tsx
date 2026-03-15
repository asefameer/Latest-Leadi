import { useEffect, useState } from "react";
import { useLeaderboard } from "@/context/LeaderboardContext";
import { useAuth } from "@/context/AuthContext";
import { TSOData } from "@/types/leaderboard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Upload, Trash2, Image as ImageIcon, ArrowLeft, LogOut, Download, Users, Shield } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import aktLogo from "@/assets/akt-logo.png";
import { parseCSV, downloadCSVTemplate } from "@/lib/csvParser";

const AdminPanel = () => {
  const {
    tsoData,
    setTsoData,
    logo,
    setLogo,
    backgroundMedia,
    setBackgroundMedia,
    backgroundMediaType,
    setBackgroundMediaType,
    siteCopy,
    setSiteCopy,
  } = useLeaderboard();
  const { user, logout, isAdmin } = useAuth();
  const navigate = useNavigate();
  const [uploadingImageId, setUploadingImageId] = useState<string | null>(null);
  const [uploadingTsoCreds, setUploadingTsoCreds] = useState(false);
  const [uploadingMgmtCreds, setUploadingMgmtCreds] = useState(false);
  const [uploadingTsoImages, setUploadingTsoImages] = useState(false);
  const backendUrl = import.meta.env.VITE_CHATBOT_BACKEND_URL || "";
  const [authEvents, setAuthEvents] = useState<Array<{
    id: number;
    userId: number | null;
    email: string | null;
    eventType: string;
    ipAddress: string | null;
    userAgent: string | null;
    createdAt: string;
    role?: string | null;
  }>>([]);
  const [loadingAuthEvents, setLoadingAuthEvents] = useState(false);

  const getAuthToken = () => localStorage.getItem("auth_token");

  const uploadAsset = async (file: File) => {
    const token = getAuthToken();
    if (!token) {
      throw new Error("Authentication required");
    }

    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch(`${backendUrl}/api/admin/content/upload`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
      },
      body: formData,
    });

    if (!response.ok) {
      throw new Error("Upload failed");
    }

    const data = await response.json();
    return data.asset as { storageUrl: string };
  };

  const saveSettings = async (settings: Record<string, string>) => {
    const token = getAuthToken();
    if (!token) {
      throw new Error("Authentication required");
    }

    const response = await fetch(`${backendUrl}/api/admin/content/settings`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ settings }),
    });

    if (!response.ok) {
      throw new Error("Failed to save settings");
    }
  };

  const saveTsoData = async (nextTsoData: TSOData[]) => {
    const token = getAuthToken();
    if (!token) {
      throw new Error("Authentication required");
    }

    const response = await fetch(`${backendUrl}/api/admin/content/tso`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ tsoData: nextTsoData }),
    });

    if (!response.ok) {
      throw new Error("Failed to save leaderboard data");
    }
  };

  const saveSiteCopy = async (nextSiteCopy: Record<string, string>) => {
    const token = getAuthToken();
    if (!token) {
      throw new Error("Authentication required");
    }

    const response = await fetch(`${backendUrl}/api/admin/content/site-copy`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ siteCopy: nextSiteCopy }),
    });

    if (!response.ok) {
      throw new Error("Failed to save site text");
    }
  };

  const handleCSVUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      await uploadAsset(file);

      const csvText = await file.text();
      const parsedData = parseCSV(csvText);
      setTsoData(parsedData);
      await saveTsoData(parsedData);
      toast.success(`Successfully imported ${parsedData.length} TSOs from CSV`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to parse/upload CSV");
    }
  };

  const handleImageUpload = async (tsoId: string, e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploadingImageId(tsoId);
    try {
      const asset = await uploadAsset(file);
      const updatedTsoData = tsoData.map((tso) =>
        tso.id === tsoId ? { ...tso, avatar: asset.storageUrl } : tso
      );
      setTsoData(updatedTsoData);
      await saveTsoData(updatedTsoData);
      toast.success("Image uploaded successfully");
    } catch (error) {
      toast.error("Failed to upload image");
    } finally {
      setUploadingImageId(null);
    }
  };

  const handleDeleteTSO = async (id: string) => {
    const updated = tsoData.filter((tso) => tso.id !== id);
    setTsoData(updated);
    try {
      await saveTsoData(updated);
      toast.success("TSO deleted successfully");
    } catch (error) {
      toast.error("Failed to persist TSO deletion");
    }
  };

  const handleLogoUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const asset = await uploadAsset(file);
      setLogo(asset.storageUrl);
      await saveSettings({ logoUrl: asset.storageUrl });
      toast.success("Logo uploaded successfully");
    } catch (error) {
      toast.error("Failed to upload logo");
    }
  };

  const handleTsoCredentialsUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const token = getAuthToken();
    if (!token) {
      toast.error("Authentication required");
      return;
    }

    setUploadingTsoCreds(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const response = await fetch(`${backendUrl}/api/admin/upload/tso-credentials`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Upload failed");
      toast.success(`Imported ${data.count} TSO credentials`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to upload TSO credentials");
    } finally {
      setUploadingTsoCreds(false);
      e.target.value = "";
    }
  };

  const handleMgmtCredentialsUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const token = getAuthToken();
    if (!token) {
      toast.error("Authentication required");
      return;
    }

    setUploadingMgmtCreds(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const response = await fetch(`${backendUrl}/api/admin/upload/mgmt-credentials`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Upload failed");
      toast.success(`Imported ${data.count} management credentials`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to upload management credentials");
    } finally {
      setUploadingMgmtCreds(false);
      e.target.value = "";
    }
  };

  const handleTsoImagesUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const token = getAuthToken();
    if (!token) {
      toast.error("Authentication required");
      return;
    }

    setUploadingTsoImages(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const response = await fetch(`${backendUrl}/api/admin/upload/tso-images`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Upload failed");
      toast.success(`Uploaded ${data.uploaded} TSO images (${data.skipped} skipped)`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to upload TSO images");
    } finally {
      setUploadingTsoImages(false);
      e.target.value = "";
    }
  };

  const handleBackgroundMediaUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Determine if it's a video or image
    const isVideo = file.type.startsWith("video/");
    const isImage = file.type.startsWith("image/");

    if (!isVideo && !isImage) {
      toast.error("Please upload an image or video file");
      return;
    }

    try {
      const asset = await uploadAsset(file);
      const mediaType = isVideo ? "video" : "image";
      setBackgroundMedia(asset.storageUrl);
      setBackgroundMediaType(mediaType);
      await saveSettings({
        backgroundMediaUrl: asset.storageUrl,
        backgroundMediaType: mediaType,
      });
      toast.success(`Background ${mediaType} uploaded successfully`);
    } catch (error) {
      toast.error("Failed to upload background media");
    }
  };

  const handleSiteCopyField = (key: string, value: string) => {
    setSiteCopy((prev) => ({ ...prev, [key]: value }));
  };

  const handleSaveSiteCopy = async () => {
    try {
      await saveSiteCopy(siteCopy);
      toast.success("Frontend text updated");
    } catch (error) {
      toast.error("Failed to update frontend text");
    }
  };

  const handleLogout = async () => {
    await logout();
    navigate("/login");
    toast.success("Logged out successfully");
  };

  useEffect(() => {
    const fetchAuthEvents = async () => {
      const token = localStorage.getItem("auth_token");
      if (!token) {
        return;
      }

      setLoadingAuthEvents(true);
      try {
        const backendUrl = import.meta.env.VITE_CHATBOT_BACKEND_URL || "";
        const response = await fetch(`${backendUrl}/api/admin/auth-events?limit=100`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (!response.ok) {
          throw new Error("Failed to load auth events");
        }

        const data = await response.json();
        setAuthEvents(data.events || []);
      } catch (error) {
        toast.error("Could not load login/signup activity");
      } finally {
        setLoadingAuthEvents(false);
      }
    };

    fetchAuthEvents();
  }, []);

  // Sort by overall percent
  const sortedTsoData = [...tsoData].sort((a, b) => b.overallPercent - a.overallPercent);
  const userLabel =
    user?.role === "tso"
      ? user.username
      : user?.role === "management"
      ? user.display_name
      : user?.email || "Unknown";

  return (
    <div className="min-h-screen bg-background">
      <div className="container py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-4">
            <Link to="/">
              <Button variant="outline" size="icon" className="rounded-full">
                <ArrowLeft className="h-4 w-4" />
              </Button>
            </Link>
            <div className="flex items-center gap-4">
              <img src={aktLogo} alt="AKT Logo" className="h-12 w-auto" />
              <div>
                <h1 className="font-display text-2xl font-semibold text-foreground">
                  Leaderboard Editor
                </h1>
                <p className="text-muted-foreground text-sm">Manage rankings and TSO data</p>
              </div>
            </div>
          </div>

          {/* User Info and Logout */}
          <div className="flex items-center gap-4 ml-auto">
            <div className="text-right">
              <p className="text-sm font-medium text-foreground">User</p>
              <p className="text-xs text-muted-foreground">{userLabel}</p>
              {user?.role !== "tso" && user?.role !== "management" && user?.phone ? (
                <p className="text-xs text-muted-foreground">{user.phone}</p>
              ) : null}
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={handleLogout}
              className="gap-2"
            >
              <LogOut className="h-4 w-4" />
              Logout
            </Button>
          </div>
        </div>

        {/* CSV Upload Section */}
        <Card className="bg-card border-border mb-8">
          <CardHeader>
            <CardTitle className="text-foreground">CSV Upload</CardTitle>
            <CardDescription>Import TSO data from CSV file</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-4">
              <div className="flex-1">
                <Label htmlFor="csv-upload" className="cursor-pointer">
                  <div className="flex items-center justify-center w-full px-6 py-4 border-2 border-dashed border-border rounded-lg hover:border-primary/50 transition-colors">
                    <div className="text-center">
                      <Upload className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                      <p className="font-medium text-foreground">Click to upload CSV</p>
                      <p className="text-sm text-muted-foreground">or drag and drop</p>
                    </div>
                  </div>
                  <input
                    id="csv-upload"
                    type="file"
                    accept=".csv"
                    onChange={handleCSVUpload}
                    className="hidden"
                  />
                </Label>
              </div>
              <Button
                variant="outline"
                onClick={downloadCSVTemplate}
                className="gap-2"
              >
                <Download className="h-4 w-4" />
                Download Template
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* TSO Credentials CSV Upload */}
        <Card className="bg-card border-border mb-8">
          <CardHeader>
            <CardTitle className="text-foreground flex items-center gap-2">
              <Users className="h-5 w-5" />
              TSO Credentials
            </CardTitle>
            <CardDescription>
              Upload TSO login credentials CSV (columns: Wing, Division, Territory_Code, Territory, Username, Password)
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Label htmlFor="tso-creds-upload" className="cursor-pointer">
              <div className={`flex items-center justify-center w-full px-6 py-4 border-2 border-dashed rounded-lg transition-colors ${uploadingTsoCreds ? "opacity-50 cursor-not-allowed border-border" : "border-border hover:border-primary/50"}`}>
                <div className="text-center">
                  <Upload className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                  <p className="font-medium text-foreground">{uploadingTsoCreds ? "Uploading..." : "Click to upload TSO Credentials CSV"}</p>
                  <p className="text-sm text-muted-foreground">Replaces all existing TSO login accounts</p>
                </div>
              </div>
              <input
                id="tso-creds-upload"
                type="file"
                accept=".csv"
                onChange={handleTsoCredentialsUpload}
                disabled={uploadingTsoCreds}
                className="hidden"
              />
            </Label>
          </CardContent>
        </Card>

        {/* Management Credentials CSV Upload */}
        <Card className="bg-card border-border mb-8">
          <CardHeader>
            <CardTitle className="text-foreground flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Management Credentials
            </CardTitle>
            <CardDescription>
              Upload management login credentials CSV (columns: Display_Name, User_ID, Password, Visibility)
              <br />
              <span className="text-xs">Visibility values: <code>all</code> | <code>only own wing</code> | <code>only own division</code></span>
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Label htmlFor="mgmt-creds-upload" className="cursor-pointer">
              <div className={`flex items-center justify-center w-full px-6 py-4 border-2 border-dashed rounded-lg transition-colors ${uploadingMgmtCreds ? "opacity-50 cursor-not-allowed border-border" : "border-border hover:border-primary/50"}`}>
                <div className="text-center">
                  <Upload className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                  <p className="font-medium text-foreground">{uploadingMgmtCreds ? "Uploading..." : "Click to upload Management Credentials CSV"}</p>
                  <p className="text-sm text-muted-foreground">Replaces all existing management accounts</p>
                </div>
              </div>
              <input
                id="mgmt-creds-upload"
                type="file"
                accept=".csv"
                onChange={handleMgmtCredentialsUpload}
                disabled={uploadingMgmtCreds}
                className="hidden"
              />
            </Label>
          </CardContent>
        </Card>

        {/* TSO Territory ZIP Folder Upload */}
        <Card className="bg-card border-border mb-8">
          <CardHeader>
            <CardTitle className="text-foreground flex items-center gap-2">
              <ImageIcon className="h-5 w-5" />
              TSO Territory Folder (ZIP)
            </CardTitle>
            <CardDescription>
              Upload a zipped folder of territory images. Supported patterns: <code>DHK001.png</code> or <code>DHK001/photo.png</code>.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Label htmlFor="tso-images-upload" className="cursor-pointer">
              <div className={`flex items-center justify-center w-full px-6 py-4 border-2 border-dashed rounded-lg transition-colors ${uploadingTsoImages ? "opacity-50 cursor-not-allowed border-border" : "border-border hover:border-primary/50"}`}>
                <div className="text-center">
                  <Upload className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                  <p className="font-medium text-foreground">{uploadingTsoImages ? "Processing ZIP folder..." : "Click to upload zipped folder"}</p>
                  <p className="text-sm text-muted-foreground">PNG, JPG, GIF, WebP, SVG supported</p>
                </div>
              </div>
              <input
                id="tso-images-upload"
                type="file"
                accept=".zip"
                onChange={handleTsoImagesUpload}
                disabled={uploadingTsoImages}
                className="hidden"
              />
            </Label>
          </CardContent>
        </Card>

        <Card className="bg-card border-border mb-8">
          <CardHeader>
            <CardTitle className="text-foreground">User Signup/Login Activity</CardTitle>
            <CardDescription>Latest authentication events across all users</CardDescription>
          </CardHeader>
          <CardContent>
            {loadingAuthEvents ? (
              <p className="text-sm text-muted-foreground">Loading activity...</p>
            ) : authEvents.length === 0 ? (
              <p className="text-sm text-muted-foreground">No authentication activity yet.</p>
            ) : (
              <div className="space-y-2 max-h-72 overflow-y-auto">
                {authEvents.map((event) => (
                  <div
                    key={event.id}
                    className="flex flex-col gap-1 rounded-md border border-border p-3 text-sm"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-foreground">{event.eventType}</span>
                      <span className="text-xs text-muted-foreground">
                        {new Date(event.createdAt).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-muted-foreground">Email: {event.email || "N/A"}</p>
                    <p className="text-muted-foreground">Role: {event.role || "N/A"}</p>
                    <p className="text-muted-foreground">IP: {event.ipAddress || "N/A"}</p>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* TSO List with Image Upload */}
        <Card className="bg-card border-border mb-8">
          <CardHeader>
            <CardTitle className="text-foreground">Logo Settings</CardTitle>
            <CardDescription>Upload a logo to display at the top of the leaderboard</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-4 items-center">
              {logo && (
                <div className="relative w-24 h-24 flex-shrink-0">
                  <img
                    src={logo}
                    alt="Current Logo"
                    className="w-full h-full object-contain rounded-lg bg-slate-600 p-2"
                  />
                </div>
              )}
              <Label htmlFor="logo-upload" className="cursor-pointer flex-1">
                <div className="flex items-center justify-center w-full px-6 py-4 border-2 border-dashed border-border rounded-lg hover:border-primary/50 transition-colors">
                  <div className="text-center">
                    <Upload className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                    <p className="font-medium text-foreground">Click to upload logo</p>
                    <p className="text-sm text-muted-foreground">PNG, JPG, or SVG</p>
                  </div>
                </div>
                <input
                  id="logo-upload"
                  type="file"
                  accept=".png,.jpg,.jpeg,.svg,.gif"
                  onChange={handleLogoUpload}
                  className="hidden"
                />
              </Label>
            </div>
          </CardContent>
        </Card>

        {/* Background Media Upload */}
        <Card className="bg-card border-border mb-8">
          <CardHeader>
            <CardTitle className="text-foreground">Background Media</CardTitle>
            <CardDescription>Upload an image, GIF, or video for the leaderboard background (50% opacity)</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-4 items-start">
              {backgroundMedia && (
                <div className="relative w-32 h-32 flex-shrink-0 rounded-lg overflow-hidden bg-slate-600">
                  {backgroundMediaType === "video" ? (
                    <video
                      src={backgroundMedia}
                      className="w-full h-full object-cover"
                      autoPlay
                      loop
                      muted
                    />
                  ) : (
                    <img
                      src={backgroundMedia}
                      alt="Background Preview"
                      className="w-full h-full object-cover"
                    />
                  )}
                </div>
              )}
              <Label htmlFor="background-upload" className="cursor-pointer flex-1">
                <div className="flex items-center justify-center w-full px-6 py-4 border-2 border-dashed border-border rounded-lg hover:border-primary/50 transition-colors">
                  <div className="text-center">
                    <Upload className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                    <p className="font-medium text-foreground">Click to upload background</p>
                    <p className="text-sm text-muted-foreground">Image, GIF, or Video (MP4, WebM)</p>
                  </div>
                </div>
                <input
                  id="background-upload"
                  type="file"
                  accept=".png,.jpg,.jpeg,.gif,.svg,.mp4,.webm,.mov,.avi"
                  onChange={handleBackgroundMediaUpload}
                  className="hidden"
                />
              </Label>
            </div>
            {backgroundMedia && (
              <p className="text-sm text-muted-foreground">
                Current background: {backgroundMediaType === "video" ? "Video" : "Image"}
              </p>
            )}
          </CardContent>
        </Card>

        <Card className="bg-card border-border mb-8">
          <CardHeader>
            <CardTitle className="text-foreground">Frontend Text Editor</CardTitle>
            <CardDescription>Update visible text for normal users</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="company-line">Company Line</Label>
              <Input
                id="company-line"
                value={siteCopy.companyLine || ""}
                onChange={(e) => handleSiteCopyField("companyLine", e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="week-badge">Week Badge</Label>
              <Input
                id="week-badge"
                value={siteCopy.weekBadge || ""}
                onChange={(e) => handleSiteCopyField("weekBadge", e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="main-title">Main Title</Label>
              <Input
                id="main-title"
                value={siteCopy.mainTitle || ""}
                onChange={(e) => handleSiteCopyField("mainTitle", e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="subtitle">Subtitle</Label>
              <Input
                id="subtitle"
                value={siteCopy.subtitle || ""}
                onChange={(e) => handleSiteCopyField("subtitle", e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="footer">Footer</Label>
              <Input
                id="footer"
                value={siteCopy.footer || ""}
                onChange={(e) => handleSiteCopyField("footer", e.target.value)}
              />
            </div>
            <Button onClick={handleSaveSiteCopy}>Save Text Changes</Button>
          </CardContent>
        </Card>

        {/* TSO List with Image Upload */}
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-foreground">TSO Management</CardTitle>
            <CardDescription>Upload images and manage TSO information ({tsoData.length} total)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4 max-h-[600px] overflow-y-auto">
              {sortedTsoData.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <p>No TSO data loaded. Please upload a CSV file first.</p>
                </div>
              ) : (
                sortedTsoData.map((tso) => (
                  <div
                    key={tso.id}
                    className="flex items-center gap-4 p-4 bg-slate-700/50 rounded-lg border border-slate-600"
                  >
                    {/* Avatar */}
                    <div className="relative w-16 h-16 flex-shrink-0">
                      <img
                        src={tso.avatar || `https://api.dicebear.com/7.x/avataaars/svg?seed=${tso.name}`}
                        alt={tso.name}
                        className="w-full h-full rounded-full object-cover bg-slate-600"
                      />
                      <label className="absolute inset-0 flex items-center justify-center bg-black/50 rounded-full opacity-0 hover:opacity-100 transition-opacity cursor-pointer">
                        <ImageIcon className="h-4 w-4 text-white" />
                        <input
                          type="file"
                          accept="image/*"
                          onChange={(e) => handleImageUpload(tso.id, e)}
                          className="hidden"
                          disabled={uploadingImageId === tso.id}
                        />
                      </label>
                    </div>

                    {/* TSO Info */}
                    <div className="flex-1">
                      <h3 className="font-semibold text-white">{tso.name}</h3>
                      <p className="text-sm text-slate-300">
                        {tso.territory} • {tso.division} • {tso.wing}
                      </p>
                      <div className="flex gap-6 mt-2 text-xs text-slate-400">
                        <span>Overall: <span className="text-white font-medium">{tso.overallPercent.toFixed(1)}%</span></span>
                        <span>Volume: <span className="text-white font-medium">{tso.volumeSize}</span></span>
                        <span>Memo: <span className="text-white font-medium">{tso.memoSize}</span></span>
                      </div>
                    </div>

                    {/* Actions */}
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDeleteTSO(tso.id)}
                      className="text-red-400 hover:text-red-300 hover:bg-red-950/20"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default AdminPanel;
