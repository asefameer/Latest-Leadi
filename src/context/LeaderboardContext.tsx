import React, { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { TSOData, LeaderboardConfig } from "@/types/leaderboard";

// Sample initial data with Bangladeshi names and territories
const initialTSOData: TSOData[] = [
  { 
    id: "1", 
    name: "Arif Khan", 
    avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Arif",
    territory: "Dhaka East",
    division: "Central",
    wing: "Modern Trade",
    volumeSize: 80,
    memoSize: 70,
    pmpd: 90,
    salesPerMemo: 75,
    outletReach: 85,
    volumeSizePercent: 16.0,
    memoSizePercent: 14.0,
    pmpdPercent: 27.0,
    salesPerMemoPercent: 15.0,
    outletReachPercent: 8.5,
    overallPercent: 80.5
  },
  { 
    id: "2", 
    name: "Kamal Hossain", 
    avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Kamal",
    territory: "Narayanganj",
    division: "Central",
    wing: "General Trade",
    volumeSize: 75,
    memoSize: 68,
    pmpd: 85,
    salesPerMemo: 72,
    outletReach: 80,
    volumeSizePercent: 15.0,
    memoSizePercent: 13.6,
    pmpdPercent: 25.5,
    salesPerMemoPercent: 14.4,
    outletReachPercent: 8.0,
    overallPercent: 76.5
  },
  { 
    id: "3", 
    name: "Farhan Ahmed", 
    avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Farhan",
    territory: "Chittagong Sadar",
    division: "Eastern",
    wing: "Modern Trade",
    volumeSize: 70,
    memoSize: 65,
    pmpd: 80,
    salesPerMemo: 70,
    outletReach: 75,
    volumeSizePercent: 14.0,
    memoSizePercent: 13.0,
    pmpdPercent: 24.0,
    salesPerMemoPercent: 14.0,
    outletReachPercent: 7.5,
    overallPercent: 72.5
  },
  { 
    id: "4", 
    name: "Sohel Rana", 
    avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Sohel",
    territory: "Comilla",
    division: "Eastern",
    wing: "General Trade",
    volumeSize: 68,
    memoSize: 62,
    pmpd: 78,
    salesPerMemo: 68,
    outletReach: 72,
    volumeSizePercent: 13.6,
    memoSizePercent: 12.4,
    pmpdPercent: 23.4,
    salesPerMemoPercent: 13.6,
    outletReachPercent: 7.2,
    overallPercent: 70.2
  },
  { 
    id: "5", 
    name: "Mizanur Rahman", 
    avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Mizan",
    territory: "Rajshahi Sadar",
    division: "Western",
    wing: "General Trade",
    volumeSize: 65,
    memoSize: 60,
    pmpd: 75,
    salesPerMemo: 65,
    outletReach: 70,
    volumeSizePercent: 13.0,
    memoSizePercent: 12.0,
    pmpdPercent: 22.5,
    salesPerMemoPercent: 13.0,
    outletReachPercent: 7.0,
    overallPercent: 67.5
  },
  { 
    id: "6", 
    name: "Jahangir Alam", 
    avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Jahangir",
    territory: "Khulna Sadar",
    division: "Western",
    wing: "Modern Trade",
    volumeSize: 62,
    memoSize: 58,
    pmpd: 72,
    salesPerMemo: 62,
    outletReach: 68,
    volumeSizePercent: 12.4,
    memoSizePercent: 11.6,
    pmpdPercent: 21.6,
    salesPerMemoPercent: 12.4,
    outletReachPercent: 6.8,
    overallPercent: 64.8
  },
  { 
    id: "7", 
    name: "Tariqul Islam", 
    avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Tariq",
    territory: "Sylhet Sadar",
    division: "Northern",
    wing: "General Trade",
    volumeSize: 60,
    memoSize: 56,
    pmpd: 70,
    salesPerMemo: 60,
    outletReach: 65,
    volumeSizePercent: 12.0,
    memoSizePercent: 11.2,
    pmpdPercent: 21.0,
    salesPerMemoPercent: 12.0,
    outletReachPercent: 6.5,
    overallPercent: 62.7
  },
  { 
    id: "8", 
    name: "Shakib Hassan", 
    avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Shakib",
    territory: "Bogra",
    division: "Northern",
    wing: "Modern Trade",
    volumeSize: 58,
    memoSize: 54,
    pmpd: 68,
    salesPerMemo: 58,
    outletReach: 63,
    volumeSizePercent: 11.6,
    memoSizePercent: 10.8,
    pmpdPercent: 20.4,
    salesPerMemoPercent: 11.6,
    outletReachPercent: 6.3,
    overallPercent: 60.7
  },
  { 
    id: "9", 
    name: "Nahid Hasan", 
    avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Nahid",
    territory: "Rangpur Sadar",
    division: "Northern",
    wing: "General Trade",
    volumeSize: 55,
    memoSize: 52,
    pmpd: 65,
    salesPerMemo: 55,
    outletReach: 60,
    volumeSizePercent: 11.0,
    memoSizePercent: 10.4,
    pmpdPercent: 19.5,
    salesPerMemoPercent: 11.0,
    outletReachPercent: 6.0,
    overallPercent: 57.9
  },
  { 
    id: "10", 
    name: "Imran Hossain", 
    avatar: "https://api.dicebear.com/7.x/avataaars/svg?seed=Imran",
    territory: "Barisal Sadar",
    division: "Southern",
    wing: "General Trade",
    volumeSize: 52,
    memoSize: 50,
    pmpd: 62,
    salesPerMemo: 52,
    outletReach: 58,
    volumeSizePercent: 10.4,
    memoSizePercent: 10.0,
    pmpdPercent: 18.6,
    salesPerMemoPercent: 10.4,
    outletReachPercent: 5.8,
    overallPercent: 55.2
  },
];

interface LeaderboardContextType {
  tsoData: TSOData[];
  setTsoData: React.Dispatch<React.SetStateAction<TSOData[]>>;
  config: LeaderboardConfig;
  setConfig: React.Dispatch<React.SetStateAction<LeaderboardConfig>>;
  logo: string; // Logo image URL or base64
  setLogo: React.Dispatch<React.SetStateAction<string>>;
  backgroundMedia: string; // Background image/video URL or base64
  setBackgroundMedia: React.Dispatch<React.SetStateAction<string>>;
  backgroundMediaType: "image" | "video"; // Type of background media
  setBackgroundMediaType: React.Dispatch<React.SetStateAction<"image" | "video">>;
  siteCopy: Record<string, string>;
  setSiteCopy: React.Dispatch<React.SetStateAction<Record<string, string>>>;
  updateTSO: (id: string, data: Partial<TSOData>) => void;
  addTSO: (data: Omit<TSOData, "id">) => void;
  deleteTSO: (id: string) => void;
}

const LeaderboardContext = createContext<LeaderboardContextType | undefined>(undefined);

export const LeaderboardProvider = ({ children }: { children: ReactNode }) => {
  const [tsoData, setTsoData] = useState<TSOData[]>(initialTSOData);
  const [config, setConfig] = useState<LeaderboardConfig>({ weekNumber: 12 });
  const [logo, setLogo] = useState<string>("");
  const [backgroundMedia, setBackgroundMedia] = useState<string>("");
  const [backgroundMediaType, setBackgroundMediaType] = useState<"image" | "video">("image");
  const [siteCopy, setSiteCopy] = useState<Record<string, string>>({
    companyLine: "X Factor Unlocked",
    weekBadge: "Week 3 Rankings",
    mainTitle: "XForce Leaderboard",
    subtitle: "Compete with Sales Stars nationally and climb the ranks",
    footer: `© ${new Date().getFullYear()} Shah Cement. All rights reserved.`,
  });

  useEffect(() => {
    const loadPublicContent = async () => {
      try {
        const backendUrl = import.meta.env.VITE_CHATBOT_BACKEND_URL || "";
        const response = await fetch(`${backendUrl}/api/content/public`);
        if (!response.ok) {
          return;
        }

        const data = await response.json();

        if (Array.isArray(data.tsoData) && data.tsoData.length > 0) {
          setTsoData(data.tsoData);
        }

        if (data.settings?.logoUrl) {
          setLogo(data.settings.logoUrl);
        }

        if (data.settings?.backgroundMediaUrl) {
          setBackgroundMedia(data.settings.backgroundMediaUrl);
        }

        if (data.settings?.backgroundMediaType === "image" || data.settings?.backgroundMediaType === "video") {
          setBackgroundMediaType(data.settings.backgroundMediaType);
        }

        if (data.siteCopy && typeof data.siteCopy === "object") {
          setSiteCopy((prev) => ({ ...prev, ...data.siteCopy }));
        }
      } catch (_error) {
        // Keep local defaults when API is unavailable
      }
    };

    loadPublicContent();
  }, []);

  const updateTSO = (id: string, data: Partial<TSOData>) => {
    setTsoData((prev) =>
      prev.map((tso) => (tso.id === id ? { ...tso, ...data } : tso))
    );
  };

  const addTSO = (data: Omit<TSOData, "id">) => {
    const newTSO: TSOData = {
      ...data,
      id: Date.now().toString(),
    };
    setTsoData((prev) => [...prev, newTSO]);
  };

  const deleteTSO = (id: string) => {
    setTsoData((prev) => prev.filter((tso) => tso.id !== id));
  };

  return (
    <LeaderboardContext.Provider
      value={{
        tsoData,
        setTsoData,
        config,
        setConfig,
        logo,
        setLogo,
        backgroundMedia,
        setBackgroundMedia,
        backgroundMediaType,
        setBackgroundMediaType,
        siteCopy,
        setSiteCopy,
        updateTSO,
        addTSO,
        deleteTSO,
      }}
    >
      {children}
    </LeaderboardContext.Provider>
  );
};

export const useLeaderboard = () => {
  const context = useContext(LeaderboardContext);
  if (!context) {
    throw new Error("useLeaderboard must be used within a LeaderboardProvider");
  }
  return context;
};
