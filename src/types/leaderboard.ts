export interface TSOData {
  id: string;
  name: string;
  avatar: string;
  territory: string;
  division: string;
  wing: string;
  territory_code?: string;
  username?: string;
  volumeSize: number;
  memoSize: number;
  pmpd: number; // Per Man Per Day Sales
  salesPerMemo: number;
  outletReach: number;
  volumeSizePercent: number; // Volume Size (20) %
  memoSizePercent: number; // Memo Size (20) %
  pmpdPercent: number; // Per Man Per Day Sales (PMPD) (30) %
  salesPerMemoPercent: number; // Sales per Memo (20) %
  outletReachPercent: number; // Outlet Reach (10) %
  overallPercent: number; // Overall %
}

export interface LeaderboardConfig {
  weekNumber: number;
}

export interface CSVRow {
  "TSO Name": string;
  "Territory": string;
  "Division": string;
  "Wing": string;
  "Territory_Code"?: string;
  "Username"?: string;
  "Volume Size": string;
  "Memo Size": string;
  "Per Man Per Day Sales (PMPD)": string;
  "Sales per Memo": string;
  "Outlet Reach": string;
  "Volume Size (20) %": string;
  "Memo Size (20) %": string;
  "Per Man Per Day Sales (PMPD) (30) %": string;
  "Sales per Memo (20) %": string;
  "Outlet Reach (10) %": string;
  "Overall %": string;
}

