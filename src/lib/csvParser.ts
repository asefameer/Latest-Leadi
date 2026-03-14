import { TSOData, CSVRow } from "@/types/leaderboard";

export const parseCSV = (csvText: string): TSOData[] => {
  const lines = csvText.trim().split("\n");
  if (lines.length < 2) {
    throw new Error("CSV must contain headers and at least one data row");
  }

  const headers = lines[0].split(",").map((h) => h.trim());
  const requiredHeaders = [
    "TSO Name",
    "Territory",
    "Division",
    "Wing",
    "Volume Size",
    "Memo Size",
    "Per Man Per Day Sales (PMPD)",
    "Sales per Memo",
    "Outlet Reach",
    "Volume Size (20) %",
    "Memo Size (20) %",
    "Per Man Per Day Sales (PMPD) (30) %",
    "Sales per Memo (20) %",
    "Outlet Reach (10) %",
    "Overall %",
  ];

  // Validate headers
  for (const required of requiredHeaders) {
    if (!headers.includes(required)) {
      throw new Error(`Missing required column: ${required}`);
    }
  }

  const tsoData: TSOData[] = [];

  for (let i = 1; i < lines.length; i++) {
    const values = lines[i].split(",").map((v) => v.trim());
    const row: any = {};

    headers.forEach((header, index) => {
      row[header] = values[index];
    });

    try {
      const tso: TSOData = {
        id: `tso-${i}-${Date.now()}`,
        name: row["TSO Name"],
        avatar: "", // Will be uploaded separately
        territory: row["Territory"],
        division: row["Division"],
        wing: row["Wing"],
        territory_code: row["Territory_Code"] || undefined,
        username: row["Username"] || undefined,
        volumeSize: parseFloat(row["Volume Size"]) || 0,
        memoSize: parseFloat(row["Memo Size"]) || 0,
        pmpd: parseFloat(row["Per Man Per Day Sales (PMPD)"]) || 0,
        salesPerMemo: parseFloat(row["Sales per Memo"]) || 0,
        outletReach: parseFloat(row["Outlet Reach"]) || 0,
        volumeSizePercent: parseFloat(row["Volume Size (20) %"]) || 0,
        memoSizePercent: parseFloat(row["Memo Size (20) %"]) || 0,
        pmpdPercent: parseFloat(row["Per Man Per Day Sales (PMPD) (30) %"]) || 0,
        salesPerMemoPercent: parseFloat(row["Sales per Memo (20) %"]) || 0,
        outletReachPercent: parseFloat(row["Outlet Reach (10) %"]) || 0,
        overallPercent: parseFloat(row["Overall %"]) || 0,
      };

      tsoData.push(tso);
    } catch (error) {
      console.error(`Error parsing row ${i}:`, error);
      throw new Error(`Error parsing row ${i}: Invalid data format`);
    }
  }

  return tsoData;
};

export const downloadCSVTemplate = () => {
  const template = `TSO Name,Territory,Division,Wing,Volume Size,Memo Size,Per Man Per Day Sales (PMPD),Sales per Memo,Outlet Reach,Volume Size (20) %,Memo Size (20) %,Per Man Per Day Sales (PMPD) (30) %,Sales per Memo (20) %,Outlet Reach (10) %,Overall %
Arif Khan,Dhaka East,Central,Modern Trade,80,70,90,75,85,16.0,14.0,27.0,15.0,8.5,80.5
Nusrat Jahan,Chattogram South,South,General Trade,72,78,82,70,80,14.4,15.6,24.6,14.0,8.0,76.6
Imran Hossain,Rajshahi North,North,General Trade,85,75,88,82,90,17.0,15.0,26.4,16.4,9.0,83.8
Sadia Ahmed,Sylhet West,East,Modern Trade,68,72,76,74,70,13.6,14.4,22.8,14.8,7.0,72.6
Tanvir Alam,Barishal Central,South,Wholesale,90,85,92,88,95,18.0,17.0,27.6,17.6,9.5,89.7`;

  const blob = new Blob([template], { type: "text/csv" });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "tso_template.csv";
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
};
