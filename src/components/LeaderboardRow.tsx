import { cn } from "@/lib/utils";
import RankBadge from "./RankBadge";
import { TSOData } from "@/types/leaderboard";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Info } from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { useLeaderboard } from "@/context/LeaderboardContext";

interface LeaderboardRowProps {
  rank: number;
  name: string;
  overallPercent: number;
  avatar: string;
  territory: string;
  division: string;
  tsoData: TSOData;
  index: number;
}

const LeaderboardRow = ({
  rank,
  name,
  overallPercent,
  avatar,
  territory,
  division,
  tsoData,
  index,
}: LeaderboardRowProps) => {
  const { user } = useAuth();
  const { tsoImages } = useLeaderboard();

  const canViewBreakdown = (() => {
    if (!user) return false;
    if (user.role === "admin") return true;

    if (user.role === "tso") {
      return !!tsoData.username && user.username === tsoData.username;
    }

    if (user.role === "management") {
      if (user.visibility === "all") return true;
      if (user.visibility === "only own wing") return tsoData.wing === user.display_name;
      if (user.visibility === "only own division") return tsoData.division === user.display_name;
    }

    return false;
  })();

  const resolvedAvatar =
    (tsoData.territory_code ? tsoImages[tsoData.territory_code] : undefined) || avatar;

  const rowContent = (
    <div
      className={cn(
        "grid grid-cols-[auto_1fr_auto_auto] md:grid-cols-[60px_1fr_180px_80px] gap-4 items-center",
        "px-4 md:px-6 py-4 rounded-2xl transition-all duration-300",
        canViewBreakdown ? "cursor-pointer" : "cursor-default",
        "bg-card hover:bg-secondary border border-transparent hover:border-border",
        "opacity-0 animate-slide-up"
      )}
      style={{ animationDelay: `${index * 0.05}s` }}
    >
      {/* Rank */}
      <div className="flex justify-center">
        <RankBadge rank={rank} size="sm" />
      </div>

      {/* TSO Info */}
      <div className="flex items-center gap-4 min-w-0">
        <div className="w-12 h-12 rounded-full overflow-hidden border-2 border-border flex-shrink-0">
          <img
            src={resolvedAvatar}
            alt={name}
            className="w-full h-full object-cover bg-muted"
          />
        </div>
        <div className="min-w-0">
          <span className="font-semibold text-foreground truncate block">{name}</span>
          <span className="text-muted-foreground text-sm truncate block">{territory}, {division}</span>
        </div>
      </div>

      {/* Overall % */}
      <div className="text-right md:text-left">
        <span className="font-display font-bold text-foreground">
          {overallPercent.toFixed(1)} <span className="text-muted-foreground font-normal text-sm">%</span>
        </span>
      </div>

      {/* Details Icon */}
      <div className="flex justify-center text-muted-foreground transition-colors">
        {canViewBreakdown ? <Info size={18} className="hover:text-foreground" /> : null}
      </div>
    </div>
  );

  if (!canViewBreakdown) {
    return rowContent;
  }

  return (
    <Popover>
      <PopoverTrigger asChild>
        {rowContent}
      </PopoverTrigger>
      <PopoverContent className="w-80 bg-slate-800 border-slate-700">
        <div className="space-y-3">
          <h4 className="font-semibold text-white">{tsoData.name}</h4>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <p className="text-muted-foreground">Territory</p>
              <p className="text-white font-medium">{tsoData.territory}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Wing</p>
              <p className="text-white font-medium">{tsoData.wing}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Overall %</p>
              <p className="text-white font-medium">{tsoData.overallPercent.toFixed(1)}%</p>
            </div>
            <div>
              <p className="text-muted-foreground">Volume Size</p>
              <p className="text-white font-medium">{tsoData.volumeSize}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Memo Size</p>
              <p className="text-white font-medium">{tsoData.memoSize}</p>
            </div>
            <div>
              <p className="text-muted-foreground">PMPD</p>
              <p className="text-white font-medium">{tsoData.pmpd}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Sales/Memo</p>
              <p className="text-white font-medium">{tsoData.salesPerMemo}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Outlet Reach</p>
              <p className="text-white font-medium">{tsoData.outletReach}</p>
            </div>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
};

export default LeaderboardRow;
