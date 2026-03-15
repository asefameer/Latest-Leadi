import TopThreeCard from "./TopThreeCard";
import LeaderboardRow from "./LeaderboardRow";
import { useLeaderboard } from "@/context/LeaderboardContext";
import aktLogo from "@/assets/akt-logo.png";

const Leaderboard = () => {
  const { tsoData, config, logo, backgroundMedia, backgroundMediaType, siteCopy } = useLeaderboard();

  // Sort by Overall % and get top 500
  const sortedData = [...tsoData].sort((a, b) => b.overallPercent - a.overallPercent).slice(0, 500);
  const topThree = sortedData.slice(0, 3);
  const restOfPlayers = sortedData.slice(3);

  return (
    <div className="min-h-screen bg-background relative">
      {/* Background Media with 100% Opacity */}
      {backgroundMedia && (
        <div className="fixed inset-0 overflow-hidden pointer-events-none">
          {backgroundMediaType === "video" ? (
            <video
              src={backgroundMedia}
              autoPlay
              loop
              muted
              playsInline
              className="absolute inset-0 w-full h-full object-cover opacity-100"
            />
          ) : (
            <img
              src={backgroundMedia}
              alt="Background"
              className="absolute inset-0 w-full h-full object-cover opacity-100"
            />
          )}
        </div>
      )}

      {/* Hero Section */}
      <div className="relative overflow-hidden">
        <div className="container relative pt-12 pb-8">
          {/* Header with Logo */}
          <div className="text-center mb-12">
            {/* Logo */}
            <div className="flex justify-center mb-6">
              <img 
                src={logo || aktLogo} 
                alt="Leaderboard Logo" 
                className="h-24 w-auto"
              />
            </div>

            {/* Company Name */}
            <p className="text-muted-foreground text-sm tracking-widest uppercase mb-4">
              {siteCopy.companyLine || "X Factor Unlocked"}
            </p>
            
            {/* Week Badge */}
            <div className="inline-flex items-center gap-2 mb-6 px-4 py-2 rounded-full bg-primary/5 border border-primary/10">
              <span className="text-primary font-medium text-sm">{siteCopy.weekBadge || "Week 3 Rankings"}</span>
            </div>

            <h1 
              className="inline-block px-4 py-2 rounded-xl bg-background/70 backdrop-blur-sm font-display text-4xl md:text-6xl font-semibold mb-4 tracking-tight text-foreground"
            >
              {siteCopy.mainTitle || "XForce Leaderboard"}
            </h1>
            <p className="text-muted-foreground text-lg max-w-md mx-auto">
              {siteCopy.subtitle || "Compete with Sales Stars nationally and climb the ranks"}
            </p>
          </div>

          {/* Top 3 Podium */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl mx-auto mb-16">
            {topThree.map((tso, index) => (
              <TopThreeCard
                key={tso.id}
                rank={(index + 1) as 1 | 2 | 3}
                name={tso.name}
                overallPercent={tso.overallPercent}
                avatar={tso.avatar}
                territory={tso.territory}
                division={tso.division}
                tsoData={tso}
              />
            ))}
          </div>
        </div>
      </div>

      {/* Leaderboard Table */}
      <div className="container pb-16">
        <div className="bg-secondary/30 backdrop-blur-sm rounded-3xl border border-border p-4 md:p-6">
          {/* Table Header */}
          <div className="hidden md:grid grid-cols-[60px_1fr_180px_80px] gap-4 px-6 py-3 text-sm font-medium text-muted-foreground mb-2">
            <span className="text-center">Rank</span>
            <span>TSO</span>
            <span>Overall %</span>
            <span className="text-center">Details</span>
          </div>

          {/* Rows */}
          <div className="space-y-2">
            {restOfPlayers.map((tso, index) => (
              <LeaderboardRow
                key={tso.id}
                rank={index + 4}
                name={tso.name}
                overallPercent={tso.overallPercent}
                avatar={tso.avatar}
                territory={tso.territory}
                division={tso.division}
                tsoData={tso}
                index={index}
              />
            ))}
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="container pb-8">
        <div className="text-center text-muted-foreground text-sm">
          {siteCopy.footer || `© ${new Date().getFullYear()} Shah Cement. All rights reserved.`}
        </div>
      </footer>
    </div>
  );
};

export default Leaderboard;
