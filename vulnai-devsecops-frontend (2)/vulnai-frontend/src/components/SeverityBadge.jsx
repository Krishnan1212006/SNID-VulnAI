const STYLES = {
  critical: "text-[#A83B42] border-[#A83B42]/35",
  high: "text-[#B5692B] border-[#B5692B]/35",
  medium: "text-[#9C8536] border-[#9C8536]/35",
  low: "text-[#4F7A5E] border-[#4F7A5E]/35",
};

export default function SeverityBadge({ level, size = "sm" }) {
  const cls = STYLES[level] || STYLES.low;
  const padding = size === "sm" ? "px-2 py-0.5 text-[10.5px]" : "px-2.5 py-1 text-xs";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-sm border font-mono font-medium uppercase tracking-wider ${cls} ${padding}`}
    >
      <span className="h-[7px] w-[7px] bg-current" />
      {level}
    </span>
  );
}
