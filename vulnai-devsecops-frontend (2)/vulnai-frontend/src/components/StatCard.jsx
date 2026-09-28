export default function StatCard({ label, value, icon: Icon, accent = "purple", suffix, trend }) {
  const colorMap = {
    purple: "#C6A15B",
    blue: "#8FA8B3",
    critical: "#A83B42",
    high: "#B5692B",
    medium: "#9C8536",
    low: "#4F7A5E",
  };
  const color = colorMap[accent];

  return (
    <div className="card card-hover p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="kicker">{label}</p>
          <p className="mt-2 font-display text-3xl font-semibold text-text-main">
            {value}
            {suffix && <span className="ml-1 text-base font-normal text-text-secondary">{suffix}</span>}
          </p>
          {trend && <p className="mt-1 text-xs text-text-secondary">{trend}</p>}
        </div>
        {Icon && (
          <div className="rounded-md border border-border p-2" style={{ color }}>
            <Icon size={17} strokeWidth={1.75} />
          </div>
        )}
      </div>
    </div>
  );
}
