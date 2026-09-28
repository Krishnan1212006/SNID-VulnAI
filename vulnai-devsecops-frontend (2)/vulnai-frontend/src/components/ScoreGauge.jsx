import { useEffect, useState } from "react";

function tierFor(score) {
  if (score < 40) return { color: "#A83B42", label: "Critical" };
  if (score < 70) return { color: "#9C8536", label: "Elevated" };
  if (score < 85) return { color: "#8FA8B3", label: "Moderate" };
  return { color: "#4F7A5E", label: "Sound" };
}

export default function ScoreGauge({ score = 0, size = 176 }) {
  const [animated, setAnimated] = useState(0);
  const radius = (size - 14) / 2;
  const circumference = 2 * Math.PI * radius;

  useEffect(() => {
    const t = setTimeout(() => setAnimated(score), 150);
    return () => clearTimeout(t);
  }, [score]);

  const offset = circumference - (animated / 100) * circumference;
  const tier = tierFor(score);

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#29292E" strokeWidth="2" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={tier.color}
          strokeWidth="2"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 1.1s cubic-bezier(0.4, 0, 0.2, 1)" }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="font-display text-5xl font-medium leading-none text-text-main">
          {Math.round(animated)}
        </span>
        <span className="mt-2 kicker" style={{ color: tier.color }}>
          {tier.label}
        </span>
      </div>
    </div>
  );
}
