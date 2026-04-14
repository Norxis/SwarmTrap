import { Link } from "react-router-dom";

export function IpLink({ ip }: { ip: string }) {
  return (
    <Link
      to={`/ip/${ip}`}
      className="text-accent hover:underline font-mono"
    >
      {ip}
    </Link>
  );
}
