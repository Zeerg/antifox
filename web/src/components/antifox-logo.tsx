// AntiFox brand mark (curled-fox round badge, transparent PNG) — sized via className; works in light and dark themes.
export function AntifoxLogo({ className }: { className?: string }) {
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img src="/logo.png" alt="AntiFox" className={className} />
  );
}
