export const siteConfig = {
  name: "Angelos",
  strapline: "Greek for “messenger.”",
  description: "Connect your AI agent to your existing mailbox. Find what needs attention, understand conversations, and prepare thoughtful replies with Angelos.",
  repoUrl: "https://github.com/amxv/angelos",
  logoHref: "/favicon.svg",
  accentColor: "#a83b1d",
  accentColorDark: "#f4926f"
} as const;

export const docCategories = ["Get started", "Use your inbox", "Reference", "Contributing"] as const;
export const primaryNav = [
  { href: "/docs", label: "Docs" },
  { href: "/docs/changelog", label: "Changelog" },
  { href: siteConfig.repoUrl, label: "GitHub repository", external: true }
];
