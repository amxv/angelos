export const siteConfig = {
  name: "Angelos",
  strapline: "Email infrastructure for agents",
  description:
    "Documentation for Angelos, an agent-native layer for securely sending, receiving, and operating email.",
  repoUrl: "https://github.com/amxv/angelos",
  footerSections: [
    {
      title: "Angelos",
      text: "Email infrastructure designed for agents that need to work with an inbox as part of a larger workflow."
    },
    {
      title: "Documentation",
      text: "The docs live with the code and should evolve alongside the implementation."
    },
    {
      title: "Repository",
      linkPrefix: "Source: ",
      linkHref: "https://github.com/amxv/angelos",
      linkLabel: "github.com/amxv/angelos"
    }
  ]
} as const;

export const docCategories = [
  "Start",
  "Concepts",
  "Guides",
  "Reference",
  "Contributing"
] as const;

export const primaryNav = [
  { href: "/docs", label: "Docs" },
  { href: siteConfig.repoUrl, label: "GitHub", external: true }
];
