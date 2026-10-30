export const localToolDetails = {
  "local-source": {
    "provider": "OFFENSE / OPENGREP + ZIZMOR",
    "status": "LOCAL TOOL",
    "title": "Source and workflow scanning",
    "description": "Check tracked source files and GitHub Actions workflows in your local checkout.",
    "points": [
      "Requires the selected scanner binaries: Opengrep 1.32.0 or Zizmor 1.31.1. The helper does not install them.",
      "Fixed rules scan supported JS/TS/Python and workflow/action YAML. Source is not uploaded and the application is not executed.",
      "Reports stay local. Static findings require applicability review; missing tools and incomplete coverage remain explicit."
    ],
    "url": "https://offense.sh/skills/purple/SKILL.md",
    "action": "Read Offense skill"
  },
  "local-api": {
    "provider": "OFFENSE / SCHEMATHESIS",
    "status": "LOCAL TOOL",
    "title": "Sandbox API testing",
    "description": "Exercise a prepared local API against its OpenAPI schema with Schemathesis.",
    "points": [
      "Requires a prepared Node or Python application, an OpenAPI 3.0/3.1 schema, local Docker, and an explicitly built Schemathesis 4.32.4 image.",
      "Runs bounded requests against a local loopback target in separate application and scanner containers, with Internet access disabled during testing.",
      "Reports stay local. This is not a hosted or production-target scan; authentication, validation, and server-error candidates require review."
    ],
    "url": "https://offense.sh/skills/purple/SKILL.md",
    "action": "Read Offense skill"
  }
};
