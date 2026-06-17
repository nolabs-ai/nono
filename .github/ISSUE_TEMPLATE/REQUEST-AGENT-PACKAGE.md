name: New Agent Package Request
description: Request a nono package for an AI agent that isn't supported yet
labels: ["agent-package"]
body:
  - type: markdown
    attributes:
      value: |
        Thanks for helping us grow nono's agent coverage!
        Use this template to request a nono package for an AI agent that isn't supported yet. The more detail you can give us about the agent — especially the hooks and customization points it exposes — the easier it is for us to build a solid, secure package.
        **Please note:** opening this request is not a guarantee that we'll build the package. We prioritize based on demand, so the more popular and widely-used the agent, the more likely support will land. Either way, we'll do our best.

  - type: input
    id: agent-name
    attributes:
      label: Agent name
      description: The name of the agent you'd like a nono package for.
      placeholder: "e.g. Aider, Cline, OpenHands"
    validations:
      required: true

  - type: input
    id: docs-url
    attributes:
      label: Documentation URL
      description: Link to the agent's official documentation.
      placeholder: "https://docs.example.com"
    validations:
      required: true

  - type: input
    id: github-repo
    attributes:
      label: GitHub repository
      description: Link to the agent's source repository.
      placeholder: "https://github.com/org/agent"
    validations:
      required: true

  - type: textarea
    id: hooks-customization
    attributes:
      label: Hooks and customization
      description: |
        What hooks, plugins, lifecycle events, config files, or other customization points does the agent provide that a nono package could leverage? For example: pre/post-command hooks, tool-call interception, a settings/config file, SKILL files, environment variables, or an extension API. Link to the relevant docs or source where you can.
      placeholder: "The agent supports a pre-tool-use hook defined in ~/.agent/config.yaml that runs a command before each shell action..."
    validations:
      required: true

  - type: textarea
    id: popularity
    attributes:
      label: Adoption and popularity
      description: Help us gauge demand — GitHub stars, download counts, community size, or where the agent is being used. This directly informs prioritization.

  - type: textarea
    id: context
    attributes:
      label: Additional context
      description: Anything else that would help us build the package — known security concerns, platform support (Linux/macOS), how you intend to use the agent under nono, or related requests.
