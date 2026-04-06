/** Short tooltips for the results page (popover-sized). */

export const HELP = {
  rSast:
    "Slither, Slitherin, and Semgrep findings boiled down to one number. Severity and how loud the tool is about it, capped at 100.",
  rDast:
    "Mythril’s column. Higher when it’s worried; a bit stronger if it printed an actual trace, not just a vague flag.",
  rComp: "How gnarly the code is (cyclomatic complexity). Not a vuln score on its own - just a heads-up.",
  rModel: "CodeBERT’s risk number when the checkpoint loaded. You’ll see it as a small decimal in the table.",
  composite:
    "Mix of static analysis, Mythril, complexity, and the model. If Mythril saw something, it gets a little extra weight.",
  lossPct:
    "Ballpark loss % from finding types and DeFi category. Handy for ranking, not something to bank on literally.",

  codebertAvailable: "Whether the model weights were there and we actually ran inference on this file.",
  codebertTypes: "Vuln labels the model fired on, only if they passed its per-class cutoff.",
  codebertRisk: "Single score from the model’s regression head when it ran.",
  codebertError: "Something broke during load or inference - details here.",

  avgRubric: "Average business-risk score (0-100) across the findings we scored.",
  maxRubric: "The worst rubric score in the pile - usually the one to read first.",
  findingsAssessed: "Count of findings that got a rubric row.",
  consensus:
    "How often the rubric’s severity lines up with an optional LLM loss estimate. If we never got that estimate, this sits at 0% - that doesn’t mean the tools disagree.",

  verifyStatus:
    "Overall verdict on the summary’s claims vs tool output: verified, needs another look, rejected, etc.",
  hallucinationRate:
    "Claims we couldn’t back with any tool finding. “Unverified” is tracked separately and isn’t mixed in here.",
  verifyClaims: "Claims we pulled from the summary JSON to compare against the tools.",

  findingTitle: "What the tool called this hit (check name or similar).",
  findingType: "Vuln category after we map different tools onto the same vocabulary.",
  findingSource: "Which tool raised it.",
  findingImpact: "Critical / High / Medium / Low / Info - straight from the tool.",
  findingConfidence: "How confident this row looks (often from calibrated per-tool scores).",
  findingTier: "Did multiple tools agree, or is this only one analyzer?",
  findingLocation: "File, line, or whatever location string the tool gave.",
  modelVerified:
    "Whether CodeBERT’s predicted labels line up with this row’s type. Different check from the summary verification block.",

  executiveSummary:
    "The LLM’s write-up based only on your findings, shown as Markdown. We cross-check those claims against the tools above.",
} as const;
