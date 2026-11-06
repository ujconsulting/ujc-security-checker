<!-- source: SKILL.md sha256:29188bc9821f7209002913eceacd24b192c1f8701c1854581c20d8d046c4d4dd -->
[English](README.md) | [Deutsch](README_de.md)

# usage-analysis

Short human documentation. The agents load [`SKILL.md`](SKILL.md), which is authoritative.

## Purpose

Answers "where in my projects does this tool help, and where not?" before the owner decides about
it. The analysis defines the scope of use against which the threat model is written (step 8 of
`tool-review`). It names the owner's own projects and is therefore **private**:
`private/repos/<name>/usage-analysis.md`. The public summary says nothing about own use.

## When to use

- step 7 of `tool-review` is reached;
- someone asks whether a tool is worth it or where it helps;
- after a new round or an upstream update the analysis needs updating;
- someone asks how autonomously an agent can work with the tool.

## Flow

1. Read the private portfolio (`private/context/portfolio.md`, if present) and, if needed, the
   `CLAUDE.md` of candidate projects - read only, no customer folders, no secrets.
2. Describe the tool in your own words, including the limits of the reviewed state.
3. Usage matrix per project: use case, measurable benefit, effort, data class (does content leave
   the machine?), recommendation (use / pilot / no).
4. Excluded areas, overlaps with existing tools, recommendation with a pilot and an abort
   criterion.
5. Mandatory section 6 "Autonomous agentic work": contribution per phase, loop closure, sandbox
   model, GUI automation, risks, rating high/medium/low - separately for the developer machine (E)
   and an isolated autonomy environment (A).

## Commands

None of its own. Template: `private/templates/usage-analysis.md`; result:
`private/repos/<name>/usage-analysis.md`; the public summary `repos/<name>/README.md` is not updated with it.

## Example

For a code-graph tool the matrix shows a clear benefit in two large code bases (dependencies
before changing a database view, estimate: 20 minutes per change), no use for customer data
(cloud backend), overlap with an existing knowledge base. Recommendation: pilot in one project for
four weeks, abort if fewer than five hits per week.

## See also

[`tool-review`](../tool-review/README.md), [`docs/SKILLS.md`](../../../docs/SKILLS.md).
