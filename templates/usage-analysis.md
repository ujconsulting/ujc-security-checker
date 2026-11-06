# <name> - usage analysis

<!--
Location: private/repos/<name>/usage-analysis.md (private and gitignored: it names your own projects,
hosts and data classes). Written by the skill usage-analysis, before the decision in tool-review step 8.
Keep placeholders for customers ("Customer X"). No secrets, IP addresses or key paths.
-->

As of: <date> - reviewed state: `<sha>` (`<version>`) - latest verdict: `<...>`

## 1. The tool in your own words

What it does and how it works (local or cloud, which models, which files it reads and writes), and which
limits the reviewed or hardened state has.

## 2. Usage matrix

| Project | Concrete use | Benefit (measurable where possible) | Effort | Risk / data class | Recommendation |
|---|---|---|---|---|---|
| `<folder>` | ... | ... | S/M/L | own / customer / personal - local / cloud | use / trial / no |

Data classes: **own** (tools, docs without customer reference), **customer** (schemas, documents, customer
scripts), **personal** (participant lists, finances, mail), **secrets** (folders with plaintext access
data). Cloud means the content leaves the machine (model API, service).

## 3. Where it should NOT be used

| Area | Reason |
|---|---|
| Clones of foreign repositories | outside the threat model: untrusted content |
| Customer folders | customer data, only after agreement |
| Folders with plaintext access data | secrets |

## 4. Overlap with existing tools

| Existing tool | Overlap | Added value or duplicate |
|---|---|---|
| | | |

## 5. Recommendation and next steps

- Recommendation in one sentence.
- Pilot: <project>, <measure>, <abort criterion>.
- Prerequisites (approval, installation, configuration).
