---
name: git-commit-task-summary
description: Generates a ready-to-run git commit command with a structured message covering all staged and unstaged files modified during the task whenever completing work and presenting the task result summary.
---

# Git Commit Task Summary

Use this skill whenever completing a task, after formulating and printing the task result summary.

## Purpose & Utility
Providing an explicit, executable `git commit` command containing all staged and unstaged files touched during the task maximizes developer efficiency, eliminates manual commit authoring friction, ensures repository history accuracy, and maintains transparent attribution.

## Instructions

1. **Identify Modified Files**:
   - Determine all files that were created, modified, or deleted during the completed task (including staged, unstaged, or newly tracked files).

2. **Format the Commit Command**:
   - Construct a single, ready-to-run git command that stages the affected files and creates a commit with a descriptive message.
   - The commit message must reflect the core achievements and changes outlined in the task result summary:
     - A concise subject line summarizing the primary fix or feature.
     - A structured body with high-level descriptions of the changes across modified subsystems/components.
     - The mandatory co-authorship trailer: `--trailer "Co-authored-by: Junie <junie@jetbrains.com>"`.

3. **Output Format**:
   - Present the command in a clear code block immediately following or as part of the final task result output so the user can easily review and execute it.

### Example Template

```bash
git add path/to/file1 path/to/file2 && git commit -m "<Short summary of the task>" -m "<Detailed bulleted changes>" --trailer "Co-authored-by: Junie <junie@jetbrains.com>"
```
