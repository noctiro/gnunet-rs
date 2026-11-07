# Documentation

- Write repository documentation in English, with one H1 and descriptive sections.
- README files cover purpose, public interfaces, configuration, examples and constraints.
  Put long interface/command references in linked topic files.
- Keep open work in `IMPLEMENTATION_STATUS.md` and shared design in `ARCHITECTURE.md`.
- Keep wire, security, ownership, cancellation and error contracts precise.
- Delete superseded plans and status diaries. Do not append dated progress sections,
  handoff narratives, author/agent commentary or historical test counts to module docs.
- Do not repeat whole-project completion disclaimers or production-backend policy
  across packages. Link the central contract when the distinction matters.
- Generated verification logs, source/binary digests and process transcripts belong
  under `target/`. Do not create persistent report/history directories in the source tree.
- Never turn a failed or narrower run into a broader passing claim when editing docs.
- Use relative repository links and verify moved/deleted-document references.
- Documentation cleanup does not require rerunning unchanged product tests.
