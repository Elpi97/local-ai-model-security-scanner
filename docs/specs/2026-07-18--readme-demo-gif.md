# README Demo GIF Design

## Goal

Add a concise visual demonstration to the GitHub README so a visitor can
understand the scanner's end-to-end value without reading the full usage guide.

## Deliverable

- A 35–45 second animated GIF at approximately 960×540.
- The GIF uses the already captured real execution results:
  - `model-scanner --doctor` reports deep ONNX scanning enabled.
  - A real Hugging Face safetensors file receives `SAFE` with exit code 0.
  - A controlled hostile ONNX external-data escape receives `DANGEROUS` with
    exit code 1.
  - The full test suite reports 94/94 passing.
- The GIF is stored under `assets/` and displayed inline in `README.md`.
- A short “See it in action” section is placed immediately after the existing
  “Start here” link.
- The section links to `examples/DEMO.md` for full commands, output, caveats,
  and evidence.

## Presentation

The recording will use a readable terminal-style layout with chapter captions.
It will prioritize the two decisions—SAFE handoff and DANGEROUS block—over
showing every output line. Long hashes and paths may be visually shortened, but
the verdicts, exit codes, file formats, critical finding, and test count must
remain exact.

## GitHub Compatibility

GitHub READMEs do not execute the interactive HTML replay. The README therefore
uses an animated GIF, which GitHub renders inline without JavaScript. The local
HTML replay may remain as a development artifact, but it is not the README
embed target.

## Size and Accessibility

- Optimize the GIF to avoid an unnecessarily large repository asset.
- Keep text legible at the README's normal content width.
- Add descriptive alt text that identifies the SAFE and DANGEROUS outcomes.
- Include a text summary below the GIF so the result is still understandable
  when animation is disabled.

## Verification

Before completion:

1. Confirm the GIF opens and animates.
2. Confirm its dimensions and duration are within the intended range.
3. Confirm the README references the correct repository-relative path.
4. Confirm the README text accurately states SAFE exit 0, DANGEROUS exit 1,
   and 94/94 tests passing.
5. Run the existing test suite because README content is covered by packaging
   tests.

## Out of Scope

- GitHub Pages deployment.
- Uploading media to GitHub user attachments.
- Changing scanner behavior.
- Replacing the detailed `examples/DEMO.md` walkthrough.
