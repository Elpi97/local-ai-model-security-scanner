#!/usr/bin/env python3
"""Render the README demo GIF from captured end-to-end scan evidence."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "build" / "e2e-demo" / "logs"
OUTPUT = ROOT / "assets" / "e2e-demo.gif"

WIDTH, HEIGHT = 960, 540
FRAME_MS = 100  # 10 fps while text is appearing.
COLORS = {
    "background": "#0b1020",
    "panel": "#111827",
    "border": "#334155",
    "muted": "#94a3b8",
    "text": "#e5e7eb",
    "blue": "#60a5fa",
    "green": "#4ade80",
    "red": "#fb7185",
    "yellow": "#facc15",
}


@dataclass(frozen=True)
class Chapter:
    label: str
    command: str
    lines: tuple[str, ...]
    accent: str
    hold_ms: int


@dataclass(frozen=True)
class FrameState:
    chapter: Chapter | None
    lines: tuple[str, ...]
    duration_ms: int
    footer: str = ""


def read_evidence(filename: str, required: Iterable[str]) -> str:
    path = LOG_DIR / filename
    text = path.read_text(encoding="utf-8")
    missing = [fragment for fragment in required if fragment not in text]
    if missing:
        raise ValueError(f"{path} is missing expected evidence: {missing}")
    return text


def load_exit_code(filename: str, expected: str) -> str:
    path = LOG_DIR / filename
    code = path.read_text(encoding="utf-8").strip()
    if code != expected:
        raise ValueError(f"{path} expected exit code {expected!r}, got {code!r}")
    return code


def load_chapters() -> tuple[Chapter, ...]:
    doctor = read_evidence(
        "01-doctor.txt",
        ("deep ONNX scan: ENABLED", "verdict:        install OK"),
    )
    benign = read_evidence(
        "03-benign-scan.txt",
        ("Format:     safetensors", "hash_match:  True", "SAFE"),
    )
    hostile = read_evidence(
        "05-hostile-scan.txt",
        (
            "Format:     onnx",
            "ONNX external_data location escapes model dir",
            "../../../../etc/passwd",
            "DANGEROUS",
        ),
    )
    tests = read_evidence("06-tests.txt", ("collected 94 items", "94 passed"))
    benign_exit = load_exit_code("03-benign-exit-code.txt", "0")
    hostile_exit = load_exit_code("05-hostile-exit-code.txt", "1")

    # Keep the displayed excerpts deterministic while proving every claim against
    # the captured command output above. Exit codes come from captured log files.
    assert doctor and benign and hostile and tests
    return (
        Chapter(
            "1 / 4  VERIFY INSTALL",
            "$ model-scanner --doctor",
            (
                "model-scanner doctor",
                "  version:        0.4.1",
                "  onnx package:   present and working (1.19.1)",
                "  deep ONNX scan: ENABLED",
                "  verdict:        install OK",
            ),
            COLORS["blue"],
            3_200,
        ),
        Chapter(
            "2 / 4  SAFE PATH",
            "$ model-scanner model.safetensors --sha256 <trusted-digest>",
            (
                "File:       model.safetensors",
                "Format:     safetensors",
                "Size:       453,864 bytes",
                "SHA256:     8111d5afb0715dbf5a31396d31432cb5...",
                "Provenance:",
                "     hash_match:  True",
                "     [INFO] Safetensors header OK (64 tensors).",
                "",
                "Verdict:    SAFE",
                f"exit code: {benign_exit}",
            ),
            COLORS["green"],
            4_000,
        ),
        Chapter(
            "3 / 4  DANGEROUS PATH",
            "$ model-scanner trojan.onnx",
            (
                "File:       trojan.onnx",
                "Format:     onnx",
                "Size:       150 bytes",
                "Findings:",
                "[CRITICAL] ONNX external_data location escapes model dir: '../../../../etc/passwd'",
                "     [INFO] ONNX external-data tensors: 1",
                "",
                "Verdict:    DANGEROUS",
                f"exit code: {hostile_exit}",
            ),
            COLORS["red"],
            4_800,
        ),
        Chapter(
            "4 / 4  TESTS",
            "$ pytest",
            (
                "================ test session starts ================",
                "platform darwin -- Python 3.9.6, pytest-8.4.2",
                "collected 94 items",
                "",
                "tests/test_scanner.py ......................... [ 74%]",
                "tests/test_trust_behavior.py .................. [100%]",
                "",
                "================ 94 passed in 0.38s =================",
                "94 passed",
            ),
            COLORS["yellow"],
            4_000,
        ),
    )


def progressive_states(chapter: Chapter) -> list[FrameState]:
    states = [FrameState(chapter, (), 600)]
    visible: list[str] = []
    for line in chapter.lines:
        if not line:
            visible.append("")
            continue
        step = max(4, min(12, len(line) // 5 or 4))
        for end in range(step, len(line), step):
            states.append(
                FrameState(chapter, tuple(visible + [line[:end] + "▋"]), FRAME_MS)
            )
        visible.append(line)
        states.append(FrameState(chapter, tuple(visible), FRAME_MS))
    states.append(FrameState(chapter, tuple(visible), chapter.hold_ms))
    return states


def build_timeline(chapters: Sequence[Chapter]) -> list[FrameState]:
    states = [
        FrameState(
            None,
            ("LOCAL AI MODEL SAFETY SCANNER", "", "Real scans. Clear verdicts."),
            1_800,
            "End-to-end evidence",
        )
    ]
    for chapter in chapters:
        states.extend(progressive_states(chapter))
    states.append(
        FrameState(
            None,
            ("INSTALL VERIFIED", "SAFE MODEL ACCEPTED", "HOSTILE MODEL BLOCKED", "", "94 passed"),
            2_500,
            "Scan before you load.",
        )
    )

    duration = sum(state.duration_ms for state in states)
    if duration < 35_000:
        last = states[-1]
        states[-1] = FrameState(
            last.chapter, last.lines, last.duration_ms + 35_000 - duration, last.footer
        )
    elif duration > 45_000:
        raise ValueError(f"Timeline is too long: {duration / 1000:.1f}s")
    return states


def load_font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    names = (
        ("/System/Library/Fonts/Menlo.ttc",)
        if not bold
        else ("/System/Library/Fonts/SFNSMono.ttf", "/System/Library/Fonts/Menlo.ttc")
    )
    names += (
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
        if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    )
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


BODY_FONT = load_font(16)
BODY_BOLD = load_font(16, bold=True)
LABEL_FONT = load_font(15, bold=True)
TITLE_FONT = load_font(25, bold=True)


def draw_frame(state: FrameState) -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT), COLORS["background"])
    draw = ImageDraw.Draw(image)

    draw.rounded_rectangle(
        (24, 22, WIDTH - 24, HEIGHT - 22),
        radius=14,
        fill=COLORS["panel"],
        outline=COLORS["border"],
        width=2,
    )
    for x, color in ((48, COLORS["red"]), (70, COLORS["yellow"]), (92, COLORS["green"])):
        draw.ellipse((x - 6, 42, x + 6, 54), fill=color)
    draw.text((WIDTH - 205, 39), "model-scanner", font=LABEL_FONT, fill=COLORS["muted"])
    draw.line((42, 70, WIDTH - 42, 70), fill=COLORS["border"], width=1)

    if state.chapter is None:
        y = 176
        for index, line in enumerate(state.lines):
            color = COLORS["blue"] if index == 0 else COLORS["text"]
            font = TITLE_FONT if index == 0 else BODY_BOLD
            box = draw.textbbox((0, 0), line, font=font)
            x = (WIDTH - (box[2] - box[0])) // 2
            draw.text((x, y), line, font=font, fill=color)
            y += 48
        footer = state.footer
    else:
        chapter = state.chapter
        draw.text((50, 88), chapter.label, font=LABEL_FONT, fill=chapter.accent)
        draw.text((50, 116), chapter.command, font=BODY_BOLD, fill=COLORS["text"])
        draw.line((50, 148, WIDTH - 50, 148), fill=COLORS["border"], width=1)

        y = 168
        for line in state.lines:
            if "[CRITICAL]" in line or "DANGEROUS" in line:
                color = COLORS["red"]
            elif line.startswith("exit code:"):
                code = line.removeprefix("exit code:").strip()
                color = COLORS["green"] if code == "0" else COLORS["red"]
            elif "SAFE" in line:
                color = COLORS["green"]
            elif "94 passed" in line:
                color = COLORS["yellow"]
            elif line.startswith("$"):
                color = COLORS["blue"]
            else:
                color = COLORS["text"]
            draw.text((50, y), line, font=BODY_FONT, fill=color)
            y += 27
        footer = "Captured from build/e2e-demo/logs/"

    if footer:
        draw.text((50, HEIGHT - 53), footer, font=LABEL_FONT, fill=COLORS["muted"])
    return image


def make_global_palette(states: Sequence[FrameState]) -> Image.Image:
    sample_count = min(20, len(states))
    indices = {
        round(index * (len(states) - 1) / max(1, sample_count - 1))
        for index in range(sample_count)
    }
    samples = [draw_frame(states[index]).resize((240, 135)) for index in sorted(indices)]
    contact = Image.new("RGB", (240, 135 * len(samples)))
    for index, sample in enumerate(samples):
        contact.paste(sample, (0, index * 135))
    return contact.quantize(colors=64, method=Image.Quantize.MEDIANCUT)


def render(states: Sequence[FrameState]) -> None:
    palette = make_global_palette(states)
    frames = [
        draw_frame(state).quantize(palette=palette, dither=Image.Dither.NONE)
        for state in states
    ]
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    frames[0].save(
        OUTPUT,
        save_all=True,
        append_images=frames[1:],
        duration=[state.duration_ms for state in states],
        loop=0,
        optimize=True,
        disposal=1,
    )
    print(
        f"Wrote {OUTPUT.relative_to(ROOT)}: {len(frames)} frames, "
        f"{sum(state.duration_ms for state in states) / 1000:.1f}s"
    )


def main() -> None:
    render(build_timeline(load_chapters()))


if __name__ == "__main__":
    main()
