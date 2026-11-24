#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Check pull-request bodies and comments for stale base and dependency-head claims.

With --pull-json, --head HEX requires an exact match between pull head.sha and
full 40-hex HEX (exiting 3 on mismatch) before checking claims, and --label TEXT
overrides the display label for FILE arguments in stale-claim diagnostics.
Repeat --dependency-json N=PATH to supply each dependency PR's live head (no stdin).
With --list-dependencies, print sorted unique dependency PR numbers instead of
checking claims, after the same input and optional pull-head validation.
Dependency lists pair each reference with its own head; an ambiguous lone
trailing head is rejected. Headless list members still count toward the limit.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path

BASE_CLAIM = re.compile(
    r"\bbase\b[:\s]+(?:(?:ffmpeg|master|is|commit)\s+){0,3}([0-9a-f]{7,40})\b",
    re.IGNORECASE,
)
DEPENDENCY_MEMBER = re.compile(r"(?:#|PR\s+#?|pull\s+request\s+#?)([0-9]{1,7})\b", re.IGNORECASE)
DEPENDENCY_REFERENCE = re.compile(
    r"\b(?:depends\s+on|stacked\s+on|on\s+top\s+of|builds\s+on|based\s+on)"
    r"\s+" + DEPENDENCY_MEMBER.pattern,
    re.IGNORECASE,
)
DEPENDENCY_SEPARATOR = re.compile(r"\s*(?:,\s*(?:and\s+)?|\band\s+|&\s*)", re.IGNORECASE)
DEPENDENCY_NONMEMBER_PREFIX = re.compile(r"\s*\b(?:and\s+)?(?:see|unrelated)\s+", re.IGNORECASE)
DEPENDENCY_LEAD_GAP = re.compile(r"\s+(?:(?:and\s+)?now|previously)\s+", re.IGNORECASE)
DEPENDENCY_HEAD = re.compile(
    r"\b(?:head|ending\s+at|ends\s+at|tip)\b[\s:(]*([0-9a-f]{7,40})\b", re.IGNORECASE
)
DEPENDENCY_ANNOTATION = re.compile(
    r"\s*(?:[:,|\u2013\u2014-]\s*)?(?:[a-z]+\s+)*(?:\([^()\[\]#&;]*"
    + DEPENDENCY_HEAD.pattern
    + r"[^()\[\]#&;]*\)+|\[[^\[\]#&;]*"
    + DEPENDENCY_HEAD.pattern
    + r"[^\[\]#&;]*\]|"
    + DEPENDENCY_HEAD.pattern
    + r"\)*)",
    re.IGNORECASE,
)
SENTENCE_BREAK = re.compile(r"[.!?]\s|;")
CLAUSE_BREAK = re.compile(r"[;,|()]|\.\s")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
HISTORY_WORDS = re.compile(r"\b(previous|prior|earlier|former|old)\b", re.IGNORECASE)
HEX_SHA = re.compile(r"[0-9a-fA-F]{40}")
BRACKET_PAIRS: dict[str, str] = {"(": ")", "[": "]", "{": "}"}
MAX_DEPENDENCIES = 8


def _step_fence(line: str, fence: tuple[str, int] | None) -> tuple[tuple[str, int] | None, bool]:
    """Update CommonMark fence state for one line and report whether to skip it."""
    match = FENCE.match(line)
    if fence is None:
        if match is None:
            return None, False
        run, rest = match.group(1), match.group(2)
        if run[0] == "~" or "`" not in rest:
            return (run[0], len(run)), True
        return None, False
    open_char, open_len = fence
    if (
        match is not None
        and match.group(1)[0] == open_char
        and len(match.group(1)) >= open_len
        and not match.group(2).strip()
    ):
        return None, True
    return fence, True


def _line_claims(line: str) -> list[str]:
    """Extract base-commit hex claims from one non-fenced, non-quoted line."""
    claims: list[str] = []
    prev_end = 0
    for match in BASE_CLAIM.finditer(line):
        clause_start = prev_end
        for sep in CLAUSE_BREAK.finditer(line, prev_end, match.start()):
            clause_start = sep.end()
        if HISTORY_WORDS.search(line, clause_start, match.start()) is None:
            claims.append(match.group(1).lower())
        prev_end = match.end()
    return claims


def _claim_lines(text: str) -> Iterator[str]:
    """Yield lines outside CommonMark fences and block quotes for both claim kinds."""
    fence: tuple[str, int] | None = None
    for line in text.splitlines():
        fence, skipped = _step_fence(line, fence)
        if not skipped and not line.lstrip().startswith(">"):
            yield line


def find_base_claims(text: str) -> list[str]:
    """Return lowercased base-commit hex claims outside fences, quotes and history clauses."""
    return [claim for line in _claim_lines(text) for claim in _line_claims(line)]


def _dependency_bracket_depths(sentence: str) -> list[int]:
    """Return bracket depth immediately before each sentence index in one bounded pass."""
    closers = set(BRACKET_PAIRS.values())
    depths = [0] * (len(sentence) + 1)
    depth = 0
    for index, char in enumerate(sentence):
        depths[index] = depth
        if char in BRACKET_PAIRS:
            depth += 1
        elif char in closers and depth > 0:
            depth -= 1
    depths[len(sentence)] = depth
    return depths


def _dependency_prose_break(sentence: str, depths: list[int], index: int) -> bool:
    """Report whether an index is a depth-zero prose clause or list boundary."""
    if index >= len(sentence) or depths[index] != 0:
        return False
    char = sentence[index]
    if char in ",;|":
        return True
    return char == "." and index + 1 < len(sentence) and sentence[index + 1].isspace()


def _dependency_clause_start(
    sentence: str, depths: list[int], start: int, end: int, fallback: int = 0
) -> int:
    """Return the last depth-zero prose boundary in a range or the supplied fallback."""
    clause_start = fallback
    for index in range(start, end):
        if _dependency_prose_break(sentence, depths, index):
            clause_start = index + 1 if sentence[index] != "." else index + 2
    return clause_start


def _dependency_bracket_extent(sentence: str, open_index: int, end: int) -> int:
    """Return the index after the bracket opened at open_index, or end when unclosed."""
    open_char = sentence[open_index]
    close_char = BRACKET_PAIRS[open_char]
    depth = 0
    for index in range(open_index, end):
        if sentence[index] == open_char:
            depth += 1
        elif sentence[index] == close_char:
            depth -= 1
            if depth == 0:
                return index + 1
    return end


def _dependency_head_clause_start(
    sentence: str, depths: list[int], scope_start: int, head_index: int, depth: int
) -> int:
    """Return the start of the depth-local clause holding head_index."""
    clause_start = scope_start
    for index in range(scope_start, head_index):
        if depths[index] == depth and sentence[index] in ",;":
            clause_start = index + 1
    return clause_start


def _dependency_head_scope_start(
    sentence: str, depths: list[int], reference_end: int, head_index: int
) -> int:
    """Return the search start for history in the scope that owns head_index."""
    head_depth = depths[min(head_index, len(sentence))]
    if head_depth != 0:
        return reference_end
    index = reference_end
    for _ in range(head_index - reference_end + 1):
        if index >= head_index:
            break
        if sentence[index] in BRACKET_PAIRS:
            index = _dependency_bracket_extent(sentence, index, head_index)
            continue
        if sentence[index].isspace() or sentence[index] in ",;|":
            index += 1
            continue
        break
    return index


def _dependency_head_is_historical(
    sentence: str,
    depths: list[int],
    reference: re.Match[str],
    head: re.Match[str],
    reference_clause_start: int,
) -> bool:
    """Check history in the reference lead and the head's depth-local clause before its hex."""
    head_index = head.start(1)
    reference_lead = sentence[reference_clause_start : reference.start()]
    if HISTORY_WORDS.search(reference_lead) or re.search(
        r"\bpreviously\b", reference_lead, re.IGNORECASE
    ):
        return True
    head_depth = depths[min(head_index, len(sentence))]
    scope_start = _dependency_head_scope_start(sentence, depths, reference.end(), head_index)
    clause_start = _dependency_head_clause_start(
        sentence, depths, scope_start, head_index, head_depth
    )
    clause = sentence[clause_start:head_index]
    return bool(HISTORY_WORDS.search(clause) or re.search(r"\bpreviously\b", clause, re.IGNORECASE))


def _dependency_member_end(sentence: str, depths: list[int], start: int, end: int) -> int:
    """Consume annotation heads without crossing depth-zero member separators."""
    cursor = start
    for _ in range(end - start + 1):
        separator = DEPENDENCY_SEPARATOR.match(sentence, cursor, end)
        if separator is not None and _dependency_prose_break(sentence, depths, separator.start()):
            break
        annotation = DEPENDENCY_ANNOTATION.match(sentence, cursor, end)
        if annotation is None:
            break
        cursor = annotation.end()
    return cursor


def _sentence_member_numbers(sentence: str) -> str:
    """Format each member reference number in a sentence once in appearance order."""
    numbers = dict.fromkeys(match.group(1) for match in DEPENDENCY_MEMBER.finditer(sentence))
    return ", ".join(f"#{number}" for number in numbers)


def _dependency_sentence_error(sentence: str, subject: str, fix: str) -> ValueError:
    """Build an ambiguity error naming every sentence member and one repair clause."""
    numbers = _sentence_member_numbers(sentence)
    return ValueError(f"ambiguous dependency {subject} for {numbers}: {fix}")


def _dependency_attribution_error(sentence: str) -> ValueError:
    """Name sentence references when a head or hidden member cannot be safely attributed."""
    numbers = _sentence_member_numbers(sentence)
    return ValueError(
        f"ambiguous dependency heads for {numbers}: unpaired head or hidden member; "
        "write the head right after each reference or one dependency per sentence"
    )


def _dependency_list_lead_historical(
    sentence: str,
    depths: list[int],
    first: re.Match[str],
    lead_start: int,
    end: int | None = None,
) -> bool:
    """Return whether list history appears before the first member annotation."""
    window = len(sentence) if end is None else end
    gap_end = first.end()
    if DEPENDENCY_SEPARATOR.match(sentence, gap_end, window) is None:
        member_end = _dependency_member_end(sentence, depths, first.end(), window)
        for index in range(first.end(), min(member_end, window)):
            if sentence[index] in BRACKET_PAIRS:
                gap_end = index
                break
        else:
            gap_end = member_end
    lead = sentence[lead_start:gap_end]
    return bool(HISTORY_WORDS.search(lead) or re.search(r"\bpreviously\b", lead, re.IGNORECASE))


def _dependency_lead_annotation_end(
    sentence: str, depths: list[int], member_start: int, end: int
) -> int:
    """Return the furthest bracketed annotation end before prose or a depth-zero member."""
    cursor = member_start
    for index in range(member_start, end):
        if _dependency_prose_break(sentence, depths, index):
            return cursor
        if depths[index] == 0 and DEPENDENCY_MEMBER.match(sentence, index, end) is not None:
            return cursor
        if sentence[index] in BRACKET_PAIRS:
            cursor = max(cursor, _dependency_bracket_extent(sentence, index, end))
    return cursor


def _dependency_separated_member(
    sentence: str, depths: list[int], start: int, end: int
) -> re.Match[str] | None:
    """Return the member after the next depth-zero list separator, or None on prose."""
    for separator in DEPENDENCY_SEPARATOR.finditer(sentence, start, end):
        if depths[separator.start()] != 0:
            continue
        return DEPENDENCY_MEMBER.match(sentence, separator.end(), end)
    return None


def _reject_hidden_dependency_members(
    sentence: str,
    depths: list[int],
    members: list[tuple[re.Match[str], int]],
    end: int,
) -> None:
    """Reject unparsed members hidden inside parsed member annotations."""
    first = members[0][0]
    parsed_starts = {reference.start() for reference, _ in members[1:]}
    for member in DEPENDENCY_MEMBER.finditer(sentence, first.end(), end):
        if member.start() in parsed_starts or member.start() <= first.start():
            continue
        if depths[member.start()] == 0:
            continue
        raise _dependency_attribution_error(sentence)


def _dependency_nonmember_introducer(sentence: str, start: int, end: int) -> bool:
    """Report whether clause text before a later reference is an allowed introducer."""
    return DEPENDENCY_NONMEMBER_PREFIX.fullmatch(sentence, start, end) is not None


def _is_repeat_dependency_member(
    sentence: str, member: re.Match[str], member_numbers: set[int], end: int, fix: str
) -> bool:
    """Accept a headless repeat of a listed member and reject a repeat with a head."""
    if int(member.group(1)) not in member_numbers:
        return False
    if _dependency_member_heads(sentence, member, end):
        raise _dependency_sentence_error(sentence, "references", fix)
    return True


def _reject_unlisted_later_references(
    sentence: str,
    depths: list[int],
    members: list[tuple[re.Match[str], int]],
    bounds: tuple[int, int],
    lead_historical: bool,
) -> None:
    """Reject later window references on current leads unless allow-listed."""
    if lead_historical:
        return
    floor, end = bounds
    member_numbers = {int(reference.group(1)) for reference, _ in members}
    fix = "write the head right after its reference or one dependency per sentence"
    chain_end: int | None = None
    for member in DEPENDENCY_MEMBER.finditer(sentence, floor, end):
        if depths[member.start()] != 0:
            raise _dependency_sentence_error(sentence, "references", fix)
        if _is_repeat_dependency_member(sentence, member, member_numbers, end, fix):
            chain_end = None
            continue
        if chain_end is not None and DEPENDENCY_SEPARATOR.fullmatch(
            sentence, chain_end, member.start()
        ):
            chain_end = member.end()
            continue
        clause_start = _dependency_clause_start(sentence, depths, floor, member.start(), floor)
        if not _dependency_nonmember_introducer(sentence, clause_start, member.start()):
            raise _dependency_sentence_error(sentence, "references", fix)
        chain_end = member.end()


def _dependency_member_heads(
    sentence: str, reference: re.Match[str], end: int
) -> list[re.Match[str]]:
    """Attribute heads to their nearest preceding reference, including nonmembers."""
    following = DEPENDENCY_MEMBER.search(sentence, reference.end(), end)
    stop = following.start() if following else end
    return list(DEPENDENCY_HEAD.finditer(sentence, reference.end(), stop))


def _widened_head_gap_allowed(sentence: str, own_end: int, head_start: int) -> bool:
    """Report whether text from a single member's annotation end to a head lacks digits."""
    gap = DEPENDENCY_HEAD.sub("", sentence[own_end:head_start])
    return not any("0" <= char <= "9" for char in gap)


def _reject_ambiguous_member_heads(
    sentence: str,
    own_ends: list[int],
    current: list[list[re.Match[str]]],
) -> None:
    """Reject multiple distinct current heads per member or digit-bearing single-member gaps."""
    fix = "write the head right after its reference or one dependency per sentence"
    for member_heads in current:
        if len({head.group(1).lower() for head in member_heads}) > 1:
            raise _dependency_sentence_error(sentence, "heads", fix)
    if len(own_ends) == 1:
        own_end = own_ends[0]
        for head in current[0]:
            if head.start() > own_end and not _widened_head_gap_allowed(
                sentence, own_end, head.start()
            ):
                raise _dependency_sentence_error(sentence, "heads", fix)


def _reject_unpaired_dependency_heads(
    sentence: str,
    depths: list[int],
    members: list[tuple[re.Match[str], int]],
    own_ends: list[int],
    list_bounds: tuple[int, int],
) -> None:
    """Reject current member-owned heads outside the shared annotation grammar."""
    list_end, _ = list_bounds
    heads = [_dependency_member_heads(sentence, reference, list_end) for reference, _ in members]
    current = _current_dependency_heads(sentence, depths, members, heads, list_bounds)
    for (_, member_end), member_heads in zip(members, current, strict=True):
        for head in member_heads:
            if head.end() > member_end:
                raise ValueError(
                    f"{_dependency_attribution_error(sentence)}: {head.group(1).lower()}"
                )
    _reject_ambiguous_member_heads(sentence, own_ends, current)


def _dependency_lead_gap_allowed(gap: str) -> bool:
    """Report whether text from clause start to a later lead verb is allow-listed."""
    return DEPENDENCY_LEAD_GAP.fullmatch(gap) is not None


def _dependency_next_lead_start(
    sentence: str, depths: list[int], prev_floor: int, reference: re.Match[str]
) -> int:
    """Validate a later lead's depth and clause gap and return its history-window start."""
    fix = "write one dependency per sentence"
    if depths[reference.start()] != 0:
        raise _dependency_sentence_error(sentence, "leads", fix)
    lead_start = _dependency_clause_start(
        sentence, depths, prev_floor, reference.start(), prev_floor
    )
    if not _dependency_lead_gap_allowed(sentence[lead_start : reference.start()]):
        raise _dependency_sentence_error(sentence, "leads", fix)
    return lead_start


def _split_claim_sentences(line: str) -> list[str]:
    """Split a claim line only at depth-zero sentence breaks."""
    depths = _dependency_bracket_depths(line)
    sentences: list[str] = []
    start = 0
    for match in SENTENCE_BREAK.finditer(line):
        if depths[match.start()] == 0:
            sentences.append(line[start : match.start()])
            start = match.end()
    sentences.append(line[start:])
    return sentences


def _reject_bracketed_sentence_break(sentence: str, depths: list[int]) -> None:
    """Reject a sentence with a dependency lead and a bracketed sentence break."""
    for match in SENTENCE_BREAK.finditer(sentence):
        if depths[match.start()] > 0:
            raise _dependency_sentence_error(
                sentence, "annotation", "write no sentence break inside the annotation"
            )


def _parse_dependency_members(
    sentence: str, depths: list[int], first: re.Match[str], list_end: int
) -> list[tuple[re.Match[str], int]]:
    """Parse separator-joined list members and their own supported annotation ends."""
    reference = first
    members: list[tuple[re.Match[str], int]] = []
    for _ in range(list_end - reference.end() + 1):
        member_end = _dependency_member_end(sentence, depths, reference.end(), list_end)
        members.append((reference, member_end))
        separator = DEPENDENCY_SEPARATOR.match(sentence, member_end, list_end)
        following = (
            DEPENDENCY_MEMBER.match(sentence, separator.end(), list_end) if separator else None
        )
        if following is None:
            break
        reference = following
    return members


def _dependency_list_floor(
    sentence: str,
    depths: list[int],
    members: list[tuple[re.Match[str], int]],
    list_end: int,
) -> int:
    """Return the end of the last member's annotation and bracket extent."""
    first_bracket = _dependency_lead_annotation_end(sentence, depths, members[0][0].end(), list_end)
    last_bracket = _dependency_lead_annotation_end(sentence, depths, members[-1][0].end(), list_end)
    return max(members[-1][1], first_bracket, last_bracket)


def _validate_dependency_list(
    sentence: str,
    depths: list[int],
    members: list[tuple[re.Match[str], int]],
    bounds: tuple[int, int, int],
) -> None:
    """Validate hidden members, later references and current head attribution for one list."""
    floor, list_end, lead_start = bounds
    lead_historical = _dependency_list_lead_historical(
        sentence, depths, members[0][0], lead_start, list_end
    )
    if lead_historical:
        return
    own_ends = [member_end for _, member_end in members]
    _reject_hidden_dependency_members(sentence, depths, members, floor)
    _reject_unlisted_later_references(sentence, depths, members, (floor, list_end), lead_historical)
    widened = [(members[0][0], list_end)] if len(members) == 1 else members
    _reject_unpaired_dependency_heads(sentence, depths, widened, own_ends, (list_end, lead_start))


def _dependency_lists(
    sentence: str, depths: list[int] | None = None
) -> Iterator[tuple[list[tuple[re.Match[str], int]], int, int]]:
    """Yield grammar spans, rejecting unlisted continuations and unpaired heads."""
    if depths is None:
        depths = _dependency_bracket_depths(sentence)
    references = list(DEPENDENCY_REFERENCE.finditer(sentence))
    if references:
        _reject_bracketed_sentence_break(sentence, depths)
    prev_floor = 0
    for index, first in enumerate(references):
        list_end = references[index + 1].start() if index + 1 < len(references) else len(sentence)
        lead_start = (
            _dependency_clause_start(sentence, depths, 0, first.start())
            if index == 0
            else _dependency_next_lead_start(sentence, depths, prev_floor, first)
        )
        members = _parse_dependency_members(sentence, depths, first, list_end)
        floor = _dependency_list_floor(sentence, depths, members, list_end)
        _validate_dependency_list(sentence, depths, members, (floor, list_end, lead_start))
        if len(members) == 1:
            members[0] = (members[0][0], list_end)
        prev_floor = floor
        yield members, list_end, lead_start


def _reject_ambiguous_dependency_list(
    sentence: str, members: list[tuple[re.Match[str], int]], heads: list[list[re.Match[str]]]
) -> None:
    """Reject a lone trailing head that could belong to one member or the whole list."""
    if len(members) > 1 and heads[-1] and not any(heads[:-1]):
        numbers = _sentence_member_numbers(sentence)
        prefix = heads[-1][0].group(1).lower()
        raise ValueError(
            f"ambiguous dependency heads for {numbers}: {prefix}; "
            "write the head right after each reference or one dependency per sentence"
        )


def _dependency_list_history(
    sentence: str,
    depths: list[int],
    first: re.Match[str],
    list_bounds: tuple[int, int],
) -> tuple[int, bool]:
    """Locate the lead clause and judge history shared by every list member."""
    list_end, lead_start = list_bounds
    historical = _dependency_list_lead_historical(sentence, depths, first, lead_start, list_end)
    return lead_start, historical


def _current_dependency_heads(
    sentence: str,
    depths: list[int],
    members: list[tuple[re.Match[str], int]],
    heads: list[list[re.Match[str]]],
    list_bounds: tuple[int, int],
) -> list[list[re.Match[str]]]:
    """Filter member heads through unchanged clause history before ambiguity judgement."""
    first = members[0][0]
    lead_start, historical = _dependency_list_history(sentence, depths, first, list_bounds)
    current = []
    for (reference, _), member_heads in zip(members, heads, strict=True):
        clause_start = lead_start if reference is first else reference.start()
        current.append(
            [
                head
                for head in member_heads
                if not historical
                and not _dependency_head_is_historical(
                    sentence, depths, reference, head, clause_start
                )
            ]
        )
    return current


def _dependency_list_claims(
    sentence: str,
    depths: list[int],
    members: list[tuple[re.Match[str], int]],
    list_bounds: tuple[int, int],
) -> list[tuple[int, str | None]]:
    """Pair nearest-reference member heads, judging history before ambiguity."""
    list_end, lead_start = list_bounds
    if _dependency_list_lead_historical(sentence, depths, members[0][0], lead_start, list_end):
        return []
    heads = [_dependency_member_heads(sentence, reference, list_end) for reference, _ in members]
    current = _current_dependency_heads(sentence, depths, members, heads, list_bounds)
    if any(heads) and not any(current):
        return []
    _reject_ambiguous_dependency_list(sentence, members, heads)
    claims: list[tuple[int, str | None]] = []
    for (reference, _), member_heads, member_heads_raw in zip(members, current, heads, strict=True):
        number = int(reference.group(1))
        if number == 0:
            continue
        if len(members) > 1 and (member_heads or not member_heads_raw):
            claims.append((number, None))
        claims.extend((number, head.group(1).lower()) for head in member_heads)
    return claims


def _sentence_dependencies(sentence: str) -> list[tuple[int, str | None]]:
    """Extract list members and their own heads, raising ValueError for ambiguous lists."""
    depths = _dependency_bracket_depths(sentence)
    return [
        claim
        for members, list_end, lead_start in _dependency_lists(sentence, depths)
        for claim in _dependency_list_claims(sentence, depths, members, (list_end, lead_start))
    ]


def _check_dependency_count(numbers: set[int]) -> None:
    """Reject distinct dependency member counts above the shared limit."""
    if len(numbers) > MAX_DEPENDENCIES:
        raise ValueError(f"more than {MAX_DEPENDENCIES} distinct dependency PR numbers")


def _dependency_records(text: str) -> list[tuple[int, str | None]]:
    """Collect bounded member records outside fences and quotes, rejecting ambiguous lists."""
    records = [
        claim
        for line in _claim_lines(text)
        for sentence in _split_claim_sentences(line)
        for claim in _sentence_dependencies(sentence)
    ]
    _check_dependency_count({number for number, _ in records})
    return records


def find_dependency_claims(text: str) -> list[tuple[int, str]]:
    """Return members' own nonhistorical heads; raise ValueError on ambiguity or excess."""
    return [(number, head) for number, head in _dependency_records(text) if head is not None]


def stale_claims(text: str, merge_base: str) -> list[str]:
    """Return base claims in text that are not a prefix of merge_base."""
    normalized = merge_base.lower()
    return [claim for claim in find_base_claims(text) if not normalized.startswith(claim)]


def _validate_options(args: argparse.Namespace) -> None:
    """Reject option combinations and --head values outside the CLI contract."""
    if args.pull_json is None:
        if args.live_body:
            raise ValueError("--live-body requires --pull-json")
        if args.head is not None:
            raise ValueError("--head requires --pull-json")
    if args.head is not None and HEX_SHA.fullmatch(args.head) is None:
        raise ValueError("--head must be a full 40-hex commit id")


def _read_pull_payload(path_or_dash: str) -> dict[str, object]:
    """Load and type-check the pull-request JSON object from a path or stdin."""
    raw = (
        sys.stdin.read() if path_or_dash == "-" else Path(path_or_dash).read_text(encoding="utf-8")
    )
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("pull JSON must be an object")
    return payload


def _check_pull_head(payload: dict[str, object], expected_head: str | None) -> str | None:
    """Verify pull JSON head.sha against expected_head, returning a mismatch message."""
    if expected_head is None:
        return None
    head = payload.get("head")
    sha = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(sha, str) or HEX_SHA.fullmatch(sha) is None:
        raise ValueError(f"invalid pull head: {sha!r}")
    actual, wanted = sha.lower(), expected_head.lower()
    if actual != wanted:
        return f"pull head {actual} is not {wanted}"
    return None


def _load_targets(
    args: argparse.Namespace,
) -> tuple[str | None, object, list[tuple[str, str]]]:
    """Read head mismatch, merge base and labelled texts from parsed CLI arguments."""
    _validate_options(args)
    targets: list[tuple[str, str]] = []
    merge_base: object = args.merge_base
    if args.pull_json is not None:
        payload = _read_pull_payload(args.pull_json)
        mismatch = _check_pull_head(payload, args.head)
        if mismatch is not None:
            return mismatch, None, []
        merge_base = payload.get("merge_base")
        if args.live_body:
            body = payload.get("body")
            if not isinstance(body, str):
                raise ValueError("pull JSON missing string body")
            targets.append(("live PR body", body))
    targets.extend(
        (args.label if args.label is not None else path, Path(path).read_text(encoding="utf-8"))
        for path in args.files
    )
    return None, merge_base, targets


def _build_parser() -> argparse.ArgumentParser:
    """Construct the parser for base checks, dependency heads and dependency listing."""
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--merge-base", metavar="HEX", help="live 40-hex merge base")
    source.add_argument("--pull-json", metavar="PATH", help="pull JSON path or '-' for stdin")
    parser.add_argument(
        "--head",
        metavar="HEX",
        help="require pull JSON head.sha to match full 40-hex HEX exactly (exit 3 on mismatch)",
    )
    parser.add_argument(
        "--live-body",
        action="store_true",
        help="check the pull JSON body field as 'live PR body'",
    )
    parser.add_argument(
        "--label",
        metavar="TEXT",
        help="label every FILE argument as TEXT instead of its path",
    )
    parser.add_argument(
        "--dependency-json",
        action="append",
        default=[],
        metavar="N=PATH",
        help="dependency PR number and pull JSON path (repeatable, no stdin)",
    )
    parser.add_argument(
        "--list-dependencies",
        action="store_true",
        help="list sorted unique dependency PR numbers without checking claims",
    )
    parser.add_argument("files", nargs="*", metavar="FILE", help="body file to check")
    return parser


def _dependency_numbers(targets: list[tuple[str, str]]) -> list[int]:
    """List all member numbers, including headless members; reject ambiguity and overflow."""
    numbers = {number for _, text in targets for number, _ in _dependency_records(text)}
    _check_dependency_count(numbers)
    return sorted(numbers)


def _dependency_option(option: str) -> tuple[int, str]:
    """Parse one positive bounded PR number and non-stdin dependency JSON path."""
    number_text, separator, path = option.partition("=")
    if not separator or re.fullmatch(r"[0-9]{1,7}", number_text) is None:
        raise ValueError(f"invalid --dependency-json N=PATH: {option!r}")
    number = int(number_text)
    if number == 0 or not path or path == "-":
        raise ValueError(f"invalid --dependency-json N=PATH: {option!r}")
    return number, path


def _load_dependencies(options: list[str]) -> dict[int, str]:
    """Validate bounded N=PATH options and load full live dependency heads."""
    if len(options) > MAX_DEPENDENCIES:
        raise ValueError(f"more than {MAX_DEPENDENCIES} --dependency-json options")
    heads: dict[int, str] = {}
    for option in options:
        number, path = _dependency_option(option)
        if number in heads:
            raise ValueError(f"repeated --dependency-json for #{number}")
        payload = _read_pull_payload(path)
        head = payload.get("head")
        sha = head.get("sha") if isinstance(head, dict) else None
        if not isinstance(sha, str) or HEX_SHA.fullmatch(sha) is None:
            raise ValueError(f"invalid dependency pull #{number} head: {sha!r}")
        heads[number] = sha.lower()
    return heads


def _base_diagnostics(targets: list[tuple[str, str]], merge_base: object) -> list[str]:
    """Validate the merge base when needed and format stale base diagnostics."""
    if not any(find_base_claims(text) for _, text in targets):
        return []
    if not isinstance(merge_base, str) or HEX_SHA.fullmatch(merge_base) is None:
        raise ValueError(f"invalid merge base: {merge_base!r}")
    return [
        f"{label}: names base {claim}, the live merge base is {merge_base}"
        for label, text in targets
        for claim in stale_claims(text, merge_base)
    ]


def _dependency_diagnostics(targets: list[tuple[str, str]], heads: dict[int, str]) -> list[str]:
    """Format stale dependency-head diagnostics from validated live heads."""
    return [
        f"{label}: names head {claim} of #{number}, the live head of #{number} is {heads[number]}"
        for label, text in targets
        for number, claim in find_dependency_claims(text)
        if not heads[number].startswith(claim)
    ]


def main(argv: list[str] | None = None) -> int:
    """Check claims or list bounded dependency members, refusing ambiguous heads with rc 2."""
    args = _build_parser().parse_args(argv)
    try:
        mismatch, merge_base, targets = _load_targets(args)
        if mismatch is not None:
            print(mismatch, file=sys.stderr)
            return 3
        numbers = _dependency_numbers(targets)
        heads = _load_dependencies(args.dependency_json)
        if args.list_dependencies:
            for number in numbers:
                print(number)
            return 0
        for number in numbers:
            if number not in heads:
                raise ValueError(f"missing --dependency-json for #{number}")
        stale = _base_diagnostics(targets, merge_base)
        stale.extend(_dependency_diagnostics(targets, heads))
    except (OSError, UnicodeError, ValueError) as error:
        print(f"base_claims: {error}", file=sys.stderr)
        return 2
    for message in stale:
        print(message, file=sys.stderr)
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
