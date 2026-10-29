#!/usr/bin/env python3
"""Validate Android string/plural resource translations against the base locale.

Language-agnostic checker for GeDefense TV (reusable for other Android projects).

Checks, per locale directory:
  1. XML well-formedness (xml.etree.ElementTree) for every checked file.
  2. Exact string key-set equality with the base file (missing, extra and
     duplicate keys all fail).
  3. Per-key placeholder multiset equality with the base (e.g. ``%1$s``,
     ``%2$d``); literal ``%%`` is ignored on both sides.
  4. Non-empty string values.

With --include-plurals additionally:
  5. Exact plural-group key-set equality with the base.
  6. Every base quantity (one/other/...) present in the locale (missing fails);
     extra quantities such as French ``many`` are allowed but every quantity
     must be a valid Android quantity and contain the same placeholders as the
     base (extra quantities are compared against the base ``other`` form).
  7. Non-empty plural item values and valid XML in plurals.xml.

Usage (from the project root, stdlib only):

  python tools/check_translations.py \
      --base app/src/main/res/values \
      --locale app/src/main/res/values-en \
      --locale app/src/main/res/values-de \
      --locale app/src/main/res/values-fr \
      --include-plurals

Exit code 0 when every locale passes, 1 otherwise (details on stdout).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, OrderedDict

DEFAULT_FILES = (
    "strings.xml",
    "strings_check.xml",
    "strings_fit.xml",
    "strings_home.xml",
    "strings_screens.xml",
    "strings_settings.xml",
    "strings_v2.xml",
    "strings_v2_ui.xml",
)

VALID_QUANTITIES = ("zero", "one", "two", "few", "many", "other")

# Android format specifiers: %s, %d, %1$s, %2$d, %1$.2f, %1$02d, ...
# Literal "%%" is not a placeholder and is removed before matching.
PLACEHOLDER_RE = re.compile(r"%(?!%)(?:\d+\$)?[-#+ 0,(]*\d*(?:\.\d+)?[a-zA-Z]")

# Catalog messages (tv-core text catalog) use positional brace placeholders {0}..{7}.
CATALOG_PLACEHOLDER_RE = re.compile(r"\{[0-7]\}")


def placeholders(text: str) -> Counter:
    """Return the multiset of Android format placeholders in ``text``."""
    return Counter(PLACEHOLDER_RE.findall(text.replace("%%", "")))


def parse_strings(path: str):
    """Parse one string resource file.

    Returns (ordered mapping name -> value, list of duplicate names).
    """
    tree = ET.parse(path)
    values = OrderedDict()
    duplicates = []
    for element in tree.getroot().findall("string"):
        name = element.get("name")
        if name is None:
            continue
        if name in values:
            duplicates.append(name)
        values[name] = "".join(element.itertext())
    return values, duplicates


def parse_plurals(path: str):
    """Parse one plural resource file.

    Returns (ordered mapping name -> ordered (quantity -> text),
    duplicate group names, duplicate quantities).
    """
    tree = ET.parse(path)
    groups = OrderedDict()
    duplicate_groups = []
    duplicate_quantities = []
    for element in tree.getroot().findall("plurals"):
        name = element.get("name")
        if name is None:
            continue
        if name in groups:
            duplicate_groups.append(name)
        items = OrderedDict()
        for item in element.findall("item"):
            quantity = item.get("quantity")
            if quantity is None:
                continue
            if quantity in items:
                duplicate_quantities.append(f"{name}/{quantity}")
            items[quantity] = "".join(item.itertext())
        groups[name] = items
    return groups, duplicate_groups, duplicate_quantities


def load_base_strings(base_dir, files):
    """Load base strings; returns ordered map name -> (value, file)."""
    base = OrderedDict()
    errors = []
    for filename in files:
        path = os.path.join(base_dir, filename)
        if not os.path.isfile(path):
            errors.append(f"base file missing: {path}")
            continue
        try:
            values, duplicates = parse_strings(path)
        except ET.ParseError as exc:
            errors.append(f"base XML parse error in {path}: {exc}")
            continue
        for name in duplicates:
            errors.append(f"base duplicate key '{name}' in {filename}")
        for name, value in values.items():
            if name in base:
                errors.append(
                    f"base duplicate key '{name}' in {filename} "
                    f"(already in {base[name][1]})"
                )
            else:
                base[name] = (value, filename)
    return base, errors


def check_locale_strings(base, locale_dir, files):
    """Validate one locale directory for string files."""
    failures = []
    stats = {
        "files": 0,
        "keys": 0,
        "missing": 0,
        "extra": 0,
        "duplicates": 0,
        "placeholders": 0,
        "empty": 0,
        "xml_errors": 0,
    }

    expected_by_file = OrderedDict()
    for name in base:
        expected_by_file.setdefault(base[name][1], []).append(name)

    for filename in files:
        path = os.path.join(locale_dir, filename)
        expected = expected_by_file.get(filename, [])
        if not os.path.isfile(path):
            stats["xml_errors"] += 1
            failures.append(f"missing file: {path}")
            continue
        stats["files"] += 1
        try:
            values, duplicates = parse_strings(path)
        except ET.ParseError as exc:
            stats["xml_errors"] += 1
            failures.append(f"XML parse error in {path}: {exc}")
            continue

        stats["keys"] += len(values)
        for name in duplicates:
            stats["duplicates"] += 1
            failures.append(f"{filename}: duplicate key '{name}'")

        expected_set = set(expected)
        actual_set = set(values)
        for name in expected:
            if name not in actual_set:
                stats["missing"] += 1
                failures.append(f"{filename}: missing key '{name}'")
        for name in values:
            if name not in expected_set:
                stats["extra"] += 1
                failures.append(f"{filename}: extra key '{name}'")

        for name in expected:
            if name not in values:
                continue
            translated = values[name]
            if not translated.strip():
                stats["empty"] += 1
                failures.append(f"{filename}: empty value for '{name}'")
            base_ph = placeholders(base[name][0])
            loc_ph = placeholders(translated)
            if base_ph != loc_ph:
                stats["placeholders"] += 1
                failures.append(
                    f"{filename}: placeholder mismatch for '{name}': "
                    f"base {dict(base_ph)} != locale {dict(loc_ph)}"
                )

    stats["expected_keys"] = len(base)
    return failures, stats


def load_base_plurals(base_dir):
    path = os.path.join(base_dir, "plurals.xml")
    if not os.path.isfile(path):
        return None, [f"base plurals missing: {path}"]
    try:
        groups, duplicate_groups, duplicate_quantities = parse_plurals(path)
    except ET.ParseError as exc:
        return None, [f"base XML parse error in {path}: {exc}"]
    errors = [f"base duplicate plural group '{name}'" for name in duplicate_groups]
    errors += [f"base duplicate quantity '{q}'" for q in duplicate_quantities]
    for name, items in groups.items():
        if "other" not in items:
            errors.append(f"base plural '{name}' has no 'other' quantity")
        if not items:
            errors.append(f"base plural '{name}' has no quantities")
    return groups, errors


def check_locale_plurals(base_groups, locale_dir):
    path = os.path.join(locale_dir, "plurals.xml")
    stats = {
        "groups": 0,
        "missing_groups": 0,
        "extra_groups": 0,
        "missing_quantities": 0,
        "extra_quantities": 0,
        "placeholders": 0,
        "empty": 0,
        "duplicates": 0,
        "xml_errors": 0,
    }
    failures = []
    if not os.path.isfile(path):
        stats["xml_errors"] += 1
        return ["missing file: " + path], stats
    try:
        groups, duplicate_groups, duplicate_quantities = parse_plurals(path)
    except ET.ParseError as exc:
        stats["xml_errors"] += 1
        return [f"XML parse error in {path}: {exc}"], stats

    stats["groups"] = len(groups)
    for name in duplicate_groups:
        stats["duplicates"] += 1
        failures.append(f"plurals.xml: duplicate plural group '{name}'")
    for entry in duplicate_quantities:
        stats["duplicates"] += 1
        failures.append(f"plurals.xml: duplicate quantity '{entry}'")

    for name, base_items in base_groups.items():
        if name not in groups:
            stats["missing_groups"] += 1
            failures.append(f"plurals.xml: missing plural group '{name}'")
            continue
        items = groups[name]
        for quantity in base_items:
            if quantity not in items:
                stats["missing_quantities"] += 1
                failures.append(
                    f"plurals.xml: '{name}' missing quantity '{quantity}'"
                )
        extra = [q for q in items if q not in base_items]
        for quantity in extra:
            if quantity not in VALID_QUANTITIES:
                stats["extra_quantities"] += 1
                failures.append(
                    f"plurals.xml: '{name}' has invalid quantity '{quantity}'"
                )
            else:
                stats["extra_quantities"] += 1
        for quantity, text in items.items():
            if not text.strip():
                stats["empty"] += 1
                failures.append(
                    f"plurals.xml: empty value for '{name}'/'{quantity}'"
                )
            reference = base_items.get(quantity, base_items.get("other"))
            if reference is None:
                continue
            base_ph = placeholders(reference)
            loc_ph = placeholders(text)
            if base_ph != loc_ph:
                stats["placeholders"] += 1
                failures.append(
                    f"plurals.xml: placeholder mismatch for '{name}'/'{quantity}': "
                    f"base {dict(base_ph)} != locale {dict(loc_ph)}"
                )

    for name in groups:
        if name not in base_groups:
            stats["extra_groups"] += 1
            failures.append(f"plurals.xml: extra plural group '{name}'")

    return failures, stats


def load_catalog_base(tsv_path):
    """Load the catalog TSV (message_ref, resource_key, german_text)."""
    rows = []
    errors = []
    try:
        with open(tsv_path, encoding="utf-8-sig") as fh:
            header = fh.readline().rstrip("\r\n").split("\t")
            if header[:3] != ["message_ref", "resource_key", "german_text"]:
                return [], [f"unexpected catalog TSV header: {header}"]
            for lineno, line in enumerate(fh, 2):
                line = line.rstrip("\r\n")
                if not line.strip():
                    continue
                parts = line.split("\t")
                if len(parts) != 3:
                    errors.append(f"{tsv_path}:{lineno}: expected 3 columns")
                    continue
                rows.append({"ref": parts[0], "key": parts[1], "german": parts[2]})
    except OSError as exc:
        return [], [f"cannot read catalog TSV {tsv_path}: {exc}"]
    keys = [row["key"] for row in rows]
    for key in sorted({key for key in keys if keys.count(key) > 1}):
        errors.append(f"catalog TSV duplicate resource_key '{key}'")
    refs = [row["ref"] for row in rows]
    for ref in sorted({ref for ref in refs if refs.count(ref) > 1}):
        errors.append(f"catalog TSV duplicate message_ref '{ref}'")
    for row in rows:
        if not row["german"].strip():
            errors.append(f"catalog TSV empty german_text for '{row['key']}'")
    return rows, errors


def check_catalog_locale(catalog_rows, locale_dir):
    """Validate <locale>/strings_catalog.xml against the catalog TSV."""
    filename = "strings_catalog.xml"
    path = os.path.join(locale_dir, filename)
    stats = {
        "keys": 0,
        "missing": 0,
        "extra": 0,
        "duplicates": 0,
        "placeholders": 0,
        "empty": 0,
        "xml_errors": 0,
    }
    failures = []
    if not os.path.isfile(path):
        stats["xml_errors"] += 1
        return ["missing file: " + path], stats
    try:
        values, duplicates = parse_strings(path)
    except ET.ParseError as exc:
        stats["xml_errors"] += 1
        return [f"XML parse error in {path}: {exc}"], stats

    stats["keys"] = len(values)
    for name in duplicates:
        stats["duplicates"] += 1
        failures.append(f"{filename}: duplicate key '{name}'")

    base = {row["key"]: row["german"] for row in catalog_rows}
    for key in base:
        if key not in values:
            stats["missing"] += 1
            failures.append(f"{filename}: missing key '{key}'")
    for key in values:
        if key not in base:
            stats["extra"] += 1
            failures.append(f"{filename}: extra key '{key}'")
    for key in base:
        if key not in values:
            continue
        if not values[key].strip():
            stats["empty"] += 1
            failures.append(f"{filename}: empty value for '{key}'")
        base_ph = Counter(CATALOG_PLACEHOLDER_RE.findall(base[key]))
        loc_ph = Counter(CATALOG_PLACEHOLDER_RE.findall(values[key]))
        if base_ph != loc_ph:
            stats["placeholders"] += 1
            failures.append(
                f"{filename}: placeholder mismatch for '{key}': "
                f"base {dict(base_ph)} != locale {dict(loc_ph)}"
            )
    stats["expected_keys"] = len(base)
    return failures, stats


def run_catalog_check(tsv_path, locales):
    """Validate catalog message resources in every locale directory."""
    print("GeDefense catalog translation check")
    print(f"  source:  {tsv_path}")
    print(f"  locales: {len(locales)}")
    print()
    rows, base_errors = load_catalog_base(tsv_path)
    if base_errors:
        for message in base_errors:
            print(f"  BASE FAIL {message}")
        print()
    print(f"Base catalog messages: {len(rows)} keys")
    print()
    total_failures = len(base_errors)
    for locale_dir in locales:
        failures, stats = check_catalog_locale(rows, locale_dir)
        total_failures += len(failures)
        status = "PASS" if not failures else "FAIL"
        print(f"{status} {locale_dir}")
        print(
            "  catalog: keys=%d (expected %d) missing=%d extra=%d "
            "duplicates=%d placeholder_mismatches=%d empty=%d xml_errors=%d"
            % (
                stats["keys"],
                stats.get("expected_keys", 0),
                stats["missing"],
                stats["extra"],
                stats["duplicates"],
                stats["placeholders"],
                stats["empty"],
                stats["xml_errors"],
            )
        )
        for message in failures:
            print(f"  FAIL {message}")
        print()
    if total_failures:
        print(f"RESULT: FAIL ({total_failures} problem(s))")
        return 1
    print(
        f"RESULT: PASS (0 problems, {len(locales)} locales, "
        f"{len(rows)} catalog keys each)"
    )
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check Android string translations against the base locale."
    )
    parser.add_argument(
        "--base",
        default=os.path.join("app", "src", "main", "res", "values"),
        help="base resource directory (default: app/src/main/res/values)",
    )
    parser.add_argument(
        "--locale",
        action="append",
        default=None,
        help="locale resource directory to check (repeatable)",
    )
    parser.add_argument(
        "--files",
        default=",".join(DEFAULT_FILES),
        help="comma-separated string resource file names",
    )
    parser.add_argument(
        "--include-plurals",
        action="store_true",
        help="also validate plurals.xml (key set, quantities, placeholders)",
    )
    parser.add_argument(
        "--catalog-tsv",
        default=None,
        help=(
            "validate <locale>/strings_catalog.xml against this catalog TSV "
            "(columns message_ref, resource_key, german_text) instead of the "
            "values/ string resources"
        ),
    )
    args = parser.parse_args(argv)

    files = [name.strip() for name in args.files.split(",") if name.strip()]
    locales = args.locale or [
        os.path.join("app", "src", "main", "res", name)
        for name in ("values-en", "values-de", "values-fr")
    ]

    if args.catalog_tsv:
        return run_catalog_check(args.catalog_tsv, locales)

    print("GeDefense translation check")
    print(f"  base:    {args.base}")
    print(f"  strings: {len(files)} files")
    print(f"  plurals: {'yes' if args.include_plurals else 'no'}")
    print(f"  locales: {len(locales)}")
    print()

    base, base_errors = load_base_strings(args.base, files)
    base_plural_groups = None
    if args.include_plurals:
        base_plural_groups, plural_errors = load_base_plurals(args.base)
        base_errors.extend(plural_errors)

    if base_errors:
        print("BASE ERRORS:")
        for message in base_errors:
            print(f"  FAIL {message}")
        print()
    print(f"Base strings: {len(base)} keys")
    if base_plural_groups is not None:
        print(f"Base plurals: {len(base_plural_groups)} groups")
    print()

    total_failures = len(base_errors)
    for locale_dir in locales:
        failures, stats = check_locale_strings(base, locale_dir, files)
        plural_failures = []
        plural_stats = None
        if base_plural_groups is not None:
            plural_failures, plural_stats = check_locale_plurals(
                base_plural_groups, locale_dir
            )
            failures = failures + plural_failures
        total_failures += len(failures)
        status = "PASS" if not failures else "FAIL"
        print(f"{status} {locale_dir}")
        print(
            "  strings: files=%d keys=%d (expected %d) missing=%d extra=%d "
            "duplicates=%d placeholder_mismatches=%d empty=%d xml_errors=%d"
            % (
                stats["files"],
                stats["keys"],
                stats["expected_keys"],
                stats["missing"],
                stats["extra"],
                stats["duplicates"],
                stats["placeholders"],
                stats["empty"],
                stats["xml_errors"],
            )
        )
        if plural_stats is not None:
            print(
                "  plurals: groups=%d (expected %d) missing_groups=%d "
                "extra_groups=%d missing_quantities=%d extra_quantities=%d "
                "duplicates=%d placeholder_mismatches=%d empty=%d xml_errors=%d"
                % (
                    plural_stats["groups"],
                    len(base_plural_groups),
                    plural_stats["missing_groups"],
                    plural_stats["extra_groups"],
                    plural_stats["missing_quantities"],
                    plural_stats["extra_quantities"],
                    plural_stats["duplicates"],
                    plural_stats["placeholders"],
                    plural_stats["empty"],
                    plural_stats["xml_errors"],
                )
            )
        for message in failures:
            print(f"  FAIL {message}")
        print()

    summary = f"{len(locales)} locales, {len(base)} string keys each"
    if base_plural_groups is not None:
        summary += f", {len(base_plural_groups)} plural groups each"
    if total_failures:
        print(f"RESULT: FAIL ({total_failures} problem(s))")
        return 1
    print(f"RESULT: PASS (0 problems, {summary})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
