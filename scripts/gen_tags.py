#!/usr/bin/env python3
"""Regenerate tags/<name>.md files from _posts front matter.

Each tag page lists the posts carrying that tag, deep-linked to the most
relevant section when a post declares an anchor. Two front-matter keys drive
this (both optional):

    tags: [windows-ad, dll-hijacking, ...]

    tag_anchors:                      # optional; tag -> in-post anchor
      dll-hijacking: "#46-exploitation--dll-hijacking"

Anchors may be written with or without quotes; a leading '#' is optional.
If a tag has no anchor for a given post, the link goes to the post root.

Run from the blog repo root:  python3 scripts/gen_tags.py
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POSTS = os.path.join(ROOT, "_posts")
TAGS_DIR = os.path.join(ROOT, "tags")

FM_RE = re.compile(r"^---\n(.*?)\n---", re.DOTALL)
TAGS_RE = re.compile(r"^tags:\s*\[(.*?)\]\s*$", re.MULTILINE)
ANCHORS_RE = re.compile(r"^tag_anchors:\n((?:[ \t]+.*\n?)+)", re.MULTILINE)
PAIR_RE = re.compile(r"^[ \t]+([\w-]+):\s*['\"]?([^'\"\s]+)['\"]?\s*$", re.MULTILINE)


def parse_post(path):
    """Return {tags, anchors, url, title} or None if not a tagged post."""
    text = open(path, encoding="utf-8").read()
    m = FM_RE.match(text)
    if not m:
        return None
    fm = m.group(1)

    tm = TAGS_RE.search(fm)
    if not tm:
        return None
    tags = [t.strip() for t in tm.group(1).split(",") if t.strip()]

    anchors = {}
    am = ANCHORS_RE.search(fm)
    if am:
        for tag, anchor in PAIR_RE.findall(am.group(1)):
            anchors[tag] = anchor if anchor.startswith("#") else "#" + anchor

    fn = os.path.basename(path)
    slug = re.sub(r"^\d{4}-\d{2}-\d{2}-", "", fn[:-3])
    cm = re.search(r"^categories:\s*\[(.*?)\]", fm, re.MULTILINE)
    cat = (cm.group(1) if cm else "uncategorized").split(",")[0].strip().lower()
    tm_title = re.search(r'^title:\s*"(.*?)"\s*$', fm, re.MULTILINE)
    title = tm_title.group(1) if tm_title else slug

    return {"tags": tags, "anchors": anchors, "url": f"/{cat}/{slug}/", "title": title}


def yaml_str(value):
    """Quote a YAML scalar if it contains characters that need it."""
    return f'"{value}"' if (":" in value or value.startswith("#") or "#" in value) else value


def main():
    posts = []
    for fn in sorted(os.listdir(POSTS)):
        if fn.endswith(".md"):
            p = parse_post(os.path.join(POSTS, fn))
            if p:
                posts.append(p)

    if not posts:
        print("No tagged posts found — nothing to do.")
        return

    # tag -> list of {title, url}
    tag_map = {}
    for p in posts:
        for t in p["tags"]:
            url = p["url"] + p["anchors"].get(t, "")
            tag_map.setdefault(t, []).append({"title": p["title"], "url": url})

    os.makedirs(TAGS_DIR, exist_ok=True)

    # Remove stale generated files (keep tags/index.html and any hand-made extras)
    removed = 0
    for fn in os.listdir(TAGS_DIR):
        if fn.endswith(".md"):
            os.remove(os.path.join(TAGS_DIR, fn))
            removed += 1

    for tag in sorted(tag_map):
        lines = ["---", "layout: tag", f"tag: {tag}", "posts:"]
        for e in tag_map[tag]:
            lines.append(f"  - title: {yaml_str(e['title'])}")
            lines.append(f"    url: {yaml_str(e['url'])}")
        lines.append(f"permalink: /tags/{tag.lower()}/")
        lines.append("---")
        path = os.path.join(TAGS_DIR, f"{tag.lower()}.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    print(f"{len(tag_map)} tag pages written to {TAGS_DIR}/ "
          f"({removed} stale removed, {sum(len(v) for v in tag_map.values())} post links, "
          f"{sum(1 for v in tag_map.values() for e in v if '#' in e['url'])} deep-linked)")
    print("Tip: add tag_anchors to a post's front matter to deep-link a tag to a section:")
    print('  tag_anchors:')
    print('    dll-hijacking: "#46-exploitation--dll-hijacking"')


if __name__ == "__main__":
    sys.exit(main())
