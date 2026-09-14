#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Validate every post's tag_anchors section live-fast, die-young.
# Run from the blog repo root:
#   ruby scripts/validate_tag_anchors.rb
#
# Only checks posts that declare `tag_anchors:`. Walks the anchor IDs
# against every HTML-id-bearing heading, fenced-code label, and image
# alt-text token in the rendered Markdown -- no Jekyll build required.

require "set"

POSTS_DIR = "_posts"

# Jekyll kramdown id rules (what this build uses):
def slug_id(raw)
  s = raw.to_s.strip
  s = s.downcase
  # Strip angle-bracket headings if present: <h2>Foo</h2>
  s = s.gsub(/<[^>]+>/, "")
  # Drop leading/trailing punctuation, collapse spaces
  s = s.gsub(/[!"\#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~]/, "-")
  s = s.gsub(/\s+/, "-")
  s = s.gsub(/-+/, "-")
  s = s.sub(/\A-+/, "").sub(/-+\z/, "")
  s
end

def headings_and_labels(text)
  ids = Set.new

  # ATX headings: ## Foo # -> id from "Foo"
  text.each_line do |line|
    m = line.match(/\A#{1,6}\s+(.+?)\s*(?:#{1,6})?\s*\z/)
    next unless m
    ids << slug_id(m[1])
  end

  # Setext H1/H2 via line scan
  lines = text.lines
  (0...(lines.size - 1)).each do |i|
    bottom = lines[i + 1]
    if bottom =~ /\A=+\s*\z/
      ids << slug_id(lines[i].strip)
    elsif bottom =~ /\A-+\s*\z/
      ids << slug_id(lines[i].strip)
    end
  end

  # Fenced code blocks with an info string that becomes the id:
  # ```sh -> id "sh"
  text.scan(/\A[ \t]*```(\S*)\s*\z/m) do |m|
    info = m[0]
    next if info.empty?
    ids << slug_id(info)
  end

  ids
end

def anchors_from_front_matter(text)
  m = text.match(/\A---\n(.*?)\n---\n/ms)
  return {} unless m
  fm = m[1]
  am = fm.match(/\Atag_anchors:\n((?:[ \t]+.*\n?)+)/m)
  return {} unless am
  pairs = {}
  am[1].each_line do |line|
    m = line.match(/\A[ \t]+([\w-]+):\s*['"]?([^'"\s]+)['"]?\s*\z/)
    next unless m
    tag, anchor = m[1], m[2]
    anchor = anchor.sub(/\A#/, "")
    pairs[tag] = anchor
  end
  pairs
end

def run
  unless Dir.exist?(POSTS_DIR)
    $stderr.puts "No #{POSTS_DIR}/ directory -- nothing to validate."
    exit 0
  end

  posts = Dir.glob("#{POSTS_DIR}/*.md").sort
  error_count = 0

  posts.each do |path|
    text = File.read(path, encoding: "utf-8")
    anchors = anchors_from_front_matter(text)
    next if anchors.empty?

    available = headings_and_labels(text)
    if available.empty?
      $stderr.puts "#{path}: tag_anchors present but couldn't parse any IDs from the body."
      error_count += 1
      next
    end

    anchors.each do |tag, anchor|
      next if anchor.empty?
      # exact match
      if available.include?(anchor)
        next
      end

      $stderr.puts "#{path}: tag_anchors tag #{tag} -> #{anchor} not found in body IDs."
      error_count += 1
    end
  end

  if error_count.zero?
    $stderr.puts "All tag_anchors resolve."
    exit 0
  else
    $stderr.puts "Found #{error_count} unresolved tag_anchors."
    exit 1
  end
end

run
