# frozen_string_literal: true

require 'nokogiri'
require 'find'

# Post-process: wrap every fenced code block (Rouge emits
# <div class="language-* highlighter-rouge">) in terminal chrome.
#
# Jekyll 4.x fires :post_write after the site is fully written to dest,
# so the method below walks dest and rewrites each .html file from disk.
# Walking dest (instead of site.pages) guarantees we catch posts, pages,
# and collection/tag pages alike — site.pages excludes _posts entirely.
#
module Jekyll
  Jekyll::Hooks.register :site, :post_write do |site|
    dest = site.dest
    next unless dest && File.directory?(dest)

    Find.find(dest) do |path|
      next unless path.end_with?('.html')
      next if File.directory?(path)

      html = File.read(path)
      next if html.nil? || html.empty?

      doc = Nokogiri::HTML5(html)
      changed = false

      doc.css('div[class^="language-"]').each do |block|
        next if block.ancestors('div.terminal').any?

        lang = block['class'].to_s
                          .split
                          .find { |c| c.start_with?('language-') }
                          .to_s
                          .sub('language-', '')
        title = lang.empty? ? '➜ ' : lang

        wrap = Nokogiri::HTML.fragment(<<~HTML).at_css('div.terminal')
          <div class="terminal">
            <div class="terminal-bar">
              <span class="terminal-dot red"></span>
              <span class="terminal-dot yellow"></span>
              <span class="terminal-dot green"></span>
              <span class="terminal-title">#{title}</span>
            </div>
            <div class="terminal-body"></div>
          </div>
        HTML

        block.add_previous_sibling(wrap)
        wrap.at_css('div.terminal-body').add_child(block.remove)
        changed = true
      end

      File.write(path, doc.to_html) if changed
    end
  end
end
