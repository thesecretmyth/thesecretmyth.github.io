# frozen_string_literal: true

require 'liquid'

# Jekyll tag: {% terminal "title" %} ... {% endterminal %}
# Wraps the block content in a styled terminal window with CRT scanlines.
#
# Usage:
#   {% terminal "root@syrax:~#" %}
#   ```bash
#   ls -la /tmp/
#   ```
#   {% endterminal %}
#
# With no title argument, the prompt defaults to "➜ " (oh-my-zsh style):
#   {% terminal %}
#   ```bash
#   nmap -sC -sV target
#   ```
#   {% endterminal %}
#
module Jekyll
  class TerminalBlock < Liquid::Block
    def initialize(tag_name, title, tokens)
      super
      @title = title.strip.gsub(/^["']|["']$/, '')
    end

    def render(context)
      # Liquid 4.x stores parsed block content in +nodelist+, not +@tokens+.
      inner = Liquid::Template.parse(nodelist.join).render(context)
      title = @title.empty? ? '➜ ' : @title

      <<~HTML
        <div class="terminal">
          <div class="terminal-bar">
            <span class="terminal-dot red"></span>
            <span class="terminal-dot yellow"></span>
            <span class="terminal-dot green"></span>
            <span class="terminal-title">#{title}</span>
          </div>
          <div class="terminal-body">
            #{inner}
          </div>
        </div>
      HTML
    end
  end
end

Liquid::Template.register_tag('terminal', Jekyll::TerminalBlock)
