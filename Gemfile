source "https://rubygems.org"

# Jekyll 4.x — matches the engine Cloudflare Pages (and local) will build with.
gem "jekyll", "~> 4.4"

# Plugins required by _plugins/*.rb (custom terminal windows).
# These are NOT on GitHub Pages' whitelist, which is the reason to move to CF.
gem "nokogiri"
gem "liquid"

# Default Jekyll stack (kept explicit so the lockfile is complete).
group :jekyll_plugins do
  gem "jekyll-sass-converter", "~> 3.0"
  gem "kramdown"
  gem "kramdown-parser-gfm"
  gem "rouge"
  gem "webrick"
end
