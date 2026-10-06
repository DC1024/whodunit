# The landing page

`index.html` here is the whole site: one file, inline CSS and JS, no external
requests, no build step. It works opened straight from disk, and it works from
any static host.

It is published in two places:

| Where | URL |
|---|---|
| GitHub Pages | <https://dc1024.github.io/whodunit/> |
| WorkBuddy | <https://whodunit.app.workbuddy.host/> |

## Updating GitHub Pages

Pages serves the `gh-pages` branch. That branch was cut from `main`, so it also
carries the Go sources — harmless, but it means the branch is not "just the
site". Only two files on it matter:

- `index.html` — a copy of this directory's `index.html`
- `.nojekyll` — empty, present so GitHub does not run the page through Jekyll

To publish a change, copy the file across and push:

```bash
git checkout gh-pages
cp site/index.html index.html
git add index.html && git commit -m "Update the landing page"
git push origin gh-pages
git checkout main
```

If `git push` is not usable (the machine this was authored on has `github.com`
pinned to 127.0.0.1 in its hosts file), the same thing can be done through the
API instead — create the file on the `gh-pages` branch with
`PUT /repos/DC1024/whodunit/contents/index.html` and a base64 `content`, then
`POST /repos/DC1024/whodunit/pages/builds` to rebuild. Check the result with
`GET /repos/DC1024/whodunit/pages`; `status: built` means it is live.

## Keeping the copy honest

The page quotes a real report and links a real release. If the demo output or
the version number changes, the page is lying until it is updated. CI does not
check this — it only checks the CLI. So: after cutting a release, update the
version in the download links and in the `hero.cta` string, in **both**
languages in the `DICT` object at the bottom of `index.html`.
