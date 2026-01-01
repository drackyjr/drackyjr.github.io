import { BLOG_FILES } from "./docs/blogIndex.js";

/* ---------- Marked + Highlight ---------- */
marked.setOptions({
  highlight: (code, lang) => {
    const language = hljs.getLanguage(lang) ? lang : "plaintext";
    return hljs.highlight(code, { language }).value;
  },
  gfm: true,
  breaks: true
});

/* ---------- DOM ---------- */
const homepage = document.getElementById("homepage");
const blogViewer = document.getElementById("blog-viewer");
const blogList = document.getElementById("blog-list");
const blogTitle = document.getElementById("blog-title");
const blogContent = document.getElementById("blog-content");
const backButton = document.getElementById("back-button");
const searchToggle = document.getElementById("search-toggle");
const blogSearch = document.getElementById("blog-search");

/* ---------- State ---------- */
let allBlogData = [];
let isLoaded = false;

/* ---------- Frontmatter ---------- */
function parseFrontmatter(text) {
  const match = /^---\s*([\s\S]*?)\s*---/.exec(text);
  const meta = {};
  let content = text;

  if (match) {
    match[1].split("\n").forEach(line => {
      const [k, ...v] = line.split(":");
      if (k && v.length) {
        let value = v.join(":").trim();
        if (k.trim() === "tags") {
          value = value.replace(/[\[\]]/g, "").split(",").map(t => t.trim());
        }
        meta[k.trim()] = value;
      }
    });
    content = text.slice(match[0].length).trim();
  }
  return { meta, content };
}

/* ---------- Cards ---------- */
function renderCards(data) {
  blogList.innerHTML = "";

  if (!data.length) {
    blogList.innerHTML = `<p class="page-title">No matches found.</p>`;
    return;
  }

  data.forEach((b, i) => {
    const card = document.createElement("div");
    card.className = "blog-card";
    card.dataset.slug = b.slug;
    card.dataset.milestone = data.length - i;

    card.innerHTML = `
      <div class="card-cover">
        <img src="${b.cover}" onerror="this.src='assets/background.gif'">
      </div>
      <div class="card-content">
        <p class="date">${b.date}</p>
        <h2>${b.title}</h2>
        <p>${b.description}</p>
        <div class="tags">${b.tags.map(t => `<span class="tag">${t}</span>`).join("")}</div>
      </div>
    `;

    card.onclick = () => navigateToBlog(b.slug);
    blogList.appendChild(card);
  });
}

/* ---------- Load Blogs (SAFE) ---------- */
async function loadBlogs() {
  allBlogData = [];

  for (const file of BLOG_FILES) {
    const slug = file.replace(".md", "");
    const res = await fetch(`./docs/${file}`);
    if (!res.ok) continue;

    const { meta } = parseFrontmatter(await res.text());

    allBlogData.push({
      slug,
      title: meta.title || slug.replace(/[-_]/g, " "),
      date: meta.date || "Unknown Date",
      description: meta.description || "No description available.",
      tags: meta.tags || [],
      cover: meta.cover || `./docs/${slug}.png`
    });
  }

  allBlogData.sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0));
  renderCards(allBlogData);
  isLoaded = true;
}

/* ---------- Viewer ---------- */
async function loadMarkdown(slug) {
  if (!isLoaded) await loadBlogs();
  const res = await fetch(`./docs/${slug}.md`);
  const { meta, content } = parseFrontmatter(await res.text());

  blogTitle.textContent = meta.title || slug;
  blogContent.innerHTML = marked.parse(content);
  blogContent.querySelectorAll("pre code").forEach(el => hljs.highlightElement(el));
  switchView("viewer");
}

/* ---------- Navigation ---------- */
function switchView(v) {
  homepage.classList.toggle("hidden", v === "viewer");
  blogViewer.classList.toggle("hidden", v !== "viewer");
}

function navigateToBlog(slug) {
  history.pushState({ slug }, "", `#/blogs/${slug}`);
  loadMarkdown(slug);
}

function navigateToHomepage() {
  history.pushState({}, "", "#/");
  switchView("homepage");
}

/* ---------- Search ---------- */
searchToggle.onclick = () => {
  blogSearch.classList.toggle("hidden");
  blogSearch.focus();
};

blogSearch.oninput = e => {
  const q = e.target.value.toLowerCase();
  renderCards(
    !q ? allBlogData :
    allBlogData.filter(b =>
      b.title.toLowerCase().includes(q) ||
      b.description.toLowerCase().includes(q) ||
      b.tags.some(t => t.toLowerCase().includes(q))
    )
  );
};

/* ---------- Init ---------- */
window.onpopstate = e => e.state?.slug ? loadMarkdown(e.state.slug) : switchView("homepage");
backButton.onclick = navigateToHomepage;

document.addEventListener("DOMContentLoaded", () => {
  location.hash.startsWith("#/blogs/")
    ? loadMarkdown(location.hash.split("#/blogs/")[1])
    : loadBlogs();
});
