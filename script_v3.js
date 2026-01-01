// ================================
// Imports
// ================================
import { BLOG_FILES } from "./docs/blogIndex.js";

// ================================
// Marked + Highlight setup
// ================================
marked.setOptions({
    renderer: new marked.Renderer(),
    highlight: function (code, lang) {
        const language = hljs.getLanguage(lang) ? lang : "plaintext";
        return hljs.highlight(code, { language }).value;
    },
    langPrefix: "hljs language-",
    gfm: true,
    breaks: true,
});

// ================================
// DOM references
// ================================
const homepage = document.getElementById("homepage");
const blogViewer = document.getElementById("blog-viewer");
const blogList = document.getElementById("blog-list");
const blogTitle = document.getElementById("blog-title");
const blogContent = document.getElementById("blog-content");
const backButton = document.getElementById("back-button");
const searchToggle = document.getElementById("search-toggle");
const blogSearch = document.getElementById("blog-search");

// ================================
// State
// ================================
let allBlogData = [];
let isLoaded = false;

// ================================
// Front-matter parser
// ================================
function parseFrontmatter(text) {
    const regex = /^---\s*([\s\S]*?)\s*---/;
    const match = regex.exec(text);
    const result = { metadata: {}, content: text };

    if (match) {
        const lines = match[1].split("\n");
        lines.forEach(line => {
            const [key, ...valueParts] = line.split(":");
            if (key && valueParts.length) {
                let value = valueParts.join(":").trim();
                if (key.trim() === "tags") {
                    value = value.replace(/[\[\]]/g, "")
                        .split(",")
                        .map(t => t.trim());
                }
                result.metadata[key.trim()] = value;
            }
        });
        result.content = text.substring(match[0].length).trim();
    }
    return result;
}

// ================================
// Render homepage cards
// ================================
function renderCards(data) {
    blogList.innerHTML = "";

    if (data.length === 0) {
        blogList.innerHTML =
            `<p class="page-title" style="text-align:center;width:100%;">No matches found.</p>`;
        return;
    }

    data.forEach((blog, index) => {
        const card = document.createElement("div");
        card.className = "blog-card";
        card.dataset.slug = blog.slug;
        card.dataset.milestone = data.length - index;

        const tagsHtml = blog.tags.map(
            tag => `<span class="tag">${tag}</span>`
        ).join("");

        card.innerHTML = `
            <div class="card-cover">
                <img src="${blog.cover}" alt="${blog.title}" onerror="this.src='assets/background.gif'">
            </div>
            <div class="card-content">
                <p class="date">${blog.date}</p>
                <h2>${blog.title}</h2>
                <p>${blog.description}</p>
                <div class="tags">${tagsHtml}</div>
            </div>
        `;

        card.addEventListener("click", () => navigateToBlog(blog.slug));
        blogList.appendChild(card);
    });
}

// ================================
// Load blogs (GitHub Pages SAFE)
// ================================
async function loadBlogs() {
    allBlogData = [];

    for (const file of BLOG_FILES) {
        try {
            const slug = file.replace(".md", "");
            const res = await fetch(`./docs/${file}`);
            if (!res.ok) continue;

            const raw = await res.text();
            const parsed = parseFrontmatter(raw);
            const meta = parsed.metadata;

            allBlogData.push({
                slug,
                isFolder: false,
                title: meta.title || slug.replace(/[-_]/g, " "),
                date: meta.date || "Unknown Date",
                description: meta.description || "No description available.",
                tags: Array.isArray(meta.tags) ? meta.tags : [],
                cover: meta.cover || `./docs/${slug}.png`
            });
        } catch {}
    }

    allBlogData.sort((a, b) =>
        new Date(b.date || 0) - new Date(a.date || 0)
    );

    renderCards(allBlogData);
    isLoaded = true;
}

// ================================
// Search
// ================================
searchToggle.addEventListener("click", () => {
    blogSearch.classList.toggle("active");
    blogSearch.classList.toggle("hidden");

    if (blogSearch.classList.contains("active")) {
        blogSearch.focus();
    } else {
        blogSearch.value = "";
        renderCards(allBlogData);
    }
});

blogSearch.addEventListener("input", e => {
    const query = e.target.value.toLowerCase();
    if (!query) {
        renderCards(allBlogData);
        return;
    }

    const filtered = allBlogData.filter(post =>
        post.title.toLowerCase().includes(query) ||
        post.description.toLowerCase().includes(query) ||
        post.tags.some(tag => tag.toLowerCase().includes(query))
    );

    renderCards(filtered);
});

// ================================
// Video embeds
// ================================
function processVideoLinks(content) {
    const yt = /(?:youtube\.com\/watch\?v=|youtu\.be\/)([a-zA-Z0-9_-]{11})/;
    return content.replace(yt, (_, id) =>
        `<div class="video-container">
            <iframe src="https://www.youtube.com/embed/${id}" allowfullscreen></iframe>
        </div>`
    );
}

// ================================
// Load single blog
// ================================
async function loadMarkdown(slug) {
    try {
        if (!isLoaded) await loadBlogs();

        const response = await fetch(`./docs/${slug}.md`);
        const rawText = await response.text();
        const processed = parseFrontmatter(rawText);

        let html = marked.parse(processed.content);
        html = html.replace(/src="(?!https?:\/\/)([^"]+)"/g, `src="./docs/$1"`);
        html = processVideoLinks(html);

        blogTitle.textContent = processed.metadata.title || slug;
        blogContent.innerHTML = html;
        blogContent.querySelectorAll("pre code")
            .forEach(block => hljs.highlightElement(block));

        switchView("viewer");
    } catch {
        switchView("viewer");
    }
}

// ================================
// Navigation
// ================================
function switchView(view) {
    if (view === "homepage") {
        blogViewer.classList.add("hidden");
        homepage.classList.remove("hidden");
    } else {
        homepage.classList.add("hidden");
        blogViewer.classList.remove("hidden");
        window.scrollTo(0, 0);
    }
}

function navigateToBlog(slug) {
    history.pushState({ slug }, "", `#/blogs/${slug}`);
    loadMarkdown(slug);
}

function navigateToHomepage() {
    history.pushState({}, "", "#/");
    switchView("homepage");
}

window.addEventListener("popstate", e =>
    e.state?.slug ? loadMarkdown(e.state.slug) : switchView("homepage")
);

// ================================
// Initial route
// ================================
function handleInitialRoute() {
    const path = window.location.hash;
    if (path.startsWith("#/blogs/")) {
        loadMarkdown(path.split("#/blogs/")[1]);
    } else {
        loadBlogs();
        switchView("homepage");
    }
}

backButton.addEventListener("click", navigateToHomepage);
document.querySelector(".logo")
    .addEventListener("click", e => {
        e.preventDefault();
        navigateToHomepage();
    });

document.addEventListener("DOMContentLoaded", handleInitialRoute);
