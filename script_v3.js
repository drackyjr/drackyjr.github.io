// Initialize Marked.js and Highlight.js

import { BLOG_FILES } from "./docs/blogIndex.js";

BLOG_FILES.forEach(file => {
    fetch(`./docs/${file}`)
        .then(res => res.text())
        .then(md => {
            renderMarkdown(md, file);
        })
        .catch(err => console.error(err));
});

marked.setOptions({
    renderer: new marked.Renderer(),
    highlight: function (code, lang) {
        const language = hljs.getLanguage(lang) ? lang : 'plaintext';
        return hljs.highlight(code, { language }).value;
    },
    langPrefix: 'hljs language-',
    gfm: true,
    breaks: true,
});

const homepage = document.getElementById('homepage');
const blogViewer = document.getElementById('blog-viewer');
const blogList = document.getElementById('blog-list');
const blogTitle = document.getElementById('blog-title');
const blogContent = document.getElementById('blog-content');
const backButton = document.getElementById('back-button');
const searchToggle = document.getElementById('search-toggle');
const blogSearch = document.getElementById('blog-search');

let allBlogData = [];
let isLoaded = false;

function parseFrontmatter(text) {
    const regex = /^---\s*([\s\S]*?)\s*---/;
    const match = regex.exec(text);
    const result = { metadata: {}, content: text };
    if (match) {
        const lines = match[1].split('\n');
        lines.forEach(line => {
            const [key, ...valueParts] = line.split(':');
            if (key && valueParts.length) {
                let value = valueParts.join(':').trim();
                if (key.trim() === 'tags') {
                    value = value.replace(/[\[\]]/g, '').split(',').map(t => t.trim());
                }
                result.metadata[key.trim()] = value;
            }
        });
        result.content = text.substring(match[0].length).trim();
    }
    return result;
}

function renderCards(data) {
    blogList.innerHTML = '';
    if (data.length === 0) {
        blogList.innerHTML = `<p class="page-title" style="text-align: center; width: 100%;">No matches found.</p>`;
        return;
    }

    data.forEach((blog, index) => {
        const card = document.createElement('div');
        card.className = 'blog-card';
        card.setAttribute('data-slug', blog.slug);
        // Milestone Descending: Total down to 1
        card.setAttribute('data-milestone', data.length - index);
        const tagsHtml = blog.tags.map(tag => `<span class="tag">${tag}</span>`).join('');
        card.innerHTML = `
            <div class="card-cover">
                <img src="${blog.cover}" alt="${blog.title} Cover" onerror="this.src='assets/background.gif'">
            </div>
            <div class="card-content">
                <p class="date">${blog.date}</p>
                <h2>${blog.title}</h2>
                <p>${blog.description}</p>
                <div class="tags">${tagsHtml}</div>
            </div>
        `;
        blogList.appendChild(card);
        card.addEventListener('click', () => navigateToBlog(blog.slug));
    });
}

async function loadBlogs() {
    try {
        const response = await fetch('./docs/');
        const html = await response.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');

        let links = Array.from(doc.querySelectorAll('a'))
            .map(a => a.getAttribute('href'))
            .filter(href => href && !href.startsWith('..') && !href.includes('writeups.json'));

        allBlogData = [];
        for (let href of links) {
            // Robust Path Handling: Remove leading/trailing slashes/backslashes and the 'docs' prefix
            let cleanName = href.replace(/^[\\\/]docs[\\\/]/, '')
                .replace(/^[\\\/]/, '')
                .replace(/[\\\/]$/, '');

            if (!cleanName || cleanName === 'docs' || cleanName.includes('index.html')) continue;

            let slug, fetchUrl, coverUrl, isFolder;

            if (cleanName.endsWith('.md')) {
                slug = cleanName.replace('.md', '');
                fetchUrl = `./docs/${cleanName.replace(/\\/g, '/')}`;
                coverUrl = `./docs/${slug.replace(/\\/g, '/')}.png`;
                isFolder = false;
            } else if (!cleanName.includes('.')) {
                slug = cleanName;
                fetchUrl = `./docs/${slug}/index.md`.replace(/\\/g, '/');
                coverUrl = `./docs/${slug}/images/logo.png`.replace(/\\/g, '/');
                isFolder = true;
            } else continue;

            try {
                const postResponse = await fetch(fetchUrl);
                if (!postResponse.ok) continue;
                const text = await postResponse.text();
                const processed = parseFrontmatter(text);
                const meta = processed.metadata;
                allBlogData.push({
                    slug: slug.replace(/\\/g, '/'),
                    isFolder: isFolder,
                    title: meta.title || slug.replace(/_/g, ' ').replace(/-/g, ' '),
                    date: meta.date || 'Unknown Date',
                    description: meta.description || 'No description available.',
                    tags: Array.isArray(meta.tags) ? meta.tags : [],
                    cover: meta.cover || coverUrl
                });
            } catch (err) { }
        }

        // Sorting: Newer First (Recent blogs at the top)
        allBlogData.sort((a, b) => {
            const dateA = a.date === 'Unknown Date' ? new Date('1970-01-01') : new Date(a.date);
            const dateB = b.date === 'Unknown Date' ? new Date('1970-01-01') : new Date(b.date);
            return dateB - dateA;
        });

        renderCards(allBlogData);
        isLoaded = true;
    } catch (error) {
        console.error("Error loading blogs:", error);
        blogList.innerHTML = `<p style="color:red;">Failed to auto-detect blogs.</p>`;
    }
}

searchToggle.addEventListener('click', () => {
    blogSearch.classList.toggle('active');
    blogSearch.classList.toggle('hidden');
    if (blogSearch.classList.contains('active')) {
        blogSearch.focus();
    } else {
        blogSearch.value = '';
        renderCards(allBlogData);
    }
});

blogSearch.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase();
    const filtered = allBlogData.filter(post =>
        post.title.toLowerCase().includes(query) ||
        post.description.toLowerCase().includes(query) ||
        post.tags.some(tag => tag.toLowerCase().includes(query))
    );
    renderCards(filtered);
});

function processVideoLinks(content) {
    const ytIdRegex = /(?:https?:\/\/)?(?:www\.)?(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/)([a-zA-Z0-9_-]{11})/;
    return content.replace(/<img[^>]+src="([^"]+)"[^>]*>/g, (match, src) => {
        const ytMatch = src.match(ytIdRegex);
        return ytMatch ? `<div class="video-container"><iframe src="https://www.youtube.com/embed/${ytMatch[1]}" frameborder="0" allowfullscreen></iframe></div>` : match;
    }).replace(/<a[^>]+href="([^"]+)"[^>]*>(.*?)<\/a>|(?<!src="|href=")(https?:\/\/(?:www\.)?(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/)[a-zA-Z0-9_-]{11})/g, (match, href, text, plainUrl) => {
        const url = href || plainUrl;
        const ytMatch = url.match(ytIdRegex);
        return ytMatch ? `<div class="video-container"><iframe src="https://www.youtube.com/embed/${ytMatch[1]}" frameborder="0" allowfullscreen></iframe></div>` : match;
    });
}

async function loadMarkdown(slug) {
    try {
        if (!isLoaded) await loadBlogs();
        const blogInfo = allBlogData.find(b => b.slug === slug);
        const fetchUrl = blogInfo && !blogInfo.isFolder ? `./docs/${slug}.md` : `./docs/${slug}/index.md`;
        const response = await fetch(fetchUrl);
        const rawText = await response.text();
        const processed = parseFrontmatter(rawText);
        const htmlContent = marked.parse(processed.content);
        let finalContent = blogInfo && !blogInfo.isFolder ? htmlContent.replace(/src="(?!https?:\/\/)([^"]+)"/g, `src="./docs/$1"`) : htmlContent.replace(/src="(?!https?:\/\/)([^"]+)"/g, `src="./docs/${slug}/$1"`);
        finalContent = processVideoLinks(finalContent);
        blogTitle.textContent = processed.metadata.title || slug;
        blogContent.innerHTML = finalContent;
        blogContent.querySelectorAll('pre code').forEach((block) => hljs.highlightElement(block));
        switchView('viewer');
    } catch (error) {
        switchView('viewer');
    }
}

function switchView(view) {
    if (view === 'homepage') {
        blogViewer.classList.add('fade-out');
        setTimeout(() => {
            blogViewer.classList.add('hidden');
            blogViewer.classList.remove('fade-out');
            homepage.classList.remove('hidden');
            homepage.classList.add('fade-in');
        }, 500);
    } else {
        homepage.classList.add('fade-out');
        setTimeout(() => {
            homepage.classList.add('hidden');
            homepage.classList.remove('fade-out');
            blogViewer.classList.remove('hidden');
            blogViewer.classList.add('fade-in');
            window.scrollTo(0, 0);
        }, 500);
    }
}

function navigateToBlog(slug) {
    history.pushState({ slug: slug }, '', `#/blogs/${slug}`);
    loadMarkdown(slug);
}

function navigateToHomepage() {
    history.pushState({}, '', '#/');
    switchView('homepage');
}

window.addEventListener('popstate', (e) => e.state && e.state.slug ? loadMarkdown(e.state.slug) : switchView('homepage'));

function handleInitialRoute() {
    const path = window.location.hash;
    if (path.startsWith('#/blogs/')) loadMarkdown(path.split('#/blogs/')[1]);
    else { loadBlogs(); switchView('homepage'); }
}

backButton.addEventListener('click', navigateToHomepage);
document.querySelector('.logo').addEventListener('click', (e) => { e.preventDefault(); navigateToHomepage(); });
document.addEventListener('DOMContentLoaded', handleInitialRoute);
