// Initialize Marked.js and Highlight.js
marked.setOptions({
    renderer: new marked.Renderer(),
    highlight: function(code, lang) {
        const language = hljs.getLanguage(lang) ? lang : 'plaintext';
        return hljs.highlight(code, { language }).value;
    },
    langPrefix: 'hljs language-', // prefix for autodetected languages
    gfm: true, // Use GitHub flavored markdown
    breaks: true, // Allow GFM line breaks
});

const homepage = document.getElementById('homepage');
const writeupViewer = document.getElementById('writeup-viewer');
const writeupList = document.getElementById('writeup-list');
const writeupTitle = document.getElementById('writeup-title');
const writeupContent = document.getElementById('writeup-content');
const backButton = document.getElementById('back-button');

// Function to fetch and display writeup cards
async function loadWriteups() {
    try {
        const response = await fetch('/docs/writeups.json');
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const writeups = await response.json();

        writeupList.innerHTML = ''; // Clear existing cards
        writeups.forEach(writeup => {
            const card = document.createElement('div');
            card.className = 'writeup-card';
            card.setAttribute('data-slug', writeup.slug);

            const tagsHtml = writeup.tags.map(tag => `<span class="tag">${tag}</span>`).join('');

            card.innerHTML = `
                <h2>${writeup.title}</h2>
                <p>${writeup.description}</p>
                <div class="tags">${tagsHtml}</div>
                <a href="#/writeups/${writeup.slug}" class="read-more">Read More</a>
            `;
            writeupList.appendChild(card);

            // Add event listener to the card (not the button, for whole card click)
            card.addEventListener('click', (event) => {
                // Prevent navigating if the click was specifically on the "Read More" button itself
                if (!event.target.classList.contains('read-more')) {
                    navigateToWriteup(writeup.slug);
                }
            });
        });
    } catch (error) {
        console.error("Error loading writeups:", error);
        writeupList.innerHTML = `<p style="color:red;">Failed to load writeups. Please check the 'docs/writeups.json' file and network.</p>`;
    }
}

// Function to fetch and render a specific Markdown file
async function loadMarkdown(slug) {
    try {
        const response = await fetch(`/docs/${slug}/index.md`);
        if (!response.ok) {
            if (response.status === 404) {
                throw new Error(`Writeup '${slug}' not found.`);
            }
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const markdown = await response.text();

        // Basic frontmatter parsing (if not using writeups.json for title)
        let titleMatch = markdown.match(/^title:\s*(.*)/m);
        let title = titleMatch ? titleMatch[1].trim() : slug; // Default to slug if no title in frontmatter

        // Use the title from writeups.json if available and more robust
        const writeupsResponse = await fetch('/docs/writeups.json');
        if (writeupsResponse.ok) {
            const writeupsData = await writeupsResponse.json();
            const matchingWriteup = writeupsData.find(w => w.slug === slug);
            if (matchingWriteup && matchingWriteup.title) {
                title = matchingWriteup.title;
            }
        }

        // Render Markdown to HTML
        const htmlContent = marked.parse(markdown);

        // Pre-process images to fix paths
        const imagePathFixedContent = htmlContent.replace(/src="(?!https?:\/\/)([^"]+)"/g, `src="/docs/${slug}/$1"`);

        writeupTitle.textContent = title;
        writeupContent.innerHTML = imagePathFixedContent;

        // Apply syntax highlighting to all code blocks
        writeupContent.querySelectorAll('pre code').forEach((block) => {
            hljs.highlightElement(block);
        });

        switchView('viewer');
    } catch (error) {
        console.error("Error loading Markdown:", error);
        writeupTitle.textContent = "Error Loading Writeup";
        writeupContent.innerHTML = `<p style="color:red;">${error.message}</p><p>Please ensure the markdown file '/docs/${slug}/index.md' exists.</p>`;
        switchView('viewer'); // Still show viewer with error
    }
}

// Function to switch between homepage and viewer
function switchView(view) {
    if (view === 'homepage') {
        writeupViewer.classList.add('fade-out');
        setTimeout(() => {
            writeupViewer.classList.add('hidden');
            writeupViewer.classList.remove('fade-out');
            homepage.classList.remove('hidden');
            homepage.classList.add('fade-in');
        }, 500); // Wait for fade-out to complete
    } else { // view === 'viewer'
        homepage.classList.add('fade-out');
        setTimeout(() => {
            homepage.classList.add('hidden');
            homepage.classList.remove('fade-out');
            writeupViewer.classList.remove('hidden');
            writeupViewer.classList.add('fade-in');
            window.scrollTo(0, 0); // Scroll to top of writeup
        }, 500); // Wait for fade-out to complete
    }
}

// Navigation logic using window.history.pushState
function navigateToWriteup(slug) {
    history.pushState({ slug: slug }, '', `#/writeups/${slug}`);
    loadMarkdown(slug);
}

function navigateToHomepage() {
    history.pushState({}, '', '#/');
    switchView('homepage');
}

// Handle browser's back/forward buttons
window.addEventListener('popstate', (event) => {
    if (event.state && event.state.slug) {
        loadMarkdown(event.state.slug);
    } else {
        switchView('homepage');
    }
});

// Initial route handling on page load
function handleInitialRoute() {
    const path = window.location.hash;
    if (path.startsWith('#/writeups/')) {
        const slug = path.split('#/writeups/')[1];
        loadMarkdown(slug);
    } else {
        loadWriteups();
        switchView('homepage');
    }
}

// Event Listeners
backButton.addEventListener('click', navigateToHomepage);
document.querySelector('.logo').addEventListener('click', (event) => {
    event.preventDefault(); // Prevent default anchor behavior
    navigateToHomepage();
});


// Load writeups and handle initial route when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', handleInitialRoute);