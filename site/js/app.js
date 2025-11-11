// RegSeek Enhanced Application
// Version: 2.0 with Security Fixes, Mobile Optimization, and Interactive Features

// ============================================================================
// SECURITY: HTML Escaping Helper
// ============================================================================
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return '';
    const div = document.createElement('div');
    div.textContent = unsafe;
    return div.innerHTML;
}

// ============================================================================
// SECURITY: URL Validation Helper
// ============================================================================
function isValidUrl(url) {
    if (!url) return false;
    try {
        const parsed = new URL(url);
        // Only allow https and http protocols (prevent javascript:, data:, etc.)
        if (!['https:', 'http:'].includes(parsed.protocol)) {
            console.warn(`Blocked invalid URL protocol: ${parsed.protocol}`);
            return false;
        }
        return true;
    } catch (error) {
        console.warn(`Invalid URL: ${url}`, error);
        return false;
    }
}

// ============================================================================
// UTILITY: Category Name Formatter
// ============================================================================
function formatCategoryName(category) {
    if (!category) return '';

    // Special case for AI-related categories
    if (category.toLowerCase().startsWith('ai-')) {
        return 'AI ' + category.slice(3).split('-').map(word =>
            word.charAt(0).toUpperCase() + word.slice(1)
        ).join(' ');
    }

    // Standard formatting: capitalize first letter of each word, replace hyphens with spaces
    return category.split('-').map(word =>
        word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ');
}

// ============================================================================
// GLOBAL STATE
// ============================================================================
let allArtifacts = [];
let filteredArtifacts = [];
let currentFilters = {
    search: '',
    category: '',
    criticality: '',
    investigationPhase: '',
    attackTechnique: '',
    windowsVersion: '',
    hive: '',
    hasTools: ''
};

// Event listener references for cleanup
let modalEventListeners = {
    toolClick: null,
    keydown: null
};

// ============================================================================
// FEATHER ICONS: Enhanced Loading
// ============================================================================
function waitForFeather() {
    return new Promise((resolve) => {
        if (typeof feather !== 'undefined') {
            resolve(true);
            return;
        }

        let attempts = 0;
        const maxAttempts = 100; // 5 seconds max
        const check = setInterval(() => {
            attempts++;
            if (typeof feather !== 'undefined') {
                clearInterval(check);
                resolve(true);
            } else if (attempts >= maxAttempts) {
                clearInterval(check);
                console.warn('Feather icons failed to load');
                resolve(false);
            }
        }, 50);
    });
}

function initializeFeatherIcons() {
    try {
        if (typeof feather !== 'undefined' && feather.replace) {
            feather.replace();
        } else {
            // Fallback: hide icon elements
            document.querySelectorAll('[data-feather]').forEach(icon => {
                icon.style.display = 'none';
            });
        }
    } catch (error) {
        console.error('Error initializing Feather icons:', error);
        document.querySelectorAll('[data-feather]').forEach(icon => {
            icon.style.display = 'none';
        });
    }
}

// ============================================================================
// DATA LOADING
// ============================================================================
async function loadArtifacts() {
    try {
        const response = await fetch('build/artifacts.json');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        allArtifacts = data.artifacts;

        console.log(`Loaded ${allArtifacts.length} artifacts`);

        // Initialize the UI
        init(data);
    } catch (error) {
        console.error('Failed to load artifacts:', error);
        showError('Failed to load artifacts. Please check your network connection or try refreshing the page.');
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================
function init(data) {
    populateFilterOptions(data);
    filteredArtifacts = [...allArtifacts];
    renderArtifacts(filteredArtifacts);
    updateStats(data.statistics);
    setupEventListeners();
}

// ============================================================================
// UI POPULATION
// ============================================================================
function populateFilterOptions(data) {
    // Categories
    const categorySelect = document.getElementById('filter-category');
    if (categorySelect && data.categories) {
        data.categories.forEach(category => {
            const option = document.createElement('option');
            option.value = category;
            option.textContent = escapeHtml(formatCategoryName(category));
            categorySelect.appendChild(option);
        });
    }

    // Windows versions
    const versionSelect = document.getElementById('filter-windows-version');
    if (versionSelect && data.statistics?.windows_versions) {
        data.statistics.windows_versions.forEach(version => {
            const option = document.createElement('option');
            option.value = version;
            option.textContent = escapeHtml(version);
            versionSelect.appendChild(option);
        });
    }
}

// ============================================================================
// ARTIFACT RENDERING
// ============================================================================
function renderArtifacts(artifacts) {
    const grid = document.getElementById('registry-grid');
    grid.innerHTML = '';

    if (artifacts.length === 0) {
        const emptyDiv = document.createElement('div');
        emptyDiv.className = 'empty-state';
        emptyDiv.innerHTML = `
            <h3>No artifacts found</h3>
            <p>Try adjusting your search criteria or filters</p>
        `;
        grid.appendChild(emptyDiv);
        return;
    }

    artifacts.forEach((artifact, index) => {
        const item = createArtifactElement(artifact, index);
        grid.appendChild(item);
    });

    updateVisibleCount(artifacts.length);
}

// SECURITY FIX: Safe element creation with proper escaping
function createArtifactElement(artifact, index) {
    const div = document.createElement('div');
    div.className = 'registry-item';
    div.dataset.category = artifact.category;
    div.dataset.index = index;

    const metadata = artifact.metadata || {};
    const criticality = metadata.criticality || 'unspecified';
    const primaryPath = artifact.paths && artifact.paths[0] ?
        escapeHtml(artifact.paths[0].trim()) : 'Unknown path';

    // Create tags
    const tags = [];
    if (metadata.investigation_types) {
        tags.push(...metadata.investigation_types.slice(0, 3));
    }
    if (metadata.tags) {
        tags.push(...metadata.tags.slice(0, 2));
    }

    const tagsHtml = tags.length > 0 ? `
        <div class="item-tags">
            ${tags.map(tag => `<span class="item-tag">${escapeHtml(tag)}</span>`).join('')}
        </div>
    ` : '';

    const criticalityBadge = criticality !== 'unspecified' ? `
        <span class="item-criticality ${criticality}">${escapeHtml(criticality)}</span>
    ` : '';

    div.innerHTML = `
        <div class="item-header">
            <div class="item-badges">
                <span class="item-category">${escapeHtml(formatCategoryName(artifact.category))}</span>
                ${criticalityBadge}
            </div>
            <h3 class="item-title">${escapeHtml(artifact.title)}</h3>
        </div>
        <div class="item-path">${primaryPath}</div>
        <div class="item-description">${escapeHtml(artifact.description)}</div>
        ${tagsHtml}
        <div class="item-footer">
            <span class="item-meta">Click for details</span>
            <span class="item-arrow">→</span>
        </div>
    `;

    div.addEventListener('click', () => showEnhancedModal(artifact));

    // Mobile: Add touch feedback
    div.addEventListener('touchstart', () => {
        div.style.transform = 'scale(0.98)';
    });
    div.addEventListener('touchend', () => {
        div.style.transform = '';
    });

    return div;
}

// ============================================================================
// MODAL MANAGEMENT
// ============================================================================
function showEnhancedModal(artifact) {
    const modal = document.getElementById('modal');

    // Track artifact view
    if (typeof trackArtifactView === 'function') {
        trackArtifactView(
            artifact.title,
            artifact.category,
            artifact.metadata?.criticality
        );
    }

    // Clean up old event listeners before creating new modal
    cleanupModalListeners();

    // Create enhanced modal structure
    modal.innerHTML = `
        <div class="enhanced-modal">
            <span class="close-modal" id="close-modal" tabindex="0" role="button" aria-label="Close modal">&times;</span>

            <!-- Sidebar Navigation -->
            <div class="modal-sidebar" role="navigation" aria-label="Section navigation">
                <div class="sidebar-section">
                    <div class="sidebar-title">Quick Overview</div>
                    <div class="nav-item active" data-section="overview" tabindex="0" role="button">
                        <i data-feather="info" class="nav-icon"></i>
                        Overview
                    </div>
                    <div class="nav-item" data-section="limitations" tabindex="0" role="button">
                        <i data-feather="alert-triangle" class="nav-icon"></i>
                        Limitations
                        <span class="nav-badge">Important</span>
                    </div>
                    <div class="nav-item" data-section="correlation" tabindex="0" role="button">
                        <i data-feather="link" class="nav-icon"></i>
                        Correlation
                        <span class="nav-badge warning">Required</span>
                    </div>
                </div>

                <div class="sidebar-section">
                    <div class="sidebar-title">Details</div>
                    <div class="nav-item" data-section="structure" tabindex="0" role="button">
                        <i data-feather="layers" class="nav-icon"></i>
                        Structure & Format
                    </div>
                    <div class="nav-item" data-section="examples" tabindex="0" role="button">
                        <i data-feather="file-text" class="nav-icon"></i>
                        Examples
                    </div>
                    <div class="nav-item" data-section="tools" tabindex="0" role="button">
                        <i data-feather="tool" class="nav-icon"></i>
                        Analysis Tools
                    </div>
                </div>

                <div class="sidebar-section">
                    <div class="sidebar-title">Metadata</div>
                    <div class="nav-item" data-section="investigation" tabindex="0" role="button">
                        <i data-feather="search" class="nav-icon"></i>
                        Investigation Use
                    </div>
                    <div class="nav-item" data-section="references" tabindex="0" role="button">
                        <i data-feather="book-open" class="nav-icon"></i>
                        References
                    </div>
                    <div class="nav-item" data-section="contribution" tabindex="0" role="button">
                        <i data-feather="user" class="nav-icon"></i>
                        Contribution Info
                    </div>
                </div>
            </div>

            <!-- Main Content -->
            <div class="modal-main">
                <!-- Enhanced Header -->
                <div class="modal-header-enhanced" id="modal-header"></div>

                <!-- Content Area -->
                <div class="modal-content-area" id="modal-content"></div>
            </div>
        </div>
    `;

    // Populate content
    populateModalHeader(artifact);
    populateModalContent(artifact);

    // Setup navigation and listeners
    setupModalNavigation();
    setupModalEventListeners();
    showSection('overview');
    initializeFeatherIcons();

    // Show modal with accessibility
    modal.style.display = 'block';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');

    // Disable body scroll
    const scrollY = window.scrollY;
    document.body.style.overflow = 'hidden';
    document.body.style.position = 'fixed';
    document.body.style.top = `-${scrollY}px`;
    document.body.style.width = '100%';

    // Focus close button for accessibility
    setTimeout(() => {
        document.getElementById('close-modal')?.focus();
    }, 100);
}

// SECURITY FIX: Safe modal header population
function populateModalHeader(artifact) {
    const header = document.getElementById('modal-header');
    const metadata = artifact.metadata || {};
    const criticality = metadata.criticality || 'unspecified';
    const cleanPaths = artifact.paths ?
        artifact.paths
            .map(path => escapeHtml(path.trim()))
            .filter(path => path.length > 0)
        : [];

    header.innerHTML = `
        <h2 class="artifact-title">${escapeHtml(artifact.title)}</h2>
        <div class="artifact-badges">
            <span class="badge badge-category">${escapeHtml(formatCategoryName(artifact.category))}</span>
            ${criticality !== 'unspecified' ? `<span class="badge badge-criticality">${escapeHtml(criticality)} priority</span>` : ''}
            ${metadata.deprecated ? `<span class="badge badge-deprecated">Deprecated ${escapeHtml(metadata.deprecated)}</span>` : ''}
        </div>
        <div class="artifact-paths">${cleanPaths.join('\n')}</div>
    `;
}

// SECURITY FIX: Safe modal content population
function populateModalContent(artifact) {
    const content = document.getElementById('modal-content');
    const details = artifact.details || {};
    const metadata = artifact.metadata || {};
    const author = artifact.author || {};
    const contribution = artifact.contribution || {};
    const limitations = artifact.limitations || [];
    const correlation = artifact.correlation || {};

    // Safe text conversion helper
    const safeText = (text) => {
        if (!text) return 'No information available';
        return escapeHtml(text).replace(/\n/g, '<br>');
    };

    content.innerHTML = `
        <!-- Overview Section -->
        <div class="content-section active" id="overview">
            <div class="section-header">
                <i data-feather="info" class="section-icon"></i>
                <h3 class="section-title">Artifact Overview</h3>
            </div>

            <div class="info-card">
                <h3>What It Stores</h3>
                <p>${safeText(details.what)}</p>
            </div>

            <div class="info-card">
                <h3>Forensic Value</h3>
                <p>${safeText(details.forensic_value)}</p>
            </div>
        </div>

        <!-- Limitations Section -->
        <div class="content-section" id="limitations">
            <div class="section-header">
                <i data-feather="alert-triangle" class="section-icon"></i>
                <h3 class="section-title">Forensic Limitations</h3>
            </div>

            ${limitations.length > 0 ? `
            <div class="limitations-section">
                <div class="limitations-header">
                    <i data-feather="alert-triangle" class="warning-icon"></i>
                    <h4 class="limitations-title">What This Artifact CANNOT Prove</h4>
                </div>
                <ul class="limitations-list">
                    ${limitations.map(limitation => `<li>${escapeHtml(limitation)}</li>`).join('')}
                </ul>
            </div>
            ` : `
            <div class="info-card">
                <p>No specific limitations documented. Consider what assumptions you might be making.</p>
            </div>
            `}
        </div>

        <!-- Correlation Section -->
        <div class="content-section" id="correlation">
            <div class="section-header">
                <i data-feather="link" class="section-icon"></i>
                <h3 class="section-title">Artifact Correlation</h3>
            </div>

            ${correlation.required_for_definitive_conclusions || correlation.strengthens_evidence ? `
            <div class="correlation-section">
                <div class="correlation-header">
                    <i data-feather="link" class="warning-icon"></i>
                    <h4 class="correlation-title">Required for Definitive Conclusions</h4>
                </div>

                ${correlation.required_for_definitive_conclusions ? `
                <div class="correlation-subsection">
                    <h5 class="correlation-subtitle">Required for Proof:</h5>
                    <ul class="correlation-list">
                        ${correlation.required_for_definitive_conclusions.map(item => `<li>${escapeHtml(item)}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}

                ${correlation.strengthens_evidence ? `
                <div class="correlation-subsection">
                    <h5 class="correlation-subtitle">Strengthens Evidence:</h5>
                    <ul class="correlation-list">
                        ${correlation.strengthens_evidence.map(item => `<li>${escapeHtml(item)}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}
            </div>
            ` : `
            <div class="info-card">
                <p>No correlation requirements documented.</p>
            </div>
            `}
        </div>

        <!-- Structure Section -->
        <div class="content-section" id="structure">
            <div class="section-header">
                <i data-feather="layers" class="section-icon"></i>
                <h3 class="section-title">Data Structure & Format</h3>
            </div>

            <div class="info-card">
                <h3>Storage Format</h3>
                <p>${safeText(details.structure)}</p>
            </div>
        </div>

        <!-- Examples Section -->
        <div class="content-section" id="examples">
            <div class="section-header">
                <i data-feather="file-text" class="section-icon"></i>
                <h3 class="section-title">Examples</h3>
            </div>

            ${details.examples && details.examples.length > 0 ? `
            <div class="examples-grid">
                ${details.examples.map(example => `
                    <div class="example-item">${escapeHtml(example).replace(/\\n/g, '<br>')}</div>
                `).join('')}
            </div>
            ` : `
            <div class="info-card">
                <p>No examples available for this artifact.</p>
            </div>
            `}
        </div>

        <!-- Tools Section -->
        <div class="content-section" id="tools">
            <div class="section-header">
                <i data-feather="tool" class="section-icon"></i>
                <h3 class="section-title">Analysis Tools</h3>
            </div>

            ${details.tools && details.tools.length > 0 ? `
            <div class="tools-grid">
                ${details.tools.map(tool => {
                    if (typeof tool === 'string') {
                        return `
                            <div class="tool-card">
                                <div class="tool-name">${escapeHtml(tool)}</div>
                            </div>
                        `;
                    }
                    // SECURITY FIX: Validate URLs before creating links
                    const toolUrl = tool.url && isValidUrl(tool.url) ? tool.url : null;
                    return `
                        <div class="tool-card">
                            <div class="tool-name">
                                ${toolUrl ? `<a href="${escapeHtml(toolUrl)}" target="_blank" rel="noopener noreferrer" data-tool-name="${escapeHtml(tool.name)}" data-tool-url="${escapeHtml(toolUrl)}" class="tool-link">${escapeHtml(tool.name)}</a>` : escapeHtml(tool.name)}
                            </div>
                            ${tool.description ? `<div class="tool-description">${escapeHtml(tool.description)}</div>` : ''}
                        </div>
                    `;
                }).join('')}
            </div>
            ` : `
            <div class="info-card">
                <p>No analysis tools documented for this artifact.</p>
            </div>
            `}
        </div>

        <!-- Investigation Section -->
        <div class="content-section" id="investigation">
            <div class="section-header">
                <i data-feather="search" class="section-icon"></i>
                <h3 class="section-title">Investigation Use Cases</h3>
            </div>

            ${metadata.investigation_types && metadata.investigation_types.length > 0 ? `
            <div class="info-card">
                <h3>Investigation Types</h3>
                <div class="tag-grid">
                    ${metadata.investigation_types.map(type => `<span class="tag">${escapeHtml(type)}</span>`).join('')}
                </div>
            </div>
            ` : ''}

            ${metadata.windows_versions && metadata.windows_versions.length > 0 ? `
            <div class="info-card">
                <h3>Windows Versions</h3>
                <p>${metadata.windows_versions.map(v => escapeHtml(v)).join(', ')}</p>
            </div>
            ` : ''}

            ${metadata.criticality ? `
            <div class="info-card">
                <h3>Criticality Level</h3>
                <p class="text-${metadata.criticality}">${escapeHtml(metadata.criticality.charAt(0).toUpperCase() + metadata.criticality.slice(1))} Priority</p>
            </div>
            ` : ''}

            ${metadata.retention ? `
            <div class="info-card">
                <h3>Retention Information</h3>
                <ul>
                    ${metadata.retention.default_location ? `<li><strong>Default Location:</strong> ${escapeHtml(metadata.retention.default_location)}</li>` : ''}
                    ${metadata.retention.persistence ? `<li><strong>Persistence:</strong> ${escapeHtml(metadata.retention.persistence)}</li>` : ''}
                    ${metadata.retention.volatility ? `<li><strong>Volatility:</strong> ${escapeHtml(metadata.retention.volatility)}</li>` : ''}
                </ul>
            </div>
            ` : ''}

            ${metadata.introduced || metadata.deprecated ? `
            <div class="info-card">
                <h3>Version History</h3>
                <ul>
                    ${metadata.introduced ? `<li><strong>Introduced:</strong> ${escapeHtml(metadata.introduced)}</li>` : ''}
                    ${metadata.deprecated ? `<li><strong>Deprecated:</strong> ${escapeHtml(metadata.deprecated)}</li>` : ''}
                </ul>
            </div>
            ` : ''}
        </div>

        <!-- References Section -->
        <div class="content-section" id="references">
            <div class="section-header">
                <i data-feather="book-open" class="section-icon"></i>
                <h3 class="section-title">References & Resources</h3>
            </div>

            ${metadata.references && metadata.references.length > 0 ? `
            <div class="info-card">
                <h3>Documentation & Research</h3>
                <ul>
                    ${metadata.references.map(ref => {
                        const refUrl = ref.url && isValidUrl(ref.url) ? ref.url : null;
                        return `
                            <li>
                                ${refUrl ? `<a href="${escapeHtml(refUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(ref.title)}</a>` : escapeHtml(ref.title)}
                                ${ref.type ? ` (${escapeHtml(ref.type)})` : ''}
                            </li>
                        `;
                    }).join('')}
                </ul>
            </div>
            ` : `
            <div class="info-card">
                <p>No references documented for this artifact.</p>
            </div>
            `}
        </div>

        <!-- Contribution Section -->
        <div class="content-section" id="contribution">
            <div class="section-header">
                <i data-feather="user" class="section-icon"></i>
                <h3 class="section-title">Contribution Information</h3>
            </div>

            ${author.name || contribution.date_added ? `
            <div class="info-card">
                <h3>Author & Version</h3>
                <ul>
                    ${author.name ? `<li><strong>Author:</strong> ${escapeHtml(author.name)}${author.organization ? ` (${escapeHtml(author.organization)})` : ''}</li>` : ''}
                    ${author.github ? `<li><strong>GitHub:</strong> <a href="https://github.com/${escapeHtml(author.github)}" target="_blank" rel="noopener noreferrer">@${escapeHtml(author.github)}</a></li>` : ''}
                    ${author.x ? `<li><strong>X (Twitter):</strong> <a href="https://x.com/${escapeHtml(author.x)}" target="_blank" rel="noopener noreferrer">@${escapeHtml(author.x)}</a></li>` : ''}
                    ${contribution.date_added ? `<li><strong>Added:</strong> ${escapeHtml(contribution.date_added)}</li>` : ''}
                    ${contribution.version ? `<li><strong>Version:</strong> ${escapeHtml(contribution.version)}</li>` : ''}
                </ul>
            </div>
            ` : `
            <div class="info-card">
                <p>No contribution information available.</p>
            </div>
            `}
        </div>
    `;
}

// ============================================================================
// MODAL NAVIGATION
// ============================================================================
function setupModalNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        // Click handler
        item.addEventListener('click', function() {
            const sectionId = this.getAttribute('data-section');
            showSection(sectionId);
            updateNavigation(this);
        });

        // Keyboard handler for accessibility
        item.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                this.click();
            }
        });
    });

    // Touch scrolling for mobile sidebar
    const sidebar = document.querySelector('.modal-sidebar');
    if (sidebar && 'ontouchstart' in window) {
        let isDown = false;
        let startX;
        let scrollLeft;

        sidebar.addEventListener('touchstart', (e) => {
            isDown = true;
            startX = e.touches[0].pageX - sidebar.offsetLeft;
            scrollLeft = sidebar.scrollLeft;
        }, { passive: true });

        sidebar.addEventListener('touchmove', (e) => {
            if (!isDown) return;
            const x = e.touches[0].pageX - sidebar.offsetLeft;
            const walk = (x - startX) * 2;
            sidebar.scrollLeft = scrollLeft - walk;
        }, { passive: true });

        sidebar.addEventListener('touchend', () => {
            isDown = false;
        }, { passive: true });
    }
}

function showSection(sectionId) {
    // Hide all sections
    document.querySelectorAll('.content-section').forEach(section =>
        section.classList.remove('active')
    );

    // Show selected section
    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.classList.add('active');
        initializeFeatherIcons();
    }
}

function updateNavigation(activeItem) {
    document.querySelectorAll('.nav-item').forEach(nav =>
        nav.classList.remove('active')
    );
    activeItem.classList.add('active');
}

// ============================================================================
// MODAL EVENT LISTENERS (with cleanup)
// ============================================================================
function setupModalEventListeners() {
    // Close modal handlers
    const closeBtn = document.getElementById('close-modal');
    if (closeBtn) {
        closeBtn.addEventListener('click', hideModal);
        closeBtn.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                hideModal();
            }
        });
    }

    // Close on background click
    const modal = document.getElementById('modal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target.id === 'modal') {
                hideModal();
            }
        });
    }

    // SECURITY FIX: Tool link handler with validation and cleanup tracking
    modalEventListeners.toolClick = (e) => {
        if (e.target.classList.contains('tool-link')) {
            e.preventDefault();
            const toolName = e.target.dataset.toolName;
            const toolUrl = e.target.dataset.toolUrl;

            // Track tool click
            if (typeof trackToolClick === 'function') {
                trackToolClick(toolName, toolUrl);
            }

            // Open validated URL
            if (isValidUrl(toolUrl)) {
                window.open(toolUrl, '_blank', 'noopener,noreferrer');
            } else {
                console.warn('Attempted to open invalid URL:', toolUrl);
            }
        }
    };
    document.addEventListener('click', modalEventListeners.toolClick);

    // Keyboard shortcuts for modal
    modalEventListeners.keydown = (e) => {
        // ESC to close modal
        if (e.key === 'Escape') {
            hideModal();
        }
    };
    document.addEventListener('keydown', modalEventListeners.keydown);
}

// PERFORMANCE FIX: Cleanup modal event listeners
function cleanupModalListeners() {
    if (modalEventListeners.toolClick) {
        document.removeEventListener('click', modalEventListeners.toolClick);
        modalEventListeners.toolClick = null;
    }
    if (modalEventListeners.keydown) {
        document.removeEventListener('keydown', modalEventListeners.keydown);
        modalEventListeners.keydown = null;
    }
}

function hideModal() {
    const modal = document.getElementById('modal');
    if (modal) {
        modal.style.display = 'none';
        modal.removeAttribute('role');
        modal.removeAttribute('aria-modal');

        // Restore scrolling
        const scrollY = document.body.style.top;
        document.body.style.position = '';
        document.body.style.top = '';
        document.body.style.width = '';
        document.body.style.overflow = '';

        if (scrollY) {
            window.scrollTo(0, parseInt(scrollY || '0') * -1);
        }

        // Clean up listeners
        cleanupModalListeners();
    }
}

// ============================================================================
// MAIN EVENT LISTENERS
// ============================================================================
function setupEventListeners() {
    // Search functionality
    const searchInput = document.getElementById('search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(performSearch, 300));
    }

    // Quick filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-btn').forEach(b =>
                b.classList.remove('active')
            );
            e.target.classList.add('active');

            const filterValue = e.target.dataset.filter;
            currentFilters.category = filterValue === 'all' ? '' : filterValue;

            if (typeof trackFilterUsage === 'function' && filterValue !== 'all') {
                trackFilterUsage('quick_category', filterValue);
            }

            performSearch();
        });
    });

    // Advanced search toggle
    const advancedBtn = document.getElementById('advanced-search-btn');
    const advancedPanel = document.getElementById('advanced-search-panel');
    if (advancedBtn && advancedPanel) {
        advancedBtn.addEventListener('click', () => {
            advancedPanel.classList.toggle('open');
        });
    }

    // Advanced search filters
    const filterElements = [
        'filter-category', 'filter-criticality', 'filter-investigation-phase',
        'filter-attack-technique', 'filter-windows-version', 'filter-hive', 'filter-has-tools'
    ];

    filterElements.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.addEventListener('change', updateAdvancedFilters);
        }
    });

    // Advanced search actions
    const applyBtn = document.getElementById('apply-filters');
    const clearBtn = document.getElementById('clear-filters');

    if (applyBtn) {
        applyBtn.addEventListener('click', () => {
            updateAdvancedFilters();
            advancedPanel?.classList.remove('open');
        });
    }

    if (clearBtn) {
        clearBtn.addEventListener('click', clearAllFilters);
    }

    // Sort functionality
    const sortSelect = document.getElementById('sort-select');
    if (sortSelect) {
        sortSelect.addEventListener('change', handleSort);
    }
}

// ============================================================================
// FILTERING & SEARCH
// ============================================================================
function updateAdvancedFilters() {
    const oldFilters = {...currentFilters};

    currentFilters.category = document.getElementById('filter-category')?.value || '';
    currentFilters.criticality = document.getElementById('filter-criticality')?.value || '';
    currentFilters.investigationPhase = document.getElementById('filter-investigation-phase')?.value || '';
    currentFilters.attackTechnique = document.getElementById('filter-attack-technique')?.value || '';
    currentFilters.windowsVersion = document.getElementById('filter-windows-version')?.value || '';
    currentFilters.hive = document.getElementById('filter-hive')?.value || '';
    currentFilters.hasTools = document.getElementById('filter-has-tools')?.value || '';

    // Track filter changes
    if (typeof trackFilterUsage === 'function') {
        Object.keys(currentFilters).forEach(filterType => {
            if (currentFilters[filterType] && currentFilters[filterType] !== oldFilters[filterType]) {
                trackFilterUsage(filterType, currentFilters[filterType]);
            }
        });
    }

    performSearch();
}

function clearAllFilters() {
    // Reset form elements
    ['filter-category', 'filter-criticality', 'filter-investigation-phase',
     'filter-attack-technique', 'filter-windows-version', 'filter-hive',
     'filter-has-tools', 'search'].forEach(id => {
        const element = document.getElementById(id);
        if (element) element.value = '';
    });

    // Reset quick filters
    document.querySelectorAll('.filter-btn').forEach(btn =>
        btn.classList.remove('active')
    );
    document.querySelector('.filter-btn[data-filter="all"]')?.classList.add('active');

    // Reset filters object
    currentFilters = {
        search: '',
        category: '',
        criticality: '',
        investigationPhase: '',
        attackTechnique: '',
        windowsVersion: '',
        hive: '',
        hasTools: ''
    };

    performSearch();
}

function performSearch() {
    const searchInput = document.getElementById('search');
    currentFilters.search = searchInput ? searchInput.value.toLowerCase() : '';

    // Track search queries
    if (currentFilters.search && typeof trackSearch === 'function') {
        trackSearch(currentFilters.search);
    }

    filteredArtifacts = allArtifacts.filter(artifact => {
        // Text search
        if (currentFilters.search) {
            const searchableText = [
                artifact.title,
                artifact.description,
                artifact.category,
                ...(artifact.paths || []),
                ...(artifact.search_tags || []),
                ...(artifact.metadata?.tags || [])
            ].join(' ').toLowerCase();

            if (!searchableText.includes(currentFilters.search)) {
                return false;
            }
        }

        // Category filter
        if (currentFilters.category && artifact.category !== currentFilters.category) {
            return false;
        }

        // Criticality filter
        if (currentFilters.criticality) {
            const criticality = artifact.metadata?.criticality;
            if (criticality !== currentFilters.criticality) {
                return false;
            }
        }

        // Investigation phase filter
        if (currentFilters.investigationPhase) {
            const investigationTypes = artifact.metadata?.investigation_types || [];
            if (!investigationTypes.includes(currentFilters.investigationPhase)) {
                return false;
            }
        }

        // Attack technique filter
        if (currentFilters.attackTechnique) {
            const investigationTypes = artifact.metadata?.investigation_types || [];
            if (!investigationTypes.includes(currentFilters.attackTechnique)) {
                return false;
            }
        }

        // Windows version filter
        if (currentFilters.windowsVersion) {
            const versions = artifact.metadata?.windows_versions || [];
            if (!versions.includes(currentFilters.windowsVersion)) {
                return false;
            }
        }

        // Registry hive filter
        if (currentFilters.hive) {
            const paths = artifact.paths || [];
            const hasHive = paths.some(path => path.startsWith(currentFilters.hive + '\\'));
            if (!hasHive) {
                return false;
            }
        }

        // Has tools filter
        if (currentFilters.hasTools) {
            const tools = artifact.details?.tools || [];
            const hasTools = tools.length > 0;
            if (currentFilters.hasTools === 'yes' && !hasTools) {
                return false;
            }
            if (currentFilters.hasTools === 'no' && hasTools) {
                return false;
            }
        }

        return true;
    });

    renderArtifacts(filteredArtifacts);
}

// ============================================================================
// SORTING
// ============================================================================
function handleSort() {
    const sortSelect = document.getElementById('sort-select');
    const sortBy = sortSelect?.value;

    if (typeof trackSort === 'function') {
        trackSort(sortBy);
    }

    const sorted = [...filteredArtifacts].sort((a, b) => {
        switch (sortBy) {
            case 'title':
                return a.title.localeCompare(b.title);
            case 'title-desc':
                return b.title.localeCompare(a.title);
            case 'category':
                return a.category.localeCompare(b.category) || a.title.localeCompare(b.title);
            case 'criticality':
                const criticalityOrder = { 'high': 3, 'medium': 2, 'low': 1, 'unspecified': 0 };
                const aCrit = a.metadata?.criticality || 'unspecified';
                const bCrit = b.metadata?.criticality || 'unspecified';
                return criticalityOrder[bCrit] - criticalityOrder[aCrit] || a.title.localeCompare(b.title);
            case 'recent':
                const aDate = a.contribution?.date_added || '0000-00-00';
                const bDate = b.contribution?.date_added || '0000-00-00';
                return bDate.localeCompare(aDate) || a.title.localeCompare(b.title);
            default:
                return 0;
        }
    });

    renderArtifacts(sorted);
}

// ============================================================================
// STATISTICS & UI UPDATES
// ============================================================================
function updateStats(statistics) {
    const elements = {
        'total-artifacts': statistics?.total || allArtifacts.length,
        'total-categories': statistics?.by_category ? Object.keys(statistics.by_category).length : 0,
        'visible-artifacts': filteredArtifacts.length,
        'high-criticality': statistics?.by_criticality?.high || 0
    };

    Object.entries(elements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    });
}

function updateVisibleCount(count) {
    const element = document.getElementById('visible-artifacts');
    if (element) {
        element.textContent = count;
    }
}

function showError(message) {
    const grid = document.getElementById('registry-grid');
    if (grid) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'empty-state';
        errorDiv.innerHTML = `
            <h3>Error</h3>
            <p>${escapeHtml(message)}</p>
        `;
        grid.innerHTML = '';
        grid.appendChild(errorDiv);
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// ============================================================================
// INITIALIZATION ON PAGE LOAD
// ============================================================================
document.addEventListener('DOMContentLoaded', async () => {
    // Wait for Feather icons to load
    const featherLoaded = await waitForFeather();

    if (featherLoaded) {
        initializeFeatherIcons();
    }

    // Load artifacts
    await loadArtifacts();

    // Show keyboard shortcuts hint
    console.log('%c⌨️ Keyboard Shortcuts:', 'font-size: 14px; font-weight: bold;');
    console.log('/ - Focus search | t - Toggle theme | e - Export | ? - Show help');
});
