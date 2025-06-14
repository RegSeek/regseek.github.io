// Global variables
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

// Load artifacts from JSON file
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
        showError('Failed to load artifacts. Please check the console for details.');
    }
}

// Initialize application
function init(data) {
    populateFilterOptions(data);
    filteredArtifacts = [...allArtifacts];
    renderArtifacts(filteredArtifacts);
    updateStats(data.statistics);
    setupEventListeners();
}

// Populate filter dropdown options
function populateFilterOptions(data) {
    // Categories
    const categorySelect = document.getElementById('filter-category');
    if (categorySelect && data.categories) {
        data.categories.forEach(category => {
            const option = document.createElement('option');
            option.value = category;
            option.textContent = category.charAt(0).toUpperCase() + category.slice(1).replace('-', ' ');
            categorySelect.appendChild(option);
        });
    }
    
    // Windows versions
    const versionSelect = document.getElementById('filter-windows-version');
    if (versionSelect && data.statistics?.windows_versions) {
        data.statistics.windows_versions.forEach(version => {
            const option = document.createElement('option');
            option.value = version;
            option.textContent = version;
            versionSelect.appendChild(option);
        });
    }
}

// Render artifacts
function renderArtifacts(artifacts) {
    const grid = document.getElementById('registry-grid');
    grid.innerHTML = '';
    
    if (artifacts.length === 0) {
        grid.innerHTML = `
            <div class="empty-state">
                <h3>No artifacts found</h3>
                <p>Try adjusting your search criteria or filters</p>
            </div>
        `;
        return;
    }
    
    artifacts.forEach((artifact, index) => {
        const item = createArtifactElement(artifact, index);
        grid.appendChild(item);
    });
    
    updateVisibleCount(artifacts.length);
}

// Create artifact element
function createArtifactElement(artifact, index) {
    const div = document.createElement('div');
    div.className = 'registry-item';
    div.dataset.category = artifact.category;
    div.dataset.index = index;
    
    const metadata = artifact.metadata || {};
    const criticality = metadata.criticality || 'unspecified';
    const primaryPath = artifact.paths ? artifact.paths[0] : 'Unknown path';
    
    // Create tags from investigation types and other metadata
    const tags = [];
    if (metadata.investigation_types) {
        tags.push(...metadata.investigation_types.slice(0, 3)); // Show max 3
    }
    if (metadata.tags) {
        tags.push(...metadata.tags.slice(0, 2)); // Show max 2 more
    }
    
    const tagsHtml = tags.length > 0 ? `
        <div class="item-tags">
            ${tags.map(tag => `<span class="item-tag">${tag}</span>`).join('')}
        </div>
    ` : '';
    
    const criticalityBadge = criticality !== 'unspecified' ? `
        <span class="item-criticality ${criticality}">${criticality}</span>
    ` : '';
    
    div.innerHTML = `
        <div class="item-header">
            <div class="item-badges">
                <span class="item-category">${artifact.category}</span>
                ${criticalityBadge}
            </div>
            <h3 class="item-title">${artifact.title}</h3>
        </div>
        <div class="item-path">${primaryPath}</div>
        <div class="item-description">${artifact.description}</div>
        ${tagsHtml}
        <div class="item-footer">
            <span class="item-meta">Click for details</span>
            <span class="item-arrow">→</span>
        </div>
    `;
    
    div.addEventListener('click', () => showEnhancedModal(artifact));
    return div;
}

// Show enhanced modal with artifact details
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
    
    // Create enhanced modal structure
    modal.innerHTML = `
        <div class="enhanced-modal">
            <span class="close-modal" id="close-modal">&times;</span>
                
            <!-- Sidebar Navigation -->
            <div class="modal-sidebar">
                <div class="sidebar-section">
                    <div class="sidebar-title">Quick Overview</div>
                    <div class="nav-item active" data-section="overview">
                        <i data-feather="info" class="nav-icon"></i>
                        Overview
                    </div>
                    <div class="nav-item" data-section="limitations">
                        <i data-feather="alert-triangle" class="nav-icon"></i>
                        Limitations
                        <span class="nav-badge">Important</span>
                    </div>
                    <div class="nav-item" data-section="correlation">
                        <i data-feather="link" class="nav-icon"></i>
                        Correlation
                        <span class="nav-badge warning">Required</span>
                    </div>
                </div>
                    
                <div class="sidebar-section">
                    <div class="sidebar-title">Details</div>
                    <div class="nav-item" data-section="structure">
                        <i data-feather="layers" class="nav-icon"></i>
                        Structure & Format
                    </div>
                    <div class="nav-item" data-section="examples">
                        <i data-feather="file-text" class="nav-icon"></i>
                        Examples
                    </div>
                    <div class="nav-item" data-section="tools">
                        <i data-feather="tool" class="nav-icon"></i>
                        Analysis Tools
                    </div>
                </div>
                    
                <div class="sidebar-section">
                    <div class="sidebar-title">Metadata</div>
                    <div class="nav-item" data-section="investigation">
                        <i data-feather="search" class="nav-icon"></i>
                        Investigation Use
                    </div>
                    <div class="nav-item" data-section="references">
                        <i data-feather="book-open" class="nav-icon"></i>
                        References
                    </div>
                    <div class="nav-item" data-section="contribution">
                        <i data-feather="user" class="nav-icon"></i>
                        Contribution Info
                    </div>
                </div>
            </div>

            <!-- Main Content -->
            <div class="modal-main">
                <!-- Enhanced Header -->
                <div class="modal-header-enhanced" id="modal-header">
                    <!-- Content will be populated -->
                </div>

                <!-- Content Area -->
                <div class="modal-content-area" id="modal-content">
                    <!-- Content sections will be populated -->
                </div>
            </div>
        </div>
    `;
    
    // Populate header
    populateModalHeader(artifact);
    
    // Populate content sections
    populateModalContent(artifact);
    
    // Setup navigation
    setupModalNavigation();
    
    // Show overview section by default
    showSection('overview');
    
    // Setup event listeners
    setupModalEventListeners();
    
    // Setup feather icons
    initializeFeatherIcons();
    
    modal.style.display = 'block';
    document.body.style.overflow = 'hidden';
}

// Populate modal header
function populateModalHeader(artifact) {
    const header = document.getElementById('modal-header');
    const metadata = artifact.metadata || {};
    const criticality = metadata.criticality || 'unspecified';
    const primaryPath = artifact.paths ? artifact.paths[0] : 'Unknown path';
    const additionalPaths = artifact.paths ? artifact.paths.slice(1) : [];
    
    header.innerHTML = `
        <h2 class="artifact-title">${artifact.title}</h2>
        <div class="artifact-badges">
            <span class="badge badge-category">${artifact.category}</span>
            ${criticality !== 'unspecified' ? `<span class="badge badge-criticality">${criticality} priority</span>` : ''}
        </div>
        <div class="artifact-paths">
            ${primaryPath}
            ${additionalPaths.map(path => `<br>${path}`).join('')}
        </div>
    `;
}

// Populate modal content
function populateModalContent(artifact) {
    const content = document.getElementById('modal-content');
    const details = artifact.details || {};
    const metadata = artifact.metadata || {};
    const author = artifact.author || {};
    const contribution = artifact.contribution || {};
    const limitations = artifact.limitations || [];
    const correlation = artifact.correlation || {};
    
    content.innerHTML = `
        <!-- Overview Section -->
        <div class="content-section active" id="overview">
            <div class="section-header">
                <i data-feather="info" class="section-icon"></i>
                <h3 class="section-title">Artifact Overview</h3>
            </div>
            
            <div class="info-card">
                <h3>What It Stores</h3>
                <p>${details.what || 'No details available'}</p>
            </div>
            
            <div class="info-card">
                <h3>Forensic Value</h3>
                <p>${details.forensic_value || 'No forensic value description'}</p>
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
                    ${limitations.map(limitation => `<li>${limitation}</li>`).join('')}
                </ul>
            </div>
            ` : `
            <div class="info-card">
                <p>No specific limitations documented for this artifact. Consider what assumptions you might be making about what this artifact proves vs. what it actually shows.</p>
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
                        ${correlation.required_for_definitive_conclusions.map(item => `<li>${item}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}
                
                ${correlation.strengthens_evidence ? `
                <div class="correlation-subsection">
                    <h5 class="correlation-subtitle">Strengthens Evidence:</h5>
                    <ul class="correlation-list">
                        ${correlation.strengthens_evidence.map(item => `<li>${item}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}
            </div>
            ` : `
            <div class="info-card">
                <p>No correlation requirements documented. Consider what other artifacts you need to validate findings from this artifact before drawing conclusions.</p>
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
                <p>${details.structure || 'No structure information available'}</p>
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
                    <div class="example-item">${example.replace(/\\n/g, '<br>')}</div>
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
                                <div class="tool-name">${tool}</div>
                            </div>
                        `;
                    }
                    return `
                        <div class="tool-card">
                            <div class="tool-name">
                                ${tool.url ? `<a href="${tool.url}" target="_blank" rel="noopener" data-tool-name="${tool.name}" data-tool-url="${tool.url}" class="tool-link">${tool.name}</a>` : tool.name}
                            </div>
                            ${tool.description ? `<div class="tool-description">${tool.description}</div>` : ''}
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
                    ${metadata.investigation_types.map(type => `<span class="tag">${type}</span>`).join('')}
                </div>
            </div>
            ` : ''}
            
            ${metadata.windows_versions && metadata.windows_versions.length > 0 ? `
            <div class="info-card">
                <h3>Windows Versions</h3>
                <p>${metadata.windows_versions.join(', ')}</p>
            </div>
            ` : ''}
            
            ${metadata.criticality ? `
            <div class="info-card">
                <h3>Criticality Level</h3>
                <p class="text-${metadata.criticality}">${metadata.criticality.charAt(0).toUpperCase() + metadata.criticality.slice(1)} Priority</p>
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
                    ${metadata.references.map(ref => `
                        <li>
                            ${ref.url ? `<a href="${ref.url}" target="_blank" rel="noopener">${ref.title}</a>` : ref.title}
                            ${ref.type ? ` (${ref.type})` : ''}
                        </li>
                    `).join('')}
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
                    ${author.name ? `<li><strong>Author:</strong> ${author.name}${author.organization ? ` (${author.organization})` : ''}</li>` : ''}
                    ${author.github ? `<li><strong>GitHub:</strong> <a href="https://github.com/${author.github}" target="_blank" rel="noopener">@${author.github}</a></li>` : ''}
                    ${author.x ? `<li><strong>X (Twitter):</strong> <a href="https://x.com/${author.x}" target="_blank" rel="noopener">@${author.x}</a></li>` : ''}
                    ${contribution.date_added ? `<li><strong>Added:</strong> ${contribution.date_added}</li>` : ''}
                    ${contribution.version ? `<li><strong>Version:</strong> ${contribution.version}</li>` : ''}
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

// Setup modal navigation
function setupModalNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', function() {
            const sectionId = this.getAttribute('data-section');
            showSection(sectionId);
            
            // Update navigation
            document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
            this.classList.add('active');
        });
    });
}

// Show content section
function showSection(sectionId) {
    // Hide all sections
    document.querySelectorAll('.content-section').forEach(section => section.classList.remove('active'));
    
    // Show selected section
    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.classList.add('active');
        
        // Refresh feather icons for the newly shown section
        initializeFeatherIcons();
    }
}

// Setup modal event listeners
function setupModalEventListeners() {
    // Close modal
    const closeBtn = document.getElementById('close-modal');
    if (closeBtn) {
        closeBtn.addEventListener('click', hideModal);
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
    
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('tool-link')) {
            e.preventDefault();
            const toolName = e.target.dataset.toolName;
            const toolUrl = e.target.dataset.toolUrl;
            
            if (typeof trackToolClick === 'function') {
                trackToolClick(toolName, toolUrl);
            }
            
            // Open the link
            window.open(toolUrl, '_blank', 'noopener,noreferrer');
        }
    });
}

// Setup event listeners
function setupEventListeners() {
    // Search functionality
    const searchInput = document.getElementById('search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(performSearch, 300));
    }
    
    // Quick filter buttons with tracking
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            
            const filterValue = e.target.dataset.filter;
            currentFilters.category = filterValue === 'all' ? '' : filterValue;
            
            // Track quick filter usage
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
    
    // Advanced search filters - updated with split dropdowns
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
            advancedPanel.classList.remove('open');
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
 
// Update advanced filters
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

// Clear all filters
function clearAllFilters() {
    // Reset form elements
    document.getElementById('filter-category').value = '';
    document.getElementById('filter-criticality').value = '';
    document.getElementById('filter-investigation-phase').value = '';
    document.getElementById('filter-attack-technique').value = '';
    document.getElementById('filter-windows-version').value = '';
    document.getElementById('filter-hive').value = '';
    document.getElementById('filter-has-tools').value = '';
    document.getElementById('search').value = '';
    
    // Reset quick filters
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector('.filter-btn[data-filter="all"]').classList.add('active');
    
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

// Perform search with all active filters
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

// Handle sorting
function handleSort() {
    const sortSelect = document.getElementById('sort-select');
    const sortBy = sortSelect.value;
    
    // Track sort usage
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

// Hide modal
function hideModal() {
    const modal = document.getElementById('modal');
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = 'auto';
    }
}

// Update statistics
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

// Update visible count
function updateVisibleCount(count) {
    const element = document.getElementById('visible-artifacts');
    if (element) {
        element.textContent = count;
    }
}

// Show error message
function showError(message) {
    const grid = document.getElementById('registry-grid');
    if (grid) {
        grid.innerHTML = `
            <div class="empty-state">
                <h3>Error</h3>
                <p>${message}</p>
            </div>
        `;
    }
}

// Utility: debounce function
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

// Add feature icons
function initializeFeatherIcons() {
    try {
        if (typeof feather !== 'undefined' && feather.replace) {
            feather.replace();
        } else {
            console.warn('Feather icons library not loaded');
            // Fallback: hide icons or use text alternatives
            document.querySelectorAll('[data-feather]').forEach(icon => {
                icon.style.display = 'none';
            });
        }
    } catch (error) {
        console.error('Error initializing Feather icons:', error);
        // Fallback for icon failures
        document.querySelectorAll('[data-feather]').forEach(icon => {
            icon.style.display = 'none';
        });
    }
}

// Load artifacts when page loads
document.addEventListener('DOMContentLoaded', () => {
    // Wait a bit for external scripts to load
    setTimeout(() => {
        initializeFeatherIcons();
        loadArtifacts();
    }, 100);
});
